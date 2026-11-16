package hub

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"howett.net/plist"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/mailctl"
	"github.com/portcullis/hub/internal/state"
)

// Mail passwords (contract §5.1 "Mail passwords", §13.16, §19.6): created
// by the person only on the Sign-in page, behind a fresh sign-in under
// the people core template; shown once; Stalwart holds the hash; the Hub
// keeps metadata rows in state.yaml mail_credentials.

// Mail ports the clients use (contract §19.2).
const (
	mailIMAPSPort       = 993
	mailSubmissionsPort = 465
	mailSubmissionPort  = 587
)

var (
	// errNoMail is the one 404 for anyone not in mail_users (and while
	// mail is off), the same body for every case.
	errNoMail = &StatusError{Status: http.StatusNotFound, Err: errors.New("not found: no mailbox for this account")}
	// errMailDown: mail isn't running (contract §19.9).
	errMailDown = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("mail isn't running right now")}
	// errMailNotReady: the mailbox isn't in mailctl's applied state yet.
	errMailNotReady = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("your mailbox isn't ready yet: try again in a minute")}
	// errNoMailPassword: no such password of the caller's.
	errNoMailPassword = &StatusError{Status: http.StatusNotFound, Err: errors.New("not found: no such mail password")}
)

// IsMailUnavailable: err is one of mail's fixed 503s (mail isn't
// running, the mailbox isn't ready), whose text the routes pass on.
func IsMailUnavailable(err error) bool {
	return errors.Is(err, errMailDown) || errors.Is(err, errMailNotReady) || errors.Is(err, errMailSecret)
}

// MailSecretProblem is the doctor's and Settings → Mail's text when mail
// is on but the Hub's mail secret is missing or too short.
const MailSecretProblem = "Mail can't be managed: the Hub's mail secret is missing or too short"

// errMailSecret: every mail write answers it while the secret is bad.
var errMailSecret = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New(MailSecretProblem)}

// mailSecretInvalid: PORTCULLIS_MAIL=on but mailctl isn't configured
// (the secret file missing, unreadable or under 32 characters), read
// again at every call (a fixed file clears it without a restart).
func (h *Hub) mailSecretInvalid() bool {
	if !h.mailOn() {
		return false
	}
	h.mu.RLock()
	api := h.mailAPI
	h.mu.RUnlock()
	return api == nil || api.Available() != nil
}

// mailWriteGuard refuses a mail write while the secret is bad (503).
func (h *Hub) mailWriteGuard() error {
	if h.mailSecretInvalid() {
		return errMailSecret
	}
	return nil
}

// MailPasswordView is one mail password as people and admins see it
// (contract §19.9). Never a secret.
type MailPasswordView struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used"`
	Status    string     `json:"status"` // active | voided
}

// MyMailView is GET /api/me/mail.
type MyMailView struct {
	Addresses   []string           `json:"addresses"`
	Server      string             `json:"server"`
	IMAPS       int                `json:"imaps"`
	Submissions int                `json:"submissions"`
	Submission  int                `json:"submission"`
	Username    string             `json:"username"`
	Passwords   []MailPasswordView `json:"passwords"`
}

// CreatedMailPassword is a new mail password: the only copy of Password
// and of the profile carrying it. The caller zeroes both (Zero) once it
// has written its one answer.
type CreatedMailPassword struct {
	ID           string
	Password     []byte
	MobileConfig []byte
}

// Zero wipes the password and the profile.
func (c *CreatedMailPassword) Zero() {
	if c == nil {
		return
	}
	for i := range c.Password {
		c.Password[i] = 0
	}
	for i := range c.MobileConfig {
		c.MobileConfig[i] = 0
	}
}

// mailAccount is the caller's account in the document the directory
// builds now (nil, errNoMail: not in mail_users or mail off).
func (h *Hub) mailAccount(ctx context.Context, user string) (*mailctl.Account, *mailctl.MailState, error) {
	if h.mailClient() == nil {
		return nil, nil, errNoMail
	}
	doc, err := h.mailBuild(ctx)
	if err != nil {
		if _, ok := err.(*StatusError); ok {
			return nil, nil, err
		}
		// No document (the primary domain isn't on): nobody has mail.
		return nil, nil, errNoMail
	}
	for i := range doc.Accounts {
		if doc.Accounts[i].Username == user {
			return &doc.Accounts[i], doc, nil
		}
	}
	return nil, nil, errNoMail
}

// mailUp: mailctl reachable with the base plan in place (else 503).
func (h *Hub) mailUp(ctx context.Context) (MailAPI, error) {
	if h.mailSecretInvalid() {
		return nil, errMailSecret
	}
	api := h.mailClient()
	if api == nil {
		return nil, errMailDown
	}
	st, err := api.State(ctx)
	if err != nil || !st.Bootstrap {
		return nil, errMailDown
	}
	return api, nil
}

// MyMail is the caller's mail section (GET /api/me/mail): 404 for anyone
// not in mail_users or while mail is off; 503 when mailctl can't be
// read. Reconciles the caller's rows first.
func (h *Hub) MyMail(ctx context.Context, user string) (*MyMailView, error) {
	user = strings.ToLower(user)
	acct, _, err := h.mailAccount(ctx, user)
	if err != nil {
		return nil, err
	}
	api, err := h.mailUp(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.reconcileMailPasswords(ctx, api, user, acct.UUID); err != nil {
		return nil, err
	}
	return &MyMailView{Addresses: acct.Addresses, Server: h.mailCore().Hostname, IMAPS: mailIMAPSPort, Submissions: mailSubmissionsPort,
		Submission: mailSubmissionPort, Username: acct.Addresses[0], Passwords: h.MailPasswords(user, acct.UUID)}, nil
}

// MailPasswords are user's active and voided mail passwords (metadata
// only), newest first: only the rows created under uuid, the person's
// current account (a re-created username never sees the former holder's).
func (h *Hub) MailPasswords(user, uuid string) []MailPasswordView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []MailPasswordView{}
	for _, c := range h.st.MailCredentials[strings.ToLower(user)] {
		if uuid == "" || c.UUID != uuid {
			continue
		}
		status := ""
		switch {
		case c.Active():
			status = "active"
		case c.Reason == state.MailCredentialReasonVoidRestore:
			status = "voided"
		default:
			continue
		}
		out = append(out, MailPasswordView{ID: c.ID, Label: c.Label, CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, Status: status})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// mailLabelProblem: 1–64 characters on one line.
func mailLabelProblem(label string) string {
	n := utf8.RuneCountInString(label)
	if !utf8.ValidString(label) || n < 1 || n > 64 || strings.TrimSpace(label) == "" {
		return "the label must be 1 to 64 characters"
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f || r == ' ' || r == ' ' {
			return "the label must be one line of text"
		}
	}
	return ""
}

// mailExpiry is expiry's end time from now (nil: none).
func mailExpiry(expiry string, now time.Time) (*time.Time, bool) {
	var t time.Time
	switch expiry {
	case "none":
		return nil, true
	case "90d":
		t = now.Add(90 * 24 * time.Hour)
	case "1y":
		t = now.AddDate(1, 0, 0)
	default:
		return nil, false
	}
	return &t, true
}

func newMailCredentialID() string {
	var b [8]byte
	rand.Read(b[:])
	return "m" + hex.EncodeToString(b[:])
}

// CreateMailPassword creates one of user's mail passwords. Checks, in
// contract order (§5.1; the proof is consumed only at step 7): 1. the
// refusal limit (429); 2. mail running (503); 3. the caller in mail_users
// (the shared 404); 4. label and expiry (400); 5. fewer than 5 active
// (409); 6. the uuid (503); 7. the fresh-auth proof under the people core
// template (403 / 503); 8. mailctl; 9. the row, the audit, the answer.
func (h *Hub) CreateMailPassword(ctx context.Context, user, label, expiry string, p freshauth.Proof) (*CreatedMailPassword, error) {
	user = strings.ToLower(user)
	if !h.entryLimit.reserve(user, h.entryClock()) {
		return nil, errEntryLimited
	}
	cc, err := h.createMailPassword(ctx, user, label, expiry, p)
	h.entryLimit.release(user, h.entryClock(), isRefusal(err))
	return cc, err
}

func (h *Hub) createMailPassword(ctx context.Context, user, label, expiry string, p freshauth.Proof) (*CreatedMailPassword, error) {
	// 2. Mail running.
	api, err := h.mailUp(ctx)
	if err != nil {
		return nil, err
	}
	// 3. In mail_users (an unexpired membership; never the LLDAP admin).
	if h.mailClient() == nil {
		return nil, errNoMail
	}
	m, err := h.membership(ctx)
	if err != nil {
		return nil, err
	}
	if _, in := m.Users[user][MailUsersGroup]; !in || m.Expired[user][MailUsersGroup] || user == mailNeverAccount {
		return nil, errNoMail
	}
	// 4. Label and expiry.
	if why := mailLabelProblem(label); why != "" {
		return nil, statusErr(http.StatusBadRequest, "%s", why)
	}
	now := h.mailNow()
	expires, ok := mailExpiry(expiry, now)
	if !ok {
		return nil, statusErr(http.StatusBadRequest, "expiry must be none, 90d or 1y")
	}
	// 5. Fewer than 5 active (the rows reconciled with mailctl first;
	// only the current account's rows count).
	uuid := m.UUIDs[user]
	if uuid != "" {
		if err := h.reconcileMailPasswords(ctx, api, user, uuid); err != nil {
			return nil, err
		}
		if n := len(h.activeMailRowsOf(user, uuid)); n >= mailctl.MaxActivePasswords {
			return nil, statusErr(http.StatusConflict, "at most 5 mail passwords: revoke one first")
		}
	}
	// 6. The uuid (503), then the account in the document the directory
	// builds now (a reserved username has none: not ready).
	if uuid == "" {
		return nil, statusErr(http.StatusServiceUnavailable, "Users & Groups gave no account id for %s: try again later", user)
	}
	acct, _, err := h.mailAccount(ctx, user)
	if err != nil || acct.UUID != uuid {
		return nil, errMailNotReady
	}
	// The username's former account is still being removed: a pending
	// mass removal names it, or the last document mailctl accepted lists
	// it under another uuid (controller ruling, fail closed).
	if h.mailStillRemoving(user, uuid) {
		return nil, errMailStillRemoving(user)
	}
	// 7. The fresh-auth proof, governed by the people core template (the
	// Sign-in page's), audited with the reason only.
	if _, reason, err := h.checkFreshAuth(ctx, govCore("people"), p, user); err != nil {
		h.auditOp(directory.Human(user), "mail_credential.create", user, "reason="+reason, err)
		return nil, err
	}
	// The create and the mail sync take the same lock: under it, the
	// membership and the pending removal are checked again, so a removal
	// can't be refused (and its passwords revoked) between the check and
	// the create (L1).
	h.mailState.pass.Lock()
	defer h.mailState.pass.Unlock()
	m2, err := h.membership(ctx)
	if err != nil {
		return nil, err
	}
	if _, in := m2.Users[user][MailUsersGroup]; !in || m2.Expired[user][MailUsersGroup] || m2.UUIDs[user] != uuid {
		return nil, errNoMail
	}
	if h.mailStillRemoving(user, uuid) {
		return nil, errMailStillRemoving(user)
	}
	// 8. mailctl.
	created, err := api.CreateCredential(ctx, user, uuid, label, expires)
	if err != nil {
		created.Secret.Zero()
		var ae *mailctl.APIError
		if errors.As(err, &ae) && ae.Kind == mailctl.ErrorKindAccountMismatch {
			return nil, errMailStillRemoving(user)
		}
		switch mailctl.StatusOf(err) {
		case http.StatusConflict:
			return nil, statusErr(http.StatusConflict, "at most 5 mail passwords: revoke one first")
		case http.StatusBadRequest:
			return nil, statusErr(http.StatusBadRequest, "the label or expiry was refused")
		case http.StatusNotFound:
			return nil, errMailNotReady
		}
		log.Printf("mail: creating a mail password for %s: %v", user, err)
		return nil, errMailDown
	}
	// 9. The row, the audit, the answer.
	row := state.MailCredential{ID: newMailCredentialID(), StalwartID: created.ID, Label: label, UUID: acct.UUID,
		CreatedAt: created.CreatedAt.UTC(), ExpiresAt: created.ExpiresAt, CreatedBy: user}
	h.mu.Lock()
	// An older active row with the same Stalwart id and creation time
	// can't stand for a live password any more (the id was reused within
	// one second): it ends, so no row ever matches two passwords.
	for i, c := range h.st.MailCredentials[user] {
		if c.Active() && c.StalwartID == row.StalwartID && c.CreatedAt.Equal(row.CreatedAt) {
			t := now
			h.st.MailCredentials[user][i].RevokedAt, h.st.MailCredentials[user][i].Reason = &t, state.MailCredentialReasonMissing
		}
	}
	h.st.MailCredentials[user] = append(h.st.MailCredentials[user], row)
	saveErr := h.saveStateLocked()
	h.mu.Unlock()
	if saveErr != nil {
		// Never a password the Hub can't list: take it back.
		if rerr := api.RevokeCredential(context.WithoutCancel(ctx), uuid, created.ID); rerr != nil {
			log.Printf("mail: taking back %s's unrecorded mail password %s failed: %v", user, created.ID, rerr)
		}
		created.Secret.Zero()
		return nil, saveErr
	}
	h.auditOp(directory.Human(user), "mail_credential.create", user, fmt.Sprintf("id=%s label_length=%d", row.ID, utf8.RuneCountInString(label)), nil)
	pw := []byte(created.Secret)
	prof, err := mobileConfig(h.mailCore().Hostname, acct.Addresses[0], acct.DisplayName, label, pw)
	if err != nil {
		log.Printf("mail: the configuration profile for %s failed: %v", user, err)
		prof = nil
	}
	return &CreatedMailPassword{ID: row.ID, Password: pw, MobileConfig: prof}, nil
}

// activeMailRowsOf are user's active rows created under uuid.
func (h *Hub) activeMailRowsOf(user, uuid string) []state.MailCredential {
	var out []state.MailCredential
	for _, c := range h.activeMailRows(user) {
		if c.UUID == uuid {
			out = append(out, c)
		}
	}
	return out
}

// activeMailRows are user's active rows.
func (h *Hub) activeMailRows(user string) []state.MailCredential {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []state.MailCredential
	for _, c := range h.st.MailCredentials[user] {
		if c.Active() {
			out = append(out, c)
		}
	}
	return out
}

// matchLive is the live password row c stands for: the same Stalwart id
// and created_at, under the uuid the row was created with (a reused id
// never revives a row).
func matchLive(c state.MailCredential, uuid string, live []mailctl.Credential) bool {
	if c.UUID != uuid {
		return false
	}
	for _, l := range live {
		if l.ID == c.StalwartID && l.CreatedAt.Equal(c.CreatedAt) {
			return true
		}
	}
	return false
}

// reconcileMailPasswords matches user's active rows with mailctl's live
// passwords (contract §19.11): an active row with no live password ends
// as void_restore (a restore since it was created) or missing (logged);
// an expired one as expired. 404 (no account yet): nothing is live.
func (h *Hub) reconcileMailPasswords(ctx context.Context, api MailAPI, user, uuid string) error {
	if len(h.activeMailRows(user)) == 0 {
		return nil
	}
	live, err := api.Credentials(ctx, user)
	if mailctl.StatusOf(err) == http.StatusNotFound {
		live, err = nil, nil
	}
	if err != nil {
		return errMailDown
	}
	var restoredAt *time.Time
	needStatus := false
	for _, c := range h.activeMailRows(user) {
		if !matchLive(c, uuid, live) {
			needStatus = true
		}
	}
	if needStatus {
		st, err := api.Status(ctx)
		if err != nil {
			return errMailDown
		}
		restoredAt = st.RestoredAt
	}
	now := h.mailNow()
	h.mu.Lock()
	rows := h.st.MailCredentials[user]
	voided, changed := 0, false
	for i := range rows {
		c := &rows[i]
		if !c.Active() {
			continue
		}
		switch {
		case c.ExpiresAt != nil && !now.Before(*c.ExpiresAt):
			c.Reason = state.MailCredentialReasonExpired
		case matchLive(*c, uuid, live):
			continue
		case c.UUID != uuid:
			// The former holder of the username: they left.
			c.Reason = state.MailCredentialReasonRevokeLeave
		case restoredAt != nil && restoredAt.After(c.CreatedAt):
			c.Reason = state.MailCredentialReasonVoidRestore
			voided++
		default:
			c.Reason = state.MailCredentialReasonMissing
			log.Printf("mail: %s's mail password %s has no Stalwart password and no restore since it was created: ended (missing)", user, c.ID)
		}
		t := now
		c.RevokedAt = &t
		changed = true
	}
	var saveErr error
	if changed {
		saveErr = h.saveStateLocked()
	}
	h.mu.Unlock()
	if voided > 0 {
		h.auditOp(directory.Human("hub"), "mail_credential.void_restore", user, fmt.Sprintf("count=%d", voided), nil)
	}
	return saveErr
}

// reconcileAllMailPasswords reconciles everyone with active rows (at
// start, after the first accepted document).
func (h *Hub) reconcileAllMailPasswords(ctx context.Context, api MailAPI) {
	m, err := h.membership(ctx)
	if err != nil {
		return
	}
	h.mu.RLock()
	users := make([]string, 0, len(h.st.MailCredentials))
	for u := range h.st.MailCredentials {
		users = append(users, u)
	}
	h.mu.RUnlock()
	sort.Strings(users)
	for _, u := range users {
		if err := h.reconcileMailPasswords(ctx, api, u, m.UUIDs[u]); err != nil {
			log.Printf("mail: reconciling %s's mail passwords: %v", u, err)
		}
	}
}

// mailMarkLeft ends the active rows created under each removed account's
// uuid (revoke_leave: the holder left mail_users, was deleted or
// re-created), audited with the count.
func (h *Hub) mailMarkLeft(removed map[string]string) {
	now := h.mailNow()
	users := make([]string, 0, len(removed))
	for u := range removed {
		users = append(users, u)
	}
	sort.Strings(users)
	for _, u := range users {
		h.mu.Lock()
		n := 0
		rows := h.st.MailCredentials[u]
		for i := range rows {
			if rows[i].Active() && rows[i].UUID == removed[u] {
				t := now
				rows[i].RevokedAt, rows[i].Reason = &t, state.MailCredentialReasonRevokeLeave
				n++
			}
		}
		if n > 0 {
			h.saveLocked()
		}
		h.mu.Unlock()
		if n > 0 {
			h.auditOp(directory.Human("hub"), "mail_credential.revoke_leave", u, fmt.Sprintf("count=%d", n), nil)
		}
	}
}

// RevokeOwnMailPassword revokes one of the caller's mail passwords (by
// the Hub's id): 204 also when it was already gone; another person's id
// is 404.
func (h *Hub) RevokeOwnMailPassword(ctx context.Context, user, id string) error {
	user = strings.ToLower(user)
	return h.revokeMailPassword(ctx, user, id, directory.Human(user))
}

// AdminRevokeMailPassword revokes one of user's mail passwords for an
// administrator or a sign_in_help holder (the route checks who; contract
// §19.9). Admins revoke, never create.
func (h *Hub) AdminRevokeMailPassword(ctx context.Context, user, id string, actor directory.Actor) error {
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusBadRequest, "no signed-in user to audit the change as")
	}
	return h.revokeMailPassword(ctx, strings.ToLower(user), id, actor)
}

func (h *Hub) revokeMailPassword(ctx context.Context, user, id string, actor directory.Actor) (err error) {
	defer func() {
		if err != nil && isRefusal(err) {
			return
		}
		h.auditOp(actor, "mail_credential.revoke", user, "id="+id+" actor="+actor.User, err)
	}()
	h.mu.RLock()
	var row *state.MailCredential
	for _, c := range h.st.MailCredentials[user] {
		if c.ID == id {
			c := c
			row = &c
		}
	}
	h.mu.RUnlock()
	if row == nil {
		return errNoMailPassword
	}
	if !row.Active() {
		return nil
	}
	// The username's current account (it may have been re-created with a
	// new uuid since the row was made).
	m, err := h.membership(ctx)
	if err != nil {
		return err
	}
	cur := m.UUIDs[user]
	if cur == "" {
		// The username isn't known (yet): decide nothing (fail closed).
		return errMailNotReady
	}
	api, err := h.mailUp(ctx)
	if err != nil {
		return err
	}
	if cur != row.UUID {
		// The row's holder is gone (the username was re-created): revoke
		// it in the former account (by its uuid, parked or not); the row
		// ends only on mailctl's 204.
		if err := api.RevokeCredential(ctx, row.UUID, row.StalwartID); err != nil {
			log.Printf("mail: revoking %s's former mail password %s: %v", user, id, err)
			return errMailNotReady
		}
		return h.endMailRow(user, id, actor.User, state.MailCredentialReasonRevokeLeave)
	}
	// Delete only the password this row stands for: a reused Stalwart id
	// may name a newer password now.
	live, lerr := api.Credentials(ctx, user)
	if lerr != nil && mailctl.StatusOf(lerr) != http.StatusNotFound {
		return errMailDown
	}
	if matchLive(*row, cur, live) {
		// Marked only after mailctl destroyed it; a failure leaves the
		// row active (503).
		if err := api.RevokeCredential(ctx, row.UUID, row.StalwartID); err != nil {
			log.Printf("mail: revoking %s's mail password %s: %v", user, id, err)
			return errMailDown
		}
	}
	// Not live (mailctl's list is the confirmation: it is gone already).
	saveErr := h.endMailRow(user, id, actor.User, state.MailCredentialReasonRevoked)
	// Stalwart keeps sessions opened with it alive: restart mail.
	h.goBackground(func() {
		rctx, cancel := context.WithTimeout(context.Background(), mailRestartTimeout+5*time.Second)
		defer cancel()
		h.mailRestart(rctx, "a revoked mail password")
	})
	return saveErr
}

// mobileConfig is an unsigned Apple configuration profile for the
// account (com.apple.mail.managed: IMAP host:993 SSL, SMTP host:465 SSL,
// the login for both, the password for both). The password is never put
// in a Go string: the profile is rendered with a random slot and the
// password's XML-escaped bytes copied into a fresh buffer; every
// intermediate buffer is zeroed.
func mobileConfig(host, login, displayName, label string, pw []byte) ([]byte, error) {
	var slotB [16]byte
	rand.Read(slotB[:])
	slot := "PORTCULLIS-SLOT-" + hex.EncodeToString(slotB[:])
	uuid := func() string {
		var b [16]byte
		rand.Read(b[:])
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		x := hex.EncodeToString(b[:])
		return strings.ToUpper(x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:])
	}
	if displayName == "" {
		displayName = login
	}
	acct := map[string]any{
		"PayloadType":                            "com.apple.mail.managed",
		"PayloadVersion":                         1,
		"PayloadIdentifier":                      "portcullis.mail." + login + ".account",
		"PayloadUUID":                            uuid(),
		"PayloadDisplayName":                     "Mail: " + login,
		"EmailAccountDescription":                login + " (" + label + ")",
		"EmailAccountName":                       displayName,
		"EmailAccountType":                       "EmailTypeIMAP",
		"EmailAddress":                           login,
		"IncomingMailServerAuthentication":       "EmailAuthPassword",
		"IncomingMailServerHostName":             host,
		"IncomingMailServerPortNumber":           mailIMAPSPort,
		"IncomingMailServerUseSSL":               true,
		"IncomingMailServerUsername":             login,
		"IncomingPassword":                       slot,
		"OutgoingMailServerAuthentication":       "EmailAuthPassword",
		"OutgoingMailServerHostName":             host,
		"OutgoingMailServerPortNumber":           mailSubmissionsPort,
		"OutgoingMailServerUseSSL":               true,
		"OutgoingMailServerUsername":             login,
		"OutgoingPassword":                       slot,
		"OutgoingPasswordSameAsIncomingPassword": true,
	}
	prof := map[string]any{
		"PayloadContent":     []any{acct},
		"PayloadDisplayName": "Mail for " + login,
		"PayloadIdentifier":  "portcullis.mail." + login,
		"PayloadType":        "Configuration",
		"PayloadUUID":        uuid(),
		"PayloadVersion":     1,
	}
	tmpl, err := plist.MarshalIndent(prof, plist.XMLFormat, "  ")
	if err != nil {
		return nil, err
	}
	// esc never grows (5 bytes per input byte at most), so no abandoned
	// copy; it is zeroed on every path.
	var esc bytes.Buffer
	esc.Grow(len(pw) * 5)
	defer func() {
		b := esc.Bytes()
		b = b[:cap(b)]
		for i := range b {
			b[i] = 0
		}
	}()
	for _, c := range pw {
		switch c {
		case '&':
			esc.WriteString("&amp;")
		case '<':
			esc.WriteString("&lt;")
		case '>':
			esc.WriteString("&gt;")
		default:
			if c < 0x20 || c == 0x7f {
				return nil, errors.New("the password has a control byte")
			}
			esc.WriteByte(c)
		}
	}
	// One allocation of the final size (bytes.ReplaceAll counts first).
	return bytes.ReplaceAll(tmpl, []byte(slot), esc.Bytes()), nil
}

// endMailRow ends user's active row id with reason (by: revoked_by).
func (h *Hub) endMailRow(user, id, by, reason string) error {
	now := h.mailNow()
	h.mu.Lock()
	defer h.mu.Unlock()
	rows := h.st.MailCredentials[user]
	for i := range rows {
		if rows[i].ID == id && rows[i].Active() {
			rows[i].RevokedAt, rows[i].RevokedBy, rows[i].Reason = &now, by, reason
		}
	}
	return h.saveStateLocked()
}

// errMailStillRemoving: the username's former account is still being
// removed.
func errMailStillRemoving(user string) error {
	return statusErr(http.StatusConflict, "mail for %s is still being removed: try again after the removal", user)
}

// mailStillRemoving: user is in the pending mass removal, or the last
// accepted document lists user under a uuid other than uuid.
func (h *Hub) mailStillRemoving(user, uuid string) bool {
	h.mu.RLock()
	p := h.st.Mail.PendingRemoval
	if p != nil {
		for _, a := range p.Accounts {
			if a.Username == user {
				h.mu.RUnlock()
				return true
			}
		}
	}
	h.mu.RUnlock()
	s := &h.mailState
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last == nil {
		last, _ = h.loadMailLast()
	}
	if last != nil {
		for _, a := range last.Accounts {
			if a.Username == user && a.UUID != uuid {
				return true
			}
		}
	}
	return false
}
