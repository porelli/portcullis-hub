package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	netmail "net/mail"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// App mail senders and Portcullis's own sender (contract §19.14). Every
// MailState lists, as senders, each enabled instance whose template
// declares mail_sender (portcullis-app-<instance>) and, while a provider
// is wired and mail is on, the Hub's own (portcullis-hub-mail). Each has
// a Hub-generated v4 uuid in state.yaml mail_senders, kept across syncs
// and replaced only when the sender is voided (wiring, switching, a
// restore: raiseVoidDebtLocked; an unwire drops them). After an accepted
// document the Hub makes sure each has a live credential (POST
// /v1/credentials, without allowed_ips); the passwords are kept in one
// 0600 file on hub_secrets (senderStoreFile), never in state.yaml, a log,
// the audit, an error or argv. A new password is written into the
// instance's .env (the five PORTCULLIS_MAIL_SENDER_* variables) and the
// instance restarts.

const (
	// senderHubUsername is Portcullis's own sender; senderAppPrefix
	// starts an app's (portcullis-app-<instance>).
	senderHubUsername = "portcullis-hub-mail"
	senderAppPrefix   = "portcullis-app-"
	// senderHubLabel is the Hub's sender label (its From: name).
	senderHubLabel = "Portcullis"
	// senderPort is the submission port (STARTTLS) senders use.
	senderPort = 587
	// senderStoreFile is the senders' passwords on hub_secrets (key →
	// password; a name no instance id can take, kept by the reconcile).
	senderStoreFile = ".mail-senders.json"
)

// senderUsernameRe is a sender username the provider accepts (contract
// §19.5; mailctl's state.ValidSenderUsername).
var senderUsernameRe = regexp.MustCompile(`^portcullis-(hub-mail|app-[a-z][a-z0-9-]{0,31})$`)

// senderUsername is key's sender username (key: an instance id or
// state.MailSenderHub).
func senderUsername(key string) string {
	if key == state.MailSenderHub {
		return senderHubUsername
	}
	return senderAppPrefix + key
}

// appSenderKey: id may key an app's sender — a template or instance id,
// never the Hub's own key (defence in depth: ids can't take it).
func appSenderKey(id string) bool {
	return id != state.MailSenderHub && templates.ValidID(id) && templates.CheckIDShape(id) == nil
}

// storedSender is a sender with its password (senderEnv's input).
type storedSender struct {
	Username, Address, Password string
}

// senderWantedLocked are the senders the documents list now: key →
// label. Caller holds mu.
func (h *Hub) senderWantedLocked() map[string]string {
	out := map[string]string{}
	if h.st.Mail.Provider == nil {
		return out
	}
	// The Hub's own sender only while mail is on (§19.14).
	if h.mailCore().On {
		out[state.MailSenderHub] = senderHubLabel
	}
	ids := slices.Clone(h.st.Enabled)
	for id := range h.senderEnabling {
		ids = append(ids, id)
	}
	for _, id := range ids {
		t := h.findLocked(id)
		if t == nil || t.Manifest.MailSender == nil || h.kubeOn() || !appSenderKey(id) {
			continue
		}
		if !senderUsernameRe.MatchString(senderUsername(id)) {
			continue
		}
		out[id] = t.Manifest.MailSender.Label
	}
	return out
}

// senderEnableWait bounds how long an enable waits for its instance's
// sender (enableSender); its passes are senderEnablePoll apart at first,
// doubling up to senderEnablePollMax (variables for the tests).
var (
	senderEnableWait    = 3 * time.Minute
	senderEnablePoll    = 2 * time.Second
	senderEnablePollMax = 30 * time.Second
)

// enableSender prepares the sender of instance id before its first start
// (contract §19.14): an app that sends its mail through the provider may
// refuse to start without the five PORTCULLIS_MAIL_SENDER_* values
// (firefox-sync-fxa's fxa-mail-check), and senders exist only for
// enabled instances, so the first start would always fail and the
// instance never become enabled. While a provider is wired and mail is
// on, precheck (the enable's own refusals, so a 409 comes back at once
// and no sender is made for it) runs first; then the instance's sender
// is wanted from now on (senderEnabling) and mail passes run here until
// it has a password (written into its .env by
// ensureSenderCredentialWith), within senderEnableWait, backing off
// between passes. A pass carries everyone's pending changes (a removal
// and its restart, §19.5), so it runs to its end whatever the enable's
// ctx says (mail_wire.go's rule): a Stop ends the wait between passes.
// done ends it all (the enable's commit makes the instance wanted as
// enabled; a failed enable drops the sender at the next pass). Nothing
// to do (no mail_sender, mail off or unwired, Kubernetes, already
// enabled): done is a no-op and the start goes on as before (the app
// decides).
func (h *Hub) enableSender(ctx context.Context, id string, precheck func() error) (done func(), err error) {
	noop := func() {}
	h.mu.Lock()
	t := h.findLocked(id)
	if t == nil || t.Manifest.MailSender == nil || h.kubeOn() || !appSenderKey(id) ||
		!senderUsernameRe.MatchString(senderUsername(id)) || h.st.Mail.Provider == nil ||
		h.st.IsEnabled(id) || !h.mailCore().On {
		h.mu.Unlock()
		return noop, nil
	}
	h.mu.Unlock()
	if precheck != nil {
		if err := precheck(); err != nil {
			return noop, err
		}
	}
	h.mu.Lock()
	if h.senderEnabling == nil {
		h.senderEnabling = map[string]bool{}
	}
	h.senderEnabling[id] = true
	ready := h.storedSenderLocked(id) != nil
	h.mu.Unlock()
	done = func() {
		h.mu.Lock()
		delete(h.senderEnabling, id)
		enabled := h.st.IsEnabled(id)
		h.mu.Unlock()
		if !enabled {
			// Not started after all: its sender goes at the next pass.
			h.TriggerMailSync()
		}
	}
	stopped := func() (func(), error) {
		done()
		return noop, fmt.Errorf("stopped while waiting for the mail sender %s: %w", senderUsername(id), ctx.Err())
	}
	deadline := time.Now().Add(senderEnableWait)
	poll := senderEnablePoll
	for !ready {
		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mailSyncTimeout)
		h.mailSyncOnce(pctx)
		cancel()
		h.mu.RLock()
		ready = h.storedSenderLocked(id) != nil
		h.mu.RUnlock()
		if ready {
			break
		}
		if ctx.Err() != nil {
			return stopped()
		}
		left := time.Until(deadline)
		if left <= 0 {
			done()
			why := ""
			if b := h.MailSyncBlocked(); b != "" {
				why = "; mail's sync is held: " + b
			}
			return noop, statusErr(http.StatusServiceUnavailable,
				"%s sends its mail through the mail provider, which gave its mail sender (%s) no password within %s%s: not started (see Settings → Mail and the doctor)",
				id, senderUsername(id), senderEnableWait, why)
		}
		select {
		case <-ctx.Done():
			return stopped()
		case <-time.After(min(poll, left)):
		}
		poll = min(2*poll, senderEnablePollMax)
	}
	return done, nil
}

// kickMailSendersLocked triggers a mail sync when the enabled
// mail_sender instances (or their labels) changed since the last rebuild
// (an enable, a disable, a delete, a template update adding or dropping
// mail_sender): their senders are created and removed promptly. Caller
// holds mu (write).
func (h *Hub) kickMailSendersLocked() {
	var b strings.Builder
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil && t.Manifest.MailSender != nil {
			b.WriteString(id + "\x00" + t.Manifest.MailSender.Label + "\x00")
		}
	}
	if sig := b.String(); sig != h.mailSenderSig {
		h.mailSenderSig = sig
		h.TriggerMailSync()
	}
}

// senderLabelLocked is key's label ("" = not a wanted sender).
func (h *Hub) senderLabelLocked(key string) string {
	return h.senderWantedLocked()[key]
}

// mailEnsureSendersLocked gives every wanted sender an entry (a fresh v4
// uuid) and drops every other entry with its password (a disabled or
// deleted instance: the next document removes its account). changed:
// state.yaml must be saved. Caller holds mu (write).
func (h *Hub) mailEnsureSendersLocked() bool {
	want := h.senderWantedLocked()
	changed := false
	if h.st.MailSenders == nil {
		h.st.MailSenders = map[string]state.MailSender{}
	}
	var dropped []string
	for key := range h.st.MailSenders {
		if _, ok := want[key]; !ok {
			delete(h.st.MailSenders, key)
			dropped = append(dropped, key)
			changed = true
		}
	}
	for key := range want {
		if _, ok := h.st.MailSenders[key]; !ok {
			h.st.MailSenders[key] = state.MailSender{UUID: uuid.NewString()}
			changed = true
		}
	}
	if len(dropped) > 0 {
		if err := h.dropSenderPasswordsLocked(dropped...); err != nil {
			log.Printf("mail: dropping the passwords of former senders: %v", err)
		}
	}
	return changed
}

// mailSendersLocked is the senders of the next document: every entry
// that is still wanted, sorted by username. Caller holds mu.
func (h *Hub) mailSendersLocked() []mailprovider.Sender {
	want := h.senderWantedLocked()
	primary := mailPrimary(h.st.Mail, h.cfg.Domain)
	out := []mailprovider.Sender{}
	for key, e := range h.st.MailSenders {
		if _, ok := want[key]; !ok || e.UUID == "" {
			continue
		}
		u := senderUsername(key)
		out = append(out, mailprovider.Sender{Username: u, UUID: e.UUID, Address: u + "@" + primary})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// voidSendersLocked forgets every sender (a void: wiring, switching, a
// restore; an unwire): new uuids at the next document, the passwords
// gone and the instances' five variables emptied now (their restart
// comes with the new password). changed: the caller saves. Caller holds
// mu (write).
func (h *Hub) voidSendersLocked() bool {
	if len(h.st.MailSenders) == 0 {
		return false
	}
	keys := make([]string, 0, len(h.st.MailSenders))
	for key := range h.st.MailSenders {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h.st.MailSenders = map[string]state.MailSender{}
	if err := h.dropSenderPasswordsLocked(keys...); err != nil {
		log.Printf("mail: voiding the senders' passwords: %v", err)
	}
	for _, key := range keys {
		if key == state.MailSenderHub || !appSenderKey(key) {
			continue
		}
		if t := h.findLocked(key); t != nil {
			if err := h.writeSenderEnvLocked(t); err != nil {
				log.Printf("mail: emptying %s's mail sender variables: %v", key, err)
			}
		}
	}
	return true
}

// ── the password store (hub_secrets) ───────────────────

// senderPasswordsLocked is the store (missing = none). Errors never
// quote it. Caller holds mu.
func (h *Hub) senderPasswordsLocked() (map[string]string, error) {
	r, err := h.openSecrets()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := r.ReadFile(senderStoreFile)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, errors.New("reading the mail senders' passwords failed")
	}
	defer clear(b)
	out := map[string]string{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, errors.New("the mail senders' password store is not a JSON object of strings")
	}
	return out, nil
}

// writeSenderPasswordsLocked replaces the store (empty: removed).
func (h *Hub) writeSenderPasswordsLocked(vals map[string]string) error {
	r, err := h.openSecrets()
	if err != nil {
		return err
	}
	defer r.Close()
	if len(vals) == 0 {
		if err := r.Remove(senderStoreFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return errors.New("removing the mail senders' password store failed")
		}
		return nil
	}
	b, err := json.Marshal(vals)
	if err != nil {
		return errors.New("encoding the mail senders' password store failed")
	}
	defer clear(b)
	if err := writeRootAtomic(r, senderStoreFile, b); err != nil {
		return errors.New("writing the mail senders' password store failed")
	}
	return nil
}

// dropSenderPasswordsLocked removes keys' passwords from the store.
func (h *Hub) dropSenderPasswordsLocked(keys ...string) error {
	vals, err := h.senderPasswordsLocked()
	if err != nil {
		if h.secretsBaseErr() != nil {
			return nil // no store: nothing kept
		}
		return err
	}
	n := len(vals)
	for _, k := range keys {
		delete(vals, k)
	}
	if len(vals) == n {
		return nil
	}
	return h.writeSenderPasswordsLocked(vals)
}

// storedSenderLocked is key's sender with its password (nil: no entry,
// no credential or no password). Caller holds mu.
func (h *Hub) storedSenderLocked(key string) *storedSender {
	if key != state.MailSenderHub && !appSenderKey(key) {
		return nil
	}
	e, ok := h.st.MailSenders[key]
	if !ok || e.CredentialID == "" || h.st.Mail.Provider == nil {
		return nil
	}
	vals, err := h.senderPasswordsLocked()
	if err != nil || vals[key] == "" {
		return nil
	}
	u := senderUsername(key)
	return &storedSender{Username: u, Address: u + "@" + mailPrimary(h.st.Mail, h.cfg.Domain), Password: vals[key]}
}

// ── the instance environment ───────────────────────────

// senderEnv is the five PORTCULLIS_MAIL_SENDER_* variables of sender key
// (contract §19.14): all empty while no provider is wired or mail is off
// (s nil: no credential yet), else HOST = MAIL_HOSTNAME, PORT 587
// (STARTTLS), USER the address, PASSWORD the credential's and FROM
// "<label> <address>".
func senderEnv(key string, s *storedSender, mc mailCoreEnv, label string) map[string]string {
	out := map[string]string{}
	for _, k := range templates.MailSenderVars {
		out[k] = ""
	}
	if s == nil || !mc.On || mc.Hostname == "" || s.Password == "" || key == "" {
		return out
	}
	out[templates.VarMailSenderHost] = mc.Hostname
	out[templates.VarMailSenderPort] = fmt.Sprint(senderPort)
	out[templates.VarMailSenderUser] = s.Address
	out[templates.VarMailSenderPassword] = s.Password
	out[templates.VarMailSenderFrom] = senderFrom(label, s.Address)
	return out
}

// senderFrom is FROM: an RFC 5322 name-addr, the label quoted (or RFC
// 2047-encoded) as needed. A label with " would be quoted with \, which
// the single-quoted .env can't carry: it is RFC 2047-encoded instead
// (base64), so the value never holds a backslash or a quote.
func senderFrom(label, addr string) string {
	if strings.ContainsAny(label, `"\`) {
		return "=?utf-8?b?" + base64.StdEncoding.EncodeToString([]byte(label)) + "?= <" + addr + ">"
	}
	return (&netmail.Address{Name: label, Address: addr}).String()
}

// senderEnvForLocked is t's five variables (nil: t has no mail_sender,
// or the Hub runs on Kubernetes, where mail isn't available: §11.10).
// Caller holds mu.
func (h *Hub) senderEnvForLocked(t *templates.Template) map[string]string {
	if t == nil || t.Manifest.MailSender == nil || h.kubeOn() {
		return nil
	}
	if !appSenderKey(t.ID) {
		// Never the Hub's own sender: the five stay empty.
		return senderEnv("", nil, mailCoreEnv{}, "")
	}
	return senderEnv(t.ID, h.storedSenderLocked(t.ID), h.mailCore(), t.Manifest.MailSender.Label)
}

// writeSenderEnvLocked writes t's five variables into its existing .env
// (single-quoted; a missing .env: nothing, enable writes it whole).
func (h *Hub) writeSenderEnvLocked(t *templates.Template) error {
	vars := h.senderEnvForLocked(t)
	return rewriteEnvPrefix(h.envPath(t.ID), templates.VarMailSenderPrefix, vars)
}

// ── credentials ────────────────────────────────────────

// ensureSenderCredential makes sure sender key has a live credential
// with its password stored: an existing one is checked against the
// provider's list; a missing one (or one the provider no longer holds)
// is created. changed: a new password (an app instance then restarts).
func (h *Hub) ensureSenderCredential(ctx context.Context, key string) (changed bool, err error) {
	api := h.mailClient()
	if api == nil {
		return false, errMailNotWired
	}
	return h.ensureSenderCredentialWith(ctx, api, key)
}

func (h *Hub) ensureSenderCredentialWith(ctx context.Context, api MailAPI, key string) (bool, error) {
	h.mu.Lock()
	e, ok := h.st.MailSenders[key]
	label := h.senderLabelLocked(key)
	var have bool
	if ok && e.CredentialID != "" {
		vals, err := h.senderPasswordsLocked()
		if err != nil {
			h.mu.Unlock()
			return false, err
		}
		have = vals[key] != ""
	}
	h.mu.Unlock()
	if !ok || label == "" {
		return false, nil
	}
	username := senderUsername(key)
	if have {
		live, err := api.Credentials(ctx, e.UUID)
		if err != nil && mailprovider.StatusOf(err) != http.StatusNotFound {
			return false, fmt.Errorf("listing the sender %s's password: %v", username, err)
		}
		if slices.ContainsFunc(live, func(c mailprovider.Credential) bool { return c.ID == e.CredentialID }) {
			return false, nil
		}
	}
	if e.CredentialID != "" {
		if err := api.RevokeCredential(ctx, e.UUID, e.CredentialID); err != nil {
			log.Printf("mail: revoking the sender %s's former password: %v", username, err)
		}
	}
	c, err := api.CreateCredential(ctx, username, e.UUID, label, nil)
	if err != nil {
		return false, fmt.Errorf("creating the sender %s's password: %v", username, err)
	}
	defer clear(c.Secret)
	revoke := func() {
		if err := api.RevokeCredential(context.WithoutCancel(ctx), e.UUID, c.ID); err != nil {
			log.Printf("mail: revoking the sender %s's unused password: %v", username, err)
		}
	}
	secret := string(c.Secret)
	if _, qerr := envQuote(secret); qerr != nil || len(c.Secret) == 0 {
		revoke()
		return false, fmt.Errorf("the provider's password for the sender %s can't be written to an .env: revoked", username)
	}
	h.mu.Lock()
	cur, ok := h.st.MailSenders[key]
	if !ok || cur.UUID != e.UUID {
		h.mu.Unlock()
		revoke()
		return false, fmt.Errorf("the sender %s was voided meanwhile", username)
	}
	if cur.CredentialID != e.CredentialID {
		// Another run gave it a password meanwhile: that one stays.
		h.mu.Unlock()
		revoke()
		return false, nil
	}
	vals, err := h.senderPasswordsLocked()
	if err == nil {
		vals[key] = secret
		err = h.writeSenderPasswordsLocked(vals)
	}
	if err != nil {
		h.mu.Unlock()
		revoke()
		return false, err
	}
	at := h.mailNow().UTC()
	cur.CredentialID, cur.CreatedAt = c.ID, &at
	h.st.MailSenders[key] = cur
	if err := h.saveStateLocked(); err != nil {
		log.Printf("mail: saving the sender %s: %v", username, err)
	}
	if key != state.MailSenderHub && appSenderKey(key) {
		if t := h.findLocked(key); t != nil {
			if err := h.writeSenderEnvLocked(t); err != nil {
				log.Printf("mail: writing %s's mail sender variables: %v", key, err)
			}
		}
	}
	h.mu.Unlock()
	// The key only: never the password.
	h.auditOp(directory.Actor{User: purgeActor}, "mail_sender.created", key, "", nil)
	return true, nil
}

// mailSyncSenders gives the senders of doc (the document just accepted,
// generation gen, or with accepted false the unchanged last one) that
// have no credential yet one (after an accepted document, once it
// applied): no provider call for a sender that has one, so the pass is
// never slowed (the background reconcile checks those: mailVerifySenders).
// An app whose password changed restarts.
func (h *Hub) mailSyncSenders(ctx context.Context, api MailAPI, doc *mailprovider.MailState, gen int, accepted bool) error {
	if doc == nil || doc.Senders == nil || len(*doc.Senders) == 0 {
		return nil
	}
	h.mu.RLock()
	byUser := map[string]string{}
	for key := range h.st.MailSenders {
		byUser[senderUsername(key)] = key
	}
	vals, _ := h.senderPasswordsLocked()
	var todo []string
	for _, s := range *doc.Senders {
		key, ok := byUser[s.Username]
		if !ok || h.st.MailSenders[key].UUID != s.UUID {
			continue
		}
		if h.st.MailSenders[key].CredentialID == "" || vals[key] == "" {
			todo = append(todo, key)
		}
	}
	h.mu.RUnlock()
	clear(vals)
	if len(todo) == 0 {
		return nil
	}
	if accepted {
		h.mailWaitApplied(ctx, api, gen)
	}
	return h.mailEnsureSenders(ctx, api, todo)
}

// mailVerifySenders checks every sender that has a credential against the
// provider's list (the background reconcile: at start and after a
// provider restore), replacing one it no longer holds.
func (h *Hub) mailVerifySenders(ctx context.Context, api MailAPI) error {
	h.mu.RLock()
	var todo []string
	for key, e := range h.st.MailSenders {
		if e.CredentialID != "" {
			todo = append(todo, key)
		}
	}
	h.mu.RUnlock()
	sort.Strings(todo)
	return h.mailEnsureSenders(ctx, api, todo)
}

// mailEnsureSenders runs ensureSenderCredentialWith for each key and
// restarts each app whose password changed.
func (h *Hub) mailEnsureSenders(ctx context.Context, api MailAPI, todo []string) error {
	var first error
	var restart []string
	for _, key := range todo {
		changed, err := h.ensureSenderCredentialWith(ctx, api, key)
		if err != nil && first == nil {
			first = err
		}
		if changed && key != state.MailSenderHub && appSenderKey(key) {
			restart = append(restart, key)
		}
	}
	for _, id := range restart {
		if h.IsEnabled(id) {
			h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
		}
	}
	return first
}

// mailSendersUnwiredLocked are the enabled instances whose template has
// mail_sender while no provider is wired or mail is off (doctor
// mail_sender_unwired), sorted. Caller holds mu.
func (h *Hub) mailSendersUnwiredLocked(mailOn bool) []string {
	// Mail can't be wired on Kubernetes (§19.12): nothing to fix there.
	if (mailOn && h.st.Mail.Provider != nil) || h.kubeOn() {
		return nil
	}
	var out []string
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil && t.Manifest.MailSender != nil {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
