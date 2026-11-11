package hub

// Help to reset and the administrator's actions on someone else's
// sign-in (contract §9.6 sign_in_help, §9.7 "Person's Sign-in routes",
// plan D32): the person's Sign-in tab (the view and the history), the
// revocation of one of their certificates (administrators and
// sign_in_help holders) and the issue of a YubiKey certificate from a
// CSR (administrators only, with D26's fresh sign-in). Who may act on
// whom is the directory's decision (CheckHelp: an administrator, or a
// holder for whom checkDelegateTarget passes on a fresh snapshot); the
// certificate routes also refuse administrator targets and the
// protected names for everyone (409), before enroll is reached.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
)

// SignInHelp is the directory's decision on who may act on another
// person's sign-in (directory.Service.CheckHelp). Network calls: never
// call it holding mu.
type SignInHelp interface {
	CheckHelp(ctx context.Context, c *directory.Caller, target string) error
}

// SetSignInHelp wires the directory's help decision (main: the
// directory; nil: every person's Sign-in route is 503).
func (h *Hub) SetSignInHelp(s SignInHelp) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.signInHelp = s
}

func (h *Hub) signInHelpOrNil() SignInHelp {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.signInHelp
}

// HelpCan are the actions the caller may take on the person
// (PersonSignIn.Can, contract §9.7).
type HelpCan struct {
	SetupLink      bool `json:"setup_link"`
	RemovePasskeys bool `json:"remove_passkeys"`
	Revoke         bool `json:"revoke"`
	Issue          bool `json:"issue"`
	Password       bool `json:"password"`
}

// PersonSignIn is GET /api/directory/users/{u}/signin's answer: the
// person's Sign-in view exactly as theirs (MySignIn) plus what the
// caller may do.
type PersonSignIn struct {
	MySignIn
	Can HelpCan `json:"can"`
}

var (
	// errAdminCertsServer: an administrator's certificates are never
	// issued or revoked from the Hub (D32, F14); the CLI recovers.
	errAdminCertsServer = &StatusError{Status: http.StatusConflict, Err: errors.New("administrators' certificates are managed from the server: ./portcullis cert revoke <serial>")}
	errHelpUnavailable  = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("users & groups is not available")}
	errNoHelpCaller     = &StatusError{Status: http.StatusUnauthorized, Err: errors.New("no signed-in user")}
	errIssueAdminsOnly  = &StatusError{Status: http.StatusForbidden, Err: errors.New("not allowed: admins only")}
)

// helpTarget is the person a route names, lowercased (400 when it isn't
// an LLDAP username).
func helpTarget(user string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(user))
	if !lldap.ValidUsername(u) {
		return "", statusErr(http.StatusBadRequest, "not a valid username")
	}
	return u, nil
}

// checkHelp is CheckHelp as a StatusError: 401 without a caller, 403
// with the directory's text, 503 while it can't decide.
func (h *Hub) checkHelp(ctx context.Context, c *directory.Caller, u string) error {
	if c == nil || strings.TrimSpace(c.User) == "" {
		return errNoHelpCaller
	}
	sh := h.signInHelpOrNil()
	if sh == nil {
		return errHelpUnavailable
	}
	if err := sh.CheckHelp(ctx, c, u); err != nil {
		return dirStatusErr("deciding whether "+c.User+" may help "+u, err)
	}
	return nil
}

// helpPerson checks c may help user and that user is a person (404
// otherwise); it answers the target and the directory snapshot.
func (h *Hub) helpPerson(ctx context.Context, c *directory.Caller, user string) (string, *directory.Membership, error) {
	u, err := helpTarget(user)
	if err != nil {
		return "", nil, err
	}
	if err := h.checkHelp(ctx, c, u); err != nil {
		return u, nil, err
	}
	m, err := h.membership(ctx)
	if err != nil {
		return u, nil, err
	}
	if _, ok := m.UUIDs[u]; !ok {
		return u, nil, statusErr(http.StatusNotFound, "no such person: %s", u)
	}
	return u, m, nil
}

// PersonSignInView is user's Sign-in view for c (contract §9.7): an
// administrator, or a sign_in_help holder who may target user (403
// otherwise); 404 for an unknown person. FreshAuth is the people
// listener's (the route sets its own listener's). Can: for
// administrators everything, except setup_link, issue and revoke on an
// administrator target (core refuses their invites; the certificate
// routes refuse them) and what the protected names refuse (D13, D32);
// for a holder setup_link, remove_passkeys and revoke.
func (h *Hub) PersonSignInView(ctx context.Context, c *directory.Caller, user string) (*PersonSignIn, error) {
	u, m, err := h.helpPerson(ctx, c, user)
	if err != nil {
		return nil, err
	}
	v, err := h.MySignInView(ctx, u)
	if err != nil {
		return nil, err
	}
	return &PersonSignIn{MySignIn: *v, Can: h.helpCan(c, m, u)}, nil
}

// helpCan is what c may do on u, exactly as the routes answer (review
// I2): a holder sets up, removes passkeys and revokes, never sets a
// password or issues; an administrator does everything, except on an
// administrator target (no setup link, issue or revoke: core refuses
// invites, the certificate routes refuse them), on a protected name
// (admin, portcullis-hub, portcullis-*: no setup link, revoke, issue
// or password — SetPassword and enroll refuse them; admin and
// portcullis-hub not even passkeys, checkTarget) and issue while
// yubikey_cert is off.
func (h *Hub) helpCan(c *directory.Caller, m *directory.Membership, u string) HelpCan {
	can := HelpCan{SetupLink: true, RemovePasskeys: true, Revoke: true}
	if c.Admin {
		h.mu.RLock()
		ykOn := h.st.SignIn.MethodsOn()[signin.YubiKeyCert]
		h.mu.RUnlock()
		can.Issue, can.Password = ykOn, true
	}
	if m.Administrators[u] {
		can.SetupLink, can.Issue, can.Revoke = false, false, false
	}
	if invite.ProtectedName(u) {
		can.SetupLink, can.Revoke, can.Issue, can.Password = false, false, false, false
	}
	if noPasswordAccounts[u] {
		can = HelpCan{}
	}
	return can
}

// PersonSignInHistory is user's sign-in history for c, under
// PersonSignInView's rule; the cursor is passed through unchanged.
func (h *Hub) PersonSignInHistory(ctx context.Context, c *directory.Caller, user, cursor string, limit int) (*HistoryPage, error) {
	u, _, err := h.helpPerson(ctx, c, user)
	if err != nil {
		return nil, err
	}
	return h.SignInHistory(ctx, u, cursor, limit)
}

// CheckCertTarget is certTarget's decision, read only: the Portcullis
// MCP's revoke_person_certificate asks it before a confirmation (review
// m3), so a refused target (403, the protected names' and
// administrators' 409s, 404) never gets one.
func (h *Hub) CheckCertTarget(ctx context.Context, c *directory.Caller, user string) error {
	_, err := h.certTarget(ctx, c, user)
	return err
}

// certTarget is the certificate routes' target check (D32, review I3):
// c may help user (403), then for everyone the protected names (409,
// before anything else is read) and administrators (409), then 404 for
// an unknown person.
func (h *Hub) certTarget(ctx context.Context, c *directory.Caller, user string) (string, error) {
	u, err := helpTarget(user)
	if err != nil {
		return "", err
	}
	if err := h.checkHelp(ctx, c, u); err != nil {
		return u, err
	}
	if invite.ProtectedName(u) {
		return u, errOwnCertsProtected
	}
	m, err := h.membership(ctx)
	if err != nil {
		return u, err
	}
	if m.Administrators[u] {
		return u, errAdminCertsServer
	}
	if _, ok := m.UUIDs[u]; !ok {
		return u, statusErr(http.StatusNotFound, "no such person: %s", u)
	}
	return u, nil
}

// helpDetail is an audit detail, with D32's "as sign_in_help" for a
// caller who isn't an administrator.
func helpDetail(c *directory.Caller, d string) string {
	if c == nil || c.Admin || !c.Perms[directory.PermSignInHelp] {
		return d
	}
	return d + "; as " + directory.PermSignInHelp
}

// RevokePersonCertificate revokes user's certificate serial (YubiKey or
// browser) for c (contract §9.7): an administrator or a sign_in_help
// holder who may target user (403); 409 for an administrator or a
// protected name (enroll isn't called); 404 when serial isn't one of
// user's. Audited cert.revoke (detail "<kind> <serial>", "; as
// sign_in_help" for a holder) — refusals too.
func (h *Hub) RevokePersonCertificate(ctx context.Context, c *directory.Caller, user, serial string) (err error) {
	u := strings.ToLower(strings.TrimSpace(user))
	shown := clip(serial, 128)
	defer func() {
		h.auditSignIn(c.Actor(), "cert.revoke", u, helpDetail(c, shown), err)
	}()
	if u, err = h.certTarget(ctx, c, user); err != nil {
		return err
	}
	errNoSuch := statusErr(http.StatusNotFound, "%s has no certificate with that serial", u)
	want, ok := serialKey(serial)
	if !ok {
		return errNoSuch
	}
	recs, err := h.certRecords(ctx)
	if err != nil {
		return err
	}
	var rec *invite.CertRecord
	for i := range recs {
		r := &recs[i]
		if k, ok := serialKey(r.Serial); ok && k == want && r.Kind.Known() && strings.EqualFold(strings.TrimSpace(r.User), u) {
			rec = r
			break
		}
	}
	if rec == nil {
		return errNoSuch
	}
	shown = string(rec.Kind) + " " + rec.Serial
	ca := h.certActionsOrNil()
	if ca == nil {
		return errCertsUnavailable
	}
	if err := ca.RevokeCertificate(ctx, u, rec.Serial); err != nil {
		return enrollErr("revoking "+u+"'s certificate "+rec.Serial, err)
	}
	h.MarkInventoryStale()
	return nil
}

// IssueYubiKeyCertificate is IssueYubiKeyCertificateOn for a proof made
// on the people listener (the person's Sign-in tab).
func (h *Hub) IssueYubiKeyCertificate(ctx context.Context, c *directory.Caller, user, csrPEM string, p freshauth.Proof) (*invite.IssuedCert, error) {
	return h.IssueYubiKeyCertificateOn(ctx, ListenerPeople, c, user, csrPEM, p)
}

// IssueYubiKeyCertificateOn issues a YubiKey certificate for user from
// csrPEM (made on the YubiKey) through enroll's admin CSR path (contract
// §9.7, D26, D32). Refusals in order: 403 not an administrator (re-
// checked on a fresh snapshot); 409 a protected name or an
// administrator target; 404 an unknown person; 409 while yubikey_cert
// is off; 400 no CSR; 409 no method may approve a new certificate
// (before the proof, so it isn't spent); 503 enroll isn't configured;
// 403 a refused proof (listener's verifier, the people core template,
// never password or browser_cert; the reason audited only); then
// enroll's answer (400 with its CSR text). The CN is always user.
// Audited cert.create "yubikey <serial> until <date>".
func (h *Hub) IssueYubiKeyCertificateOn(ctx context.Context, listener string, c *directory.Caller, user, csrPEM string, p freshauth.Proof) (ic *invite.IssuedCert, err error) {
	u := strings.ToLower(strings.TrimSpace(user))
	detail := "yubikey"
	defer func() {
		h.auditSignIn(c.Actor(), "cert.create", u, detail, err)
	}()
	if c == nil || strings.TrimSpace(c.User) == "" {
		return nil, errNoHelpCaller
	}
	if !c.Admin {
		if _, err := helpTarget(user); err != nil {
			return nil, err
		}
		return nil, errIssueAdminsOnly
	}
	if u, err = h.certTarget(ctx, c, user); err != nil {
		return nil, err
	}
	h.mu.RLock()
	ykOn := h.st.SignIn.MethodsOn()[signin.YubiKeyCert]
	h.mu.RUnlock()
	if !ykOn {
		return nil, errYubiKeyCertOff
	}
	if strings.TrimSpace(csrPEM) == "" || len(csrPEM) > maxCSR {
		return nil, statusErr(http.StatusBadRequest, "csr must be a PEM certificate request")
	}
	if allowed, tmpl := h.peopleCertFresh(); len(allowed) == 0 {
		detail = "yubikey; no method of template " + tmpl + " may add a certificate"
		return nil, h.errCertNeedsKey()
	}
	ca := h.certActionsOrNil()
	if ca == nil {
		detail = "yubikey; enroll isn't configured"
		return nil, errCertsUnavailable
	}
	fresh, reason, err := h.checkFreshAuthOn(ctx, listener, govCore("people"), p, c.User)
	if err != nil {
		if reason != "" {
			detail = "yubikey; " + reason
		}
		return nil, err
	}
	// D26, after the exchange: the method must still be one that may add
	// a certificate under the people template as it is now.
	allowed, tmpl := h.peopleCertFresh()
	if !slices.Contains(allowed, signin.Method(fresh.Method)) {
		detail = "yubikey; pc_fresh names " + fresh.Method + ", which can't add a certificate (template " + tmpl + ")"
		return nil, errFreshAuth
	}
	ic, err = ca.IssueYubiKeyCertificate(ctx, u, csrPEM)
	if err != nil {
		return nil, enrollErr("issuing a YubiKey certificate for "+u, err)
	}
	h.MarkInventoryStale()
	detail = fmt.Sprintf("yubikey %s until %s", ic.Serial, ic.NotAfter.UTC().Format(time.DateOnly))
	return ic, nil
}
