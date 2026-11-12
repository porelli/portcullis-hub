package hub

// The Sign-in page's view and the caller's own password (contract §5.1
// "Sign-in page", plan D24–D26): every person's one place for their
// sign-in methods, on the people listener, for the caller only.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/signin"
)

// MySignIn is GET /api/me/signin's answer.
type MySignIn struct {
	User               string                   `json:"user"`
	Methods            []MethodRow              `json:"methods"`
	Certificates       []CertRow                `json:"certificates"`
	Apps               []AppNeed                `json:"apps"`
	Limits             LimitsView               `json:"limits"`
	ActiveBrowserCerts int                      `json:"active_browser_certs"`
	AddStronger        bool                     `json:"add_stronger"`
	FreshAuth          *freshauth.AuthorizeInfo `json:"fresh_auth"`
	// AccountURL is the account console's signing-in page (Config.AccountURL):
	// where passkeys and security keys are added; "" = no link.
	AccountURL string `json:"account_url"`
	// CertFresh are the methods a fresh sign-in may use to create a
	// certificate (D26: the people template's fresh methods minus password
	// and browser_cert), and CertFreshRefusal the 409 text when none of
	// them fits: the page says it before opening the popup.
	CertFresh        []signin.Method `json:"cert_fresh"`
	CertFreshRefusal string          `json:"cert_fresh_refusal"`
}

// The method states of a MethodRow.
const (
	MethodSet     = "set"
	MethodNone    = "none"
	MethodUnknown = "unknown"
	MethodOff     = "off"
)

// MethodRow is one of the six methods for the caller: State set, none,
// unknown (its source couldn't be read) or off (switched off: "off on
// this server").
type MethodRow struct {
	ID            signin.Method `json:"id"`
	Label         string        `json:"label"`
	On            bool          `json:"on"`
	State         string        `json:"state"`
	Passkeys      []PasskeyRow  `json:"passkeys,omitempty"`
	PasswordSetAt *time.Time    `json:"password_set_at,omitempty"`
}

// PasskeyRow is one of the caller's passkeys.
type PasskeyRow struct {
	Label     string        `json:"label"`
	Kind      signin.Method `json:"kind"`
	CreatedAt time.Time     `json:"created_at"`
}

// AppNeed is an app or core page the caller signs in to, the template
// that governs it and whether the caller has a set-up method that meets
// it (OK nil: not known).
type AppNeed struct {
	Kind         string       `json:"kind"` // instance | core
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Template     string       `json:"template"`
	TemplateName string       `json:"template_name"`
	Score        signin.Score `json:"score"`
	OK           *bool        `json:"ok"`
}

// OwnPasswords is the directory's own-password side
// (directory.Service): set and remove, both signing the person out of
// Keycloak and audited signin.password by the directory. Network calls:
// never call them holding mu.
type OwnPasswords interface {
	SetOwnPassword(ctx context.Context, a directory.Actor, password string) (*directory.Result, error)
	RemoveOwnPassword(ctx context.Context, a directory.Actor) (*directory.Result, error)
}

// SetOwnPasswords wires the directory's own-password side (nil: 503).
func (h *Hub) SetOwnPasswords(p OwnPasswords) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ownPasswords = p
}

// MySignInView is user's (the caller's) Sign-in page: the six methods,
// their certificates (revoked ones included), the apps and core pages
// they sign in to with what each needs, the limits and the people
// listener's fresh-auth parameters. The inventory is read fresh (at most
// once per 30 s); a source it couldn't read leaves its methods unknown.
// The directory unavailable is its error.
func (h *Hub) MySignInView(ctx context.Context, user string) (*MySignIn, error) {
	u, err := myUser(user)
	if err != nil {
		return nil, err
	}
	m, err := h.membership(ctx)
	if err != nil {
		return nil, err
	}
	base, _ := h.inventoryBase(ctx, true)
	info := h.FreshAuthInfo()
	now := h.certClock()
	h.mu.RLock()
	defer h.mu.RUnlock()
	si := h.st.SignIn
	on := si.MethodsOn()
	v := &MySignIn{User: u, Methods: []MethodRow{}, Certificates: []CertRow{}, Apps: []AppNeed{}, Limits: h.limitsViewLocked(),
		AddStronger: si.AddStronger, FreshAuth: info, AccountURL: h.cfg.AccountURL, CertFresh: []signin.Method{},
		CertFreshRefusal: h.errCertNeedsKey().Error()}
	if _, rule, why := h.governingLocked(govCore("people")); why == "" {
		if cf := certFreshAllowed(rule, on); cf != nil {
			v.CertFresh = cf
		}
	}

	var pm PersonMethods
	known := false
	keysKnown := false
	if base != nil {
		pm, known = composeInventory(base, si.Passwords).People[u]
		_, keysKnown = base.keys[u]
		keysKnown = keysKnown || base.disabled[u]
		if base.certsKnown {
			v.Certificates = certRowsFor(base.records, u, now, h.cfg.CertExpiryWarnDays)
			v.ActiveBrowserCerts = activeBrowserCerts(v.Certificates)
		}
	}
	has := map[signin.Method]bool{}
	for _, x := range pm.Methods {
		has[x] = true
	}
	for _, meth := range signin.Methods {
		mi, _ := signin.InfoOf(meth)
		row := MethodRow{ID: meth, Label: mi.Label, On: on[meth]}
		switch meth {
		case signin.Password:
			if rec, ok := si.Passwords[u]; ok && base != nil && base.uuids != nil && rec.UUID != "" && base.uuids[u] == rec.UUID && !noPasswordAccounts[u] {
				at := rec.SetAt.UTC()
				row.PasswordSetAt = &at
			}
		}
		switch {
		case !on[meth]:
			row.State = MethodOff
		case meth == signin.Password:
			switch {
			case noPasswordAccounts[u]:
				row.State = MethodNone
			case base == nil || base.uuids == nil:
				row.State = MethodUnknown
			case row.PasswordSetAt != nil && !base.disabled[u]:
				row.State = MethodSet
			default:
				row.State = MethodNone
			}
		case meth == signin.BrowserCert || meth == signin.YubiKeyCert:
			switch {
			case base == nil || !base.certsKnown:
				row.State = MethodUnknown
			case has[meth]:
				row.State = MethodSet
			default:
				row.State = MethodNone
			}
		default:
			switch {
			case !keysKnown:
				row.State = MethodUnknown
			case has[meth]:
				row.State = MethodSet
				for _, pk := range base.keys[u] {
					if signin.Method(pk.Type) == meth {
						row.Passkeys = append(row.Passkeys, PasskeyRow{Label: clipRunes(pk.Label, 128), Kind: meth, CreatedAt: pk.Created.UTC()})
					}
				}
			default:
				row.State = MethodNone
			}
		}
		v.Methods = append(v.Methods, row)
	}

	okFor := func(compiled *signin.Node) *bool {
		if compiled == nil {
			f := false
			return &f
		}
		if !known {
			return nil
		}
		ok := meets(pm, *compiled, on)
		if !ok && !pm.CertsKnown && namesCert(*compiled) {
			return nil
		}
		return &ok
	}
	need := func(kind, id, name, tmpl string) AppNeed {
		a := AppNeed{Kind: kind, ID: id, Name: name, Template: tmpl}
		t, ok := si.Templates[tmpl]
		if ok {
			a.TemplateName = t.Name
			a.Score = signin.ScoreOf(t.Rule, on)
		}
		var c *signin.Node
		if rule, ok := compiledIn(si, tmpl); ok {
			c = &rule
		}
		a.OK = okFor(c)
		return a
	}
	var insts []AppNeed
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		acc := h.accessLocked(t)
		if !acc.Capability.Templates || !slices.Contains(lowerAll(instanceSignInUsers(t, m)), u) {
			continue
		}
		insts = append(insts, need("instance", t.ID, instanceName(t), acc.Template))
	}
	slices.SortStableFunc(insts, func(a, b AppNeed) int { return strings.Compare(a.ID, b.ID) })
	v.Apps = append(v.Apps, insts...)
	for _, k := range []string{"people", "hub"} {
		if !slices.Contains(lowerAll(coreSignInUsers(k, m)), u) {
			continue
		}
		pick := si.Core[k]
		if pick == "" {
			pick = si.Default
		}
		v.Apps = append(v.Apps, need("core", k, coreSignInLabels[k], pick))
	}
	return v, nil
}

func lowerAll(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = strings.ToLower(s)
	}
	return out
}

// ── the caller's own password ────────────────────────────

var (
	errNoOwnPassword  = &StatusError{Status: http.StatusConflict, Err: errors.New("Password sign-in isn't available for this account")}
	errPasswordOff    = &StatusError{Status: http.StatusConflict, Err: errors.New("password sign-in is off on this server")}
	errOwnPasswordsNA = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("passwords can't be changed right now: try again later")}
)

// dirStatusErr is a directory error as a StatusError (its status and
// text; anything else 503 generic, logged).
func dirStatusErr(what string, err error) error {
	var de *directory.Error
	if errors.As(err, &de) {
		return &StatusError{Status: de.Status, Err: errors.New(de.Msg)}
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se
	}
	log.Printf("signin: %s: %v", what, err)
	return &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New(directory.GenericUnavailable)}
}

func (h *Hub) ownPasswordsOrNil() OwnPasswords {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ownPasswords
}

// SetOwnPassword sets user's (the caller's) own LLDAP password (contract
// §5.1, D25, D26): refused for admin and portcullis-hub (409, D13's
// text), while the password method is off (409), with CheckPassword's
// text (400), then a fresh-auth proof under the plain
// FreshAccepted(people template) (403) — never browser_cert, and
// password only to change an existing password (fix round 1). The
// portcullis-* names are refused like admin, before any proof. The directory sets it, signs
// the person out of Keycloak and audits signin.password "self set"; the
// Hub records it with set_by = the caller. Counts toward the refusal
// limit.
func (h *Hub) SetOwnPassword(ctx context.Context, user, password string, p freshauth.Proof) (err error) {
	u, err := myUser(user)
	if err != nil {
		return err
	}
	if !h.entryLimit.reserve(u, h.entryClock()) {
		return errEntryLimited
	}
	defer func() { h.entryLimit.release(u, h.entryClock(), isRefusal(err)) }()
	actor := directory.Human(u)
	refuse := func(err error, reason string) error {
		d := "self set"
		if reason != "" {
			d += "; " + reason
		}
		h.auditSignIn(actor, "signin.password", u, d, err)
		return err
	}
	if ownPasswordRefused(u) {
		return refuse(errNoOwnPassword, "")
	}
	h.mu.RLock()
	on := h.st.SignIn.MethodsOn()[signin.Password]
	h.mu.RUnlock()
	if !on {
		return refuse(errPasswordOff, "")
	}
	if err := directory.CheckHubPassword(u, password); err != nil {
		return refuse(dirStatusErr("checking a password", err), "")
	}
	op := h.ownPasswordsOrNil()
	if op == nil {
		return refuse(errOwnPasswordsNA, "")
	}
	fresh, reason, err := h.checkFreshAuth(ctx, govCore("people"), p, u)
	if err != nil {
		return refuse(err, reason)
	}
	// A copied certificate file never sets a password, and a password
	// never adds one where there was none (security review, fix round 1;
	// as certFreshAllowed): only changing an existing password may use a
	// fresh password sign-in.
	switch m := signin.Method(fresh.Method); {
	case m == signin.BrowserCert:
		return refuse(errFreshAuth, "pc_fresh names browser_cert, which can't set a password (template "+fresh.Template+")")
	case m == signin.Password && !h.hasOwnPassword(ctx, u):
		return refuse(errFreshAuth, "pc_fresh names password, but there is no password yet: adding one needs a passkey or YubiKey sign-in (template "+fresh.Template+")")
	}
	res, err := op.SetOwnPassword(ctx, actor, password)
	logWarnings(u, res)
	if err != nil {
		return dirStatusErr("setting "+u+"'s own password", err)
	}
	return nil
}

// RemoveOwnPassword removes user's (the caller's) own password: LLDAP
// can't clear one, so the directory sets a random 32-byte one nobody
// sees, signs the person out and audits signin.password "self removed";
// the Hub drops its record. No fresh auth (it only removes access);
// refused for admin and portcullis-hub (409). Counts toward the refusal
// limit.
func (h *Hub) RemoveOwnPassword(ctx context.Context, user string) (err error) {
	u, err := myUser(user)
	if err != nil {
		return err
	}
	if !h.entryLimit.reserve(u, h.entryClock()) {
		return errEntryLimited
	}
	defer func() { h.entryLimit.release(u, h.entryClock(), isRefusal(err)) }()
	actor := directory.Human(u)
	if ownPasswordRefused(u) {
		h.auditSignIn(actor, "signin.password", u, "self removed", errNoOwnPassword)
		return errNoOwnPassword
	}
	op := h.ownPasswordsOrNil()
	if op == nil {
		h.auditSignIn(actor, "signin.password", u, "self removed", errOwnPasswordsNA)
		return errOwnPasswordsNA
	}
	res, err := op.RemoveOwnPassword(ctx, actor)
	logWarnings(u, res)
	if err != nil {
		return dirStatusErr("removing "+u+"'s own password", err)
	}
	h.MarkInventoryStale()
	if warn := h.forgetPassword(u); len(warn) > 0 {
		log.Printf("ERROR: signin: %s", strings.Join(warn, "; "))
		return &StatusError{Status: http.StatusInternalServerError, Err: errors.New("the password was removed, but the Hub's record of it couldn't be dropped: try again")}
	}
	return nil
}

// ownPasswordRefused: the accounts whose own password the Sign-in page
// never changes (D13: admin, portcullis-hub; and every portcullis-* name,
// which the directory reserves), refused before any proof is spent.
func ownPasswordRefused(u string) bool {
	return noPasswordAccounts[u] || strings.HasPrefix(u, directory.ReservedUserPrefix)
}

// hasOwnPassword reports whether u has a Hub-set password for their
// current LLDAP account (the record's uuid is the account's); the
// directory unreadable counts as none (fail closed).
func (h *Hub) hasOwnPassword(ctx context.Context, u string) bool {
	h.mu.RLock()
	rec, ok := h.st.SignIn.Passwords[u]
	h.mu.RUnlock()
	if !ok || rec.UUID == "" {
		return false
	}
	m, err := h.membership(ctx)
	return err == nil && m.UUIDs[u] == rec.UUID
}

func logWarnings(u string, res *directory.Result) {
	if res == nil {
		return
	}
	for _, w := range res.Warnings {
		log.Printf("signin: %s's own password: %s", u, w)
	}
}
