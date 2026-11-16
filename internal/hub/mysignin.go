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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
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
	// MaxAuthenticators is how many authenticator apps a person may have
	// (the page hides "+ Add" at it; the extension enforces it).
	MaxAuthenticators int `json:"max_authenticators"`
}

// MaxAuthenticators is the most authenticator apps per person (T18; the
// extension's TotpRegister.MAX is the enforcement).
const MaxAuthenticators = 3

// The method states of a MethodRow.
const (
	MethodSet     = "set"
	MethodNone    = "none"
	MethodUnknown = "unknown"
	MethodOff     = "off"
)

// MethodRow is one of the seven methods for the caller: State set, none,
// unknown (its source couldn't be read) or off (switched off: "off on
// this server").
type MethodRow struct {
	ID            signin.Method `json:"id"`
	Label         string        `json:"label"`
	On            bool          `json:"on"`
	State         string        `json:"state"`
	Passkeys      []PasskeyRow  `json:"passkeys,omitempty"`
	PasswordSetAt *time.Time    `json:"password_set_at,omitempty"`
	// Authenticators are the caller's authenticator apps, oldest first
	// (the totp row only).
	Authenticators []AuthenticatorRow `json:"authenticators,omitempty"`
	// RemoveImpact (T7, the totp row, exactly one app set up): the names
	// of the caller's apps they could no longer open without it.
	RemoveImpact []string `json:"remove_impact,omitempty"`
}

// AuthenticatorRow is one of the caller's authenticator apps: its
// Keycloak credential id, its name and when it was set up (zero: unknown).
type AuthenticatorRow struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

// PasskeyRow is one of the caller's passkeys: ID its Keycloak credential
// id, Label its name (Keycloak's userLabel), Model the FIDO list's name
// for its AAGUID (display only; "" = unknown model).
type PasskeyRow struct {
	ID        string        `json:"id"`
	Label     string        `json:"label"`
	Kind      signin.Method `json:"kind"`
	Model     string        `json:"model"`
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

// MySignInView is user's (the caller's) Sign-in page: the seven methods,
// their certificates (revoked ones included), the apps and core pages
// they sign in to with what each needs, the limits and the people
// listener's fresh-auth parameters. The inventory is read fresh (at most
// once per 30 s); a source it couldn't read leaves its methods unknown.
// The directory unavailable is its error.
func (h *Hub) MySignInView(ctx context.Context, user string) (*MySignIn, error) {
	v, err := h.mySignInView(ctx, user)
	if err == nil && v.FreshAuth != nil && v.FreshAuth.Refusal == freshNeedsStronger && h.freshRecheck(ctx, v.User) {
		return h.mySignInView(ctx, user)
	}
	return v, err
}

func (h *Hub) mySignInView(ctx context.Context, user string) (*MySignIn, error) {
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
	models := h.mdsModels() // its own leaf lock: before mu
	h.mu.RLock()
	defer h.mu.RUnlock()
	si := h.st.SignIn
	on := si.MethodsOn()
	v := &MySignIn{User: u, Methods: []MethodRow{}, Certificates: []CertRow{}, Apps: []AppNeed{}, Limits: h.limitsViewLocked(),
		AddStronger: si.AddStronger, FreshAuth: info, AccountURL: h.cfg.AccountURL, CertFresh: []signin.Method{},
		CertFreshRefusal: h.errCertNeedsKey().Error(), MaxAuthenticators: MaxAuthenticators}
	var peopleRule *signin.Node
	if _, rule, why := h.governingLocked(govCore("people")); why == "" {
		if cf := certFreshAllowed(rule, on); cf != nil {
			v.CertFresh = cf
		}
		// The popup's method for this person (T9, final review M1).
		r := rule
		peopleRule = &r
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
	if peopleRule != nil {
		pc, refusal := freshPcFor(*peopleRule, on, has, known)
		v.FreshAuth = withPcMethod(info, pc, refusal)
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
		case meth == signin.TOTP:
			switch {
			case ownPasswordRefused(u):
				row.State = MethodNone // P28: never for admin or portcullis-*
			case !keysKnown:
				row.State = MethodUnknown
			case has[meth]:
				row.State = MethodSet
				for _, pk := range base.keys[u] {
					if signin.Method(pk.Type) == meth {
						row.Authenticators = append(row.Authenticators, AuthenticatorRow{ID: pk.ID, Label: clipRunes(pk.Label, 128), CreatedAt: pk.Created.UTC()})
					}
				}
				slices.SortStableFunc(row.Authenticators, func(a, b AuthenticatorRow) int { return a.CreatedAt.Compare(b.CreatedAt) })
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
						row.Passkeys = append(row.Passkeys, PasskeyRow{ID: pk.ID, Label: clipRunes(pk.Label, 128), Kind: meth, Model: models[pk.AAGUID], CreatedAt: pk.Created.UTC()})
					}
				}
			default:
				row.State = MethodNone
			}
		}
		v.Methods = append(v.Methods, row)
	}

	okFor := func(pm PersonMethods, compiled *signin.Node) *bool {
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
	// T7: with exactly one authenticator app, the apps it alone keeps open.
	var withoutCode *PersonMethods
	var impact []string
	ti := slices.IndexFunc(v.Methods, func(r MethodRow) bool { return r.ID == signin.TOTP })
	if ti >= 0 && v.Methods[ti].State == MethodSet && len(v.Methods[ti].Authenticators) == 1 {
		wc := pm
		wc.Methods = slices.DeleteFunc(slices.Clone(pm.Methods), func(m signin.Method) bool { return m == signin.TOTP })
		withoutCode = &wc
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
		a.OK = okFor(pm, c)
		if a.OK != nil && *a.OK && withoutCode != nil {
			if lost := okFor(*withoutCode, c); lost != nil && !*lost {
				impact = append(impact, name)
			}
		}
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
	if ti >= 0 {
		v.Methods[ti].RemoveImpact = impact
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
	// Allowlists (security review, fix round 1; T10): a strong method
	// sets a password; a password or a code only changes an existing one;
	// anything else (a copied certificate file, a method added later)
	// never sets one.
	if m := signin.Method(fresh.Method); !passwordFreshAllowed(m, func() bool { return h.hasOwnPassword(ctx, u) }) {
		if slices.Contains(passwordChangeFreshMethods, m) {
			return refuse(errFreshAuth, "pc_fresh names "+fresh.Method+", but there is no password yet: adding one needs a passkey or YubiKey sign-in (template "+fresh.Template+")")
		}
		return refuse(errFreshAuth, "pc_fresh names "+fresh.Method+", which can't set a password (template "+fresh.Template+")")
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

// passwordChangeFreshMethods may approve changing an existing own
// password, never adding the first one (T10).
var passwordChangeFreshMethods = []signin.Method{signin.Password, signin.TOTP}

// passwordFreshAllowed reports whether a fresh sign-in with m may set an
// own password: any strongFreshMethods; passwordChangeFreshMethods only
// when hasPassword says one exists (asked only then). Everything else no.
func passwordFreshAllowed(m signin.Method, hasPassword func() bool) bool {
	if strongFresh(m) {
		return true
	}
	return slices.Contains(passwordChangeFreshMethods, m) && hasPassword()
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

// MaxPasskeyLabelRunes is the longest passkey name (contract §5.1).
const MaxPasskeyLabelRunes = 64

var (
	errPasskeyLabel    = &StatusError{Status: http.StatusBadRequest, Err: errors.New("a passkey name is 1–64 characters on one line")}
	errNoSuchPasskey   = &StatusError{Status: http.StatusNotFound, Err: errors.New("no such passkey")}
	errPasskeyLabelsNA = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("passkey names can't be changed right now: try again later")}
)

// passkeyLabel is raw trimmed, when it is a passkey name: 1–64 runes of
// valid UTF-8 with no control or bidi character (one line); else the 400.
func passkeyLabel(raw string) (string, error) {
	l := strings.TrimSpace(raw)
	if n := utf8.RuneCountInString(l); !utf8.ValidString(l) || n < 1 || n > MaxPasskeyLabelRunes || strings.IndexFunc(l, controlOrBidi) >= 0 {
		return "", errPasskeyLabel
	}
	return l, nil
}

// RenameOwnPasskey renames one of user's (the caller's) own passkeys
// (contract §5.1, polish 1): Keycloak's credential userLabel, by
// credential id (not a UUID, another person's, or not a passkey: 404
// "no such passkey"); the label must be unique among the caller's other
// credentials, case-insensitively (409). No fresh auth: it only changes a
// name. The inventory is marked stale, so the next view shows the new
// name. Audited signin.passkey.label "<old> → <new>" ("credential <id>"
// when refused); counts toward the refusal limit. Keycloak unreachable
// (or no source) is 503.
func (h *Hub) RenameOwnPasskey(ctx context.Context, user, credentialID, label string) error {
	return h.renameOwnCredential(ctx, user, credentialID, label, passkeyRename)
}

// credentialRename is what differs between renaming a passkey and an
// authenticator app.
type credentialRename struct {
	action             string // the audit action
	badLabel, notFound error
	unavailable        error
	notFoundErr        error // the Keycloak client's "not one of theirs"
	source             func(SignInSources) func(ctx context.Context, username, credentialID, label string) (string, error)
}

var (
	passkeyRename = credentialRename{action: "signin.passkey.label", badLabel: errPasskeyLabel, notFound: errNoSuchPasskey, unavailable: errPasskeyLabelsNA,
		notFoundErr: keycloak.ErrPasskeyNotFound, source: func(s SignInSources) func(context.Context, string, string, string) (string, error) {
			return s.PasskeyLabel
		}}
	authenticatorRename = credentialRename{action: "signin.authenticator.label", badLabel: errAuthenticatorLabel, notFound: errNoSuchAuthenticator, unavailable: errAuthenticatorLabelsNA,
		notFoundErr: keycloak.ErrAuthenticatorNotFound, source: func(s SignInSources) func(context.Context, string, string, string) (string, error) {
			return s.AuthenticatorLabel
		}}
)

var (
	errAuthenticatorLabel    = &StatusError{Status: http.StatusBadRequest, Err: errors.New("an authenticator name is 1–64 characters on one line")}
	errNoSuchAuthenticator   = &StatusError{Status: http.StatusNotFound, Err: errors.New("no such authenticator app")}
	errAuthenticatorLabelsNA = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("authenticator names can't be changed right now: try again later")}
)

// RenameOwnAuthenticator renames one of user's (the caller's) own
// authenticator apps (T6), with RenameOwnPasskey's rules: 400 "an
// authenticator name is 1–64 characters on one line", 404 "no such
// authenticator app" (not a UUID, another person's, or not an otp), 409
// a duplicate, 503 Keycloak unreachable; audited
// signin.authenticator.label.
func (h *Hub) RenameOwnAuthenticator(ctx context.Context, user, credentialID, label string) error {
	return h.renameOwnCredential(ctx, user, credentialID, label, authenticatorRename)
}

func (h *Hub) renameOwnCredential(ctx context.Context, user, credentialID, label string, k credentialRename) (err error) {
	u, err := myUser(user)
	if err != nil {
		return err
	}
	if !h.entryLimit.reserve(u, h.entryClock()) {
		return errEntryLimited
	}
	defer func() { h.entryLimit.release(u, h.entryClock(), isRefusal(err)) }()
	actor := directory.Human(u)
	// A credential id is a UUID (8-4-4-4-12 hex, canonical form only):
	// anything else is 404 without a Keycloak call, audited as invalid
	// (never the raw path value).
	_, perr := uuid.Parse(credentialID)
	validID := perr == nil && len(credentialID) == 36
	refuse := func(err error) error {
		d := "credential (invalid)"
		if validID {
			d = "credential " + credentialID
		}
		h.auditSignIn(actor, k.action, u, d, err)
		return err
	}
	l, err := passkeyLabel(label)
	if err != nil {
		return refuse(k.badLabel)
	}
	if !validID {
		return refuse(k.notFound)
	}
	c := &h.signInInv
	c.mu.Lock()
	src := k.source(c.src)
	c.mu.Unlock()
	if src == nil {
		return refuse(k.unavailable)
	}
	old, err := src(ctx, u, credentialID, l)
	switch {
	case errors.Is(err, k.notFoundErr), errors.Is(err, keycloak.ErrUserNotFound):
		return refuse(k.notFound)
	case errors.Is(err, keycloak.ErrPasskeyLabelTaken):
		return refuse(&StatusError{Status: http.StatusConflict, Err: errors.New("you already have a sign-in method named “" + l + "”")})
	case err != nil:
		log.Printf("signin: renaming %s's credential %s: %v", u, credentialID, err)
		return refuse(k.unavailable)
	}
	h.MarkInventoryStale()
	h.auditSignIn(actor, k.action, u, old+" → "+l, nil)
	return nil
}

// refreshMinGap: ?refresh=1 marks the inventory stale at most once per
// caller per 10 s (T5).
const refreshMinGap = 10 * time.Second

// refreshThrottle is the last ?refresh=1 mark per caller.
type refreshThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// RefreshMySignIn is GET /api/me/signin?refresh=1 (T5): it marks the
// inventory stale, at most once per 10 s per caller; otherwise (or for no
// user) it does nothing. Never an error.
func (h *Hub) RefreshMySignIn(user string) {
	u, err := myUser(user)
	if err != nil {
		return
	}
	if h.signInRefresh.allow(u, h.entryClock(), refreshMinGap) {
		h.MarkInventoryStale()
	}
}

// allow records u's mark at now and is true unless u had one less than
// gap ago (then nothing is recorded).
func (r *refreshThrottle) allow(u string, now time.Time, gap time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.last[u]; ok && now.Sub(t) < gap {
		return false
	}
	if r.last == nil {
		r.last = map[string]time.Time{}
	}
	for k, t := range r.last { // keep the map small: drop the old marks
		if now.Sub(t) >= gap {
			delete(r.last, k)
		}
	}
	r.last[u] = now
	return true
}
