package hub

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// The Hub's two browser listeners (contract §5.1, §8): each has its own
// fresh-auth verifier, whose redirect URI is its own host.
const (
	ListenerHub    = confirm.ListenerHub
	ListenerPeople = confirm.ListenerPeople
)

// FreshAuth verifies fresh-auth proofs (contract §8, freshauth.Verifier):
// a sign-in made just now, before a person creates or regenerates a
// file-share password or approves a confirmation; the Hub then checks its
// method against the action's governing template (checkFreshAuthOn). Verify makes network calls (the code
// exchange, the realm's keys): never call it holding mu.
type FreshAuth interface {
	Verify(ctx context.Context, p freshauth.Proof, user string) (*freshauth.Result, error)
	Info() freshauth.AuthorizeInfo
}

// SetFreshAuth wires listener's verifier (ListenerPeople: redirect
// https://people.<d>/, ListenerHub: https://hub.<d>/; nil: every proof on
// that listener is refused). One readiness gate (freshAuthReady) covers
// both: they share the one Keycloak client.
func (h *Hub) SetFreshAuth(listener string, f FreshAuth) {
	if listener != ListenerHub && listener != ListenerPeople && listener != ListenerPeopleVPN {
		panic("SetFreshAuth: unknown listener " + listener)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.freshAuth == nil {
		h.freshAuth = map[string]FreshAuth{}
	}
	if f == nil {
		delete(h.freshAuth, listener)
		return
	}
	h.freshAuth[listener] = f
}

// SetFreshAuthReadyForTest marks the fresh-auth Keycloak client as configured
// (for testing only; in production the directory sync sets it). Panics outside
// tests.
func (h *Hub) SetFreshAuthReadyForTest(ready bool) {
	if !testing.Testing() {
		panic("SetFreshAuthReadyForTest: refuses to work outside tests (it turns off a fail-closed gate)")
	}
	h.freshAuthReady.Store(ready)
}

// SetFreshAuthClient sets the Keycloak call that creates / re-asserts the
// fresh-auth client (keycloak.Client.EnsureFreshAuthClient); the directory
// sync loop runs it next to the attribute mappers, retried on failure.
// Call before RunDirectorySync.
func (h *Hub) SetFreshAuthClient(ensure func(ctx context.Context) error) {
	h.policyWriteMu.Lock()
	defer h.policyWriteMu.Unlock()
	h.freshAuthEnsure = ensure
}

func (h *Hub) freshAuthVerifier(listener string) FreshAuth {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.freshAuth[listener]
}

// FreshAuthInfo is what My apps (the people listener) hands the page to
// start the popup flow (nil without a verifier).
func (h *Hub) FreshAuthInfo() *freshauth.AuthorizeInfo {
	return h.FreshAuthInfoFor(ListenerPeople)
}

// FreshAuthInfoFor is listener's popup flow parameters (nil without a
// verifier).
func (h *Hub) FreshAuthInfoFor(listener string) *freshauth.AuthorizeInfo {
	f := h.freshAuthVerifier(listener)
	if f == nil {
		return nil
	}
	info := f.Info()
	return &info
}

// freshAuthAccepted are the methods pc_fresh may name switched on right
// now, in order (freshauth.FreshMethods: the seven method ids). Whether one approves an action is the governing
// template's check (checkFreshAuthOn). Takes mu (read).
func (h *Hub) freshAuthAccepted() []string {
	h.mu.RLock()
	on := h.st.SignIn.MethodsOn()
	h.mu.RUnlock()
	out := []string{}
	for _, m := range freshauth.FreshMethods {
		if on[signin.Method(m)] {
			out = append(out, m)
		}
	}
	return out
}

// FreshAuthAccepted is freshAuthAccepted for the verifiers'
// freshauth.Config.Accepted (cmd/hub wires it).
func (h *Hub) FreshAuthAccepted() []string { return h.freshAuthAccepted() }

// freshGov names the governing template of a fresh-auth check (contract
// §8 "Governing template"): an instance's template (its own pick, else
// the default) or a core page's (state.CoreSignInKeys; "" = the default).
// Exactly one is set; the zero value refuses (fail closed).
type freshGov struct {
	instance string
	core     string
}

func govInstance(id string) freshGov { return freshGov{instance: id} }
func govCore(key string) freshGov    { return freshGov{core: key} }

// governingLocked resolves g: the template id and its compiled rule (D2),
// with the switches as they are now; false (with a reason for the audit)
// when the instance is gone, the core key unknown, or the template
// unknown, disabled or unmeetable. Caller holds mu (read).
func (h *Hub) governingLocked(g freshGov) (id string, rule signin.Node, why string) {
	switch {
	case g.instance != "" && g.core == "":
		t := h.findLocked(g.instance)
		if t == nil {
			return "", signin.Node{}, "no governing template: the instance is gone"
		}
		id = h.templateForInstanceLocked(t)
	case g.core != "" && g.instance == "":
		if !slices.Contains(state.CoreSignInKeys, g.core) {
			return "", signin.Node{}, "no governing template: unknown core page"
		}
		id = h.st.SignIn.Core[g.core]
		if id == "" {
			id = h.st.SignIn.Default
		}
	default:
		return "", signin.Node{}, "no governing template"
	}
	c, ok := h.compiledLocked(id)
	if !ok {
		return id, signin.Node{}, "governing template " + id + " is disabled, gone or can't be met"
	}
	return id, c, ""
}

// freshPcMethod is the fresh-auth popup's pc_method for a governing
// compiled rule (T9): "totp" when signin.FreshAccepted is exactly {totp}
// (with totp on), else "". Anything that isn't a compiled rule: "".
func freshPcMethod(compiled signin.Node, on map[signin.Method]bool) string {
	acc, err := signin.FreshAccepted(compiled, on)
	if err != nil || len(acc) != 1 || !acc[signin.TOTP] || !on[signin.TOTP] {
		return ""
	}
	return string(signin.TOTP)
}

// freshNeedsStronger is the fresh-auth refusal for a person none of
// whose set-up methods can pass the governing rule (final review M1).
const freshNeedsStronger = "This needs a stronger sign-in: you don't have a method it accepts yet."

// freshPcFor is the fresh-auth popup's pc_method for a person with the
// set-up methods has (final review M1, ruling), under compiled rule:
//   - a set-up method other than totp that the rule accepts as a fresh
//     method on its own (signin.FreshAccepted): "" — the person signs in
//     with it, as before;
//   - otherwise, an alternative holding totp whose every method the person
//     has (password + code): "totp" — Keycloak asks for the password, then
//     the code;
//   - otherwise: refusal = freshNeedsStronger (the page doesn't open the
//     popup).
//
// known false (the inventory doesn't know the person): the rule alone
// decides (freshPcMethod), never a refusal — the Hub's proof check still
// decides.
func freshPcFor(compiled signin.Node, on, has map[signin.Method]bool, known bool) (pc, refusal string) {
	if !known {
		return freshPcMethod(compiled, on), ""
	}
	acc, err := signin.FreshAccepted(compiled, on)
	if err != nil {
		return "", ""
	}
	for m := range acc {
		if m != signin.TOTP && has[m] {
			return "", ""
		}
	}
	if acc[signin.TOTP] && on[signin.TOTP] && has[signin.TOTP] {
		alts, err := signin.Alternatives(compiled)
		if err == nil {
			for _, a := range alts {
				if slices.Contains(a, signin.TOTP) && !slices.ContainsFunc(a, func(m signin.Method) bool { return !has[m] || !on[m] }) {
					return string(signin.TOTP), ""
				}
			}
		}
	}
	return "", freshNeedsStronger
}

// withPcMethod is a copy of info with PcMethod and Refusal set (nil stays
// nil): the shared info is never changed.
func withPcMethod(info *freshauth.AuthorizeInfo, pc, refusal string) *freshauth.AuthorizeInfo {
	if info == nil {
		return nil
	}
	c := *info
	c.PcMethod, c.Refusal = pc, refusal
	return &c
}

// freshRecheckGap: a person is re-read before a refusal at most once per
// 5 s (it reads Keycloak: never a way to hammer it).
const freshRecheckGap = 5 * time.Second

// freshRecheck is called when freshPcFor refused a known person
// (freshNeedsStronger): the inventory may predate a method they just set
// up (a setup link redeemed, an authenticator app added), so it is read
// again at once, past the 30 s throttle — at most once per 5 s per
// person. True: it was read again (the caller computes the answer
// again, as strictly); false: throttled, the refusal stands.
func (h *Hub) freshRecheck(ctx context.Context, user string) bool {
	if !h.freshRecheckT.allow(strings.ToLower(user), h.entryClock(), freshRecheckGap) {
		return false
	}
	h.MarkInventoryStale()
	_, _ = h.inventoryBase(ctx, true)
	return true
}

// personMethods is user's set-up methods from the sign-in inventory (read
// fresh as the Sign-in page reads it: at most once per 30 s; never under
// mu), and whether the inventory knows them.
func (h *Hub) personMethods(ctx context.Context, user string) (map[signin.Method]bool, bool) {
	inv, err := h.SignInInventory(ctx, true)
	if err != nil || inv == nil {
		return nil, false
	}
	pm, ok := inv.People[strings.ToLower(user)]
	if !ok {
		return nil, false
	}
	has := make(map[signin.Method]bool, len(pm.Methods))
	for _, m := range pm.Methods {
		has[m] = true
	}
	return has, true
}

// freshProof is an accepted fresh-auth proof and the template it was
// checked against (named in the audit, never the token).
type freshProof struct {
	*freshauth.Result
	Template string
}

// errFreshAuth is the one answer to every fresh-auth failure (contract
// §5.1: 403 "a fresh sign-in is required").
var errFreshAuth = &StatusError{Status: 403, Err: errors.New(freshauth.Message)}

// errFreshAuthUnavailable is the answer when fresh sign-in can't be
// checked for a reason on the Hub's side (the Keycloak client not in
// place, the token endpoint unreachable: C-M7): 503, generic text.
var errFreshAuthUnavailable = &StatusError{Status: 503, Err: errors.New("fresh sign-in can't be checked right now: try again later")}

// checkFreshAuth verifies p for user (the people listener) outside mu,
// governed by g. Every failure — no verifier, the Keycloak client not
// (yet) in place (freshAuthReady), no governing template, a refused
// proof, a method the template doesn't accept, anything unexpected — is
// errFreshAuth; reason is for the audit only (a fixed string of the
// verifier or this file plus the template id, never the code, verifier,
// nonce or a token). A refusal is a 4xx: callers on the people listener
// count it toward the caller's refusal limit (entryLimit, F45).
func (h *Hub) checkFreshAuth(ctx context.Context, g freshGov, p freshauth.Proof, user string) (res *freshProof, reason string, err error) {
	return h.checkFreshAuthOn(ctx, ListenerPeople, g, p, user)
}

// checkFreshAuthOn is checkFreshAuth with listener's verifier (a proof
// is exchanged with the redirect URI of the page that started it).
// Contract §8 "Governing template": pc_fresh must be the strongest
// switched-on method of an alternative of g's compiled rule and switched
// on — both read again after the exchange, so a template or
// switch change during it never lets a method through.
func (h *Hub) checkFreshAuthOn(ctx context.Context, listener string, g freshGov, p freshauth.Proof, user string) (res *freshProof, reason string, err error) {
	f := h.freshAuthVerifier(listener)
	if f == nil {
		return nil, "fresh auth is not configured", errFreshAuth
	}
	if !h.freshAuthReady.Load() {
		// C-M7: the Hub's own outage, not the caller's refusal (503, not
		// counted by the people listener's limit).
		return nil, "fresh-auth client not in place", errFreshAuthUnavailable
	}
	// No governing template: refused before the code is exchanged.
	h.mu.RLock()
	tmpl, _, why := h.governingLocked(g)
	h.mu.RUnlock()
	if why != "" {
		return nil, why, errFreshAuth
	}
	r, err := f.Verify(ctx, p, strings.ToLower(user))
	if err == nil && r != nil {
		return h.freshMethodAccepted(g, r)
	}
	var fe *freshauth.Error
	if errors.As(err, &fe) && fe.Reason == freshauth.ReasonUnreachable {
		return nil, fe.Reason, errFreshAuthUnavailable
	}
	if errors.As(err, &fe) && fe.Reason != "" {
		return nil, fe.Reason + " (template " + tmpl + ")", errFreshAuth
	}
	// Not the verifier's own refusal: its text may say anything.
	return nil, "fresh auth failed (template " + tmpl + ")", errFreshAuth
}

// freshMethodAccepted checks a verified proof's method against g as it is
// now: switched on, and the strongest switched-on method of at least one
// alternative of the governing template's compiled rule
// (signin.FreshAccepted: all[security_key, password] takes the key, never
// the password alone).
func (h *Hub) freshMethodAccepted(g freshGov, r *freshauth.Result) (*freshProof, string, error) {
	h.mu.RLock()
	tmpl, rule, why := h.governingLocked(g)
	on := h.st.SignIn.MethodsOn()
	h.mu.RUnlock()
	if why != "" {
		return nil, why, errFreshAuth
	}
	m := signin.Method(r.Method)
	if !slices.Contains(freshauth.FreshMethods, r.Method) || !on[m] {
		return nil, "pc_fresh names a method that is switched off (template " + tmpl + ")", errFreshAuth
	}
	accepted, err := signin.FreshAccepted(rule, on)
	if err != nil || !accepted[m] {
		return nil, "pc_fresh names a method template " + tmpl + " doesn't accept", errFreshAuth
	}
	return &freshProof{Result: r, Template: tmpl}, "", nil
}

// isRefusal reports whether err is a 4xx answer (what the people
// listener's refusal limit counts; a 5xx is never the caller's).
func isRefusal(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status >= 400 && se.Status < 500
}
