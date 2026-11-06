package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/freshauth"
)

// The Hub's two browser listeners (contract §5.1, §8): each has its own
// fresh-auth verifier, whose redirect URI is its own host.
const (
	ListenerHub    = confirm.ListenerHub
	ListenerPeople = confirm.ListenerPeople
)

// FreshAuth verifies fresh-auth proofs (contract §8, freshauth.Verifier):
// a sign-in with a hardware key made just now, before a person creates or
// regenerates a file-share password. Verify makes network calls (the code
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
	if listener != ListenerHub && listener != ListenerPeople {
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

// errFreshAuth is the one answer to every fresh-auth failure (contract
// §5.1: 403 "a fresh passkey sign-in is required").
var errFreshAuth = &StatusError{Status: 403, Err: errors.New(freshauth.Message)}

// errFreshAuthUnavailable is the answer when fresh sign-in can't be
// checked for a reason on the Hub's side (the Keycloak client not in
// place, the token endpoint unreachable: C-M7): 503, generic text.
var errFreshAuthUnavailable = &StatusError{Status: 503, Err: errors.New("fresh sign-in can't be checked right now: try again later")}

// checkFreshAuth verifies p for user (the people listener) outside mu. Every failure — no
// verifier, the Keycloak client not (yet) in place (freshAuthReady), a
// refused proof, anything unexpected — is errFreshAuth; reason
// is for the audit only (a fixed string of the verifier, never the code,
// verifier, nonce or a token). A refusal is a 4xx: callers on the people
// listener count it toward the caller's refusal limit (entryLimit, F45).
func (h *Hub) checkFreshAuth(ctx context.Context, p freshauth.Proof, user string) (res *freshauth.Result, reason string, err error) {
	return h.checkFreshAuthOn(ctx, ListenerPeople, p, user)
}

// checkFreshAuthOn is checkFreshAuth with listener's verifier (a proof
// is exchanged with the redirect URI of the page that started it).
func (h *Hub) checkFreshAuthOn(ctx context.Context, listener string, p freshauth.Proof, user string) (res *freshauth.Result, reason string, err error) {
	f := h.freshAuthVerifier(listener)
	if f == nil {
		return nil, "fresh auth is not configured", errFreshAuth
	}
	if !h.freshAuthReady.Load() {
		// C-M7: the Hub's own outage, not the caller's refusal (503, not
		// counted by the people listener's limit).
		return nil, "fresh-auth client not in place", errFreshAuthUnavailable
	}
	res, err = f.Verify(ctx, p, strings.ToLower(user))
	if err == nil && res != nil {
		return res, "", nil
	}
	var fe *freshauth.Error
	if errors.As(err, &fe) && fe.Reason == freshauth.ReasonUnreachable {
		return nil, fe.Reason, errFreshAuthUnavailable
	}
	if errors.As(err, &fe) && fe.Reason != "" {
		return nil, fe.Reason, errFreshAuth
	}
	// Not the verifier's own refusal: its text may say anything.
	return nil, "fresh auth failed", errFreshAuth
}

// isRefusal reports whether err is a 4xx answer (what the people
// listener's refusal limit counts; a 5xx is never the caller's).
func isRefusal(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status >= 400 && se.Status < 500
}
