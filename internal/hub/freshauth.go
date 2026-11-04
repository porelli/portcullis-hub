package hub

import (
	"context"
	"errors"
	"strings"

	"github.com/portcullis/hub/internal/freshauth"
)

// FreshAuth verifies fresh-auth proofs (contract §8, freshauth.Verifier):
// a sign-in with a hardware key made just now, before a person creates or
// regenerates a file-share password. Verify makes network calls (the code
// exchange, the realm's keys): never call it holding mu.
type FreshAuth interface {
	Verify(ctx context.Context, p freshauth.Proof, user string) (*freshauth.Result, error)
	Info() freshauth.AuthorizeInfo
}

// SetFreshAuth wires the verifier (nil: every proof is refused).
func (h *Hub) SetFreshAuth(f FreshAuth) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.freshAuth = f
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

func (h *Hub) freshAuthVerifier() FreshAuth {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.freshAuth
}

// FreshAuthInfo is what My apps hands the page to start the popup flow
// (nil without a verifier).
func (h *Hub) FreshAuthInfo() *freshauth.AuthorizeInfo {
	f := h.freshAuthVerifier()
	if f == nil {
		return nil
	}
	info := f.Info()
	return &info
}

// errFreshAuth is the one answer to every fresh-auth failure (contract
// §5.1: 403 "a fresh passkey sign-in is required").
var errFreshAuth = &StatusError{Status: 403, Err: errors.New(freshauth.Message)}

// checkFreshAuth verifies p for user outside mu. Every failure — no
// verifier, the Keycloak client not (yet) in place (freshAuthReady), a
// refused proof, anything unexpected — is errFreshAuth; reason
// is for the audit only (a fixed string of the verifier, never the code,
// verifier, nonce or a token). A refusal is a 4xx: callers on the people
// listener count it toward the caller's refusal limit (entryLimit, F45).
func (h *Hub) checkFreshAuth(ctx context.Context, p freshauth.Proof, user string) (res *freshauth.Result, reason string, err error) {
	f := h.freshAuthVerifier()
	if f == nil {
		return nil, "fresh auth is not configured", errFreshAuth
	}
	if !h.freshAuthReady.Load() {
		return nil, "fresh-auth client not in place", errFreshAuth
	}
	res, err = f.Verify(ctx, p, strings.ToLower(user))
	if err == nil && res != nil {
		return res, "", nil
	}
	var fe *freshauth.Error
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
