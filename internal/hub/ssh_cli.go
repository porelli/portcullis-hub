package hub

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
)

// CLIVerifier verifies the CLI's loopback proofs (contract §18.2): every
// freshauth check for portcullis-cli, the username taken from the token.
// Network calls: never call it holding mu.
type CLIVerifier interface {
	VerifyAnyUser(ctx context.Context, p freshauth.Proof) (*freshauth.Result, error)
}

// cliClient is the CLI Keycloak client's state: the verifier, the ensure
// call the directory sync runs, and its last outcome. Its own lock, so
// none of it touches mu.
type cliClient struct {
	mu       sync.Mutex
	verifier CLIVerifier
	ensure   func(ctx context.Context) error
	lastErr  string
	ready    atomic.Bool
	conflict atomic.Bool
}

// SetCLIVerifier wires the CLI's verifier (cmd/hub: freshauth.New with
// ClientID portcullis-cli and the three loopback redirect URIs). nil
// refuses every CLI proof.
func (h *Hub) SetCLIVerifier(v CLIVerifier) {
	h.cli.mu.Lock()
	defer h.cli.mu.Unlock()
	h.cli.verifier = v
}

// SetCLIClient sets the call that creates / re-asserts portcullis-cli
// (keycloak.Client.EnsureCLIClient); the directory sync loop runs it next
// to the fresh-auth client's. Call before RunDirectorySync.
func (h *Hub) SetCLIClient(ensure func(ctx context.Context) error) {
	h.cli.mu.Lock()
	defer h.cli.mu.Unlock()
	h.cli.ensure = ensure
}

// CLIClientReady reports that the last ensure of portcullis-cli
// succeeded: false at start and after any failure, so every CLI proof
// fails closed until the client is known to be right.
func (h *Hub) CLIClientReady() bool { return h.cli.ready.Load() }

// CLIClientConflict reports that portcullis-cli is held by an untagged or
// foreign client (the doctor's ssh_cli_client_conflict).
func (h *Hub) CLIClientConflict() bool { return h.cli.conflict.Load() }

// SetCLIClientReadyForTest opens the fail-closed gate (tests only).
func (h *Hub) SetCLIClientReadyForTest(ready bool) {
	if !testing.Testing() {
		panic("SetCLIClientReadyForTest: refuses to work outside tests (it turns off a fail-closed gate)")
	}
	h.cli.ready.Store(ready)
}

// ensureCLIClient runs the ensure once (the directory sync loop).
func (h *Hub) ensureCLIClient(ctx context.Context) {
	h.cli.mu.Lock()
	ensure := h.cli.ensure
	h.cli.mu.Unlock()
	if ensure == nil {
		return
	}
	err := ensure(ctx)
	var ce *keycloak.ConflictError
	h.cli.conflict.Store(errors.As(err, &ce))
	h.cli.ready.Store(err == nil)
	h.cli.mu.Lock()
	defer h.cli.mu.Unlock()
	if err == nil {
		h.cli.lastErr = ""
		return
	}
	if ctx.Err() == nil && err.Error() != h.cli.lastErr {
		log.Printf("keycloak: CLI client %s not in place: %v", keycloak.CLIClientID, err)
		h.cli.lastErr = err.Error()
	}
}

// cliVerifier is the wired verifier, or nil while the client isn't ready.
func (h *Hub) cliVerifier() CLIVerifier {
	if !h.cli.ready.Load() {
		return nil
	}
	h.cli.mu.Lock()
	defer h.cli.mu.Unlock()
	return h.cli.verifier
}
