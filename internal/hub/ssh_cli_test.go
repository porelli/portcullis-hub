package hub

import (
	"context"
	"errors"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
)

func newBareHub(t *testing.T) *Hub {
	t.Helper()
	h, err := newTestHub(Config{ProjectDir: t.TempDir(), ProjectHostDir: "/hp", DataDir: t.TempDir(), Domain: "example.org"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Wait)
	return h
}

func TestCLIClientReadinessAndConflict(t *testing.T) {
	h := newBareHub(t)
	if h.CLIClientReady() || h.cliVerifier() != nil {
		t.Fatal("ready before any ensure (must fail closed)")
	}
	ensureErr := error(&keycloak.ConflictError{ClientID: keycloak.CLIClientID, TemplateID: keycloak.CLIClientID, Owner: ""})
	h.SetCLIClient(func(context.Context) error { return ensureErr })
	h.ensureCLIClient(context.Background())
	if h.CLIClientReady() || !h.CLIClientConflict() {
		t.Errorf("conflict: ready %v conflict %v", h.CLIClientReady(), h.CLIClientConflict())
	}
	ensureErr = errors.New("keycloak down")
	h.ensureCLIClient(context.Background())
	if h.CLIClientReady() || h.CLIClientConflict() {
		t.Errorf("outage: ready %v conflict %v", h.CLIClientReady(), h.CLIClientConflict())
	}
	ensureErr = nil
	h.ensureCLIClient(context.Background())
	if !h.CLIClientReady() || h.CLIClientConflict() {
		t.Errorf("ok: ready %v conflict %v", h.CLIClientReady(), h.CLIClientConflict())
	}
}

func TestImpFileClientRefusesCLI(t *testing.T) {
	if impFileClient(keycloak.CLIClientID) {
		t.Error("portcullis-cli may appear in the impersonation file's clients")
	}
}

func TestGovTemplate(t *testing.T) {
	h := newBareHub(t)
	h.mu.RLock()
	defer h.mu.RUnlock()
	id, _, why := h.governingLocked(govTemplate("strong"))
	if id != "strong" || why != "" {
		t.Errorf("govTemplate(strong) = %q %q", id, why)
	}
	if _, _, why := h.governingLocked(govTemplate("no-such")); why == "" {
		t.Error("unknown template resolved")
	}
	if _, _, why := h.governingLocked(freshGov{template: "strong", core: "hub"}); why == "" {
		t.Error("two governing sources resolved")
	}
}
