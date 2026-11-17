package agent

import (
	"context"
	"testing"

	"github.com/portcullis/hub/internal/compose"
)

// Test hooks for the shared real-agent harness (internal/workertest):
// they panic outside tests (they bypass the start backstop that sets a
// quarantine, and the bundle lock).

// QuarantineForTest quarantines instance id as the start backstop does.
func (a *API) QuarantineForTest(id, why string) {
	if !testing.Testing() {
		panic("QuarantineForTest outside tests")
	}
	a.quarantine(id, why)
}

// QuarantineAllForTest makes every instance count as quarantined (an
// unreadable quarantine.json).
func (a *API) QuarantineAllForTest(why string) {
	if !testing.Testing() {
		panic("QuarantineAllForTest outside tests")
	}
	a.mu.Lock()
	a.quarantineAll = why
	a.mu.Unlock()
}

// HoldsForTest: the agent holds a bundle of instance id.
func (a *API) HoldsForTest(id string) bool {
	if !testing.Testing() {
		panic("HoldsForTest outside tests")
	}
	return a.project(id) != nil
}

// SetOwnProjectForTest sets the agent's own compose project.
func (a *API) SetOwnProjectForTest(p string) {
	if !testing.Testing() {
		panic("SetOwnProjectForTest outside tests")
	}
	a.mu.Lock()
	a.cfg.OwnProject = p
	a.mu.Unlock()
}

// SetConfigForTest replaces the agent's compose config runner.
func (a *API) SetConfigForTest(f func(ctx context.Context, p compose.Project) ([]byte, error)) {
	if !testing.Testing() {
		panic("SetConfigForTest outside tests")
	}
	a.cfg.Config = f
}
