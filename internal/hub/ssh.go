package hub

// SSH access (contract §18): the compiled mapping and its wiring. The
// Hub-wide state is h.st.SSH (under mu); everything derived lives in
// h.sshrt with its own lock, never held across a network call.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/sshaccess"
)

// SSHActions is enroll's SSH API (internal/invite, contract §18.8).
type SSHActions interface {
	PutSSHRole(ctx context.Context, hg string, r cliapi.RoleSpec) (*cliapi.RoleSpec, error)
	DeleteSSHRole(ctx context.Context, hg string) error
	ListSSHRoles(ctx context.Context) ([]string, error)
	SignSSHUser(ctx context.Context, r invite.SSHUserSign) (*invite.SSHSigned, error)
	SignSSHHost(ctx context.Context, r invite.SSHHostSign) (*invite.SSHSigned, error)
	SSHCA(ctx context.Context) (*invite.SSHCA, error)
}

// sshRuntime is SSH access's memory.
type sshRuntime struct {
	mu      sync.Mutex
	actions SSHActions
	// compiled is the last good compilation (nil: none yet, or SSH off).
	compiled *sshaccess.Compiled
	// roles: host group → the role as Vault read it back after the last
	// successful put (what ensureRoleCurrent compares).
	roles map[string]cliapi.RoleSpec
	// roleErr: host group → why its role couldn't be made current.
	roleErr map[string]string
	// userCAs / hostCAs are the last CA keys enroll answered; caProblems
	// its §18.7 differences (or why it couldn't be asked).
	userCAs, hostCAs, caProblems []string
	// dirErr is set while the directory can't be read (the last
	// compilation stays).
	dirErr string
	// compileErr is the last compile error ("" = ok).
	compileErr string
	// changed is closed (and replaced) whenever a host's serial moves:
	// the long-polls wake on it.
	changed chan struct{}

	// kc looks up a person's Keycloak account (disabled = nothing).
	kc SSHUserLookup
	// dir is the directory's SSH checks (ssh_grants.go).
	dir SSHDirectory
	// incomplete: fingerprints revoked without their key (Ruling C21-b).
	incomplete map[string]time.Time
	// breakglassImported / breakglassMalformed: ImportBreakglass's counts
	// (the doctor's ssh_breakglass_cert).
	breakglassImported, breakglassMalformed int

	runMu   sync.Mutex
	pending atomic.Bool
	now     func() time.Time
}

func (r *sshRuntime) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// SetSSHActions wires enroll's SSH API (cmd/hub: the invite client).
func (h *Hub) SetSSHActions(a SSHActions) {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	h.sshrt.actions = a
}

func (h *Hub) sshActions() SSHActions {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	return h.sshrt.actions
}

// sshCompiled is the last good compilation (nil: none).
func (h *Hub) sshCompiled() *sshaccess.Compiled {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	return h.sshrt.compiled
}

// SSHEnabled reports Settings → SSH's switch.
func (h *Hub) SSHEnabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.SSH.Settings.Enabled
}

// SSHSharedAccount reports whether name is a shared account of any grant
// (directory.Service.SSHSharedAccount: such a username can't be created).
func (h *Hub) SSHSharedAccount(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, g := range h.st.SSH.Grants {
		for _, a := range g.Accounts {
			if a == name && a != cliapi.UsernamePlaceholder {
				return true
			}
		}
	}
	return false
}

// sshChanged returns the channel the next serial move closes.
func (h *Hub) sshChanged() <-chan struct{} {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	if h.sshrt.changed == nil {
		h.sshrt.changed = make(chan struct{})
	}
	return h.sshrt.changed
}

// sshBroadcast wakes every long-poll.
func (h *Hub) sshBroadcast() {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	if h.sshrt.changed != nil {
		close(h.sshrt.changed)
	}
	h.sshrt.changed = make(chan struct{})
}

// SetSSHEnabledForTest switches SSH access (tests of other packages).
func (h *Hub) SetSSHEnabledForTest(on bool) error {
	if !testing.Testing() {
		return errors.New("SetSSHEnabledForTest: tests only")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.SSH.Settings.Enabled = on
	return nil
}
