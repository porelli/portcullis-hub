package hub

import (
	"context"

	"io"
	"maps"
	"sync"

	"github.com/portcullis/hub/internal/runtime"
)

// Per-instance runtimes (multiple servers, contract §17): an instance on
// the primary ("" server) uses h.rt; one placed on a worker uses that
// server's agent backend, only while the server is ready. The registry
// has its own lock (never mu: call sites may hold mu).

// Server states (contract §17.3).
const (
	ServerEnrolling = "enrolling"
	ServerReady     = "ready"
	ServerOffline   = "offline"
	ServerRevoked   = "revoked"
)

// serverRT is one worker server as the runtime router sees it.
type serverRT struct {
	Name, State string
	RT          runtime.Instances
}

// serverRegistry: server id → its runtime, instance id → its server.
type serverRegistry struct {
	mu        sync.RWMutex
	servers   map[string]*serverRT
	instances map[string]string
}

func (h *Hub) reg() *serverRegistry {
	h.srvOnce.Do(func() {
		h.srv = &serverRegistry{servers: map[string]*serverRT{}, instances: map[string]string{}}
	})
	return h.srv
}

// setServer records (or with nil removes) a server's runtime state. A
// revoked entry is terminal (review B-M1): only nil (the server's
// removal) replaces it; anything else is refused (false).
func (h *Hub) setServer(id string, s *serverRT) bool {
	r := h.reg()
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == nil {
		delete(r.servers, id)
		return true
	}
	if cur := r.servers[id]; cur != nil && cur.State == ServerRevoked && s.State != ServerRevoked {
		return false
	}
	r.servers[id] = s
	return true
}

// setLive registers server id's backend as state (ready or offline) —
// only while state.yaml still has it neither revoked nor being revoked,
// checked under mu with the registry write (B-M1: a revocation landing
// between a check and the write can't be undone by it). ok: one of the
// accepted states (nil: ready or offline).
func (h *Hub) setLive(id string, rt runtime.Instances, stateName string) bool {
	if h.srvT.beforeSetServer != nil {
		h.srvT.beforeSetServer(id)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.st.Servers[id]
	if !ok || s.Revoke != nil || s.State == ServerRevoked || s.State == ServerEnrolling {
		return false
	}
	return h.setServer(id, &serverRT{Name: s.Name, State: stateName, RT: rt})
}

// noteInstanceServer records instance id's server ("" = primary).
func (h *Hub) noteInstanceServer(id, server string) {
	r := h.reg()
	r.mu.Lock()
	defer r.mu.Unlock()
	if server == "" {
		delete(r.instances, id)
		return
	}
	r.instances[id] = server
}

// noteServersLocked rebuilds the instance → server index from state.
// Caller holds mu.
func (h *Hub) noteServersLocked() {
	r := h.reg()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.instances = map[string]string{}
	for id, in := range h.st.Instances {
		if in.Server != "" {
			r.instances[id] = in.Server
		}
	}
}

// serverOf is instance id's server ("" = the primary).
func (h *Hub) serverOf(id string) string {
	r := h.reg()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.instances[id]
}

// rtFor is instance id's runtime: the primary's for "" server, the
// server's agent backend while it is ready, else 409 (fail closed: an
// unknown server is refused too).
func (h *Hub) rtFor(id string) (runtime.Instances, error) {
	server := h.serverOf(id)
	if server == "" {
		return h.rt, nil
	}
	r := h.reg()
	r.mu.RLock()
	s := r.servers[server]
	r.mu.RUnlock()
	if s == nil {
		return nil, statusErr(409, "server %s is unknown", server)
	}
	name := s.Name
	if name == "" {
		name = server
	}
	switch {
	case s.State == ServerReady && s.RT != nil:
		return s.RT, nil
	case s.State == ServerRevoked:
		return nil, statusErr(409, "server %s is revoked", name)
	case s.State == ServerEnrolling:
		return nil, statusErr(409, "server %s isn't ready yet", name)
	}
	return nil, statusErr(409, "server %s is offline", name)
}

// rtOf is rtFor where the call site has no error path of its own: a
// server that isn't ready answers every call with rtFor's refusal.
func (h *Hub) rtOf(id string) runtime.Instances {
	rt, err := h.rtFor(id)
	if err != nil {
		return refusedRT{err: err, kind: h.rtKind()}
	}
	return rt
}

func (h *Hub) rtKind() runtime.Kind {
	if h.rt == nil {
		return ""
	}
	return h.rt.Kind()
}

// runtimes are "primary" and every ready server's runtime.
func (h *Hub) runtimes() map[string]runtime.Instances {
	out := map[string]runtime.Instances{}
	if h.rt != nil {
		out["primary"] = h.rt
	}
	r := h.reg()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, s := range r.servers {
		if s.State == ServerReady && s.RT != nil {
			out[id] = s.RT
		}
	}
	return maps.Clone(out)
}

// refusedRT answers every call with err (a server that isn't ready).
type refusedRT struct {
	err  error
	kind runtime.Kind
}

var _ runtime.Instances = refusedRT{}

func (r refusedRT) Kind() runtime.Kind                                 { return r.kind }
func (r refusedRT) Env() []string                                      { return nil }
func (r refusedRT) Info(context.Context) (runtime.Info, error)         { return runtime.Info{}, r.err }
func (r refusedRT) Create(context.Context, runtime.Project) error      { return r.err }
func (r refusedRT) Down(context.Context, runtime.Project) error        { return r.err }
func (r refusedRT) DownByName(context.Context, string) error           { return r.err }
func (r refusedRT) EnsureImage(context.Context, string) error          { return r.err }
func (r refusedRT) RemoveVolume(context.Context, string) error         { return r.err }
func (r refusedRT) RemoveHelper(context.Context, string) error         { return r.err }
func (r refusedRT) CreateVolume(context.Context, runtime.Volume) error { return r.err }
func (r refusedRT) Signal(context.Context, string, string) error       { return r.err }
func (r refusedRT) Up(context.Context, runtime.Project, func(string, int64, int64, bool)) error {
	return r.err
}
func (r refusedRT) Pull(context.Context, string, func(int64, int64, bool)) error { return r.err }
func (r refusedRT) List(context.Context, runtime.Filter) ([]runtime.Unit, error) {
	return nil, r.err
}
func (r refusedRT) Inspect(context.Context, string) (runtime.UnitInfo, error) {
	return runtime.UnitInfo{}, r.err
}
func (r refusedRT) Logs(context.Context, string, int, bool) ([]byte, error) { return nil, r.err }
func (r refusedRT) Exec(context.Context, string, runtime.ExecInput) (*runtime.ExecResult, error) {
	return nil, r.err
}
func (r refusedRT) ExecSplit(context.Context, string, runtime.ExecInput) (*runtime.ExecSplitResult, error) {
	return nil, r.err
}
func (r refusedRT) ExecRunning(context.Context, string) (bool, error) { return false, r.err }
func (r refusedRT) State(context.Context, string) (runtime.State, error) {
	return runtime.State{}, r.err
}
func (r refusedRT) Events(context.Context, runtime.Filter, func(runtime.Event)) error {
	return r.err
}
func (r refusedRT) ListVolumes(context.Context, runtime.Filter) ([]runtime.Volume, error) {
	return nil, r.err
}
func (r refusedRT) InspectVolume(context.Context, string) (runtime.Volume, error) {
	return runtime.Volume{}, r.err
}
func (r refusedRT) VolumeOut(context.Context, string, string, string) (io.ReadCloser, error) {
	return nil, r.err
}
func (r refusedRT) VolumeIn(context.Context, string, string, string, io.Reader) error { return r.err }
func (r refusedRT) RunFixer(context.Context, runtime.FixerSpec, func(io.Reader) error) (*runtime.RunResult, error) {
	return nil, r.err
}
