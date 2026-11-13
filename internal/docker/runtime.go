package docker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"
)

// Runtime is the container engine core runs on (contract §6:
// HUB_CONTAINER_RUNTIME, from core's CONTAINER_RUNTIME).
type Runtime string

const (
	RuntimeDocker Runtime = "docker"
	RuntimePodman Runtime = "podman"
)

// ParseRuntime accepts exactly "docker" or "podman"; anything else
// (empty included) is an error. There is no default.
func ParseRuntime(s string) (Runtime, error) {
	switch Runtime(s) {
	case RuntimeDocker, RuntimePodman:
		return Runtime(s), nil
	case "":
		return "", errors.New("the container runtime is not set (docker or podman)")
	}
	return "", fmt.Errorf("unknown container runtime %q (docker or podman)", s)
}

// Engine component names in GET /version (Components[].Name). Upstream
// calls the field informational; TestRuntimeOf pins the names we rely on.
const (
	ComponentDocker = "Engine"
	ComponentPodman = "Podman Engine"
)

// ErrEngineRefused is wrapped by every refusal of the runtime guard: the
// engine isn't verified (yet), or it contradicts HUB_CONTAINER_RUNTIME.
// The API answers it with 503.
var ErrEngineRefused = errors.New("the container engine is not verified")

// RefusedError is the guard's refusal; errors.Is(err, ErrEngineRefused).
// guard (set on the request hook's refusals) names the guard whose
// current refusal Message reports.
type RefusedError struct {
	Why   string
	guard *Guard
}

func (e *RefusedError) Error() string { return ErrEngineRefused.Error() + ": " + e.Why }

// Message is the refusal to show: the guard's current one when e came
// from a request (its fixed text never carries the guard's reasons, see
// guardHook), else e's own.
func (e *RefusedError) Message() string {
	if e.guard != nil {
		if err := e.guard.Err(); err != nil {
			return err.Error()
		}
	}
	return e.Error()
}

// hookWhy is the fixed text of a request the guard refused. It never
// carries an engine error or engine names: the SDK replaces a transport
// error whose text holds "connection refused" or "dial unix" with its own
// unwrapped error (moby client request.go), which would lose
// ErrEngineRefused and with it the 503.
const hookWhy = "engine operations wait until the start-time check passes (GET /api/runtime shows why)"

// whyUnanswered is the guard's refusal while the engine's /version can't
// be read (the read error itself is logged and kept in LastError, never
// put into the refusal).
const whyUnanswered = "the engine's /version doesn't answer yet"

// Is makes errors.Is(err, ErrEngineRefused) hold.
func (e *RefusedError) Is(target error) bool { return target == ErrEngineRefused }

// Component is one entry of GET /version's Components.
type Component struct {
	Name    string
	Version string
}

// VersionReader reads the engine's /version components.
type VersionReader interface {
	Components(ctx context.Context) ([]Component, error)
}

// RuntimeOf names the runtime the components describe: a "Podman Engine"
// component → podman, else an "Engine" one → docker, else "".
func RuntimeOf(cs []Component) Runtime {
	for _, c := range cs {
		if c.Name == ComponentPodman {
			return RuntimePodman
		}
	}
	for _, c := range cs {
		if c.Name == ComponentDocker {
			return RuntimeDocker
		}
	}
	return ""
}

// componentOf is the component that names rt.
func componentOf(cs []Component, rt Runtime) Component {
	want := ComponentDocker
	if rt == RuntimePodman {
		want = ComponentPodman
	}
	for _, c := range cs {
		if c.Name == want {
			return c
		}
	}
	return Component{}
}

// EngineInfo is what the guard knows about the engine.
type EngineInfo struct {
	Runtime  Runtime // HUB_CONTAINER_RUNTIME
	Verified bool
	Engine   string // the component that identified the engine ("Engine", "Podman Engine")
	Version  string // its version
	Mismatch string // set once the engine contradicted Runtime (permanent)
}

// Guard holds every engine operation until the engine's /version agrees
// with the configured runtime (contract §6). Unverified = refused (retried
// by Run); a contradiction is permanent: the Hub keeps running and
// answers 503 until it is restarted with a matching engine.
type Guard struct {
	want     Runtime
	mu       sync.Mutex
	err      error
	info     EngineInfo
	verified chan struct{}
	settled  chan struct{}
	lastErr  error // the last failed /version read (logged by Run)
}

// NewGuard returns an unverified guard for want.
func NewGuard(want Runtime) *Guard {
	return &Guard{
		want:     want,
		err:      &RefusedError{Why: "not checked yet"},
		info:     EngineInfo{Runtime: want},
		verified: make(chan struct{}),
		settled:  make(chan struct{}),
	}
}

// Runtime is the configured runtime.
func (g *Guard) Runtime() Runtime { return g.want }

// Err is nil once verified, else the refusal (wrapping ErrEngineRefused).
func (g *Guard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// Info is a copy of what the guard knows.
func (g *Guard) Info() EngineInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.info
}

// LastError is the last failed /version read (nil: none).
func (g *Guard) LastError() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastErr
}

// Verified is closed once the engine is verified.
func (g *Guard) Verified() <-chan struct{} { return g.verified }

// Settled is closed once the guard's state is final: verified or a
// mismatch.
func (g *Guard) Settled() <-chan struct{} { return g.settled }

// Verify asks r once. A failed read leaves the guard unverified (retry);
// an answer naming another runtime, or none, is a permanent mismatch.
// It returns the guard's error after the check (nil = verified).
func (g *Guard) Verify(ctx context.Context, r VersionReader) error {
	g.mu.Lock()
	if g.info.Verified || g.info.Mismatch != "" {
		defer g.mu.Unlock()
		return g.err
	}
	g.mu.Unlock()
	cs, err := r.Components(ctx)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.info.Verified || g.info.Mismatch != "" {
		return g.err
	}
	if err != nil {
		g.lastErr = err
		g.err = &RefusedError{Why: whyUnanswered}
		return g.err
	}
	rt := RuntimeOf(cs)
	if rt != g.want {
		engine := "unknown"
		if rt != "" {
			engine = componentOf(cs, rt).Name
			if rt == RuntimeDocker {
				engine = "Docker Engine"
			}
		} else if names := componentNames(cs); names != "" {
			engine = "unknown (" + names + ")"
		}
		g.info.Mismatch = fmt.Sprintf("HUB_CONTAINER_RUNTIME=%s but the engine is %s", g.want, engine)
		g.err = &RefusedError{Why: g.info.Mismatch}
		close(g.settled)
		return g.err
	}
	c := componentOf(cs, rt)
	g.info.Verified, g.info.Engine, g.info.Version = true, c.Name, c.Version
	g.err = nil
	close(g.verified)
	close(g.settled)
	return nil
}

func componentNames(cs []Component) string {
	var names []string
	for _, c := range cs {
		if n := strings.TrimSpace(c.Name); n != "" && len(names) < 4 {
			names = append(names, fmt.Sprintf("%q", clip(n, 64)))
		}
	}
	return strings.Join(names, ", ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Run verifies until the guard is settled (verified or a mismatch) or ctx
// ends, every `every`; it logs once per change of state.
func (g *Guard) Run(ctx context.Context, r VersionReader, every time.Duration) {
	last := ""
	for {
		err := g.Verify(ctx, r)
		msg := "ok"
		if err != nil {
			msg = err.Error()
			if le := g.LastError(); le != nil && g.Info().Mismatch == "" {
				msg += " (" + le.Error() + ")"
			}
		}
		if msg != last {
			if err == nil {
				i := g.Info()
				log.Printf("engine: verified: %s %s (HUB_CONTAINER_RUNTIME=%s)", i.Engine, i.Version, i.Runtime)
			} else {
				log.Printf("engine: %s — engine operations answer 503", msg)
			}
			last = msg
		}
		select {
		case <-g.settled:
			return
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-g.settled:
			return
		case <-time.After(every):
		}
	}
}

// unguardedPath: the requests the guard always lets through, the ones
// verification itself needs (the SDK's version negotiation pings with
// HEAD, then GET, /_ping).
var versionPathRe = regexp.MustCompile(`^(/v[0-9][0-9.]*)?/version$`)

func unguarded(r *http.Request) bool {
	switch {
	case r.URL.Path == "/_ping":
		return r.Method == http.MethodHead || r.Method == http.MethodGet
	case versionPathRe.MatchString(r.URL.Path):
		return r.Method == http.MethodGet
	}
	return false
}

// guardHook is the client's request hook: everything but unguarded
// requests returns the guard's error while it has one.
func guardHook(g *Guard) client.RequestHook {
	return func(r *http.Request) error {
		if unguarded(r) || g.Err() == nil {
			return nil
		}
		return &RefusedError{Why: hookWhy, guard: g}
	}
}

// Components is GET /version's Components (VersionReader).
func (c *Client) Components(ctx context.Context) ([]Component, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]Component, 0, len(res.Components))
	for _, cv := range res.Components {
		out = append(out, Component{Name: cv.Name, Version: cv.Version})
	}
	return out, nil
}
