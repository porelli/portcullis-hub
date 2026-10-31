// Package hub is the Hub's application core: template catalog, per-app
// lifecycle (enable/disable/restart) with per-app locking, env/override
// generation, template sources, the group-gate policy file and the
// state-vs-Docker reconcile loop. HTTP lives in internal/httpapi.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// ProjectPrefix prefixes every app's compose project name.
const ProjectPrefix = "portcullis-"

const (
	execTimeout = 15 * time.Minute
	gitTimeout  = 5 * time.Minute
)

// Config is the Hub's static configuration.
type Config struct {
	ProjectDir     string // core checkout as seen by the Hub (container path)
	ProjectHostDir string // same checkout as seen by the Docker daemon (host path)
	DataDir        string // writable state: state.yaml, env/, overrides/, repos/, policy file
	Domain         string
	// DefaultTemplatesURL is cloned as source "portcullis" when no source
	// is configured.
	DefaultTemplatesURL string
	// ReconcileInterval is the periodic drift check (default 60s).
	ReconcileInterval time.Duration
}

// Engine is the part of the Docker Engine API the Hub uses.
type Engine interface {
	ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error)
	Logs(ctx context.Context, id string, tail int, timestamps bool) ([]byte, error)
	Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (*docker.ExecResult, error)
	Events(ctx context.Context, f docker.Filters, fn func(docker.Event)) error
}

// IdP manages the OIDC clients templates declare.
type IdP interface {
	RegisterClient(ctx context.Context, s keycloak.ClientSpec) error
	UpdateClientACR(ctx context.Context, s keycloak.ClientSpec) error
}

// Hub is the application core. All exported methods are safe for
// concurrent use.
type Hub struct {
	cfg     Config
	compose compose.Runner
	engine  Engine
	idp     IdP

	// mu guards st and templates. Never hold it across docker/network calls.
	mu        sync.RWMutex
	st        *state.AppState
	templates []templates.Template

	// appOps serialises lifecycle operations per app so the slow parts can
	// run without holding mu.
	appOps    sync.Map
	sourceOps sync.Map
	// lockPoll is how often a queued restart retries the app lock.
	lockPoll time.Duration

	policyWriteMu   sync.Mutex
	defaultPolicyMu sync.Mutex

	driftMu  sync.Mutex
	drift    DriftReport
	driftKey map[string]string
	kick     chan struct{}
}

// New loads state from cfg.DataDir and prepares the data directories. It
// fails on a corrupt state file rather than starting empty.
func New(cfg Config, runner compose.Runner, engine Engine, idp IdP) (*Hub, error) {
	if cfg.ProjectHostDir == "" {
		cfg.ProjectHostDir = cfg.ProjectDir
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = time.Minute
	}
	for _, d := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "repos"), filepath.Join(cfg.DataDir, "env"), filepath.Join(cfg.DataDir, "overrides")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, err
		}
	}
	h := &Hub{
		cfg:      cfg,
		compose:  runner,
		engine:   engine,
		idp:      idp,
		lockPoll: 2 * time.Second,
		kick:     make(chan struct{}, 1),
		driftKey: map[string]string{},
	}
	st, err := state.Load(h.statePath())
	if err != nil {
		return nil, err
	}
	h.st = st
	return h, nil
}

// Init clones the default source on first run, discovers templates and
// seeds the group-gate policy file.
func (h *Hub) Init() {
	h.autoLoadDefaultTemplates()
	h.Discover()
	if err := h.WritePolicy(); err != nil {
		log.Printf("auth-policy: initial group-gate policy write failed: %v", err)
	}
}

// Domain returns the configured base domain.
func (h *Hub) Domain() string { return h.cfg.Domain }

func (h *Hub) statePath() string        { return filepath.Join(h.cfg.DataDir, "state.yaml") }
func (h *Hub) policyPath() string       { return filepath.Join(h.cfg.DataDir, "group-gate-policy.json") }
func (h *Hub) envPath(id string) string { return filepath.Join(h.cfg.DataDir, "env", id+".env") }
func (h *Hub) overridePath(id string) string {
	return filepath.Join(h.cfg.DataDir, "overrides", id+".override.yml")
}
func (h *Hub) templatesRoot() string { return filepath.Join(h.cfg.ProjectDir, "templates") }
func projectName(id string) string   { return ProjectPrefix + id }

// saveLocked persists state. Caller must hold mu (write).
func (h *Hub) saveLocked() {
	if err := h.st.Save(h.statePath()); err != nil {
		log.Printf("ERROR: save state: %v", err)
	}
}

// ── errors ───────────────────────────────────────────────

// StatusError carries the HTTP status an error should map to.
type StatusError struct {
	Status int
	Err    error
}

func (e *StatusError) Error() string { return e.Err.Error() }
func (e *StatusError) Unwrap() error { return e.Err }

func statusErr(code int, format string, args ...interface{}) error {
	return &StatusError{Status: code, Err: fmt.Errorf(format, args...)}
}

// ErrNotFound is returned for unknown template IDs.
var ErrNotFound = &StatusError{Status: http.StatusNotFound, Err: errors.New("not found")}

// ── catalog ──────────────────────────────────────────────

// Discover rebuilds the template catalog from the configured sources.
func (h *Hub) Discover() {
	h.mu.Lock()
	defer h.mu.Unlock()
	var ts []templates.Template
	for _, src := range h.st.Sources {
		if src.Path != "" {
			ts = append(ts, templates.Discover(src.Path, src.Name, h.cfg.Domain)...)
		}
	}
	// The first source wins on duplicate IDs: two templates with the same
	// ID would share a compose project, env file and policy keys.
	seen := map[string]bool{}
	uniq := ts[:0]
	for _, t := range ts {
		if seen[t.ID] {
			log.Printf("Skipping template %s from source %s: ID already provided by another source", t.ID, t.Source)
			continue
		}
		seen[t.ID] = true
		t.Enabled = h.st.IsEnabled(t.ID)
		uniq = append(uniq, t)
	}
	for _, id := range h.st.Enabled {
		if !seen[id] {
			log.Printf("WARNING: enabled app %s has no (valid) template any more — its containers keep running; disable it to stop them", id)
		}
	}
	templates.Sort(uniq)
	h.templates = uniq
}

// findLocked returns a pointer into the catalog. Caller must hold mu.
func (h *Hub) findLocked(id string) *templates.Template {
	for i := range h.templates {
		if h.templates[i].ID == id {
			return &h.templates[i]
		}
	}
	return nil
}

// Template returns a copy of a template (nil if unknown).
func (h *Hub) Template(id string) *templates.Template {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if t := h.findLocked(id); t != nil {
		c := *t
		return &c
	}
	return nil
}

// Templates returns a copy of the catalog.
func (h *Hub) Templates() []templates.Template {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]templates.Template(nil), h.templates...)
}

// Sources returns a copy of the configured sources.
func (h *Hub) Sources() []state.Source {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]state.Source(nil), h.st.Sources...)
}

// Counts summarises the catalog for /api/status.
func (h *Hub) Counts() (templates, enabled, sources int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.templates), len(h.st.Enabled), len(h.st.Sources)
}

// IsEnabled reports whether id is enabled.
func (h *Hub) IsEnabled(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.IsEnabled(id)
}

// ── group-gate policy file ───────────────────────────────

// WritePolicy regenerates group-gate-policy.json from current state. Takes
// mu itself — callers must NOT hold it.
func (h *Hub) WritePolicy() error {
	// Serialise snapshot → rename so an older snapshot can never overwrite a
	// newer one (a stale file could drop groups and fail open).
	h.policyWriteMu.Lock()
	defer h.policyWriteMu.Unlock()
	h.mu.RLock()
	apps := make([]policy.App, 0, len(h.templates))
	for i := range h.templates {
		t := &h.templates[i]
		a := policy.App{
			ID:          t.ID,
			Enabled:     t.Enabled,
			GroupAccess: t.Manifest.Auth.GroupAccess,
			AccessGroup: t.Manifest.Auth.AccessGroup,
			AdminGroup:  t.Manifest.Auth.AdminGroup,
			AdminPaths:  t.Manifest.Auth.AdminPaths,
		}
		if t.Enabled {
			a.Subdomains = templates.Subdomains(t.ReadCompose())
		}
		apps = append(apps, a)
	}
	perApp := make(map[string]policy.AuthPolicy, len(h.st.AuthPolicies))
	for k, v := range h.st.AuthPolicies {
		perApp[k] = v
	}
	doc := policy.Build(apps, perApp, h.st.DefaultPolicy)
	h.mu.RUnlock()
	return policy.Write(h.policyPath(), doc)
}

func (h *Hub) writePolicyLogged() {
	if err := h.WritePolicy(); err != nil {
		log.Printf("auth-policy: group-gate policy write failed: %v", err)
	}
}
