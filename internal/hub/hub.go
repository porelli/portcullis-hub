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
	"reflect"
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
	// OverrideBindRoots is HUB_OVERRIDE_BIND_ROOTS: host directories custom
	// overrides may bind-mount from ("" = /srv:/mnt:/media).
	OverrideBindRoots string
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
	// UpdateClientHosts moves an instance client's redirect URIs and web
	// origins to new hostnames (keycloak.Client.UpdateClientHosts).
	UpdateClientHosts(ctx context.Context, s keycloak.ClientSpec, oldURIs []string, hostMap map[string]string) error
	// UpdateForwardAuthCallbacks adds/removes extra-domain callback URIs
	// on portcullis-forward-auth (contract §5).
	UpdateForwardAuthCallbacks(ctx context.Context, add, remove []string) error
	// EnsureClientAccess / RemoveClientAccess manage an instance client's
	// access role, group mapping and access flow (contract §8).
	EnsureClientAccess(ctx context.Context, s keycloak.AccessSpec) error
	RemoveClientAccess(ctx context.Context, clientID, owner string, allowedHosts []string) error
}

// Hub is the application core. All exported methods are safe for
// concurrent use.
type Hub struct {
	cfg     Config
	compose compose.Runner
	engine  Engine
	idp     IdP
	// domains lists the main and enrolled domains (hosts.go); audit
	// receives instance operations (SetAudit). Both guarded by mu.
	domains DomainSource
	audit   Auditor

	// mu guards st and templates. Never hold it across docker/network calls.
	mu        sync.RWMutex
	st        *state.AppState
	templates []templates.Template // the catalog, by template id
	// instances are the instance views (instances.go): the default
	// instance of every catalog template plus state's instances.
	instances []templates.Template
	// brokenInstances: instance id → why it has no view (template missing
	// or its hostnames no longer fit); listed with state "error".
	brokenInstances map[string]string
	// allTemplates is every template discovered in any source (duplicates
	// and skipped ones included): their default names are reserved
	// (§11.1). templateIDs are their ids.
	allTemplates []templates.Template
	templateIDs  map[string]bool

	// appOps serialises lifecycle operations per app so the slow parts can
	// run without holding mu.
	appOps    sync.Map
	sourceOps sync.Map
	// syncMu: per template id, a *sync.Mutex around its support-file sync
	// (shared by all its instances).
	syncMu sync.Map
	// syncHashes: template dir → tree hash last published there
	// (<data>/template-sync.json); guarded by syncHashMu.
	syncHashMu sync.Mutex
	syncHashes map[string]string
	// lockPoll is how often a queued restart retries the app lock.
	lockPoll time.Duration

	// bg tracks background lifecycle work (queued restarts, default-policy
	// propagation) so callers can wait for it.
	bg sync.WaitGroup

	policyWriteMu   sync.Mutex
	defaultPolicyMu sync.Mutex

	driftMu sync.Mutex
	drift   DriftReport
	// runtimeSubs: subdomains routed by each app project's containers (from
	// their Traefik labels), as last seen by Reconcile.
	runtimeSubs map[string][]string
	driftKey    map[string]string
	kick        chan struct{}
	bindRoots   []string // validated OverrideBindRoots

	// ops: each app's last lifecycle operation (mirrors <data>/ops).
	opsMu sync.Mutex
	ops   map[string]OpRecord

	// Directory publishing (SetDirectory). lastExpiring is the expiring
	// list last written (guarded by policyWriteMu; nil: not yet known).
	dirState     DirectoryState
	attrSync     func(ctx context.Context) error
	lastExpiring []policy.Expiring
	dirKick      chan struct{}
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
	for _, d := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "repos"), filepath.Join(cfg.DataDir, "env"), filepath.Join(cfg.DataDir, "overrides"), filepath.Join(cfg.DataDir, "ops")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, err
		}
	}
	roots, err := ParseBindRoots(cfg.OverrideBindRoots, cfg.ProjectHostDir)
	if err != nil {
		return nil, err
	}
	h := &Hub{
		bindRoots: roots,
		cfg:       cfg,
		compose:   runner,
		engine:    engine,
		idp:       idp,
		lockPoll:  2 * time.Second,
		kick:      make(chan struct{}, 1),
		dirKick:   make(chan struct{}, 1),
		driftKey:  map[string]string{},
		domains:   mainDomainOnly{cfg.Domain},
	}
	st, err := state.Load(h.statePath())
	if err != nil {
		return nil, err
	}
	h.st = st
	h.loadOps()
	h.loadSyncHashes()
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

// Wait blocks until queued background restarts and policy propagation
// have finished.
func (h *Hub) Wait() { h.bg.Wait() }

func (h *Hub) goBackground(fn func()) {
	h.bg.Add(1)
	go func() {
		defer h.bg.Done()
		fn()
	}()
}

// Domain returns the configured base domain.
func (h *Hub) Domain() string { return h.cfg.Domain }

func (h *Hub) statePath() string        { return filepath.Join(h.cfg.DataDir, "state.yaml") }
func (h *Hub) policyPath() string       { return filepath.Join(h.cfg.DataDir, "group-gate-policy.json") }
func (h *Hub) attributesPath() string   { return filepath.Join(h.cfg.DataDir, policy.UserAttributesFile) }
func (h *Hub) envPath(id string) string { return filepath.Join(h.cfg.DataDir, "env", id+".env") }
func (h *Hub) overridePath(id string) string {
	return filepath.Join(h.cfg.DataDir, "overrides", id+".override.yml")
}

// userOverridePath is the app's custom override (Expert mode): kept by the
// Hub, outside the template clone, so template syncs never touch it.
func (h *Hub) userOverridePath(id string) string {
	return filepath.Join(h.cfg.DataDir, "overrides", id+".user.yml")
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
	h.allTemplates = append([]templates.Template(nil), ts...)
	h.templateIDs = map[string]bool{}
	for _, t := range ts {
		h.templateIDs[t.ID] = true
	}
	// The first source wins on duplicate IDs: two templates with the same
	// ID would share a compose project, env file and policy keys.
	seen := map[string]bool{}
	var uniq []templates.Template
	for _, t := range ts {
		if seen[t.ID] {
			log.Printf("Skipping template %s from source %s: ID already provided by another source", t.ID, t.Source)
			continue
		}
		if sub := coreSubdomain(t.Subdomains); sub != "" {
			log.Printf("Skipping template %s: it routes core subdomain %q", t.ID, sub)
			continue
		}
		if e, ok := h.st.Instances[t.ID]; ok && e.Template != t.ID {
			log.Printf("Skipping template %s: its id is already an instance of %s", t.ID, e.Template)
			continue
		}
		seen[t.ID] = true
		uniq = append(uniq, t)
	}
	// A template whose default names (project, volumes, groups, Keycloak
	// clients) an existing instance of another template already derives
	// would share them: the instance was there first.
	byID := map[string]*templates.Template{}
	for i := range uniq {
		byID[uniq[i].ID] = &uniq[i]
	}
	kept := make([]templates.Template, 0, len(uniq))
	for _, t := range uniq {
		if c := h.claimCollision(&t, byID); c != "" {
			log.Printf("Skipping template %s: its default instance would use the %s", t.ID, c)
			continue
		}
		kept = append(kept, t)
	}
	uniq = kept
	templates.Sort(uniq)
	h.templates = uniq
	h.rebuildLocked()
	for _, id := range h.st.Enabled {
		if h.findLocked(id) == nil {
			log.Printf("WARNING: enabled app %s has no (valid) template any more — its containers keep running; disable it to stop them", id)
		}
	}
	if h.refreshPublishedLocked() {
		h.saveLocked()
	}
}

// snapshot captures what an enabled template publishes to group-gate.
// Caller must hold mu.
func (h *Hub) snapshot(t *templates.Template) state.PublishedApp {
	a := t.Manifest.Auth
	acc := h.accessLocked(t)
	p := state.PublishedApp{
		Subdomains:      append([]string(nil), t.Subdomains...),
		GroupAccess:     acc.groupAccess(t),
		NativeLoginOnly: acc.SignIn == SignInNative,
		AccessGroup:     a.AccessGroup,
		AdminGroup:      a.AdminGroup,
		AdminPaths:      append([]string(nil), a.AdminPaths...),
	}
	if ov, ok := h.st.AuthPolicies[t.ID]; ok {
		ov.Factors = append([]string(nil), ov.Factors...)
		p.Policy = &ov
	}
	if pub := h.publicLocked(t, t.Public); pub.Active() {
		p.PublicSubdomains = append([]string(nil), t.Public.Subdomains...)
		p.Public = publicEntry(&t.Manifest, pub.Published)
	}
	return p
}

// refreshPublishedLocked brings state.Published in line with the catalog:
// enabled apps whose template loads get a fresh snapshot, apps that are no
// longer enabled lose theirs, and enabled apps whose template is missing
// keep their last known one. Returns whether anything changed. Caller must
// hold mu (write).
func (h *Hub) refreshPublishedLocked() bool {
	changed := false
	for id := range h.st.Published {
		if !h.st.IsEnabled(id) {
			delete(h.st.Published, id)
			changed = true
		}
	}
	for _, id := range h.st.Enabled {
		t := h.findLocked(id)
		if t == nil {
			continue
		}
		snap := h.snapshot(t)
		if old, ok := h.st.Published[id]; !ok || !reflect.DeepEqual(old, snap) {
			h.st.Published[id] = snap
			changed = true
		}
	}
	return changed
}

// findLocked returns a pointer into the instance views (by instance id;
// a template id names its default instance). Caller must hold mu.
func (h *Hub) findLocked(id string) *templates.Template {
	for i := range h.instances {
		if h.instances[i].ID == id {
			return &h.instances[i]
		}
	}
	return nil
}

// Template returns a copy of an instance's view (nil if unknown).
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
	// Directory state first: it is network I/O, never under h.mu.
	expiring, attrs, keepAttrs := h.directoryState()
	h.driftMu.Lock()
	runtime := make(map[string][]string, len(h.runtimeSubs))
	for id, subs := range h.runtimeSubs {
		runtime[id] = subs
	}
	h.driftMu.Unlock()

	h.mu.RLock()
	perApp := make(map[string]policy.AuthPolicy, len(h.st.AuthPolicies))
	for k, v := range h.st.AuthPolicies {
		perApp[k] = v
	}
	apps := make([]policy.App, 0, len(h.instances))
	covered := map[string]bool{}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		covered[t.ID] = true
		app := policy.App{
			ID:          t.ID,
			Enabled:     true,
			Subdomains:  t.Subdomains,
			GroupAccess: h.accessLocked(t).groupAccess(t),
			AccessGroup: t.Manifest.Auth.AccessGroup,
			AdminGroup:  t.Manifest.Auth.AdminGroup,
			AdminPaths:  t.Manifest.Auth.AdminPaths,
		}
		if pub := h.publicLocked(t, t.Public); pub.Active() {
			app.PublicSubdomains, app.Public = t.Public.Subdomains, publicEntry(&t.Manifest, pub.Published)
		}
		apps = append(apps, app)
	}
	for _, id := range h.st.Enabled {
		if covered[id] {
			continue
		}
		covered[id] = true
		if snap, ok := h.st.Published[id]; ok {
			log.Printf("auth-policy: WARNING: template for enabled app %s is missing — still enforcing its last known config (subdomains %v)", id, snap.Subdomains)
			if _, ok := perApp[id]; !ok && snap.Policy != nil {
				perApp[id] = *snap.Policy
			}
			apps = append(apps, policy.App{
				ID:          id,
				Enabled:     true,
				Subdomains:  snap.Subdomains,
				GroupAccess: snap.GroupAccess,
				AccessGroup: snap.AccessGroup,
				AdminGroup:  snap.AdminGroup,
				AdminPaths:  snap.AdminPaths,
				// The containers keep the public router they were started
				// with: keep showing it.
				PublicSubdomains: snap.PublicSubdomains,
				Public:           snap.Public,
			})
			continue
		}
		if subs := runtime[id]; len(subs) > 0 {
			apps = append(apps, policy.App{ID: id, Enabled: true, Deny: true, Subdomains: subs})
		} else {
			log.Printf("auth-policy: WARNING: enabled app %s has neither a template nor a last known config, and no routed subdomains are known yet — cannot publish a deny entry", id)
		}
	}
	// Running app projects that are not enabled (drift) are routed by
	// Traefik but have no config: deny their subdomains too.
	for id, subs := range runtime {
		if !covered[id] && len(subs) > 0 {
			apps = append(apps, policy.App{ID: id, Enabled: true, Deny: true, Subdomains: subs})
		}
	}
	doc := policy.Build(apps, perApp, h.st.Default())
	doc.Expiring = expiring
	portal := h.portalLocked()
	h.mu.RUnlock()
	if err := policy.Write(h.policyPath(), doc); err != nil {
		return err
	}
	h.lastExpiring = expiring
	var errs []error
	switch {
	case keepAttrs:
	case attrs == nil:
		if err := os.Remove(h.attributesPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	default:
		if err := policy.WriteUserAttributes(h.attributesPath(), *attrs); err != nil {
			errs = append(errs, err)
		}
	}
	// The landing portal's app list (contract §10) changes exactly when
	// the policy does: enable, disable, template sync.
	errs = append(errs, writePortal(h.portalPath(), portal))
	return errors.Join(errs...)
}

func coreSubdomain(subs []string) string {
	for _, s := range subs {
		if policy.CoreSubdomains[s] {
			return s
		}
	}
	return ""
}

func (h *Hub) writePolicyLogged() {
	if err := h.WritePolicy(); err != nil {
		log.Printf("auth-policy: group-gate policy write failed: %v", err)
	}
}
