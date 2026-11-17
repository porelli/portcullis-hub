package hub

import (
	"context"
	"fmt"
	"github.com/portcullis/hub/internal/directory"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/templates"
)

// Placement (contract §17, pre-flight P9/P10): an instance runs on the
// primary or on one worker server. Everything a render reads of the
// engine is that server's (engineFacts), and a worker instance's runtime
// is placedRT: its bundle pushed before the create, its relays on the
// primary up after the up and down before the down.

// engineFacts are the engine an instance runs on: the primary's from the
// Hub's config and caches, a worker's from its last /v1/info.
type engineFacts struct {
	Kind                  runtime.Kind
	Rootless, SELinux     bool
	UnprivilegedPortStart int
	ForbiddenRoots        []string
	// AppFilesHost is where the data files are on the engine's host.
	AppFilesHost string
	BindRoots    []string
	Arch         string
	// Known: a worker's facts were read (false: no /v1/info yet).
	Known bool
}

// serverInfo is a server's last /v1/info (nil: none yet).
func (h *Hub) serverInfo(server string) *agentapi.Info {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if ps := h.polls[server]; ps != nil && ps.info != nil {
		i := *ps.info
		return &i
	}
	return nil
}

// factsOfServer are server's engine facts ("" = the primary).
func (h *Hub) factsOfServer(server string) engineFacts {
	if server == "" {
		return engineFacts{Kind: h.cfg.Runtime, Rootless: h.rootlessOn(), SELinux: h.rootlessOn() && h.selinuxCached(),
			UnprivilegedPortStart: h.unprivilegedPortStart(), AppFilesHost: filepath.ToSlash(h.cfg.AppFilesHostDir),
			BindRoots: h.bindRoots, Known: true}
	}
	inf := h.serverInfo(server)
	if inf == nil {
		return engineFacts{}
	}
	f := engineFacts{Kind: runtime.Kind(inf.Runtime), Rootless: inf.Rootless, SELinux: inf.SELinux,
		UnprivilegedPortStart: inf.UnprivilegedPortStart, BindRoots: inf.BindRoots, Arch: inf.Arch, Known: true}
	if inf.DataDir != "" {
		f.AppFilesHost = path.Join(inf.DataDir, "appfiles")
	}
	if inf.DockerRootDir != "" {
		f.ForbiddenRoots = []string{inf.DockerRootDir}
	}
	return f
}

// factsFor are instance id's engine facts.
func (h *Hub) factsFor(id string) engineFacts { return h.factsOfServer(h.serverOf(id)) }

// relabelFor: instance id's binds are relabelled (rootless Podman on
// SELinux, P10), judged by the engine it runs on.
func (h *Hub) relabelFor(id string) bool {
	f := h.factsFor(id)
	return f.Kind == runtime.KindPodman && f.SELinux
}

// appFilesHostFor is the data files' directory on id's engine host.
func (h *Hub) appFilesHostFor(id string) string { return h.factsFor(id).AppFilesHost }

// refreshServerFacts reads server's /v1/info now (a render must never
// use facts of an engine it can't reach): 409 when it isn't ready.
func (h *Hub) refreshServerFacts(ctx context.Context, server string) (*agentapi.Info, error) {
	rt, err := h.rtForServer(server)
	if err != nil {
		return nil, err
	}
	b, ok := unwrapRT(rt).(agentInfoer)
	if !ok {
		return nil, statusErr(409, "server %s has no agent backend", h.serverName(server))
	}
	c, cancel := context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
	defer cancel()
	inf, err := b.AgentInfo(c)
	if err != nil {
		return nil, statusErr(409, "server %s doesn't answer: %v", h.serverName(server), err)
	}
	h.notePoll(server, &inf, "")
	return &inf, nil
}

// agentInfoer reads a worker's /v1/info (the agent backend).
type agentInfoer interface {
	AgentInfo(ctx context.Context) (agentapi.Info, error)
}

// bundlePusher sends a worker its instance bundle (the agent backend).
type bundlePusher interface {
	PushBundle(ctx context.Context, id string, files fs.FS, m agentapi.BundleManifest) error
}

// rtForServer is a server's runtime: the primary's for "", the agent
// backend of a ready worker, else 409.
func (h *Hub) rtForServer(server string) (runtime.Instances, error) {
	if server == "" || server == servers.PrimaryID {
		return h.rt, nil
	}
	r := h.reg()
	r.mu.RLock()
	s := r.servers[server]
	r.mu.RUnlock()
	switch {
	case s == nil:
		return nil, statusErr(409, "server %s is unknown", server)
	case s.State == ServerReady && s.RT != nil:
		return s.RT, nil
	case s.State == ServerRevoked:
		return nil, statusErr(409, "server %s is revoked", nameOr(s.Name, server))
	case s.State == ServerEnrolling:
		return nil, statusErr(409, "server %s isn't ready yet", nameOr(s.Name, server))
	}
	return nil, statusErr(409, "server %s is offline", nameOr(s.Name, server))
}

// checkPlacement: template t may be created on server (contract §17,
// Task 10): the server is ready; the template isn't primary-only
// (templates.Placement); its runtime compatibility on the server's engine
// passes; every image pulls for the server's architecture. Each refusal
// is a 409 before anything is created.
func (h *Hub) checkPlacement(ctx context.Context, t *templates.Template, server string) error {
	if server == "" || server == servers.PrimaryID {
		return nil
	}
	if err := servers.ValidID(server); err != nil {
		return statusErr(400, "server: %v", err)
	}
	if h.kubeOn() {
		return statusErr(409, "servers need a Docker or Podman primary")
	}
	if _, err := h.serversOn(); err != nil {
		return err
	}
	h.mu.RLock()
	_, known := h.st.Servers[server]
	perr := h.placeableLocked(server)
	h.mu.RUnlock()
	if !known {
		return statusErr(400, "no server %s", server)
	}
	if perr != nil {
		return perr
	}
	inf, err := h.refreshServerFacts(ctx, server)
	if err != nil {
		return err
	}
	compose := t.ReadCompose()
	env := h.compatEnv(readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env")))
	env[templates.EnvBindRoots] = strings.Join(inf.BindRoots, ":")
	if primaryOnly, reasons := templates.Placement(compose, t.Manifest, env, inf.BindRoots); primaryOnly {
		return statusErr(409, "%s can't run on a worker: %s", t.Manifest.Name, strings.Join(reasons, "; "))
	}
	kind := runtime.Kind(inf.Runtime)
	if c := templates.RuntimeCompat(kind, compose, t.Manifest, env, inf.UnprivilegedPortStart); c.Status == templates.CompatRefused {
		return statusErr(409, "%s can't run on %s (%s): %s", t.Manifest.Name, h.serverName(server), kind, strings.Join(c.Reasons, "; "))
	}
	rt, err := h.rtForServer(server)
	if err != nil {
		return err
	}
	imgs := templates.ServiceImages(compose)
	type pull struct{ raw, ref string }
	var pulls []pull
	for _, raw := range imgs {
		if raw == "" || slices.ContainsFunc(pulls, func(p pull) bool { return p.raw == raw }) {
			continue
		}
		// Resolved only from the template's own defaults and the
		// non-secret variables imageRefVars allows (never the core env:
		// a ref is echoed in errors); anything else is refused.
		ref, ok := expandRef(raw, imageRefEnv(h, inf))
		if !ok {
			return statusErr(409, "the image reference %s uses a variable that can't be resolved here", raw)
		}
		pulls = append(pulls, pull{raw, ref})
	}
	sort.Slice(pulls, func(i, j int) bool { return pulls[i].raw < pulls[j].raw })
	// A worker runs only images pinned by digest (it never pulls a
	// mutable tag): every ref is checked before any pull.
	for _, pl := range pulls {
		if !docker.DigestRef(pl.ref) {
			return statusErr(409, "image %s isn't pinned by digest: templates must pin images to run on a worker", pl.raw)
		}
	}
	// No bundle exists yet: the agent pulls only with preflight (a ref
	// pinned by digest, contract §17.4).
	pre, ok := rt.(preflighter)
	if !ok {
		return statusErr(409, "%s can't pre-pull images", h.serverName(server))
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	for _, pl := range pulls {
		// Messages name the template's unexpanded reference.
		if err := pre.PreflightPull(pctx, pl.ref); err != nil {
			// The agent's own words in the log only (the ref, the server and
			// its message, clipped; refs carry no secret: imageRefEnv).
			log.Printf("placement: pre-pull of %s on %s failed: %s", pl.ref, server, untrusted(err.Error(), 300))
			if noPlatform(err) {
				return statusErr(409, "%s has no %s image", pl.raw, untrusted(inf.Arch, 20))
			}
			return statusErr(409, "pulling %s on %s failed", pl.raw, h.serverName(server))
		}
	}
	return nil
}

// preflighter is an agent backend's placement pre-pull.
type preflighter interface {
	PreflightPull(ctx context.Context, ref string) error
}

// placedRT is a worker instance's runtime: the agent backend, with the
// bundle pushed before every create and the relays on the primary up
// after an up and down before a down (Task 10 order).
type placedRT struct {
	runtime.Instances
	h  *Hub
	id string
}

var _ runtime.Instances = placedRT{}

// Unwrap is the agent backend (agentrt.Unwrap).
func (p placedRT) Unwrap() runtime.Instances { return p.Instances }

func (p placedRT) Create(ctx context.Context, pr runtime.Project) error {
	if err := p.h.pushBundle(ctx, p.id, p.Instances); err != nil {
		return err
	}
	return p.Instances.Create(ctx, pr)
}

func (p placedRT) Up(ctx context.Context, pr runtime.Project, onPull func(string, int64, int64, bool)) error {
	if err := p.Instances.Up(ctx, pr, onPull); err != nil {
		return err
	}
	return p.h.relaysUp(ctx, p.id)
}

func (p placedRT) Down(ctx context.Context, pr runtime.Project) error {
	if err := p.h.relaysDown(ctx, p.id); err != nil {
		return err
	}
	return p.Instances.Down(ctx, pr)
}

func (p placedRT) DownByName(ctx context.Context, name string) error {
	if name == projectName(p.id) {
		if err := p.h.relaysDown(ctx, p.id); err != nil {
			return err
		}
	}
	return p.Instances.DownByName(ctx, name)
}

// DeliverFile passes a data file to the agent (fileDeliverer), after the
// placement and quarantine checks (R3-L12; no stop from here).
func (p placedRT) DeliverFile(ctx context.Context, instance string, f runtime.FileDelivery) error {
	if err := p.h.placedCheck(ctx, instance, true, false); err != nil {
		return err
	}
	if err := p.h.pushAllowed(p.h.serverOf(instance)); err != nil {
		return err
	}
	d, ok := p.Instances.(fileDeliverer)
	if !ok {
		return statusErr(500, "the worker's runtime can't take data files")
	}
	return d.DeliverFile(ctx, instance, f)
}

// placedPreflight (fix round 3): a placed instance's template must still
// be placeable — a template update can make it primary-only (an ai
// block: its provider secrets never reach a worker; primary_only; a core
// volume …) — and the instance not quarantined by its agent. A template
// turned primary-only stops the instance on the worker and is doctor
// server_placement_invalid; nothing is rendered or sent.
func (h *Hub) placedPreflight(ctx context.Context, id string) error {
	return h.placedCheck(ctx, id, true, true)
}

// placedCheck is placedPreflight's work: quarantine whether the agent's
// quarantine refuses (a bundle push doesn't: a PUT never lifts it, and a
// lift is followed by a push, R3-M2); stop whether a primary-only
// template is stopped on the worker.
func (h *Hub) placedCheck(ctx context.Context, id string, quarantine, stop bool) error {
	server := h.serverOf(id)
	if server == "" {
		return nil
	}
	h.mu.RLock()
	v := h.findLocked(id)
	var t templates.Template
	if v != nil {
		t = *v
	}
	h.mu.RUnlock()
	if v == nil {
		return statusErr(409, "instance %s does not resolve", id)
	}
	f := h.factsOfServer(server)
	env := h.compatEnv(readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env")))
	for k, val := range readEnvRaw(h.envPath(id)) {
		env[k] = val
	}
	env[templates.EnvBindRoots] = strings.Join(f.BindRoots, ":")
	if primaryOnly, reasons := templates.Placement(t.ReadCompose(), t.Manifest, env, f.BindRoots); primaryOnly {
		why := strings.Join(reasons, "; ")
		h.notePlacementInvalid(id, why)
		// Stopped on the worker (and its relays on the primary), best
		// effort: nothing new is sent either way.
		if stop {
			h.stopInvalidPlacement(ctx, &t, server)
		}
		return statusErr(409, "%s can't run on a worker any more: %s; move it to the primary", t.Manifest.Name, why)
	}
	h.notePlacementInvalid(id, "")
	if inf := h.serverInfo(server); inf != nil && quarantine {
		why := inf.Quarantined[id]
		if why == "" {
			why = inf.Quarantined["*"] // every instance (the agent's file is unreadable)
		}
		if why != "" {
			return statusErr(409, "%s is quarantined on %s (%s): an admin must lift the quarantine", id, serverLabel(server), untrusted(why, 200))
		}
	}
	return nil
}

// notePlacementInvalid records why instance id can't run on its worker
// any more ("" = it can): doctor server_placement_invalid.
func (h *Hub) notePlacementInvalid(id, why string) {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if why == "" {
		delete(h.placementInvalid, id)
		return
	}
	if h.placementInvalid == nil {
		h.placementInvalid = map[string]string{}
	}
	h.placementInvalid[id] = why
}

// relaysFirst brings a placed, enabled instance's relays to the labels
// the Hub renders now, on the primary, before anything on the worker
// (review B2-H2). A relay that can't be updated is stopped (fail closed).
func (h *Hub) relaysFirst(ctx context.Context, t *templates.Template) error {
	h.mu.RLock()
	enabled := h.st.IsEnabled(t.ID)
	h.mu.RUnlock()
	if !enabled {
		return nil
	}
	if err := h.relaysUp(ctx, t.ID); err != nil {
		if derr := h.relaysDown(ctx, t.ID); derr != nil {
			return fmt.Errorf("%s: its relays couldn't be updated (%v) nor stopped: %w", t.ID, err, derr)
		}
		return fmt.Errorf("%s: its relays couldn't be updated, so they were stopped: %w", t.ID, err)
	}
	return nil
}

// LiftQuarantine asks instance id's worker to lift the agent's
// quarantine (fix round 3, A2-M1; the T12 route: admin, fresh sign-in):
// the agent walks the bundle's bind sources again first. Audited
// server.quarantine_lift.
func (h *Hub) LiftQuarantine(ctx context.Context, actor directory.Actor, id string) (err error) {
	defer func() { h.auditOp(actor, "server.quarantine_lift", id, "", err) }()
	if actor.User == "" {
		return statusErr(401, "no acting user")
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
	}
	defer unlock()
	if err := h.pending(id); err != nil {
		return err // moving (R4-L5), deleting, restoring
	}
	server := h.serverOf(id)
	if server == "" {
		return statusErr(409, "%s runs on the primary: nothing is quarantined", id)
	}
	rt, err := h.rtForServer(server)
	if err != nil {
		return err
	}
	b, ok := unwrapRT(rt).(interface {
		Unquarantine(ctx context.Context, id string) error
	})
	if !ok {
		return statusErr(500, "the worker's runtime can't lift a quarantine")
	}
	if err := b.Unquarantine(ctx, id); err != nil {
		return err
	}
	// Then the bundle through the normal, validated path (R3-M2): the
	// agent quarantines it again if it refuses it.
	if err := h.pushBundle(ctx, id, rt); err != nil {
		h.refreshServerFacts(ctx, server)
		return fmt.Errorf("the quarantine was lifted, but the bundle push failed (the instance stays refused until a push succeeds): %w", err)
	}
	_, err = h.refreshServerFacts(ctx, server)
	return err
}

// imageRefVars are the only variables an image reference may name
// (non-secret, listed explicitly): the main domain and the worker's
// folder roots.
var imageRefVars = []string{"PORTCULLIS_DOMAIN", templates.EnvBindRoots}

// imageRefEnv is imageRefVars' values for a worker.
func imageRefEnv(h *Hub, inf *agentapi.Info) map[string]string {
	return map[string]string{"PORTCULLIS_DOMAIN": h.cfg.Domain, templates.EnvBindRoots: strings.Join(inf.BindRoots, ":")}
}

// expandRef resolves ${VAR}, ${VAR:-def}, ${VAR-def} and $VAR in an image
// reference: an allowed variable from env, else the reference's own
// (template-declared) default; ok false when a variable is neither.
func expandRef(ref string, env map[string]string) (string, bool) {
	ok := true
	out := os.Expand(ref, func(k string) string {
		name, def, hasDef := k, "", false
		if i := strings.Index(k, ":-"); i >= 0 {
			name, def, hasDef = k[:i], k[i+2:], true
		} else if i := strings.Index(k, "-"); i >= 0 {
			name, def, hasDef = k[:i], k[i+1:], true
		}
		if slices.Contains(imageRefVars, name) {
			if v := env[name]; v != "" {
				return v
			}
		}
		if hasDef {
			return def
		}
		ok = false
		return ""
	})
	if strings.Contains(out, "$") {
		ok = false
	}
	return out, ok
}

// reservedOnWorker: the instance ids no worker takes — "worker" (the
// worker stack's own project name) and any whose project would be the
// agent's own (its /v1/info own_project).
func (h *Hub) checkReservedID(id, server string) error {
	if server == "" {
		return nil
	}
	own := ""
	if inf := h.serverInfo(server); inf != nil {
		own = inf.OwnProject
	}
	if id == "worker" || (own != "" && projectName(id) == own) {
		return statusErr(409, "the instance id %s is reserved on a worker: its project would be the worker's own — choose another id", id)
	}
	return nil
}

// checkWorkerClean refuses (409) a create or move of id onto worker
// server while the agent still holds a bundle of id the Hub doesn't run
// there (final re-review N2/M1: an earlier copy, its env and volumes,
// would be taken over silently). The agent's 404 is "holds nothing"; an
// unreadable answer refuses too (fail closed).
func (h *Hub) checkWorkerClean(ctx context.Context, server, id string) error {
	if server == "" {
		return nil
	}
	rt, err := h.rtForServer(server)
	if err != nil {
		return statusErr(502, "%s: %v", serverLabel(server), err)
	}
	_, err = unwrapRT(rt).List(ctx, runtime.Filter{Instance: id})
	switch {
	case workerNotFound(err):
		return nil
	case err == nil:
		return statusErr(409, "%s still holds an earlier copy of %s (its bundle): wait for its removal (retried each minute) or remove it on the worker, then try again", serverLabel(server), id)
	default:
		return statusErr(502, "%s: can't check for an earlier copy of %s: %s", serverLabel(server), id, untrusted(err.Error(), 200))
	}
}

// stopInvalidPlacement stops a placed instance whose template turned
// primary-only (on the worker, its relays on the primary), best effort.
func (h *Hub) stopInvalidPlacement(ctx context.Context, t *templates.Template, server string) {
	if rt, err := h.rtFor(t.ID); err == nil {
		if derr := rt.Down(ctx, h.runtimeProject(t)); derr != nil {
			log.Printf("placement: %s: stopping it on %s: %v", t.ID, serverLabel(server), derr)
		}
	} else if derr := h.relaysDown(ctx, t.ID); derr != nil {
		log.Printf("placement: %s: its relays: %v", t.ID, derr)
	}
}
