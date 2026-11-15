package hub

import (
	"context"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
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
	h.mu.RLock()
	perr := h.placeableLocked(server)
	h.mu.RUnlock()
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
	refs := make([]string, 0, len(imgs))
	for _, ref := range imgs {
		if ref != "" && !strings.Contains(ref, "$") && !slices.Contains(refs, ref) {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	for _, ref := range refs {
		if err := rt.Pull(ctx, ref, nil); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "no matching manifest") || strings.Contains(msg, "platform") || strings.Contains(msg, "architecture") {
				return statusErr(409, "%s has no %s image", ref, inf.Arch)
			}
			return statusErr(409, "pulling %s on %s failed: %s", ref, h.serverName(server), clipRunes(err.Error(), 200))
		}
	}
	return nil
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

// DeliverFile passes a data file to the agent (fileDeliverer).
func (p placedRT) DeliverFile(ctx context.Context, instance string, f runtime.FileDelivery) error {
	d, ok := p.Instances.(fileDeliverer)
	if !ok {
		return statusErr(500, "the worker's runtime can't take data files")
	}
	return d.DeliverFile(ctx, instance, f)
}
