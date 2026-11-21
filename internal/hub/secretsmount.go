package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"golang.org/x/mod/semver"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/templates"
)

// MinSubpathAPI is the oldest Engine API with volume subpath mounts
// (Docker Engine 26.0, API 1.45; contract §6). An older daemon would
// ignore the subpath and mount the whole secrets volume: refused.
const MinSubpathAPI = "1.45"

// loadRendered loads t's project as compose will run it (template, Hub
// override, custom override merged; interpolated from exactly compose's
// environment — compose.Runner.Env, never the Hub's own — and the
// instance's env file; every profile), with compose's own library.
// compose-go is what the docker compose CLI is built on: keep its version
// within the compose-go line the image's docker-cli-compose (alpine,
// compose ≥ compose.MinVersion) vendors — .github/dependabot.yml groups it
// on its own so a bump is reviewed against that — so the check reads the
// project as the up will (TestRealTemplatesInstances loads every real
// template through it).
func (h *Hub) loadRendered(ctx context.Context, t *templates.Template) (*types.Project, error) {
	return h.loadRenderedWith(ctx, t, []string{"*"})
}

// loadRenderedWith is loadRendered with exactly profiles active ("*" =
// every one; none = only the services without compose profiles:). The
// safety checks always pass "*" (loadRendered); only the runtime views
// pass the instance's selected profiles (loadRuntime, contract §13.18).
func (h *Hub) loadRenderedWith(ctx context.Context, t *templates.Template, profiles []string) (*types.Project, error) {
	p := h.project(t)
	opts := []cli.ProjectOptionsFn{
		cli.WithName(p.Name),
		cli.WithWorkingDirectory(h.cfg.ProjectDir),
		// compose's environment wins over the env file, as in the CLI.
		cli.WithEnv(h.rt.Env()),
		cli.WithProfiles(profiles),
		cli.WithConsistency(false),
		cli.WithResolvedPaths(false),
		cli.WithoutEnvironmentResolution,
	}
	if p.EnvFile != "" {
		if _, err := os.Stat(p.EnvFile); err == nil {
			opts = append(opts, cli.WithEnvFiles(p.EnvFile), cli.WithDotEnv)
		}
	}
	po, err := cli.NewProjectOptions(p.Files, opts...)
	if err != nil {
		return nil, err
	}
	return po.LoadProject(ctx)
}

// dockerRootMounts refuses (400, dockerRootRule) every bind source and
// every local volume's driver_opts.device at, above or under the data
// root of the engine the instance runs on (M1: a worker instance's is its
// agent's /v1/info DockerRootDir, the primary's only for a primary
// instance); unreadable = 503. On the primary, relative bind sources are
// the daemon's paths under the project directory; on a worker they lie
// inside the instance's bundle directory, which the agent resolves and
// confines (its bind checks), so only absolute ones are judged here.
func (h *Hub) dockerRootMounts(ctx context.Context, t *templates.Template, proj *types.Project) error {
	server := h.serverOf(t.ID)
	type use struct{ what, p string }
	var uses []use
	add := func(what, p string) {
		if p == "" {
			return
		}
		if !path.IsAbs(p) && server != "" {
			return
		}
		if !path.IsAbs(p) {
			p = path.Join(filepath.ToSlash(h.cfg.ProjectHostDir), p)
		}
		uses = append(uses, use{what, path.Clean(p)})
	}
	svcs := make([]string, 0, len(proj.Services)+len(proj.DisabledServices))
	all := map[string]types.ServiceConfig{}
	for n, s := range proj.Services {
		all[n] = s
		svcs = append(svcs, n)
	}
	for n, s := range proj.DisabledServices {
		if _, dup := all[n]; !dup {
			all[n] = s
			svcs = append(svcs, n)
		}
	}
	sort.Strings(svcs)
	for _, n := range svcs {
		for _, m := range all[n].Volumes {
			if m.Type == types.VolumeTypeBind {
				add("service "+n+": bind "+m.Source, m.Source)
			}
		}
	}
	keys := make([]string, 0, len(proj.Volumes))
	for k := range proj.Volumes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := proj.Volumes[k]
		if dev := v.DriverOpts["device"]; dev != "" && (v.Driver == "" || v.Driver == "local") {
			add("volume "+k+": device "+dev, dev)
		}
	}
	for _, u := range uses {
		if err := h.dockerRootRule(ctx, server, u.p); err != nil {
			var se *StatusError
			if errors.As(err, &se) && se.Status == http.StatusBadRequest {
				return statusErr(http.StatusBadRequest, "%s was not started: %s: %v", t.ID, u.what, err)
			}
			return err
		}
	}
	return nil
}

// checkSecretsMounts is the pre-up check of contract §6 (F15) on t's
// rendered project: every top-level volume whose resolved name is the
// secrets volume, under any key, is mounted only through the key
// templates.SecretsVolumeKey (external, that name), only by a
// person_secret option's mount.service at its mount.path, read-only,
// with exactly <instance>/<key> as subpath; no service takes a mounting
// service's volumes (volumes_from); and the daemon supports subpath
// mounts. Anything else refuses the up (409; 503 when the daemon can't
// be asked). Outside mu (it reads files and asks the daemon).
func (h *Hub) checkSecretsMounts(ctx context.Context, t *templates.Template) error {
	proj, err := h.loadRendered(ctx, t)
	if err != nil {
		// The loader's text may quote the env file or the overrides:
		// logged redacted, then clipped; never answered.
		log.Printf("instance %s: compose-go can't load the project: %s", t.ID, clip(h.secretRedactor(t.ID)(err.Error()), 600))
		return statusErr(http.StatusConflict, "%s was not started: the instance's .env or compose files don't parse (see the Hub's log)", t.ID)
	}
	// No host path at, above or under Docker's data root (fix round 1):
	// a bind there reaches every volume, the secrets one included.
	if err := h.dockerRootMounts(ctx, t, proj); err != nil {
		return err
	}
	h.mu.RLock()
	mode := h.mailRenderModeLocked(t)
	h.mu.RUnlock()
	if err := checkMailMounts(proj, t, mode); err != nil {
		return err
	}
	if err := checkMailNetworkAttachments(proj, t, mode, h.mailCore().ProviderIP.String()); err != nil {
		return err
	}
	vol := h.cfg.SecretsVolume
	type want struct{ sub string }
	expected := map[string]map[string]want{} // service → target → subpath
	for _, o := range personSecretOptions(t) {
		sub, err := secretDirRel(t.ID, o.Key)
		if err != nil {
			return err
		}
		if expected[o.Mount.Service] == nil {
			expected[o.Mount.Service] = map[string]want{}
		}
		expected[o.Mount.Service][o.Mount.Path] = want{sub: sub}
	}
	refuse := func(format string, args ...any) error {
		return statusErr(http.StatusConflict, "%s was not started: %s (the Hub's secrets volume %s may only be mounted by a per-person password's service, read-only, at its own subpath)", t.ID, fmt.Sprintf(format, args...), vol)
	}
	secretKeys := map[string]bool{}
	keys := make([]string, 0, len(proj.Volumes))
	for k := range proj.Volumes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := proj.Volumes[k]
		name := v.Name
		if name == "" {
			name = k
			if !bool(v.External) {
				name = proj.Name + "_" + k
			}
		}
		if name == vol || k == templates.SecretsVolumeKey {
			secretKeys[k] = true
		}
	}
	if v, ok := proj.Volumes[templates.SecretsVolumeKey]; ok {
		if len(expected) == 0 {
			return refuse("volume %s is declared but the template has no per-person password", templates.SecretsVolumeKey)
		}
		if !bool(v.External) || v.Name != vol {
			return refuse("volume %s must be external and named %s", templates.SecretsVolumeKey, vol)
		}
	}
	mounters := map[string]bool{}
	names := make([]string, 0, len(proj.Services)+len(proj.DisabledServices))
	all := map[string]types.ServiceConfig{}
	for n, s := range proj.Services {
		all[n] = s
		names = append(names, n)
	}
	for n, s := range proj.DisabledServices {
		if _, dup := all[n]; !dup {
			all[n] = s
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		for _, m := range all[n].Volumes {
			if m.Type != types.VolumeTypeVolume || !secretKeys[m.Source] {
				continue
			}
			if m.Source != templates.SecretsVolumeKey {
				return refuse("service %s mounts it through volume %s", n, m.Source)
			}
			w, ok := expected[n][m.Target]
			sub := ""
			if m.Volume != nil {
				sub = m.Volume.Subpath
			}
			switch {
			case !ok:
				return refuse("service %s mounts it at %s", n, m.Target)
			case sub != w.sub:
				return refuse("service %s mounts the subpath %q, not %q", n, sub, w.sub)
			case !m.ReadOnly:
				return refuse("service %s mounts it writable", n)
			}
			mounters[n] = true
		}
	}
	if len(mounters) > 0 {
		// A shared pid or ipc namespace reaches a mounting service's
		// files (/proc/<pid>/root) or memory, in either direction (a
		// mounter joining another service's namespace exposes them
		// there): with a mounter, every service's pid / ipc stays
		// private — no host, container:* or service:* (fix round 1).
		for _, n := range names {
			for field, v := range map[string]string{"pid": all[n].Pid, "ipc": all[n].Ipc} {
				switch lv := strings.ToLower(strings.TrimSpace(v)); {
				case lv == "", lv == "private", field == "ipc" && (lv == "shareable" || lv == "none"):
				default:
					return refuse("service %s shares the %s namespace %s", n, field, v)
				}
			}
		}
	}
	for _, n := range names {
		for _, vf := range all[n].VolumesFrom {
			src := strings.TrimPrefix(vf, "service:")
			src, _, _ = strings.Cut(src, ":")
			if strings.HasPrefix(vf, "container:") || mounters[src] {
				return refuse("service %s takes the volumes of %s (volumes_from)", n, vf)
			}
		}
	}
	if len(mounters) == 0 {
		return nil
	}
	if h.kubeOn() {
		return nil // a *-pw Secret, not a volume subpath (§6 "On Kubernetes")
	}
	if h.noEngine() {
		return statusErr(http.StatusServiceUnavailable, "%s was not started: per-person passwords need the Docker Engine API", t.ID)
	}
	info, err := h.rt.Info(ctx)
	if err != nil {
		return statusErr(http.StatusServiceUnavailable, "%s was not started: can't read the container engine's version: %v", t.ID, err)
	}
	if why := subpathRefusal(h.cfg.Runtime, info); why != "" {
		return statusErr(http.StatusConflict, "%s was not started: %s", t.ID, why)
	}
	return nil
}

// subpathRefusal is why the engine can't do volume subpath mounts (""
// = it can). Under Podman its own version (/version's "Podman Engine"
// component) decides, never the compat API version (always 1.41);
// under Docker the Engine API version (1.45). The runtime fence stays
// the adapter's CheckLayout.
func subpathRefusal(kind runtime.Kind, info runtime.Info) string {
	if kind == runtime.KindPodman {
		// Ruling R-POD2: Podman's compat API ignores compose `subpath`
		// (live e2e: the files never reached the container), whatever
		// its version; the version names the engine only.
		v := info.EngineVersion
		if v == "" {
			v = "(version unknown)"
		}
		return "per-person passwords need Docker for now (rootless Podman " + clip(v, 40) + " doesn't apply compose volume subpaths)"
	}
	api := info.APIVersion
	if !semver.IsValid("v"+api) || semver.Compare("v"+api, "v"+MinSubpathAPI) < 0 {
		return "Docker Engine API " + clip(api, 40) + " is too old for per-person passwords (volume subpath mounts need API " + MinSubpathAPI + ", Docker Engine 26.0 or newer)"
	}
	return ""
}

// checkMailMounts is contract §19.1's mail_tls check on t's rendered
// project: a volume whose resolved name is portcullis_mail_tls, under
// any key, is mounted only by the wired provider's tls services (mode
// void or normal), read-only. Anything else refuses the up (409).
func checkMailMounts(proj *types.Project, t *templates.Template, mode mailMode) error {
	var tls, gated []string
	if mode != mailUnwired && t.Manifest.Mail != nil {
		tls, gated = t.Manifest.Mail.TLS, t.Manifest.Mail.Gated
	}
	if err := checkMailVolume(proj, t, mailTLSVolume, mailTLSVolumeKey, tls, "the mail certificate %s may only be mounted read-only by the wired mail provider's tls services"); err != nil {
		return err
	}
	// The slot volume (R-POD2): whole, read-only, the gated services only.
	return checkMailVolume(proj, t, mailProviderSlotVolume, mailProviderSlotVolumeKey, gated, "the mail provider's slot %s may only be mounted read-only and whole by the wired mail provider's gated services")
}

// checkMailVolume: a volume named vol (under any key, or key) is mounted
// only by the services in allowed, read-only, never by a subpath, and no
// other service takes their volumes.
func checkMailVolume(proj *types.Project, t *templates.Template, vol, key string, allowed []string, why string) error {
	keys := map[string]bool{}
	for k, v := range proj.Volumes {
		name := v.Name
		if name == "" {
			name = k
			if !bool(v.External) {
				name = proj.Name + "_" + k
			}
		}
		if name == vol || k == key {
			keys[k] = true
		}
	}
	if len(keys) == 0 {
		return nil
	}
	all := map[string]types.ServiceConfig{}
	for n, sv := range proj.Services {
		all[n] = sv
	}
	for n, sv := range proj.DisabledServices {
		if _, dup := all[n]; !dup {
			all[n] = sv
		}
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	refuse := func(format string, args ...any) error {
		return statusErr(http.StatusConflict, "%s was not started: %s ("+why+")", t.ID, fmt.Sprintf(format, args...), vol)
	}
	for _, n := range names {
		for _, m := range all[n].Volumes {
			if m.Type != types.VolumeTypeVolume || !keys[m.Source] {
				continue
			}
			switch {
			case !slices.Contains(allowed, n):
				return refuse("service %s mounts it", n)
			case !m.ReadOnly:
				return refuse("service %s mounts it writable", n)
			case m.Volume != nil && m.Volume.Subpath != "":
				return refuse("service %s mounts it by a subpath", n)
			}
		}
		for _, vf := range all[n].VolumesFrom {
			src := strings.TrimPrefix(vf, "service:")
			src, _, _ = strings.Cut(src, ":")
			if slices.Contains(allowed, src) && !slices.Contains(allowed, n) {
				return refuse("service %s takes the volumes of %s (volumes_from)", n, vf)
			}
		}
	}
	return nil
}

// mailAttach is one attachment the Hub's override makes on a core
// network: the service, its address ("" none) and aliases (sorted).
type mailAttach struct {
	ip      string
	aliases []string
}

// checkMailNetworkAttachments is Ruling RR2-H1 (c) on a mail template's
// rendered project: on every external network only the Hub's own
// attachments exist — the API service on portcullis-mail-api at the
// provider address with its alias; in normal mode the metrics services
// on portcullis-metrics-mail with theirs and the well-known service on
// portcullis-proxy (no address, no alias). Any other service, address
// or alias there refuses the up (409).
func checkMailNetworkAttachments(proj *types.Project, t *templates.Template, mode mailMode, providerIP string) error {
	b := t.Manifest.Mail
	if b == nil {
		return nil
	}
	want := map[string]map[string]mailAttach{} // network → service → attachment
	add := func(n, s, ip string, aliases ...string) {
		if want[n] == nil {
			want[n] = map[string]mailAttach{}
		}
		a := want[n][s]
		if ip != "" {
			a.ip = ip
		}
		a.aliases = append(a.aliases, aliases...)
		slices.Sort(a.aliases)
		want[n][s] = a
	}
	if mode != mailUnwired {
		add(mailAPINetwork, b.API.Service, providerIP, mailAPIAlias)
	}
	if mode == mailNormal {
		add(mailMetricsNetwork, b.Metrics.Service, "", mailMetricsAlias)
		if sm := b.ServerMetrics; sm != nil {
			add(mailMetricsNetwork, sm.Service, "", mailServerMetricsAlias)
		}
		add(mailProxyNetwork, b.Wellknown.Service, "")
		if b.AdminView != nil {
			// The read-only admin view router (contract §19.13).
			add(mailProxyNetwork, b.AdminView.Service, "")
		}
	}
	refuse := func(f string, a ...any) error {
		return statusErr(http.StatusConflict, "%s was not started: "+f, append([]any{t.ID}, a...)...)
	}
	for key, n := range proj.Networks {
		if !bool(n.External) {
			continue
		}
		name := n.Name
		if name == "" {
			name = key
		}
		allowed := want[name]
		for sname, svc := range proj.Services {
			c, on := svc.Networks[key]
			if !on {
				continue
			}
			w, ok := allowed[sname]
			if !ok {
				return refuse("service %s is on the core network %s: only the Hub's own attachments are (RR2-H1)", sname, name)
			}
			ip, aliases := "", []string{}
			if c != nil {
				ip = c.Ipv4Address
				if c.Ipv6Address != "" || len(c.LinkLocalIPs) > 0 {
					return refuse("service %s has an IPv6 or link-local address on %s", sname, name)
				}
				aliases = append(aliases, c.Aliases...)
			}
			slices.Sort(aliases)
			wa := w.aliases
			if wa == nil {
				wa = []string{}
			}
			if ip != w.ip || !slices.Equal(aliases, wa) {
				return refuse("service %s's attachment to %s isn't the Hub's (address %q, aliases %v)", sname, name, ip, aliases)
			}
		}
	}
	return nil
}
