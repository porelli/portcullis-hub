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
	"sort"
	"strings"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"golang.org/x/mod/semver"

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
// every local volume's driver_opts.device at, above or under the Docker
// daemon's data root; unreadable = 503. Relative bind sources are the
// daemon's paths under the project directory.
func (h *Hub) dockerRootMounts(ctx context.Context, t *templates.Template, proj *types.Project) error {
	type use struct{ what, p string }
	var uses []use
	add := func(what, p string) {
		if p == "" {
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
		if err := h.dockerRootRule(ctx, u.p); err != nil {
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
	api := info.APIVersion
	if err != nil {
		return statusErr(http.StatusServiceUnavailable, "%s was not started: can't read the Docker Engine API version: %v", t.ID, err)
	}
	if !semver.IsValid("v"+api) || semver.Compare("v"+api, "v"+MinSubpathAPI) < 0 {
		return statusErr(http.StatusConflict, "%s was not started: Docker Engine API %s is too old for per-person passwords (volume subpath mounts need API %s, Docker Engine 26.0 or newer)", t.ID, clip(api, 40), MinSubpathAPI)
	}
	return nil
}
