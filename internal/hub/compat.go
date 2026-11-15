package hub

import (
	"os"
	"strings"

	"github.com/portcullis/hub/internal/runtime"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Runtime compatibility (contract §11.10): under
// HUB_CONTAINER_RUNTIME=podman and kubernetes every template and instance
// is judged by templates.RuntimeCompat for that runtime; a refused one is
// never created, enabled or restarted. Under Docker nothing here applies.

// rootlessOn: the runtime is podman (the Podman-only rules: restart
// policy, SELinux relabelling, P5).
func (h *Hub) rootlessOn() bool { return h.cfg.Runtime == runtime.KindPodman }

// compatOn: the runtime judges compatibility (podman, kubernetes).
func (h *Hub) compatOn() bool {
	return h.cfg.Runtime == runtime.KindPodman || h.cfg.Runtime == runtime.KindKubernetes
}

// compatEnv adds the Hub's bind roots (the Kubernetes shared-folder
// roots) to env.
func (h *Hub) compatEnv(env map[string]string) map[string]string {
	if env == nil {
		env = map[string]string{}
	}
	env[templates.EnvBindRoots] = strings.Join(h.bindRoots, ":")
	return env
}

// templateCompat is t's verdict at its defaults.
func (h *Hub) templateCompat(t *templates.Template) templates.Compat {
	return templates.RuntimeCompat(h.cfg.Runtime, t.ReadCompose(), t.Manifest, h.compatEnv(nil), h.unprivilegedPortStart())
}

// instanceCompat is instance t's verdict with its own values: its .env
// as compose reads it (every line, the last one winning: env overrides
// included) and its ports (s.Ports over the manifest defaults).
func (h *Hub) instanceCompat(t *templates.Template, s state.InstanceSettings) templates.Compat {
	env := map[string]string{}
	if b, err := os.ReadFile(h.envPath(t.ID)); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok {
				env[k] = envUnquote(v)
			}
		}
	}
	for k, v := range s.Ports {
		env[k] = v
	}
	// The Avahi services directory (a path setting, Kubernetes: degraded
	// when set).
	if v, ok := s.Values[templates.AvahiServicesDirKey].(string); ok {
		env[templates.AvahiServicesDirKey] = v
	}
	return templates.RuntimeCompat(h.cfg.Runtime, t.ReadCompose(), t.Manifest, h.compatEnv(env), h.unprivilegedPortStart())
}

// compatRefusal is the 409 for a refused verdict (nil otherwise).
func compatRefusal(id string, c templates.Compat) error {
	if c.Status != templates.CompatRefused {
		return nil
	}
	where := "under rootless Podman"
	if c.Runtime == runtime.KindKubernetes {
		where = "on Kubernetes"
	}
	return statusErr(409, "%s can't run %s: %s", id, where, strings.Join(c.Reasons, "; "))
}

// withCompat sets each view's Compat under podman and kubernetes
// (catalog views at the defaults).
func (h *Hub) withCompat(ts []templates.Template) []templates.Template {
	if !h.compatOn() {
		return ts
	}
	for i := range ts {
		c := h.templateCompat(&ts[i])
		ts[i].Compat = &c
	}
	return ts
}

// podmanRestartAlways are the services whose restart policy the override
// sets to `always` under podman (contract §11.10): rootless Podman has
// no daemon, and its podman-restart.service starts only containers with
// policy `always` at boot, so an `unless-stopped` app would never come
// back after a reboot. Only a literal `unless-stopped` is changed, never
// a one-off job (t.Jobs: manifest jobs and depends_on
// service_completed_successfully targets, all `restart: "no"`) nor
// `no`, `on-failure` (a job that fails would loop as `always`) or no
// policy. A stopped instance has no containers (Disable is compose
// down), so `always` never brings back what an admin stopped. nil under
// Docker.
func (h *Hub) podmanRestartAlways(t *templates.Template) map[string]bool {
	if !h.rootlessOn() {
		return nil
	}
	services, err := orderedServiceNodes(t.ReadCompose())
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for name, s := range services {
		if t.Jobs[name] {
			continue
		}
		if r := mapField(s, "restart"); r != nil && r.Kind == yaml.ScalarNode && strings.TrimSpace(r.Value) == "unless-stopped" {
			out[name] = true
		}
	}
	return out
}
