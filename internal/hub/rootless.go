package hub

import (
	"os"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Rootless compatibility (contract §11.10): under
// HUB_CONTAINER_RUNTIME=podman every template and instance is judged by
// templates.RootlessCompat; a refused one is never created, enabled or
// restarted. Under Docker nothing here applies.

// rootlessOn: the runtime is podman (the only gate condition, P5).
func (h *Hub) rootlessOn() bool { return h.cfg.Runtime == docker.RuntimePodman }

// templateCompat is t's verdict at its defaults.
func (h *Hub) templateCompat(t *templates.Template) templates.Compat {
	return templates.RootlessCompat(t.ReadCompose(), t.Manifest, nil, h.unprivilegedPortStart())
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
	return templates.RootlessCompat(t.ReadCompose(), t.Manifest, env, h.unprivilegedPortStart())
}

// rootlessRefusal is the 409 for a refused verdict (nil otherwise).
func rootlessRefusal(id string, c templates.Compat) error {
	if c.Status != templates.CompatRefused {
		return nil
	}
	return statusErr(409, "%s can't run under rootless Podman: %s", id, strings.Join(c.Reasons, "; "))
}

// withRootless sets each view's Rootless under podman (catalog views at
// the defaults).
func (h *Hub) withRootless(ts []templates.Template) []templates.Template {
	if !h.rootlessOn() {
		return ts
	}
	for i := range ts {
		c := h.templateCompat(&ts[i])
		ts[i].Rootless = &c
	}
	return ts
}
