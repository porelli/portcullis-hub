package hub

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/settings"
)

// The committed VPN render keys survive a restart (I2): written to
// <data>/vpn-render.json after each successful override write, read at
// New. At start (once the engine is verified) every enabled instance's
// running labels are compared with the override as rendered now: a
// difference the Hub can't prove harmless (a narrowing one, or one it
// can't read) restarts the instance.

const vpnRenderFile = "vpn-render.json"

func (h *Hub) vpnRenderPath() string { return filepath.Join(h.cfg.DataDir, vpnRenderFile) }

// loadVPNRendered reads the committed keys (a missing or unreadable file
// = none known: every instance counts as never rendered).
func (h *Hub) loadVPNRendered() {
	b, err := os.ReadFile(h.vpnRenderPath())
	if err != nil {
		return
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		log.Printf("vpn: %s doesn't parse: every instance's VPN rendering is checked again", vpnRenderFile)
		return
	}
	h.vpnrt.mu.Lock()
	for k, v := range m {
		h.vpnrt.rendered[k] = v
	}
	h.vpnrt.mu.Unlock()
}

// saveVPNRenderedLocked writes the committed keys (caller holds
// vpnrt.mu). A failure only logs: the start check covers a lost file.
func (h *Hub) saveVPNRenderedLocked() {
	b, err := json.Marshal(h.vpnrt.rendered)
	if err == nil {
		err = fsutil.WriteFileAtomic(h.vpnRenderPath(), b, 0o600)
	}
	if err != nil {
		log.Printf("vpn: saving %s: %v", vpnRenderFile, err)
	}
}

// vpnStartCheck restarts every enabled instance whose running containers
// carry exposure labels that differ from the override rendered now, when
// the Hub can't tell the difference is a widening only: any VPN-relevant
// difference (entrypoints, the allowlist, the friendly router) or a
// container list it can't read.
// eng is the engine read once by the caller (Init), never h.engine
// from the background goroutine.
func (h *Hub) vpnStartCheck(ctx context.Context, eng Engine) {
	if eng == nil {
		return
	}
	h.mu.RLock()
	type want struct {
		id     string
		labels map[string]map[string]string
		mw     bool
		vpn    bool
	}
	var ws []want
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		d, err := h.desiredRouteLabelsLocked(t)
		if err != nil {
			continue
		}
		a := h.vpnAccessLocked(t)
		ws = append(ws, want{id: t.ID, labels: d, mw: h.accessLocked(t).SignIn != "" || a.VPNOnly, vpn: a.VPNOnly || a.GW != ""})
	}
	h.mu.RUnlock()
	var restart []string
	for _, w := range ws {
		cs, err := eng.ListContainers(ctx, docker.Filters{"label": {docker.LabelProject + "=" + projectName(w.id)}})
		if err != nil {
			if w.vpn {
				restart = append(restart, w.id) // unknown: fail closed
			}
			continue
		}
		for _, c := range cs {
			if c.State != "running" {
				continue
			}
			svc := c.Labels[docker.LabelService]
			if d := diffExposure(w.id, w.labels[svc], c.Labels, w.mw); d != "" && vpnRelevantDiff(d) {
				log.Printf("vpn: %s: its running labels differ from its rendering (%s): restarted", w.id, d)
				restart = append(restart, w.id)
				break
			}
		}
	}
	for _, id := range restart {
		h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
	}
}

// vpnRelevantDiff: a diffExposure text touches what the VPN rendering
// decides (entrypoints, middlewares, the allowlist, the friendly router).
func vpnRelevantDiff(d string) bool {
	for _, s := range []string{".entrypoints", ".middlewares", VPNAllowPrefix, VPNOnlyPrefix, "+"} {
		if strings.Contains(d, s) {
			return true
		}
	}
	return false
}
