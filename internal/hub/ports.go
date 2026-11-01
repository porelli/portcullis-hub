package hub

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/templates"
)

// portBinding is the effective binding for one declared port after applying
// user overrides from settings.
type portBinding struct {
	AppID           string
	Key             string
	Bind            string
	Port            int
	Protocol        string
	NetworkModeHost bool
	RangeStart      int
	RangeEnd        int
	Custom          bool // from the custom override (Expert)
}

func resolvePortBindings(t *templates.Template, values map[string]string) []portBinding {
	out := make([]portBinding, 0, len(t.Manifest.Ports))
	for _, p := range t.Manifest.Ports {
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		bind := p.Bind
		if v, ok := values[p.Key+"_BIND"]; ok && v != "" {
			bind = v
		}
		if bind == "" {
			bind = "0.0.0.0"
		}
		pb := portBinding{AppID: t.ID, Key: p.Key, Bind: bind, Protocol: proto, NetworkModeHost: p.NetworkModeHost}
		// Port ranges (e.g. coturn media relays) — not user-configurable.
		if p.Range != "" {
			if a, b, ok := parsePortRange(p.Range); ok {
				pb.RangeStart, pb.RangeEnd = a, b
				out = append(out, pb)
				continue
			}
		}
		port := p.Default
		if v, ok := values[p.Key]; ok {
			if v == "" && !p.Required {
				continue // user disabled this port
			}
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				port = n
			}
		}
		if port <= 0 {
			continue
		}
		pb.Port = port
		out = append(out, pb)
	}
	return out
}

func parsePortRange(s string) (int, int, bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || a <= 0 || b < a {
		return 0, 0, false
	}
	return a, b, true
}

// bindsOverlap: 0.0.0.0 claims every interface, so it conflicts with any bind.
func bindsOverlap(a, b string) bool {
	return a == b || a == "0.0.0.0" || b == "0.0.0.0"
}

func portOverlap(a, b portBinding) bool {
	if a.Protocol != b.Protocol || !bindsOverlap(a.Bind, b.Bind) {
		return false
	}
	aStart, aEnd := a.Port, a.Port
	if a.RangeEnd > 0 {
		aStart, aEnd = a.RangeStart, a.RangeEnd
	}
	bStart, bEnd := b.Port, b.Port
	if b.RangeEnd > 0 {
		bStart, bEnd = b.RangeStart, b.RangeEnd
	}
	return aStart <= bEnd && bStart <= aEnd
}

// appPortsLocked is every host port an app publishes: its manifest ports
// as set in Settings plus its custom override's. Caller must hold mu.
func (h *Hub) appPortsLocked(t *templates.Template) []portBinding {
	return append(resolvePortBindings(t, h.st.Settings[t.ID]), h.userPortsLocked(t)...)
}

func portDesc(p portBinding) string {
	if p.RangeEnd > 0 {
		return fmt.Sprintf("%s:%d-%d/%s", p.Bind, p.RangeStart, p.RangeEnd, p.Protocol)
	}
	return fmt.Sprintf("%s:%d/%s", p.Bind, p.Port, p.Protocol)
}

// checkPortCollisionsLocked refuses if t's ports overlap any other enabled
// app's ports (pre-flight before compose up: the definite conflicts the Hub
// can see; conflicts with host services only compose reports). Caller must
// hold mu.
func (h *Hub) checkPortCollisionsLocked(t *templates.Template) error {
	return h.checkPortsLocked(t, h.appPortsLocked(t))
}

// checkPortsLocked checks candidate (t's ports) against itself — a custom
// override port clashing with a Settings one — and the other enabled apps.
// Caller must hold mu.
func (h *Hub) checkPortsLocked(t *templates.Template, candidate []portBinding) error {
	for i, a := range candidate {
		for _, b := range candidate[i+1:] {
			if (a.Custom || b.Custom) && portOverlap(a, b) {
				return statusErr(409, "port %s is published twice by this app (custom override and %s)", portDesc(a), b.Key)
			}
		}
	}
	if len(candidate) == 0 {
		return nil
	}
	for _, enabledID := range h.st.Enabled {
		if enabledID == t.ID {
			continue
		}
		other := h.findLocked(enabledID)
		if other == nil {
			continue
		}
		for _, c := range candidate {
			for _, e := range h.appPortsLocked(other) {
				if !portOverlap(c, e) {
					continue
				}
				where := "change " + e.Key + " in its settings"
				if e.Custom {
					where = "change its custom override (Expert)"
				}
				return statusErr(409, "port %s already claimed by enabled app %s — %s to free it", portDesc(c), enabledID, where)
			}
		}
	}
	return nil
}
