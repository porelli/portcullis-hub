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

// checkPortCollisionsLocked refuses if t's ports overlap any other enabled
// app's ports. Caller must hold mu.
func (h *Hub) checkPortCollisionsLocked(t *templates.Template) error {
	candidate := resolvePortBindings(t, h.st.Settings[t.ID])
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
			for _, e := range resolvePortBindings(other, h.st.Settings[enabledID]) {
				if !portOverlap(c, e) {
					continue
				}
				desc := fmt.Sprintf("%d/%s", c.Port, c.Protocol)
				if c.RangeEnd > 0 {
					desc = fmt.Sprintf("%d-%d/%s", c.RangeStart, c.RangeEnd, c.Protocol)
				}
				return statusErr(409, "port %s already claimed by enabled app %s — change %s in its settings to free it", desc, enabledID, e.Key)
			}
		}
	}
	return nil
}
