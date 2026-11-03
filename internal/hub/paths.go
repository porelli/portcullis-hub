package hub

import (
	"log"
	"sort"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// PathUsage is one host directory an enabled instance mounts through a
// path-like option: where, into which service and mount, how (mode,
// needs) and as whom it writes (writes_as resolved; OwnerKnown false =
// not declared or not resolvable).
type PathUsage struct {
	Instance   string `json:"instance"`
	Key        string `json:"key"`
	Type       string `json:"type"`
	HostPath   string `json:"host_path"`
	Service    string `json:"service"`
	Mount      string `json:"mount"`
	Mode       string `json:"mode"` // ro | rw
	Needs      string `json:"needs,omitempty"`
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`
	OwnerKnown bool   `json:"owner_known"`
}

// PathUsages lists every enabled instance's path-like option that has a
// value (sorted by instance, then the template's option order). A value
// that no longer resolves is left out (logged).
func (h *Hub) PathUsages() []PathUsage {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []PathUsage{}
	for _, t := range h.instances {
		if !h.st.IsEnabled(t.ID) {
			continue
		}
		s := h.st.Settings[t.ID]
		opts := t.Manifest.Options()
		var values map[string]settings.Value
		for i := range opts {
			o := &opts[i]
			if o.Type != templates.TypePath || o.EffectiveScope() != templates.ScopeInstance || o.Target == nil {
				continue
			}
			v, ok := h.effectiveValue(&t, o, s)
			if !ok {
				continue
			}
			host, err := h.mountSourceLocked(o, v)
			if err != nil {
				log.Printf("settings: %s: %s: %v", t.ID, o.Key, err)
				continue
			}
			u := PathUsage{Instance: t.ID, Key: o.Key, Type: o.Type, HostPath: host, Service: o.Target.Service,
				Mount: o.Target.Mount, Mode: o.EffectiveMode(), Needs: o.Needs}
			if o.WritesAs != nil {
				if values == nil {
					values = h.instanceValuesLocked(&t, s)
				}
				if uid, gid, err := settings.ResolveOwner(o, values); err == nil {
					u.UID, u.GID, u.OwnerKnown = uid, gid, true
				}
			}
			out = append(out, u)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}
