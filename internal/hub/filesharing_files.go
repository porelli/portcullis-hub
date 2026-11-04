package hub

import (
	"context"
	"fmt"
	"log"
	"maps"
	"slices"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// File sharing's data files (plan 3 Task 10, contract §13.2 / §13.5 /
// §13.7 / §13.16):
//   - instance-scope group / groups values are id-bound
//     (InstanceSettings.GroupIDs, set at save): a name grants only while
//     the directory's group of that name has the stored id (F3);
//   - render.expand_members delivers the members of the bound groups
//     within the population instead of the names;
//   - the people section carries each member's person_id values; a member
//     without one (no LLDAP uuid: ensurePersonIDs gave them none) is left
//     out of the files, expanded lists included (F9).
// expandedMembersLocked (revoke.go, F28) is built from the same helpers,
// so the holder check compares exactly what the files hold.

// personIDOptions are t's person_id options.
func personIDOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].Type == templates.TypePersonID {
			out = append(out, &opts[i])
		}
	}
	return out
}

// isGroupOption: o is an instance-scope group / groups option (its
// values are id-bound).
func isGroupOption(o *templates.Option) bool {
	return o != nil && o.EffectiveScope() == templates.ScopeInstance && (o.Type == templates.TypeGroup || o.Type == templates.TypeGroups)
}

// expandsMembers: d renders o's groups as their members.
func expandsMembers(d *templates.Delivery) bool {
	r := settings.RenderOf(d)
	return d.File != nil && r != nil && r.ExpandMembers
}

// optionExpands: some delivery of o expands members.
func optionExpands(o *templates.Option) bool {
	for i := range o.Delivery {
		if expandsMembers(&o.Delivery[i]) {
			return true
		}
	}
	return false
}

// fileMembersLocked are the population members of t in m the data files
// carry (sorted): with person_id options, only those holding every id
// under their current LLDAP uuid (idless: the others, for the log; an
// empty or changed uuid holds none). Caller holds mu (read).
func (h *Hub) fileMembersLocked(t *templates.Template, m *directory.Membership) (members, idless []string) {
	ids := personIDOptions(t)
	members = []string{}
	for _, p := range h.populationLocked(t, m).People {
		ok := true
		for _, o := range ids {
			if _, has := h.personIDForLocked(o.Pool, p.User, m.UUIDs[p.User]); !has {
				ok = false
			}
		}
		if ok {
			members = append(members, p.User)
		} else {
			idless = append(idless, p.User)
		}
	}
	return members, idless
}

// boundGroupsLocked are the group names of o's effective value in s that
// are bound (GroupIDs) to the id the directory's group of that name has
// in m. A default (never saved) is bound to nothing. Caller holds mu.
func (h *Hub) boundGroupsLocked(t *templates.Template, o *templates.Option, s state.InstanceSettings, m *directory.Membership) []string {
	v, ok := h.effectiveValue(t, o, s)
	if !ok || m == nil {
		return nil
	}
	var out []string
	for _, n := range groupNames(v) {
		id := s.GroupIDs[o.Key][n]
		g := placeholderGroup(t, n)
		if mg, exists := m.Groups[g]; id != 0 && exists && mg.ID == id {
			out = append(out, g)
		}
	}
	return out
}

// boundMembersLocked are the members (unexpired) of o's bound groups who
// are in members, sorted, never nil. Caller holds mu (read).
func (h *Hub) boundMembersLocked(t *templates.Template, o *templates.Option, s state.InstanceSettings, m *directory.Membership, members []string) []string {
	in := map[string]bool{}
	for _, u := range members {
		in[u] = true
	}
	set := map[string]bool{}
	for _, g := range h.boundGroupsLocked(t, o, s, m) {
		for _, u := range m.Groups[g].Members {
			if in[u] && !m.Expired[u][g] {
				set[u] = true
			}
		}
	}
	out := slices.Sorted(maps.Keys(set))
	if out == nil {
		out = []string{}
	}
	return out
}

// renderExpanded renders users for o's delivery d as a list (a group
// option expands to several people too).
func renderExpanded(o *templates.Option, users []string, d *templates.Delivery) (settings.Rendered, error) {
	oo := *o
	oo.Type = templates.TypeGroups
	l := make([]settings.Value, len(users))
	for i, u := range users {
		l[i] = u
	}
	return settings.RenderDelivery(&oo, l, d)
}

// logIdless logs the population members a data file of t leaves out for
// want of an id (F9).
func logIdless(t *templates.Template, idless []string) {
	if len(idless) > 0 {
		log.Printf("settings: %s: %v have no person id yet (no LLDAP uuid): left out of the data files", t.ID, idless)
	}
}

// noAccessWarnings is noAccessWarningsLocked for a committed save of
// keys (one directory read, outside mu; unavailable: none).
func (h *Hub) noAccessWarnings(t *templates.Template, keys []string) []string {
	want := false
	for _, k := range keys {
		if o := optionByKey(t, k); isGroupOption(o) && optionExpands(o) {
			want = true
		}
	}
	if !want {
		return nil
	}
	m, err := h.membership(context.Background())
	if err != nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	live := h.findLocked(t.ID)
	if live == nil {
		return nil
	}
	return h.noAccessWarningsLocked(live, h.st.Settings[t.ID], keys, m)
}

// noAccessWarningsLocked are a save's warnings for the expanded group options
// it changed: "<N> member(s) of <group> has/have no access to <app> and
// won't get this share" for bound groups' members outside the
// population (§13.5). Caller holds mu (read).
func (h *Hub) noAccessWarningsLocked(t *templates.Template, s state.InstanceSettings, keys []string, m *directory.Membership) []string {
	if m == nil {
		return nil
	}
	pop := map[string]bool{}
	for _, p := range h.populationLocked(t, m).People {
		pop[p.User] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, k := range keys {
		o := optionByKey(t, k)
		if !isGroupOption(o) || !optionExpands(o) {
			continue
		}
		for _, g := range h.boundGroupsLocked(t, o, s, m) {
			if seen[g] {
				continue
			}
			seen[g] = true
			n := 0
			for _, u := range m.Groups[g].Members {
				if !pop[u] && !m.Expired[u][g] {
					n++
				}
			}
			switch {
			case n == 1:
				out = append(out, fmt.Sprintf("1 member of %s has no access to %s and won't get this share", g, t.Manifest.Name))
			case n > 1:
				out = append(out, fmt.Sprintf("%d members of %s have no access to %s and won't get this share", n, g, t.Manifest.Name))
			}
		}
	}
	return out
}
