package hub

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The people & groups pages' two admin reads (contract §9.7): one
// person's apps and per-app values (GET /api/directory/users/{u}/apps)
// and what uses one group (GET /api/directory/groups/{g}/uses). The
// routes and their Portcullis MCP twins are admin-only; these methods
// don't judge the caller.

// PersonVia is one group that lets the person into an app, and when that
// membership ends (nil: no end).
type PersonVia struct {
	Group string     `json:"group"`
	Until *time.Time `json:"until"`
}

// PersonApp is one app the person can use. Via is [] for an app every
// signed-in person can use; Until is when access ends (nil: no end, or
// some group of Via has none).
type PersonApp struct {
	Instance string      `json:"instance"`
	Name     string      `json:"name"`
	Via      []PersonVia `json:"via"`
	Until    *time.Time  `json:"until"`
}

// PersonValue is one of the person's resolved per-person values (Display
// form). From is where it comes from: the winning group's name (a
// combined value's groups, ", "-joined), "default", "fail-closed", or for
// a person-entered value "own entry" / "set by <admin>".
type PersonValue struct {
	Instance string `json:"instance"`
	App      string `json:"app"`
	Key      string `json:"key"`
	Label    string `json:"label"`
	Value    string `json:"value"`
	From     string `json:"from"`
}

// PersonAppsView is GET /api/directory/users/{u}/apps' answer. Both lists
// are always [] (never null).
type PersonAppsView struct {
	Apps   []PersonApp   `json:"apps"`
	Values []PersonValue `json:"values"`
}

// PersonApps is user's (any case) apps — My apps' (MyApps) without
// credentials or AI, and with the apps that give them no value: every
// enabled instance whose population holds them (Via: their groups that
// grant it, with each membership's end), or whose person-entered options'
// population holds them with an entry; and the values MyApps shows them
// (self-visible person options, never secrets or Hub-set ones) plus
// their entries. 404 for an unknown person, 503 while the directory is
// down.
func (h *Hub) PersonApps(ctx context.Context, user string) (*PersonAppsView, error) {
	user = strings.ToLower(user)
	m, err := h.readMembership(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := m.Users[user]; !ok {
		return nil, statusErr(404, "no such user %s", user)
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	v := &PersonAppsView{Apps: []PersonApp{}, Values: []PersonValue{}}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		name := instanceName(t)
		var groups map[string]int
		for _, p := range h.populationLocked(t, m).People {
			if p.User == user {
				groups = p.Groups
				break
			}
		}
		var vals []PersonValue
		if eo := entryOptions(t); len(eo) > 0 && inPopulation(h.entryPopulationLocked(t, m), user) {
			for _, o := range eo {
				if pv, ok := h.entryValueLocked(t, o, user, m.UUIDs[user]); ok {
					pv.Instance, pv.App = t.ID, name
					vals = append(vals, pv)
				}
			}
		}
		if groups == nil {
			if len(vals) == 0 {
				continue
			}
		} else {
			resolved := h.resolvePeopleLocked(t, m)[user]
			opts := t.Manifest.Options()
			var own []PersonValue
			for j := range opts {
				o := &opts[j]
				if o.EffectiveScope() != templates.ScopePerson || o.Type == templates.TypeSecret || hubSetOption(o) || (o.SelfVisible != nil && !*o.SelfVisible) {
					continue
				}
				r, ok := resolved[o.Key]
				if !ok || r.Value == nil {
					continue
				}
				own = append(own, PersonValue{Instance: t.ID, App: name, Key: o.Key, Label: o.Label, Value: h.kinds.Display(o, r.Value), From: valueFrom(r.Reason)})
			}
			vals = append(own, vals...)
		}
		app := PersonApp{Instance: t.ID, Name: name, Via: []PersonVia{}}
		if g := accessGroupOf(t); g != "" && groups != nil {
			via := PersonVia{Group: g}
			if at, ok := m.Pending[user][g]; ok {
				via.Until = &at
			}
			app.Via = append(app.Via, via)
		}
		app.Until = accessEnd(app.Via)
		v.Apps = append(v.Apps, app)
		v.Values = append(v.Values, vals...)
	}
	slices.SortStableFunc(v.Apps, func(a, b PersonApp) int { return strings.Compare(a.Instance, b.Instance) })
	slices.SortStableFunc(v.Values, func(a, b PersonValue) int { return strings.Compare(a.Instance, b.Instance) })
	return v, nil
}

// accessEnd is when the access via gives ends: nil when via is empty or
// some membership has no end, else the latest end.
func accessEnd(via []PersonVia) *time.Time {
	var end *time.Time
	for _, g := range via {
		if g.Until == nil {
			return nil
		}
		if end == nil || g.Until.After(*end) {
			end = g.Until
		}
	}
	return end
}

// valueFrom is PersonValue.From of a resolved value.
func valueFrom(r settings.Reason) string {
	switch r.Source {
	case settings.ReasonGroup:
		if r.Group != "" {
			return r.Group
		}
	case settings.ReasonCombined:
		if len(r.Groups) > 0 {
			return strings.Join(r.Groups, ", ")
		}
	case settings.ReasonFailClosed:
		return settings.ReasonFailClosed
	}
	return settings.ReasonDefault
}

// entryValueLocked is user's person-entered value of o (myEntryLocked's
// rules: bound to the account uuid, the option's type unchanged); ok
// false when there is none. Caller holds mu.
func (h *Hub) entryValueLocked(t *templates.Template, o *templates.Option, user, uuid string) (PersonValue, bool) {
	e := h.myEntryLocked(t, o, user, uuid)
	if e.Value == nil {
		return PersonValue{}, false
	}
	from := "own entry"
	if by := h.st.Settings[t.ID].Entered[o.Key][user].SetBy; by != "" {
		from = "set by " + by
	}
	return PersonValue{Key: o.Key, Label: o.Label, Value: e.Display, From: from}, true
}

// GroupApp is one app that uses a group: Role "access" (its access
// group), "admin" (its admin group) or "privileged" (a row of one of its
// privileged options names it, so it guards: App.PrivilegedGroups).
type GroupApp struct {
	Instance string `json:"instance"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

// GroupSetting is one setting row or group record that names the group:
// Scope "person" (a per-person option's row), "group" (a group option's
// record) or "instance" (an instance group / groups value, Value is then
// the group's name).
type GroupSetting struct {
	Instance string `json:"instance"`
	App      string `json:"app"`
	Key      string `json:"key"`
	Label    string `json:"label"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
}

// GroupUsesView is GET /api/directory/groups/{g}/uses' answer. Every list
// is always [] (never null).
type GroupUsesView struct {
	Apps        []GroupApp     `json:"apps"`
	Settings    []GroupSetting `json:"settings"`
	Permissions []string       `json:"permissions"`
}

// GroupUses is what uses group (its exact LLDAP name): the instances
// whose access or admin group it is (DirectoryApps' groups, enabled or
// not) or whose privileged rows name it; every setting row and group
// record PurgeGroupSettings would drop for it (namesGroup: the exact
// name, another case only when bound to its id); the delegated
// permissions directory.yaml grants it. 400 for a malformed name, 404 for
// an unknown group, 503 while the directory is down.
func (h *Hub) GroupUses(ctx context.Context, group string) (*GroupUsesView, error) {
	if !lldap.ValidGroupName(group) {
		return nil, statusErr(400, "%q is not a valid group name", group)
	}
	m, err := h.readMembership(ctx)
	if err != nil {
		return nil, err
	}
	mg, ok := m.Groups[group]
	if !ok {
		return nil, statusErr(404, "no such group %s", group)
	}
	v := &GroupUsesView{Apps: []GroupApp{}, Settings: []GroupSetting{}, Permissions: []string{}}
	for _, p := range slices.Sorted(maps.Keys(m.Permissions)) {
		if m.Permissions[p] == group {
			v.Permissions = append(v.Permissions, p)
		}
	}
	names := namesGroup(group, mg.ID)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := range h.instances {
		t := &h.instances[i]
		name := instanceName(t)
		if t.Manifest.Auth.AccessGroup == group {
			v.Apps = append(v.Apps, GroupApp{Instance: t.ID, Name: name, Role: "access"})
		}
		if t.Manifest.Auth.AdminGroup == group {
			v.Apps = append(v.Apps, GroupApp{Instance: t.ID, Name: name, Role: "admin"})
		}
		if slices.Contains(h.privilegedGroupsLocked(t), group) {
			v.Apps = append(v.Apps, GroupApp{Instance: t.ID, Name: name, Role: "privileged"})
		}
	}
	for _, inst := range slices.Sorted(maps.Keys(h.st.Settings)) {
		t := h.findLocked(inst)
		_, rows := dropRows(h.st.Settings[inst], inst, t, func(_, g string, r state.GroupValue) string {
			if names(g, r) {
				return "names the group"
			}
			return ""
		})
		for _, r := range rows {
			gs := GroupSetting{Instance: inst, App: inst, Key: r.key, Label: r.key, Scope: r.scope, Value: fmt.Sprint(r.value)}
			if t != nil {
				gs.App = instanceName(t)
				if o := optionByKey(t, r.key); o != nil {
					gs.Label = o.Label
					if r.scope != templates.ScopeInstance {
						gs.Value = h.rowDisplay(o, r.value)
					}
				}
			}
			v.Settings = append(v.Settings, gs)
		}
	}
	return v, nil
}

// rowDisplay is a stored row value in Display form (as stored when it
// doesn't parse any more).
func (h *Hub) rowDisplay(o *templates.Option, raw any) string {
	if o.Type == templates.TypeSecret {
		return "•••"
	}
	if pv, err := h.kinds.Parse(o, raw); err == nil {
		return h.kinds.Display(o, pv)
	}
	return fmt.Sprint(raw)
}

// readMembership is membership with any directory failure answered 503
// (the two reads say "unavailable", whatever LLDAP's state).
func (h *Hub) readMembership(ctx context.Context) (*directory.Membership, error) {
	m, err := h.membership(ctx)
	var se *StatusError
	if err != nil && errors.As(err, &se) && se.Status != 503 {
		return nil, &StatusError{Status: 503, Err: se.Err}
	}
	return m, err
}
