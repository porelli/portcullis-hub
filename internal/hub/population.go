package hub

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Who a person option applies to (spec call 27, contract §13.4): the
// people group-gate or the access role would let in on the instance's
// signed-in routes.
//
//   - With an access group (group access on, or the access role
//     enforced): its LLDAP members, minus the memberships that expired
//     and aren't removed yet (group-gate already denies them).
//   - Otherwise: every LLDAP user but the Hub's service account.
//   - Admin, extra and core groups never widen it; public routes add
//     nobody.
//   - sign_in native, and routes that carry no Portcullis identity at all
//     (method public, custom without native_login): nobody, with Why.

// Population reasons.
const (
	WhyNativeSignIn = "per-person values need Portcullis sign-in"
	WhyNoIdentity   = "per-person values need Portcullis sign-in: this app's routes carry no Portcullis identity"
	WhyNoAccess     = "the access group doesn't exist in LLDAP: nobody can reach the app"
)

// Population is an option's people, sorted by user, each with their
// groups (expired memberships dropped); Why says why it is empty when no
// one can get a per-person value.
type Population struct {
	People []settings.Person
	Why    string
}

// populationWhyLocked is why t's routes give per-person values to
// nobody ("" = they carry Portcullis identity). Caller holds mu.
func (h *Hub) populationWhyLocked(t *templates.Template) string {
	return populationWhy(t, h.accessLocked(t).SignIn == SignInNative)
}

// populationWhy is populationWhyLocked with the sign-in mode given
// (native: the app's own login only).
func populationWhy(t *templates.Template, native bool) string {
	a := &t.Manifest.Auth
	switch {
	case t.Manifest.Routerless() && a.GroupAccess && a.AccessGroup != "":
		// Router-less custom with group access (F1, file sharing): the
		// access group's members (minus expired) — what
		// entryPopulationLocked gives such an instance.
		return ""
	case a.Method == "public", a.Method == "custom" && !a.HasNativeLogin():
		return WhyNoIdentity
	case native:
		return WhyNativeSignIn
	}
	return ""
}

// accessGroupOf is the group that gates t's signed-in routes ("" =
// none: group access off and no access role). t is an instance view:
// its Manifest.Auth carries instanceGroupsLocked's answer
// (stampInstanceLocked), the bound group included (§11.9).
//
// An unstamped view (built without newViewLocked) has no known group:
// it answers unstampedGroup, a name no LLDAP group can have, so the
// population is nobody (fail closed) — never "" (no gate: everybody).
func accessGroupOf(t *templates.Template) string {
	a := &t.Manifest.Auth
	if a.AccessGroup == "" || !(a.GroupAccess || t.Manifest.AccessRoleEnforced()) {
		return ""
	}
	if !t.Stamped {
		return unstampedGroup
	}
	return a.AccessGroup
}

// unstampedGroup is the group of an unstamped view: a name LLDAP group
// names can't take (spaces and brackets), so it matches nobody.
const unstampedGroup = "[unresolved instance groups]"

// personOf is user's Person from m, without expired memberships.
func personOf(m *directory.Membership, user string) settings.Person {
	groups := map[string]int{}
	for g, id := range m.Users[user] {
		if !m.Expired[user][g] {
			groups[g] = id
		}
	}
	return settings.Person{User: user, Groups: groups}
}

// populationLocked is t's population in m. Caller holds mu (read).
func (h *Hub) populationLocked(t *templates.Template, m *directory.Membership) Population {
	return populationIn(t, m, h.accessLocked(t).SignIn == SignInNative)
}

// populationIn is t's population in m with the sign-in mode given
// (native: the app's own login only; a draft's mode in the preview).
func populationIn(t *templates.Template, m *directory.Membership, native bool) Population {
	if why := populationWhy(t, native); why != "" {
		return Population{Why: why}
	}
	var users []string
	if g := accessGroupOf(t); g != "" {
		mg, ok := m.Groups[g]
		if !ok {
			return Population{Why: WhyNoAccess}
		}
		for _, u := range mg.Members {
			if _, isUser := m.Users[u]; isUser && !m.Expired[u][g] {
				users = append(users, u)
			}
		}
	} else {
		users = make([]string, 0, len(m.Users))
		for u := range m.Users {
			users = append(users, u)
		}
	}
	sort.Strings(users)
	out := Population{People: make([]settings.Person, 0, len(users))}
	for _, u := range users {
		out.People = append(out.People, personOf(m, u))
	}
	return out
}

// membership asks the directory for a snapshot (no lock held). nil
// People: 503.
func (h *Hub) membership(ctx context.Context) (*directory.Membership, error) {
	h.mu.RLock()
	p := h.people
	h.mu.RUnlock()
	if p == nil {
		return nil, statusErr(503, "users & groups is not available")
	}
	m, err := p.Membership(ctx, time.Now().UTC())
	if err != nil {
		// The directory's status (502 unreachable, 503 unavailable).
		status := 503
		var de *directory.Error
		if errors.As(err, &de) && de.Status >= 500 {
			status = de.Status
		}
		return nil, &StatusError{Status: status, Err: err}
	}
	return m, nil
}

// InPopulation reports whether user (any case) is in instance's
// population of person options.
func (h *Hub) InPopulation(ctx context.Context, instance, user string) (bool, error) {
	m, err := h.membership(ctx)
	if err != nil {
		return false, err
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(instance)
	if t == nil {
		return false, ErrNotFound
	}
	user = strings.ToLower(user)
	for _, p := range h.populationLocked(t, m).People {
		if p.User == user {
			return true, nil
		}
	}
	return false, nil
}

// placeholderGroup is the group a {{ACCESS_GROUP}} / {{ADMIN_GROUP}}
// row of instance view t names ("" = none); any other name is itself.
// The view's Manifest.Auth carries instanceGroupsLocked's answer
// (stampInstanceLocked): a bound instance's rows name its bound groups.
func placeholderGroup(t *templates.Template, g string) string {
	if !t.Stamped && (g == templates.PlaceholderAccessGroup || g == templates.PlaceholderAdminGroup) {
		return "" // fail closed: an unstamped view's row names nobody
	}
	switch g {
	case templates.PlaceholderAccessGroup:
		return t.Manifest.Auth.AccessGroup
	case templates.PlaceholderAdminGroup:
		return t.Manifest.Auth.AdminGroup
	}
	return g
}

// personConfigLocked is option key's configuration of instance t as
// Resolve takes it: the default and rows parsed canonical (a row that no
// longer parses is passed as stored: Resolve treats it as stale, fail
// closed), placeholders resolved to the instance's group names, unbound
// rows (id 0) left out — they grant nothing. Caller holds mu (read).
func (h *Hub) personConfigLocked(t *templates.Template, key string) settings.PersonConfig {
	return h.personConfigFrom(t, key, h.st.Settings[t.ID])
}

// personConfigFrom is personConfigLocked for the settings s (stored, or
// a preview's draft).
func (h *Hub) personConfigFrom(t *templates.Template, key string, s state.InstanceSettings) settings.PersonConfig {
	o := optionByKey(t, key)
	ps, ok := s.Person[key]
	if typ := s.Types[key]; o == nil || !ok || (typ != "" && typ != o.Type) {
		pc := settings.PersonConfig{}
		if o != nil {
			pc.Default, _ = h.kinds.Parse(o, o.Default)
		}
		return pc
	}
	pc := settings.PersonConfig{Rule: ps.Resolve}
	if v, err := h.kinds.Parse(o, ps.Default); err == nil {
		pc.Default = v
	} else if v, err := h.kinds.Parse(o, o.Default); err == nil {
		pc.Default = v
	}
	for _, r := range ps.Rows {
		name := placeholderGroup(t, r.Group)
		if name == "" || r.GroupID == 0 {
			continue
		}
		v, err := h.kinds.Parse(o, r.Value)
		if err != nil {
			v = r.Value
		}
		pc.Rows = append(pc.Rows, settings.Row{Group: name, GroupID: r.GroupID, Value: v})
	}
	return pc
}

// personConfigForLocked is personConfigLocked with m's privilege
// answers applied: a privileged option's row from a group that can't
// hold privileged values (a template update made the option privileged,
// a rule changed) grants the option's lowest-ranked value from that
// moment — never dropped, so it can't lift a min or a priority either.
func (h *Hub) personConfigForLocked(t *templates.Template, key string, m *directory.Membership) settings.PersonConfig {
	return h.personConfigForFrom(t, key, h.st.Settings[t.ID], m)
}

// personConfigForFrom is personConfigForLocked for the settings s.
func (h *Hub) personConfigForFrom(t *templates.Template, key string, s state.InstanceSettings, m *directory.Membership) settings.PersonConfig {
	pc := h.personConfigFrom(t, key, s)
	o := optionByKey(t, key)
	if o == nil || !o.Privileged {
		return pc
	}
	low := lowestValue(o)
	rows := make([]settings.Row, len(pc.Rows))
	for i, r := range pc.Rows {
		if m.Privilege[r.Group] != "" {
			r.Value = low
		}
		rows[i] = r
	}
	pc.Rows = rows
	return pc
}

// lowestValue is a privileged option's lowest-ranked value (enum: the
// first option; bool: false).
func lowestValue(o *templates.Option) settings.Value {
	if o.Type == templates.TypeEnum && len(o.Choices) > 0 {
		return o.Choices[0].Value
	}
	return false
}

// resolvePeopleLocked resolves every person option of t for its
// population in m: user → key → resolved. Group-scope options are never
// resolved per person (only their records are delivered). Caller holds
// mu (read).
func (h *Hub) resolvePeopleLocked(t *templates.Template, m *directory.Membership) map[string]map[string]settings.Resolved {
	out := map[string]map[string]settings.Resolved{}
	pop := h.populationLocked(t, m)
	opts := t.Manifest.Options()
	configs := map[string]settings.PersonConfig{}
	for i := range opts {
		if o := &opts[i]; o.EffectiveScope() == templates.ScopePerson && !hubSetOption(o) {
			// person_secret / person_id: computed by the Hub, never
			// resolved from admin rows (F5).
			configs[o.Key] = h.personConfigForLocked(t, o.Key, m)
		}
	}
	for _, p := range pop.People {
		vals := make(map[string]settings.Resolved, len(configs))
		for k, pc := range configs {
			vals[k] = h.kinds.Resolve(optionByKey(t, k), pc, settings.Person{User: p.User, Groups: maps.Clone(p.Groups)})
		}
		out[p.User] = vals
	}
	return out
}
