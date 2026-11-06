package hub

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The admin settings panel (contract §13, Task 13): what
// GET /api/instances/{id}/settings answers, the preview of a draft
// (nothing stored, no external write) and the delivery retry. Directory
// calls run before mu is taken; mu is held only while state is read.

// UnresolvedText is how an UNRESOLVED person value (settings
// ReasonFailClosed with no value) is shown: the setting is omitted for
// that person, so the app's own default applies.
const UnresolvedText = "unresolved: the app's own default applies"

// Option warnings (OptionView.Warnings).
const (
	WarnAccountCreation = "existing accounts keep their value"
	// WarnMembershipRestart is formatted with the app's name.
	WarnMembershipRestart = "people joining or leaving restarts %s"
	WarnNeedsSignIn       = "per-person values need Portcullis sign-in"
	// WarnEntryRestart: a person-entered option whose changes restart.
	WarnEntryRestart = "people entering or changing a value restarts %s"
)

// OptionView is one option as the panel shows it: its definition, the
// template default as text, its effect on a running instance (an env or
// path option restarts it), warnings, and — privileged options — every
// directory group, those that can't hold a privileged value disabled
// with the directory's reason.
type OptionView struct {
	templates.Option
	DefaultDisplay string        `json:"default_display"`
	Effect         string        `json:"effect"`
	Warnings       []string      `json:"warnings,omitempty"`
	GroupChoices   []GroupChoice `json:"group_choices,omitempty"`
}

// GroupChoice is one group a privileged option's row may name.
type GroupChoice struct {
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
	Reason   string `json:"reason,omitempty"`
}

// PopulationView is who per-person values reach: how many people, or
// why nobody.
type PopulationView struct {
	Count int    `json:"count"`
	Why   string `json:"why,omitempty"`
}

// EntryRow is one stored person-entered value (spec call 32): the
// person, the value, when and by whom it was set (the person's name, or
// the admin's), and whether it is delivered or why not (EntryWhyNoAccess,
// EntryWhyAccountChanged).
type EntryRow struct {
	User      string    `json:"user"`
	Value     any       `json:"value"`
	Display   string    `json:"display"`
	UpdatedAt time.Time `json:"updated_at"`
	SetBy     string    `json:"set_by"`
	Delivered bool      `json:"delivered"`
	Why       string    `json:"why,omitempty"`
}

// EntriesView is a person_entered option's values: every stored value,
// sorted by user, and the population members without one.
type EntriesView struct {
	Rows   []EntryRow `json:"rows"`
	NotSet []string   `json:"not_set"`
}

// SettingsPanel is an instance's settings panel. Secret values never
// appear: Secrets carries {set, updated_at, generated} only.
type SettingsPanel struct {
	AppSettingsView
	// Name is the app's display name; Enabled: the instance runs (a save
	// that changes its sign-in or access restarts it).
	Name     string       `json:"name"`
	Enabled  bool         `json:"enabled"`
	Sections []string     `json:"sections"`
	Options  []OptionView `json:"options"`
	// Instance: the stored instance option values (canonical; absent =
	// the default; never secrets).
	Instance map[string]any `json:"instance"`
	// InstanceGroupIDs: the LLDAP ids instance group / groups values are
	// bound to (option key → name → id); send them back with the value
	// (value_group_ids): a mismatch is a 409.
	InstanceGroupIDs map[string]map[string]int `json:"instance_group_ids"`
	// Person / Groups: per-person configurations and group records as
	// stored, placeholders shown as the instance's group names, each row
	// with its stored group_id (send it back: a mismatch is a 409).
	Person     map[string]state.PersonSetting `json:"person"`
	Groups     map[string][]state.GroupValue  `json:"groups"`
	Secrets    map[string]SecretView          `json:"secrets"`
	Ports      map[string]string              `json:"ports"`
	Population PopulationView                 `json:"population"`
	Deliveries DeliveryStatus                 `json:"deliveries"`
	Entries    map[string]EntriesView         `json:"entries"`
	// DirectoryGroups: every directory group name, sorted (the row
	// pickers; empty while the directory is unavailable). Privileged
	// options carry GroupChoices instead.
	DirectoryGroups []string `json:"directory_groups"`
}

// PersonPreview is one person's value under a draft. Reason.Others (the
// losing rows) is shown here only: the admin preview.
type PersonPreview struct {
	User    string          `json:"user"`
	Display string          `json:"display"`
	Reason  settings.Reason `json:"reason"`
}

// OptionPreview is a person option under a draft: every population
// member (sorted by user), how many get another value than under the
// saved configuration, and per row group how many of its members are
// outside the population (they get nothing).
type OptionPreview struct {
	People   []PersonPreview `json:"people"`
	Changes  int             `json:"changes"`
	NoAccess map[string]int  `json:"no_access"`
}

// Preview is what saving a draft would do: its effect and the person
// options' values. The effect covers the option values, secrets and
// ports; a policy, public-access or sign-in change restarts an enabled
// instance on top (its override changes).
//
// Population is who per-person values reach under the draft: a draft
// that switches to the app's own login only reaches nobody
// (WhyNativeSignIn).
type Preview struct {
	Effect     string                   `json:"effect"`
	Options    map[string]OptionPreview `json:"options"`
	Population PopulationView           `json:"population"`
}

// withPlaceholders maps rows the panel sent with the instance's group
// name back to the {{ACCESS_GROUP}} / {{ADMIN_GROUP}} placeholder of the
// stored row they were shown for, so a resent row stays a placeholder.
// u's maps are not modified.
func withPlaceholders(t *templates.Template, cur state.InstanceSettings, u SettingsUpdate) SettingsUpdate {
	names := func(stored []state.GroupValue) map[string]string {
		out := map[string]string{}
		for _, r := range stored {
			if isPlaceholder(r.Group) {
				if n := placeholderGroup(t, r.Group); n != "" {
					out[strings.ToLower(n)] = r.Group
				}
			}
		}
		return out
	}
	mapRows := func(in []GroupValueInput, ph map[string]string) []GroupValueInput {
		if len(ph) == 0 {
			return in
		}
		out := slices.Clone(in)
		for i := range out {
			if p, ok := ph[strings.ToLower(out[i].Group)]; ok {
				out[i].Group = p
			}
		}
		return out
	}
	if len(u.Person) > 0 {
		person := make(map[string]PersonChange, len(u.Person))
		for k, pc := range u.Person {
			pc.Rows = mapRows(pc.Rows, names(cur.Person[k].Rows))
			person[k] = pc
		}
		u.Person = person
	}
	if len(u.Groups) > 0 {
		groups := make(map[string][]GroupValueInput, len(u.Groups))
		for k, recs := range u.Groups {
			groups[k] = mapRows(recs, names(cur.Groups[k]))
		}
		u.Groups = groups
	}
	return u
}

// hasPersonOptions: t has a person-scope option.
func hasPersonOptions(t *templates.Template) bool {
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].EffectiveScope() == templates.ScopePerson {
			return true
		}
	}
	return false
}

// optionRunningEffect is a change of o's effect on a running instance
// (as SaveSettings computes it): a path or env-delivered option restarts.
func optionRunningEffect(o *templates.Option) string {
	if o.Type == templates.TypePath || len(envDeliveries(o)) > 0 {
		return settings.EffectRestart
	}
	return settings.EffectOf(o.EffectiveApplies())
}

// SettingsPanel is instance id's settings panel. The directory snapshot
// (population, privileged group choices) is taken before mu; the
// directory unavailable leaves them empty with the reason.
func (h *Hub) SettingsPanel(ctx context.Context, id string) (*SettingsPanel, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	var m *directory.Membership
	var merr error
	if hasPeopleOptions(t) {
		m, merr = h.membership(ctx)
	}
	base, err := h.AppSettings(id)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	live := h.findLocked(id)
	if live == nil {
		h.mu.RUnlock()
		return nil, ErrNotFound
	}
	t = live
	s := h.st.Settings[id]
	p := &SettingsPanel{
		AppSettingsView:  *base,
		Sections:         []string{},
		Options:          []OptionView{},
		Instance:         map[string]any{},
		InstanceGroupIDs: map[string]map[string]int{},
		Person:           map[string]state.PersonSetting{},
		Groups:           map[string][]state.GroupValue{},
		Secrets:          base.Secrets,
		Ports:            maps.Clone(s.Ports),
		Entries:          map[string]EntriesView{},
		Name:             t.Manifest.Name,
		Enabled:          t.Enabled,
		DirectoryGroups:  []string{},
	}
	if m != nil {
		p.DirectoryGroups = slices.Sorted(maps.Keys(m.Groups))
	}
	if p.Ports == nil {
		p.Ports = map[string]string{}
	}
	if t.Manifest.Settings != nil && t.Manifest.Settings.Sections != nil {
		p.Sections = slices.Clone(t.Manifest.Settings.Sections)
	}
	why := h.populationWhyLocked(t)
	switch {
	case m != nil:
		pop := h.populationLocked(t, m)
		p.Population = PopulationView{Count: len(pop.People), Why: pop.Why}
		why = pop.Why
	case merr != nil && why == "":
		p.Population.Why = "Users & Groups unavailable: " + merr.Error()
	default:
		p.Population.Why = why
	}
	shown := func(rows []state.GroupValue) []state.GroupValue {
		out := make([]state.GroupValue, len(rows))
		for i, r := range rows {
			if n := placeholderGroup(t, r.Group); n != "" {
				r.Group = n
			}
			out[i] = r
		}
		return out
	}
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		typeOK := h.typeMatchesLocked(t, o.Key, o)
		switch o.EffectiveScope() {
		case templates.ScopeInstance:
			if v, ok := s.Values[o.Key]; ok && typeOK && o.Type != templates.TypeSecret {
				p.Instance[o.Key] = v
				if ids := s.GroupIDs[o.Key]; len(ids) > 0 {
					p.InstanceGroupIDs[o.Key] = maps.Clone(ids)
				}
			}
		case templates.ScopePerson:
			if ps, ok := s.Person[o.Key]; ok && typeOK && !hubSetOption(o) {
				ps.Rows = shown(ps.Rows)
				p.Person[o.Key] = ps
			}
		case templates.ScopeGroup:
			if recs, ok := s.Groups[o.Key]; ok && typeOK {
				p.Groups[o.Key] = shown(recs)
			}
		}
		p.Options = append(p.Options, h.optionViewLocked(t, o, m, why))
	}
	p.Entries = h.entriesViewLocked(t, m)
	h.mu.RUnlock()
	p.Deliveries = h.DeliveryStatus(id)
	return p, nil
}

// optionViewLocked is o's OptionView (why: the population's reason).
// Caller holds mu (read).
func (h *Hub) optionViewLocked(t *templates.Template, o *templates.Option, m *directory.Membership, why string) OptionView {
	v := OptionView{Option: *o, Effect: optionRunningEffect(o)}
	if o.Default != nil && o.Type != templates.TypeSecret {
		if d, err := h.kinds.Parse(o, o.Default); err == nil && d != nil {
			v.DefaultDisplay = h.kinds.Display(o, d)
		}
	}
	if o.EffectiveApplies() == templates.AppliesAccountCreation {
		v.Warnings = append(v.Warnings, WarnAccountCreation)
	}
	if o.EffectiveScope() == templates.ScopePerson {
		restarts := false
		for _, d := range o.Delivery {
			if d.File == nil {
				continue
			}
			for _, f := range t.Manifest.Files {
				restarts = restarts || (f.Name == d.File.Name && f.OnMembershipChange == templates.MembershipRestart)
			}
		}
		if restarts {
			v.Warnings = append(v.Warnings, fmt.Sprintf(WarnMembershipRestart, t.Manifest.Name))
		}
		if why == WhyNativeSignIn || why == WhyNoIdentity {
			v.Warnings = append(v.Warnings, WarnNeedsSignIn)
		}
	}
	if o.EffectiveScope() == templates.ScopePersonEntered && entryRestarts(t, o) {
		v.Warnings = append(v.Warnings, fmt.Sprintf(WarnEntryRestart, t.Manifest.Name))
	}
	if o.Privileged && m != nil {
		for _, g := range slices.Sorted(maps.Keys(m.Groups)) {
			reason := m.Privilege[g]
			v.GroupChoices = append(v.GroupChoices, GroupChoice{Name: g, Disabled: reason != "", Reason: reason})
		}
	}
	return v
}

// previewDisplay is a resolved value as the preview shows it.
func previewDisplay(kinds *settings.Registry, o *templates.Option, r settings.Resolved) string {
	if r.Value == nil {
		return UnresolvedText
	}
	return kinds.Display(o, r.Value)
}

// PreviewSettings is what saving u to instance id would do, without
// storing anything or writing anywhere: u is checked like a save (the
// same 400 / 409 refusals), its rows bound against ONE directory
// snapshot, which also gives the population every person option is
// resolved for, under the draft and under the saved configuration.
func (h *Hub) PreviewSettings(ctx context.Context, id string, u SettingsUpdate) (*Preview, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	h.mu.RLock()
	// A restore, delete or shared-folder apply in progress (ruling 6).
	pendErr := h.pendingLocked(id)
	native := h.st.SignIn[id] == state.SignInNative
	folders := h.folderSourceLocked()
	defs := maps.Clone(h.st.Folders)
	stored := h.st.Settings[id].Clone()
	u = withPlaceholders(t, h.st.Settings[id], u)
	h.mu.RUnlock()
	if pendErr != nil {
		return nil, pendErr
	}
	if u.SignIn != nil {
		native = *u.SignIn == SignInNative
	}
	// The save's folder refusals (ruling 18): the preview accepts only
	// what the save would.
	if err := folderSaveCheck(t, stored, defs, u); err != nil {
		return nil, err
	}
	parsed, problems := configCheck(t, h.kinds, folders, u, native)
	if len(problems) > 0 {
		return nil, problems[0]
	}
	if err := gidRangeSaveCheck(t, parsed); err != nil {
		return nil, err
	}
	if err := privilegedDefaults(t, parsed); err != nil {
		return nil, err
	}
	var m *directory.Membership
	if rowCount(parsed) > 0 || hasPersonOptions(t) {
		var err error
		if m, err = h.membership(ctx); err != nil {
			if rowCount(parsed) > 0 {
				return nil, bindDirectoryErr(err)
			}
			m = nil // instance values only: the effect is still known
		}
	}
	if rowCount(parsed) > 0 {
		if _, err := h.bindRowsWith(t, parsed, m); err != nil {
			return nil, err
		}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	live := h.findLocked(id)
	if live == nil {
		return nil, ErrNotFound
	}
	cur := h.st.Settings[id]
	next, effects, own, _, err := h.nextSettingsLocked(live, cur, parsed)
	if err != nil {
		return nil, err
	}
	out := &Preview{Effect: settings.Strongest(own...), Options: map[string]OptionPreview{}}
	if live.Enabled {
		out.Effect = settings.Strongest(effects...)
	}
	if m == nil {
		if hasPersonOptions(live) {
			out.Population.Why = "Users & Groups unavailable"
		}
		return out, nil
	}
	pop := h.populationLocked(live, m)
	if u.SignIn != nil && live.Manifest.Auth.HasNativeLogin() {
		pop = populationIn(live, m, *u.SignIn == SignInNative && live.Manifest.Auth.NativeLogin.AllowWithoutGateway)
	}
	out.Population = PopulationView{Count: len(pop.People), Why: pop.Why}
	in := map[string]bool{}
	for _, p := range pop.People {
		in[p.User] = true
	}
	opts := live.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.EffectiveScope() != templates.ScopePerson || hubSetOption(o) {
			continue
		}
		before := h.personConfigForFrom(live, o.Key, cur, m)
		after := h.personConfigForFrom(live, o.Key, next, m)
		op := OptionPreview{People: make([]PersonPreview, 0, len(pop.People)), NoAccess: map[string]int{}}
		for _, p := range pop.People {
			person := func() settings.Person { return settings.Person{User: p.User, Groups: maps.Clone(p.Groups)} }
			r := h.kinds.Resolve(o, after, person())
			old := h.kinds.Resolve(o, before, person())
			if !reflect.DeepEqual(r.Value, old.Value) {
				op.Changes++
			}
			op.People = append(op.People, PersonPreview{User: p.User, Display: previewDisplay(h.kinds, o, r), Reason: r.Reason})
		}
		for _, r := range after.Rows {
			n := 0
			for _, u := range m.Groups[r.Group].Members {
				if _, isUser := m.Users[u]; isUser && !in[u] {
					n++
				}
			}
			op.NoAccess[r.Group] = n
		}
		out.Options[o.Key] = op
	}
	return out, nil
}

// RetryDeliveries runs instance id's deliveries again now (every hook,
// trigger retry) and reports each unit; audited settings.retry by actor.
// The run is not cancelled with the request, and never waits for one in
// progress (a hook can hold the delivery lock for its whole timeout):
// busy = queued (TriggerRetry), reported as a busy unit; the panel polls.
func (h *Hub) RetryDeliveries(ctx context.Context, id string, actor directory.Actor) (*DeliveryReport, error) {
	if h.Template(id) == nil {
		return nil, ErrNotFound
	}
	rep, err := h.deliver(context.WithoutCancel(ctx), id, TriggerRetry, deliverOpts{noWait: true})
	detail := ""
	if rep != nil {
		failed := 0
		for _, u := range rep.Units {
			if u.Error != "" {
				failed++
			}
		}
		detail = fmt.Sprintf("%d units, %d failed", len(rep.Units), failed)
	}
	h.auditOp(actor, "settings.retry", id, detail, err)
	return rep, err
}

// entryRestarts: a change of person-entered option o restarts the app
// (an env list, or a data file with on_membership_change: restart).
func entryRestarts(t *templates.Template, o *templates.Option) bool {
	for _, d := range o.Delivery {
		if d.Env != "" {
			return true
		}
		if d.File == nil {
			continue
		}
		for _, f := range t.Manifest.Files {
			if f.Name == d.File.Name && f.OnMembershipChange == templates.MembershipRestart {
				return true
			}
		}
	}
	return false
}
