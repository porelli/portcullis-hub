package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Per-person and per-group settings against the directory (contract
// §13.4, spec calls 9, 19, 27–29):
//
//   - Every row and record stores the LLDAP group id it was saved
//     against; resolution matches name and id, so a group deleted and
//     re-created (in the Hub or straight in LLDAP) inherits nothing.
//   - {{ACCESS_GROUP}} / {{ADMIN_GROUP}} rows stay placeholders and are
//     bound to the instance's groups' ids when those exist: EnableAs
//     after its groups, CreateInstanceAs after its groups, restore and
//     "create missing groups" (bindPlaceholderRows) — never at delivery
//     time. An unbound row (id 0) grants nothing.
//   - A privileged option takes rows only from groups that can hold
//     privileged values (directory PrivilegeProblem): checked at save,
//     applied at resolution from the current directory state, and such
//     rows are dropped by the next reconcile.
//   - Deleting a group through the Hub purges its rows and records in
//     every instance at once (PurgeGroupSettings); a mismatch found later
//     is purged by reconcileGroupRows, only while LLDAP passes the user
//     sweep's sanity check (an empty or partial LLDAP would wipe them).
//   - Discover never changes settings: values of options a template
//     update removed, retyped or rescoped are ignored at once and dropped
//     by pruneSettings after the final Discover of a source sync or Init.
//
// Directory calls (network) never run under mu; audits run after mu is
// released (auditOp takes it).

// purgeActor audits the Hub's own purges.
const purgeActor = "hub"

// typeMatchesLocked: the stored type of key (none recorded = ok) is o's.
func (h *Hub) typeMatchesLocked(t *templates.Template, key string, o *templates.Option) bool {
	typ := h.st.Settings[t.ID].Types[key]
	return typ == "" || typ == o.Type
}

// isPlaceholder reports a {{ACCESS_GROUP}} / {{ADMIN_GROUP}} row.
func isPlaceholder(g string) bool {
	return g == templates.PlaceholderAccessGroup || g == templates.PlaceholderAdminGroup
}

// TriggerDelivery queues instance id's settings delivery for trig. Until
// the delivery engine (Task 9) it only records the request and runs the
// stub Deliver in the background: never inline, so it is safe under any
// lifecycle lock (PurgeGroupSettings runs inside DeleteInstance's).
// immediate=false will be debounced (settingsDebounce) by the engine.
func (h *Hub) TriggerDelivery(id string, trig Trigger, immediate bool) {
	h.deliveryMu.Lock()
	if h.pendingDelivery == nil {
		h.pendingDelivery = map[string]Trigger{}
	}
	h.pendingDelivery[id] = trig
	h.deliveryMu.Unlock()
	h.goBackground(func() {
		if _, err := h.Deliver(context.Background(), id, trig); err != nil {
			log.Printf("settings: %s: delivery (%s): %v", id, trig, err)
		}
	})
}

// bindRowsForSave binds the rows and records of a save to the
// directory's current group ids, before mu is taken: an unknown group is
// a 400, a placeholder whose group doesn't exist yet stays unbound (a
// warning). A privileged option's rows must come from groups that can
// hold privileged values (400 with the directory's reason) and its
// default must be its lowest-ranked value. Directory unavailable: 503.
func (h *Hub) bindRowsForSave(ctx context.Context, t *templates.Template, parsed *parsedSettings) ([]string, error) {
	n := 0
	for _, p := range parsed.person {
		n += len(p.Rows)
	}
	for _, recs := range parsed.groups {
		n += len(recs)
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.person)) {
		if o := optionByKey(t, k); o.Privileged && !reflect.DeepEqual(parsed.person[k].Default, lowestValue(o)) {
			return nil, statusErr(400, "setting %s: a privileged option's default must be its lowest-ranked value %v", k, lowestValue(o))
		}
	}
	if n == 0 {
		return nil, nil // nothing to bind: no directory needed
	}
	m, err := h.membership(ctx)
	if err != nil {
		return nil, &StatusError{Status: 503, Err: fmt.Errorf("per-person and per-group values need the directory to bind their groups (nothing was saved): %w", err)}
	}
	h.mu.RLock()
	people := h.people
	h.mu.RUnlock()
	var warnings []string
	bind := func(o *templates.Option, rows []state.GroupValue) error {
		for i := range rows {
			r := &rows[i]
			name := placeholderGroup(t, r.Group)
			if name == "" {
				return statusErr(400, "setting %s: %s: the template has no such group", o.Key, r.Group)
			}
			mg, ok := m.Groups[name]
			if !ok {
				if isPlaceholder(r.Group) {
					r.GroupID = 0
					warnings = append(warnings, fmt.Sprintf("setting %s: the row for %s (%s) grants nothing until that group exists", o.Key, r.Group, name))
					continue
				}
				return statusErr(400, "setting %s: group %s doesn't exist", o.Key, name)
			}
			r.GroupID = mg.ID
			if o.Privileged {
				why, err := people.PrivilegeProblem(ctx, name)
				if err != nil {
					var de *directory.Error
					if errors.As(err, &de) && de.Status == 404 {
						return statusErr(400, "setting %s: group %s doesn't exist", o.Key, name)
					}
					return &StatusError{Status: 503, Err: fmt.Errorf("setting %s: group %s: %w", o.Key, name, err)}
				}
				if why != "" {
					return statusErr(400, "setting %s: group %s can't grant a privileged value: %s", o.Key, name, why)
				}
			}
		}
		return nil
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.person)) {
		if err := bind(optionByKey(t, k), parsed.person[k].Rows); err != nil {
			return nil, err
		}
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.groups)) {
		if err := bind(optionByKey(t, k), parsed.groups[k]); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// groupSettingsChangesLocked applies parsed's person and group changes
// to next (cur = before): the changes for the audit (default, rule,
// order, one per group row / record), each changed option's own effect
// and its effect on a running instance (an env delivery restarts).
func (h *Hub) groupSettingsChangesLocked(t *templates.Template, cur state.InstanceSettings, next *state.InstanceSettings, parsed *parsedSettings) (effects, own []string, changes []settingChange) {
	show := func(o *templates.Option, v any) string {
		if v == nil {
			return "unset"
		}
		if cv, err := h.kinds.Parse(o, v); err == nil {
			return h.kinds.Display(o, cv)
		}
		return fmt.Sprint(v)
	}
	rowChanges := func(o *templates.Option, scope string, before, after []state.GroupValue) []settingChange {
		var out []settingChange
		b := map[string]state.GroupValue{}
		for _, r := range before {
			b[r.Group] = r
		}
		a := map[string]state.GroupValue{}
		for _, r := range after {
			a[r.Group] = r
		}
		groups := map[string]bool{}
		for g := range a {
			groups[g] = true
		}
		for g := range b {
			groups[g] = true
		}
		for _, g := range slices.Sorted(maps.Keys(groups)) {
			x, okB := b[g]
			y, okA := a[g]
			if okA && okB && reflect.DeepEqual(x.Value, y.Value) && x.GroupID == y.GroupID {
				continue
			}
			c := settingChange{key: o.Key, scope: scope, group: g, before: "unset", after: "unset"}
			if okB {
				c.before = show(o, x.Value)
			}
			if okA {
				c.after = show(o, y.Value)
			}
			out = append(out, c)
		}
		order := func(rs []state.GroupValue) []string {
			var n []string
			for _, r := range rs {
				if _, ok := a[r.Group]; ok {
					if _, ok := b[r.Group]; ok {
						n = append(n, r.Group)
					}
				}
			}
			return n
		}
		if ob, oa := order(before), order(after); !slices.Equal(ob, oa) {
			out = append(out, settingChange{key: o.Key, scope: scope, before: "order " + strings.Join(ob, ","), after: "order " + strings.Join(oa, ",")})
		}
		return out
	}
	effectOf := func(o *templates.Option) {
		e := settings.EffectOf(o.EffectiveApplies())
		own = append(own, e)
		if len(envDeliveries(o)) > 0 {
			e = settings.EffectRestart
		}
		effects = append(effects, e)
	}
	setType := func(k, typ string) {
		if next.Types == nil {
			next.Types = map[string]string{}
		}
		next.Types[k] = typ
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.person)) {
		o := optionByKey(t, k)
		p := parsed.person[k]
		old, had := cur.Person[k]
		var cs []settingChange
		if !had || !reflect.DeepEqual(old.Default, p.Default) {
			before := "unset"
			if had {
				before = show(o, old.Default)
			}
			cs = append(cs, settingChange{key: k, scope: templates.ScopePerson, before: "default " + before, after: "default " + show(o, p.Default)})
		}
		if old.Resolve != p.Resolve {
			rule := func(r string) string {
				if r == "" {
					return o.Resolve + " (template)"
				}
				return r
			}
			cs = append(cs, settingChange{key: k, scope: templates.ScopePerson, before: "resolve " + rule(old.Resolve), after: "resolve " + rule(p.Resolve)})
		}
		cs = append(cs, rowChanges(o, templates.ScopePerson, old.Rows, p.Rows)...)
		if next.Person == nil {
			next.Person = map[string]state.PersonSetting{}
		}
		next.Person[k] = p
		setType(k, o.Type)
		if len(cs) > 0 {
			changes = append(changes, cs...)
			effectOf(o)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.groups)) {
		o := optionByKey(t, k)
		recs := parsed.groups[k]
		cs := rowChanges(o, templates.ScopeGroup, cur.Groups[k], recs)
		if next.Groups == nil {
			next.Groups = map[string][]state.GroupValue{}
		}
		if len(recs) == 0 {
			delete(next.Groups, k)
		} else {
			next.Groups[k] = recs
		}
		setType(k, o.Type)
		if len(cs) > 0 {
			changes = append(changes, cs...)
			effectOf(o)
		}
	}
	if len(next.Groups) == 0 {
		next.Groups = nil
	}
	return effects, own, changes
}

// groupRecordsOut are a group option's bound records as delivered: the
// group's name (placeholders resolved) and the canonical value, in the
// admin's order. Records that aren't bound, or whose value no longer
// parses (logged), are left out. Caller holds mu (read).
func (h *Hub) groupRecordsOut(t *templates.Template, o *templates.Option, recs []state.GroupValue) []settings.Row {
	out := []settings.Row{}
	for _, r := range recs {
		name := placeholderGroup(t, r.Group)
		if name == "" || r.GroupID == 0 {
			continue
		}
		v, err := h.kinds.Parse(o, r.Value)
		if err != nil {
			log.Printf("settings: %s: %s: the record for %s no longer fits the template (%v): not delivered", t.ID, o.Key, name, err)
			continue
		}
		out = append(out, settings.Row{Group: name, GroupID: r.GroupID, Value: v})
	}
	return out
}

// renderGroupEnv renders a group option's records for its env
// deliveries: one JSON value [{"group":…,"value":…}] each (render.format
// json is required for them by the validator).
func renderGroupEnv(o *templates.Option, recs []settings.Row) (map[string]string, error) {
	out := map[string]string{}
	for _, d := range envDeliveries(o) {
		items := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			rd, err := settings.Render(o, r.Value, settings.RenderOf(&d))
			if err != nil {
				return nil, fmt.Errorf("env %s: group %s: %w", d.Env, r.Group, err)
			}
			items = append(items, map[string]any{"group": r.Group, "value": rd.JSON})
		}
		b, err := json.Marshal(items)
		if err != nil {
			return nil, err
		}
		if _, err := envQuote(string(b)); err != nil {
			return nil, fmt.Errorf("env %s: %w", d.Env, err)
		}
		out[d.Env] = string(b)
	}
	return out, nil
}

// bindPlaceholderRows binds instance id's unbound placeholder rows and
// records to the ids of the groups they name now, and reports those
// whose group doesn't exist (they grant nothing; the panel warns). Bound
// rows are never re-bound: a re-created group inherits nothing. Never
// call it holding mu.
func (h *Hub) bindPlaceholderRows(ctx context.Context, id string) []string {
	h.mu.RLock()
	t := h.findLocked(id)
	need := false
	if t != nil {
		s := h.st.Settings[id]
		for _, p := range s.Person {
			for _, r := range p.Rows {
				need = need || isPlaceholder(r.Group) && r.GroupID == 0
			}
		}
		for _, recs := range s.Groups {
			for _, r := range recs {
				need = need || isPlaceholder(r.Group) && r.GroupID == 0
			}
		}
	}
	h.mu.RUnlock()
	if !need {
		return nil
	}
	m, err := h.membership(ctx)
	if err != nil {
		return []string{fmt.Sprintf("the template's starting rows of %s were not bound to their groups (%v): they grant nothing until \"Create missing groups\" or the next enable binds them", id, err)}
	}
	var warnings []string
	h.mu.Lock()
	t = h.findLocked(id)
	if t == nil {
		h.mu.Unlock()
		return nil
	}
	s := h.st.Settings[id].Clone()
	changed := false
	bindAll := func(key string, rows []state.GroupValue) {
		for i := range rows {
			r := &rows[i]
			if !isPlaceholder(r.Group) || r.GroupID != 0 {
				continue
			}
			name := placeholderGroup(t, r.Group)
			if mg, ok := m.Groups[name]; ok && name != "" {
				r.GroupID, changed = mg.ID, true
				continue
			}
			warnings = append(warnings, fmt.Sprintf("setting %s: the row for %s (%s) grants nothing: the group doesn't exist", key, r.Group, name))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(s.Person)) {
		p := s.Person[k]
		bindAll(k, p.Rows)
		s.Person[k] = p
	}
	for _, k := range slices.Sorted(maps.Keys(s.Groups)) {
		bindAll(k, s.Groups[k])
	}
	if changed {
		h.st.Settings[id] = s
		h.saveLocked()
	}
	h.mu.Unlock()
	return warnings
}

// purged is one audited purge (after mu is released).
type purged struct{ target, detail string }

// dropRowsLocked removes the rows and records of instance t (nil: no
// view — placeholders are kept as they can't be resolved) for which
// drop(option, resolved name, row) says why; reports the purges.
func (h *Hub) dropRowsLocked(id string, t *templates.Template, drop func(key, name string, r state.GroupValue) string) []purged {
	s, ok := h.st.Settings[id]
	if !ok {
		return nil
	}
	s = s.Clone()
	var out []purged
	filter := func(key, scope string, rows []state.GroupValue) []state.GroupValue {
		kept := rows[:0:0]
		for _, r := range rows {
			name := r.Group
			if isPlaceholder(r.Group) {
				if t == nil {
					kept = append(kept, r)
					continue
				}
				name = placeholderGroup(t, r.Group)
			}
			if why := drop(key, name, r); why != "" {
				out = append(out, purged{target: id + "/" + key, detail: fmt.Sprintf("scope=%s group=%s id=%d: %s", scope, name, r.GroupID, why)})
				continue
			}
			kept = append(kept, r)
		}
		return kept
	}
	for _, k := range slices.Sorted(maps.Keys(s.Person)) {
		p := s.Person[k]
		p.Rows = filter(k, templates.ScopePerson, p.Rows)
		if len(p.Rows) == 0 {
			p.Rows = nil
		}
		s.Person[k] = p
	}
	for _, k := range slices.Sorted(maps.Keys(s.Groups)) {
		if recs := filter(k, templates.ScopeGroup, s.Groups[k]); len(recs) > 0 {
			s.Groups[k] = recs
		} else {
			delete(s.Groups, k)
		}
	}
	if len(s.Groups) == 0 {
		s.Groups = nil
	}
	if len(out) > 0 {
		h.st.Settings[id] = s
	}
	return out
}

// PurgeGroupSettings removes every per-group row and group record that
// names group name (any id) in every instance, after the directory
// deleted it (directory.Service.GroupDeleted, spec call 19): audited as
// settings.purge by actor, and the affected instances re-deliver. It
// only changes state and queues the deliveries (TriggerDelivery, in the
// background): it runs inside DeleteInstance's per-instance lock, so a
// delivery or restart here would deadlock. Never call it holding mu.
func (h *Hub) PurgeGroupSettings(ctx context.Context, actor, name string, id int) []string {
	h.mu.Lock()
	var all []purged
	affected := map[string]bool{}
	for _, inst := range slices.Sorted(maps.Keys(h.st.Settings)) {
		ps := h.dropRowsLocked(inst, h.findLocked(inst), func(_, g string, _ state.GroupValue) string {
			if strings.EqualFold(g, name) {
				return fmt.Sprintf("group deleted (id %d)", id)
			}
			return ""
		})
		if len(ps) > 0 {
			affected[inst] = true
			all = append(all, ps...)
		}
	}
	var warnings []string
	if len(all) > 0 {
		if err := h.st.Save(h.statePath()); err != nil {
			warnings = append(warnings, fmt.Sprintf("removing the app setting rows of %s: saving state failed: %v", name, err))
		}
	}
	h.mu.Unlock()
	for _, p := range all {
		log.Printf("settings: %s: %s purged", p.target, p.detail)
		h.auditOp(actor, "settings.purge", p.target, p.detail, nil)
	}
	for _, inst := range slices.Sorted(maps.Keys(affected)) {
		h.TriggerDelivery(inst, TriggerMembership, true)
	}
	return warnings
}

// ldapSane is the user sweep's LLDAP check (usersweep.go): "" when an
// irreversible purge may run — the bootstrap admin and the service
// account exist, the user count hasn't dropped more than 20 % and more
// than 2 against the sweep's baseline, the sweep isn't paused.
func (h *Hub) ldapSane(ctx context.Context) string {
	s := h.sweep
	if s == nil {
		return "the LLDAP sanity check is not configured"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.load()
	if st.Paused {
		return "LLDAP looks wrong (" + st.Reason + ")"
	}
	if _, problem, _ := s.checkLDAP(ctx, st.LastOKCount); problem != "" {
		return problem
	}
	return ""
}

// reconcileGroupRows purges instance id's rows and records whose group
// is gone or now has another id (deleted and re-created outside the
// Hub, call 29), and a privileged option's rows from groups that can no
// longer hold privileged values (Review Focus 4). Resolution already
// gives them nothing; this makes it permanent, so only while LLDAP looks
// sane (ldapSane, P22) — otherwise nothing is purged (a warning).
// Audited settings.purge by "hub"; a purge re-delivers. Never call it
// holding mu. The delivery engine (Task 9) runs it before each delivery.
func (h *Hub) reconcileGroupRows(ctx context.Context, id string) []string {
	m, err := h.membership(ctx)
	if err != nil {
		return []string{fmt.Sprintf("setting rows of %s not checked against the directory: %v", id, err)}
	}
	if problem := h.ldapSane(ctx); problem != "" {
		log.Printf("settings: %s: WARNING: stale group rows are not purged: %s", id, problem)
		return []string{fmt.Sprintf("setting rows of %s whose group was deleted or re-created were not purged (they grant nothing): %s", id, problem)}
	}
	h.mu.Lock()
	t := h.findLocked(id)
	if t == nil {
		h.mu.Unlock()
		return nil
	}
	ps := h.dropRowsLocked(id, t, func(key, name string, r state.GroupValue) string {
		if r.GroupID == 0 {
			return "" // unbound: grants nothing, kept for binding
		}
		mg, ok := m.Groups[name]
		switch {
		case !ok:
			return "the group no longer exists"
		case mg.ID != r.GroupID:
			return fmt.Sprintf("the group was re-created (now id %d)", mg.ID)
		}
		if o := optionByKey(t, key); o != nil && o.Privileged && m.Privilege[name] != "" {
			return "can't grant a privileged value: " + m.Privilege[name]
		}
		return ""
	})
	if len(ps) > 0 {
		h.saveLocked()
	}
	h.mu.Unlock()
	var warnings []string
	for _, p := range ps {
		log.Printf("settings: %s: %s purged", p.target, p.detail)
		warnings = append(warnings, fmt.Sprintf("setting %s: the row was dropped (%s)", p.target, p.detail))
		h.auditOp(purgeActor, "settings.purge", p.target, p.detail, nil)
	}
	if len(ps) > 0 {
		h.TriggerDelivery(id, TriggerMembership, true)
	}
	return warnings
}

// checkArchivedRows checks an archive's rows and records against the
// directory before a restore (call 29): a row whose group is gone or has
// another id is dropped (a restore warning); placeholder rows are reset
// to unbound for a new instance (bound to its own groups afterwards) and
// dropped like any other when they mismatch on the same instance. The
// directory unavailable: rows kept as archived (they grant nothing on a
// mismatch; the next reconcile purges them), with a warning.
func (h *Hub) checkArchivedRows(ctx context.Context, t *templates.Template, s *state.InstanceSettings, newInstance bool) []string {
	if s == nil || len(s.Person)+len(s.Groups) == 0 {
		return nil
	}
	var warnings []string
	var m *directory.Membership
	if mm, err := h.membership(ctx); err == nil {
		m = mm
	} else {
		warnings = append(warnings, fmt.Sprintf("the archive's group rows were not checked against the directory (%v): rows whose group was re-created grant nothing until the next reconcile drops them", err))
	}
	filter := func(key string, rows []state.GroupValue) []state.GroupValue {
		kept := rows[:0:0]
		for _, r := range rows {
			if isPlaceholder(r.Group) && newInstance {
				r.GroupID = 0
				kept = append(kept, r)
				continue
			}
			if m == nil || r.GroupID == 0 {
				kept = append(kept, r)
				continue
			}
			name := placeholderGroup(t, r.Group)
			if mg, ok := m.Groups[name]; ok && mg.ID == r.GroupID {
				kept = append(kept, r)
				continue
			}
			warnings = append(warnings, fmt.Sprintf("setting %s: the row for %s was dropped: the group was deleted or re-created since the backup", key, name))
		}
		return kept
	}
	for _, k := range slices.Sorted(maps.Keys(s.Person)) {
		p := s.Person[k]
		p.Rows = filter(k, p.Rows)
		if len(p.Rows) == 0 {
			p.Rows = nil
		}
		s.Person[k] = p
	}
	for _, k := range slices.Sorted(maps.Keys(s.Groups)) {
		if recs := filter(k, s.Groups[k]); len(recs) > 0 {
			s.Groups[k] = recs
		} else {
			delete(s.Groups, k)
		}
	}
	return warnings
}

// staleKey reports why a stored setting key no longer fits t ("" = it
// does): the option is gone, has another scope (want) or another type
// than when it was stored.
func staleKey(t *templates.Template, key, want, storedType string) string {
	o := optionByKey(t, key)
	switch {
	case o == nil:
		return "the option was removed from the template"
	case o.EffectiveScope() != want:
		return fmt.Sprintf("the option is now scope %s", o.EffectiveScope())
	case storedType != "" && storedType != o.Type:
		return fmt.Sprintf("the option's type changed (%s -> %s)", storedType, o.Type)
	}
	return ""
}

// pruneSettingsLocked drops the stored settings that no longer fit their
// instance's template — options removed, rescoped or retyped (values,
// per-person configurations, group records, secrets with their stored
// value, person-entered values). Instances without a view (template
// missing) are left alone. Runs only after the final Discover of a source
// sync or Init (P9): a rolled-back update drops nothing. Returns the
// audits to write once mu is released. Caller holds mu (write).
func (h *Hub) pruneSettingsLocked() (audits []func()) {
	for _, id := range slices.Sorted(maps.Keys(h.st.Settings)) {
		t := h.findLocked(id)
		if t == nil {
			continue
		}
		s := h.st.Settings[id].Clone()
		changed := false
		drop := func(key, why string) {
			changed = true
			delete(s.Types, key)
			log.Printf("settings: %s: stored %s dropped: %s", id, key, why)
			target, detail := id+"/"+key, why
			audits = append(audits, func() { h.auditOp(purgeActor, "settings.purge", target, detail, nil) })
		}
		for _, k := range slices.Sorted(maps.Keys(s.Values)) {
			o := optionByKey(t, k)
			why := staleKey(t, k, templates.ScopeInstance, s.Types[k])
			if why == "" && o.Type == templates.TypeSecret {
				why = "the option is now a secret"
			}
			if why != "" {
				delete(s.Values, k)
				drop(k, why)
			}
		}
		for _, k := range slices.Sorted(maps.Keys(s.Person)) {
			if why := staleKey(t, k, templates.ScopePerson, s.Types[k]); why != "" {
				delete(s.Person, k)
				drop(k, why)
			}
		}
		for _, k := range slices.Sorted(maps.Keys(s.Groups)) {
			if why := staleKey(t, k, templates.ScopeGroup, s.Types[k]); why != "" {
				delete(s.Groups, k)
				drop(k, why)
			}
		}
		var secretGone []string
		for _, k := range slices.Sorted(maps.Keys(s.Secrets)) {
			why := staleKey(t, k, templates.ScopeInstance, "")
			if o := optionByKey(t, k); why == "" && o.Type != templates.TypeSecret {
				why = "the option is no longer a secret"
			}
			if why != "" {
				delete(s.Secrets, k)
				secretGone = append(secretGone, k)
				drop(k, why)
			}
		}
		for _, k := range slices.Sorted(maps.Keys(s.Entered)) {
			why := staleKey(t, k, templates.ScopePersonEntered, s.Types[k])
			if why == "" {
				continue
			}
			for _, u := range slices.Sorted(maps.Keys(s.Entered[k])) {
				target := id + "/" + k + "/" + u
				audits = append(audits, func() { h.auditOp(purgeActor, "settings.person_value", target, "invalidated", nil) })
			}
			delete(s.Entered, k)
			drop(k, why)
		}
		if !changed {
			continue
		}
		if len(secretGone) > 0 {
			if vals, err := h.secretValues(id); err == nil {
				for _, k := range secretGone {
					delete(vals, k)
				}
				if err := h.writeSecrets(id, vals); err != nil {
					log.Printf("settings: %s: removing dropped secrets from the store failed: %v", id, err)
				}
			}
		}
		if len(s.Values) == 0 {
			s.Values = nil
		}
		if len(s.Person) == 0 {
			s.Person = nil
		}
		if len(s.Groups) == 0 {
			s.Groups = nil
		}
		if len(s.Secrets) == 0 {
			s.Secrets = nil
		}
		if len(s.Entered) == 0 {
			s.Entered = nil
		}
		if len(s.Types) == 0 {
			s.Types = nil
		}
		if s.IsZero() {
			delete(h.st.Settings, id)
		} else {
			h.st.Settings[id] = s
		}
	}
	if len(audits) > 0 {
		h.saveLocked()
	}
	return audits
}

// pruneSettings is pruneSettingsLocked, audited after the unlock.
func (h *Hub) pruneSettings() {
	h.mu.Lock()
	audits := h.pruneSettingsLocked()
	h.mu.Unlock()
	for _, a := range audits {
		a()
	}
}

// SettingsIncompatibilities lists what moving instance settings s from
// template version old to new would drop or change (the app-updates
// preview): options removed, retyped or rescoped (their stored values
// are dropped by the prune after the sync), and options that become
// privileged while rows from groups exist (those rows grant nothing
// unless their group can hold privileged values, and the next reconcile
// drops such rows).
func SettingsIncompatibilities(old, new *templates.Template, s state.InstanceSettings) []string {
	var out []string
	check := func(key, scope string) {
		o := optionByKey(new, key)
		prev := optionByKey(old, key)
		typ := s.Types[key]
		if typ == "" && prev != nil {
			typ = prev.Type
		}
		if why := staleKey(new, key, scope, typ); why != "" {
			out = append(out, fmt.Sprintf("setting %s: %s: its stored value is dropped", key, why))
			return
		}
		if o.Privileged && (prev == nil || !prev.Privileged) && len(s.Person[key].Rows) > 0 {
			out = append(out, fmt.Sprintf("setting %s becomes privileged: its rows from groups that can't hold privileged values (rule groups on fields delegates can edit) grant nothing and are dropped", key))
		}
	}
	keys := map[string]string{}
	for k := range s.Values {
		keys[k] = templates.ScopeInstance
	}
	for k := range s.Secrets {
		keys[k] = templates.ScopeInstance
	}
	for k := range s.Person {
		keys[k] = templates.ScopePerson
	}
	for k := range s.Groups {
		keys[k] = templates.ScopeGroup
	}
	for k := range s.Entered {
		keys[k] = templates.ScopePersonEntered
	}
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		check(k, keys[k])
	}
	return out
}

// privilegedGroupsLocked are the groups named in rows of t's privileged
// options (placeholders resolved), sorted: the directory's guarding
// groups for t (call 28). State only. Caller holds mu (read).
func (h *Hub) privilegedGroupsLocked(t *templates.Template) []string {
	set := map[string]bool{}
	for k, p := range h.st.Settings[t.ID].Person {
		o := optionByKey(t, k)
		if o == nil || !o.Privileged {
			continue
		}
		for _, r := range p.Rows {
			if name := placeholderGroup(t, r.Group); name != "" {
				set[name] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
