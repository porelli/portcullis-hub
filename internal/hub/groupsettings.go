package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
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

// groupSnapshotTimeout bounds the directory call before an env write.
const groupSnapshotTimeout = 10 * time.Second

// hasGroupEnv reports a group-scope option of t delivered by env.
func hasGroupEnv(t *templates.Template) bool {
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].EffectiveScope() == templates.ScopeGroup && len(envDeliveries(&opts[i])) > 0 {
			return true
		}
	}
	return false
}

// groupSnapshot is the directory snapshot an env write of instance id
// checks its group records against. Fetched with no lock held (network);
// nil when the instance has no group-scope env delivery (no call) or the
// directory can't be read (logged: no records are delivered).
func (h *Hub) groupSnapshot(id string) *directory.Membership {
	h.mu.RLock()
	t := h.findLocked(id)
	need := t != nil && hasGroupEnv(t)
	h.mu.RUnlock()
	if !need {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), groupSnapshotTimeout)
	defer cancel()
	m, err := h.membership(ctx)
	if err != nil {
		log.Printf("settings: %s: WARNING: directory unavailable (%v): group records are not delivered", id, err)
		return nil
	}
	return m
}

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

// bindRowsForSave binds the rows and records of a save to the
// directory's current group ids, before mu is taken: an unknown group is
// a 400, a placeholder whose group doesn't exist yet stays unbound (a
// warning). A privileged option's rows must come from groups that can
// hold privileged values (400 with the directory's reason) and its
// default must be its lowest-ranked value. Directory unavailable: 503.
func (h *Hub) bindRowsForSave(ctx context.Context, t *templates.Template, parsed *parsedSettings) ([]string, error) {
	if err := privilegedDefaults(t, parsed); err != nil {
		return nil, err
	}
	if rowCount(parsed) == 0 {
		return nil, nil // nothing to bind: no directory needed
	}
	m, err := h.membership(ctx)
	if err != nil {
		return nil, bindDirectoryErr(err)
	}
	return h.bindRowsWith(t, parsed, m)
}

// privilegedDefaults: a privileged option's default must be its
// lowest-ranked value (400).
func privilegedDefaults(t *templates.Template, parsed *parsedSettings) error {
	for _, k := range slices.Sorted(maps.Keys(parsed.person)) {
		if o := optionByKey(t, k); o.Privileged && !reflect.DeepEqual(parsed.person[k].Default, lowestValue(o)) {
			return statusErr(400, "setting %s: a privileged option's default must be its lowest-ranked value %v", k, lowestValue(o))
		}
	}
	return nil
}

// rowCount is the number of rows and records parsed carries.
func rowCount(parsed *parsedSettings) int {
	n := 0
	for _, p := range parsed.person {
		n += len(p.Rows)
	}
	for _, recs := range parsed.groups {
		n += len(recs)
	}
	return n
}

// bindDirectoryErr is the error of a save or preview whose rows can't be
// bound: the directory's status (503 by default).
func bindDirectoryErr(err error) error {
	status := 503
	var se *StatusError
	if errors.As(err, &se) {
		status = se.Status
	}
	return &StatusError{Status: status, Err: fmt.Errorf("per-person and per-group values need the directory to bind their groups (nothing was saved): %w", err)}
}

// bindRowsWith is bindRowsForSave against the snapshot m (no lock held).
func (h *Hub) bindRowsWith(t *templates.Template, parsed *parsedSettings, m *directory.Membership) ([]string, error) {
	var warnings []string
	bind := func(o *templates.Option, rows []state.GroupValue) error {
		seen := map[string]string{}
		for i := range rows {
			r := &rows[i]
			name := placeholderGroup(t, r.Group)
			if name == "" {
				return statusErr(400, "setting %s: %s: the template has no such group", o.Key, r.Group)
			}
			// {{ADMIN_GROUP}} and admin_<id> are one group: one row.
			if prev, dup := seen[strings.ToLower(name)]; dup {
				return statusErr(400, "setting %s: %s and %s are the same group %s (one value per group)", o.Key, prev, r.Group, name)
			}
			seen[strings.ToLower(name)] = r.Group
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
			// The snapshot's PrivilegeProblem answer (Membership.Privilege).
			if why := m.Privilege[name]; o.Privileged && why != "" {
				return statusErr(400, "setting %s: group %s can't grant a privileged value: %s", o.Key, name, why)
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

// staleRebind refuses (409) a save whose row or record for a group was
// stored against another id of that group than the one it was just
// bound to: the group was deleted and re-created since, and its old
// value must not pass to the new group just because the panel resent the
// row (call 29). The admin removes the row and adds it again. Checked
// under mu against the stored state.
//
// The panel also sends back the id each row was shown with
// (parsed.sentIDs): a row sent with an id must still be stored with that
// id — a row purged since (its group deleted, perhaps re-created) or
// bound to another id is the same 409. A row sent without an id is a
// new row.
func staleRebind(cur state.InstanceSettings, parsed *parsedSettings) error {
	check := func(key string, stored, sent []state.GroupValue) error {
		old := map[string]int{}
		folded := map[string]int{}
		for _, r := range stored {
			old[r.Group] = r.GroupID
			folded[strings.ToLower(r.Group)] = r.GroupID
		}
		for _, r := range sent {
			if id := old[r.Group]; id != 0 && r.GroupID != 0 && id != r.GroupID {
				return statusErr(409, "setting %s: group %s was re-created since its row was saved; remove the row and add it again", key, r.Group)
			}
			want, sentID := parsed.sentIDs[key][strings.ToLower(r.Group)]
			if !sentID {
				continue
			}
			if have, ok := folded[strings.ToLower(r.Group)]; !ok || have != want {
				return statusErr(409, "setting %s: group %s was re-created since its row was saved; remove the row and add it again", key, r.Group)
			}
		}
		return nil
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.person)) {
		if err := check(k, cur.Person[k].Rows, parsed.person[k].Rows); err != nil {
			return err
		}
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.groups)) {
		if err := check(k, cur.Groups[k], parsed.groups[k]); err != nil {
			return err
		}
	}
	return nil
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

// groupRecordsOut are a group option's records as delivered: the
// group's name (placeholders resolved) and the canonical value, in the
// admin's order — only records whose group id equals the group's id in
// the directory snapshot m (a group deleted and re-created outside the
// Hub gets nothing, before any reconcile). No snapshot (m nil: the
// directory unavailable): no records at all, logged (fail closed).
// Unbound records and values that no longer parse (logged) are left out.
// Caller holds mu (read).
func (h *Hub) groupRecordsOut(t *templates.Template, o *templates.Option, recs []state.GroupValue, m *directory.Membership) []settings.Row {
	out := []settings.Row{}
	if len(recs) == 0 {
		return out
	}
	if m == nil {
		log.Printf("settings: %s: %s: no directory snapshot: its group records are not delivered", t.ID, o.Key)
		return out
	}
	for _, r := range recs {
		name := placeholderGroup(t, r.Group)
		if name == "" || r.GroupID == 0 {
			continue
		}
		if mg, ok := m.Groups[name]; !ok || mg.ID != r.GroupID {
			log.Printf("settings: %s: %s: the record for %s doesn't match the directory (group gone or re-created): not delivered", t.ID, o.Key, name)
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
		env, err := renderGroupEnvDelivery(o, recs, &d)
		if err != nil {
			return nil, err
		}
		maps.Copy(out, env)
	}
	return out, nil
}

// renderGroupEnvDelivery is renderGroupEnv for one env delivery d.
func renderGroupEnvDelivery(o *templates.Option, recs []settings.Row, d *templates.Delivery) (map[string]string, error) {
	items := make([]map[string]any, 0, len(recs))
	for _, r := range recs {
		rd, err := settings.Render(o, r.Value, settings.RenderOf(d))
		if err != nil {
			return nil, fmt.Errorf("env %s: group %s: %w", d.Env, r.Group, err)
		}
		items = append(items, map[string]any{"group": r.Group, "value": rd.JSON})
	}
	text, err := settings.JSONText(items)
	if err != nil {
		return nil, err
	}
	if err := settings.CheckEnvText(text, true); err != nil {
		return nil, fmt.Errorf("env %s: %w", d.Env, err)
	}
	return map[string]string{d.Env: text}, nil
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

// reseedPlaceholderRows puts back instance id's template-declared
// placeholder rows (group_values) whose group was just created by
// "create missing groups" or an enable (created), when their row is
// missing — it was purged with the deleted group. Unbound (id 0):
// bindPlaceholderRows binds them to the new group. Rows an admin entered
// are never re-created, and nothing comes back for a group that already
// existed (the admin may have removed the row). Never call it holding mu.
func (h *Hub) reseedPlaceholderRows(id string, created []string) {
	if len(created) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.findLocked(id)
	if t == nil {
		return
	}
	s := h.st.Settings[id].Clone()
	changed := false
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		p, ok := s.Person[o.Key]
		if o.EffectiveScope() != templates.ScopePerson || !ok {
			continue
		}
		for _, ph := range seedPlaceholders {
			raw, declared := o.GroupValues[ph]
			name := placeholderGroup(t, ph)
			if !declared || name == "" || !slices.Contains(created, name) {
				continue
			}
			present := false
			for _, r := range p.Rows {
				present = present || r.Group == ph || strings.EqualFold(placeholderGroup(t, r.Group), name)
			}
			if present {
				continue
			}
			v, err := h.kinds.Parse(o, raw)
			if err != nil {
				continue
			}
			p.Rows = append(p.Rows, state.GroupValue{Group: ph, Value: storedValue(v)})
			changed = true
			log.Printf("settings: %s: %s: the template's row for %s (%s) is back, for the re-created group", id, o.Key, ph, name)
		}
		s.Person[o.Key] = p
	}
	if changed {
		h.st.Settings[id] = s
		h.saveLocked()
	}
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
// names group name (exactly, or in another case when bound to id) in
// every instance, after the directory
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
		ps := h.dropRowsLocked(inst, h.findLocked(inst), func(_, g string, r state.GroupValue) string {
			// The exact name; another case only when bound to this id
			// (two LLDAP groups may differ in case only).
			if g == name || strings.EqualFold(g, name) && r.GroupID == id {
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
	// The sweep's state under its lock; the LLDAP check outside it (a
	// sweep holds the lock across Keycloak).
	s.mu.Lock()
	st := s.load()
	s.mu.Unlock()
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
//
// Only rows that were stored, exactly so, before the snapshot was taken
// can be purged: a row bound or re-seeded meanwhile (CreateMissingGroups
// re-creating its group, a save) was checked against a newer directory
// than this snapshot, so it is left for the next run to judge.
func (h *Hub) reconcileGroupRows(ctx context.Context, id string) []string {
	h.mu.RLock()
	before := storedRowKeys(h.st.Settings[id])
	h.mu.RUnlock()
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
		if !before[rowKey(key, r)] {
			return "" // stored after the snapshot: the next run judges it
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

// rowKey identifies a stored row or record (option, group as stored, id).
func rowKey(key string, r state.GroupValue) string {
	return key + "\x00" + r.Group + "\x00" + strconv.Itoa(r.GroupID)
}

// storedRowKeys are the keys of s's rows and records.
func storedRowKeys(s state.InstanceSettings) map[string]bool {
	out := map[string]bool{}
	for k, p := range s.Person {
		for _, r := range p.Rows {
			out[rowKey(k, r)] = true
		}
	}
	for k, recs := range s.Groups {
		for _, r := range recs {
			out[rowKey(k, r)] = true
		}
	}
	return out
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
	case hubSetOption(o):
		// person_secret / person_id: no stored admin value (F5).
		return "the option's values are set by the Hub"
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
		// Values that no longer pass tightened constraints, and later
		// duplicates of a newly unique option (call 32).
		if more := h.pruneEntriesLocked(id, t, &s); len(more) > 0 {
			changed = true
			audits = append(audits, more...)
		}
		if !changed {
			continue
		}
		if len(secretGone) > 0 {
			h.dropStoredSecretsLocked(id, secretGone)
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

// dropStoredSecretsLocked removes the dropped secrets keys from instance
// id's store — after blanking every .env variable holding one of their
// values (the line a removed or renamed delivery left behind): once out
// of the store, nothing would recognise the value in Expert Env or a
// backup's config/env. The .env not rewritable: the values stay in the
// store (still masked and blanked by value). Caller holds mu.
func (h *Hub) dropStoredSecretsLocked(id string, keys []string) {
	vals, err := h.secretValues(id)
	if err != nil {
		log.Printf("settings: %s: removing dropped secrets from the store failed: %v", id, err)
		return
	}
	gone := map[string]string{}
	for _, k := range keys {
		if v, ok := vals[k]; ok {
			gone[k] = v
		}
	}
	if len(gone) == 0 {
		return
	}
	path := h.envPath(id)
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		log.Printf("settings: %s: the .env is unreadable (%v): the dropped secrets stay in the store", id, err)
		return
	default:
		if b := blankEnvNames(data, nil, gone); !bytes.Equal(b, data) {
			if err := fsutil.WriteFileAtomic(path, b, 0600); err != nil {
				log.Printf("settings: %s: blanking the dropped secrets in the .env failed (%v): they stay in the store", id, err)
				return
			}
		}
	}
	for k := range gone {
		delete(vals, k)
	}
	if err := h.writeSecrets(id, vals); err != nil {
		log.Printf("settings: %s: removing dropped secrets from the store failed: %v", id, err)
	}
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
		if scope == templates.ScopePersonEntered {
			out = append(out, entryIncompatibilities(o, s.Entered[key])...)
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
