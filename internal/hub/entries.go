package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Person-entered values (spec call 32, contract §13.13, Task 15A): an
// option with scope person_entered is given by each person on My apps
// (people listener), not by an admin. Values live in state.yaml under
// InstanceSettings.Entered: key → lowercase user → {value, uuid,
// updated_at, set_by}.
//
//   - Who may enter, and whose values are delivered: entryPopulationLocked
//     (call 27's population when the routes carry Portcullis identity,
//     else the template's access group minus expired entries).
//   - A value is delivered only while its holder is in that population
//     AND their LLDAP uuid equals the stored one: leaving keeps it stored,
//     not delivered; an account re-created under the same name inherits
//     nothing, and the next delivery purges the old value (only while the
//     user sweep's LDAP sanity check passes: P22).
//   - unique: checked under mu at save against every stored value of the
//     option in the instance, delivered or not; the 409 never names the
//     holder (the admin-only audit does).
//   - A change goes the membership path: TriggerDelivery(id,
//     TriggerMembership, false) — debounced, one restart for many saves.
//   - Audited settings.person_value (target <instance>/<key>/<user>),
//     always after mu is released (P26).

// Why a stored value isn't delivered (EntryRow.Why).
const (
	EntryWhyNoAccess       = "no access"
	EntryWhyAccountChanged = "account changed"
)

// EntryBodyMax bounds a person-entered value's request body (both
// listeners).
const EntryBodyMax = 4 << 10

// errNoEntry is the one answer for an instance that isn't enabled, a key
// that isn't a person_entered option and a person outside its population
// (nothing leaks which).
var errNoEntry = &StatusError{Status: 404, Err: errors.New("not found: no such app or value for this account")}

// errEntryDirectory: the population can't be checked.
func errEntryDirectory(err error) error {
	status := 503
	var se *StatusError
	if errors.As(err, &se) && se.Status >= 500 {
		status = se.Status
	}
	return &StatusError{Status: status, Err: errors.New("users & groups is not available: the value can't be checked now")}
}

// entryOptions are t's person_entered options.
func entryOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].EffectiveScope() == templates.ScopePersonEntered {
			out = append(out, &opts[i])
		}
	}
	return out
}

// entryOption is t's person_entered option key (nil: none).
func entryOption(t *templates.Template, key string) *templates.Option {
	if o := optionByKey(t, key); o != nil && o.EffectiveScope() == templates.ScopePersonEntered {
		return o
	}
	return nil
}

// entryPopulationLocked is who may enter t's person-entered values and
// whose are delivered: the population (call 27) when t's routes carry
// Portcullis identity; otherwise (method public, custom without
// Portcullis sign-in, sign_in native) the members of the instance's
// access group minus expired-but-not-removed entries. Caller holds mu
// (read).
func (h *Hub) entryPopulationLocked(t *templates.Template, m *directory.Membership) Population {
	if h.populationWhyLocked(t) == "" {
		return h.populationLocked(t, m)
	}
	g := t.NamesFor(t.ID).AccessGroup
	if g == "" {
		// The validator refuses this (fail closed: nobody).
		return Population{Why: WhyNoIdentity}
	}
	mg, ok := m.Groups[g]
	if !ok {
		return Population{Why: WhyNoAccess}
	}
	var users []string
	for _, u := range mg.Members {
		if _, isUser := m.Users[u]; isUser && !m.Expired[u][g] {
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

func inPopulation(p Population, user string) bool {
	for _, x := range p.People {
		if x.User == user {
			return true
		}
	}
	return false
}

// entryValues are the stored values of o that still fit it: user →
// canonical value. invalid: users whose value no longer parses (or whose
// stored type differs); dupes: under unique, every holder of a value but
// the earliest (updated_at, then name). Sorted.
func entryValues(kinds *settings.Registry, o *templates.Option, stored map[string]state.EnteredValue, storedType string) (keep map[string]settings.Value, invalid, dupes []string) {
	keep = map[string]settings.Value{}
	users := slices.Sorted(maps.Keys(stored))
	if storedType != "" && storedType != o.Type {
		return keep, users, nil
	}
	for _, u := range users {
		v, err := kinds.Parse(o, stored[u].Value)
		if err != nil {
			invalid = append(invalid, u)
			continue
		}
		keep[u] = v
	}
	if !o.Unique {
		return keep, invalid, nil
	}
	holders := map[string][]string{}
	for _, u := range users {
		if v, ok := keep[u]; ok {
			k := entryKey(v)
			holders[k] = append(holders[k], u)
		}
	}
	for _, us := range holders {
		if len(us) < 2 {
			continue
		}
		sort.SliceStable(us, func(i, j int) bool {
			a, b := stored[us[i]].UpdatedAt, stored[us[j]].UpdatedAt
			if !a.Equal(b) {
				return a.Before(b)
			}
			return us[i] < us[j]
		})
		for _, u := range us[1:] {
			delete(keep, u)
			dupes = append(dupes, u)
		}
	}
	sort.Strings(dupes)
	return keep, invalid, dupes
}

// entryKey is a canonical value's identity for uniqueness (exact, typed).
func entryKey(v settings.Value) string { return fmt.Sprintf("%T:%v", v, v) }

// deliveredEntriesLocked are the delivered values of t's person-entered
// option key: population members whose stored uuid equals their LLDAP
// uuid now (uuids: Membership.UUIDs), sorted by user, values canonical
// (each delivery renders them). Caller holds mu (read).
func (h *Hub) deliveredEntriesLocked(t *templates.Template, key string, pop Population, uuids map[string]string) []settings.EntryOut {
	out := []settings.EntryOut{}
	o := entryOption(t, key)
	if o == nil || uuids == nil {
		return out
	}
	s := h.st.Settings[t.ID]
	keep, _, _ := entryValues(h.kinds, o, s.Entered[key], s.Types[key])
	for _, p := range pop.People {
		e, ok := s.Entered[key][p.User]
		v, valid := keep[p.User]
		if !ok || !valid || e.UUID == "" || uuids[p.User] != e.UUID {
			continue
		}
		out = append(out, settings.EntryOut{User: p.User, Value: v})
	}
	return out
}

// peopleWithEntriesLocked is resolvePeopleLocked plus each person's own
// delivered person-entered values (as resolved values, for the claims and
// headers: their own value only, never anyone else's). m nil: none.
// Caller holds mu (read).
func (h *Hub) peopleWithEntriesLocked(t *templates.Template, m *directory.Membership) map[string]map[string]settings.Resolved {
	out := h.resolvePeopleLocked(t, m)
	opts := entryOptions(t)
	if len(opts) == 0 || m == nil {
		return out
	}
	pop := h.entryPopulationLocked(t, m)
	for _, o := range opts {
		for _, e := range h.deliveredEntriesLocked(t, o.Key, pop, m.UUIDs) {
			if out[e.User] == nil {
				out[e.User] = map[string]settings.Resolved{}
			}
			out[e.User][o.Key] = settings.Resolved{Value: e.Value}
		}
	}
	return out
}

// hasEntryEnv: t delivers a person-entered option through env.
func hasEntryEnv(t *templates.Template) bool {
	for _, o := range entryOptions(t) {
		if len(envDeliveries(o)) > 0 {
			return true
		}
	}
	return false
}

// entryEnvLocked are t's person-entered env variables: the delivered
// values (population, uuid matched) in user order, each rendered as one
// env item, then joined (render.join) or a JSON list (render.format:
// json). No usernames. An item the env can't carry (a ', a newline, the
// separator) is left out and logged. Caller holds mu (read).
func (h *Hub) entryEnvLocked(t *templates.Template, m *directory.Membership) map[string]string {
	out := map[string]string{}
	pop := h.entryPopulationLocked(t, m)
	for _, o := range entryOptions(t) {
		ds := envDeliveries(o)
		if len(ds) == 0 {
			continue
		}
		entries := h.deliveredEntriesLocked(t, o.Key, pop, m.UUIDs)
		for _, d := range ds {
			text, err := renderEntryList(o, d, entries)
			if err != nil {
				log.Printf("settings: %s: %s: %v", t.ID, o.Key, err)
			}
			out[d.Env] = text
		}
	}
	return out
}

// renderEntryList renders entries for env delivery d (items that don't
// fit are left out; err reports them, without a value).
func renderEntryList(o *templates.Option, d templates.Delivery, entries []settings.EntryOut) (string, error) {
	rd := templates.Render{}
	if d.Render != nil {
		rd = *d.Render
	}
	item := d
	itemRender := rd
	itemRender.Join, itemRender.Format = nil, ""
	item.Render = &itemRender
	sep := ","
	if rd.Join != nil {
		sep = *rd.Join
	}
	var texts []string
	var jsons []any
	var left []string
	for _, e := range entries {
		r, err := settings.RenderDelivery(o, e.Value, &item)
		if err == nil {
			_, err = envQuote(r.Text)
		}
		if err == nil && rd.Format != templates.RenderJSON && strings.Contains(r.Text, sep) {
			err = fmt.Errorf("contains the separator")
		}
		if err != nil {
			left = append(left, e.User)
			continue
		}
		texts = append(texts, r.Text)
		jsons = append(jsons, r.JSON)
	}
	var out string
	if rd.Format == templates.RenderJSON {
		if jsons == nil {
			jsons = []any{}
		}
		b, err := json.Marshal(jsons)
		if err != nil {
			return "", err
		}
		out = string(b)
		if _, err := envQuote(out); err != nil {
			return "", fmt.Errorf("env %s: the list can't be written to the env", d.Env)
		}
	} else {
		out = strings.Join(texts, sep)
	}
	if len(left) > 0 {
		return out, fmt.Errorf("env %s: the values of %s can't be delivered through the env: left out", d.Env, strings.Join(left, ", "))
	}
	return out, nil
}

// entryInput is o's input description for My apps.
func entryInput(o *templates.Option) EntryInput {
	return EntryInput{Type: o.Type, Pattern: o.Pattern, Format: o.Format, MinLen: o.MinLen, MaxLen: o.MaxLen,
		Min: o.Min, Max: o.Max, Unit: o.Unit, Choices: o.Choices}
}

// myEntryLocked is the caller's entry of o: their value when it is
// stored under their current uuid (uuid: Membership.UUIDs[user]) and
// still fits o; else not set. Caller holds mu (read).
func (h *Hub) myEntryLocked(t *templates.Template, o *templates.Option, user, uuid string) MyEntry {
	me := MyEntry{Key: o.Key, Label: o.Label, Description: o.Description, Applies: o.EffectiveApplies(), Input: entryInput(o), Unique: o.Unique}
	s := h.st.Settings[t.ID]
	e, ok := s.Entered[o.Key][user]
	if !ok || e.UUID == "" || e.UUID != uuid || !h.typeMatchesLocked(t, o.Key, o) {
		return me
	}
	v, err := h.kinds.Parse(o, e.Value)
	if err != nil {
		return me
	}
	at := e.UpdatedAt
	me.Value, me.Display, me.SetByAdmin, me.UpdatedAt = storedValue(v), h.kinds.Display(o, v), e.SetBy != "", &at
	return me
}

// entryRowLocked is stored value e of user as the admin panel shows it
// (m nil: the directory unavailable, delivery unknown). Caller holds mu.
func (h *Hub) entryRowLocked(o *templates.Option, user string, e state.EnteredValue, valid bool, pop *Population, m *directory.Membership) EntryRow {
	r := EntryRow{User: user, Value: e.Value, UpdatedAt: e.UpdatedAt, SetBy: e.SetBy}
	if r.SetBy == "" {
		r.SetBy = user
	}
	if v, err := h.kinds.Parse(o, e.Value); err == nil {
		r.Display = h.kinds.Display(o, v)
	} else {
		r.Display = fmt.Sprint(e.Value)
	}
	switch {
	case m == nil || pop == nil:
	case !inPopulation(*pop, user):
		r.Why = EntryWhyNoAccess
	case e.UUID == "" || m.UUIDs[user] != e.UUID:
		r.Why = EntryWhyAccountChanged
	case !valid:
		r.Why = "no longer valid"
	default:
		r.Delivered = true
	}
	return r
}

// entriesViewLocked is t's person-entered options' panel view: every
// stored value (sorted by user) with delivered / why, and the population
// members without one. Caller holds mu (read).
func (h *Hub) entriesViewLocked(t *templates.Template, m *directory.Membership) map[string]EntriesView {
	out := map[string]EntriesView{}
	var pop *Population
	if m != nil {
		p := h.entryPopulationLocked(t, m)
		pop = &p
	}
	s := h.st.Settings[t.ID]
	for _, o := range entryOptions(t) {
		v := EntriesView{Rows: []EntryRow{}, NotSet: []string{}}
		stored := s.Entered[o.Key]
		if !h.typeMatchesLocked(t, o.Key, o) {
			stored = nil
		}
		keep, _, _ := entryValues(h.kinds, o, stored, "")
		for _, u := range slices.Sorted(maps.Keys(stored)) {
			_, valid := keep[u]
			v.Rows = append(v.Rows, h.entryRowLocked(o, u, stored[u], valid, pop, m))
		}
		if pop != nil {
			for _, p := range pop.People {
				if _, ok := stored[p.User]; !ok {
					v.NotSet = append(v.NotSet, p.User)
				}
			}
		}
		out[o.Key] = v
	}
	return out
}

// SetPersonValue stores user's value of instance's person-entered option
// key (raw: one JSON value). actor == user: self-service; else an admin
// (the option needs admin_override). Order: the directory snapshot
// outside mu (503); under mu the instance enabled, key a person_entered
// option and user in its population (else the one 404); an admin without
// admin_override 403; the value parsed (400 naming the constraint);
// unique against every other stored value (409, never naming the
// holder); stored with the uuid; audited after mu; then the debounced
// membership delivery. An unchanged value stores and audits nothing.
func (h *Hub) SetPersonValue(ctx context.Context, instance, key, user string, raw json.RawMessage, actor string) (*MyEntry, error) {
	me, _, err := h.setEntry(ctx, instance, key, user, raw, actor, !strings.EqualFold(actor, user))
	return me, err
}

// SetEntryAsAdmin is SetPersonValue by an admin on the Hub listener
// (always the admin path: admin_override needed), answering the panel's
// row.
func (h *Hub) SetEntryAsAdmin(ctx context.Context, instance, key, user string, raw json.RawMessage, actor string) (*EntryRow, error) {
	_, row, err := h.setEntry(ctx, instance, key, user, raw, actor, true)
	return row, err
}

func (h *Hub) setEntry(ctx context.Context, instance, key, user string, raw json.RawMessage, actor string, admin bool) (*MyEntry, *EntryRow, error) {
	user, actor = strings.ToLower(user), strings.ToLower(actor)
	target := instance + "/" + key + "/" + user
	m, err := h.membership(ctx)
	if err != nil {
		return nil, nil, errEntryDirectory(err)
	}
	refuse := func(err error, detail string) (*MyEntry, *EntryRow, error) {
		h.auditOp(actor, "settings.person_value", target, detail, err)
		return nil, nil, err
	}
	h.mu.Lock()
	t := h.findLocked(instance)
	var o *templates.Option
	if t != nil {
		o = entryOption(t, key)
	}
	if t == nil || o == nil || !h.st.IsEnabled(instance) {
		h.mu.Unlock()
		return nil, nil, errNoEntry
	}
	pop := h.entryPopulationLocked(t, m)
	if !inPopulation(pop, user) {
		h.mu.Unlock()
		return nil, nil, errNoEntry
	}
	if err := h.pendingLocked(instance); err != nil {
		h.mu.Unlock()
		return nil, nil, err
	}
	if admin && !o.AdminOverride {
		h.mu.Unlock()
		return refuse(statusErr(403, "setting %s: admins can't set this value (the template has no admin_override); an admin can clear it", key), "refused")
	}
	v, perr := decodeRaw(raw)
	if perr == nil && v == nil {
		perr = errors.New("a value is required (clear it to remove it)")
	}
	if perr == nil {
		v, perr = h.kinds.Parse(o, v)
	}
	if perr == nil {
		perr = entryDeliverable(o, v)
	}
	if perr != nil {
		h.mu.Unlock()
		return refuse(statusErr(400, "%s: %v", o.Label, perr), "refused")
	}
	s := h.st.Settings[instance].Clone()
	if !h.typeMatchesLocked(t, key, o) {
		delete(s.Entered, key) // a retyped option's leftovers (prune drops them)
	}
	keep, _, _ := entryValues(h.kinds, o, s.Entered[key], "")
	if o.Unique {
		for _, u := range slices.Sorted(maps.Keys(s.Entered[key])) {
			if u == user {
				continue
			}
			if other, ok := keep[u]; ok && entryKey(other) == entryKey(v) {
				h.mu.Unlock()
				return refuse(statusErr(409, "%s: this value is already registered for %s by another person", o.Label, instanceName(t)),
					"refused: "+h.kinds.Display(o, v)+" is held by "+u)
			}
		}
	}
	uuid := m.UUIDs[user]
	prev, had := s.Entered[key][user]
	before := "unset"
	if pv, ok := keep[user]; ok && had {
		before = h.kinds.Display(o, pv)
		if entryKey(pv) == entryKey(v) && prev.UUID == uuid && prev.UUID != "" {
			me := h.myEntryLocked(t, o, user, uuid)
			row := h.entryRowLocked(o, user, prev, true, &pop, m)
			h.mu.Unlock()
			return &me, &row, nil
		}
	}
	setBy := ""
	if admin {
		setBy = actor
	}
	ev := state.EnteredValue{Value: storedValue(v), UUID: uuid, UpdatedAt: time.Now().UTC(), SetBy: setBy}
	if s.Entered == nil {
		s.Entered = map[string]map[string]state.EnteredValue{}
	}
	if s.Entered[key] == nil {
		s.Entered[key] = map[string]state.EnteredValue{}
	}
	s.Entered[key][user] = ev
	if s.Types == nil {
		s.Types = map[string]string{}
	}
	s.Types[key] = o.Type
	old, hadSettings := h.st.Settings[instance]
	h.st.Settings[instance] = s
	if err := h.st.Save(h.statePath()); err != nil {
		if hadSettings {
			h.st.Settings[instance] = old
		} else {
			delete(h.st.Settings, instance)
		}
		h.mu.Unlock()
		return refuse(statusErr(500, "saving the value failed: %v", err), "set: "+before+" -> "+h.kinds.Display(o, v))
	}
	me := h.myEntryLocked(t, o, user, uuid)
	row := h.entryRowLocked(o, user, ev, true, &pop, m)
	h.mu.Unlock()
	h.auditOp(actor, "settings.person_value", target, "set: "+before+" -> "+h.kinds.Display(o, v), nil)
	h.TriggerDelivery(instance, TriggerMembership, false)
	return &me, &row, nil
}

// entryDeliverable refuses a value o's deliveries can't take: an env
// item with a ' or a newline or the list's separator (it would be left
// out of the list), a header or claim it can't render.
func entryDeliverable(o *templates.Option, v settings.Value) error {
	for _, d := range o.Delivery {
		switch {
		case d.Env != "":
			rd := templates.Render{}
			if d.Render != nil {
				rd = *d.Render
			}
			item := d
			ir := rd
			ir.Join, ir.Format = nil, ""
			item.Render = &ir
			r, err := settings.RenderDelivery(o, v, &item)
			if err != nil {
				return err
			}
			if _, err := envQuote(r.Text); err != nil {
				return err
			}
			if rd.Join != nil && strings.Contains(r.Text, *rd.Join) {
				return fmt.Errorf("must not contain %q", *rd.Join)
			}
		case d.Header != nil, d.Claim != nil:
			if _, err := settings.RenderDelivery(o, v, &d); err != nil {
				return err
			}
		}
	}
	return nil
}

// ClearPersonValue removes user's value of instance's person-entered
// option key; nothing stored is no error. actor == user: self-service
// (the population check as for a save; the directory down 503); else an
// admin, who can always clear (any instance state, any person). Audited
// "cleared"; then the debounced membership delivery.
func (h *Hub) ClearPersonValue(ctx context.Context, instance, key, user, actor string) error {
	return h.clearEntry(ctx, instance, key, user, actor, !strings.EqualFold(actor, user))
}

// ClearEntryAsAdmin is ClearPersonValue by an admin on the Hub listener
// (always the admin path).
func (h *Hub) ClearEntryAsAdmin(ctx context.Context, instance, key, user, actor string) error {
	return h.clearEntry(ctx, instance, key, user, actor, true)
}

func (h *Hub) clearEntry(ctx context.Context, instance, key, user, actor string, admin bool) error {
	user, actor = strings.ToLower(user), strings.ToLower(actor)
	var m *directory.Membership
	if !admin {
		var err error
		if m, err = h.membership(ctx); err != nil {
			return errEntryDirectory(err)
		}
	}
	h.mu.Lock()
	t := h.findLocked(instance)
	if t == nil || entryOption(t, key) == nil || (!admin && (!h.st.IsEnabled(instance) || !inPopulation(h.entryPopulationLocked(t, m), user))) {
		h.mu.Unlock()
		return errNoEntry
	}
	if err := h.pendingLocked(instance); err != nil {
		h.mu.Unlock()
		return err
	}
	cur := h.st.Settings[instance]
	if _, ok := cur.Entered[key][user]; !ok {
		h.mu.Unlock()
		return nil
	}
	s := cur.Clone()
	dropEntry(&s, key, user)
	h.st.Settings[instance] = s
	if err := h.st.Save(h.statePath()); err != nil {
		h.st.Settings[instance] = cur
		h.mu.Unlock()
		err = statusErr(500, "saving failed: %v", err)
		h.auditOp(actor, "settings.person_value", instance+"/"+key+"/"+user, "cleared", err)
		return err
	}
	h.mu.Unlock()
	h.auditOp(actor, "settings.person_value", instance+"/"+key+"/"+user, "cleared", nil)
	h.TriggerDelivery(instance, TriggerMembership, false)
	return nil
}

// dropEntry deletes s's value of key for user (empty maps removed).
func dropEntry(s *state.InstanceSettings, key, user string) {
	delete(s.Entered[key], user)
	if len(s.Entered[key]) == 0 {
		delete(s.Entered, key)
		delete(s.Types, key)
	}
	if len(s.Entered) == 0 {
		s.Entered = nil
	}
	if len(s.Types) == 0 {
		s.Types = nil
	}
}

// PurgePersonValues deletes user's person-entered values in every
// instance (the directory's UserDeleted: the account was deleted in
// LLDAP through the Hub). Audited "deleted" by the admin (actor), after
// mu; the affected instances' deliveries are triggered (background:
// never inline). Never holds mu across a network call.
func (h *Hub) PurgePersonValues(ctx context.Context, actor, user string) []string {
	user = strings.ToLower(user)
	h.mu.Lock()
	var targets []string
	affected := map[string]bool{}
	for _, inst := range slices.Sorted(maps.Keys(h.st.Settings)) {
		cur := h.st.Settings[inst]
		var keys []string
		for _, k := range slices.Sorted(maps.Keys(cur.Entered)) {
			if _, ok := cur.Entered[k][user]; ok {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			continue
		}
		s := cur.Clone()
		for _, k := range keys {
			dropEntry(&s, k, user)
			targets = append(targets, inst+"/"+k+"/"+user)
		}
		if s.IsZero() {
			delete(h.st.Settings, inst)
		} else {
			h.st.Settings[inst] = s
		}
		affected[inst] = true
	}
	var warnings []string
	if len(targets) > 0 {
		if err := h.st.Save(h.statePath()); err != nil {
			warnings = append(warnings, fmt.Sprintf("removing the app values %s entered: saving state failed: %v", user, err))
		}
	}
	h.mu.Unlock()
	for _, t := range targets {
		h.auditOp(actor, "settings.person_value", t, "deleted", nil)
	}
	for _, inst := range slices.Sorted(maps.Keys(affected)) {
		h.TriggerDelivery(inst, TriggerMembership, true)
	}
	return warnings
}

// enteredCopy is a copy of the stored values (the purge's "before").
func enteredCopy(e map[string]map[string]state.EnteredValue) map[string]map[string]state.EnteredValue {
	if len(e) == 0 {
		return nil
	}
	out := make(map[string]map[string]state.EnteredValue, len(e))
	for k, m := range e {
		out[k] = maps.Clone(m)
	}
	return out
}

// purgeStaleEntries purges instance id's stored values whose holder is
// gone from LLDAP or has another uuid in snapshot m (deleted outside the
// Hub, or re-created): only values stored exactly so before the snapshot
// was taken (before), only while the user sweep's LDAP sanity check
// passes (P22: an empty or partial LLDAP must never wipe them — then the
// delivery only filters). Audited "purged" by hub after mu. Never holds
// mu across a network call.
func (h *Hub) purgeStaleEntries(ctx context.Context, id string, m *directory.Membership, before map[string]map[string]state.EnteredValue) {
	if m == nil || m.UUIDs == nil || len(before) == 0 {
		return
	}
	type cand struct{ key, user string }
	var cands []cand
	for _, k := range slices.Sorted(maps.Keys(before)) {
		for _, u := range slices.Sorted(maps.Keys(before[k])) {
			if e := before[k][u]; m.UUIDs[u] == "" || m.UUIDs[u] != e.UUID {
				cands = append(cands, cand{k, u})
			}
		}
	}
	if len(cands) == 0 {
		return
	}
	if problem := h.ldapSane(ctx); problem != "" {
		log.Printf("settings: %s: WARNING: values of changed or deleted accounts are not purged (they are not delivered): %s", id, problem)
		return
	}
	h.mu.Lock()
	cur, ok := h.st.Settings[id]
	if !ok {
		h.mu.Unlock()
		return
	}
	s := cur.Clone()
	var targets []string
	for _, c := range cands {
		now, ok := s.Entered[c.key][c.user]
		was := before[c.key][c.user]
		if !ok || now.UUID != was.UUID || !now.UpdatedAt.Equal(was.UpdatedAt) {
			continue // changed since the snapshot: the next run judges it
		}
		dropEntry(&s, c.key, c.user)
		targets = append(targets, id+"/"+c.key+"/"+c.user)
	}
	if len(targets) > 0 {
		if s.IsZero() {
			delete(h.st.Settings, id)
		} else {
			h.st.Settings[id] = s
		}
		if err := h.st.Save(h.statePath()); err != nil {
			h.st.Settings[id] = cur
			h.mu.Unlock()
			log.Printf("settings: %s: purging values of changed accounts: saving state failed: %v", id, err)
			return
		}
	}
	h.mu.Unlock()
	for _, t := range targets {
		log.Printf("settings: %s: the account changed outside the Hub: value purged", t)
		h.auditOp(purgeActor, "settings.person_value", t, "purged", nil)
	}
}

// pruneEntriesLocked drops s's stored values of t's person-entered
// options that no longer fit (a tightened constraint) and, under a newly
// declared unique, the later duplicates (the earliest updated_at stays),
// returning the audits ("invalidated") to write after mu. Caller holds
// mu (write).
func (h *Hub) pruneEntriesLocked(id string, t *templates.Template, s *state.InstanceSettings) (audits []func()) {
	for _, k := range slices.Sorted(maps.Keys(s.Entered)) {
		o := entryOption(t, k)
		if o == nil {
			continue
		}
		_, invalid, dupes := entryValues(h.kinds, o, s.Entered[k], s.Types[k])
		for _, u := range append(invalid, dupes...) {
			why := "no longer fits the option"
			if slices.Contains(dupes, u) {
				why = "a later duplicate of a unique value"
			}
			log.Printf("settings: %s/%s/%s: stored value dropped: %s", id, k, u, why)
			dropEntry(s, k, u)
			target := id + "/" + k + "/" + u
			audits = append(audits, func() { h.auditOp(purgeActor, "settings.person_value", target, "invalidated", nil) })
		}
	}
	return audits
}

// entryIncompatibilities is what moving stored values to option o (a
// new template version) drops: values that no longer fit, and later
// duplicates under a newly declared unique.
func entryIncompatibilities(o *templates.Option, stored map[string]state.EnteredValue) []string {
	_, invalid, dupes := entryValues(settings.NewRegistry(), o, stored, "")
	var out []string
	if len(invalid) > 0 {
		out = append(out, fmt.Sprintf("setting %s: %d stored person-entered value(s) no longer fit the option and are dropped", o.Key, len(invalid)))
	}
	if len(dupes) > 0 {
		out = append(out, fmt.Sprintf("setting %s: %d stored person-entered value(s) duplicate an earlier one of this now unique option and are dropped", o.Key, len(dupes)))
	}
	return out
}
