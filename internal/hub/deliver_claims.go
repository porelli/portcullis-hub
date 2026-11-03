package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Claim deliveries (contract §13.6, spec call 12). Keycloak has no
// per-group claim mapper without scripts, so each (instance, option)
// with a claim delivery gets a Hub-owned LLDAP user attribute
// SettingAttr(instance, key) — STRING, single-valued, not visible, not
// editable, under the directory's reserved prefix ps_ (Users & Groups
// never shows or edits it) — holding each person's rendered value, an
// LDAP mapper reading it, and a protocol mapper on that instance's
// client only, both portcullis-setting-<attr>.
//
// One unit per attribute ("claim:<attr>"), after the data files: the
// attribute and the mappers are ensured, then only the people whose
// value changed are written (per-user hashes in delivered.json under
// claims["claim:<attr>"], never values). People outside the population,
// and UNRESOLVED values (fail closed), have the attribute cleared — never
// a default. Without a directory snapshot the claims are skipped, never
// cleared. Keycloak or LLDAP not configured: the units fail, nothing
// else is skipped. Attributes whose option is gone are removed with
// their mappers. Network calls never run under mu; every write re-checks
// the generation first.

// AttrStore is LLDAP's user attribute schema and values (lldap.Client).
// Network calls: never call it holding mu.
type AttrStore interface {
	UserAttributes(ctx context.Context) ([]lldap.Attribute, error)
	AddHiddenUserAttribute(ctx context.Context, name string) error
	DeleteUserAttribute(ctx context.Context, name string) error
	SetUserAttributes(ctx context.Context, user string, set map[string][]string, remove []string) error
}

// SetAttrStore wires LLDAP's user attributes for claim deliveries (nil:
// such units fail "Users & Groups not configured").
func (h *Hub) SetAttrStore(a AttrStore) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.attrs = a
}

// settingAttrPrefix is directory.ReservedAttrPrefix: the directory hides
// these attributes and refuses fields named so.
const settingAttrPrefix = directory.ReservedAttrPrefix

// SettingAttr is the Hub-owned LLDAP attribute of option key of instance:
// "ps_" + the first 12 hex of sha256(instance + "\x00" + key).
func SettingAttr(instance, key string) string {
	sum := sha256.Sum256([]byte(instance + "\x00" + key))
	return settingAttrPrefix + hex.EncodeToString(sum[:])[:12]
}

const claimUnitPrefix = "claim:"

func claimUnit(attr string) string { return claimUnitPrefix + attr }

// claimTimeout bounds the claims step's LLDAP and Keycloak calls.
const claimTimeout = 2 * time.Minute

// claimDeliveries are o's claim deliveries.
func claimDeliveries(o *templates.Option) []templates.Delivery {
	var out []templates.Delivery
	for _, d := range o.Delivery {
		if d.Claim != nil {
			out = append(out, d)
		}
	}
	return out
}

// claimOptions are t's person options with claim deliveries (person-entered
// claims: Task 15A).
func claimOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].EffectiveScope() == templates.ScopePerson && len(claimDeliveries(&opts[i])) > 0 {
			out = append(out, &opts[i])
		}
	}
	return out
}

// claimsNeedPeople: t delivers claims (they need the directory).
func claimsNeedPeople(t *templates.Template) bool { return len(claimOptions(t)) > 0 }

// instanceClaimAttrs are the setting attributes of instance id: its
// template's claim options, and those delivered.json still records.
func (h *Hub) instanceClaimAttrs(t *templates.Template, id string) []string {
	set := map[string]bool{}
	if t != nil {
		for _, o := range claimOptions(t) {
			set[SettingAttr(id, o.Key)] = true
		}
	}
	for u := range h.loadDelivered(id).Claims {
		if a := strings.TrimPrefix(u, claimUnitPrefix); a != u {
			set[a] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// claimOutput is one attribute's desired state.
type claimOutput struct {
	attr, key string
	values    map[string]string // user → rendered value (people who get one)
	err       error
}

// claimPlan is the claims step's desired state for one run.
type claimPlan struct {
	outs    []claimOutput                      // by attribute
	clients map[string][]keycloak.SettingClaim // instance client id → its claims
	byAttr  map[string][]string                // attribute → its clients
	users   map[string]bool                    // every LLDAP user of the snapshot
	skip    string                             // SkipDirectory: no snapshot
	why     string                             // the population's reason when empty
}

// buildClaimsLocked is t's claims plan with snapshot m (nil: the
// directory unavailable — skipped, nothing cleared). Caller holds mu
// (read).
func (h *Hub) buildClaimsLocked(t *templates.Template, m *directory.Membership) claimPlan {
	plan := claimPlan{clients: map[string][]keycloak.SettingClaim{}, byAttr: map[string][]string{}}
	opts := claimOptions(t)
	if len(opts) == 0 {
		return plan
	}
	var people map[string]map[string]settings.Resolved
	if m == nil {
		plan.skip = SkipDirectory
	} else {
		people = h.resolvePeopleLocked(t, m)
		plan.why = h.populationLocked(t, m).Why
		plan.users = make(map[string]bool, len(m.Users))
		for u := range m.Users {
			plan.users[u] = true
		}
	}
	for _, o := range opts {
		out := claimOutput{attr: SettingAttr(t.ID, o.Key), key: o.Key, values: map[string]string{}}
		ds := claimDeliveries(o)
		for _, d := range ds {
			cid := t.InstanceClientID(d.Claim.Client)
			if cid == "" {
				out.err = fmt.Errorf("setting %s: claim %s names client %s, which the template doesn't declare", o.Key, d.Claim.Name, d.Claim.Client)
				break
			}
			plan.clients[cid] = append(plan.clients[cid], keycloak.SettingClaim{Attr: out.attr, Claim: d.Claim.Name, JSONType: d.Claim.JSONType})
			plan.byAttr[out.attr] = append(plan.byAttr[out.attr], cid)
		}
		if out.err == nil && people != nil {
			out.err = renderClaimValues(t.ID, o, ds, people, out.values)
		}
		plan.outs = append(plan.outs, out)
	}
	sort.Slice(plan.outs, func(i, j int) bool { return plan.outs[i].attr < plan.outs[j].attr })
	return plan
}

// renderClaimValues fills values with each person's rendered value of o
// (one attribute holds one value: every claim delivery of o must render
// it alike). nil (no value) and UNRESOLVED (ReasonFailClosed) values, and
// values a delivery refuses, are left out: those people are cleared.
func renderClaimValues(id string, o *templates.Option, ds []templates.Delivery, people map[string]map[string]settings.Resolved, values map[string]string) error {
	for _, user := range sortedUsers(people) {
		res, ok := people[user][o.Key]
		if !ok || res.Value == nil {
			continue
		}
		text, set := "", false
		for i := range ds {
			r, err := settings.RenderDelivery(o, res.Value, &ds[i])
			if err != nil {
				log.Printf("settings: %s: %s: the value of %s doesn't render (%v): cleared", id, o.Key, user, err)
				set = false
				break
			}
			if set && r.Text != text {
				return fmt.Errorf("setting %s: its claim deliveries render one value differently (%s): one attribute holds one value", o.Key, settings.DeliveryName(&ds[i]))
			}
			text, set = r.Text, true
		}
		if set {
			values[user] = text
		}
	}
	return nil
}

// claimHash is a delivered value's record (never the value).
func claimHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}

// claimPending marks a user whose last write failed: written again.
const claimPending = "pending"

// claimStep is the claims step's input from deliverOnce.
type claimStep struct {
	t         *templates.Template
	plan      claimPlan
	current   func() bool // the generation is still the run's (call under mu)
	delivered *deliveredDoc
	now       time.Time
}

// runClaims applies step.plan (outside mu): the units, and whether a
// newer commit stopped it (superseded; what it wrote is recorded).
func (h *Hub) runClaims(ctx context.Context, step claimStep) (units []UnitResult, superseded bool) {
	t, plan, d := step.t, step.plan, step.delivered
	want := map[string]bool{}
	for _, o := range plan.outs {
		want[o.attr] = true
	}
	var orphans []string
	for u := range d.Claims {
		if a := strings.TrimPrefix(u, claimUnitPrefix); a != u && !want[a] {
			orphans = append(orphans, a)
		}
	}
	sort.Strings(orphans)
	if len(plan.outs) == 0 && len(orphans) == 0 {
		return nil, false
	}
	h.mu.RLock()
	idp, store := h.idp, h.attrs
	h.mu.RUnlock()
	res := map[string]*UnitResult{}
	var order []string
	for _, o := range plan.outs {
		u := &UnitResult{Unit: claimUnit(o.attr), At: step.now}
		res[o.attr] = u
		order = append(order, o.attr)
	}
	collect := func() []UnitResult {
		out := make([]UnitResult, 0, len(order))
		for _, a := range order {
			out = append(out, *res[a])
		}
		return out
	}
	failAll := func(msg string) []UnitResult {
		for _, a := range order {
			res[a].Error = msg
		}
		return collect()
	}
	switch {
	case idp == nil:
		return failAll("Keycloak not configured: the claims can't be delivered"), false
	case store == nil:
		return failAll("Users & Groups not configured: the claims can't be delivered"), false
	}
	ctx, cancel := context.WithTimeout(ctx, claimTimeout)
	defer cancel()
	isCurrent := func() bool {
		h.mu.RLock()
		defer h.mu.RUnlock()
		return step.current()
	}

	// The schema: one read serves the orphans and the attributes.
	var schema map[string]lldap.Attribute
	readSchema := func() error {
		attrs, err := store.UserAttributes(ctx)
		if err != nil {
			return err
		}
		schema = make(map[string]lldap.Attribute, len(attrs))
		for _, a := range attrs {
			schema[a.Name] = a
		}
		return nil
	}
	if !isCurrent() {
		return collect(), true
	}
	if err := readSchema(); err != nil {
		return failAll(h.redactUnitError(t.ID, fmt.Errorf("LLDAP user attributes: %w", err))), false
	}
	if len(orphans) > 0 {
		h.removeOrphanClaims(ctx, t, orphans, schema, idp, store, d)
	}
	if plan.skip != "" {
		for _, a := range order {
			res[a].Skipped = plan.skip
		}
		return collect(), false
	}

	// The attributes (hidden, not editable), then the mappers.
	ready := map[string]bool{}
	for _, o := range plan.outs {
		u := res[o.attr]
		switch at, ok := schema[o.attr]; {
		case o.err != nil:
			u.Error = h.redactUnitError(t.ID, o.err)
		case ok && (at.IsVisible || at.IsEditable || at.IsList):
			// Not one the Hub made: never write a value users could see.
			u.Error = fmt.Sprintf("LLDAP attribute %s of setting %s exists and is visible, editable or a list: it isn't the Hub's hidden attribute, nothing was written (delete it in LLDAP)", o.attr, o.key)
		case !ok:
			if err := store.AddHiddenUserAttribute(ctx, o.attr); err != nil {
				u.Error = h.redactUnitError(t.ID, fmt.Errorf("creating LLDAP attribute %s of setting %s: %w", o.attr, o.key, err))
				break
			}
			ready[o.attr] = true
		default:
			ready[o.attr] = true
		}
	}
	cids := make([]string, 0, len(plan.clients))
	for cid := range plan.clients {
		cids = append(cids, cid)
	}
	sort.Strings(cids)
	for _, cid := range cids {
		var claims []keycloak.SettingClaim
		for _, c := range plan.clients[cid] {
			if ready[c.Attr] {
				claims = append(claims, c)
			}
		}
		if !isCurrent() {
			return collect(), true
		}
		if err := idp.EnsureSettingClaims(ctx, cid, t.ID, claims); err != nil {
			for _, c := range plan.clients[cid] {
				if ready[c.Attr] {
					ready[c.Attr] = false
					res[c.Attr].Error = h.redactUnitError(t.ID, fmt.Errorf("Keycloak client %s: %w", cid, err))
				}
			}
		}
	}

	// The values: per user, every changed attribute in one write.
	type change struct {
		set    map[string][]string
		remove []string
	}
	changes := map[string]*change{}
	written := map[string]int{}
	cleared := map[string]int{}
	for _, o := range plan.outs {
		if !ready[o.attr] {
			continue
		}
		unit := claimUnit(o.attr)
		rec, known := d.Claims[unit]
		if rec == nil {
			rec = map[string]string{}
			d.Claims[unit] = rec
		}
		ch := func(u string) *change {
			if changes[u] == nil {
				changes[u] = &change{set: map[string][]string{}}
			}
			return changes[u]
		}
		for u, v := range o.values {
			if rec[u] != claimHash(v) {
				ch(u).set[o.attr] = []string{v}
			}
		}
		for u := range rec {
			if _, keep := o.values[u]; keep {
				continue
			}
			if !plan.users[u] {
				// Gone from LLDAP: its attributes went with it.
				delete(rec, u)
				continue
			}
			ch(u).remove = append(ch(u).remove, o.attr)
		}
		if !known {
			// No record (first delivery, or delivered.json lost): clear
			// everyone else once.
			for u := range plan.users {
				if _, keep := o.values[u]; !keep && rec[u] == "" {
					ch(u).remove = append(ch(u).remove, o.attr)
				}
			}
		}
	}
	users := make([]string, 0, len(changes))
	for u := range changes {
		users = append(users, u)
	}
	sort.Strings(users)
	failed := map[string][]string{}
	for _, u := range users {
		c := changes[u]
		if !isCurrent() {
			return h.claimUnits(order, res, written, cleared, failed), true
		}
		sort.Strings(c.remove)
		err := store.SetUserAttributes(ctx, u, c.set, c.remove)
		for a, v := range c.set {
			rec := d.Claims[claimUnit(a)]
			if err != nil {
				rec[u] = claimPending
				failed[a] = append(failed[a], fmt.Sprintf("%s: %s", u, h.redactUnitError(t.ID, err)))
				continue
			}
			rec[u] = claimHash(v[0])
			written[a]++
		}
		for _, a := range c.remove {
			rec := d.Claims[claimUnit(a)]
			if err != nil {
				rec[u] = claimPending
				failed[a] = append(failed[a], fmt.Sprintf("%s: %s", u, h.redactUnitError(t.ID, err)))
				continue
			}
			delete(rec, u)
			cleared[a]++
		}
	}
	for _, o := range plan.outs {
		if ready[o.attr] {
			res[o.attr].OK = true
		}
	}
	return h.claimUnits(order, res, written, cleared, failed), false
}

// claimUnits finishes the units: counts, failed writes, unchanged.
func (h *Hub) claimUnits(order []string, res map[string]*UnitResult, written, cleared map[string]int, failed map[string][]string) []UnitResult {
	out := make([]UnitResult, 0, len(order))
	for _, a := range order {
		u := res[a]
		switch {
		case len(failed[a]) > 0:
			u.OK = false
			u.Error = clipRunes("writing LLDAP attribute "+a+" failed for "+strings.Join(failed[a], "; "), unitErrorMax)
		case u.OK && written[a]+cleared[a] == 0:
			u.Skipped = SkipUnchanged
		case u.OK:
			u.Message = fmt.Sprintf("%d written, %d cleared", written[a], cleared[a])
		}
		out = append(out, *u)
	}
	return out
}

// removeOrphanClaims removes the attributes (and their mappers on every
// client of the instance) of options that no longer deliver a claim.
// Failures keep the record: tried again on the next run.
func (h *Hub) removeOrphanClaims(ctx context.Context, t *templates.Template, orphans []string, schema map[string]lldap.Attribute, idp IdP, store AttrStore, d *deliveredDoc) {
	var errs []error
	for _, cid := range t.NamesFor(t.ID).Clients {
		err := idp.RemoveSettingClaims(ctx, cid, t.ID, orphans)
		var ce *keycloak.ConflictError
		switch {
		case errors.As(err, &ce):
			log.Printf("settings: %s: the setting claim mappers on Keycloak client %s were kept: it is not tagged as owned by %s", t.ID, cid, t.ID)
		case err != nil:
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		log.Printf("settings: %s: removing the claim mappers of %s: %v (tried again on the next delivery)", t.ID, strings.Join(orphans, ", "), err)
		return
	}
	for _, a := range orphans {
		if _, ok := schema[a]; ok {
			if err := store.DeleteUserAttribute(ctx, a); err != nil {
				log.Printf("settings: %s: deleting LLDAP attribute %s: %v (tried again on the next delivery)", t.ID, a, err)
				continue
			}
		}
		delete(d.Claims, claimUnit(a))
		delete(d.Status, claimUnit(a))
		log.Printf("settings: %s: removed setting attribute %s (its option no longer delivers a claim)", t.ID, a)
	}
}

// removeInstanceClaims is the delete cleanup (§11.4 step 4): the setting
// mappers of attrs on each client (only owner-tagged ones: another's is
// a warning; idp nil: none) and the LLDAP attributes, with their values.
func (h *Hub) removeInstanceClaims(ctx context.Context, idp IdP, id string, clients, attrs []string, res *DeleteResult) error {
	if len(attrs) == 0 {
		return nil
	}
	h.mu.RLock()
	store := h.attrs
	h.mu.RUnlock()
	for _, c := range clients {
		if idp == nil {
			break
		}
		err := idp.RemoveSettingClaims(ctx, c, id, attrs)
		var ce *keycloak.ConflictError
		switch {
		case errors.As(err, &ce):
			res.Warnings = append(res.Warnings, fmt.Sprintf("the setting claims on Keycloak client %s were kept: it is not tagged as owned by %s", c, id))
		case err != nil:
			return fmt.Errorf("removing the setting claims of client %s: %w", c, err)
		}
	}
	if store == nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("Users & Groups is not configured: the LLDAP setting attributes %s were not removed", strings.Join(attrs, ", ")))
		return nil
	}
	have, err := store.UserAttributes(ctx)
	if err != nil {
		return fmt.Errorf("listing the LLDAP user attributes: %w", err)
	}
	present := map[string]bool{}
	for _, a := range have {
		present[a.Name] = true
	}
	for _, a := range attrs {
		if !present[a] {
			continue
		}
		if err := store.DeleteUserAttribute(ctx, a); err != nil {
			return fmt.Errorf("deleting LLDAP attribute %s: %w", a, err)
		}
	}
	return nil
}
