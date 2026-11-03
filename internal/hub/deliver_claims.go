package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strconv"
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
// editable, under the directory's reserved prefix ps- (Users & Groups
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
	// ListUsers (with their attributes) finds who holds a setting value
	// when delivered.json's record of it is lost.
	ListUsers(ctx context.Context) ([]lldap.User, error)
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
// "ps-" + the first 12 hex (LLDAP allows only letters, digits and - in attribute names) of sha256(instance + "\x00" + key).
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

// claimOptions are t's person and person-entered options with claim
// deliveries (a person-entered claim carries each person's own value).
func claimOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		if sc := opts[i].EffectiveScope(); (sc == templates.ScopePerson || sc == templates.ScopePersonEntered) && len(claimDeliveries(&opts[i])) > 0 {
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
	// unrenderable: people whose value no delivery could take (cleared).
	unrenderable int
	err          error
}

// claimPlan is the claims step's desired state for one run.
type claimPlan struct {
	outs    []claimOutput                      // by attribute
	clients map[string][]keycloak.SettingClaim // instance client id → its claims
	all     []string                           // every client of the instance
	users   map[string]bool                    // every LLDAP user of the snapshot
	skip    string                             // SkipDirectory: no snapshot
}

// buildClaimsLocked is t's claims plan with snapshot m (nil: the
// directory unavailable — skipped, nothing cleared). Caller holds mu
// (read).
func (h *Hub) buildClaimsLocked(t *templates.Template, m *directory.Membership) claimPlan {
	plan := claimPlan{clients: map[string][]keycloak.SettingClaim{}, all: t.NamesFor(t.ID).Clients}
	opts := claimOptions(t)
	if len(opts) == 0 {
		return plan
	}
	var people map[string]map[string]settings.Resolved
	if m == nil {
		plan.skip = SkipDirectory
	} else {
		people = h.peopleWithEntriesLocked(t, m)
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
		}
		if out.err == nil && people != nil {
			out.unrenderable, out.err = renderClaimValues(t.ID, o, ds, people, out.values)
		}
		plan.outs = append(plan.outs, out)
	}
	sort.Slice(plan.outs, func(i, j int) bool { return plan.outs[i].attr < plan.outs[j].attr })
	return plan
}

// renderClaimValues fills values with each person's rendered value of o
// (one attribute holds one value: every claim delivery of o must render
// it alike). nil (no value) and UNRESOLVED (ReasonFailClosed) values are
// left out, and so are values a delivery refuses or its json_type can't
// take (unrenderable, counted): those people are cleared.
func renderClaimValues(id string, o *templates.Option, ds []templates.Delivery, people map[string]map[string]settings.Resolved, values map[string]string) (unrenderable int, err error) {
	for _, user := range sortedUsers(people) {
		res, ok := people[user][o.Key]
		if !ok || res.Value == nil {
			continue
		}
		text, set := "", false
		for i := range ds {
			r, err := settings.RenderDelivery(o, res.Value, &ds[i])
			if err == nil {
				err = claimValueFits(ds[i].Claim.JSONType, r.Text)
			}
			if err != nil {
				log.Printf("settings: %s: %s: the value of %s can't be delivered as a claim (%v): cleared", id, o.Key, user, err)
				set = false
				unrenderable++
				break
			}
			if set && r.Text != text {
				return 0, fmt.Errorf("setting %s: its claim deliveries render one value differently (%s): one attribute holds one value", o.Key, settings.DeliveryName(&ds[i]))
			}
			text, set = r.Text, true
		}
		if set {
			values[user] = text
		}
	}
	return unrenderable, nil
}

// claimValueFits checks a rendered value against the claim's json_type
// (Keycloak converts the attribute: int is a 32-bit integer, bool exactly
// true/false, json a JSON document; string anything).
func claimValueFits(jsonType, text string) error {
	switch jsonType {
	case "int":
		if _, err := strconv.ParseInt(text, 10, 32); err != nil {
			return fmt.Errorf("%q is not a 32-bit integer (json_type int)", text)
		}
	case "bool":
		if text != "true" && text != "false" {
			return fmt.Errorf("%q is not true or false (json_type bool)", text)
		}
	case "json":
		if !json.Valid([]byte(text)) {
			return fmt.Errorf("the value is not valid JSON (json_type json)")
		}
	}
	return nil
}

// claimHash is a delivered value's record (never the value).
func claimHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}

// claimPending marks a user whose value is unknown — a failed write, or a
// holder found by the holders query: written (or cleared) again.
const claimPending = "pending"

// claimStep is the claims step's input.
type claimStep struct {
	t         *templates.Template
	plan      claimPlan
	current   func() bool // the generation is still the run's (call under mu)
	delivered *deliveredDoc
	now       time.Time
}

// storeError is an LLDAP failure as a unit shows it (credentials missing:
// "Users & Groups not configured").
func (h *Hub) storeError(id, what string, err error) string {
	if errors.Is(err, lldap.ErrNotConfigured) {
		return "Users & Groups not configured: the claims can't be delivered"
	}
	return h.redactUnitError(id, fmt.Errorf("%s: %w", what, err))
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
	if !isCurrent() {
		return collect(), true
	}
	attrs, err := store.UserAttributes(ctx)
	if err != nil {
		h.dropChangedClaims(ctx, t, plan, idp, d, isCurrent)
		return failAll(h.storeError(t.ID, "LLDAP user attributes", err)), false
	}
	schema := make(map[string]lldap.Attribute, len(attrs))
	for _, a := range attrs {
		schema[a.Name] = a
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

	// The attributes (hidden, not editable). exists: the Hub's attribute
	// is there; ready: values may be written.
	exists, ready := map[string]bool{}, map[string]bool{}
	var lost []string // existing attributes without a record
	for _, o := range plan.outs {
		u := res[o.attr]
		unit := claimUnit(o.attr)
		at, ok := schema[o.attr]
		switch {
		case ok && (at.IsVisible || at.IsEditable || at.IsList):
			// Not one the Hub made: never write a value users could see.
			u.Error = fmt.Sprintf("LLDAP attribute %s of setting %s exists and is visible, editable or a list: it isn't the Hub's hidden attribute, nothing was written (delete it in LLDAP)", o.attr, o.key)
			continue
		case ok:
			exists[o.attr] = true
			if d.Claims[unit] == nil {
				lost = append(lost, o.attr)
			}
		default:
			if o.err != nil {
				break
			}
			if !isCurrent() {
				return collect(), true
			}
			if err := store.AddHiddenUserAttribute(ctx, o.attr); err != nil {
				u.Error = h.storeError(t.ID, fmt.Sprintf("creating LLDAP attribute %s of setting %s", o.attr, o.key), err)
				continue
			}
			// New: nobody holds a value. Known and empty from now on.
			exists[o.attr] = true
			d.Claims[unit] = map[string]string{}
		}
		if o.err != nil {
			u.Error = h.redactUnitError(t.ID, o.err)
			continue
		}
		ready[o.attr] = true
	}
	if len(lost) > 0 {
		// No record (delivered.json lost): who holds a value, from one
		// query; only those are cleared or rewritten.
		users, err := store.ListUsers(ctx)
		for _, a := range lost {
			if err != nil {
				ready[a] = false
				res[a].Error = h.storeError(t.ID, "LLDAP users (who holds "+a+")", err)
				continue
			}
			rec := map[string]string{}
			for _, u := range users {
				if len(u.Attributes[a]) > 0 {
					rec[strings.ToLower(u.ID)] = claimPending
				}
			}
			d.Claims[claimUnit(a)] = rec
		}
	}

	// The values: per user, every changed attribute in one write.
	type change struct {
		set    map[string][]string
		remove []string
	}
	changes := map[string]*change{}
	ch := func(u string) *change {
		if changes[u] == nil {
			changes[u] = &change{set: map[string][]string{}}
		}
		return changes[u]
	}
	for _, o := range plan.outs {
		if !ready[o.attr] {
			continue
		}
		rec := d.Claims[claimUnit(o.attr)]
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
	}
	users := make([]string, 0, len(changes))
	for u := range changes {
		users = append(users, u)
	}
	sort.Strings(users)
	written, cleared := map[string]int{}, map[string]int{}
	failed := map[string][]string{}
	fin := func() []UnitResult {
		return h.claimUnits(plan, order, res, written, cleared, failed)
	}
	for _, u := range users {
		c := changes[u]
		if !isCurrent() {
			return fin(), true
		}
		sort.Strings(c.remove)
		err := store.SetUserAttributes(ctx, u, c.set, c.remove)
		for a, v := range c.set {
			rec := d.Claims[claimUnit(a)]
			if err != nil {
				rec[u] = claimPending
				failed[a] = append(failed[a], fmt.Sprintf("%s: %s", u, h.storeError(t.ID, "write", err)))
				continue
			}
			rec[u] = claimHash(v[0])
			written[a]++
		}
		for _, a := range c.remove {
			rec := d.Claims[claimUnit(a)]
			if err != nil {
				rec[u] = claimPending
				failed[a] = append(failed[a], fmt.Sprintf("%s: %s", u, h.storeError(t.ID, "write", err)))
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

	// The mappers, last: every client of the instance gets its exact set
	// (none: its setting mappers go — a claim moved to another client).
	// A claim is in it only when its attribute exists AND its values were
	// reconciled in this run (written, or unchanged against the last
	// successful record): a render error, a failed write or a failed
	// holders query drops the mapper until a later run reconciles it, so
	// a stale value is never put into a token.
	reconciled := func(a string) bool { return exists[a] && ready[a] && len(failed[a]) == 0 }
	cids := append([]string(nil), plan.all...)
	for cid := range plan.clients {
		if !slices.Contains(cids, cid) {
			cids = append(cids, cid)
		}
	}
	sort.Strings(cids)
	for _, cid := range cids {
		var claims []keycloak.SettingClaim
		for _, c := range plan.clients[cid] {
			if reconciled(c.Attr) {
				claims = append(claims, c)
			}
		}
		if !isCurrent() {
			return fin(), true
		}
		err := idp.EnsureSettingClaims(ctx, cid, t.ID, claims)
		if err == nil {
			continue
		}
		var ce *keycloak.ConflictError
		hit := plan.clients[cid]
		if len(hit) == 0 {
			if errors.As(err, &ce) || errors.Is(err, keycloak.ErrClientNotFound) {
				// Nothing of ours there: another owner's client, or one
				// not registered yet (no mapper can be on it) — logged.
				log.Printf("settings: %s: Keycloak client %s (no setting claims): %v", t.ID, cid, err)
				continue
			}
			// A stale mapper may stay on it: every unit fails, retried.
			for _, o := range plan.outs {
				hit = append(hit, keycloak.SettingClaim{Attr: o.attr})
			}
		}
		for _, c := range hit {
			res[c.Attr].OK = false
			res[c.Attr].Error = h.redactUnitError(t.ID, fmt.Errorf("Keycloak client %s: %w", cid, err))
		}
	}
	return fin(), false
}

// dropChangedClaims fails closed when LLDAP can't be read (the values
// can't be reconciled): every client keeps the mappers only of claims
// whose desired values equal the last successful record; the others —
// an admin role revoked, a quota lowered — go until a run writes them.
// The directory unavailable (plan.skip) keeps the last delivery, as
// documented. Errors are logged (the units already fail).
func (h *Hub) dropChangedClaims(ctx context.Context, t *templates.Template, plan claimPlan, idp IdP, d *deliveredDoc, isCurrent func() bool) {
	if plan.skip != "" || len(plan.outs) == 0 {
		return
	}
	unchanged := map[string]bool{}
	for _, o := range plan.outs {
		rec := d.Claims[claimUnit(o.attr)]
		ok := o.err == nil && rec != nil && len(rec) == len(o.values)
		for u, v := range o.values {
			ok = ok && rec[u] == claimHash(v)
		}
		unchanged[o.attr] = ok
	}
	cids := append([]string(nil), plan.all...)
	for cid := range plan.clients {
		if !slices.Contains(cids, cid) {
			cids = append(cids, cid)
		}
	}
	sort.Strings(cids)
	for _, cid := range cids {
		var claims []keycloak.SettingClaim
		for _, c := range plan.clients[cid] {
			if unchanged[c.Attr] {
				claims = append(claims, c)
			}
		}
		if !isCurrent() {
			return
		}
		if err := idp.EnsureSettingClaims(ctx, cid, t.ID, claims); err != nil {
			log.Printf("settings: %s: LLDAP unreadable: dropping the changed claims' mappers on Keycloak client %s failed: %v", t.ID, cid, err)
		}
	}
}

// claimUnits finishes the units: counts, unrenderable values, failed
// writes, unchanged.
func (h *Hub) claimUnits(plan claimPlan, order []string, res map[string]*UnitResult, written, cleared map[string]int, failed map[string][]string) []UnitResult {
	bad := map[string]int{}
	for _, o := range plan.outs {
		bad[o.attr] = o.unrenderable
	}
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
		if u.OK && bad[a] > 0 {
			note := fmt.Sprintf("%d values can't be delivered as this claim (cleared; see the log)", bad[a])
			if u.Message != "" {
				u.Message += "; " + note
			} else {
				u.Message = note
			}
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
	if errors.Is(err, lldap.ErrNotConfigured) {
		res.Warnings = append(res.Warnings, fmt.Sprintf("Users & Groups is not configured: the LLDAP setting attributes %s were not removed", strings.Join(attrs, ", ")))
		return nil
	}
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

// deliverClaimsAfterStart delivers instance id's claims and headers
// (deliver_headers.go: they need the directory too) in the background
// after a compose up (the start run writes only the data files: a start
// never waits for LLDAP or Keycloak). It takes the delivery lock, so it
// runs after the start's own deliveries. Gated like any delivery
// (runClaimsOnly): a disabled, deleting or restoring instance gets
// nothing; a busy one (the start's lifecycle lock still held) a normal
// delivery after busyRetry; a superseded run re-queues one.
func (h *Hub) deliverClaimsAfterStart(id string) {
	d := h.loadDelivered(id)
	_, headersRecorded := d.Hashes[unitHeaders]
	recorded := len(d.Claims) > 0 || headersRecorded
	h.mu.RLock()
	t := h.findLocked(id)
	run := t != nil && (claimsNeedPeople(t) || headersNeedPeople(t) || recorded)
	h.mu.RUnlock()
	if !run {
		return
	}
	h.goBackground(func() {
		if err := h.runClaimsOnly(context.Background(), id); err != nil {
			log.Printf("settings: %s: claims after start: %v", id, err)
		}
	})
}

// runClaimsOnly is an engine run of the claims and headers steps alone.
func (h *Hub) runClaimsOnly(ctx context.Context, id string) error {
	l := h.deliverLock(id)
	l.Lock()
	defer l.Unlock()
	now := time.Now().UTC()
	h.mu.RLock()
	t := h.findLocked(id)
	h.mu.RUnlock()
	if t == nil {
		return nil
	}
	delivered := h.loadDelivered(id)
	_, headersRecorded := delivered.Hashes[unitHeaders]
	var m *directory.Membership
	if claimsNeedPeople(t) || headersNeedPeople(t) {
		mctx, cancel := context.WithTimeout(ctx, groupSnapshotTimeout)
		var err error
		m, err = h.membership(mctx)
		cancel()
		if err != nil {
			log.Printf("settings: %s: WARNING: directory unavailable (%v): the claims keep what they last delivered", id, err)
		}
	}
	h.mu.RLock()
	live := h.findLocked(id)
	if live == nil {
		h.mu.RUnlock()
		return nil
	}
	if h.pendingLocked(id) != nil || h.appBusy(id) {
		// The order of deliverOnce (P20): an operation holds the
		// instance — the enable or restore that just started it (still
		// before its commit), a delete — so a normal delivery runs after
		// busyRetry, never a write under it. It delivers once the enable
		// or restore has committed, and nothing once a delete is done.
		h.mu.RUnlock()
		h.queueDelivery(id, TriggerMembership, settings.EffectNone, busyRetry)
		return nil
	}
	if !h.st.IsEnabled(id) {
		h.mu.RUnlock()
		return nil
	}
	tmpl := *live
	gen := h.deliveryGenLocked(&tmpl)
	plan := h.buildClaimsLocked(&tmpl, m)
	headers := h.buildHeadersLocked(&tmpl, m, headersRecorded)
	h.mu.RUnlock()
	current := func() bool {
		live := h.findLocked(id)
		return live != nil && h.deliveryGenLocked(live) == gen
	}
	units, superseded := h.runClaims(ctx, claimStep{t: &tmpl, plan: plan, current: current, delivered: &delivered, now: now})
	if !superseded && headers.active {
		var hu UnitResult
		if hu, superseded = h.runHeaders(id, headers, current, &delivered, now); !superseded {
			units = append(units, hu)
		}
	}
	if superseded {
		// A newer commit: what was written is recorded; a normal
		// delivery (after this lock is released) finishes the claims.
		h.saveDelivered(id, delivered)
		h.queueDelivery(id, TriggerMembership, settings.EffectNone, 0)
		return nil
	}
	recordUnits(id, &delivered, units)
	h.saveDelivered(id, delivered)
	return nil
}
