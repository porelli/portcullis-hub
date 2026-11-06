package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/state"
)

const claimID = "immich"

// claimFixture loads testdata/settings/claimapp as instance immich
// (native-oidc, client immich): storage_quota (person, max, default
// 100GiB, claim immich_quota int in GiB, and data file people) and role
// (person, {{ADMIN_GROUP}}: admin, claim immich_role). users_immich:
// alice, bob, carol, dave; admin_immich: bob; office_milan: alice; erin
// is in no group. Not enabled yet.
func claimFixture(t *testing.T) (*fixture, *fakePeople, *fakeAttrStore) {
	return claimFixtureWith(t, nil)
}

// claimFixtureWith is claimFixture with the manifest edited by edit.
func claimFixtureWith(t *testing.T, edit func(string) string) (*fixture, *fakePeople, *fakeAttrStore) {
	t.Helper()
	m := string(mustRead(t, filepath.Join("testdata", "settings", "claimapp", "manifest.yaml")))
	if edit != nil {
		m = edit(m)
	}
	c := mustRead(t, filepath.Join("testdata", "settings", "claimapp", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{claimID: {m, string(c)}})
	if f.h.Template(claimID) == nil {
		t.Fatalf("claimapp not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople("erin")
	people.addGroup("users_immich", "alice", "bob", "carol", "dave")
	people.addGroup("admin_immich", "bob")
	people.addGroup("office_milan", "alice")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_immich": true, "admin_immich": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	store := newFakeAttrStore()
	f.h.SetAttrStore(store)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	return f, people, store
}

// settle fires the armed timers (the deliveries queued while the
// instance was busy) until none is left, then waits.
func settle(f *fixture) {
	for i := 0; i < 5; i++ {
		f.h.Wait()
		if f.clk.fire() == 0 {
			break
		}
	}
	f.h.Wait()
}

// claimEnable enables immich (binding the {{ADMIN_GROUP}} row) and
// stores the quota rows: default 100GiB, office_milan 10GiB.
func claimEnable(t *testing.T, f *fixture, id string) {
	t.Helper()
	if _, err := f.h.EnableAs(id, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	// The enable's claims: the background run found it busy and queued
	// a delivery (busyRetry), which runs once its timer fires.
	settle(f)
	if _, err := f.h.SaveSettings(id, SettingsUpdate{Person: map[string]PersonChange{
		"storage_quota": {Default: raw("100GiB"), Rows: rows("office_milan", "10GiB")},
	}}, "admin"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
}

func deliverNow(t *testing.T, f *fixture, id string, trig Trigger) *DeliveryReport {
	t.Helper()
	rep, err := f.h.Deliver(context.Background(), id, trig)
	if err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	return rep
}

func TestSettingAttrName(t *testing.T) {
	a := SettingAttr("immich", "storage_quota")
	if !strings.HasPrefix(a, "ps-") || len(a) != 15 || a == SettingAttr("immich-b", "storage_quota") || a == SettingAttr("immich", "role") {
		t.Errorf("SettingAttr = %q", a)
	}
	// "ps-" + the first 12 hex of sha256("immich\x00storage_quota").
	if a != "ps-"+sha256Hex("immich\x00storage_quota")[:12] {
		t.Errorf("SettingAttr = %q", a)
	}
	// Hidden by the directory: the same reserved prefix.
	if !strings.HasPrefix(a, reservedAttrPrefix()) {
		t.Errorf("%q is not under the directory's reserved prefix %q", a, reservedAttrPrefix())
	}
	// LLDAP (v0.6.3 validate_attribute_name) creates only attributes named
	// with a-z, A-Z, 0-9 and '-': "ps_…" was refused ("Invalid chars found:
	// _") and no claim was ever delivered (e2e-settings).
	lldapName := regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	for _, ik := range [][2]string{{"immich", "storage_quota"}, {"immich", "role"}, {"my-app_2", "a_b_c"}} {
		if n := SettingAttr(ik[0], ik[1]); !lldapName.MatchString(n) {
			t.Errorf("SettingAttr(%q, %q) = %q: LLDAP refuses the name", ik[0], ik[1], n)
		}
	}
}

func TestClaimDeliveryPerPerson(t *testing.T) {
	f, people, store := claimFixture(t)
	quota, role := SettingAttr(claimID, "storage_quota"), SettingAttr(claimID, "role")
	// erin never was in the population but holds a stale value (a lost
	// delivered.json): the first delivery clears it.
	if err := store.AddHiddenUserAttribute(context.Background(), quota); err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserAttributes(context.Background(), "erin", map[string][]string{quota: {"999"}}, nil); err != nil {
		t.Fatal(err)
	}
	claimEnable(t, f, claimID)
	rep := deliverNow(t, f, claimID, TriggerRetry)
	for _, a := range []string{quota, role} {
		if u, ok := unit(rep, "claim:"+a); !ok || !u.OK || u.Error != "" {
			t.Errorf("unit claim:%s = %+v (%v)", a, u, ok)
		}
		at, ok := store.has(a)
		if !ok || at.IsVisible || at.IsEditable || at.IsList {
			t.Errorf("attribute %s = %+v %v, want hidden and not editable", a, at, ok)
		}
	}
	for user, want := range map[string]string{"alice": "10", "bob": "100", "carol": "100", "dave": "100"} {
		if got, _ := store.value(user, quota); got != want {
			t.Errorf("%s quota = %q, want %q", user, got, want)
		}
	}
	for user, want := range map[string]string{"alice": "user", "bob": "admin", "carol": "user"} {
		if got, _ := store.value(user, role); got != want {
			t.Errorf("%s role = %q, want %q", user, got, want)
		}
	}
	if _, ok := store.value("erin", quota); ok {
		t.Error("erin (outside the population) kept a value")
	}
	// The existing attribute had no record: one holders query, and only
	// erin (the holder) was cleared — nobody else got a blind removal.
	store.mu.Lock()
	lists := store.lists
	store.mu.Unlock()
	if lists != 1 {
		t.Errorf("%d holders queries, want 1", lists)
	}
	for _, c := range store.calls() {
		if strings.HasPrefix(c, "admin ") {
			t.Errorf("blind removal: %q", c)
		}
	}
	// The mappers: on client immich, with the template's claims.
	want := []keycloak.SettingClaim{{Attr: role, Claim: "immich_role", JSONType: ""}, {Attr: quota, Claim: "immich_quota", JSONType: "int"}}
	if got := f.idp.settingClaims("immich"); !sameClaims(got, want) {
		t.Errorf("claims on immich = %+v, want %+v", got, want)
	}

	// dave leaves the access group: his values are removed.
	people.set(func(p *fakePeople) { delete(p.members["users_immich"], "dave") })
	deliverNow(t, f, claimID, TriggerMembership)
	for _, a := range []string{quota, role} {
		if v, ok := store.value("dave", a); ok {
			t.Errorf("dave (outside the population) still has %s = %q", a, v)
		}
	}
	// admin_immich members outside users_immich get nothing either.
	people.set(func(p *fakePeople) { p.members["admin_immich"]["erin"] = true })
	deliverNow(t, f, claimID, TriggerMembership)
	if v, ok := store.value("erin", role); ok {
		t.Errorf("erin (admin_immich only) has role %q", v)
	}
	// Per-user hashes only in delivered.json: no values.
	d := f.h.loadDelivered(claimID)
	if rec := d.Claims["claim:"+quota]; len(rec) != 3 || rec["alice"] == "" || rec["alice"] == "10" {
		t.Errorf("delivered claims record = %+v", rec)
	}
}

func sameClaims(a, b []keycloak.SettingClaim) bool {
	key := func(l []keycloak.SettingClaim) map[string]keycloak.SettingClaim {
		m := map[string]keycloak.SettingClaim{}
		for _, c := range l {
			m[c.Attr] = c
		}
		return m
	}
	return len(a) == len(b) && reflect.DeepEqual(key(a), key(b))
}

func TestClaimOnlyChangedUsersWritten(t *testing.T) {
	f, people, store := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	before := len(store.calls())
	// carol joins office_milan: her quota (only) changes.
	people.addGroup("office_milan", "carol")
	rep := deliverNow(t, f, claimID, TriggerMembership)
	calls := store.calls()[before:]
	if len(calls) != 1 || calls[0] != "carol +"+SettingAttr(claimID, "storage_quota")+"=10" {
		t.Errorf("writes after one membership change = %q", calls)
	}
	if u, _ := unit(rep, "claim:"+SettingAttr(claimID, "role")); !u.OK || u.Skipped != SkipUnchanged {
		t.Errorf("role unit = %+v", u)
	}
	// Nothing changed: nothing written.
	before = len(store.calls())
	rep = deliverNow(t, f, claimID, TriggerMembership)
	if n := len(store.calls()) - before; n != 0 {
		t.Errorf("an unchanged run wrote %d times: %q", n, store.calls()[before:])
	}
	if u, _ := unit(rep, "claim:"+SettingAttr(claimID, "storage_quota")); !u.OK || u.Skipped != SkipUnchanged {
		t.Errorf("quota unit = %+v", u)
	}
	// A failed write is retried on the next run (only that user).
	people.addGroup("office_milan", "dave")
	store.mu.Lock()
	store.failUser = "dave"
	store.mu.Unlock()
	rep = deliverNow(t, f, claimID, TriggerMembership)
	if u, _ := unit(rep, "claim:"+SettingAttr(claimID, "storage_quota")); u.OK || !strings.Contains(u.Error, "dave") {
		t.Errorf("failed write unit = %+v", u)
	}
	store.mu.Lock()
	store.failUser = ""
	store.mu.Unlock()
	before = len(store.calls())
	deliverNow(t, f, claimID, TriggerMembership)
	if calls := store.calls()[before:]; len(calls) != 1 || !strings.HasPrefix(calls[0], "dave ") {
		t.Errorf("retry writes = %q", calls)
	}
}

func TestClaimDeliveryNeedsKeycloak(t *testing.T) {
	f, people, store := claimFixture(t)
	claimEnable(t, f, claimID)
	f.h.mu.Lock()
	f.h.idp = nil
	f.h.mu.Unlock()
	before := len(store.calls())
	// Something to deliver: carol's quota changes.
	people.addGroup("office_milan", "carol")
	rep := deliverNow(t, f, claimID, TriggerRetry)
	for _, a := range []string{SettingAttr(claimID, "storage_quota"), SettingAttr(claimID, "role")} {
		u, ok := unit(rep, "claim:"+a)
		if !ok || u.OK || !strings.Contains(u.Error, "Keycloak not configured") {
			t.Errorf("claim:%s = %+v (%v)", a, u, ok)
		}
	}
	// Nothing else is skipped: the data file is delivered.
	if u, ok := unit(rep, "file:people"); !ok || !u.OK || u.Error != "" {
		t.Errorf("file:people = %+v (%v)", u, ok)
	}
	if d := readDoc(t, f.appFile(claimID, "people")); d.People["alice"]["quota"] != float64(10<<30) {
		t.Errorf("people.alice = %v", d.People["alice"])
	}
	if calls := store.calls()[before:]; len(calls) != 0 {
		t.Errorf("values written without Keycloak: %q", calls)
	}
}

// The directory down: the claims are skipped, never cleared.
func TestClaimDirectoryDownKeepsValues(t *testing.T) {
	f, people, store := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	before := len(store.calls())
	people.set(func(p *fakePeople) { p.err = fmt.Errorf("down") })
	rep := deliverNow(t, f, claimID, TriggerMembership)
	if u, _ := unit(rep, "claim:"+SettingAttr(claimID, "storage_quota")); u.Skipped != SkipDirectory {
		t.Errorf("unit = %+v", u)
	}
	if n := len(store.calls()) - before; n != 0 {
		t.Errorf("%d writes with the directory down", n)
	}
	if v, _ := store.value("alice", SettingAttr(claimID, "storage_quota")); v != "10" {
		t.Errorf("alice = %q", v)
	}
}

// A setting attribute that exists visible or editable isn't the Hub's:
// refused, nothing written.
func TestClaimVisibleAttributeRefused(t *testing.T) {
	f, _, store := claimFixture(t)
	quota := SettingAttr(claimID, "storage_quota")
	store.mu.Lock()
	store.schema[quota] = lldapAttr(quota, true)
	store.mu.Unlock()
	claimEnable(t, f, claimID)
	rep := deliverNow(t, f, claimID, TriggerRetry)
	if u, _ := unit(rep, "claim:"+quota); u.OK || !strings.Contains(u.Error, "visible") {
		t.Errorf("unit = %+v", u)
	}
	if v, ok := store.value("alice", quota); ok {
		t.Errorf("written into a visible attribute: %q", v)
	}
}

// T18 concern 2: a failed delivery unit is logged (redacted), not only
// shown in the panel.
func TestDeliveryUnitFailureLogged(t *testing.T) {
	f, _, store := claimFixture(t)
	logs := captureLog(t)
	quota := SettingAttr(claimID, "storage_quota")
	store.mu.Lock()
	store.schema[quota] = lldapAttr(quota, true)
	store.mu.Unlock()
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	want := "settings: " + claimID + ": delivery unit claim:" + quota + " failed: LLDAP attribute " + quota
	if got := logs.String(); !strings.Contains(got, want) {
		t.Errorf("log lacks %q:\n%s", want, got)
	}
}

func TestDeleteRemovesClaims(t *testing.T) {
	f, people, store := claimFixture(t)
	people.addGroup("users_immich-b", "alice")
	people.addGroup("admin_immich-b")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_immich": true, "admin_immich": true, "users_immich-b": true, "admin_immich-b": true}})
	if err := f.h.CreateInstance(claimID, "immich-b", nil); err != nil {
		t.Fatal(err)
	}
	claimEnable(t, f, claimID)
	claimEnable(t, f, "immich-b")
	deliverNow(t, f, claimID, TriggerRetry)
	deliverNow(t, f, "immich-b", TriggerRetry)
	mine := []string{SettingAttr(claimID, "role"), SettingAttr(claimID, "storage_quota")}
	sort.Strings(mine)
	theirs := []string{SettingAttr("immich-b", "role"), SettingAttr("immich-b", "storage_quota")}
	for _, a := range append(append([]string{}, mine...), theirs...) {
		if _, ok := store.has(a); !ok {
			t.Fatalf("attribute %s not created", a)
		}
	}
	if len(f.idp.settingClaims("immich-b")) != 2 {
		t.Fatalf("immich-b claims = %+v", f.idp.settingClaims("immich-b"))
	}

	if _, err := f.h.DeleteInstance(claimID, claimID, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	for _, a := range mine {
		if _, ok := store.has(a); ok {
			t.Errorf("attribute %s of the deleted instance kept", a)
		}
	}
	store.mu.Lock()
	deleted := append([]string(nil), store.deleted...)
	store.mu.Unlock()
	if !reflect.DeepEqual(deleted, mine) {
		t.Errorf("DeleteUserAttribute calls = %v, want %v", deleted, mine)
	}
	if got := f.idp.claimRemovals(); len(got) != 1 || got[0] != "immich:immich:"+strings.Join(mine, ",") {
		t.Errorf("mapper removals = %q", got)
	}
	// The other instance keeps its own.
	for _, a := range theirs {
		if _, ok := store.has(a); !ok {
			t.Errorf("attribute %s of immich-b removed", a)
		}
	}
	if len(f.idp.settingClaims("immich-b")) != 2 {
		t.Errorf("immich-b claims = %+v", f.idp.settingClaims("immich-b"))
	}
	if v, _ := store.value("alice", SettingAttr("immich-b", "storage_quota")); v != "10" {
		t.Errorf("alice's immich-b quota = %q", v)
	}
}

// A client the instance doesn't own keeps its mappers (warning); the
// delete goes on.
func TestDeleteClaimsForeignClientWarns(t *testing.T) {
	f, _, _ := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	f.idp.mu.Lock()
	f.idp.claimOwners = map[string]string{"immich": "someone"}
	f.idp.mu.Unlock()
	res, err := f.h.DeleteInstance(claimID, claimID, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "setting claims") {
		t.Errorf("warnings = %q", res.Warnings)
	}
}

const nativeID = "nativeapp"

func TestNativeSignInClearsPersonDeliveries(t *testing.T) {
	m := mustRead(t, filepath.Join("testdata", "settings", "nativeapp", "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", "nativeapp", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{nativeID: {string(m), string(c)}})
	if f.h.Template(nativeID) == nil {
		t.Fatalf("nativeapp not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople()
	people.addGroup("users_nativeapp", "alice", "bob")
	f.h.SetPeople(people)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	if err := f.h.Enable(nativeID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	deliverNow(t, f, nativeID, TriggerRetry)
	if d := readDoc(t, f.appFile(nativeID, "people")); len(d.People) != 2 {
		t.Fatalf("gateway sign-in: people = %v", d.People)
	}
	execs := len(f.engine.ExecCalls())

	if err := f.h.save(nativeID, SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	rep := deliverNow(t, f, nativeID, TriggerMembership)
	if d := readDoc(t, f.appFile(nativeID, "people")); len(d.People) != 0 {
		t.Errorf("native sign-in: people = %v", d.People)
	}
	runs := hookRuns(t, f, "/apply", execs)
	if len(runs) == 0 || len(runs[len(runs)-1].People) != 0 {
		t.Errorf("hook people after native sign-in = %+v", runs)
	}
	// The reason is the panel's population (never a unit message).
	for _, name := range []string{"file:people", "hook:apply"} {
		if u, ok := unit(rep, name); !ok || u.Message == WhyNativeSignIn {
			t.Errorf("%s = %+v (%v)", name, u, ok)
		}
	}
	p, err := f.h.SettingsPanel(context.Background(), nativeID)
	if err != nil || p.Population.Why != WhyNativeSignIn || p.Population.Count != 0 {
		t.Errorf("panel population = %+v, %v; want the reason %q", p.Population, err, WhyNativeSignIn)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func reservedAttrPrefix() string { return directory.ReservedAttrPrefix }

func lldapAttr(name string, visible bool) lldap.Attribute {
	return lldap.Attribute{Name: name, IsVisible: visible}
}

// A brand-new attribute: nobody can hold a value — no clearing calls, no
// holders query; only the people who get a value are written.
func TestClaimNewAttributeNoSweep(t *testing.T) {
	f, _, store := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	store.mu.Lock()
	lists := store.lists
	store.mu.Unlock()
	if lists != 0 {
		t.Errorf("%d holders queries for new attributes", lists)
	}
	for _, c := range store.calls() {
		if strings.Contains(c, " -") {
			t.Errorf("a removal for a new attribute: %q", c)
		}
	}
	// The enable's delivery wrote the four members (default config), the
	// save alice's new quota: nothing else.
	if n := len(store.calls()); n != 5 {
		t.Errorf("writes = %q", store.calls())
	}
	// Recorded as soon as they exist (known, so never swept again).
	d := f.h.loadDelivered(claimID)
	for _, a := range []string{SettingAttr(claimID, "role"), SettingAttr(claimID, "storage_quota")} {
		if d.Claims["claim:"+a] == nil {
			t.Errorf("no record for %s", a)
		}
	}
}

// A lost record: one holders query; holders outside the population are
// cleared, holders inside rewritten, nobody else touched.
func TestClaimLostRecordQueriesHolders(t *testing.T) {
	f, _, store := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	quota := SettingAttr(claimID, "storage_quota")
	if err := store.SetUserAttributes(context.Background(), "erin", map[string][]string{quota: {"7"}}, nil); err != nil {
		t.Fatal(err)
	}
	d := f.h.loadDelivered(claimID)
	delete(d.Claims, "claim:"+quota)
	f.h.saveDelivered(claimID, d)
	before := len(store.calls())
	deliverNow(t, f, claimID, TriggerRetry)
	calls := store.calls()[before:]
	want := []string{"alice +" + quota + "=10", "bob +" + quota + "=100", "carol +" + quota + "=100", "dave +" + quota + "=100", "erin -" + quota}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("writes = %q, want %q", calls, want)
	}
}

// The start never waits for the claims: they run in the background after
// the up (gated: the enable's own run finds the instance busy or not yet
// enabled, and a normal delivery follows).
func TestStartDoesNotWaitOnClaims(t *testing.T) {
	f, _, store := claimFixture(t)
	gate := make(chan struct{})
	f.idp.mu.Lock()
	f.idp.claimGate = gate
	f.idp.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := f.h.EnableAs(claimID, directory.Human("root"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		close(gate)
		t.Fatal("the enable waited for the claims")
	}
	close(gate)
	// Only the timers: the delivery queued by the background run.
	settle(f)
	if v, _ := store.value("bob", SettingAttr(claimID, "role")); v != "admin" {
		t.Errorf("bob's role = %q", v)
	}
	if u := f.h.DeliveryStatus(claimID).Units["claim:"+SettingAttr(claimID, "role")]; !u.OK {
		t.Errorf("status = %+v", u)
	}
}

// The background claims run writes nothing for a disabled, restoring or
// deleting instance, and re-queues a normal delivery while it is busy.
func TestClaimsAfterStartGated(t *testing.T) {
	f, _, store := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	before, ensures := len(store.calls()), len(f.idp.claimAllCalls())
	quiet := func(name string) {
		t.Helper()
		if err := f.h.runClaimsOnly(context.Background(), claimID); err != nil {
			t.Fatal(err)
		}
		f.h.Wait()
		if n := len(store.calls()) - before; n != 0 {
			t.Errorf("%s: %d LLDAP writes", name, n)
		}
		if n := len(f.idp.claimAllCalls()) - ensures; n != 0 {
			t.Errorf("%s: %d Keycloak ensures", name, n)
		}
	}
	// Something to write if the run went ahead: carol's quota changes.
	f.h.SetPeople(f.h.people)
	people := f.h.people.(*fakePeople)
	people.addGroup("office_milan", "carol")

	f.h.mu.Lock()
	f.h.st.SetEnabled(claimID, false)
	f.h.mu.Unlock()
	quiet("disabled")
	f.h.mu.Lock()
	f.h.st.SetEnabled(claimID, true)
	e := f.h.st.Instances[claimID]
	e.ID, e.Template, e.State = claimID, claimID, state.InstanceRestoring
	f.h.st.Instances[claimID] = e
	f.h.mu.Unlock()
	quiet("restoring")
	f.h.mu.Lock()
	e.State = state.InstanceDeleting
	f.h.st.Instances[claimID] = e
	f.h.mu.Unlock()
	quiet("deleting")
	f.h.mu.Lock()
	e.State = ""
	f.h.st.Instances[claimID] = e
	f.h.mu.Unlock()

	unlock, err := f.h.lockApp(claimID)
	if err != nil {
		t.Fatal(err)
	}
	quiet("busy")
	unlock()
	f.h.deliveryMu.Lock()
	q := f.h.queued[claimID]
	f.h.deliveryMu.Unlock()
	if q == nil {
		t.Error("busy: no delivery re-queued")
	}
}

// A delete that lands while the background claims run waits for the
// delivery lock leaves no attribute and no mapper behind.
func TestDeleteWhileClaimsWaitLeavesNothing(t *testing.T) {
	f, _, store := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	l := f.h.deliverLock(claimID)
	l.Lock()
	f.h.deliverClaimsAfterStart(claimID) // waits on the lock
	delDone := make(chan error, 1)
	go func() {
		_, err := f.h.DeleteInstance(claimID, claimID, directory.Human("root"))
		delDone <- err
	}()
	// Step 4 (the claims cleanup) takes the delivery lock too: the
	// delete waits for any run mid-write.
	time.Sleep(200 * time.Millisecond)
	store.mu.Lock()
	n := len(store.deleted)
	store.mu.Unlock()
	if n != 0 {
		t.Errorf("step 4 ran while a delivery held the lock (%d deleted)", n)
	}
	ensures := len(f.idp.claimAllCalls())
	l.Unlock()
	if err := <-delDone; err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	for _, a := range []string{SettingAttr(claimID, "role"), SettingAttr(claimID, "storage_quota")} {
		if _, ok := store.has(a); ok {
			t.Errorf("attribute %s re-created after the delete", a)
		}
	}
	if n := len(f.idp.claimAllCalls()) - ensures; n != 0 {
		t.Errorf("%d mapper ensures after the delete's step 4", n)
	}
}

// A claim moved from one client to another leaves no mapper behind on
// the first (every client gets its exact set, none included).
func TestClaimMovedClientLeavesNoMapper(t *testing.T) {
	twoClients := func(m string) string {
		return strings.Replace(m, "keycloak_clients:\n  - client_id: immich\n    redirect_uri: https://{{HOST_IMMICH}}/auth/login\n",
			"keycloak_clients:\n  - client_id: immich\n    redirect_uri: https://{{HOST_IMMICH}}/auth/login\n  - client_id: immich-web\n    redirect_uri: https://{{HOST_IMMICH}}/web/login\n", 1)
	}
	f, _, _ := claimFixtureWith(t, twoClients)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	if n := len(f.idp.settingClaims("immich")); n != 2 {
		t.Fatalf("immich claims = %+v", f.idp.settingClaims("immich"))
	}
	// A template update moves both claims to immich-web: immich has
	// none left, and must lose its mappers.
	m := twoClients(string(mustRead(t, filepath.Join("testdata", "settings", "claimapp", "manifest.yaml"))))
	m = strings.Replace(m, "{claim: {client: immich, name: immich_role}}", "{claim: {client: immich-web, name: immich_role}}", 1)
	m = strings.Replace(m, "{claim: {client: immich, name: immich_quota,", "{claim: {client: immich-web, name: immich_quota,", 1)
	writeFile(t, filepath.Join(f.src, claimID, "manifest.yaml"), m)
	f.h.Discover()
	deliverNow(t, f, claimID, TriggerRetry)
	if got := f.idp.settingClaims("immich"); len(got) != 0 {
		t.Errorf("mappers stayed on immich: %+v", got)
	}
	if got := f.idp.settingClaims("immich-web"); len(got) != 2 {
		t.Errorf("immich-web claims = %+v", got)
	}
	// A client with no claims that isn't the instance's: logged only.
	f.idp.mu.Lock()
	f.idp.claimOwners = map[string]string{"immich": "someone"}
	f.idp.mu.Unlock()
	rep := deliverNow(t, f, claimID, TriggerRetry)
	for _, a := range []string{SettingAttr(claimID, "role"), SettingAttr(claimID, "storage_quota")} {
		if u, _ := unit(rep, "claim:"+a); !u.OK {
			t.Errorf("claim:%s = %+v (a conflict on a client without claims failed it)", a, u)
		}
	}
}

// A value its json_type can't take is omitted (cleared) and counted.
func TestClaimValueMustFitJSONType(t *testing.T) {
	withUploads := func(m string) string {
		return m + `    - key: uploads
      label: Uploads
      type: int
      scope: person
      default: 5
      resolve: max
      applies: next_sign_in
      delivery: [{claim: {client: immich, name: immich_uploads, json_type: int}}]
`
	}
	f, _, store := claimFixtureWith(t, withUploads)
	claimEnable(t, f, claimID)
	if _, err := f.h.SaveSettings(claimID, SettingsUpdate{Person: map[string]PersonChange{
		"uploads": {Default: raw(5), Rows: rows("office_milan", 3000000000)},
	}}, "admin"); err != nil {
		t.Fatal(err)
	}
	rep := deliverNow(t, f, claimID, TriggerRetry)
	a := SettingAttr(claimID, "uploads")
	if v, ok := store.value("alice", a); ok {
		t.Errorf("alice got %q, over int32", v)
	}
	if v, _ := store.value("bob", a); v != "5" {
		t.Errorf("bob = %q", v)
	}
	if u, _ := unit(rep, "claim:"+a); !u.OK || !strings.Contains(u.Message, "1 values can't be delivered") {
		t.Errorf("unit = %+v", u)
	}
	if err := claimValueFits("bool", "1"); err == nil {
		t.Error("bool 1 accepted")
	}
	if err := claimValueFits("json", "a,b"); err == nil {
		t.Error("json a,b accepted")
	}
	if err := claimValueFits("json", `["a","b"]`); err != nil {
		t.Error(err)
	}
}

// Missing LLDAP credentials: "Users & Groups not configured".
func TestClaimStoreNotConfigured(t *testing.T) {
	f, _, store := claimFixture(t)
	claimEnable(t, f, claimID)
	store.mu.Lock()
	store.err = fmt.Errorf("reading: %w", lldap.ErrNotConfigured)
	store.mu.Unlock()
	rep := deliverNow(t, f, claimID, TriggerRetry)
	if u, _ := unit(rep, "claim:"+SettingAttr(claimID, "role")); !strings.Contains(u.Error, "Users & Groups not configured") {
		t.Errorf("unit = %+v", u)
	}
}

// A claim stays in the ensure set only when its attribute exists and its
// values were reconciled: an attribute that can't be (re-)created, or
// whose writes fail, loses its mapper; the reconciled one keeps its own.
func TestClaimUnreconciledDropsMapper(t *testing.T) {
	f, people, store := claimFixture(t)
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	role, quota := SettingAttr(claimID, "role"), SettingAttr(claimID, "storage_quota")
	has := func(a string) bool {
		for _, c := range f.idp.settingClaims("immich") {
			if c.Attr == a {
				return true
			}
		}
		return false
	}
	// The quota attribute vanished and can't be re-created.
	store.mu.Lock()
	delete(store.schema, quota)
	store.failAdd = true
	store.mu.Unlock()
	deliverNow(t, f, claimID, TriggerRetry)
	if !has(role) || has(quota) {
		t.Errorf("after a failed create: claims = %+v", f.idp.settingClaims("immich"))
	}
	store.mu.Lock()
	store.failAdd = false
	store.mu.Unlock()
	deliverNow(t, f, claimID, TriggerRetry)
	if !has(role) || !has(quota) {
		t.Fatalf("after recovery: claims = %+v", f.idp.settingClaims("immich"))
	}
	// A value write fails (dave joins office_milan, his write fails):
	// the quota mapper goes until a run reconciles it.
	people.addGroup("office_milan", "dave")
	store.mu.Lock()
	store.failUser = "dave"
	store.mu.Unlock()
	rep := deliverNow(t, f, claimID, TriggerMembership)
	if !has(role) || has(quota) {
		t.Errorf("after a failed write: claims = %+v", f.idp.settingClaims("immich"))
	}
	if u, _ := unit(rep, "claim:"+quota); u.OK {
		t.Errorf("quota unit = %+v", u)
	}
	store.mu.Lock()
	store.failUser = ""
	store.mu.Unlock()
	deliverNow(t, f, claimID, TriggerMembership)
	if !has(quota) {
		t.Errorf("after the retry: claims = %+v", f.idp.settingClaims("immich"))
	}
}

// A non-conflict error on a client without claims (a stale mapper may
// stay there) fails the units, retried; a conflict is only logged.
func TestClaimClientlessErrorFails(t *testing.T) {
	twoClients := func(m string) string {
		return strings.Replace(m, "keycloak_clients:\n  - client_id: immich\n    redirect_uri: https://{{HOST_IMMICH}}/auth/login\n",
			"keycloak_clients:\n  - client_id: immich\n    redirect_uri: https://{{HOST_IMMICH}}/auth/login\n  - client_id: immich-web\n    redirect_uri: https://{{HOST_IMMICH}}/web/login\n", 1)
	}
	f, _, _ := claimFixtureWith(t, twoClients)
	claimEnable(t, f, claimID)
	f.idp.mu.Lock()
	f.idp.claimFail = map[string]error{"immich-web": fmt.Errorf("keycloak 500")}
	f.idp.mu.Unlock()
	rep := deliverNow(t, f, claimID, TriggerRetry)
	if u, _ := unit(rep, "claim:"+SettingAttr(claimID, "role")); u.OK || !strings.Contains(u.Error, "immich-web") {
		t.Errorf("unit = %+v", u)
	}
	f.idp.mu.Lock()
	f.idp.claimFail = map[string]error{"immich-web": &keycloak.ConflictError{ClientID: "immich-web", Owner: "x"}}
	f.idp.mu.Unlock()
	rep = deliverNow(t, f, claimID, TriggerRetry)
	if u, _ := unit(rep, "claim:"+SettingAttr(claimID, "role")); !u.OK {
		t.Errorf("conflict on a claim-less client: unit = %+v", u)
	}
}

// After a same-instance restore the claims follow the restored settings,
// driven only by the timers (no stale value stays behind the mappers).
func TestClaimsAfterRestore(t *testing.T) {
	f, _, store := claimFixture(t)
	claimEnable(t, f, claimID)
	quota := SettingAttr(claimID, "storage_quota")
	if v, _ := store.value("alice", quota); v != "10" {
		t.Fatalf("alice = %q", v)
	}
	entry, err := f.h.BackupInstance(claimID, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	settle(f)
	if _, err := f.h.SaveSettings(claimID, SettingsUpdate{Person: map[string]PersonChange{
		"storage_quota": {Default: raw("100GiB"), Rows: rows("office_milan", "20GiB")},
	}}, "admin"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if v, _ := store.value("alice", quota); v != "20" {
		t.Fatalf("alice after the save = %q", v)
	}
	if _, err := f.h.RestoreInstance(claimID, entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	settle(f)
	if v, _ := store.value("alice", quota); v != "10" {
		t.Errorf("alice after the restore = %q, want the restored 10", v)
	}
}

// LLDAP unreadable: the mappers of claims whose desired values changed
// since the last successful record go; unchanged ones stay.
func TestClaimSchemaFailureDropsChangedMappers(t *testing.T) {
	f, people, store := claimFixture(t)
	claimEnable(t, f, claimID)
	role, quota := SettingAttr(claimID, "role"), SettingAttr(claimID, "storage_quota")
	people.addGroup("office_milan", "carol") // carol's quota changes
	store.mu.Lock()
	store.failSchema = true
	store.mu.Unlock()
	rep := deliverNow(t, f, claimID, TriggerMembership)
	if u, _ := unit(rep, "claim:"+quota); u.OK {
		t.Errorf("unit = %+v", u)
	}
	got := f.idp.settingClaims("immich")
	if len(got) != 1 || got[0].Attr != role {
		t.Errorf("claims with LLDAP unreadable = %+v, want role only", got)
	}
	store.mu.Lock()
	store.failSchema = false
	store.mu.Unlock()
	deliverNow(t, f, claimID, TriggerMembership)
	if n := len(f.idp.settingClaims("immich")); n != 2 {
		t.Errorf("after recovery: %+v", f.idp.settingClaims("immich"))
	}
	if v, _ := store.value("carol", quota); v != "10" {
		t.Errorf("carol = %q", v)
	}
}
