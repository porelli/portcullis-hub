package hub

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
)

// Person-entered values (Task 15A, spec call 32).

const (
	entryID  = "entryapp"
	entryEnv = "entryenv"
	aliceExt = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	bobExt   = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
)

// entryFixture loads testdata/settings/entryapp (method custom, no
// Portcullis identity, access group entryapp; ext_id: unique,
// admin_override, file ids with on_membership_change restart; nick: hook
// apply on membership_change; motd: an instance option) and entryenv
// (ext_id as env EXT_IDS joined with ","). alice and bob are in entryapp
// and entryenv, carol in neither. entryapp is enabled and running;
// entryenv is not enabled.
func entryFixture(t *testing.T) (*fixture, *fakePeople, *fakeClock, *fakeAudit) {
	t.Helper()
	extra := map[string][2]string{}
	for _, id := range []string{entryID, entryEnv} {
		m := mustRead(t, filepath.Join("testdata", "settings", id, "manifest.yaml"))
		c := mustRead(t, filepath.Join("testdata", "settings", id, "compose.yml"))
		extra[id] = [2]string{string(m), string(c)}
	}
	f := newInstanceFixtureExtra(t, nil, nil, extra)
	for _, id := range []string{entryID, entryEnv} {
		if f.h.Template(id) == nil {
			t.Fatalf("%s fixture not loaded (see the log)", id)
		}
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	people := newFakePeople("carol")
	people.addGroup(entryID, "alice", "bob")
	people.addGroup(entryEnv, "alice", "bob")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{entryID: true, entryEnv: true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	if err := f.h.Enable(entryID); err != nil {
		t.Fatal(err)
	}
	settle(f)
	return f, people, clk, audit
}

// setEntry is SetPersonValue with ctx and v marshalled.
func setEntry(f *fixture, id, key, user string, v any, actor string) (*MyEntry, error) {
	return f.h.SetPersonValue(context.Background(), id, key, user, raw(v), actor)
}

func mustSetEntry(t *testing.T, f *fixture, id, key, user string, v any, actor string) *MyEntry {
	t.Helper()
	e, err := setEntry(f, id, key, user, v, actor)
	if err != nil {
		t.Fatalf("%s sets %s/%s for %s: %v", actor, id, key, user, err)
	}
	return e
}

// entriesOf is the ids.json entries of key.
func entriesOf(t *testing.T, f *fixture, key string) []settings.EntryOut {
	t.Helper()
	return readDoc(t, f.appFile(entryID, "ids")).Entries[key]
}

func entryUsers(es []settings.EntryOut) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.User)
	}
	return out
}

// restartsOf counts instance id's compose downs (Restart = down + up).
func restartsOf(f *fixture, id string) int {
	n := 0
	for _, c := range f.runner.Calls() {
		if c == "down:"+ProjectPrefix+id {
			n++
		}
	}
	return n
}

func myEntry(a *MyApp, key string) *MyEntry {
	if a == nil {
		return nil
	}
	for i := range a.Entries {
		if a.Entries[i].Key == key {
			return &a.Entries[i]
		}
	}
	return nil
}

func storeEntryDirect(f *fixture, id, key, user string, v any, uuid string) {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	s := f.h.st.Settings[id].Clone()
	if s.Entered == nil {
		s.Entered = map[string]map[string]state.EnteredValue{}
	}
	if s.Entered[key] == nil {
		s.Entered[key] = map[string]state.EnteredValue{}
	}
	s.Entered[key][user] = state.EnteredValue{Value: v, UUID: uuid, UpdatedAt: time.Now().UTC()}
	f.h.st.Settings[id] = s
}

func TestSetOwnValue(t *testing.T) {
	f, people, _, audit := entryFixture(t)
	e := mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	if e.Value != aliceExt || e.SetByAdmin || e.UpdatedAt == nil {
		t.Errorf("answer = %+v", e)
	}
	got := storedSettings(f, entryID).Entered["ext_id"]["alice"]
	if got.Value != aliceExt || got.UUID != people.uuidOf("alice") || got.SetBy != "" || got.UpdatedAt.IsZero() {
		t.Errorf("stored = %+v", got)
	}
	a := myApp(myApps(t, f, "alice"), entryID)
	me := myEntry(a, "ext_id")
	if me == nil || me.Value != aliceExt || me.Display != aliceExt || me.Input.Pattern != "^[0-9a-f]{32}$" || !me.Unique || me.Input.Type != "string" || me.Applies != "restart" {
		t.Fatalf("My apps entry = %+v (app %+v)", me, a)
	}
	if n := myEntry(a, "nick"); n == nil || n.Value != nil || n.Input.MaxLen == nil || *n.Input.MaxLen != 20 {
		t.Errorf("nick = %+v, want an unset entry with max_len 20", n)
	}
	pv := auditsOf(audit, "settings.person_value")
	if len(pv) != 1 || pv[0].Target != "entryapp/ext_id/alice" || pv[0].Actor != "alice" || pv[0].Detail != "set: unset -> "+aliceExt || pv[0].Result != "ok" {
		t.Errorf("audit = %+v", pv)
	}
	// The same value again: nothing stored, nothing audited.
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	if !storedSettings(f, entryID).Entered["ext_id"]["alice"].UpdatedAt.Equal(got.UpdatedAt) || len(auditsOf(audit, "settings.person_value")) != 1 {
		t.Error("an unchanged value was stored or audited again")
	}
}

func TestEntryValidation(t *testing.T) {
	f, _, _, audit := entryFixture(t)
	for _, c := range []struct{ v, want string }{
		{strings.ToUpper(aliceExt), "pattern"},
		{aliceExt[:31], "pattern"},
		{"\x01" + aliceExt[1:], "control"},
	} {
		_, err := setEntry(f, entryID, "ext_id", "alice", c.v, "alice")
		if statusOf(err) != 400 || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want 400 naming %s", c.v, err, c.want)
		}
	}
	if len(storedSettings(f, entryID).Entered) != 0 {
		t.Errorf("stored = %+v", storedSettings(f, entryID).Entered)
	}
	pv := auditsOf(audit, "settings.person_value")
	if len(pv) != 3 || pv[0].Result != "refused" {
		t.Errorf("audit = %+v", pv)
	}
	// null is no value: DELETE clears.
	if _, err := f.h.SetPersonValue(context.Background(), entryID, "ext_id", "alice", json.RawMessage("null"), "alice"); statusOf(err) != 400 {
		t.Errorf("null = %v", err)
	}
}

func TestEntryPopulationOnly(t *testing.T) {
	f, _, _, _ := entryFixture(t)
	for _, c := range []struct{ id, key, user string }{
		{entryID, "ext_id", "carol"},  // not in the population
		{entryID, "nope", "alice"},    // unknown key
		{entryID, "motd", "alice"},    // an instance option
		{entryEnv, "ext_id", "alice"}, // a disabled instance
		{"ghost", "ext_id", "alice"},  // no such instance
	} {
		_, err := setEntry(f, c.id, c.key, c.user, aliceExt, c.user)
		if statusOf(err) != 404 || err.Error() != errNoEntry.Error() {
			t.Errorf("%+v: %v, want the one 404", c, err)
		}
	}
	if a := myApp(myApps(t, f, "carol"), entryID); a != nil {
		t.Errorf("carol sees %+v", a)
	}
	// An app whose only per-person part is an entry is listed.
	if a := myApp(myApps(t, f, "alice"), entryID); a == nil || len(a.Values) != 0 || len(a.Entries) != 2 {
		t.Errorf("alice's entryapp = %+v", a)
	}
}

func TestEntryUnique(t *testing.T) {
	f, _, _, audit := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	_, err := setEntry(f, entryID, "ext_id", "bob", aliceExt, "bob")
	if statusOf(err) != 409 || strings.Contains(strings.ToLower(err.Error()), "alice") || !strings.Contains(err.Error(), "by another person") {
		t.Fatalf("bob = %v, want a 409 without the holder", err)
	}
	pv := auditsOf(audit, "settings.person_value")
	last := pv[len(pv)-1]
	if last.Actor != "bob" || last.Result != "refused" || !strings.Contains(last.Detail+last.Error, "alice") {
		t.Errorf("refusal audit = %+v", last)
	}
	mustSetEntry(t, f, entryID, "ext_id", "bob", bobExt, "bob")
	// Values compare in canonical form: the nick is not unique.
	mustSetEntry(t, f, entryID, "nick", "alice", "same", "alice")
	mustSetEntry(t, f, entryID, "nick", "bob", "same", "bob")
}

func TestEntryUniqueRace(t *testing.T) {
	f, _, _, _ := entryFixture(t)
	const v = "cccccccccccccccccccccccccccccccc"
	for range 20 {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, u := range []string{"alice", "bob"} {
			wg.Add(1)
			go func() { defer wg.Done(); _, errs[i] = setEntry(f, entryID, "ext_id", u, v, u) }()
		}
		wg.Wait()
		ok, conflict := 0, 0
		for _, err := range errs {
			switch statusOf(err) {
			case 0:
				ok++
			case 409:
				conflict++
			}
		}
		n := 0
		for _, e := range storedSettings(f, entryID).Entered["ext_id"] {
			if e.Value == v {
				n++
			}
		}
		if ok != 1 || conflict != 1 || n != 1 {
			t.Fatalf("ok %d, 409 %d, stored %d (%v)", ok, conflict, n, errs)
		}
		for _, u := range []string{"alice", "bob"} {
			if err := f.h.ClearPersonValue(context.Background(), entryID, "ext_id", u, u); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestEntryUniqueCountsUndelivered(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	people.removeMember(entryID, "alice")
	if _, err := setEntry(f, entryID, "ext_id", "bob", aliceExt, "bob"); statusOf(err) != 409 {
		t.Errorf("bob = %v, want 409 (alice's stored value still holds it)", err)
	}
}

func TestEntriesDataFile(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "bob", bobExt, "bob")
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	storeEntryDirect(f, entryID, "ext_id", "carol", "dddddddddddddddddddddddddddddddd", people.uuidOf("carol"))
	deliverNow(t, f, entryID, TriggerMembership)
	d := readDoc(t, f.appFile(entryID, "ids"))
	want := []settings.EntryOut{{User: "alice", Value: aliceExt}, {User: "bob", Value: bobExt}}
	if !reflect.DeepEqual(d.Entries["ext_id"], want) {
		t.Errorf("entries.ext_id = %+v, want %+v", d.Entries["ext_id"], want)
	}
	if len(d.People) != 0 {
		t.Errorf("people = %+v, want none (person-entered values are never under people)", d.People)
	}
	if _, ok := d.Entries["nick"]; ok {
		t.Errorf("nick is not delivered to ids: %+v", d.Entries)
	}
	b, _ := os.ReadFile(f.appFile(entryID, "ids"))
	if strings.Contains(string(b), "carol") || strings.Contains(string(b), "dddd") {
		t.Errorf("carol's value delivered:\n%s", b)
	}
	// delivered.json: hashes only (P13).
	dj, _ := os.ReadFile(filepath.Join(f.data, "settings", entryID, "delivered.json"))
	if strings.Contains(string(dj), aliceExt) {
		t.Errorf("delivered.json holds a value: %s", dj)
	}
}

func TestLeaveRemovesFromDelivery(t *testing.T) {
	f, people, clk, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	mustSetEntry(t, f, entryID, "ext_id", "bob", bobExt, "bob")
	settle(f)
	if got := entryUsers(entriesOf(t, f, "ext_id")); strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("before = %v", got)
	}
	before := restartsOf(f, entryID)
	people.removeMember(entryID, "alice")
	f.h.TriggerMembershipDelivery()
	if ts := clk.pending(); len(ts) != 1 || ts[0].d != settingsDebounce {
		t.Fatalf("armed timers = %d, want one debounced", len(ts))
	}
	settle(f)
	if got := entryUsers(entriesOf(t, f, "ext_id")); strings.Join(got, ",") != "bob" {
		t.Errorf("after leaving = %v, want bob only", got)
	}
	if n := restartsOf(f, entryID) - before; n != 1 {
		t.Errorf("restarts = %d, want 1", n)
	}
	if storedSettings(f, entryID).Entered["ext_id"]["alice"].Value != aliceExt {
		t.Error("alice's value was dropped on leaving")
	}
	p, err := f.h.SettingsPanel(context.Background(), entryID)
	if err != nil {
		t.Fatal(err)
	}
	var row *EntryRow
	for i, r := range p.Entries["ext_id"].Rows {
		if r.User == "alice" {
			row = &p.Entries["ext_id"].Rows[i]
		}
	}
	if row == nil || row.Delivered || row.Why != EntryWhyNoAccess {
		t.Errorf("alice's row = %+v", row)
	}
	// She rejoins: delivered again, no re-entry.
	people.addGroup(entryID, "alice")
	f.h.TriggerMembershipDelivery()
	settle(f)
	if got := entryUsers(entriesOf(t, f, "ext_id")); strings.Join(got, ",") != "alice,bob" {
		t.Errorf("after rejoining = %v", got)
	}
}

func TestEntryChangesDebounced(t *testing.T) {
	f, people, clk, _ := entryFixture(t)
	users := []string{"alice", "bob", "dan", "erin", "frank"}
	people.addGroup(entryID, users...)
	before := restartsOf(f, entryID)
	for i, u := range users {
		mustSetEntry(t, f, entryID, "ext_id", u, strings.Repeat(string("abcde"[i]), 32), u)
	}
	if ts := clk.pending(); len(ts) != 1 || ts[0].d != settingsDebounce {
		t.Fatalf("armed timers = %d, want one debounced run", len(ts))
	}
	settle(f)
	if got := entryUsers(entriesOf(t, f, "ext_id")); len(got) != 5 {
		t.Errorf("entries = %v", got)
	}
	if n := restartsOf(f, entryID) - before; n != 1 {
		t.Errorf("restarts = %d, want 1", n)
	}
}

func TestEntryHook(t *testing.T) {
	f, _, _, _ := entryFixture(t)
	before := restartsOf(f, entryID)
	n := len(f.engine.ExecCalls())
	mustSetEntry(t, f, entryID, "nick", "alice", "Ali", "alice")
	settle(f)
	runs := hookRuns(t, f, "/apply", n)
	if len(runs) != 1 {
		t.Fatalf("apply ran %d times", len(runs))
	}
	if want := []settings.EntryOut{{User: "alice", Value: "Ali"}}; !reflect.DeepEqual(runs[0].Entries["nick"], want) || runs[0].Trigger != "membership_change" {
		t.Errorf("stdin = %+v (trigger %s)", runs[0].Entries, runs[0].Trigger)
	}
	if _, ok := runs[0].Entries["ext_id"]; ok {
		t.Error("ext_id sent to the hook")
	}
	if n := restartsOf(f, entryID) - before; n != 0 {
		t.Errorf("restarts = %d, want 0 (applies live)", n)
	}
}

func TestEntryEnvList(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	if err := f.h.Enable(entryEnv); err != nil {
		t.Fatal(err)
	}
	settle(f)
	mustSetEntry(t, f, entryEnv, "ext_id", "bob", bobExt, "bob")
	mustSetEntry(t, f, entryEnv, "ext_id", "alice", aliceExt, "alice")
	settle(f)
	if want := "EXT_IDS='" + aliceExt + "," + bobExt + "'"; !strings.Contains(envOf(t, f, entryEnv), want) {
		t.Errorf(".env lacks %s:\n%s", want, envOf(t, f, entryEnv))
	}
	if strings.Contains(envOf(t, f, entryEnv), "alice") {
		t.Error("the env names people")
	}
	before := restartsOf(f, entryEnv)
	people.removeMember(entryEnv, "alice")
	f.h.TriggerMembershipDelivery()
	settle(f)
	if want := "EXT_IDS='" + bobExt + "'"; !strings.Contains(envOf(t, f, entryEnv), want) {
		t.Errorf(".env lacks %s:\n%s", want, envOf(t, f, entryEnv))
	}
	if n := restartsOf(f, entryEnv) - before; n != 1 {
		t.Errorf("restarts = %d, want 1", n)
	}
	// A save of an instance option keeps the engine's list (P12).
	f.h.mu.Lock()
	err := f.h.generateAppEnvLocked(f.h.findLocked(entryEnv), nil)
	f.h.mu.Unlock()
	if err != nil || !strings.Contains(envOf(t, f, entryEnv), "EXT_IDS='"+bobExt+"'") {
		t.Errorf("generateAppEnvLocked touched EXT_IDS (%v):\n%s", err, envOf(t, f, entryEnv))
	}
}

func TestRecreatedAccountInheritsNoEntry(t *testing.T) {
	f, people, _, audit := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	mustSetEntry(t, f, entryID, "ext_id", "bob", bobExt, "bob")
	settle(f)
	people.recreate("alice")
	people.addGroup(entryID, "alice")
	// From that moment: not hers.
	if me := myEntry(myApp(myApps(t, f, "alice"), entryID), "ext_id"); me == nil || me.Value != nil {
		t.Errorf("the re-created alice sees %+v", me)
	}
	p, err := f.h.SettingsPanel(context.Background(), entryID)
	if err != nil {
		t.Fatal(err)
	}
	if rows := p.Entries["ext_id"].Rows; len(rows) != 2 || rows[0].User != "alice" || rows[0].Delivered || rows[0].Why != EntryWhyAccountChanged {
		t.Errorf("rows = %+v", rows)
	}
	deliverNow(t, f, entryID, TriggerMembership)
	if got := entryUsers(entriesOf(t, f, "ext_id")); strings.Join(got, ",") != "bob" {
		t.Errorf("entries = %v", got)
	}
	if _, ok := storedSettings(f, entryID).Entered["ext_id"]["alice"]; ok {
		t.Error("the old value was not purged")
	}
	var purged []directory.AuditEntry
	for _, e := range auditsOf(audit, "settings.person_value") {
		if e.Detail == "purged" {
			purged = append(purged, e)
		}
	}
	if len(purged) != 1 || purged[0].Actor != "hub" || purged[0].Target != "entryapp/ext_id/alice" {
		t.Errorf("purge audit = %+v", purged)
	}
	// The new alice may enter her own (the old one no longer holds it).
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
}

// The purge is irreversible: only while the LLDAP sanity check passes.
func TestEntryPurgeNeedsSaneLDAP(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	settle(f)
	people.recreate("alice")
	people.set(func(p *fakePeople) { delete(p.users, "admin") }) // LLDAP looks wrong
	deliverNow(t, f, entryID, TriggerMembership)
	if _, ok := storedSettings(f, entryID).Entered["ext_id"]["alice"]; !ok {
		t.Error("purged while LLDAP looks wrong")
	}
	if got := entriesOf(t, f, "ext_id"); len(got) != 0 {
		t.Errorf("delivered = %+v, want nobody (filtered)", got)
	}
}

func TestAccountDeletePurgesEntries(t *testing.T) {
	f, _, _, audit := entryFixture(t)
	ll := lldaptest.New(t, "portcullis-hub", "service-password-0123456789")
	ll.AddUser("root", "root@example.org", "Root", "rootpass-123456", "lldap_admin")
	ll.AddUser("alice", "alice@example.org", "Alice", "")
	ll.AddUser("bob", "bob@example.org", "Bob", "")
	ll.AddGroup(entryID, "alice", "bob")
	ll.AddGroup(entryEnv, "alice", "bob")
	credDir := t.TempDir()
	os.WriteFile(filepath.Join(credDir, "username"), []byte("portcullis-hub\n"), 0600)
	os.WriteFile(filepath.Join(credDir, "password"), []byte("service-password-0123456789\n"), 0600)
	dir := &directory.Service{
		LLDAP: lldap.New(ll.HTTP.URL, ll.LDAPURL(), ll.BaseDN, credDir),
		Audit: &directory.AuditLog{Path: filepath.Join(t.TempDir(), "audit.jsonl")},
		Apps:  f.h.DirectoryApps,
	}
	dir.UserDeleted = f.h.PurgePersonValues
	f.h.SetPeople(dir)
	if err := f.h.Enable(entryEnv); err != nil {
		t.Fatal(err)
	}
	settle(f)
	for _, id := range []string{entryID, entryEnv} {
		mustSetEntry(t, f, id, "ext_id", "alice", aliceExt, "alice")
		mustSetEntry(t, f, id, "ext_id", "bob", bobExt, "bob")
	}
	mustSetEntry(t, f, entryID, "nick", "alice", "Ali", "alice")
	if got := storedSettings(f, entryID).Entered["ext_id"]["alice"].UUID; got == "" || got != ll.UUIDOf("alice") {
		t.Errorf("stored uuid = %q, want LLDAP's %q", got, ll.UUIDOf("alice"))
	}
	settle(f)
	if _, err := dir.DeleteUser(context.Background(), &directory.Caller{User: "root", Admin: true}, "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{entryID, entryEnv} {
		for k, m := range storedSettings(f, id).Entered {
			if _, ok := m["alice"]; ok {
				t.Errorf("%s/%s: alice's value kept", id, k)
			}
		}
		if storedSettings(f, id).Entered["ext_id"]["bob"].Value != bobExt {
			t.Errorf("%s: bob's value dropped", id)
		}
	}
	var deleted []string
	for _, e := range auditsOf(audit, "settings.person_value") {
		if e.Detail == "deleted" {
			if e.Actor != "root" {
				t.Errorf("deleted by %q", e.Actor)
			}
			deleted = append(deleted, e.Target)
		}
	}
	if strings.Join(deleted, ",") != "entryapp/ext_id/alice,entryapp/nick/alice,entryenv/ext_id/alice" {
		t.Errorf("deleted audits = %v", deleted)
	}
	settle(f)
	if got := entryUsers(entriesOf(t, f, "ext_id")); strings.Join(got, ",") != "bob" {
		t.Errorf("delivered after the delete = %v", got)
	}
}

func TestAdminOverrideAndClear(t *testing.T) {
	f, _, _, audit := entryFixture(t)
	if _, err := f.h.SetEntryAsAdmin(context.Background(), entryID, "ext_id", "alice", raw(aliceExt), "root"); err != nil {
		t.Fatal(err)
	}
	if got := storedSettings(f, entryID).Entered["ext_id"]["alice"]; got.SetBy != "root" {
		t.Errorf("set_by = %q", got.SetBy)
	}
	apps := myApps(t, f, "alice")
	me := myEntry(myApp(apps, entryID), "ext_id")
	if me == nil || !me.SetByAdmin || me.Value != aliceExt {
		t.Errorf("alice sees %+v", me)
	}
	if b, _ := json.Marshal(apps); strings.Contains(string(b), "root") {
		t.Errorf("My apps names the admin: %s", b)
	}
	if pv := auditsOf(audit, "settings.person_value"); len(pv) != 1 || pv[0].Actor != "root" {
		t.Errorf("audit = %+v", pv)
	}
	// Without admin_override: 403.
	if _, err := setEntry(f, entryID, "nick", "alice", "Ali", "root"); statusOf(err) != 403 {
		t.Errorf("nick by an admin = %v, want 403", err)
	}
	// Uniqueness applies to admins too.
	if _, err := setEntry(f, entryID, "ext_id", "bob", aliceExt, "root"); statusOf(err) != 409 {
		t.Errorf("admin duplicate = %v, want 409", err)
	}
	// An admin can always clear, even without admin_override.
	mustSetEntry(t, f, entryID, "nick", "alice", "Ali", "alice")
	if err := f.h.ClearPersonValue(context.Background(), entryID, "nick", "alice", "root"); err != nil {
		t.Fatal(err)
	}
	if _, ok := storedSettings(f, entryID).Entered["nick"]["alice"]; ok {
		t.Error("nick not cleared")
	}
}

func TestClearOwnValue(t *testing.T) {
	f, _, _, audit := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	mustSetEntry(t, f, entryID, "ext_id", "bob", bobExt, "bob")
	settle(f)
	if err := f.h.ClearPersonValue(context.Background(), entryID, "ext_id", "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := storedSettings(f, entryID).Entered["ext_id"]["alice"]; ok {
		t.Error("not cleared")
	}
	pv := auditsOf(audit, "settings.person_value")
	if last := pv[len(pv)-1]; last.Detail != "cleared" || last.Actor != "alice" {
		t.Errorf("audit = %+v", last)
	}
	// Nothing set: no error, nothing audited.
	if err := f.h.ClearPersonValue(context.Background(), entryID, "ext_id", "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	if len(auditsOf(audit, "settings.person_value")) != len(pv) {
		t.Error("clearing nothing was audited")
	}
	settle(f)
	if got := entryUsers(entriesOf(t, f, "ext_id")); strings.Join(got, ",") != "bob" {
		t.Errorf("entries = %v", got)
	}
}

func TestEntriesInBackup(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	settle(f)
	entry, err := f.h.BackupInstance(entryID, "root")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.ClearPersonValue(context.Background(), entryID, "ext_id", "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstance(entryID, entry.Archive, "root"); err != nil {
		t.Fatal(err)
	}
	settle(f)
	if got := storedSettings(f, entryID).Entered["ext_id"]["alice"]; got.Value != aliceExt || got.UUID != people.uuidOf("alice") {
		t.Errorf("after restore = %+v", got)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "entryapp2", "root"); err != nil {
		t.Fatal(err)
	}
	if got := storedSettings(f, "entryapp2").Entered["ext_id"]["alice"]; got.Value != aliceExt {
		t.Errorf("restore-as = %+v", got)
	}
	// The uuid check still applies to a restored value.
	people.recreate("alice")
	people.addGroup(entryID, "alice")
	settle(f)
	deliverNow(t, f, entryID, TriggerMembership)
	if _, ok := storedSettings(f, entryID).Entered["ext_id"]["alice"]; ok {
		t.Error("a restored value of a re-created account was not purged")
	}
}

func TestEntriesTemplateUpdate(t *testing.T) {
	f, _, _, audit := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice") // has an f
	mustSetEntry(t, f, entryID, "ext_id", "bob", bobExt, "bob")
	mustSetEntry(t, f, entryID, "nick", "alice", "same", "alice")
	time.Sleep(2 * time.Millisecond)
	mustSetEntry(t, f, entryID, "nick", "bob", "same", "bob")
	old := *f.h.Template(entryID)
	m := string(mustRead(t, filepath.Join("testdata", "settings", entryID, "manifest.yaml")))
	m = strings.Replace(m, `pattern: "^[0-9a-f]{32}$"`, `pattern: "^[0-9a-e]{32}$"`, 1)
	m = strings.Replace(m, "      max_len: 20\n      scope: person_entered\n", "      max_len: 20\n      scope: person_entered\n      unique: true\n", 1)
	writeFile(t, filepath.Join(f.src, entryID, "manifest.yaml"), m)
	f.h.Discover()
	nt := f.h.Template(entryID)
	if nt == nil || !optionByKey(nt, "nick").Unique {
		t.Fatal("update not loaded")
	}
	inc := strings.Join(SettingsIncompatibilities(&old, nt, storedSettings(f, entryID)), "\n")
	for _, want := range []string{"ext_id", "nick"} {
		if !strings.Contains(inc, want) {
			t.Errorf("incompatibilities lack %s: %s", want, inc)
		}
	}
	f.h.SyncSourcesAs(SyncAPI)
	s := storedSettings(f, entryID)
	if _, ok := s.Entered["ext_id"]["alice"]; ok || s.Entered["ext_id"]["bob"].Value != bobExt {
		t.Errorf("ext_id = %+v", s.Entered["ext_id"])
	}
	if _, ok := s.Entered["nick"]["bob"]; ok || s.Entered["nick"]["alice"].Value != "same" {
		t.Errorf("nick = %+v", s.Entered["nick"])
	}
	var inval []string
	for _, e := range auditsOf(audit, "settings.person_value") {
		if e.Detail == "invalidated" {
			inval = append(inval, e.Target)
		}
	}
	if strings.Join(inval, ",") != "entryapp/ext_id/alice,entryapp/nick/bob" {
		t.Errorf("invalidated audits = %v", inval)
	}
}

func TestEntryDirectoryDown(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	settle(f)
	before, err := os.ReadFile(f.appFile(entryID, "ids"))
	if err != nil {
		t.Fatal(err)
	}
	people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 503, Msg: "LLDAP unavailable"} })
	if _, err := setEntry(f, entryID, "ext_id", "bob", bobExt, "bob"); statusOf(err) != 503 {
		t.Errorf("save = %v, want 503", err)
	}
	if err := f.h.ClearPersonValue(context.Background(), entryID, "ext_id", "alice", "alice"); statusOf(err) != 503 {
		t.Errorf("clear = %v, want 503", err)
	}
	deliverNow(t, f, entryID, TriggerMembership)
	after, _ := os.ReadFile(f.appFile(entryID, "ids"))
	if string(after) != string(before) {
		t.Errorf("ids.json changed with the directory down:\n%s", after)
	}
}

func TestPanelEntriesView(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	storeEntryDirect(f, entryID, "ext_id", "carol", "dddddddddddddddddddddddddddddddd", people.uuidOf("carol"))
	p, err := f.h.SettingsPanel(context.Background(), entryID)
	if err != nil {
		t.Fatal(err)
	}
	ev := p.Entries["ext_id"]
	if len(ev.Rows) != 2 || ev.Rows[0].User != "alice" || !ev.Rows[0].Delivered || ev.Rows[0].Display != aliceExt || ev.Rows[0].SetBy != "alice" ||
		ev.Rows[1].User != "carol" || ev.Rows[1].Delivered || ev.Rows[1].Why != EntryWhyNoAccess {
		t.Errorf("rows = %+v", ev.Rows)
	}
	if strings.Join(ev.NotSet, ",") != "bob" {
		t.Errorf("not_set = %v", ev.NotSet)
	}
	if nv := p.Entries["nick"]; len(nv.Rows) != 0 || strings.Join(nv.NotSet, ",") != "alice,bob" {
		t.Errorf("nick = %+v", nv)
	}
	if _, ok := p.Entries["motd"]; ok {
		t.Error("an instance option has an entries view")
	}
	before := storedSettings(f, entryID).Entered
	if _, err := f.h.PreviewSettings(context.Background(), entryID, SettingsUpdate{Values: vals("motd", "hi")}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(storedSettings(f, entryID).Entered, before) {
		t.Error("the preview touched the entries")
	}
}

// T15 review M1: a prefix of another name never shares data.
func TestMyEntriesNeverCrossPeople(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	people.addGroup(entryID, "alice2")
	const alice2Ext = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	mustSetEntry(t, f, entryID, "ext_id", "alice2", alice2Ext, "alice2")
	a, _ := json.Marshal(myApps(t, f, "ALICE"))
	if !strings.Contains(string(a), aliceExt) || strings.Contains(string(a), alice2Ext) || strings.Contains(string(a), "alice2") {
		t.Errorf("ALICE sees %s", a)
	}
	b, _ := json.Marshal(myApps(t, f, "alice2"))
	if !strings.Contains(string(b), alice2Ext) || strings.Contains(string(b), aliceExt) {
		t.Errorf("alice2 sees %s", b)
	}
}

// T11: a person-entered claim carries each person's own value; people
// without one get none (cleared).
func TestEntryClaimOwnValue(t *testing.T) {
	f, _, store := claimFixtureWith(t, func(m string) string {
		return m + `    - key: handle
      label: Handle
      type: string
      max_len: 30
      scope: person_entered
      applies: next_sign_in
      delivery: [{claim: {client: immich, name: immich_handle}}]
`
	})
	claimEnable(t, f, claimID)
	mustSetEntry(t, f, claimID, "handle", "alice", "ali", "alice")
	settle(f)
	deliverNow(t, f, claimID, TriggerRetry)
	attr := SettingAttr(claimID, "handle")
	if got, _ := store.value("alice", attr); got != "ali" {
		t.Errorf("alice's claim = %q", got)
	}
	for _, u := range []string{"bob", "carol", "erin"} {
		if got, ok := store.value(u, attr); ok {
			t.Errorf("%s holds %q", u, got)
		}
	}
	found := false
	for _, c := range f.idp.settingClaims(claimID) {
		found = found || (c.Attr == attr && c.Claim == "immich_handle")
	}
	if !found {
		t.Errorf("no mapper for the entry's claim: %+v", f.idp.settingClaims(claimID))
	}
}

// T12: a person-entered header carries each person's own value on every
// gated host; people without one are absent.
func TestEntryHeaderOwnValue(t *testing.T) {
	f, _, _ := headerFixture(t, func(m string) string {
		return m + `    - key: team
      label: Team
      type: string
      max_len: 30
      scope: person_entered
      applies: next_request
      delivery: [{header: {name: X-Forwarded-Attr-Team}}]
`
	})
	headerEnable(t, f)
	mustSetEntry(t, f, headerID, "team", "alice", "blue", "alice")
	settle(f)
	deliverNow(t, f, headerID, TriggerRetry)
	hosts := attrHosts(t, f)
	for _, host := range []string{headerMain, headerExtra} {
		if got := hosts[host]["Team"]; !reflect.DeepEqual(got, map[string]string{"alice": "blue"}) {
			t.Errorf("%s Team = %v", host, got)
		}
	}
}
