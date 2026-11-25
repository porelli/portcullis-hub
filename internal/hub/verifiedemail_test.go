package hub

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

const veID = "veapp"

// veFixture loads testdata/settings/veapp (a header-auth app whose
// verified_email option email goes into data file access; its per-person
// seats go into both access and roster) with alice, bob and carol in users_veapp and erin
// outside: alice's email is verified (and erin's), bob has an unverified
// email, carol none. The instance is enabled.
func veFixture(t *testing.T) (*fixture, *fakePeople) {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", veID, "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", veID, "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{veID: {string(m), string(c)}})
	if f.h.Template(veID) == nil {
		t.Fatalf("veapp not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople("erin")
	people.addGroup("users_"+veID, "alice", "bob", "carol")
	people.addGroup("admin_" + veID)
	people.set(func(p *fakePeople) {
		p.emails = map[string]string{"alice": "alice@example.org", "bob": "bob@example.org", "erin": "erin@example.org"}
		p.verified = map[string]string{"alice": "alice@example.org", "erin": "erin@example.org"}
	})
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_" + veID: true, "admin_" + veID: true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	if err := f.h.Enable(veID); err != nil {
		t.Fatal(err)
	}
	settle(f)
	return f, people
}

func veDeliver(t *testing.T, f *fixture) *DeliveryReport {
	t.Helper()
	rep, err := f.h.Deliver(context.Background(), veID, TriggerMembership)
	if err != nil {
		t.Fatal(err)
	}
	settle(f)
	return rep
}

func TestVerifiedEmailInDataFile(t *testing.T) {
	f, _ := veFixture(t)
	veDeliver(t, f)
	p := f.appFile(veID, "access")
	d := readDoc(t, p)
	// bob and carol are in the population, but have no entry at all
	// (their seats included).
	want := map[string]map[string]any{"alice": {"email": "alice@example.org", "seats": 1}}
	if !jsonEq(d.People, want) {
		t.Errorf("access people = %v, want %v", d.People, want)
	}
	if d.Values["greeting"] != "hello" {
		t.Errorf("access values = %v", d.Values)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != dataFileMode {
		t.Errorf("access.json mode = %v, want %v", fi.Mode().Perm(), os.FileMode(dataFileMode))
	}
	// Only the file the email goes into leaves people out: roster has
	// all three.
	r := readDoc(t, f.appFile(veID, "roster"))
	if got := slices.Sorted(maps.Keys(r.People)); strings.Join(got, ",") != "alice,bob,carol" {
		t.Errorf("roster people = %v", r.People)
	}
	// Never in the env, on My apps or as a panel value.
	if _, ok := envValue(t, f, veID, "EMAIL"); ok {
		t.Error("EMAIL in the env")
	}
	panel, err := f.h.SettingsPanel(context.Background(), veID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := panel.Person["email"]; ok {
		t.Error("panel person value email")
	}
	if _, ok := panel.Instance["email"]; ok {
		t.Error("panel instance value email")
	}
}

func TestVerifiedEmailPanelList(t *testing.T) {
	f, _ := veFixture(t)
	p, err := f.h.SettingsPanel(context.Background(), veID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Population.NoVerifiedEmail, ",") != "bob,carol" || p.Population.Count != 3 {
		t.Errorf("population = %+v, want no_verified_email [bob carol] of 3", p.Population)
	}
	b, _ := json.Marshal(p.Population)
	if !strings.Contains(string(b), `"no_verified_email":["bob","carol"]`) {
		t.Errorf("population JSON = %s", b)
	}
	// Usernames only: never an address.
	if strings.Contains(string(b), "@") {
		t.Errorf("population JSON names an email: %s", b)
	}
	// A template without the type lists nothing (omitted).
	tf, _, _ := tmFixture(t)
	tp, err := tf.h.SettingsPanel(context.Background(), tmID)
	if err != nil {
		t.Fatal(err)
	}
	if tp.Population.NoVerifiedEmail != nil {
		t.Errorf("tmfixture no_verified_email = %v", tp.Population.NoVerifiedEmail)
	}
	if b, _ := json.Marshal(tp.Population); strings.Contains(string(b), "no_verified_email") {
		t.Errorf("tmfixture population JSON = %s", b)
	}
}

func TestVerifiedEmailRedelivers(t *testing.T) {
	f, people := veFixture(t)
	if !hasPeopleOptions(f.h.Template(veID)) {
		t.Fatal("veapp has no people options: the membership delivery would skip it")
	}
	veDeliver(t, f)
	p := f.appFile(veID, "access")
	before, _ := os.ReadFile(p)
	// bob verifies his email: the next membership run changes the file.
	people.set(func(p *fakePeople) { p.verified["bob"] = "bob@example.org" })
	rep := veDeliver(t, f)
	if u, ok := unit(rep, "file:access"); !ok || !u.OK || u.Skipped != "" {
		t.Errorf("file:access = %+v, want delivered", u)
	}
	after, _ := os.ReadFile(p)
	if string(after) == string(before) {
		t.Fatal("the file didn't change when bob verified")
	}
	if d := readDoc(t, p); d.People["bob"]["email"] != "bob@example.org" {
		t.Errorf("bob = %v", d.People["bob"])
	}
	// alice's record is dropped (the prune: her LLDAP email changed):
	// she is left out at once.
	people.set(func(p *fakePeople) {
		delete(p.verified, "alice")
		p.emails["alice"] = "alice.b@example.org"
	})
	veDeliver(t, f)
	d := readDoc(t, p)
	if _, ok := d.People["alice"]; ok {
		t.Errorf("alice still in the file after her verification was dropped: %v", d.People)
	}
	// Nothing changed: unchanged.
	if u, ok := unit(veDeliver(t, f), "file:access"); !ok || u.Skipped != SkipUnchanged {
		t.Errorf("file:access = %+v, want unchanged", u)
	}
}

func TestVerifiedEmailNotParsedFromAdmin(t *testing.T) {
	f, _ := veFixture(t)
	for name, u := range map[string]SettingsUpdate{
		"value":  {Values: vals("email", "mallory@example.org")},
		"person": {Person: map[string]PersonChange{"email": {Default: raw("mallory@example.org")}}},
		"rows":   {Person: map[string]PersonChange{"email": {Rows: rows("users_"+veID, "mallory@example.org")}}},
		"groups": {Groups: map[string][]GroupValueInput{"email": {{Group: "users_" + veID, Value: raw("mallory@example.org")}}}},
	} {
		if _, err := f.h.SaveSettings(veID, u, directory.Human("admin")); statusOf(err) != 400 || !strings.Contains(err.Error(), "set by the Hub") {
			t.Errorf("%s: %v, want 400 (set by the Hub)", name, err)
		}
	}
	f.h.mu.RLock()
	s := f.h.st.Settings[veID]
	f.h.mu.RUnlock()
	if _, ok := s.Person["email"]; ok {
		t.Error("email stored as a person value")
	}
	if _, ok := s.Values["email"]; ok {
		t.Error("email stored as an instance value")
	}
	veDeliver(t, f)
	if d := readDoc(t, f.appFile(veID, "access")); strings.Contains(string(mustJSON(t, d)), "mallory") {
		t.Errorf("an admin value reached the file: %v", d.People)
	}
}
