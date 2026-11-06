package hub

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// myAppsExtra: claimapp (as immich) gains an instance int trash_days, an
// instance secret api_key and a person option hidden_tier that people
// don't see (self_visible: false).
const myAppsExtra = `    - key: trash_days
      label: Trash days
      type: int
      min: 1
      default: 30
      applies: restart
      delivery: [{env: IMMICH_TRASH_DAYS}]
    - key: api_key
      label: API key
      type: secret
      applies: restart
      delivery: [{env: IMMICH_API_KEY}]
    - key: hidden_tier
      label: Hidden tier
      type: enum
      scope: person
      self_visible: false
      options:
        - {value: basic, label: Basic}
        - {value: gold, label: Gold}
      default: basic
      resolve: max
      applies: next_sign_in
      delivery: [{file: {name: people, field: tier}}]
`

// myDashManifest: a second app (Grafana) gated by users_dash (bob only)
// with a per-person theme.
const myDashManifest = `name: Grafana
category: monitoring
instances: multi
auth:
  method: header-auth
  group_access: true
  access_group: users_dash
  admin_group: admin_dash
urls:
  - label: Dashboards
    url: "https://{{HOST_DASH}}"
files:
  - {name: people, service: web, mount: /portcullis}
settings:
  options:
    - key: theme
      label: Theme
      type: enum
      scope: person
      options:
        - {value: light, label: Light}
        - {value: dark, label: Dark}
      default: light
      resolve: max
      applies: next_sign_in
      delivery: [{file: {name: people}}]
`

const myDashCompose = `services:
  web:
    image: grafana
    labels:
      traefik.enable: "true"
      traefik.http.routers.dash.rule: Host(` + "`${PORTCULLIS_HOST_DASH:-dash.portcullis.local}`" + `)
      traefik.http.routers.dash.middlewares: portcullis-auth@docker,portcullis-groups@docker
`

// myAppsFixture: immich (claimFixture's people: users_immich alice, bob,
// carol, dave; admin_immich bob; office_milan alice — plus bob here;
// it_staff bob) and dash (users_dash: bob), both enabled. storage_quota:
// default 100GiB, office_milan 10GiB, it_staff 20GiB.
func myAppsFixture(t *testing.T) (*fixture, *fakePeople) {
	t.Helper()
	m := string(mustRead(t, filepath.Join("testdata", "settings", "claimapp", "manifest.yaml"))) + myAppsExtra
	c := strings.Replace(string(mustRead(t, filepath.Join("testdata", "settings", "claimapp", "compose.yml"))), "    image: immich\n",
		"    image: immich\n    environment:\n      TRASH: ${IMMICH_TRASH_DAYS}\n      KEY: ${IMMICH_API_KEY}\n", 1)
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{claimID: {m, c}, "dash": {myDashManifest, myDashCompose}})
	if f.h.Template(claimID) == nil || f.h.Template("dash") == nil {
		t.Fatalf("fixtures not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople("erin", "alice2")
	people.addGroup("users_immich", "alice", "bob", "carol", "dave")
	people.addGroup("admin_immich", "bob")
	people.addGroup("office_milan", "alice", "bob")
	people.addGroup("it_staff", "bob")
	people.addGroup("users_dash", "bob")
	people.addGroup("admin_dash")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_immich": true, "admin_immich": true, "users_dash": true, "admin_dash": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	f.h.SetAttrStore(newFakeAttrStore())
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	for _, id := range []string{claimID, "dash"} {
		if _, err := f.h.EnableAs(id, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
		settle(f)
	}
	tok := "my-apps-secret-value-0123"
	if _, err := f.h.SaveSettings(claimID, SettingsUpdate{
		Person:  map[string]PersonChange{"storage_quota": {Default: raw("100GiB"), Rows: rows("office_milan", "10GiB", "it_staff", "20GiB")}},
		Values:  vals("trash_days", 7),
		Secrets: map[string]SecretChange{"api_key": {Value: &tok}},
	}, directory.Human("admin")); err != nil {
		t.Fatal(err)
	}
	settle(f)
	return f, people
}

func myApps(t *testing.T, f *fixture, user string) []MyApp {
	t.Helper()
	apps, err := f.h.MyApps(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	return apps.Apps
}

func myApp(apps []MyApp, id string) *MyApp {
	for i := range apps {
		if apps[i].ID == id {
			return &apps[i]
		}
	}
	return nil
}

func myValue(a *MyApp, key string) *MyValue {
	for i := range a.Values {
		if a.Values[i].Key == key {
			return &a.Values[i]
		}
	}
	return nil
}

func TestMyAppsOnlyCallersApps(t *testing.T) {
	f, _ := myAppsFixture(t)
	apps := myApps(t, f, "alice")
	if len(apps) != 1 || apps[0].ID != claimID || myApp(apps, "dash") != nil {
		t.Fatalf("alice's apps = %+v, want immich only", apps)
	}
	a := apps[0]
	if a.Name != "Immich Claims Fixture" {
		t.Errorf("name = %q", a.Name)
	}
	q := myValue(&a, "storage_quota")
	if q == nil || q.Value != "10 GiB" || q.Label != "Storage quota" || q.Applies != templates.AppliesNextSignIn ||
		q.Reason.Source != settings.ReasonGroup || q.Reason.Group != "office_milan" || len(q.Reason.Groups) != 0 {
		t.Errorf("storage_quota = %+v", q)
	}
	r := myValue(&a, "role")
	if r == nil || r.Value != "User" || r.Reason.Source != settings.ReasonDefault || r.Reason.Group != "" {
		t.Errorf("role = %+v", r)
	}
	if len(a.Values) != 2 || myValue(&a, "trash_days") != nil || myValue(&a, "api_key") != nil {
		t.Errorf("values = %+v, want storage_quota and role only", a.Values)
	}
	b, _ := json.Marshal(map[string]any{"apps": apps})
	s := string(b)
	for _, bad := range []string{"trash_days", "api_key", "my-apps-secret-value", "others", `"entries":null`, `"credentials":null`} {
		if strings.Contains(s, bad) {
			t.Errorf("answer contains %q: %s", bad, s)
		}
	}
	for _, want := range []string{`"entries":[]`, `"credentials":[]`, `"values":[`, `"key":"storage_quota"`, `"applies":"next_sign_in"`, `"reason":{"source":"group","group":"office_milan"}`} {
		if !strings.Contains(s, want) {
			t.Errorf("answer lacks %s: %s", want, s)
		}
	}
	if a.Entries == nil || a.Credentials == nil || len(a.Entries) != 0 || len(a.Credentials) != 0 {
		t.Errorf("entries %v, credentials %v: want [] both", a.Entries, a.Credentials)
	}
	// Nobody's apps for someone in no access group; never null.
	if got := myApps(t, f, "erin"); got == nil || len(got) != 0 {
		t.Errorf("erin's apps = %#v, want []", got)
	}
}

func TestMyAppsNeverShowsLosingGroups(t *testing.T) {
	f, _ := myAppsFixture(t)
	apps := myApps(t, f, "bob")
	a := myApp(apps, claimID)
	if a == nil || myApp(apps, "dash") == nil {
		t.Fatalf("bob's apps = %+v, want immich and dash", apps)
	}
	q := myValue(a, "storage_quota")
	if q == nil || q.Value != "20 GiB" || q.Reason.Group != "it_staff" || q.Reason.Source != settings.ReasonGroup {
		t.Errorf("bob's storage_quota = %+v, want 20 GiB from it_staff", q)
	}
	b, _ := json.Marshal(a)
	if strings.Contains(string(b), "office_milan") || strings.Contains(string(b), "others") {
		t.Errorf("bob's immich names the losing group: %s", b)
	}
}

func TestMyAppsHidesSelfInvisible(t *testing.T) {
	f, _ := myAppsFixture(t)
	for _, u := range []string{"alice", "bob"} {
		a := myApp(myApps(t, f, u), claimID)
		if a == nil || myValue(a, "hidden_tier") != nil {
			t.Errorf("%s's immich = %+v, want no hidden_tier", u, a)
		}
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), "hidden_tier") || strings.Contains(string(b), "Hidden tier") {
			t.Errorf("%s sees hidden_tier: %s", u, b)
		}
	}
}

func TestMyAppsDisabledInstanceAbsent(t *testing.T) {
	f, _ := myAppsFixture(t)
	if err := f.h.Disable(claimID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if apps := myApps(t, f, "alice"); len(apps) != 0 {
		t.Errorf("alice's apps with immich disabled = %+v", apps)
	}
	if apps := myApps(t, f, "bob"); len(apps) != 1 || apps[0].ID != "dash" {
		t.Errorf("bob's apps with immich disabled = %+v, want dash", apps)
	}
}

func TestMyAppsCallerCaseFolded(t *testing.T) {
	f, _ := myAppsFixture(t)
	apps := myApps(t, f, "ALICE")
	if len(apps) != 1 || apps[0].ID != claimID || myValue(&apps[0], "storage_quota").Value != "10 GiB" {
		t.Errorf("ALICE's apps = %+v, want alice's", apps)
	}
	if apps := myApps(t, f, "Alice2"); len(apps) != 0 {
		t.Errorf("Alice2's apps = %+v, want none", apps)
	}
}

func TestMyAppsDirectoryDown(t *testing.T) {
	f, people := myAppsFixture(t)
	people.set(func(p *fakePeople) { p.err = errors.New("ldap: connection refused") })
	_, err := f.h.MyApps(context.Background(), "alice")
	var se *StatusError
	if !errors.As(err, &se) || se.Status < 500 {
		t.Errorf("MyApps with the directory down = %v, want a 5xx", err)
	}
}

// TestMyValueOf: UNRESOLVED is left out, a fail-closed value is shown as
// such, and a reason names only the caller's groups.
func TestMyValueOf(t *testing.T) {
	kinds := settings.NewRegistry()
	o := &templates.Option{Key: "q", Label: "Q", Type: templates.TypeSize, Scope: templates.ScopePerson, Applies: templates.AppliesLive}
	mine := map[string]int{"office_milan": 7, "it_staff": 8}
	if _, ok := myValueOf(kinds, o, settings.Resolved{Value: nil, Reason: settings.Reason{Source: settings.ReasonFailClosed}}, mine); ok {
		t.Error("UNRESOLVED is listed")
	}
	v, ok := myValueOf(kinds, o, settings.Resolved{Value: int64(1 << 30), Reason: settings.Reason{Source: settings.ReasonFailClosed, Rule: "min",
		Others: []settings.Candidate{{Group: "secret_group", Value: int64(1)}}}}, mine)
	if !ok || v.Value != "1 GiB" || v.Reason.Source != settings.ReasonFailClosed {
		t.Errorf("fail-closed value = %+v %v", v, ok)
	}
	v, _ = myValueOf(kinds, o, settings.Resolved{Value: int64(1 << 30), Reason: settings.Reason{Source: settings.ReasonCombined,
		Groups: []string{"it_staff", "office_milan", "not_mine"}}}, mine)
	if strings.Join(v.Reason.Groups, ",") != "it_staff,office_milan" {
		t.Errorf("groups = %v", v.Reason.Groups)
	}
	v, _ = myValueOf(kinds, o, settings.Resolved{Value: int64(1 << 30), Reason: settings.Reason{Source: settings.ReasonGroup, Group: "not_mine"}}, mine)
	if v.Reason.Group != "" {
		t.Errorf("group = %q, want none", v.Reason.Group)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "not_mine") || strings.Contains(string(b), "others") {
		t.Errorf("%s", b)
	}
}
