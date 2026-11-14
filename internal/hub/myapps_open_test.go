package hub

import (
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// myPlainManifest: an app without personal settings, gated by
// users_plain; myOpenManifest: one every signed-in person can open.
const myPlainManifest = `name: Plain
category: tools
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_plain
  admin_group: admin_plain
urls:
  - label: Plain
    url: "https://{{HOST_PLAIN}}"
`

const myPlainCompose = `services:
  web:
    image: plain
    labels:
      traefik.enable: "true"
      traefik.http.routers.plain.rule: Host(` + "`${PORTCULLIS_HOST_PLAIN:-plain.portcullis.local}`" + `)
      traefik.http.routers.plain.middlewares: portcullis-auth@docker,portcullis-groups@docker
`

const myOpenManifest = `name: Open
category: tools
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
urls:
  - label: Open
    url: "https://{{HOST_OPEN}}"
`

const myOpenCompose = `services:
  web:
    image: open
    labels:
      traefik.enable: "true"
      traefik.http.routers.open.rule: Host(` + "`${PORTCULLIS_HOST_OPEN:-open.portcullis.local}`" + `)
      traefik.http.routers.open.middlewares: portcullis-auth@docker
`

// myOpenFixture: plain (users_plain: alice, and carol whose membership
// expired) and open, both enabled, plus plain2 (users_plain2: alice)
// left disabled. bob is in no group.
func myOpenFixture(t *testing.T) *fixture {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"plain": {myPlainManifest, myPlainCompose}, "open": {myOpenManifest, myOpenCompose}})
	if f.h.Template("plain") == nil || f.h.Template("open") == nil {
		t.Fatalf("fixtures not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople("bob")
	people.addGroup("users_plain", "alice", "carol")
	people.addGroup("admin_plain")
	people.expired["carol"] = map[string]bool{"users_plain": true}
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_plain": true, "admin_plain": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	f.h.SetAttrStore(newFakeAttrStore())
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	for _, id := range []string{"plain", "open"} {
		if _, err := f.h.EnableAs(id, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
		settle(f)
	}
	return f
}

func appIDs(apps []MyApp) []string {
	out := []string{}
	for _, a := range apps {
		out = append(out, a.ID)
	}
	return out
}

// TestMyAppsListsMemberAppWithoutPersonOptions: My apps lists every app
// the portal would let the person open, settings or not — and nothing
// the portal wouldn't.
func TestMyAppsListsMemberAppWithoutPersonOptions(t *testing.T) {
	f := myOpenFixture(t)
	apps := myApps(t, f, "alice")
	if got := appIDs(apps); len(got) != 2 || got[0] != "open" || got[1] != "plain" {
		t.Fatalf("alice's apps = %v, want open and plain", got)
	}
	p := myApp(apps, "plain")
	if p.Name != "Plain" || p.URL == "" || p.Values == nil || p.Entries == nil || p.Credentials == nil ||
		len(p.Values)+len(p.Entries)+len(p.Credentials) != 0 || p.AI != nil {
		t.Errorf("plain = %+v, want no settings, lists [] and a URL", p)
	}
	// Not a member: the open app only.
	if got := appIDs(myApps(t, f, "bob")); len(got) != 1 || got[0] != "open" {
		t.Errorf("bob's apps = %v, want open", got)
	}
	// An expired membership doesn't open the app.
	if got := appIDs(myApps(t, f, "carol")); len(got) != 1 || got[0] != "open" {
		t.Errorf("carol's apps = %v, want open (users_plain expired)", got)
	}
	// Unknown to the directory: nothing (fail closed).
	if got := appIDs(myApps(t, f, "zed")); len(got) != 0 {
		t.Errorf("zed's apps = %v, want none", got)
	}
	// Disabled: gone.
	if err := f.h.Disable("plain"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if got := appIDs(myApps(t, f, "alice")); len(got) != 1 || got[0] != "open" {
		t.Errorf("alice's apps with plain disabled = %v", got)
	}
}
