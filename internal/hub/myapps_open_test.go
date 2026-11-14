package hub

import (
	"fmt"
	"testing"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/runtime"

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
// expired) and open, both enabled. bob is in no group.
func myOpenFixture(t *testing.T) *fixture {
	f, _ := myOpenFixturePeople(t)
	return f
}

func myOpenFixturePeople(t *testing.T) (*fixture, *fakePeople) {
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
	return f, people
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

// TestMyAppsHidesWhatTheGateDenies: an app whose sign-in template can't
// be published is denied by group-gate (policy.Build: DenyGroup), so My
// apps doesn't list it — for anyone — and the portal entry carries the
// deny group (group-gate's portal hides it).
func TestMyAppsHidesWhatTheGateDenies(t *testing.T) {
	f := myOpenFixture(t)
	f.h.mu.Lock()
	setPickLocked(f.h, "open", certOnlyTemplate)
	tm := f.h.st.SignIn.Templates[certOnlyTemplate]
	tm.Enabled = false // the pick is no longer publishable
	f.h.st.SignIn.Templates[certOnlyTemplate] = tm
	f.h.mu.Unlock()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if doc := f.h.gatePolicy.Load(); doc == nil || doc.Groups[f.h.routedHostsOf(t, "open")] != policy.DenyGroup {
		t.Fatalf("the gate doesn't deny open: %+v", doc)
	}
	for _, u := range []string{"alice", "bob"} {
		if a := myApp(myApps(t, f, u), "open"); a != nil {
			t.Errorf("%s sees open, which the gate denies: %+v", u, a)
		}
	}
	if a := myApp(myApps(t, f, "alice"), "plain"); a == nil {
		t.Error("alice lost plain")
	}
	for _, a := range f.h.Portal().Apps {
		if a.ID == "open" && a.AccessGroup != policy.DenyGroup {
			t.Errorf("portal open access_group = %q, want the deny group", a.AccessGroup)
		}
		if a.ID == "plain" && a.AccessGroup != "users_plain" {
			t.Errorf("portal plain access_group = %q", a.AccessGroup)
		}
	}
	// No policy written yet: nothing opens (fail closed).
	f.h.gatePolicy.Store(nil)
	if got := appIDs(myApps(t, f, "alice")); len(got) != 0 {
		t.Errorf("without a policy alice's apps = %v, want none", got)
	}
}

// TestMyAppsVPNOnlyBadge: a VPN-only host (the policy's vpn.hosts) is
// listed with vpn_only.
func TestMyAppsVPNOnlyBadge(t *testing.T) {
	f := myOpenFixture(t)
	doc := *f.h.gatePolicy.Load()
	doc.VPN.Hosts = map[string]policy.VPNHost{f.h.routedHostsOf(t, "plain"): {Via: []string{"*"}}}
	f.h.gatePolicy.Store(&doc)
	apps := myApps(t, f, "alice")
	if p := myApp(apps, "plain"); p == nil || !p.VPNOnly {
		t.Errorf("plain = %+v, want vpn_only", p)
	}
	if o := myApp(apps, "open"); o == nil || o.VPNOnly {
		t.Errorf("open = %+v, want no vpn_only", o)
	}
}

// TestMyAppsBoundGroup: an instance bound to an existing group (§11.9)
// opens for that group's members, not for its derived users_<id>.
func TestMyAppsBoundGroup(t *testing.T) {
	f, people := myOpenFixturePeople(t)
	people.addGroup("team", "bob")
	f.h.mu.Lock()
	e := f.h.st.Instances["plain"]
	e.ID, e.Template, e.UsersGroup = "plain", "plain", "team"
	f.h.st.Instances["plain"] = e
	f.h.mu.Unlock()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if a := myApp(myApps(t, f, "bob"), "plain"); a == nil {
		t.Error("bob (in team) doesn't see plain")
	}
	if a := myApp(myApps(t, f, "alice"), "plain"); a != nil {
		t.Errorf("alice (users_plain only) sees plain bound to team: %+v", a)
	}
}

// routedHostsOf is instance id's one published host.
func (h *Hub) routedHostsOf(t *testing.T, id string) string {
	t.Helper()
	h.mu.RLock()
	defer h.mu.RUnlock()
	hosts := h.routedHostsLocked(h.findLocked(id))
	if len(hosts) != 1 {
		t.Fatalf("%s hosts = %v", id, hosts)
	}
	return hosts[0]
}

// TestMyAppsUnderKubernetes: My apps reads the same gate policy under the
// kubernetes runtime (the policy and the routes' hosts don't depend on
// the runtime; the IngressRoutes carry the same Host() rules).
func TestMyAppsUnderKubernetes(t *testing.T) {
	f := myOpenFixture(t)
	docker := appIDs(myApps(t, f, "alice"))
	f.setRuntime(runtime.KindKubernetes)
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if got := appIDs(myApps(t, f, "alice")); fmt.Sprint(got) != fmt.Sprint(docker) || len(got) == 0 {
		t.Errorf("kubernetes: %v, docker: %v", got, docker)
	}
}
