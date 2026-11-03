package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

const (
	headerTemplate = "dash"
	headerID       = "dash-b"
	hdrSuffix      = "Grafana-Role"
	headerMain     = "dash-b.example.org"
	headerExtra    = "dash.team-b.example.org"
	headerStatus   = "dash-b-status.example.org"
)

// headerFixture loads testdata/settings/headerapp as template dash
// (header-auth): role (person, privileged, Viewer < Editor < Admin,
// {{ADMIN_GROUP}}: Admin, header X-Forwarded-Attr-Grafana-Role,
// next_request) on routers dash and dash-team (portcullis-groups), and a
// status service whose router dash-status has no gateway. Instance
// dash-b: dash on the main domain, dash-team on the enrolled team-b
// domain, dash-status on the main domain. users_dash-b: alice, bob,
// carol; admin_dash-b: bob; editors: carol; erin is in no group. Not enabled yet.
func headerFixture(t *testing.T, edit func(string) string) (*fixture, *fakePeople, *fakeDomains) {
	t.Helper()
	m := string(mustRead(t, filepath.Join("testdata", "settings", "headerapp", "manifest.yaml")))
	if edit != nil {
		m = edit(m)
	}
	c := mustRead(t, filepath.Join("testdata", "settings", "headerapp", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{headerTemplate: {m, string(c)}})
	if f.h.Template(headerTemplate) == nil {
		t.Fatalf("headerapp not loaded (see the log)")
	}
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople("erin")
	people.addGroup("users_dash-b", "alice", "bob", "carol")
	people.addGroup("admin_dash-b", "bob")
	people.addGroup("editors", "carol")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_dash-b": true, "admin_dash-b": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	if err := f.h.CreateInstance(headerTemplate, headerID, map[string]string{"dash": headerMain, "dash-team": headerExtra, "dash-status": headerStatus}); err != nil {
		t.Fatal(err)
	}
	return f, people, doms
}

// headerEnable enables dash-b and stores the role rows: default Viewer,
// {{ADMIN_GROUP}} Admin (the template's row, kept), editors Editor.
func headerEnable(t *testing.T, f *fixture) {
	t.Helper()
	if _, err := f.h.EnableAs(headerID, "root"); err != nil {
		t.Fatal(err)
	}
	settle(f)
	if _, err := f.h.SaveSettings(headerID, SettingsUpdate{Person: map[string]PersonChange{
		"role": {Default: raw("Viewer"), Rows: rows("{{ADMIN_GROUP}}", "Admin", "editors", "Editor")},
	}}, "admin"); err != nil {
		t.Fatal(err)
	}
	settle(f)
}

// attrHosts is the hosts section of user-attributes.json (nil: no file).
func attrHosts(t *testing.T, f *fixture) map[string]map[string]map[string]string {
	t.Helper()
	doc, ok := readAttrs(t, f)
	if !ok {
		return nil
	}
	if doc.Version != policy.UserAttributesVersion {
		t.Errorf("user-attributes.json version = %d", doc.Version)
	}
	return doc.Hosts
}

var headerWant = map[string]string{"alice": "Viewer", "bob": "Admin", "carol": "Editor"}

func TestHeaderDeliveryAllGroupsHosts(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	rep := deliverNow(t, f, headerID, TriggerRetry)
	if u, ok := unit(rep, unitHeaders); !ok || !u.OK {
		t.Errorf("unit headers = %+v (%v)", u, ok)
	}
	hosts := attrHosts(t, f)
	for _, host := range []string{headerMain, headerExtra} {
		if got := hosts[host][hdrSuffix]; !reflect.DeepEqual(got, headerWant) {
			t.Errorf("%s %s = %v, want %v", host, hdrSuffix, got, headerWant)
		}
	}
	// The ungated router's host gets nothing; nor does anything else.
	if _, ok := hosts[headerStatus]; ok || len(hosts) != 2 {
		t.Errorf("hosts = %v, want only %s and %s", hosts, headerMain, headerExtra)
	}
	h := f.h
	h.mu.RLock()
	got, err := h.groupsHostsLocked(h.findLocked(headerID))
	h.mu.RUnlock()
	if err != nil || !slices.Equal(got, []string{headerMain, headerExtra}) {
		t.Errorf("groupsHostsLocked = %v, %v", got, err)
	}
}

// TestHeaderKeysAreSuffixes pins the hosts map keys to what core's
// group-gate reads (group-gate.py parse_user_attributes): the header
// name after ATTR_HEADER_PREFIX "X-Forwarded-Attr-", which it prefixes
// again; a full name would be sent as X-Forwarded-Attr-X-Forwarded-Attr-….
func TestHeaderKeysAreSuffixes(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	b, err := os.ReadFile(filepath.Join(f.data, policy.UserAttributesFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"X-Forwarded-Attr-`) || !strings.Contains(string(b), `"`+hdrSuffix+`": {`) {
		t.Errorf("user-attributes.json keys are not header suffixes:\n%s", b)
	}
	tmpl := f.h.Template(headerID)
	name := optionByKey(tmpl, "role").Delivery[0].Header.Name
	if policy.HeaderPrefix != "X-Forwarded-Attr-" || policy.HeaderPrefix+hdrSuffix != name {
		t.Errorf("prefix %q + %q != declared %q", policy.HeaderPrefix, hdrSuffix, name)
	}
}

// TestHeaderRefusedWithNativeSignIn exercises the defence-in-depth branch
// of configCheck: the manifest has native_login without
// allow_without_gateway, because the templates validator already refuses
// a header delivery together with allow_without_gateway (the template
// would not load), so a template that really allows native sign-in can
// never also deliver headers.
func TestHeaderRefusedWithNativeSignIn(t *testing.T) {
	f, _, _ := headerFixture(t, func(m string) string {
		m = strings.Replace(m, "method: header-auth", "method: custom", 1)
		return strings.Replace(m, "  admin_group: admin_dash\n", "  admin_group: admin_dash\n  sso: false\n  native_login:\n    supported: true\n    note: its own accounts\n", 1)
	})
	headerEnable(t, f)
	_, err := f.h.SaveSettings(headerID, SettingsUpdate{SignIn: strp(SignInNative)}, "admin")
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "header") {
		t.Fatalf("native sign-in with a header delivery: %v, want 400 naming the header", err)
	}
	if got := attrHosts(t, f)[headerMain][hdrSuffix]; !reflect.DeepEqual(got, headerWant) {
		t.Errorf("headers after the refusal = %v", got)
	}
}

func TestHeadersSurviveRestart(t *testing.T) {
	f, _, doms := headerFixture(t, nil)
	headerEnable(t, f)
	if got := attrHosts(t, f)[headerMain][hdrSuffix]; !reflect.DeepEqual(got, headerWant) {
		t.Fatalf("headers before the restart = %v", got)
	}
	f.h.Wait()
	// A new Hub over the same data directory, its directory not wired
	// yet: Init's policy write keeps the headers group-gate reads.
	h2, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "example.org"}, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h2.SetDomainSource(doms)
	h2.Init()
	t.Cleanup(h2.Wait)
	for _, host := range []string{headerMain, headerExtra} {
		if got := attrHosts(t, f)[host][hdrSuffix]; !reflect.DeepEqual(got, headerWant) {
			t.Errorf("after restart %s = %v, want %v", host, got, headerWant)
		}
	}
	h2.mu.RLock()
	seeded := h2.hostHeaders[headerID][headerMain][hdrSuffix]
	h2.mu.RUnlock()
	if !reflect.DeepEqual(seeded, headerWant) {
		t.Errorf("seeded hostHeaders = %v", seeded)
	}
}

func TestHeadersOnlyEnabledInstances(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	if hosts := attrHosts(t, f); len(hosts[headerMain]) == 0 {
		t.Fatalf("enabled: hosts = %v", hosts)
	}
	if err := f.h.Disable(headerID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if hosts := attrHosts(t, f); len(hosts) != 0 {
		t.Errorf("disabled: hosts = %v, want none", hosts)
	}
	// Enabled again: nothing stale is published before a delivery runs.
	f.h.mu.RLock()
	_, kept := f.h.hostHeaders[headerID]
	f.h.mu.RUnlock()
	if kept {
		t.Error("a disabled instance keeps its header record")
	}
}

func TestHeaderDeliveryNoRestart(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	before := len(f.runner.Calls())
	res, err := f.h.SaveSettings(headerID, SettingsUpdate{Person: map[string]PersonChange{
		"role": {Default: raw("Viewer"), Rows: rows("{{ADMIN_GROUP}}", "Admin", "editors", "Admin")},
	}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	settle(f)
	if res.Effect != settings.EffectNone {
		t.Errorf("effect = %s, want none", res.Effect)
	}
	if got := attrHosts(t, f)[headerMain][hdrSuffix]["carol"]; got != "Admin" {
		t.Errorf("carol = %q after the save, want Admin", got)
	}
	if calls := f.runner.Calls()[before:]; len(calls) != 0 {
		t.Errorf("compose calls after a header change: %v", calls)
	}
	if u, ok := unit(res.Deliveries, unitRestart); ok {
		t.Errorf("restart unit = %+v", u)
	}
}

// A re-created group (a new LLDAP id) grants nothing: its row's value is
// not delivered (T8 membership-snapshot id check).
func TestHeaderRecreatedGroupGrantsNothing(t *testing.T) {
	f, people, _ := headerFixture(t, nil)
	headerEnable(t, f)
	people.deleteGroup("editors")
	people.addGroup("editors", "carol")
	deliverNow(t, f, headerID, TriggerMembership)
	if got := attrHosts(t, f)[headerMain][hdrSuffix]["carol"]; got != "Viewer" {
		t.Errorf("carol = %q with a re-created editors group, want Viewer", got)
	}
}

// Population only: erin (no access group) gets no value; leaving the
// access group removes the value at the next delivery.
func TestHeaderPopulationOnly(t *testing.T) {
	f, people, _ := headerFixture(t, nil)
	headerEnable(t, f)
	if _, ok := attrHosts(t, f)[headerMain][hdrSuffix]["erin"]; ok {
		t.Error("erin (not in the population) has a header value")
	}
	people.set(func(p *fakePeople) { delete(p.members["users_dash-b"], "alice") })
	deliverNow(t, f, headerID, TriggerMembership)
	if _, ok := attrHosts(t, f)[headerMain][hdrSuffix]["alice"]; ok {
		t.Error("alice left the access group but keeps her header value")
	}
}

// The directory unavailable: the header unit is skipped and the last
// published hosts section is kept (never cleared).
func TestHeaderDirectoryDownKeepsHosts(t *testing.T) {
	f, people, _ := headerFixture(t, nil)
	headerEnable(t, f)
	people.set(func(p *fakePeople) { p.err = errors.New("lldap down") })
	rep := deliverNow(t, f, headerID, TriggerMembership)
	if u, _ := unit(rep, unitHeaders); u.Skipped != SkipDirectory {
		t.Errorf("unit headers = %+v, want skipped %q", u, SkipDirectory)
	}
	f.h.writePolicyLogged()
	if got := attrHosts(t, f)[headerMain][hdrSuffix]; !reflect.DeepEqual(got, headerWant) {
		t.Errorf("headers with the directory down = %v, want %v", got, headerWant)
	}
}

// The template missing: its hosts get no headers (fail closed).
func TestHeadersTemplateMissing(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	if err := os.RemoveAll(filepath.Join(f.src, headerTemplate)); err != nil {
		t.Fatal(err)
	}
	f.h.Discover()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if hosts := attrHosts(t, f); len(hosts) != 0 {
		t.Errorf("template missing: hosts = %v, want none", hosts)
	}
}

// P14: the public router strips every declared header-delivery name (and
// its underscore alias) whatever the instance's settings: a public path
// never passes a client's copy to the backend.
func TestPublicStripsHeaderDeliveries(t *testing.T) {
	m := templates.Manifest{}
	m.Settings = &templates.SettingsSpec{Options: []templates.Option{
		{Key: "role", Scope: templates.ScopePerson, Delivery: []templates.Delivery{{Header: &templates.HeaderDelivery{Name: "X-Forwarded-Attr-Grafana-Role"}}}},
		{Key: "team", Scope: templates.ScopePersonEntered, Delivery: []templates.Delivery{{Header: &templates.HeaderDelivery{Name: "X-Forwarded-Attr-team"}}}},
	}}
	got := publicStripHeaders(&m)
	for _, want := range []string{"X-Forwarded-Attr-Grafana-Role", "X_Forwarded_Attr_Grafana_Role", "X-Forwarded-Attr-Team", "X_Forwarded_Attr_Team"} {
		if !slices.Contains(got, want) {
			t.Errorf("publicStripHeaders lacks %s: %v", want, got)
		}
	}
}

// M2: a plan without hosts (header options, no gated host) is written
// once (its hash recorded), then unchanged: no policy write (and no
// directory call) per run.
func TestHeaderNilPlanUnchanged(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	calls := 0
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		calls++
		return nil, nil, nil
	}, nil)
	h := f.h
	h.mu.Lock()
	delete(h.hostHeaders, headerID)
	h.mu.Unlock()
	current := func() bool { return true }
	plan := headerPlan{active: true, hash: "nil-plan"}
	d := deliveredDoc{Hashes: map[string]string{}}
	u, stop := h.runHeaders(headerID, plan, current, &d, time.Now())
	if stop || !u.OK || u.Skipped != "" || d.Hashes[unitHeaders] != "nil-plan" {
		t.Errorf("first run: unit = %+v (stop %v), hash %q; want written and recorded", u, stop, d.Hashes[unitHeaders])
	}
	u, stop = h.runHeaders(headerID, plan, current, &d, time.Now())
	if stop || !u.OK || u.Skipped != SkipUnchanged {
		t.Errorf("second run: unit = %+v (stop %v), want unchanged", u, stop)
	}
	if calls != 1 {
		t.Errorf("%d policy writes, want 1 (the first run only)", calls)
	}
}

// A failed write leaves the last published hosts in the file and no
// hash: the next plan — even one without hosts — rewrites the file.
func TestHeaderNilPlanAfterFailedWrite(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	if len(attrHosts(t, f)) == 0 {
		t.Fatal("no hosts published")
	}
	h := f.h
	current := func() bool { return true }
	plan := headerPlan{active: true, hash: "nil-plan"}
	d := h.loadDelivered(headerID)
	// The policy write fails (the data directory not writable).
	if err := os.Chmod(f.data, 0555); err != nil {
		t.Fatal(err)
	}
	u, _ := h.runHeaders(headerID, plan, current, &d, time.Now())
	if err := os.Chmod(f.data, 0755); err != nil {
		t.Fatal(err)
	}
	if u.Error == "" {
		t.Fatalf("unit = %+v, want the failed write", u)
	}
	if len(attrHosts(t, f)) == 0 {
		t.Fatal("the failed write changed the file")
	}
	u, _ = h.runHeaders(headerID, plan, current, &d, time.Now())
	if !u.OK || u.Skipped != "" {
		t.Errorf("unit after the failure = %+v, want written", u)
	}
	if hosts := attrHosts(t, f); len(hosts) != 0 {
		t.Errorf("hosts = %v after a nil plan, want none (stale hosts kept published)", hosts)
	}
}

// M3: the directory state failing for the policy write (the snapshot the
// header unit used was fine): the existing file keeps its fields and
// users, only its hosts section follows the plan — a demotion still
// reaches group-gate.
func TestHeaderDemotionWithDirectoryStateDown(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	attrs := policy.BuildUserAttributes([]policy.AttrField{{Name: "cost_center"}}, map[string]map[string][]string{"carol": {"cost_center": {"CC-1"}}}, nil)
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, &attrs, nil
	}, nil)
	headerEnable(t, f)
	if got := attrHosts(t, f)[headerMain][hdrSuffix]["carol"]; got != "Editor" {
		t.Fatalf("carol = %q, want Editor", got)
	}
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, errors.New("directory publish failed")
	}, nil)
	res, err := f.h.SaveSettings(headerID, SettingsUpdate{Person: map[string]PersonChange{
		"role": {Default: raw("Viewer"), Rows: rows("{{ADMIN_GROUP}}", "Admin")},
	}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	settle(f)
	if u, _ := unit(res.Deliveries, unitHeaders); !u.OK || u.Error != "" {
		t.Errorf("unit headers = %+v", u)
	}
	doc, _ := readAttrs(t, f)
	if got := doc.Hosts[headerMain][hdrSuffix]["carol"]; got != "Viewer" {
		t.Errorf("carol = %q with the directory state down, want Viewer (demoted)", got)
	}
	if got := doc.Users["carol"]["cost_center"]; len(got) != 1 || got[0] != "CC-1" {
		t.Errorf("the kept file's users = %v, want carol's cost_center kept", doc.Users)
	}
}

// M4: a committed SetHosts queues a delivery, so the headers move to the
// new host even when the restart fails.
func TestHeadersFollowSetHosts(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	const moved = "dash-c.example.org"
	f.runner.mu.Lock()
	f.runner.upErr = errors.New("up failed")
	f.runner.mu.Unlock()
	if err := f.h.SetHosts(headerID, map[string]string{"dash": moved, "dash-team": headerExtra, "dash-status": headerStatus}, "admin"); err == nil {
		t.Log("SetHosts: the restart did not fail")
	}
	settle(f)
	hosts := attrHosts(t, f)
	if got := hosts[moved][hdrSuffix]; !reflect.DeepEqual(got, headerWant) {
		t.Errorf("%s = %v, want %v (hosts %v)", moved, got, headerWant, hosts)
	}
	if _, ok := hosts[headerMain]; ok {
		t.Errorf("the old host %s keeps headers: %v", headerMain, hosts)
	}
}
