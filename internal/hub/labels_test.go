package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Apps Task 3: instance labels and group binding (contract §11.9).

func createReq(tmpl, id, label string) CreateRequest {
	return CreateRequest{Template: tmpl, ID: id, Label: label}
}

func TestCreateWithLabelAndNewGroups(t *testing.T) {
	f := newInstanceFixture(t, nil)
	audit, g := &fakeAudit{}, &fakeGroups{}
	f.h.SetAudit(audit)
	f.h.SetGroups(g)

	res, err := f.h.CreateInstanceAs(CreateRequest{Template: "grafana", ID: "grafana-team-a", Label: "Team A", Groups: GroupChoice{Mode: GroupsNew}}, directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Label != "Team A" || res.Name != "Grafana · Team A" || res.GroupsMode != GroupsNew ||
		res.AccessGroup != "users_grafana-team-a" || res.AdminGroup != "admin_grafana-team-a" {
		t.Errorf("view = %+v", res.InstanceView)
	}
	if got := strings.Join(g.Calls(), ","); got != "+users_grafana-team-a:alice,+admin_grafana-team-a:alice" {
		t.Errorf("groups = %s", got)
	}
	st, _ := state.Load(f.h.statePath())
	if e := st.Instances["grafana-team-a"]; e.Label != "Team A" || e.Bound() {
		t.Errorf("state entry = %+v", e)
	}
	// Mode omitted is "new".
	if res, err := f.h.CreateInstanceAs(createReq("grafana", "grafana-b", "B"), directory.Human("alice")); err != nil || res.GroupsMode != GroupsNew {
		t.Fatalf("default mode = %+v %v", res, err)
	}

	// Labels §11.9 refuses: 400, nothing created.
	long := strings.Repeat("é", LabelMaxRunes)
	for _, bad := range []string{"", "   ", "two\nlines", "tab\there", "zero\u200bwidth", "nb\u00a0space", "bidi\u202ex", " lead", "trail ", long + "x", "pua\ue000", "bom\ufeff", "soft\u00adhyphen"} {
		if _, err := f.h.CreateInstanceAs(createReq("grafana", "grafana-x", bad), directory.Human("alice")); statusOf(err) != 400 {
			t.Errorf("label %q = %v", bad, err)
		}
	}
	if _, ok := f.h.InstanceView("grafana-x"); ok {
		t.Error("created with a bad label")
	}
	// 64 runes, inner spaces and punctuation are fine.
	if _, err := f.h.CreateInstanceAs(createReq("grafana", "grafana-x", long), directory.Human("alice")); err != nil {
		t.Errorf("64 runes = %v", err)
	}
	if err := CheckLabel("Team A — Ops (2026)"); err != nil {
		t.Errorf("plain label = %v", err)
	}
	// A bad groups choice: 400.
	for _, gc := range []GroupChoice{{Mode: "shared"}, {Mode: GroupsNew, Users: "team"}, {Mode: GroupsExisting}, {Mode: GroupsExisting, Users: "team"}} {
		if _, err := f.h.CreateInstanceAs(CreateRequest{Template: "grafana", ID: "grafana-y", Label: "Y", Groups: gc}, directory.Human("alice")); statusOf(err) != 400 {
			t.Errorf("groups %+v = %v", gc, err)
		}
	}
}

// boundFixture: grafana-t bound to team (users) and ops (admins).
func boundFixture(t *testing.T, users, admins string) (*fixture, *fakeGroups, *fakeAudit) {
	t.Helper()
	f := newInstanceFixture(t, nil)
	audit := &fakeAudit{}
	g := &fakeGroups{existing: map[string]bool{"team": true, "ops": true, "users_grafana-t": true}}
	f.h.SetAudit(audit)
	f.h.SetGroups(g)
	simulateCompose(f, 0)
	res, err := f.h.CreateInstanceAs(CreateRequest{Template: "grafana", ID: "grafana-t", Label: "Team",
		Groups: GroupChoice{Mode: GroupsExisting, Users: users, Admins: admins}}, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if res.GroupsMode != GroupsExisting || res.AccessGroup != users || res.AdminGroup != admins {
		t.Fatalf("view = %+v", res.InstanceView)
	}
	return f, g, audit
}

func TestCreateWithExistingGroups(t *testing.T) {
	f, g, _ := boundFixture(t, "team", "ops")
	// Nothing created; the op record says what it is bound to.
	if c := g.Calls(); len(c) != 0 {
		t.Errorf("group calls = %v", c)
	}
	if r := f.h.LastOp("grafana-t"); r == nil || !strings.Contains(stepDetail(r, StepGroups), "bound to team, ops") {
		t.Errorf("op record = %+v", r)
	}
	// One answer everywhere.
	f.h.mu.RLock()
	v := f.h.findLocked("grafana-t")
	users, admins := f.h.instanceGroupsLocked(v)
	acc, ph := accessGroupOf(v), placeholderGroup(v, templates.PlaceholderAdminGroup)
	env := v.InstanceEnv
	f.h.mu.RUnlock()
	if users != "team" || admins != "ops" || acc != "team" || ph != "ops" ||
		env[templates.VarAccessGroup] != "team" || env[templates.VarAdminGroup] != "ops" {
		t.Errorf("groups = %s %s, accessGroupOf %s, placeholder %s, env %v", users, admins, acc, ph, env)
	}
	if err := f.h.Enable("grafana-t"); err != nil {
		t.Fatal(err)
	}
	if c := g.Calls(); len(c) != 0 {
		t.Errorf("enable created groups: %v", c)
	}
	if got := readPolicy(t, f).Groups["grafana-t.example.org"]; got != "team" {
		t.Errorf("policy group = %q", got)
	}
	envFile := readFile(t, f.h.envPath("grafana-t"))
	if !strings.Contains(envFile, "PORTCULLIS_ACCESS_GROUP=team") || !strings.Contains(envFile, "PORTCULLIS_ADMIN_GROUP=ops") {
		t.Errorf(".env = %s", envFile)
	}
	if p := f.h.Portal(); !strings.Contains(mustJSON(t, p), `"access_group": "team"`) && !strings.Contains(mustJSON(t, p), `"access_group":"team"`) {
		t.Errorf("portal = %+v", p.Apps)
	}
	for _, a := range f.h.DirectoryApps() {
		if a.ID == "grafana-t" && (a.AccessGroup != "team" || a.AdminGroup != "ops") {
			t.Errorf("directory app = %+v", a)
		}
	}
	if snap := f.h.st.Published["grafana-t"]; snap.AccessGroup != "team" || snap.AdminGroup != "ops" {
		t.Errorf("published = %+v", snap)
	}
	// A bound group that is gone is "other", never created.
	g.mu.Lock()
	delete(g.existing, "team")
	g.mu.Unlock()
	rep := f.h.MissingGroups(context.Background())
	if len(rep.Instances) != 1 || len(rep.Instances[0].Creatable) != 0 || strings.Join(rep.Instances[0].Other, ",") != "team" {
		t.Errorf("missing groups = %+v", rep)
	}
	if _, err := f.h.CreateMissingGroups(context.Background(), nil, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if c := g.Calls(); len(c) != 0 {
		t.Errorf("create-missing created a bound group: %v", c)
	}
	g.mu.Lock()
	g.existing["team"] = true
	g.mu.Unlock()

	// Delete never deletes a bound group.
	res, err := f.h.DeleteInstance("grafana-t", "grafana-t", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if c := g.Calls(); len(c) != 0 {
		t.Errorf("delete deleted groups: %v", c)
	}
	if w := strings.Join(res.Warnings, "; "); !strings.Contains(w, "group team was kept: the instance is bound to it") || !strings.Contains(w, "group ops was kept") {
		t.Errorf("warnings = %s", w)
	}
}

// TestDeleteKeepsBoundDerivedName: a group bound to the instance is kept
// even when it is named exactly users_<id> (review focus: delete never
// deletes a bound group, whatever its name).
func TestDeleteKeepsBoundDerivedName(t *testing.T) {
	f, g, _ := boundFixture(t, "users_grafana-t", "ops")
	plan, err := f.h.DeletePlan("grafana-t")
	if err != nil {
		t.Fatal(err)
	}
	if p := strings.Join(plan, " "); strings.Contains(p, "group users_grafana-t") && !strings.Contains(p, "Keeps group users_grafana-t: the instance is bound to it") {
		t.Errorf("plan = %s", p)
	}
	if _, err := f.h.DeleteInstance("grafana-t", "grafana-t", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if c := g.Calls(); len(c) != 0 {
		t.Errorf("delete deleted %v", c)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.existing["users_grafana-t"] {
		t.Error("the bound group is gone")
	}
}

func TestCreateRefusesBuiltinUsersGroup(t *testing.T) {
	f := newInstanceFixture(t, nil)
	g := &fakeGroups{existing: map[string]bool{"team": true, "helpdesk": true}, privileged: map[string]bool{"helpdesk": true}}
	f.h.SetGroups(g)
	for _, users := range []string{"lldap_admin", "lldap_password_manager", "lldap_strict_readonly", "helpdesk"} {
		_, err := f.h.CreateInstanceAs(CreateRequest{Template: "grafana", ID: "grafana-t", Label: "T",
			Groups: GroupChoice{Mode: GroupsExisting, Users: users, Admins: "team"}}, directory.Human("root"))
		if statusOf(err) != 400 || !strings.Contains(err.Error(), "the users group can't be a built-in or administrator group") {
			t.Errorf("users %s = %v", users, err)
		}
	}
	// Unknown group 400; Users & Groups down 503; none at all 503.
	if _, err := f.h.CreateInstanceAs(CreateRequest{Template: "grafana", ID: "grafana-t", Label: "T",
		Groups: GroupChoice{Mode: GroupsExisting, Users: "nope", Admins: "team"}}, directory.Human("root")); statusOf(err) != 400 || !strings.Contains(err.Error(), "unknown group nope") {
		t.Errorf("unknown = %v", err)
	}
	g.missingErr = errors.New("lldap down")
	if _, err := f.h.CreateInstanceAs(CreateRequest{Template: "grafana", ID: "grafana-t", Label: "T",
		Groups: GroupChoice{Mode: GroupsExisting, Users: "team", Admins: "team"}}, directory.Human("root")); statusOf(err) != 503 {
		t.Errorf("down = %v", err)
	}
	f.h.SetGroups(nil)
	if _, err := f.h.CreateInstanceAs(CreateRequest{Template: "grafana", ID: "grafana-t", Label: "T",
		Groups: GroupChoice{Mode: GroupsExisting, Users: "team", Admins: "team"}}, directory.Human("root")); statusOf(err) != 503 {
		t.Errorf("no users & groups = %v", err)
	}
	if _, ok := f.h.InstanceView("grafana-t"); ok {
		t.Error("created despite a refusal")
	}
}

func TestCreateAllowsLldapAdminAsAdmins(t *testing.T) {
	f, g, _ := boundFixture(t, "team", "lldap_admin")
	if v, _ := f.h.InstanceView("grafana-t"); v.AdminGroup != "lldap_admin" {
		t.Errorf("view = %+v", v)
	}
	if c := g.Calls(); len(c) != 0 {
		t.Errorf("group calls = %v", c)
	}
}

func TestSetLabelChangesOnlyNames(t *testing.T) {
	f, audit, _ := grafanaB(t)
	before, _ := f.h.InstanceView("grafana-b")
	envBefore := readFile(t, f.h.envPath("grafana-b"))
	if before.Label != "grafana-b" || before.Name != "Grafana · grafana-b" {
		t.Fatalf("default label = %+v", before)
	}
	n := len(audit.entries)
	if err := f.h.SetLabel(context.Background(), "grafana-b", "Team B", root); err != nil {
		t.Fatal(err)
	}
	after, _ := f.h.InstanceView("grafana-b")
	if after.Label != "Team B" || after.Name != "Grafana · Team B" || after.Project != before.Project ||
		after.AccessGroup != before.AccessGroup || after.Hosts["grafana"] != before.Hosts["grafana"] || after.State != StateEnabled {
		t.Errorf("after = %+v, before = %+v", after, before)
	}
	if e := audit.last(); e.Action != "instance.update" || e.Detail != "label grafana-b -> Team B" || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	if readFile(t, f.h.envPath("grafana-b")) != envBefore {
		t.Error("the label changed the .env")
	}
	var portal PortalDocument
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(f.data, "portal-apps.json"))), &portal); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range portal.Apps {
		found = found || (a.ID == "grafana-b" && a.Name == "Grafana · Team B")
	}
	if !found {
		t.Errorf("portal-apps.json = %+v", portal.Apps)
	}
	// Unchanged: 200, not audited.
	n = len(audit.entries)
	if err := f.h.SetLabel(context.Background(), "grafana-b", "Team B", root); err != nil || len(audit.entries) != n {
		t.Errorf("unchanged = %v, %d new audit entries", err, len(audit.entries)-n)
	}
	// Refusals.
	if err := f.h.SetLabel(context.Background(), "grafana-b", "bad\n", root); statusOf(err) != 400 {
		t.Errorf("invalid = %v", err)
	}
	if err := f.h.SetLabel(context.Background(), "nope-x", "X", root); statusOf(err) != 404 {
		t.Errorf("unknown = %v", err)
	}
	unlock, _ := f.h.lockApp("grafana-b")
	if err := f.h.SetLabel(context.Background(), "grafana-b", "Busy", root); err == nil {
		t.Error("busy instance relabelled")
	}
	unlock()

	// Lifecycle unaffected: restart, backup, restore keep the current
	// label; restore-as takes the archive's (or the request's).
	if err := f.h.RestartApp("grafana-b"); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("grafana-b", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetLabel(context.Background(), "grafana-b", "Team C", root); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("grafana-b"); v.Label != "Team C" || v.State != StateEnabled {
		t.Errorf("after the restore = %+v", v)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", root); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("grafana-c"); v.Label != "Team B" {
		t.Errorf("restore-as label = %+v", v)
	}
	if _, _, err := f.h.runOpSync("grafana-d", OpRestore, root, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		res, err := f.h.restoreInstanceAs(ctx, entry.Archive, "grafana-d", root, nil, "Own", ready)
		return nil, restoreWarnings(res), err
	}); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("grafana-d"); v.Label != "Own" {
		t.Errorf("restore-as with a label = %+v", v)
	}
	if _, err := f.h.StartRestoreAs(entry.Archive, "grafana-e", root, nil, "bad\u200b"); statusOf(err) != 400 {
		t.Errorf("restore-as bad label = %v", err)
	}
	if _, err := f.h.DeleteInstance("grafana-b", "grafana-b", root); err != nil {
		t.Fatal(err)
	}
}

// TestSetLabelDefaultInstanceKeepsEntry: a default instance's label is
// stored on a state entry that a later hostname reset doesn't drop.
func TestSetLabelDefaultInstanceKeepsEntry(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.SetAudit(&fakeAudit{})
	if v, _ := f.h.InstanceView("grafana"); v.Label != "Grafana" || v.Name != "Grafana · Grafana" {
		t.Errorf("default = %+v", v)
	}
	if err := f.h.SetLabel(context.Background(), "grafana", "Home", root); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetHosts("grafana", map[string]string{"grafana": "dash.example.org"}, root); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetHosts("grafana", map[string]string{"grafana": "grafana.example.org"}, root); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("grafana"); v.Label != "Home" || v.Hosts["grafana"] != "grafana.example.org" {
		t.Errorf("after hosts back = %+v", v)
	}
}

func TestSetLabelReassertsConsentText(t *testing.T) {
	a := newLifecycleFixture(t)
	audit := &fakeAudit{}
	a.h.SetAudit(audit)
	if err := a.h.SetLabel(context.Background(), "aiapp", "Office", root); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{tokScope, hdrScope} {
		if sc, _ := a.kc.scope(s); sc.ConsentText != "Use AI App · Office (aiapp.example.com) as you" {
			t.Errorf("scope %s = %+v", s, sc)
		}
	}
	// A Keycloak failure: 502, the label unchanged, the text put back.
	a.kc.mu.Lock()
	a.kc.failEnsure = map[string]error{hdrScope: errors.New("keycloak down")}
	a.kc.mu.Unlock()
	n := len(audit.entries)
	err := a.h.SetLabel(context.Background(), "aiapp", "Lab", root)
	if statusOf(err) != 502 {
		t.Fatalf("failure = %v", err)
	}
	if v, _ := a.h.InstanceView("aiapp"); v.Label != "Office" {
		t.Errorf("label = %q after a failure", v.Label)
	}
	if sc, _ := a.kc.scope(tokScope); sc.ConsentText != "Use AI App · Office (aiapp.example.com) as you" {
		t.Errorf("tok not put back: %+v", sc)
	}
	if len(audit.entries) != n+1 || audit.last().Result != "error" {
		t.Errorf("audit = %+v", audit.last())
	}
	a.kc.mu.Lock()
	a.kc.failEnsure = nil
	a.kc.mu.Unlock()
	// No AI Keycloak: 502 too.
	a.h.SetAIKeycloak(nil)
	if err := a.h.SetLabel(context.Background(), "aiapp", "Lab", root); statusOf(err) != 502 {
		t.Errorf("no AI Keycloak = %v", err)
	}
}

func TestFirstInstanceIDIsTemplateID(t *testing.T) {
	f := newInstanceFixture(t, nil)
	g := &fakeGroups{}
	f.h.SetGroups(g)
	res, err := f.h.CreateInstanceAs(createReq("grafana", "grafana", "Home"), directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Default || res.State != StateCreated || res.Name != "Grafana · Home" || res.Project != "portcullis-grafana" ||
		res.AccessGroup != "users_grafana" || res.Hosts["grafana"] != "grafana.example.org" {
		t.Errorf("first instance = %+v", res.InstanceView)
	}
	if got := strings.Join(g.Calls(), ","); got != "+users_grafana:root,+admin_grafana:root" {
		t.Errorf("groups = %s", got)
	}
	st, _ := state.Load(f.h.statePath())
	if e := st.Instances["grafana"]; e.Template != "grafana" || e.Label != "Home" || len(e.Hosts) != 0 {
		t.Errorf("entry = %+v", e)
	}
	// It exists now: 409.
	if _, err := f.h.CreateInstanceAs(createReq("grafana", "grafana", "Again"), directory.Human("root")); statusOf(err) != 409 {
		t.Errorf("again = %v", err)
	}
	// An enabled default instance exists too.
	simulateCompose(f, 0)
	if err := f.h.Enable("chat"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.CreateInstanceAs(createReq("chat", "chat", "Chat"), directory.Human("root")); statusOf(err) != 409 {
		t.Errorf("enabled default = %v", err)
	}
	// A single template accepts only its own id.
	if _, err := f.h.CreateInstanceAs(createReq("disks", "disks", "Disks"), directory.Human("root")); err != nil {
		t.Errorf("single first = %v", err)
	}
	if _, err := f.h.CreateInstanceAs(createReq("disks", "disks-b", "B"), directory.Human("root")); statusOf(err) != 409 {
		t.Errorf("single other = %v", err)
	}
	// Enabling it clears "created"; its label stays.
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("grafana"); v.State != StateEnabled || v.Label != "Home" {
		t.Errorf("enabled = %+v", v)
	}
}

func TestInstanceNameEverywhere(t *testing.T) {
	// The call sites: every place the Hub names an instance to people
	// goes through instanceName (portal, My apps, directory apps, the
	// people reads, consent text, confirmations, entries' refusal, AI
	// activity).
	want := map[string]int{"portal.go": 1, "myapps.go": 1, "directory.go": 1, "people_reads.go": 3,
		"ai_instance.go": 1, "confirm.go": 1, "entries.go": 1, "ai_accesslog.go": 1,
		// The instance views' name (§11.7), new with labels.
		"instances.go": 1}
	files, _ := filepath.Glob("*.go")
	got := map[string]int{}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") || p == "labels.go" {
			continue
		}
		b, _ := os.ReadFile(p)
		if c := strings.Count(string(b), "instanceName("); c > 0 {
			got[p] = c
		}
	}
	total := 0
	for p, c := range want {
		total += c
		if got[p] != c {
			t.Errorf("%s: %d instanceName calls, want %d", p, got[p], c)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("%s calls instanceName: add it here", p)
		}
	}
	if total != 11 {
		t.Errorf("%d call sites, want the 10 of §11.9 plus the instance views", total)
	}

	f := newInstanceFixture(t, nil)
	f.h.SetAudit(&fakeAudit{})
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 0)
	if _, err := f.h.CreateInstanceAs(createReq("grafana", "grafana-a", "Team A"), root); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-a"); err != nil {
		t.Fatal(err)
	}
	check := func(where, name string) {
		t.Helper()
		if name != "Grafana · Team A" {
			t.Errorf("%s: name = %q", where, name)
		}
	}
	for _, a := range f.h.Portal().Apps {
		if a.ID == "grafana-a" {
			check("portal", a.Name)
		}
	}
	for _, a := range f.h.DirectoryApps() {
		if a.ID == "grafana-a" {
			check("directory apps", a.Name)
		}
	}
	v, _ := f.h.InstanceView("grafana-a")
	check("instance view", v.Name)
	f.h.mu.RLock()
	tv := *f.h.findLocked("grafana-a")
	f.h.mu.RUnlock()
	check("instanceName", instanceName(&tv))
	// The default instance without a stored label: the manifest's name.
	f.h.mu.RLock()
	dv := *f.h.findLocked("grafana")
	f.h.mu.RUnlock()
	if n := instanceName(&dv); n != "Grafana · Grafana" {
		t.Errorf("default = %q", n)
	}
}

func stepDetail(r *OpRecord, key string) string {
	for _, s := range r.Steps {
		if s.Key == key {
			return s.Detail
		}
	}
	return ""
}
