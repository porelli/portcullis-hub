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
	policyPath := filepath.Join(f.data, "group-gate-policy.json")
	policyBefore := readFile(t, policyPath)
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
	if readFile(t, policyPath) != policyBefore {
		t.Error("the label changed the policy file")
	}
	// Disable and enable again after the relabel: the same instance.
	if err := f.h.Disable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("grafana-b"); v.Label != "Team B" || v.State != StateEnabled || v.Project != before.Project || v.AccessGroup != before.AccessGroup {
		t.Errorf("re-enabled = %+v", v)
	}
	if readFile(t, policyPath) != policyBefore || readFile(t, f.h.envPath("grafana-b")) != envBefore {
		t.Error("re-enabling after the relabel changed the policy file or .env")
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

// TestSetLabelDefaultInstanceKeepsEntry: a label on an implicit default
// instance (no entry, not running) is 404 — it would block the first
// create; a running default instance's label is stored on an entry that
// a later hostname reset doesn't drop.
func TestSetLabelDefaultInstanceKeepsEntry(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.SetAudit(&fakeAudit{})
	simulateCompose(f, 0)
	if v, _ := f.h.InstanceView("grafana"); v.Label != "Grafana" || v.Name != "Grafana" {
		t.Errorf("default = %+v", v)
	}
	if err := f.h.SetLabel(context.Background(), "grafana", "Home", root); statusOf(err) != 404 || !strings.Contains(err.Error(), "create the instance first") {
		t.Fatalf("implicit default = %v", err)
	}
	if _, err := f.h.CreateInstanceAs(createReq("grafana", "grafana", "Home"), root); err != nil {
		t.Fatalf("first create after the refused label = %v", err)
	}
	// An enabled default instance enabled without a create (no entry).
	if err := f.h.Enable("chat"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetLabel(context.Background(), "chat", "Talk", root); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetHosts("chat", map[string]string{"chat": "talk.example.org"}, root); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetHosts("chat", map[string]string{"chat": "chat.example.org"}, root); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("chat"); v.Label != "Talk" || v.Hosts["chat"] != "chat.example.org" {
		t.Errorf("after hosts back = %+v", v)
	}
}

// TestSetLabelPortalFailureAudit (fix round 1, item 7): a committed label
// whose portal-apps.json write failed is audited ok plus one delivery
// entry with the failure.
func TestSetLabelPortalFailureAudit(t *testing.T) {
	f, audit, _ := grafanaB(t)
	// portal-apps.json can't be replaced: a directory in its place.
	os.Remove(f.h.portalPath())
	if err := os.MkdirAll(filepath.Join(f.h.portalPath(), "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := f.h.SetLabel(context.Background(), "grafana-b", "Team B", root)
	if statusOf(err) != 500 || !strings.Contains(err.Error(), "the label was saved") {
		t.Fatalf("portal failure = %v", err)
	}
	if v, _ := f.h.InstanceView("grafana-b"); v.Label != "Team B" {
		t.Errorf("label = %q", v.Label)
	}
	n := len(audit.entries)
	if n < 2 {
		t.Fatalf("audit = %+v", audit.entries)
	}
	if a, b := audit.entries[n-2], audit.entries[n-1]; a.Detail != "label grafana-b -> Team B" || a.Result != "ok" ||
		b.Detail != "delivery" || b.Result != "error" || !strings.Contains(b.Error, "portal-apps.json") {
		t.Errorf("audit = %+v / %+v", a, b)
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
	// activity, a sign-in template's uses).
	want := map[string]int{"portal.go": 1, "myapps.go": 1, "directory.go": 1, "people_reads.go": 3,
		"ai_instance.go": 1, "confirm.go": 1, "entries.go": 1, "ai_accesslog.go": 1,
		// The instance views' name (§11.7), new with labels.
		"instances.go": 1,
		// Settings → Sign-in: a template's uses (sign-in Task 3), and the
		// needs-stronger page's app name in signin-keycloak.json (Task 4).
		"signin.go": 1, "signin_publish.go": 1, "signin_people.go": 2,
		// The MCP's sign-in classes: who a change newly blocks and what
		// inherits the default (sign-in Task 6).
		"signin_class.go": 2}
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
	if total != 17 {
		t.Errorf("%d call sites, want the 10 of §11.9 plus the instance views, the sign-in uses, signin-keycloak.json, the sign-in warnings and the MCP's sign-in classes", total)
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
	// The default instance without a stored label: the manifest's name,
	// once (ruling: a label equal to the app's name is just "<App>").
	f.h.mu.RLock()
	dv := *f.h.findLocked("grafana")
	f.h.mu.RUnlock()
	if n := instanceName(&dv); n != "Grafana" {
		t.Errorf("default = %q", n)
	}
	// A stored label equal to the app's name: "<App>" everywhere, the
	// portal included; any other label "<App> · <label>".
	if err := f.h.SetLabel(context.Background(), "grafana-a", "Grafana", root); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.InstanceView("grafana-a"); v.Name != "Grafana" || v.Label != "Grafana" {
		t.Errorf("label = app name: view %+v", v)
	}
	for _, a := range f.h.Portal().Apps {
		if a.ID == "grafana-a" && a.Name != "Grafana" {
			t.Errorf("portal name = %q, want Grafana", a.Name)
		}
	}
	for _, a := range f.h.DirectoryApps() {
		if a.ID == "grafana-a" && a.Name != "Grafana" {
			t.Errorf("directory apps name = %q, want Grafana", a.Name)
		}
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

// TestFirstInstanceUndoKeepsDefaultData (fix round 1, item 1): undoing a
// first-instance create — a failing group, a Stop — removes only its
// state entry; a previously used default instance keeps its .env,
// settings, policy and the rest.
func TestFirstInstanceUndoKeepsDefaultData(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.SetAudit(&fakeAudit{})
	g := &fakeGroups{}
	f.h.SetGroups(g)
	simulateCompose(f, 0)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings("grafana", SettingsUpdate{SignInTemplate: pickTemplate("strong"), Ports: map[string]string{"GRAFANA_PORT": "3301"}}, root); err != nil {
		t.Fatal(err)
	}
	envBefore := readFile(t, f.h.envPath("grafana"))
	ovBefore := readFile(t, f.h.overridePath("grafana"))
	snapshot := func() state.InstanceSettings {
		f.h.mu.RLock()
		defer f.h.mu.RUnlock()
		return f.h.st.Settings["grafana"].Clone()
	}
	setBefore := snapshot()
	check := func(phase string) {
		t.Helper()
		if got := readFile(t, f.h.envPath("grafana")); got != envBefore {
			t.Errorf("%s: .env changed", phase)
		}
		if got := readFile(t, f.h.overridePath("grafana")); got != ovBefore {
			t.Errorf("%s: override changed", phase)
		}
		s := snapshot()
		if s.Ports["GRAFANA_PORT"] != setBefore.Ports["GRAFANA_PORT"] || s.Ports["GRAFANA_PORT"] != "3301" {
			t.Errorf("%s: settings = %+v", phase, s)
		}
		// Only the default instance's own pick is left of its entry.
		f.h.mu.RLock()
		e, entry := f.h.st.Instances["grafana"]
		f.h.mu.RUnlock()
		if !entry || !pickOnlyEntry(e, "grafana") || e.SignInTemplate != "strong" {
			t.Errorf("%s: entry = %+v %v, want only the pick strong", phase, e, entry)
		}
	}

	// A failing group: the create is undone.
	g.createErr = func(name string) error {
		if strings.HasPrefix(name, "admin_") {
			return errors.New("lldap down")
		}
		return nil
	}
	if _, err := f.h.CreateInstanceAs(createReq("grafana", "grafana", "Home"), root); err == nil || !strings.Contains(err.Error(), "removed again") {
		t.Fatalf("group failure = %v", err)
	}
	check("group failure")
	g.createErr = nil

	// A Stop: the same.
	bg := &blockingGroups{fakeGroups: &fakeGroups{}, name: "admin_grafana", reached: make(chan struct{}), release: make(chan struct{})}
	f.h.SetGroups(bg)
	a, err := f.h.StartCreate(createReq("grafana", "grafana", "Home"), directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if r := stopAndWait(t, f.h, "grafana", a.OpID, bg.reached, bg.release); !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	check("stop")
	// It can be created afterwards.
	f.h.SetGroups(&fakeGroups{})
	if _, err := f.h.CreateInstanceAs(createReq("grafana", "grafana", "Home"), root); err != nil {
		t.Fatal(err)
	}
	if s := snapshot(); s.Ports["GRAFANA_PORT"] != "3301" {
		t.Errorf("settings after the create = %+v", s)
	}

	// Final fix I2: the setup values the stopped create stored go too.
	// The cloud template (default database mysql) with a derived users
	// group, so a Stop can land in the groups step: postgres chosen,
	// stopped → no stored database value (the entry is put back as it
	// was: none); a later create without setup gets the default.
	cm := strings.Replace(setupCloudManifest, "  method: forward-auth\n", "  method: forward-auth\n  group_access: true\n  access_group: users_cloud\n", 1)
	cf := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"cloud": {cm, setupCloudCompose}})
	if cf.h.Template("cloud") == nil {
		t.Fatal("cloud template refused")
	}
	cf.h.SetAudit(&fakeAudit{})
	simulateCompose(cf, 999)
	cf.h.mu.RLock()
	_, hadSettings := cf.h.st.Settings["cloud"]
	cf.h.mu.RUnlock()
	cbg := &blockingGroups{fakeGroups: &fakeGroups{}, name: "users_cloud", reached: make(chan struct{}), release: make(chan struct{})}
	cf.h.SetGroups(cbg)
	ca, err := cf.h.StartCreate(CreateRequest{Template: "cloud", ID: "cloud", Label: "Home", Setup: setupOf("database", `"postgres"`)}, directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if r := stopAndWait(t, cf.h, "cloud", ca.OpID, cbg.reached, cbg.release); !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	cf.h.mu.RLock()
	cs, hasSettings := cf.h.st.Settings["cloud"]
	_, entry := cf.h.st.Instances["cloud"]
	cf.h.mu.RUnlock()
	if entry || hasSettings != hadSettings || cs.Values["database"] != nil {
		t.Errorf("after the stop: entry %v, settings %v (before %v) %+v", entry, hasSettings, hadSettings, cs)
	}
	cf.h.SetGroups(&fakeGroups{})
	createCloud(t, cf, "cloud", nil)
	if v := storedSetting(cf, "cloud", "database"); v != "mysql" {
		t.Errorf("a create without setup after the stop stores %v, want the default mysql", v)
	}
}

// TestBindingRecheckedAtCommitAndEnable (fix round 1, item 4): a users
// group that becomes privileged before the commit refuses the create; one
// that becomes privileged after it refuses the enable (409).
func TestBindingRecheckedAtCommitAndEnable(t *testing.T) {
	f := newInstanceFixture(t, nil)
	g := &fakeGroups{existing: map[string]bool{"team": true, "ops": true}}
	f.h.SetGroups(g)
	simulateCompose(f, 0)
	g.checkHook = func(n int) {
		if n == 2 { // the re-check right before the commit
			g.privileged = map[string]bool{"team": true}
		}
	}
	req := CreateRequest{Template: "grafana", ID: "grafana-t", Label: "T", Groups: GroupChoice{Mode: GroupsExisting, Users: "team", Admins: "ops"}}
	if _, err := f.h.CreateInstanceAs(req, root); statusOf(err) != 400 || !strings.Contains(err.Error(), "can't be a built-in or administrator group") {
		t.Fatalf("commit re-check = %v", err)
	}
	if _, ok := f.h.InstanceView("grafana-t"); ok {
		t.Error("created despite the re-check")
	}
	g.mu.Lock()
	g.checkHook, g.privileged = nil, nil
	g.mu.Unlock()
	if _, err := f.h.CreateInstanceAs(req, root); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.privileged = map[string]bool{"team": true}
	g.mu.Unlock()
	if err := f.h.Enable("grafana-t"); statusOf(err) != 409 || !strings.Contains(err.Error(), "can't start") {
		t.Fatalf("enable = %v", err)
	}
	if f.h.IsEnabled("grafana-t") {
		t.Error("enabled on a privileged users group")
	}
	// A bound group that is gone only denies: the enable goes on.
	g.mu.Lock()
	g.privileged = nil
	delete(g.existing, "team")
	g.mu.Unlock()
	if err := f.h.Enable("grafana-t"); err != nil {
		t.Errorf("enable with the group gone = %v", err)
	}
	// Without Users & Groups the binding can't be checked: 503.
	if err := f.h.Disable("grafana-t"); err != nil {
		t.Fatal(err)
	}
	f.h.SetGroups(nil)
	if err := f.h.Enable("grafana-t"); statusOf(err) != 503 {
		t.Errorf("enable without users & groups = %v", err)
	}
}

// TestDeleteBoundEntryWithoutView (fix round 1, item 5): a bound
// instance whose template is missing and that has no snapshot deletes no
// group (never the derived names).
func TestDeleteBoundEntryWithoutView(t *testing.T) {
	f := newInstanceFixture(t, func(st *state.AppState) {
		st.Instances["gone-x"] = state.Instance{ID: "gone-x", Template: "gone", State: state.InstanceCreated, Label: "X", UsersGroup: "team", AdminsGroup: "ops"}
	})
	g := &fakeGroups{existing: map[string]bool{"team": true, "ops": true, "users_gone-x": true, "admin_gone-x": true}}
	f.h.SetGroups(g)
	if _, err := f.h.DeleteInstance("gone-x", "gone-x", root); err != nil {
		t.Fatal(err)
	}
	if c := g.Calls(); len(c) != 0 {
		t.Errorf("group calls = %v", c)
	}
}

// TestInstanceViewsStamped (fix round 1, item 3): InstanceOn is called
// only by newViewLocked, and the group readers deny on an unstamped view.
func TestInstanceViewsStamped(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(p)
		n := strings.Count(string(b), ".InstanceOn(") + strings.Count(string(b), ".Instance(")
		if want := map[bool]int{true: 1, false: 0}[p == "labels.go"]; n != want {
			t.Errorf("%s builds %d instance views directly, want %d (use newViewLocked)", p, n, want)
		}
	}
	f := newInstanceFixture(t, nil)
	f.h.mu.RLock()
	stamped := *f.h.findLocked("grafana")
	cat := *f.h.catalogLocked("chat")
	f.h.mu.RUnlock()
	if !stamped.Stamped || accessGroupOf(&stamped) != "users_grafana" {
		t.Errorf("stamped view = %v %q", stamped.Stamped, accessGroupOf(&stamped))
	}
	raw, err := cat.Instance("chat-x", nil, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if raw.Stamped || accessGroupOf(&raw) != unstampedGroup || placeholderGroup(&raw, templates.PlaceholderAccessGroup) != "" {
		t.Errorf("unstamped view = %q %q", accessGroupOf(&raw), placeholderGroup(&raw, templates.PlaceholderAccessGroup))
	}
	if _, err := accessSpec(&raw, raw.Manifest.Clients[0]); err == nil {
		t.Error("access role built on an unstamped view")
	}
}

// TestSetLabelKeepsKeycloakClients (fix round 1, item 8): a relabel and
// a disable / enable after it leave the instance's Keycloak clients (ids,
// redirect URIs) and its access role as they were.
func TestSetLabelKeepsKeycloakClients(t *testing.T) {
	// chat with its access role enforced in Keycloak (§8), as "roled".
	roled := strings.NewReplacer("chat", "roled", "Chat", "Roled", "CHAT", "ROLED").Replace(v2ChatManifest)
	roled = strings.Replace(roled, "  group_access: true\n", "  group_access: true\n  keycloak_access_role: true\n", 1)
	roledCompose := strings.NewReplacer("chat", "roled", "CHAT", "ROLED").Replace(v2ChatCompose)
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"roled": {roled, roledCompose}})
	f.h.SetAudit(&fakeAudit{})
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 0)
	if _, err := f.h.CreateInstanceAs(createReq("roled", "roled-b", "Team"), root); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("roled-b"); err != nil {
		t.Fatal(err)
	}
	clients := func() (specs []string, access []string) {
		f.idp.mu.Lock()
		defer f.idp.mu.Unlock()
		for _, s := range f.idp.specs {
			specs = append(specs, s.ClientID+" "+s.TemplateID+" "+strings.Join(s.RedirectURIs, ","))
		}
		return specs, append([]string(nil), f.idp.access...)
	}
	specs0, access0 := clients()
	if len(specs0) == 0 {
		t.Fatal("no client registered")
	}
	if err := f.h.SetLabel(context.Background(), "roled-b", "Team B", root); err != nil {
		t.Fatal(err)
	}
	if specs, access := clients(); strings.Join(specs, ";") != strings.Join(specs0, ";") || strings.Join(access, ";") != strings.Join(access0, ";") {
		t.Errorf("the relabel touched Keycloak: %v %v", specs, access)
	}
	if err := f.h.Disable("roled-b"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("roled-b"); err != nil {
		t.Fatal(err)
	}
	specs, access := clients()
	if len(access) == 0 || len(access0) == 0 {
		t.Fatalf("no access role recorded (before %v, after %v)", access0, access)
	}
	// The re-enable registers the same clients again, with the same access group.
	if len(specs) != 2*len(specs0) || strings.Join(specs[len(specs0):], ";") != strings.Join(specs0, ";") {
		t.Errorf("clients after re-enable = %v, want %v again", specs, specs0)
	}
	for _, a := range access {
		if strings.HasPrefix(a, "+") && !strings.HasSuffix(a, ":users_roled-b") {
			t.Errorf("access role = %s", a)
		}
	}
}

// TestRemoveNewInstanceDefaultWithoutEntry (fix round 2): removing a
// template's default instance with no state entry — an undo retried
// after its first save failed — wipes nothing.
func TestRemoveNewInstanceDefaultWithoutEntry(t *testing.T) {
	f := newInstanceFixture(t, nil)
	simulateCompose(f, 0)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings("grafana", SettingsUpdate{SignInTemplate: pickTemplate("strong"), Ports: map[string]string{"GRAFANA_PORT": "3301"}}, root); err != nil {
		t.Fatal(err)
	}
	env, ov := readFile(t, f.h.envPath("grafana")), readFile(t, f.h.overridePath("grafana"))
	if err := f.h.removeNewInstance("grafana", nil); err != nil {
		t.Fatal(err)
	}
	if readFile(t, f.h.envPath("grafana")) != env || readFile(t, f.h.overridePath("grafana")) != ov {
		t.Error(".env or override changed")
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	if f.h.st.Settings["grafana"].Ports["GRAFANA_PORT"] != "3301" {
		t.Errorf("settings = %+v", f.h.st.Settings["grafana"])
	}
	if e := f.h.st.Instances["grafana"]; e.SignInTemplate != "strong" {
		t.Errorf("pick = %+v", e)
	}
}

// Fix round 2: an undo with no prior record (restore-as, a retried undo)
// keeps the default instance's pick from the created entry itself, never
// falling back to the (maybe weaker) default.
func TestRemoveNewInstanceKeepsPickWithoutPrior(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if _, err := f.h.SaveSettings("grafana", SettingsUpdate{SignInTemplate: pickTemplate("strong")}, root); err != nil {
		t.Fatal(err)
	}
	if err := f.h.CreateInstance("grafana", "grafana", nil); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	created := f.h.st.Instances["grafana"]
	f.h.mu.RUnlock()
	if created.State != state.InstanceCreated || created.SignInTemplate != "strong" {
		t.Fatalf("created entry = %+v", created)
	}
	if err := f.h.removeNewInstance("grafana", nil); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	e, ok := f.h.st.Instances["grafana"]
	f.h.mu.RUnlock()
	if !ok || !pickOnlyEntry(e, "grafana") || e.SignInTemplate != "strong" {
		t.Errorf("after the undo: %+v %v, want only the pick strong", e, ok)
	}
}

// Final fix M1: an instance that can't be resolved is named like a
// resolved one — the manifest's name when its template is known (the
// label==name rule too), else the template id.
func TestUnresolvedInstanceName(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.mu.Lock()
	f.h.st.Instances["grafana-x"] = state.Instance{ID: "grafana-x", Template: "grafana", Label: "Team X"}
	f.h.st.Instances["grafana-y"] = state.Instance{ID: "grafana-y", Template: "grafana"}
	f.h.st.Instances["gone-z"] = state.Instance{ID: "gone-z", Template: "gone", Label: "Zed"}
	f.h.brokenInstances = map[string]string{"grafana-x": "x", "grafana-y": "y", "gone-z": "z", "grafana": "d"}
	f.h.mu.Unlock()
	want := map[string][2]string{
		"grafana-x": {"Team X", "Grafana · Team X"},
		"grafana-y": {"grafana-y", "Grafana · grafana-y"},
		"gone-z":    {"Zed", "gone · Zed"},
		"grafana":   {"Grafana", "Grafana"}, // a default instance without a label: just the app
	}
	seen := 0
	for _, v := range f.h.Instances() {
		if w, ok := want[v.ID]; ok && v.State == StateError {
			seen++
			if v.Label != w[0] || v.Name != w[1] {
				t.Errorf("%s: label %q name %q, want %q %q", v.ID, v.Label, v.Name, w[0], w[1])
			}
		}
	}
	if seen != len(want) {
		t.Errorf("listed %d of %d unresolved instances", seen, len(want))
	}
}
