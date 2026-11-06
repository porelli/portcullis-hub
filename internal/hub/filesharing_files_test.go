package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Plan 3 Task 10: the data files and hooks file-sharing apps read — the
// tsv people file (§13.7) with person ids, id-bound share groups
// expanded to members (§13.2 / §13.5, F3), requires_any (§13.9, F2),
// PORTCULLIS_LOCAL_NETWORKS (§3.1 / §14.7, F35) and hook reports
// (§13.8, F32). Fixture: credSvcFixture (smbfixture enabled; alice, bob
// and root in users_smbfixture; carol in LLDAP only).

// tsvPath is instance id's people file.
func (f *fixture) tsvPath(id string) string {
	return filepath.Join(f.project, "appfiles", id, "people", "people.tsv")
}

// tsvLines are instance id's people.tsv lines (fatal when missing).
func tsvLines(t *testing.T, f *fixture, id string) []string {
	t.Helper()
	b, err := os.ReadFile(f.tsvPath(id))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// shareSetup adds office_milan (alice, bob, carol — carol outside the
// population) and saves share 1 = Family, readers office_milan, writers
// users_smbfixture; then delivers.
func shareSetup(t *testing.T, c *credSvc) *SaveResult {
	t.Helper()
	c.people.addGroup("office_milan", "alice", "bob", "carol")
	res, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals(
		"share1_name", "Family",
		"share1_readers", []string{"office_milan"},
		"share1_writers", []string{"users_" + smbID},
	)}, "root")
	if err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	return res
}

func TestTSVPeopleFile(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	f := c.f
	fi, err := os.Stat(f.tsvPath(smbID))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Errorf("people.tsv mode = %v, want 0640", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(f.project, "appfiles", smbID, "people", "people.json")); !os.IsNotExist(err) {
		t.Errorf("a people.json next to people.tsv: %v", err)
	}
	lines := tsvLines(t, f, smbID)
	if lines[0] != "version\t1" || lines[1] != "instance\t"+smbID {
		t.Fatalf("head = %q", lines[:2])
	}
	if !slices.IsSorted(lines[2:]) {
		t.Errorf("lines not sorted: %q", lines)
	}
	alice, bob, root := mustPersonID(t, f.h, "alice"), mustPersonID(t, f.h, "bob"), mustPersonID(t, f.h, "root")
	for _, want := range []string{
		"value\tconnect_address\tfiles.example.org",
		"value\tshare1_name\tFamily",
		"value\tshare1_readers\talice,bob",
		"value\tshare1_writers\talice,bob,root",
		"value\tshare2_readers\t",
		"value\tshare2_writers\t",
		"person\talice\tuid\t" + strconv.Itoa(alice),
		"person\tbob\tuid\t" + strconv.Itoa(bob),
		"person\troot\tuid\t" + strconv.Itoa(root),
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("people.tsv lacks %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	for _, l := range lines {
		if strings.Contains(l, "carol") {
			t.Errorf("carol (outside the population) in the file: %q", l)
		}
		if strings.Contains(l, "share_password") || strings.Contains(l, "office_milan") {
			t.Errorf("unexpected line %q", l)
		}
	}
	// Mounted as a directory, read-only.
	ov, err := os.ReadFile(f.h.overridePath(smbID))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ov), "/appfiles/"+smbID+"/people:/portcullis/data:ro") {
		t.Errorf("override lacks the people mount:\n%s", ov)
	}
}

// TestPersonIDsAllocatedAtStart: the start's data files carry each
// member's id (ensurePersonIDs before deliverForStart's render); a member
// without an LLDAP uuid gets no id and is left out (F9) — also of the
// expanded share lists.
func TestPersonIDsAllocatedAtStart(t *testing.T) {
	c := credSvcFixture(t)
	// dave joins without an LLDAP uuid.
	c.people.set(func(p *fakePeople) { p.uuids = map[string]string{"dave": ""} })
	c.people.addGroup("users_"+smbID, "dave")
	c.people.addGroup("office_milan", "alice", "dave")
	if err := c.f.h.save(smbID, SettingsUpdate{Values: vals("share1_readers", []string{"office_milan"})}); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if err := c.f.h.Disable(smbID); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(c.f.project, "appfiles", smbID)); err != nil {
		t.Fatal(err)
	}
	c.f.h.mu.Lock()
	c.f.h.st.PersonIDs = map[string]state.PersonIDPool{} // nobody has an id yet: the start allocates
	c.f.h.mu.Unlock()
	if err := c.f.h.Enable(smbID); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait()
	lines := tsvLines(t, c.f, smbID)
	if !slices.Contains(lines, "person\talice\tuid\t"+strconv.Itoa(mustPersonID(t, c.f.h, "alice"))) {
		t.Errorf("no uid line for alice:\n%s", strings.Join(lines, "\n"))
	}
	if _, ok := c.f.h.PersonID(templates.PoolPOSIXUID, "dave"); ok {
		t.Error("dave has no uuid but got an id")
	}
	for _, l := range lines {
		if strings.Contains(l, "dave") {
			t.Errorf("dave (no uuid, no id) in the file: %q", l)
		}
	}
	if !slices.Contains(lines, "value\tshare1_readers\talice") {
		t.Errorf("readers:\n%s", strings.Join(lines, "\n"))
	}
	c.f.h.mu.RLock()
	got := c.f.h.expandedMembersLocked(c.f.h.findLocked(smbID), mustMembership(t, c.f.h))
	c.f.h.mu.RUnlock()
	if !slices.Equal(got["share1_readers"], []string{"alice"}) || slices.Contains(got[membersPopulation], "dave") {
		t.Errorf("expandedMembersLocked = %v, not what the file holds", got)
	}
}

func mustMembership(t *testing.T, h *Hub) *directory.Membership {
	t.Helper()
	m, err := h.membership(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExpandMembersPopulationOnly(t *testing.T) {
	c := credSvcFixture(t)
	res := shareSetup(t, c)
	want := "1 member of office_milan has no access to SMB Fixture and won't get this share"
	if !slices.Contains(res.Warnings, want) {
		t.Errorf("warnings = %q, want %q", res.Warnings, want)
	}
	// The stored value is bound to the group's LLDAP id.
	s := storedSettings(c.f, smbID)
	if got := s.GroupIDs["share1_readers"]["office_milan"]; got == 0 || got != c.people.id("office_milan") {
		t.Errorf("share1_readers bound to %d, want %d (%+v)", got, c.people.id("office_milan"), s.GroupIDs)
	}
	// Unknown groups are refused.
	if _, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share2_readers", []string{"nope"})}, "root"); statusOf(err) != 400 || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown group = %v", err)
	}
	// What the holder check compares is what the file holds.
	c.f.h.mu.RLock()
	got := c.f.h.expandedMembersLocked(c.f.h.findLocked(smbID), mustMembership(t, c.f.h))
	c.f.h.mu.RUnlock()
	if !slices.Equal(got["share1_readers"], []string{"alice", "bob"}) || !slices.Equal(got["share1_writers"], []string{"alice", "bob", "root"}) {
		t.Errorf("expandedMembersLocked = %v", got)
	}
	if d := c.f.h.loadDelivered(smbID).Members; !slices.Equal(d["share1_readers"], []string{"alice", "bob"}) {
		t.Errorf("delivered members = %v", d)
	}
}

// TestShareGroupRecreatedGrantsNothing (F3): office_milan deleted and
// re-created straight in LLDAP (another id) — its members get nothing
// from the stored value even before any purge (the sanity check fails
// here: no user sweep), and a save resending the old name is 409.
func TestShareGroupRecreatedGrantsNothing(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	old := c.people.id("office_milan")
	c.people.deleteGroup("office_milan")
	c.people.addGroup("office_milan", "alice", "bob")
	if c.people.id("office_milan") == old {
		t.Fatal("re-created group kept its id")
	}
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	lines := tsvLines(t, c.f, smbID)
	if !slices.Contains(lines, "value\tshare1_readers\t") {
		t.Errorf("a re-created group still grants the share:\n%s", strings.Join(lines, "\n"))
	}
	c.f.h.mu.RLock()
	got := c.f.h.expandedMembersLocked(c.f.h.findLocked(smbID), mustMembership(t, c.f.h))
	c.f.h.mu.RUnlock()
	if len(got["share1_readers"]) != 0 {
		t.Errorf("expandedMembersLocked = %v", got)
	}
	_, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_readers", []string{"office_milan", "users_" + smbID})}, "root")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "office_milan was re-created") {
		t.Errorf("stale rebind = %v", err)
	}
}

// TestShareGroupPurged (F3, §13.11): deleting the group through the Hub
// purges it from every instance value (audited settings.purge), and a
// group re-created under the name grants nothing.
func TestShareGroupPurged(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	old := c.people.id("office_milan")
	c.people.deleteGroup("office_milan")
	if w := c.f.h.PurgeGroupSettings(context.Background(), "root", "office_milan", old); len(w) != 0 {
		t.Fatalf("warnings %v", w)
	}
	settle(c.f)
	s := storedSettings(c.f, smbID)
	if v := s.Values["share1_readers"]; v == nil || len(v.([]any)) != 0 {
		t.Errorf("share1_readers after the purge = %#v", v)
	}
	if _, ok := s.GroupIDs["share1_readers"]["office_milan"]; ok {
		t.Errorf("binding kept: %+v", s.GroupIDs)
	}
	purges := auditsOf(c.audit, "settings.purge")
	if len(purges) != 1 || purges[0].Actor != "root" || purges[0].Target != smbID+"/share1_readers" || !strings.Contains(purges[0].Detail, "office_milan") {
		t.Errorf("purge audit = %+v", purges)
	}
	c.people.addGroup("office_milan", "alice", "bob")
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if lines := tsvLines(t, c.f, smbID); !slices.Contains(lines, "value\tshare1_readers\t") {
		t.Errorf("the re-created group grants the share:\n%s", strings.Join(lines, "\n"))
	}
}

// TestShareGroupReconciled: a group re-created outside the Hub is purged
// from the value by the reconcile (LLDAP sane), audited by hub.
func TestShareGroupReconciled(t *testing.T) {
	c := credSvcFixture(t)
	c.f.h.SetUserSweep(c.people, nil)
	shareSetup(t, c)
	c.people.deleteGroup("office_milan")
	c.people.addGroup("office_milan", "alice")
	c.f.h.reconcileGroupRows(context.Background(), smbID)
	s := storedSettings(c.f, smbID)
	if v, _ := s.Values["share1_readers"].([]any); len(v) != 0 {
		t.Errorf("share1_readers = %v", s.Values["share1_readers"])
	}
	if w := s.Values["share1_writers"].([]any); len(w) != 1 {
		t.Errorf("share1_writers touched: %v", w)
	}
	purges := auditsOf(c.audit, "settings.purge")
	if len(purges) != 1 || purges[0].Actor != "hub" || purges[0].Target != smbID+"/share1_readers" {
		t.Errorf("purge audit = %+v", purges)
	}
}

// TestShareRemovalChangesTheFile (F28 with id-bound groups): bob leaves
// office_milan → the holder check delivers at once, the file changes and
// the membership_change hook runs.
func TestShareRemovalChangesTheFile(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	execs := len(c.f.engine.ExecCalls())
	c.people.removeMember("office_milan", "bob")
	if _, err := c.f.h.CheckCredentialHolders(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.f.h.Wait()
	if lines := tsvLines(t, c.f, smbID); !slices.Contains(lines, "value\tshare1_readers\talice") {
		t.Errorf("readers after the removal:\n%s", strings.Join(lines, "\n"))
	}
	calls := c.f.engine.ExecCalls()
	if len(calls) <= execs {
		t.Fatal("no hook ran after the removal")
	}
	var in settings.HookInput
	if err := json.Unmarshal(calls[len(calls)-1].in.Stdin, &in); err != nil || in.Trigger != "membership_change" {
		t.Errorf("hook trigger = %q (%v)", in.Trigger, err)
	}
}

func TestRequiresAnyOnSave(t *testing.T) {
	c := credSvcFixture(t)
	_, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_folder", directory.Human("/srv/share1"))}, "root")
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "share1_folder") {
		t.Fatalf("a folder without readers or writers = %v", err)
	}
	c.people.addGroup("office_milan", "alice")
	if _, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_folder", "/srv/share1", "share1_writers", []string{"office_milan"})}, "root"); err != nil {
		t.Fatalf("with writers: %v", err)
	}
	_, err = c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_writers", []string{})}, "root")
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "share1_folder") {
		t.Errorf("emptying the last group = %v", err)
	}
}

func envValue(t *testing.T, f *fixture, id, k string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(f.h.envPath(id))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, k+"="); ok {
			return v, true
		}
	}
	return "", false
}

func TestLocalNetworksEnv(t *testing.T) {
	c := credSvcFixture(t)
	f := c.f
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	settle(f)
	want := "'10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,100.64.0.0/10'"
	for _, id := range []string{smbID, "grafana"} {
		if v, ok := envValue(t, f, id, templates.VarLocalNetworks); !ok || v != want {
			t.Errorf("%s: %s=%s (%v), want %s", id, templates.VarLocalNetworks, v, ok, want)
		}
	}
	if !f.h.Template(smbID).UsesLocalNetworks || f.h.Template("grafana").UsesLocalNetworks {
		t.Error("UsesLocalNetworks not cached at Discover")
	}
	before := len(f.runner.Calls())
	if err := f.h.SetLocalNetworks([]string{}, directory.Human("root")); err != nil {
		t.Fatalf("an empty list: %v", err)
	}
	f.h.Wait()
	calls := f.runner.Calls()[before:]
	if !slices.Contains(calls, "up:"+smbProject) {
		t.Errorf("smbfixture not restarted: %v", calls)
	}
	for _, call := range calls {
		if strings.HasSuffix(call, ":"+ProjectPrefix+"grafana") {
			t.Errorf("grafana (no reference) restarted: %v", calls)
		}
	}
	// Empty: written KEY= like every empty Hub value (compose reads '').
	if v, ok := envValue(t, f, smbID, templates.VarLocalNetworks); !ok || v != "" {
		t.Errorf("saved empty: %s=%s (%v), want empty", templates.VarLocalNetworks, v, ok)
	}
	if err := f.h.SetLocalNetworks([]string{"192.168.1.0/24"}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if v, _ := envValue(t, f, smbID, templates.VarLocalNetworks); v != "'192.168.1.0/24'" {
		t.Errorf("%s=%s", templates.VarLocalNetworks, v)
	}
}

// answerHooks makes the engine's hook execs answer out with exit code.
func answerHooks(f *fixture, out string, code int) {
	f.engine.mu.Lock()
	f.engine.execStdin = func(string, docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte(out), ExitCode: code}, nil
	}
	f.engine.mu.Unlock()
}

const goodReport = `PORTCULLIS-REPORT {"version": 1, "findings": [` +
	`{"code": "former_account", "severity": "warning", "subject": "alice", "message": "alice's folder belongs to a former account (uid 20555)", "uid": 20555},` +
	`{"code": "wrong_owner", "severity": "warning", "subject": "mallory", "message": "not in the population"},` +
	`{"code": "name_refused", "severity": "info", "subject": "Family", "message": "Family is reserved"},` +
	`{"code": "name_refused", "severity": "info", "subject": "Nope", "message": "no such share"}],` +
	` "folders": [{"option": "share1_folder", "name": "alice", "uid": 20556, "former": true, "bytes": 1024},` +
	`{"option": "nope", "name": "bob", "uid": 20000, "former": false, "bytes": null}]}`

func TestHookReportStored(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	f := c.f
	answerHooks(f, "syncing\n"+goodReport+"\ndone\n", 0)
	rep, err := f.h.Deliver(context.Background(), smbID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range rep.Units {
		if u.Unit == "hook:sync" && !u.OK {
			t.Fatalf("hook unit = %+v", u)
		}
	}
	got, ok := f.h.HookReport(smbID)
	if !ok {
		t.Fatal("no stored report")
	}
	if got.ReceivedAt.IsZero() || got.Hook != "sync" {
		t.Errorf("report meta = %+v", got)
	}
	var subjects []string
	for _, x := range got.Report.Findings {
		subjects = append(subjects, x.Subject)
	}
	if !slices.Equal(subjects, []string{"alice", "Family"}) {
		t.Errorf("findings kept = %v", subjects)
	}
	if len(got.Report.Folders) != 1 || got.Report.Folders[0].Option != "share1_folder" || got.Report.Folders[0].Name != "alice" {
		t.Errorf("folders kept = %+v", got.Report.Folders)
	}
	fi, err := os.Stat(filepath.Join(f.data, "settings", smbID, "hook-report.json"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("hook-report.json: %v %v", fi, err)
	}
	// The owners it lists are never allocated (F8).
	f.h.mu.RLock()
	seen := slices.Clone(f.h.st.PersonIDs[templates.PoolPOSIXUID].Seen)
	f.h.mu.RUnlock()
	var ids []int
	for _, s := range seen {
		ids = append(ids, s.ID)
	}
	if !slices.Contains(ids, 20555) || !slices.Contains(ids, 20556) || slices.Contains(ids, 20000) {
		t.Errorf("seen owners = %v", ids)
	}
	// The admin's credentials view lists the folders.
	views, err := f.h.Credentials(context.Background(), smbID)
	if err != nil || len(views) != 1 || len(views[0].Folders) != 1 || views[0].Folders[0].Name != "alice" {
		t.Errorf("Credentials folders = %+v (%v)", views, err)
	}

	// A malformed report: logged and ignored, the unit stays OK, the
	// last accepted report is kept.
	answerHooks(f, "PORTCULLIS-REPORT {\"version\": 2}\n", 0)
	rep, err = f.h.Deliver(context.Background(), smbID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range rep.Units {
		if u.Unit == "hook:sync" && !u.OK {
			t.Errorf("a malformed report failed the unit: %+v", u)
		}
	}
	if again, ok := f.h.HookReport(smbID); !ok || len(again.Report.Findings) != 2 {
		t.Errorf("the last accepted report was replaced: %+v", again)
	}

	// A failing hook: the report line never reaches the op record.
	answerHooks(f, "oops\n"+goodReport+"\n", 3)
	if _, err := f.h.Deliver(context.Background(), smbID, TriggerRetry); err != nil {
		t.Fatal(err)
	}
	last := f.h.LastOp(smbID)
	if last == nil || last.OK || !strings.Contains(last.Error, "oops") {
		t.Fatalf("op record = %+v", last)
	}
	if strings.Contains(last.Error, "PORTCULLIS-REPORT") || strings.Contains(last.Error, "former_account") {
		t.Errorf("the report line is in the op record: %q", last.Error)
	}
	for _, u := range f.h.DeliveryStatus(smbID).Units {
		if strings.Contains(u.Error, "PORTCULLIS-REPORT") {
			t.Errorf("the report line is in unit %s: %q", u.Unit, u.Error)
		}
	}
}

// Fix round 1 #1: a re-created account (another LLDAP uuid) never gets
// the former account's uid, even when its own can't be allocated: it is
// left out of the file.
func TestRecreatedAccountNoOldUID(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	old := mustPersonID(t, c.f.h, "alice")
	c.f.h.mu.Lock()
	p := c.f.h.st.PersonIDs[templates.PoolPOSIXUID]
	p.Next = 60000 // exhausted: ensurePersonIDs fails for the new account
	c.f.h.st.PersonIDs[templates.PoolPOSIXUID] = p
	c.f.h.mu.Unlock()
	c.people.recreate("alice")
	c.people.addGroup("users_"+smbID, "alice")
	c.people.addGroup("office_milan", "alice")
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	for _, l := range tsvLines(t, c.f, smbID) {
		if strings.Contains(l, "alice") || strings.Contains(l, strconv.Itoa(old)) {
			t.Errorf("the re-created alice (or her former uid %d) is in the file: %q", old, l)
		}
	}
	c.f.h.mu.RLock()
	got := c.f.h.expandedMembersLocked(c.f.h.findLocked(smbID), mustMembership(t, c.f.h))
	c.f.h.mu.RUnlock()
	if slices.Contains(got[membersPopulation], "alice") || slices.Contains(got["share1_readers"], "alice") {
		t.Errorf("expandedMembersLocked = %v", got)
	}
}

// Fix round 1 #4: the panel shows each instance group value's bound id
// and sends it back; a name sent with an id that isn't stored for it is
// 409 (a stale panel never re-binds a purged or re-created group); a name
// without an id is new.
func TestShareGroupStalePanel(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	old := c.people.id("office_milan")
	p, err := c.f.h.SettingsPanel(context.Background(), smbID)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.InstanceGroupIDs["share1_readers"]["office_milan"]; got != old {
		t.Fatalf("panel instance_group_ids = %+v", p.InstanceGroupIDs)
	}
	// Purged and re-created meanwhile; the panel resends what it showed.
	c.people.deleteGroup("office_milan")
	c.f.h.PurgeGroupSettings(context.Background(), "root", "office_milan", old)
	c.people.addGroup("office_milan", "alice")
	settle(c.f)
	stale := SettingsUpdate{
		Values:        vals("share1_readers", []string{"office_milan"}),
		ValueGroupIDs: map[string]map[string]int{"share1_readers": {"office_milan": old}},
	}
	if _, err := c.f.h.SaveSettings(smbID, stale, directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "re-created since it was saved") {
		t.Errorf("stale panel save = %v", err)
	}
	if _, err := c.f.h.PreviewSettings(context.Background(), smbID, stale); statusOf(err) != 409 {
		t.Errorf("stale panel preview = %v", err)
	}
	// Without an id: a new name, bound to the group's current id.
	if _, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_readers", []string{"office_milan"})}, "root"); err != nil {
		t.Fatalf("a new name: %v", err)
	}
	if got := storedSettings(c.f, smbID).GroupIDs["share1_readers"]["office_milan"]; got != c.people.id("office_milan") {
		t.Errorf("bound to %d", got)
	}
	// The current id sent back: accepted.
	cur := SettingsUpdate{
		Values:        vals("share1_readers", []string{"office_milan", "users_" + smbID}),
		ValueGroupIDs: map[string]map[string]int{"share1_readers": {"office_milan": c.people.id("office_milan")}},
	}
	if _, err := c.f.h.SaveSettings(smbID, cur, directory.Human("root")); err != nil {
		t.Errorf("the current id: %v", err)
	}
}

// Fix round 1 #5: an expired membership of a share group is left out of
// the expanded list.
func TestExpiredShareMemberLeftOut(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	c.people.set(func(p *fakePeople) { p.expired["bob"] = map[string]bool{"office_milan": true} })
	if _, err := c.f.h.Deliver(context.Background(), smbID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	lines := tsvLines(t, c.f, smbID)
	if !slices.Contains(lines, "value\tshare1_readers\talice") || !slices.Contains(lines, "value\tshare1_writers\talice,bob,root") {
		t.Errorf("readers / writers:\n%s", strings.Join(lines, "\n"))
	}
}

// Fix round 1 #5: with the directory down the last people.tsv is kept and
// a hook report is ignored (its subjects can't be checked).
func TestDirectoryDownKeepsFileIgnoresReport(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	before, err := os.ReadFile(c.f.tsvPath(smbID))
	if err != nil {
		t.Fatal(err)
	}
	c.people.set(func(p *fakePeople) { p.err = errors.New("lldap down") })
	answerHooks(c.f, goodReport+"\n", 0)
	rep, err := c.f.h.Deliver(context.Background(), smbID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	for _, u := range rep.Units {
		if u.Unit == "file:people" && u.Skipped != SkipDirectory {
			t.Errorf("people unit = %+v", u)
		}
		if u.Unit == "hook:sync" && u.OK {
			ran = true
		}
	}
	if !ran {
		t.Fatalf("the hook didn't run: %+v", rep.Units)
	}
	after, _ := os.ReadFile(c.f.tsvPath(smbID))
	if string(after) != string(before) {
		t.Errorf("people.tsv changed with the directory down:\n%s", after)
	}
	if r, ok := c.f.h.HookReport(smbID); ok {
		t.Errorf("a report was stored with the directory down: %+v", r)
	}
}

// Fix round 1 #6: saving the same effective list restarts nothing.
func TestLocalNetworksUnchangedNoRestart(t *testing.T) {
	c := credSvcFixture(t)
	f := c.f
	for _, step := range []struct {
		name  string
		cidrs []string
		want  bool
	}{
		{"defaults again", nil, false},
		{"defaults written out", append([]string{}, DefaultLocalNetworks...), false},
		{"a change", []string{"192.168.1.0/24"}, true},
		{"the same list", []string{"192.168.1.0/24"}, false},
	} {
		before := len(f.runner.Calls())
		if err := f.h.SetLocalNetworks(step.cidrs, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
		f.h.Wait()
		got := slices.Contains(f.runner.Calls()[before:], "up:"+smbProject)
		if got != step.want {
			t.Errorf("%s: restarted = %v, want %v", step.name, got, step.want)
		}
	}
}

// TestSaveOfHookFileRunsItsHooks (e2e Hub bug 1): a save that changes a
// data file with on_membership_change: hook runs the hooks that file
// names in the same run, once — even when the hook's own input (no
// deliveries of its own) did not change. Emptying share1_writers must
// reach Samba's sync hook.
func TestSaveOfHookFileRunsItsHooks(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	execs := len(c.f.engine.ExecCalls())
	res, err := c.f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("share1_writers", []string{})}, "root")
	if err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	if lines := tsvLines(t, c.f, smbID); !slices.Contains(lines, "value\tshare1_writers\t") {
		t.Fatalf("people.tsv after the save:\n%s", strings.Join(lines, "\n"))
	}
	if res.Deliveries == nil {
		t.Fatal("no delivery report")
	}
	var file, hook *UnitResult
	for i, u := range res.Deliveries.Units {
		switch u.Unit {
		case fileUnit("people"):
			file = &res.Deliveries.Units[i]
		case hookUnit("sync"):
			hook = &res.Deliveries.Units[i]
		}
	}
	if file == nil || !file.OK || file.Skipped != "" {
		t.Fatalf("people unit = %+v, want written", file)
	}
	if hook == nil || !hook.OK || hook.Skipped != "" {
		t.Fatalf("sync unit = %+v, want run (not skipped)", hook)
	}
	calls := c.f.engine.ExecCalls()
	if n := len(calls) - execs; n != 1 {
		t.Fatalf("hook execs in the save = %d, want 1", n)
	}
	var in settings.HookInput
	if err := json.Unmarshal(calls[len(calls)-1].in.Stdin, &in); err != nil || in.Trigger != "settings_change" {
		t.Errorf("hook trigger = %q (%v), want settings_change", in.Trigger, err)
	}
}
