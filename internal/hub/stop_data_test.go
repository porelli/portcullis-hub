package hub

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// Backups, restores, restores into a new id, creates and deletes report
// their steps and can be stopped (contract §11.4–11.7).

// auditEntry is a's first entry with action (zero when none).
func auditEntry(a *fakeAudit, action string) directory.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action {
			return e
		}
	}
	return directory.AuditEntry{}
}

// grafanaRunning: grafana-b's project has a running container.
func grafanaRunning(f *fixture) bool {
	f.engine.mu.Lock()
	defer f.engine.mu.Unlock()
	for _, c := range f.engine.containers {
		if c.Project() == projectName("grafana-b") && c.State == "running" {
			return true
		}
	}
	return false
}

func allDone(t *testing.T, r OpRecord) {
	t.Helper()
	for _, s := range r.Steps {
		if s.State != StepDone {
			t.Errorf("step %s: %s (%s)", s.Key, s.State, s.Detail)
		}
	}
}

// partialLeftovers are the .partial archives and staging directories in
// id's backup directory.
func partialLeftovers(f *fixture, id string) []string {
	var out []string
	es, _ := os.ReadDir(filepath.Join(f.data, "backups", id))
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".partial") || strings.HasPrefix(e.Name(), ".staging-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestBackupSteps(t *testing.T) {
	f, _, _ := grafanaB(t)
	a, err := f.h.StartBackup("grafana-b", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "grafana-b", a.OpID)
	if !r.OK {
		t.Fatalf("record %+v", r)
	}
	if got := stepKeys(r); !slices.Equal(got, []string{StepStop, "volume:grafana-data", StepArchive, StepStart}) {
		t.Fatalf("steps %v", got)
	}
	allDone(t, r)
	if r.Before["running"] != "true" || r.Stoppable {
		t.Errorf("before %v stoppable %v", r.Before, r.Stoppable)
	}
	// Not running: no stop / start.
	f.runner.onDown(projectName("grafana-b"))
	a, err = f.h.StartBackup("grafana-b", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // another second: another archive name
	r = waitOp(t, f.h, "grafana-b", a.OpID)
	if got := stepKeys(r); !r.OK || !slices.Equal(got, []string{"volume:grafana-data", StepArchive}) {
		t.Fatalf("steps %v (%+v)", got, r)
	}
}

// TestStopBackup: a Stop while a volume is copied deletes the partial
// archive and starts the app again; no archive is listed.
func TestStopBackup(t *testing.T) {
	f, audit, _ := grafanaB(t)
	reached, release := blockStep(t, f.h, "volume:grafana-data")
	a, err := f.h.StartBackup("grafana-b", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, f.h, "grafana-b", a.OpID, reached, release)
	if !r.Stopped() || r.Error != "" || r.Stoppable {
		t.Fatalf("record %+v", r)
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 0 {
		t.Errorf("archives %+v", l)
	}
	if lo := partialLeftovers(f, "grafana-b"); len(lo) != 0 {
		t.Errorf("leftovers %v", lo)
	}
	if !grafanaRunning(f) || !f.h.IsEnabled("grafana-b") {
		t.Error("not running again")
	}
	if stepOf(r, StepStop).State != StepUndone || stepOf(r, UndoStart).State != StepDone || stepOf(r, UndoArchive).State != StepDone {
		t.Errorf("steps %+v", r.Steps)
	}
	if e := auditEntry(audit, "backup.stop"); e.Result != "ok" || e.Detail != "volume:grafana-data" || e.Actor != "bob" {
		t.Errorf("audit %+v", e)
	}
}

// TestStopInterruptedBackup: a backup the Hub stopped half-way is
// stoppable; the Stop removes its partial archive and starts the app.
func TestStopInterruptedBackup(t *testing.T) {
	f, _, _ := grafanaB(t)
	f.runner.onDown(projectName("grafana-b"))
	dir := filepath.Join(f.data, "backups", "grafana-b")
	os.MkdirAll(filepath.Join(dir, ".staging-123"), 0700)
	os.WriteFile(filepath.Join(dir, "20261107T100000Z.tar.partial"), []byte("x"), 0600)
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	f.h.recordOp("grafana-b", OpRecord{Op: OpBackup, OpID: "crashed2", At: t0, Running: true, Actor: "alice", Stoppable: true,
		Before: map[string]string{"running": "true"},
		Steps: []Step{{Key: StepStop, Label: "s", State: StepDone}, {Key: "volume:grafana-data", Label: "v", State: StepRunning},
			{Key: StepArchive, Label: "a", State: StepWaiting}, {Key: StepStart, Label: "st", State: StepWaiting}},
		Created: &Created{}})
	f.h.loadOps()
	if r := f.h.LastOp("grafana-b"); !r.Interrupted || !r.Stoppable {
		t.Fatalf("interrupted %+v", r)
	}
	if _, err := f.h.StopOp("grafana-b", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "grafana-b", "crashed2")
	if !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	if lo := partialLeftovers(f, "grafana-b"); len(lo) != 0 {
		t.Errorf("leftovers %v", lo)
	}
	if !grafanaRunning(f) {
		t.Error("not started again")
	}
}

func TestRestoreSteps(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	a, err := f.h.StartRestore("grafana-b", entry.Archive, directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "grafana-b", a.OpID)
	if !r.OK {
		t.Fatalf("record %+v", r)
	}
	if got := stepKeys(r); !slices.Equal(got, []string{StepVerify, StepPreBackup, StepVolumes, StepConfig, StepStart}) {
		t.Fatalf("steps %v", got)
	}
	allDone(t, r)
	for _, k := range []string{StepVerify, StepVolumes} {
		if s := stepOf(r, k); s.Percent == nil || *s.Percent != 100 {
			t.Errorf("%s percent %v", k, s.Percent)
		}
	}
}

// TestStopRestore: a Stop once the volumes were replaced rolls the
// restore back from the pre-restore backup (rolled_back), which stays
// listed; the app runs with its previous data.
func TestStopRestore(t *testing.T) {
	f, audit, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "grafana.db", Mode: 0600, UID: 472, Body: "current"})
	reached, release := blockStep(t, f.h, StepConfig)
	a, err := f.h.StartRestore("grafana-b", entry.Archive, directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if got := f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"].Body; got != "v1" {
		t.Fatalf("volume not replaced yet: %q", got)
	}
	r := stopAndWait(t, f.h, "grafana-b", a.OpID, reached, release)
	if !r.Stopped() || !r.RolledBack || r.Error != "" {
		t.Fatalf("record %+v", r)
	}
	if got := f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"].Body; got != "current" {
		t.Errorf("volume %q", got)
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 2 {
		t.Errorf("backups %+v", l)
	}
	f.h.mu.RLock()
	st := f.h.st.Instances["grafana-b"].State
	f.h.mu.RUnlock()
	if st == state.InstanceRestoring || !f.h.IsEnabled("grafana-b") || !grafanaRunning(f) {
		t.Errorf("state %q enabled %v running %v", st, f.h.IsEnabled("grafana-b"), grafanaRunning(f))
	}
	if stepOf(r, StepVolumes).State != StepUndone || stepOf(r, UndoRollback).State != StepDone {
		t.Errorf("steps %+v", r.Steps)
	}
	if e := auditEntry(audit, "restore.stop"); e.Result != "ok" || e.Detail != StepConfig {
		t.Errorf("audit %+v", e)
	}
}

// TestStopRestoreBeforePreBackup: stopped before the pre-restore backup,
// nothing changed and nothing is rolled back.
func TestStopRestoreBeforePreBackup(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "grafana.db", Mode: 0600, UID: 472, Body: "current"})
	reached, release := blockStep(t, f.h, StepPreBackup)
	a, err := f.h.StartRestore("grafana-b", entry.Archive, directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, f.h, "grafana-b", a.OpID, reached, release)
	if !r.Stopped() || r.RolledBack {
		t.Fatalf("record %+v", r)
	}
	if got := f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"].Body; got != "current" {
		t.Errorf("volume %q", got)
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 1 {
		t.Errorf("backups %+v", l)
	}
	if !grafanaRunning(f) || !f.h.IsEnabled("grafana-b") {
		t.Error("not running")
	}
}

// TestStopRestoreAs: a Stop removes the new instance completely: its
// state, files, and the volumes and groups of the record's ledger.
func TestStopRestoreAs(t *testing.T) {
	f, audit, groups := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	reached, release := blockStep(t, f.h, StepConfig)
	a, err := f.h.StartRestoreAs(entry.Archive, "grafana-c", directory.Human("alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, f.h, "grafana-c", a.OpID, reached, release)
	if !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	if got := stepKeys(r)[:5]; !slices.Equal(got, []string{StepVerify, StepInstance, StepGroups, StepVolumes, StepConfig}) {
		t.Errorf("steps %v", got)
	}
	if !slices.Equal(r.Created.Groups, []string{"users_grafana-c", "admin_grafana-c"}) || !slices.Equal(r.Created.Volumes, []string{"portcullis_grafana-c-grafana-data"}) {
		t.Errorf("created %+v", r.Created)
	}
	if f.h.Template("grafana-c") != nil {
		t.Error("grafana-c still there")
	}
	f.h.mu.RLock()
	_, inState := f.h.st.Instances["grafana-c"]
	f.h.mu.RUnlock()
	if inState || slices.Contains(f.engine.volumeNames(), "portcullis_grafana-c-grafana-data") {
		t.Error("state or volume left")
	}
	if _, err := os.Stat(f.h.envPath("grafana-c")); !os.IsNotExist(err) {
		t.Errorf("env left: %v", err)
	}
	calls := groups.Calls()
	if !slices.Contains(calls, "-users_grafana-c:bob") || !slices.Contains(calls, "-admin_grafana-c:bob") {
		t.Errorf("groups %v", calls)
	}
	if e := auditEntry(audit, "restore.stop"); e.Result != "ok" || e.Target != "grafana-c" {
		t.Errorf("audit %+v", e)
	}
}

// blockingGroups blocks the creation of one group (outside the fake's
// lock) until release is closed.
type blockingGroups struct {
	*fakeGroups
	name             string
	reached, release chan struct{}
}

func (b *blockingGroups) CreateInstanceGroup(ctx context.Context, actor directory.Actor, name string) (bool, []string, error) {
	if name == b.name {
		close(b.reached)
		<-b.release
	}
	return b.fakeGroups.CreateInstanceGroup(ctx, actor, name)
}

func TestCreateSteps(t *testing.T) {
	f := newInstanceFixture(t, nil)
	g := &fakeGroups{}
	f.h.SetGroups(g)
	a, err := f.h.StartCreate("grafana", "grafana-b", nil, directory.Human("alice"))
	if err != nil || a.Op != OpCreate || a.Instance != "grafana-b" {
		t.Fatalf("%+v %v", a, err)
	}
	r := waitOp(t, f.h, "grafana-b", a.OpID)
	if !r.OK || r.Result["instance"] != "grafana-b" {
		t.Fatalf("record %+v", r)
	}
	if got := stepKeys(r); !slices.Equal(got, []string{StepInstance, StepGroups}) {
		t.Fatalf("steps %v", got)
	}
	allDone(t, r)
	if !slices.Equal(r.Created.Groups, []string{"users_grafana-b", "admin_grafana-b"}) {
		t.Errorf("created %+v", r.Created)
	}
	// Refusals stay synchronous, nothing recorded.
	if _, err := f.h.StartCreate("grafana", "grafana-b", nil, directory.Human("alice")); statusOf(err) != 409 {
		t.Errorf("exists: %v", err)
	}
	if _, err := f.h.StartCreate("grafana", "Bad", nil, directory.Human("alice")); statusOf(err) != 400 {
		t.Errorf("bad id: %v", err)
	}
}

// TestStopCreate: a Stop removes the new instance and exactly the groups
// it created.
func TestStopCreate(t *testing.T) {
	f := newInstanceFixture(t, nil)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	g := &blockingGroups{fakeGroups: &fakeGroups{}, name: "admin_grafana-b", reached: make(chan struct{}), release: make(chan struct{})}
	f.h.SetGroups(g)
	a, err := f.h.StartCreate("grafana", "grafana-b", nil, directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, f.h, "grafana-b", a.OpID, g.reached, g.release)
	if !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	if f.h.Template("grafana-b") != nil {
		t.Error("instance still there")
	}
	calls := g.Calls()
	if !slices.Contains(calls, "-users_grafana-b:bob") || !slices.Contains(calls, "-admin_grafana-b:bob") {
		t.Errorf("groups %v (created %+v)", calls, r.Created)
	}
	if stepOf(r, StepInstance).State != StepUndone || stepOf(r, UndoInstance).State != StepDone {
		t.Errorf("steps %+v", r.Steps)
	}
	if e := auditEntry(audit, "create.stop"); e.Result != "ok" {
		t.Errorf("audit %+v", e)
	}
}

func TestDeleteSteps(t *testing.T) {
	f, _, _ := grafanaB(t)
	a, err := f.h.StartDelete("grafana-b", "grafana-b", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "grafana-b", a.OpID)
	if !r.OK || !r.PointOfNoReturn || r.Stoppable {
		t.Fatalf("record %+v", r)
	}
	if got := stepKeys(r); !slices.Equal(got, []string{StepBackup, StepStop, StepVolumes, StepKeycloak, StepGroups, StepFiles}) {
		t.Fatalf("steps %v", got)
	}
	allDone(t, r)
}

// TestStopDeleteBeforeNoReturn: the delete is cancelled and the app is
// back as before; the delete's backup stays listed.
func TestStopDeleteBeforeNoReturn(t *testing.T) {
	f, audit, groups := grafanaB(t)
	reached, release := blockStep(t, f.h, StepStop)
	a, err := f.h.StartDelete("grafana-b", "grafana-b", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, f.h, "grafana-b", a.OpID, reached, release)
	if !r.Stopped() || r.PointOfNoReturn {
		t.Fatalf("record %+v", r)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.State == state.InstanceDeleting || e.Backup != "" || !f.h.IsEnabled("grafana-b") || !grafanaRunning(f) {
		t.Errorf("entry %+v enabled %v running %v", e, f.h.IsEnabled("grafana-b"), grafanaRunning(f))
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 1 || l[0].Reason != BackupDelete {
		t.Errorf("backups %+v", l)
	}
	if f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"].Body != "v1" || len(groups.Calls()) != 0 {
		t.Error("data or groups touched")
	}
	if e := auditEntry(audit, "delete.stop"); e.Result != "ok" || e.Detail != StepStop {
		t.Errorf("audit %+v", e)
	}
}

// TestStopDeleteAfterNoReturn: from the volumes step a Stop is refused
// 409 "past the point of no return — finishing"; the delete completes.
func TestStopDeleteAfterNoReturn(t *testing.T) {
	f, audit, _ := grafanaB(t)
	reached, release := blockStep(t, f.h, StepKeycloak)
	a, err := f.h.StartDelete("grafana-b", "grafana-b", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	rec, err := f.h.StopOp("grafana-b", directory.Human("bob"))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "past the point of no return — finishing") || rec == nil || !rec.PointOfNoReturn {
		t.Fatalf("stop: %+v %v", rec, err)
	}
	close(release)
	r := waitOp(t, f.h, "grafana-b", a.OpID)
	if !r.OK || r.StoppedAt != nil {
		t.Fatalf("record %+v", r)
	}
	if f.h.Template("grafana-b") != nil {
		t.Error("not deleted")
	}
	if e := auditEntry(audit, "delete.stop"); e.Result != "refused" {
		t.Errorf("audit %+v", e)
	}
}

// TestStopInterruptedDeleteBeforeNoReturn: a delete the Hub stopped
// before its point of no return is stoppable and undone from its record.
func TestStopInterruptedDeleteBeforeNoReturn(t *testing.T) {
	f, _, _ := grafanaB(t)
	f.h.mu.Lock()
	e := f.h.st.Instances["grafana-b"]
	e.State, e.Backup = state.InstanceDeleting, "grafana-b/20261107T100000Z.tar"
	f.h.st.Instances["grafana-b"] = e
	f.h.st.SetEnabled("grafana-b", false)
	f.h.rebuildLocked()
	f.h.saveLocked()
	f.h.mu.Unlock()
	f.runner.onDown(projectName("grafana-b"))
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	f.h.recordOp("grafana-b", OpRecord{Op: OpDelete, OpID: "crashed3", At: t0, Running: true, Actor: "alice", Stoppable: true,
		Before: map[string]string{"running": "true", "enabled": "true", "state": "", "had_entry": "true"},
		Steps: []Step{{Key: StepBackup, Label: "b", State: StepDone}, {Key: StepStop, Label: "s", State: StepRunning},
			{Key: StepVolumes, Label: "v", State: StepWaiting}},
		Created: &Created{}})
	f.h.loadOps()
	if r := f.h.LastOp("grafana-b"); !r.Stoppable {
		t.Fatalf("not stoppable %+v", r)
	}
	if _, err := f.h.StopOp("grafana-b", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "grafana-b", "crashed3")
	if !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	f.h.mu.RLock()
	e = f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.State == state.InstanceDeleting || !f.h.IsEnabled("grafana-b") || !grafanaRunning(f) {
		t.Errorf("entry %+v enabled %v", e, f.h.IsEnabled("grafana-b"))
	}
}

// TestInterruptedNotStoppable: the three cases recovered at start are
// stoppable false; a backup, a create and a delete before its point of
// no return are stoppable.
func TestInterruptedNotStoppable(t *testing.T) {
	steps := []Step{{Key: "x", State: StepRunning}}
	for _, c := range []struct {
		r    OpRecord
		want bool
	}{
		{OpRecord{Op: OpRestore, Steps: steps}, false},
		{OpRecord{Op: OpRestore, Steps: steps, Before: map[string]string{"new_id": "true"}}, false},
		{OpRecord{Op: OpDelete, Steps: steps, PointOfNoReturn: true}, false},
		{OpRecord{Op: OpDelete, Steps: steps}, true},
		{OpRecord{Op: OpBackup, Steps: steps}, true},
		{OpRecord{Op: OpCreate, Steps: steps}, true},
	} {
		r := c.r
		r.Running = true
		markInterrupted(&r)
		if r.Stoppable != c.want {
			t.Errorf("%s %v: stoppable %v", c.r.Op, c.r.Before, r.Stoppable)
		}
	}
}
