package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// TestDeleteNoBackup (user ruling 2026-11-26, contract §11.4): an admin
// may delete without a backup, explicitly. No archive is written, the
// backup step is recorded as skipped, the instance's data and state go
// as in any delete, the op record's result says no_backup and the audit
// records backup=none no_backup=true.
func TestDeleteNoBackup(t *testing.T) {
	f, audit, groups := grafanaB(t)
	n := len(f.runner.Calls())
	res, err := f.h.DeleteInstanceWith("grafana-b", "grafana-b", directory.Human("root"), DeleteOptions{NoBackup: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Backup != "" || !res.NoBackup {
		t.Errorf("result = %+v", res)
	}
	if l, _ := f.h.ListBackups(""); len(l) != 0 {
		t.Errorf("an archive was written: %+v", l)
	}
	// One down (the stop step), never the backup's down/up pair.
	if got := strings.Join(f.runner.Calls()[n:], " "); strings.Contains(got, "up:") || strings.Count(got, "down:portcullis-grafana-b") != 1 {
		t.Errorf("calls = %s", got)
	}
	if len(f.engine.volumeNames()) != 0 || f.h.Template("grafana-b") != nil || f.h.IsEnabled("grafana-b") {
		t.Errorf("not deleted: volumes %v", f.engine.volumeNames())
	}
	if got := strings.Join(groups.Calls(), ","); got != "-users_grafana-b:root,-admin_grafana-b:root" {
		t.Errorf("groups = %s", got)
	}
	r := f.h.LastOp("grafana-b")
	if r == nil || !r.OK || r.Result["no_backup"] != "true" || r.Result["backup"] != "" {
		t.Fatalf("op record = %+v", r)
	}
	if len(r.Steps) == 0 || r.Steps[0].Key != StepBackup || r.Steps[0].Detail != "skipped: no backup taken" {
		t.Errorf("steps = %+v", r.Steps)
	}
	if a := audit.lastOf("instance.delete"); a.Result != "ok" || a.Detail != "backup=none no_backup=true" || a.Actor != "root" {
		t.Errorf("audit = %+v", a)
	}
}

// TestDeleteDefaultStillBacksUp: without options (the MCP's path,
// StartDelete / DeleteInstance) a delete always backs up first.
func TestDeleteDefaultStillBacksUp(t *testing.T) {
	f, audit, _ := grafanaB(t)
	a, err := f.h.StartDelete("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "grafana-b", a.OpID)
	if !r.OK || r.Result["backup"] == "" || r.Result["no_backup"] != "" {
		t.Fatalf("record = %+v", r)
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 1 || l[0].Reason != BackupDelete {
		t.Errorf("backups = %+v", l)
	}
	if e := audit.lastOf("instance.delete"); e.Detail != "backup="+r.Result["backup"] {
		t.Errorf("audit = %+v", e)
	}
}

// TestDeleteNoBackupRetry (review I1): a no-backup delete that fails
// part-way stays "deleting" with no archive and DeleteNoBackup set. A
// plain retry (the MCP's delete_instance, the browser's retry without the
// choice) is refused 409 before anything changes; only a retry that says
// "no backup" again finishes it, still without an archive.
func TestDeleteNoBackupRetry(t *testing.T) {
	f, audit, groups := grafanaB(t)
	groups.delErr = errors.New("lldap down")
	_, err := f.h.DeleteInstanceWith("grafana-b", "grafana-b", directory.Human("root"), DeleteOptions{NoBackup: true})
	var oe *OpError
	if !errors.As(err, &oe) || !strings.Contains(err.Error(), "no backup was taken") {
		t.Fatalf("delete = %v", err)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.State != state.InstanceDeleting || e.Backup != "" || !e.DeleteNoBackup {
		t.Fatalf("entry = %+v", e)
	}
	if st, _ := state.Load(f.h.statePath()); !st.Instances["grafana-b"].DeleteNoBackup {
		t.Error("delete_no_backup not persisted")
	}
	if lines, _ := f.h.DeletePlan("grafana-b"); len(lines) == 0 || !strings.Contains(lines[0], "without a backup") {
		t.Errorf("plan = %v", lines)
	}
	groups.delErr = nil
	n := len(groups.Calls())
	_, err = f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root"))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "only an administrator can finish it") {
		t.Fatalf("plain retry = %v, want 409", err)
	}
	f.h.mu.RLock()
	e2 := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e2.State != state.InstanceDeleting || len(groups.Calls()) != n {
		t.Errorf("a refused retry changed something: %+v %v", e2, groups.Calls()[n:])
	}
	if a := audit.lastOf("instance.delete"); a.Result != "refused" {
		t.Errorf("audit of the refused retry = %+v", a)
	}
	res, err := f.h.DeleteInstanceWith("grafana-b", "grafana-b", directory.Human("root"), DeleteOptions{NoBackup: true})
	if err != nil || res.Backup != "" || !res.NoBackup {
		t.Fatalf("retry = %+v %v", res, err)
	}
	if l, _ := f.h.ListBackups(""); len(l) != 0 {
		t.Errorf("archives = %+v", l)
	}
	if a := audit.lastOf("instance.delete"); a.Result != "ok" || a.Detail != "backup=none no_backup=true" {
		t.Errorf("audit = %+v", a)
	}
}

// TestDeleteRetryOfBackedUpDeleteUnchanged: a retry of a delete that took
// a backup needs no option (and the no-backup option changes nothing).
func TestDeleteRetryOfBackedUpDeleteUnchanged(t *testing.T) {
	f, _, groups := grafanaB(t)
	groups.delErr = errors.New("lldap down")
	if _, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root")); err == nil {
		t.Fatal("delete did not fail")
	}
	groups.delErr = nil
	res, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil || res.Backup == "" || res.NoBackup {
		t.Fatalf("retry = %+v %v", res, err)
	}
}

// TestRefusedNoBackupDeleteAudited (review M2): a no-backup delete refused
// early still records the choice in its audit detail.
func TestRefusedNoBackupDeleteAudited(t *testing.T) {
	f, audit, _ := grafanaB(t)
	if _, err := f.h.DeleteInstanceWith("grafana-b", "wrong", directory.Human("root"), DeleteOptions{NoBackup: true}); statusOf(err) != 400 {
		t.Fatalf("delete = %v", err)
	}
	if a := audit.lastOf("instance.delete"); a.Result != "refused" || a.Detail != "backup=none no_backup=true" {
		t.Errorf("audit = %+v", a)
	}
}

// TestStopNoBackupDeleteBeforeNoReturn: a Stop before the volumes step
// puts the instance back as before (enabled and running, no deleting
// record) and nothing was archived.
func TestStopNoBackupDeleteBeforeNoReturn(t *testing.T) {
	f, _, groups := grafanaB(t)
	reached, release := blockStep(t, f.h, StepStop)
	a, err := f.h.StartDeleteWith("grafana-b", "grafana-b", directory.Human("alice"), DeleteOptions{NoBackup: true})
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
	if e.State == state.InstanceDeleting || !f.h.IsEnabled("grafana-b") || !grafanaRunning(f) {
		t.Errorf("entry %+v enabled %v running %v", e, f.h.IsEnabled("grafana-b"), grafanaRunning(f))
	}
	if l, _ := f.h.ListBackups(""); len(l) != 0 {
		t.Errorf("backups %+v", l)
	}
	if f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"].Body != "v1" || len(groups.Calls()) != 0 {
		t.Error("data or groups touched")
	}
}

// TestForgetRefusesNoBackupOption: a forget never backs up; asking for
// "no backup" with it is a 400 (the route refuses the combination too).
func TestForgetRefusesNoBackupOption(t *testing.T) {
	f, _, _ := grafanaB(t)
	f.h.mu.Lock()
	e := f.h.st.Instances["grafana-b"]
	e.State = state.InstanceOrphaned
	f.h.st.Instances["grafana-b"] = e
	f.h.mu.Unlock()
	_, _, err := f.h.runOpSync("grafana-b", OpDelete, directory.Human("root"), []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return deleteResult(f.h.deleteInstance(context.WithValue(deleteCtx(ctx, DeleteOptions{NoBackup: true}), forgetKey{}, true), "grafana-b", "grafana-b", directory.Human("root"), ready))
	})
	if statusOf(err) != 400 {
		t.Errorf("forget with no_backup = %v", err)
	}
}
