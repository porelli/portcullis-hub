package hub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
)

// TestOpHistoryQueuedRestart (contract §11.7 "Op history"): a restart
// queued while an enable runs takes the instance's record right after
// the enable ends ok; the enable's own record stays readable by its op id
// (OpByID), running or ended, and the restart's by its own.
func TestOpHistoryQueuedRestart(t *testing.T) {
	f := stopFixture(t)
	reached, release := f.blockAt(StepSettings)
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if r := f.h.OpByID("other", a.OpID); r == nil || !r.Running || r.Op != OpEnable {
		t.Fatalf("running enable by id: %+v", r)
	}
	// The Hub's own queued restart waits for the enable's lock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.h.Restart(*f.h.Template("other"))
	}()
	close(release)
	<-done
	cur := f.h.LastOp("other")
	if cur == nil || cur.Op != OpRestart || cur.OpID == "" || cur.OpID == a.OpID || cur.Running {
		t.Fatalf("current record: %+v", cur)
	}
	r := f.h.OpByID("other", a.OpID)
	if r == nil || r.Op != OpEnable || !r.OK || r.Running || r.OpID != a.OpID || r.Actor != "alice" || len(r.Steps) == 0 {
		t.Fatalf("the enable's record by id: %+v", r)
	}
	if r := f.h.OpByID("other", cur.OpID); r == nil || r.Op != OpRestart {
		t.Fatalf("the restart's record by id: %+v", r)
	}
	if r := f.h.OpByID("other", "0123456789abcdef"); r != nil {
		t.Fatalf("unknown op id: %+v", r)
	}
	if r := f.h.OpByID("other", "NOT-HEX"); r != nil {
		t.Fatalf("malformed op id: %+v", r)
	}
}

// TestOpHistoryPrunedAt21: the history keeps the newest 20 ended records
// per instance; the 21st prunes the oldest. Running records and records
// without an op id (finishOp's) are never kept.
func TestOpHistoryPrunedAt21(t *testing.T) {
	f := newFixture(t)
	base := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	ids := make([]string, 21)
	for i := range ids {
		ids[i] = fmt.Sprintf("%016x", 0xa000+i)
		f.h.recordOp("grafana", OpRecord{Op: OpBackup, OpID: ids[i], At: base.Add(time.Duration(i) * time.Minute), OK: true})
		if i == 19 {
			if n := historyFiles(t, f.h, "grafana"); n != 20 {
				t.Fatalf("20 written, %d kept", n)
			}
			if f.h.OpByID("grafana", ids[0]) == nil {
				t.Fatal("the oldest was pruned at 20")
			}
		}
	}
	if n := historyFiles(t, f.h, "grafana"); n != 20 {
		t.Fatalf("21 written, %d kept", n)
	}
	if r := f.h.OpByID("grafana", ids[0]); r != nil {
		t.Fatalf("the oldest is still there: %+v", r)
	}
	for _, id := range ids[1:] {
		if r := f.h.OpByID("grafana", id); r == nil || r.OpID != id {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	// Not kept: a running record, a record without an op id, a folder's.
	f.h.recordOp("grafana", OpRecord{Op: OpBackup, OpID: "00000000000000ff", At: base.Add(time.Hour), Running: true})
	f.h.recordOp("grafana", OpRecord{Op: OpHook, At: base.Add(2 * time.Hour)})
	f.h.recordOp(opKeyFolder("media"), OpRecord{Op: OpFolderAssign, OpID: "00000000000000fe", At: base})
	if n := historyFiles(t, f.h, "grafana"); n != 20 || f.h.OpByID("grafana", ids[1]) == nil {
		t.Fatalf("a running or op-id-less record was kept (%d files)", n)
	}
	if _, err := os.Stat(f.h.opHistoryDir(opKeyFolder("media"))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a folder record has a history: %v", err)
	}
}

func historyFiles(t *testing.T, h *Hub, id string) int {
	t.Helper()
	es, err := os.ReadDir(h.opHistoryDir(id))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".") {
			n++
		}
	}
	return n
}

// TestOpHistoryOutlivesReplacedRecord: an operation whose final record
// couldn't become the instance's (another operation's running record
// took it first) still ends in the history; a reload marks a running
// record interrupted there too.
func TestOpHistoryOutlivesReplacedRecord(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	f.h.recordOp("grafana", OpRecord{Op: OpRestart, OpID: "1111111111111111", At: now, Running: true})
	if f.h.recordOpUnlessOther("grafana", OpRecord{Op: OpEnable, OpID: "2222222222222222", At: now, OK: true}) {
		t.Fatal("written over another operation's running record")
	}
	if r := f.h.OpByID("grafana", "2222222222222222"); r == nil || !r.OK || r.Op != OpEnable {
		t.Fatalf("the replaced enable: %+v", r)
	}
	f.h.loadOps()
	if r := f.h.OpByID("grafana", "1111111111111111"); r == nil || !r.Interrupted || r.Running {
		t.Fatalf("the interrupted restart: %+v", r)
	}
	f.h.recordOp("grafana", OpRecord{Op: OpBackup, OpID: "3333333333333333", At: now, OK: true})
	if r := f.h.OpByID("grafana", "1111111111111111"); r == nil || !r.Interrupted {
		t.Fatalf("the interrupted restart after a newer record: %+v", r)
	}
}

// TestOpHistoryDelete: a delete removes the instance's earlier kept
// records with its files and keeps its own final record (readable by op
// id after the instance is gone).
func TestOpHistoryDelete(t *testing.T) {
	f, _, _ := grafanaB(t)
	b, err := f.h.StartBackup("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	waitOp(t, f.h, "grafana-b", b.OpID)
	if f.h.OpByID("grafana-b", b.OpID) == nil {
		t.Fatal("the backup isn't kept")
	}
	d, err := f.h.StartDelete("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if r := waitOp(t, f.h, "grafana-b", d.OpID); !r.OK {
		t.Fatalf("delete: %+v", r)
	}
	if r := f.h.OpByID("grafana-b", b.OpID); r != nil {
		t.Errorf("the deleted instance's backup is still kept: %+v", r)
	}
	if r := f.h.OpByID("grafana-b", d.OpID); r == nil || r.Op != OpDelete || !r.OK {
		t.Errorf("the delete's own record: %+v", r)
	}
}

// TestPreBackupRestartFailureKeepsPrefix: a delete's or restore's backup
// whose start-again fails ends as the delete's / restore's own record —
// op, prefix ("nothing was deleted" / "nothing was restored") and status —
// with the backup's failure after the prefix, never the backup's record.
func TestPreBackupRestartFailureKeepsPrefix(t *testing.T) {
	f, _, _ := grafanaB(t)
	b, err := f.h.StartBackup("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	archive := waitOp(t, f.h, "grafana-b", b.OpID).Result["archive"]
	if archive == "" {
		t.Fatal("no archive")
	}
	ve := f.engine.vol()
	ve.copyFromErr = func(string) error { return errors.New("disk full") }
	f.runner.mu.Lock()
	f.runner.upErr = errors.New("up failed")
	f.runner.mu.Unlock()

	d, err := f.h.StartDelete("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "grafana-b", d.OpID)
	const delPrefix = "the backup before the delete failed — nothing was deleted: "
	if r.Op != OpDelete || r.OK || !strings.HasPrefix(r.Error, delPrefix) || !strings.Contains(r.Error, "disk full") ||
		!strings.Contains(r.Error, "starting grafana-b again failed") || r.Status != 500 {
		t.Fatalf("delete record: %+v", r)
	}

	// Running again (the failed delete's start-again left it down), then
	// the restore's pre-backup fails the same way.
	f.runner.mu.Lock()
	f.runner.upErr = nil
	f.runner.mu.Unlock()
	if err := f.h.RestartApp("grafana-b"); err != nil {
		t.Fatal(err)
	}
	f.runner.mu.Lock()
	f.runner.upErr = errors.New("up failed")
	f.runner.mu.Unlock()
	s, err := f.h.StartRestore("grafana-b", archive, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	r = waitOp(t, f.h, "grafana-b", s.OpID)
	const resPrefix = "the backup before the restore failed — nothing was restored: "
	if r.Op != OpRestore || r.OK || !strings.HasPrefix(r.Error, resPrefix) || !strings.Contains(r.Error, "starting grafana-b again failed") || r.Status != 500 {
		t.Fatalf("restore record: %+v", r)
	}
	// The synchronous form says the same.
	var oe *OpError
	if err := prefixOpError(OpDelete, "p: ", &OpError{Record: OpRecord{Op: OpBackup, Error: "x", Hint: "h"}, Err: statusErr(409, "x")}); !errors.As(err, &oe) ||
		oe.Record.Op != OpDelete || oe.Record.Error != "p: x" || oe.Record.Hint != "h" || errStatus(err) != 409 || time.Since(oe.Record.At) > time.Minute {
		t.Fatalf("prefixOpError = %#v", err)
	}
	if err := prefixOpError(OpDelete, "p: ", statusErr(409, "x")); errors.As(err, &oe) && oe.Record.Op == OpDelete || err.Error() != "p: x" || errStatus(err) != 409 {
		t.Fatalf("prefixOpError of a plain error = %v", err)
	}
}

// TestHealthyCountsOnlyRenderedServices: the healthy / start counts are
// over the containers whose service is in the rendered project; an
// orphan of a service the project no longer has is never counted.
func TestHealthyCountsOnlyRenderedServices(t *testing.T) {
	f := progressFixture(t)
	proj := projectName("grafana")
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{
		container("w1", proj, "web", "running"), container("d1", proj, "db", "running"), container("o1", proj, "old", "exited"),
	}
	f.engine.mu.Unlock()
	tm := f.h.Template("grafana")
	services := f.h.renderedServices(context.Background(), tm)
	if !services["web"] || !services["db"] || !services["init"] || services["old"] {
		t.Fatalf("rendered services %v", services)
	}
	n, m, others, err := f.h.countStarted(context.Background(), tm, services)
	if err != nil || n != 2 || m != 2 || len(others) != 0 {
		t.Fatalf("counted %d of %d (%v) %v", n, m, others, err)
	}
	// A service set without db: its container isn't counted either.
	n, m, _, err = f.h.countStarted(context.Background(), tm, map[string]bool{"web": true})
	if err != nil || n != 1 || m != 1 {
		t.Fatalf("counted %d of %d %v", n, m, err)
	}
}
