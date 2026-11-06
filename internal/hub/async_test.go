package hub

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// waitOp polls id's op record until operation opID finished.
func waitOp(t *testing.T, h *Hub, id, opID string) OpRecord {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if r := h.LastOp(id); r != nil && r.OpID == opID && !r.Running {
			return *r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("op %s on %s did not finish: %+v", opID, id, h.LastOp(id))
	return OpRecord{}
}

// TestAsyncInstanceOps: backup, restore, restore into a new id and delete
// are accepted once validated and locked, run in the background holding
// the instance's lock (a second request is 409 busy meanwhile), and end in
// the op record (also for a deleted instance). Refusals stay synchronous.
func TestAsyncInstanceOps(t *testing.T) {
	f, _, _ := grafanaB(t)
	h := f.h

	// A backup that blocks in its compose down (the instance is stopped).
	release := make(chan struct{})
	inDown := make(chan struct{}, 1)
	prev := f.runner.onDown
	f.runner.onDown = func(p string) {
		select {
		case inDown <- struct{}{}:
		default:
		}
		<-release
		if prev != nil {
			prev(p)
		}
	}
	op, err := h.StartBackup("grafana-b", directory.Human("root"))
	if err != nil || op.Op != OpBackup || op.Instance != "grafana-b" || len(op.OpID) != 16 {
		t.Fatalf("StartBackup = %+v %v", op, err)
	}
	select {
	case <-inDown:
	case <-time.After(10 * time.Second):
		t.Fatal("the backup never ran")
	}
	if r := h.LastOp("grafana-b"); r == nil || !r.Running || r.OpID != op.OpID || r.Op != OpBackup {
		t.Errorf("record while running = %+v", r)
	}
	// Concurrent requests on the same instance: busy, at once.
	if _, err := h.StartBackup("grafana-b", directory.Human("root")); err == nil || errStatus(err) != 409 {
		t.Errorf("second backup = %v, want 409 busy", err)
	}
	if _, err := h.StartDelete("grafana-b", "grafana-b", directory.Human("root")); err == nil || errStatus(err) != 409 {
		t.Errorf("delete while backing up = %v, want 409 busy", err)
	}
	close(release)
	f.runner.onDown = prev
	r := waitOp(t, h, "grafana-b", op.OpID)
	if !r.OK || !strings.HasPrefix(r.Result["archive"], "grafana-b/") || r.Status != 0 {
		t.Fatalf("backup record = %+v", r)
	}
	archive := r.Result["archive"]
	if _, err := os.Stat(archivePath(f, archive)); err != nil {
		t.Fatal(err)
	}

	// Synchronous refusals: nothing is started, no record replaced.
	for name, start := range map[string]func() (*AsyncOp, error){
		"unknown backup": func() (*AsyncOp, error) { return h.StartBackup("nope", directory.Human("root")) },
		"untyped delete": func() (*AsyncOp, error) { return h.StartDelete("grafana-b", "grafana", directory.Human("root")) },
		"bad archive":    func() (*AsyncOp, error) { return h.StartRestore("grafana-b", "../x.tar", directory.Human("root")) },
		"missing archive": func() (*AsyncOp, error) {
			return h.StartRestore("grafana-b", "grafana-b/20201102T153000Z.tar", directory.Human("root"))
		},
		"restore onto exists": func() (*AsyncOp, error) { return h.StartRestoreAs(archive, "grafana-b", directory.Human("root"), nil) },
		"bad new id":          func() (*AsyncOp, error) { return h.StartRestoreAs(archive, "Bad", directory.Human("root"), nil) },
	} {
		if op, err := start(); err == nil || op != nil || statusOf(err) < 400 || statusOf(err) >= 500 {
			t.Errorf("%s = %+v %v, want a synchronous 4xx", name, op, err)
		}
	}
	if r := h.LastOp("grafana-b"); r.OpID != op.OpID {
		t.Errorf("a refusal replaced the op record: %+v", r)
	}

	// A refusal found in the background (the archive doesn't verify) is
	// the operation's failure, with its status; nothing changed.
	time.Sleep(1100 * time.Millisecond)
	bad := "grafana-b/20261102T000000Z.tar"
	if err := os.WriteFile(archivePath(f, bad), []byte("not a tar"), 0600); err != nil {
		t.Fatal(err)
	}
	op2, err := h.StartRestore("grafana-b", bad, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if r := waitOp(t, h, "grafana-b", op2.OpID); r.OK || r.Status != 409 || r.Error == "" || r.Op != OpRestore {
		t.Errorf("bad archive restore record = %+v", r)
	}

	// Restore into a new id: the new id's record.
	op3, err := h.StartRestoreAs(archive, "grafana-c", directory.Human("root"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := waitOp(t, h, "grafana-c", op3.OpID); !r.OK || r.Result["instance"] != "grafana-c" || r.Result["archive"] != archive {
		t.Errorf("restore-as record = %+v", r)
	}

	// Delete: the record outlives the instance.
	op4, err := h.StartDelete("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	r = waitOp(t, h, "grafana-b", op4.OpID)
	if !r.OK || r.Op != OpDelete || !strings.HasPrefix(r.Result["backup"], "grafana-b/") {
		t.Errorf("delete record = %+v", r)
	}
	if _, ok := h.InstanceView("grafana-b"); ok {
		t.Error("instance still there")
	}
	if _, err := os.Stat(h.opPath("grafana-b")); err != nil {
		t.Errorf("the delete's op record is not on disk: %v", err)
	}
}
