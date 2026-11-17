package hub

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/state"
)

// Final re-review (rereview-hub.md N1–N3, H2/M1 remainders): faults the
// real agent answers with — 5xx, a dropped transport, a Stop mid-push, a
// crash after the write-ahead save — never leave a move stuck, and a
// copy that may have landed is downed and recorded, never silently kept.

// notStuck: id runs on the primary again, no move record, no leftover
// recorded on nas (the agent held nothing).
func notStuck(t *testing.T, p *placedFixture, id string) {
	t.Helper()
	in := p.instance(id)
	if in.Move != nil || in.State == state.InstanceMoving || in.Server != "" {
		t.Fatalf("stuck or moved: %+v", in)
	}
	if d := p.h.serversDoctorIn(); d != nil && d.Stuck[id] != "" {
		t.Errorf("doctor: stuck")
	}
	if p.w.holds(id) {
		t.Error("the worker still holds a bundle")
	}
}

// TestMoveFirstPushFaultsNotStuck (H2/N1): the move's first bundle push
// fails without a clean refusal — an agent 500, a dropped connection, a
// Stop while it is sent: the rollback's down meets the agent's never-held
// 404 = nothing there; the move ends back on the primary.
func TestMoveFirstPushFaultsNotStuck(t *testing.T) {
	for name, arm := range map[string]func(p *placedFixture, cancel context.CancelFunc){
		"500": func(p *placedFixture, _ context.CancelFunc) {
			p.w.wt.Fail(`^PUT /v1/projects/plainapp/bundle$`, 1, http.StatusInternalServerError, "disk full")
		},
		"transport drop": func(p *placedFixture, _ context.CancelFunc) {
			p.w.wt.Drop(`^PUT /v1/projects/plainapp/bundle$`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPlacedFixture(t)
			enabledOnPrimary(t, p)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			arm(p, cancel)
			err := p.h.moveInstance(withProgress(ctx, p.h.newProgress("plainapp", OpMove, movePlan())), "plainapp", "nas", admin, func() {})
			if err == nil {
				t.Fatal("the move succeeded")
			}
			if strings.Contains(err.Error(), "runs nowhere") {
				t.Fatalf("stuck: %v", err)
			}
			notStuck(t, p, "plainapp")
			if !p.w.wt.Got(`^POST /v1/projects/plainapp/down$`) {
				t.Error("the rollback never asked the worker (the push may have landed)")
			}
			if l := p.instance("plainapp").MoveTargetLeftover; l != nil {
				t.Errorf("a leftover recorded for nothing: %+v", l)
			}
		})
	}
}

// TestMoveStopMidPushNotStuck (H2/N1/N2): a Stop while a bundle push to
// the target is on the wire. plainapp's push (at the switch) lands: the
// rollback downs it and its bundle is owed and removed. filesapp's (the
// restore's, under the op's context) is cut: the down meets the 404.
// Neither is stuck; nothing stays on the worker.
func TestMoveStopMidPushNotStuck(t *testing.T) {
	for _, id := range []string{"plainapp", "filesapp"} {
		t.Run(id, func(t *testing.T) {
			p := newPlacedFixture(t)
			if err := p.create(t, id, ""); err != nil {
				t.Fatal(err)
			}
			if err := p.h.Enable(id); err != nil {
				t.Fatal(err)
			}
			if id == "filesapp" {
				// Data on the primary: the restore pushes first, under the
				// op's context (the Stop cuts it).
				vol := p.h.volumeNamesFor(p.h.Template(id), id)["data"]
				p.engine.addVolume(vol, "portcullis-filesapp", "data", 0, fakeFile{Name: "marker", Mode: 0o644, Body: "hi"})
			}
			p.w.wt.Hook(`^PUT /v1/projects/`+id+`/bundle$`, 1, func(r *http.Request) {
				go p.h.StopOp(id, admin)
				select {
				case <-r.Context().Done():
				case <-time.After(300 * time.Millisecond):
				}
			})
			op, err := p.h.StartMove(id, "nas", admin)
			if err != nil {
				t.Fatal(err)
			}
			rec := waitOp(t, p.h, id, op.OpID)
			if rec.OK || rec.StoppedBy == "" {
				t.Fatalf("the move wasn't stopped: %+v", rec)
			}
			p.h.drainOwedBundles(context.Background())
			notStuck(t, p, id)
			if n := owedCount(p); n != 0 {
				t.Errorf("%d removals still owed", n)
			}
		})
	}
}

// TestMoveCrashAfterWriteAheadRecovers (N1): a crash after the push's
// write-ahead save (Pushed, nothing sent): the recovery's down gets the
// agent's 404 and the move ends, never stuck.
func TestMoveCrashAfterWriteAheadRecovers(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.State = state.InstanceMoving
	in.Move = &state.Move{From: "", To: "nas", Phase: MoveSwitch, StartedAt: time.Now(), Pushed: true}
	p.h.st.Instances["plainapp"] = in
	p.h.noteServersLocked()
	p.h.saveLocked()
	p.h.mu.Unlock()
	p.h.RecoverMoves()
	notStuck(t, p, "plainapp")
}

// TestMoveLaterRefusalKeepsLandedCopy (N2/M1): the restore's push landed
// and filled the data volume; the switch's push is refused (409). The
// target's copy is downed, its volumes recorded as the move's leftover
// and its bundle (env) owed and removed — and a later move there is
// refused while the copy is recorded.
func TestMoveLaterRefusalKeepsLandedCopy(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable("filesapp"); err != nil {
		t.Fatal(err)
	}
	vol := p.h.volumeNamesFor(p.h.Template("filesapp"), "filesapp")["data"]
	p.engine.addVolume(vol, "portcullis-filesapp", "data", 0, fakeFile{Name: "marker", Mode: 0o644, Body: "hi"})
	var n atomic.Int32
	p.w.mu.Lock()
	p.w.pushHook = func() {
		if n.Add(1) == 2 {
			p.w.wt.Fail(`^PUT /v1/projects/filesapp/bundle$`, 1, http.StatusConflict, "instance filesapp is quarantined")
		}
	}
	p.w.mu.Unlock()
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin); err == nil {
		t.Fatalf("the move succeeded: %d pushes, %v", n.Load(), p.w.wt.Requests())
	}
	if n.Load() < 2 {
		t.Fatalf("only %d pushes", n.Load())
	}
	in := p.instance("filesapp")
	if in.Move != nil || in.Server != "" {
		t.Fatalf("state %+v", in)
	}
	if in.MoveTargetLeftover == nil || in.MoveTargetLeftover.Server != "nas" || !slices.Contains(in.MoveTargetLeftover.Volumes, vol) {
		t.Fatalf("the landed copy isn't recorded: %+v", in.MoveTargetLeftover)
	}
	p.h.drainOwedBundles(context.Background())
	if p.w.holds("filesapp") {
		t.Error("the copy's bundle (its env) stayed on the worker")
	}
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin); errStatus(err) != 409 {
		t.Errorf("a move onto the recorded copy: %v", err)
	}
	// Removing the leftover goes through the real agent.
	if err := p.h.RemoveMoveLeftover(context.Background(), "filesapp", "filesapp", admin); err != nil {
		t.Fatal(err)
	}
}

// TestCreateRefusesUnrecordedWorkerBundle (N2/M1): a worker that holds a
// bundle of the id the Hub has no record of refuses a create there (409)
// — the earlier copy is never taken over; an unreadable answer refuses
// too.
func TestCreateRefusesUnrecordedWorkerBundle(t *testing.T) {
	p := newPlacedFixture(t)
	f, m := conformBundle("plainapp", "plainapp", true)
	if err := p.w.Backend.PushBundle(context.Background(), "plainapp", f, m); err != nil {
		t.Fatal(err)
	}
	if err := p.create(t, "plainapp", "nas"); errStatus(err) != 409 || !strings.Contains(err.Error(), "earlier copy") {
		t.Fatalf("create over a held bundle: %v", err)
	}
	if err := p.w.Backend.RemoveProject(context.Background(), "plainapp"); err != nil {
		t.Fatal(err)
	}
	p.w.wt.Fail(`^GET /v1/containers$`, 1, http.StatusInternalServerError, "engine down")
	if err := p.create(t, "plainapp", "nas"); err == nil {
		t.Fatal("create with an unreadable worker went through")
	}
	p.w.wt.ClearFaults()
	if err := p.create(t, "plainapp", "nas"); err != nil {
		t.Fatalf("a clean worker: %v", err)
	}
}

// TestDeleteDropsCopyOnRevokedServer (N3): a kept copy on a revoked
// server is recorded and dropped: the delete (and Remove the old copy)
// go through.
func TestDeleteDropsCopyOnRevokedServer(t *testing.T) {
	p, vol := movedToPrimary(t)
	p.h.mu.Lock()
	p.h.beginRevokeLocked("nas", false)
	p.h.mu.Unlock()
	logs := captureLog(t)
	if _, err := p.h.DeleteInstance("filesapp", "filesapp", admin); err != nil {
		t.Fatalf("delete with a copy on a revoked server: %v", err)
	}
	if !strings.Contains(logs.String(), vol) || !strings.Contains(logs.String(), "dropped") {
		t.Errorf("the dropped copy isn't recorded: %s", logs.String())
	}
	p.h.mu.RLock()
	_, still := p.h.st.Instances["filesapp"]
	p.h.mu.RUnlock()
	if still {
		t.Errorf("not deleted: %+v", p.instance("filesapp"))
	}

	p2, _ := movedToPrimary(t)
	p2.h.mu.Lock()
	p2.h.beginRevokeLocked("nas", false)
	p2.h.mu.Unlock()
	if err := p2.h.RemoveMoveLeftover(context.Background(), "filesapp", "filesapp", admin); err != nil {
		t.Fatalf("remove the old copy on a revoked server: %v", err)
	}
	if in := p2.instance("filesapp"); in.MovedFrom != nil {
		t.Errorf("still recorded: %+v", in.MovedFrom)
	}
}
