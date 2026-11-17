package hub

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
)

// TestLiftQuarantineWithoutBundle (R3-M2): the lift, then the validated
// push; the instance starts again. A refused push fails the lift.
func TestLiftQuarantineWithoutBundle(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.w.quarantine("plainapp", "a container of an instance the agent holds no valid bundle for")
	p.h.refreshServerFacts(context.Background(), "nas")
	bundles := len(p.w.bundles)
	if err := p.h.LiftQuarantine(context.Background(), admin, "plainapp"); err != nil {
		t.Fatal(err)
	}
	if len(p.w.bundles) != bundles+1 {
		t.Error("no bundle pushed after the lift")
	}
	if err := p.h.RestartApp("plainapp"); err != nil {
		t.Errorf("restart after the lift: %v", err)
	}
	p.w.quarantine("plainapp", "x")
	p.w.mu.Lock()
	p.w.pushErr = errors.New("bundle refused")
	p.w.mu.Unlock()
	p.h.refreshServerFacts(context.Background(), "nas")
	if err := p.h.LiftQuarantine(context.Background(), admin, "plainapp"); err == nil || !strings.Contains(err.Error(), "bundle push failed") {
		t.Errorf("refused push: %v", err)
	}
}

// TestQuarantineAllAndDeliverFile (R3-L2 at the Hub, R3-L12): the agent's
// "*" quarantines every instance there; data files aren't delivered to a
// quarantined instance.
func TestQuarantineAllAndDeliverFile(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.w.quarantineAll("the agent's quarantine.json is unreadable")
	p.h.refreshServerFacts(context.Background(), "nas")
	if err := p.h.RestartApp("plainapp"); errStatus(err) != 409 || !strings.Contains(err.Error(), "quarantined") {
		t.Errorf("restart: %v", err)
	}
	rt, err := p.h.rtFor("plainapp")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.(fileDeliverer).DeliverFile(context.Background(), "plainapp", runtime.FileDelivery{Name: "x", Data: []byte("{}")}); errStatus(err) != 409 {
		t.Errorf("deliver: %v", err)
	}
	if in := p.h.serversDoctorIn(); in == nil || in.Quarantined["plainapp"] == "" {
		t.Errorf("doctor %+v", in)
	}
}

// TestPlacementInvalidWithoutStart (R3-L7): the doctor sees a placed
// instance whose template turned primary-only, with no start attempt.
func TestPlacementInvalidWithoutStart(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	chat := readFixture(t, filepath.Join("testdata", "ai", "chatapp"))
	writeFile(t, filepath.Join(p.src, "plainapp", "manifest.yaml"), chat[0])
	writeFile(t, filepath.Join(p.src, "plainapp", "compose.yml"), chat[1])
	p.h.Discover()
	if in := p.h.serversDoctorIn(); in == nil || !strings.Contains(in.PlacementInvalid["plainapp"], "AI page") {
		t.Errorf("doctor %+v", in)
	}
}

// TestOwedBundleRetried (R3-L10): a failed bundle removal at a move's keep
// is owed, persisted, and retried each tick until it succeeds.
func TestOwedBundleRetried(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.w.mu.Lock()
	p.w.removeErrs = 1
	p.w.mu.Unlock()
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	p.h.mu.RLock()
	owed := len(p.h.st.OwedBundles)
	p.h.mu.RUnlock()
	if owed != 1 || workerHas(p.w, "signal remove-project plainapp") {
		t.Fatalf("owed %d calls %v", owed, p.w.Calls())
	}
	p.h.serversTick(context.Background())
	p.h.mu.RLock()
	owed = len(p.h.st.OwedBundles)
	p.h.mu.RUnlock()
	if owed != 0 || !workerHas(p.w, "signal remove-project plainapp") {
		t.Errorf("after the tick: owed %d calls %v", owed, p.w.Calls())
	}
}

// TestUndoDoesntPersistTheSource (R3-L8): while an undo starts the copy on
// its worker source, the stored server stays the current one.
func TestUndoDoesntPersistTheSource(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	var during string
	p.w.mu.Lock()
	p.w.pushHook = func() { during = p.instance("plainapp").Server }
	p.w.mu.Unlock()
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	if during != "" {
		t.Errorf("the stored server was %q during the undo's start (want the primary)", during)
	}
	if in := p.instance("plainapp"); in.Server != "nas" {
		t.Errorf("after the undo %+v", in)
	}
}

// TestUndoToPrimaryStuck (R3-L9): a failed start on the primary whose
// copy can't be taken down routes to neither (stuck), never both.
func TestUndoToPrimaryStuck(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	// On nas, moved there from the primary (the undo goes back there).
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.MovedFrom = &state.MovedFrom{Server: "", At: time.Now()}
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
	p.runner.mu.Lock()
	p.runner.upErr = errors.New("up failed")
	p.runner.downErr = errors.New("down failed")
	p.runner.mu.Unlock()
	err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin)
	if err == nil {
		t.Fatal("undone")
	}
	got := p.instance("plainapp")
	if got.State != state.InstanceMoving || got.Move == nil || got.Move.Phase != MoveStuck {
		t.Errorf("state %+v (%v)", got, err)
	}
}

// TestPrepareUpRefusesMoving (R3-L11): every start path through prepareUp
// refuses a moving instance.
func TestPrepareUpRefusesMoving(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.State = state.InstanceMoving
	in.Move = &state.Move{Phase: MoveRestore}
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
	if _, err := p.h.prepareUp(p.h.Template("plainapp")); errStatus(err) != 409 {
		t.Errorf("%v", err)
	}
}

// TestExpandRefForms (R3-L6): the tricky forms are refused.
func TestExpandRefForms(t *testing.T) {
	env := map[string]string{"PORTCULLIS_DOMAIN": "example.org", "SECRET": "s3cr3t"}
	for _, ref := range []string{"x/${VAR:-${SECRET}}/a", "x/${X:-$SECRET}/a", "x/$$/a", "x/${VAR:+alt}/a", "x/${VAR:?e}/a", "x/a$", "x/${SECRET}/a", "x/$SECRET/a"} {
		if got, ok := expandRef(ref, env); ok || strings.Contains(got, "s3cr3t") {
			t.Errorf("%s: %q %v", ref, got, ok)
		}
	}
}

// TestOwedBundleVsUndo (round 4 review, revised): an owed removal of
// (S, X) and an undo back to S: settled only once the undo committed on
// S with its bundle pushed; the bundle survives and the instance runs; a
// drain during a move/undo leaves it alone; an undo that fails at its
// placement check leaves it owed, and it drains after.
func TestOwedBundleVsUndo(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.w.mu.Lock()
	p.w.removeErrs = 1 // the keep's removal fails: owed
	p.w.mu.Unlock()
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	p.h.mu.RLock()
	owed := len(p.h.st.OwedBundles)
	p.h.mu.RUnlock()
	if owed != 0 {
		t.Errorf("owed %d", owed)
	}
	p.h.serversTick(context.Background())
	if workerHas(p.w, "signal remove-project plainapp") {
		t.Errorf("the bundle the undo pushed back was removed: %v", p.w.Calls())
	}
	if in := p.instance("plainapp"); in.Server != "nas" {
		t.Errorf("state %+v", in)
	}
	// A drain while a move/undo owns the instance leaves it alone.
	p.h.oweBundle("nas", "plainapp")
	release := p.h.ownMove("plainapp")
	p.h.drainOwedBundle(context.Background(), state.OwedBundle{Server: "nas", Instance: "plainapp"})
	release()
	if workerHas(p.w, "signal remove-project plainapp") {
		t.Error("drained during an owned move")
	}
}

func TestOwedBundleUndoFails(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.w.mu.Lock()
	p.w.removeErrs = 1
	p.w.mu.Unlock()
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	p.w.mu.Lock()
	p.w.pullErr = errors.New("no matching manifest for linux/arm64")
	p.w.mu.Unlock()
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err == nil {
		t.Fatal("undone")
	}
	p.h.mu.RLock()
	owed := len(p.h.st.OwedBundles)
	p.h.mu.RUnlock()
	if owed != 1 {
		t.Fatalf("owed %d after the failed undo", owed)
	}
	p.h.serversTick(context.Background())
	if !workerHas(p.w, "signal remove-project plainapp") {
		t.Errorf("not drained after: %v", p.w.Calls())
	}
}
