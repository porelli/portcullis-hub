package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/state"
)

// movedHereFromPrimary: plainapp enabled on nas, recorded as moved
// there from the primary (an undo goes back to the primary).
func movedHereFromPrimary(t *testing.T, p *placedFixture) {
	t.Helper()
	placedEnabled(t, p, "plainapp")
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.MovedFrom = &state.MovedFrom{Server: "", At: time.Now()}
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
}

func owedCount(p *placedFixture) int {
	p.h.mu.RLock()
	defer p.h.mu.RUnlock()
	return len(p.h.st.OwedBundles)
}

// TestUndoStopDownFailsOwed (R4-L3): the undo's down of the old worker
// copy fails → owed (persisted) with a doctor problem, never routed; the
// next tick downs the copy, then removes its bundle.
func TestUndoStopDownFailsOwed(t *testing.T) {
	p := newPlacedFixture(t)
	movedHereFromPrimary(t, p)
	p.w.mu.Lock()
	p.w.downErrs = 1
	p.w.mu.Unlock()
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	if owedCount(p) != 1 || workerHas(p.w, "signal remove-project plainapp") {
		t.Fatalf("owed %d calls %v", owedCount(p), p.w.Calls())
	}
	if p.h.serverOf("plainapp") != "" {
		t.Errorf("routed to %q", p.h.serverOf("plainapp"))
	}
	if in := p.h.serversDoctorIn(); in == nil || in.OwedCopies["plainapp"] == "" {
		t.Errorf("no doctor problem: %+v", in)
	}
	downs := len(slices.DeleteFunc(p.w.Calls(), func(c string) bool { return c != "down portcullis-plainapp" }))
	p.h.serversTick(context.Background())
	calls := p.w.Calls()
	after := len(slices.DeleteFunc(slices.Clone(calls), func(c string) bool { return c != "down portcullis-plainapp" }))
	di, ri := slices.Index(calls, "down portcullis-plainapp"), slices.Index(calls, "signal remove-project plainapp")
	if after <= downs || ri < 0 || di > ri {
		t.Errorf("not downed then removed: %v", calls)
	}
	if owedCount(p) != 0 {
		t.Errorf("still owed")
	}
	if in := p.h.serversDoctorIn(); in != nil && in.OwedCopies["plainapp"] != "" {
		t.Errorf("doctor problem stays")
	}
}

// TestOwedBundleKeptForStuckMove (R4-L4): an owed (nas, X) and a stuck
// move of X to nas: the drain leaves the bundle, the recovery completes,
// then the drain settles it.
func TestOwedBundleKeptForStuckMove(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	p.h.oweBundle("nas", "plainapp")
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.State, in.Server = state.InstanceMoving, ""
	in.Move = &state.Move{From: "", To: "nas", Phase: MoveStuck, StartedAt: time.Now()}
	p.h.st.Instances["plainapp"] = in
	p.h.noteServersLocked()
	p.h.mu.Unlock()
	p.h.drainOwedBundles(context.Background())
	if workerHas(p.w, "signal remove-project plainapp") || owedCount(p) != 1 {
		t.Fatalf("drained under a stuck move: %v", p.w.Calls())
	}
	p.h.RecoverMoves()
	if in := p.instance("plainapp"); in.State != "" || in.Move != nil || in.Server != "" {
		t.Fatalf("not recovered: %+v", in)
	}
	p.h.drainOwedBundles(context.Background())
	if !workerHas(p.w, "signal remove-project plainapp") || owedCount(p) != 0 {
		t.Errorf("not drained after the recovery: %v", p.w.Calls())
	}
}

// TestLiftWhileMoving (R4-L5): 409, the agent untouched.
func TestLiftWhileMoving(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.State = state.InstanceMoving
	in.Move = &state.Move{From: "nas", To: "", Phase: MoveRestore}
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
	if err := p.h.LiftQuarantine(context.Background(), admin, "plainapp"); errStatus(err) != 409 {
		t.Errorf("%v", err)
	}
	if workerHas(p.w, "signal unquarantine") {
		t.Error("lifted")
	}
}

// TestUndoToPrimaryStuckRecovers (R4-L7): after the stuck undo recovers
// the record names the right pair, an undo works and returns it to the
// primary; one whose source is the current server is refused.
func TestUndoToPrimaryStuckRecovers(t *testing.T) {
	p := newPlacedFixture(t)
	movedHereFromPrimary(t, p)
	p.runner.mu.Lock()
	p.runner.upErr, p.runner.downErr = errors.New("up failed"), errors.New("down failed")
	p.runner.mu.Unlock()
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err == nil {
		t.Fatal("undone")
	}
	p.runner.mu.Lock()
	p.runner.upErr, p.runner.downErr = nil, nil
	p.runner.mu.Unlock()
	p.h.RecoverMoves()
	in := p.instance("plainapp")
	if in.State != "" || in.Server != "nas" || in.MovedFrom == nil || in.MovedFrom.Server == in.Server {
		t.Fatalf("after recovery %+v (from %+v)", in, in.MovedFrom)
	}
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	if in := p.instance("plainapp"); in.Server != "" || p.h.serverOf("plainapp") != "" {
		t.Errorf("after the undo %+v", in)
	}
	// A record naming the current server (src == cur) is refused.
	p.h.mu.Lock()
	in = p.h.st.Instances["plainapp"]
	in.MovedFrom = &state.MovedFrom{Server: "", At: time.Now()}
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); errStatus(err) != 409 {
		t.Errorf("src == cur: %v", err)
	}
}

// TestUndoMarkerRecovered (R4-L8): an undo persists a marker before it
// starts the source copy; a Hub restart with that marker takes the
// source copy down and leaves the current one the only routed copy.
func TestUndoMarkerRecovered(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	var during *state.Move
	p.w.mu.Lock()
	p.w.pushHook = func() { during = p.instance("plainapp").Move }
	p.w.pushErr = errors.New("crash stand-in")
	p.w.downErrs = 1 // the undo's own cleanup fails: the marker stays
	p.w.mu.Unlock()
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err == nil {
		t.Fatal("undone")
	}
	if during == nil || during.Phase != MoveUndoStarting || during.To != "nas" {
		t.Fatalf("no marker during the start: %+v", during)
	}
	if in := p.instance("plainapp"); in.Move == nil || in.Move.Phase != MoveUndoStarting || in.Server != "" {
		t.Fatalf("marker gone: %+v", in)
	}
	ups := upCount(p.runner.Calls(), "portcullis-plainapp")
	before := len(p.w.Calls())
	p.h.RecoverMoves()
	if in := p.instance("plainapp"); in.State != "" || in.Move != nil || in.Server != "" || p.h.serverOf("plainapp") != "" {
		t.Errorf("after recovery %+v", in)
	}
	if c := p.w.Calls()[before:]; !slices.Contains(c, "down portcullis-plainapp") || slices.Contains(c, "up portcullis-plainapp") {
		t.Errorf("worker calls %v", p.w.Calls())
	}
	if upCount(p.runner.Calls(), "portcullis-plainapp") != ups {
		t.Errorf("the primary copy was restarted: %v", p.runner.Calls())
	}
}

// TestPlacedPullRefs (R3-L5): a placed instance pre-pulls only template
// refs the allowlist resolves to the image compose would run; an
// env-overridden one is left to the worker's create (an env-only one is
// refused at create).
func TestPlacedPullRefs(t *testing.T) {
	p := newPlacedFixture(t)
	writeFile(t, filepath.Join(p.src, "refapp", "manifest.yaml"), "name: Refs\ncategory: misc\nai: {unsupported: t}\nauth: {method: forward-auth}\n")
	writeFile(t, filepath.Join(p.src, "refapp", "compose.yml"), `services:
  plain:
    image: plain:1@sha256:3333333333333333333333333333333333333333333333333333333333333333
    labels:
      traefik.enable: "true"
      traefik.http.routers.refs.rule: Host(`+"`${PORTCULLIS_HOST_REFS:-refs.portcullis.local}`"+`)
      traefik.http.routers.refs.middlewares: portcullis-auth@docker,portcullis-groups@docker
      traefik.http.services.refs.loadbalancer.server.port: "8080"
  defaulted:
    image: ${IMG_DEF:-reg.example/def:1@sha256:4444444444444444444444444444444444444444444444444444444444444444}
  overridden:
    image: ${IMG_OVR:-reg.example/ovr:1@sha256:5555555555555555555555555555555555555555555555555555555555555555}
  domain:
    image: reg.${PORTCULLIS_DOMAIN}/dom:1@sha256:6666666666666666666666666666666666666666666666666666666666666666
`)
	p.h.Discover()
	if err := p.create(t, "refapp", "nas"); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p.h.envPath("refapp"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("IMG_OVR=evil.example/ovr:6\nPORTCULLIS_DOMAIN=" + p.h.cfg.Domain + "\n")
	f.Close()
	if _, err := p.h.refreshServerFacts(context.Background(), "nas"); err != nil {
		t.Fatal(err)
	}
	got := p.h.pullRefs(context.Background(), p.h.Template("refapp"))
	want := []string{"plain:1@sha256:3333333333333333333333333333333333333333333333333333333333333333", "reg." + p.h.cfg.Domain + "/dom:1@sha256:6666666666666666666666666666666666666666666666666666666666666666", "reg.example/def:1@sha256:4444444444444444444444444444444444444444444444444444444444444444"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("pullRefs = %v, want %v", got, want)
	}
	// No facts for the server: nothing is pulled.
	p.h.srvMu.Lock()
	delete(p.h.polls, "nas")
	p.h.srvMu.Unlock()
	if got := p.h.pullRefs(context.Background(), p.h.Template("refapp")); got != nil {
		t.Errorf("no facts, still pulled %v", got)
	}
}
