package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

func enableSteps() []Step {
	return []Step{{Key: "groups", Label: "Groups"}, {Key: "keycloak", Label: "Sign-in client in Keycloak"}, {Key: "images", Label: "Downloading images"}}
}

// opFile is id's op record as stored on disk.
func opFile(t *testing.T, h *Hub, id string) OpRecord {
	t.Helper()
	data, err := os.ReadFile(h.opPath(id))
	if err != nil {
		t.Fatal(err)
	}
	var r OpRecord
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func stepOf(r OpRecord, key string) Step {
	for _, s := range r.Steps {
		if s.Key == key {
			return s
		}
	}
	return Step{}
}

// testClock is a settable progress clock.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestProgressPersisted: every Start / Done / Created writes the record
// (memory and file) at once; Percent at most every 500 ms, the last
// value flushed after; the file survives a reload.
func TestProgressPersisted(t *testing.T) {
	f := newFixture(t)
	clk := &testClock{t: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)}
	f.h.progressNow = clk.now
	var flushes []func()
	var waits []time.Duration
	f.h.afterFunc = func(d time.Duration, fn func()) func() bool {
		waits = append(waits, d)
		flushes = append(flushes, fn)
		return func() bool { return true }
	}
	p := f.h.newProgress("grafana", OpEnable, enableSteps())
	p.Start("groups") // before it is accepted: nothing written
	if _, err := os.Stat(f.h.opPath("grafana")); !os.IsNotExist(err) {
		t.Fatal("written before the operation was accepted")
	}
	p.begin("op1", "alice", nil)
	r := opFile(t, f.h, "grafana")
	if !r.Running || r.OpID != "op1" || r.Actor != "alice" || !r.Stoppable || r.Created == nil || stepOf(r, "groups").State != StepRunning || stepOf(r, "keycloak").State != StepWaiting {
		t.Fatalf("begin: %+v", r)
	}
	if b, _ := os.ReadFile(f.h.opPath("grafana")); !strings.Contains(string(b), `"keycloak_clients": []`) {
		t.Fatalf("created lists not always present: %s", b)
	}

	clk.add(time.Second)
	p.Created(CreatedGroups, "users_grafana")
	p.Created(CreatedGroups, "users_grafana") // once
	if r := opFile(t, f.h, "grafana"); !slices.Equal(r.Created.Groups, []string{"users_grafana"}) {
		t.Fatalf("created: %+v", r.Created)
	}
	clk.add(time.Second)
	p.Done("groups")
	r = opFile(t, f.h, "grafana")
	g := stepOf(r, "groups")
	if g.State != StepDone || g.StartedAt == nil || g.EndedAt == nil || g.EndedAt.Sub(*g.StartedAt) != 2*time.Second {
		t.Fatalf("done: %+v", g)
	}
	p.Start("images")

	// Percent: the first one after a write waits; then at most every
	// 500 ms; the pending value is flushed.
	p.Percent("images", 10, "gitea/gitea:1.25 — 69 of 690 MB")
	if s := stepOf(opFile(t, f.h, "grafana"), "images"); s.Percent != nil {
		t.Fatalf("percent written within 500 ms of the last write: %+v", s)
	}
	if len(flushes) != 1 || waits[0] != progressThrottle {
		t.Fatalf("flush armed %d times, waits %v", len(flushes), waits)
	}
	clk.add(100 * time.Millisecond)
	p.Percent("images", 20, "b")
	if len(flushes) != 1 {
		t.Fatal("a second flush armed")
	}
	clk.add(400 * time.Millisecond)
	flushes[0]()
	if s := stepOf(opFile(t, f.h, "grafana"), "images"); s.Percent == nil || *s.Percent != 20 || s.Detail != "b" {
		t.Fatalf("flushed: %+v", s)
	}
	clk.add(100 * time.Millisecond)
	p.Percent("images", 30, "c")
	if s := stepOf(opFile(t, f.h, "grafana"), "images"); *s.Percent != 20 {
		t.Fatalf("written 100 ms after the last write: %+v", s)
	}
	clk.add(500 * time.Millisecond)
	p.Percent("images", 140, "multi\nline") // clamped, one line
	s := stepOf(opFile(t, f.h, "grafana"), "images")
	if *s.Percent != 100 || s.Detail != "multi line" {
		t.Fatalf("after 500 ms: %+v", s)
	}
	if mem := f.h.LastOp("grafana"); mem == nil || *stepOf(*mem, "images").Percent != 100 {
		t.Fatal("memory and file disagree")
	}

	// The final record keeps the steps and created; a reload keeps it.
	p.finish(OpRecord{Op: OpEnable, OK: true, At: clk.now()}, nil)
	p.Start("keycloak") // after the end: nothing written
	f.h.loadOps()
	lo := f.h.LastOp("grafana")
	if lo == nil || lo.Running || !lo.OK || lo.Interrupted || stepOf(*lo, "images").State != StepDone ||
		stepOf(*lo, "keycloak").State != StepWaiting || !slices.Equal(lo.Created.Groups, []string{"users_grafana"}) || lo.Stoppable {
		t.Fatalf("after reload: %+v", lo)
	}
}

// TestProgressRedactsDetail: a step's detail never holds a secret.
func TestProgressRedactsDetail(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.h.envPath("grafana"), "GF_SECURITY_ADMIN_PASSWORD=hunter2-secret\n")
	p := f.h.newProgress("grafana", OpEnable, enableSteps())
	p.begin("op1", "alice", nil)
	p.Fail("groups", errors.New("login hunter2-secret refused"))
	b, _ := os.ReadFile(f.h.opPath("grafana"))
	if strings.Contains(string(b), "hunter2-secret") {
		t.Fatalf("secret in the record: %s", b)
	}
	if s := stepOf(opFile(t, f.h, "grafana"), "groups"); s.State != StepFailed || !strings.Contains(s.Detail, "refused") {
		t.Fatalf("failed step: %+v", s)
	}
}

// TestProgressNilSafe: a nil reporter (no progress in ctx) does nothing.
func TestProgressNilSafe(t *testing.T) {
	p := progressFrom(context.Background())
	if p != nil {
		t.Fatal("progress in a bare context")
	}
	p.Start("a")
	p.Percent("a", 50, "x")
	p.Done("a")
	p.Fail("a", errors.New("x"))
	p.Created(CreatedVolumes, "v")
	p.NoReturn()
	p.AddStep("undo:a", "Undo")
	p.Undone("a")
	if p.Stopping() {
		t.Fatal("nil stopping")
	}
}

// TestStartAsyncCancellable: a Stop cancels the operation's context, fn
// sees ctx.Err(); the record goes stopping, then stopped (ok false, no
// error, no failure).
func TestStartAsyncCancellable(t *testing.T) {
	f := newFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var seen error
	a, err := f.h.startAsync("grafana", OpEnable, directory.Human("alice"), enableSteps(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		p := progressFrom(ctx)
		p.Start("groups")
		p.Created(CreatedGroups, "users_grafana")
		close(started)
		<-ctx.Done()
		seen = ctx.Err()
		<-release
		p.Start("undo:groups")
		p.Done("undo:groups")
		p.Undone("groups")
		return nil, nil, ctx.Err()
	})
	if err != nil || a == nil {
		t.Fatal(a, err)
	}
	<-started
	if err := f.h.cancelOp("grafana", directory.Actor{}); statusOf(err) != 401 {
		t.Fatalf("no actor: %v", err)
	}
	if err := f.h.cancelOp("grafana", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	r := opFile(t, f.h, "grafana")
	if !r.Running || !r.Stopping || r.Stoppable || r.StoppedBy != "bob" || r.StoppedAt == nil || stepOf(r, "groups").State != StepStopped {
		t.Fatalf("stopping: %+v", r)
	}
	if err := f.h.cancelOp("grafana", directory.Human("bob")); statusOf(err) != 409 || !strings.Contains(err.Error(), "already stopping") {
		t.Fatalf("second stop: %v", err)
	}
	close(release)
	f.h.Wait()
	if !errors.Is(seen, context.Canceled) {
		t.Fatalf("fn saw %v", seen)
	}
	r = opFile(t, f.h, "grafana")
	if r.Running || r.Stopping || r.Stoppable || r.OK || r.Error != "" || r.Status != 0 || !r.Stopped() || r.Actor != "alice" || r.StoppedBy != "bob" ||
		stepOf(r, "groups").State != StepUndone || stepOf(r, "undo:groups").State != StepDone || !slices.Equal(r.Created.Groups, []string{"users_grafana"}) {
		t.Fatalf("stopped: %+v", r)
	}
	if fo := f.h.FailedOps(); len(fo) != 0 {
		t.Fatalf("a stopped op counts as failed: %v", fo)
	}
	for _, v := range f.h.Instances() {
		if v.ID == "grafana" && v.State == StateError {
			t.Fatal("a stopped op shows the instance as error")
		}
	}
	if err := f.h.cancelOp("grafana", directory.Human("bob")); statusOf(err) != 409 || !strings.Contains(err.Error(), "no operation is running") {
		t.Fatalf("stop after the end: %v", err)
	}
}

// TestCancelOpRefusals: past the point of no return and an operation
// without steps can't be stopped; an undo that fails stays stoppable.
func TestCancelOpRefusals(t *testing.T) {
	f := newFixture(t)
	hold := func(id string, steps []Step, body func(ctx context.Context)) chan struct{} {
		release, started := make(chan struct{}), make(chan struct{})
		if _, err := f.h.startAsync(id, OpDelete, directory.Human("alice"), steps, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
			ready()
			body(ctx)
			close(started)
			<-release
			return nil, nil, nil
		}); err != nil {
			t.Fatal(err)
		}
		<-started
		return release
	}
	rel := hold("grafana", []Step{{Key: "backup"}, {Key: "volumes"}}, func(ctx context.Context) {
		p := progressFrom(ctx)
		p.Start("volumes")
		p.NoReturn()
	})
	if err := f.h.cancelOp("grafana", directory.Human("bob")); statusOf(err) != 409 || !strings.Contains(err.Error(), "point of no return") {
		t.Fatalf("past the point of no return: %v", err)
	}
	if r := opFile(t, f.h, "grafana"); !r.PointOfNoReturn || r.Stoppable {
		t.Fatalf("no return: %+v", r)
	}
	close(rel)
	rel = hold("other", nil, func(context.Context) {})
	if err := f.h.cancelOp("other", directory.Human("bob")); statusOf(err) != 409 || !strings.Contains(err.Error(), "can't be stopped") {
		t.Fatalf("no steps: %v", err)
	}
	close(rel)
	f.h.Wait()
	if err := f.h.cancelOp("nothing", directory.Human("bob")); statusOf(err) != 409 {
		t.Fatalf("unknown: %v", err)
	}

	// A failed undo: the error stays, stoppable again.
	started := make(chan struct{})
	release := make(chan struct{})
	f.h.startAsync("grafana", OpEnable, directory.Human("alice"), enableSteps(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		progressFrom(ctx).Start("groups")
		close(started)
		<-ctx.Done()
		<-release
		p := progressFrom(ctx)
		p.Start("undo:groups")
		return nil, nil, statusErr(500, "delete group users_grafana: refused")
	})
	<-started
	if err := f.h.cancelOp("grafana", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	close(release)
	f.h.Wait()
	r := opFile(t, f.h, "grafana")
	if r.OK || r.Running || r.Stopping || !r.Stoppable || r.Stopped() || !r.Failed() || r.Status != 500 || !strings.Contains(r.Error, "refused") ||
		stepOf(r, "undo:groups").State != StepFailed || stepOf(r, "groups").State != StepStopped {
		t.Fatalf("undo failed: %+v", r)
	}
}

// TestRunOpSync: the synchronous form shares the record and returns
// fn's own answer; a refusal before ready records nothing.
func TestRunOpSync(t *testing.T) {
	f := newFixture(t)
	boom := statusErr(409, "busy")
	if _, _, err := f.h.runOpSync("grafana", OpEnable, directory.Human("alice"), enableSteps(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return nil, nil, boom
	}); err != boom {
		t.Fatalf("refusal: %v", err)
	}
	if f.h.LastOp("grafana") != nil {
		t.Fatal("a refusal was recorded")
	}
	res, warn, err := f.h.runOpSync("grafana", OpEnable, directory.Human("alice"), enableSteps(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		p := progressFrom(ctx)
		for _, k := range []string{"groups", "keycloak", "images"} {
			p.Start(k)
			p.Done(k)
		}
		return map[string]string{"x": "y"}, []string{"w"}, nil
	})
	if err != nil || res["x"] != "y" || len(warn) != 1 {
		t.Fatal(res, warn, err)
	}
	r := f.h.LastOp("grafana")
	if r == nil || r.Running || !r.OK || r.Actor != "alice" || stepOf(*r, "images").State != StepDone {
		t.Fatalf("record: %+v", r)
	}
}

// TestInterruptedKeepsLedger: a record still running at load becomes
// interrupted (stoppable, steps and created intact, the running step
// stopped); restores and a delete past its point of no return are
// recovered at start and not stoppable.
func TestInterruptedKeepsLedger(t *testing.T) {
	f := newFixture(t)
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Second)
	running := func(op string, noReturn bool) OpRecord {
		return OpRecord{Op: op, OpID: "op1", At: t0, Running: true, Actor: "alice", Stoppable: !noReturn, PointOfNoReturn: noReturn,
			Steps: []Step{{Key: "groups", Label: "Groups", State: StepDone, StartedAt: &t0, EndedAt: &t1},
				{Key: "images", Label: "Downloading images", State: StepRunning, StartedAt: &t1}, {Key: "start", Label: "Starting", State: StepWaiting}},
			Created: &Created{Groups: []string{"users_grafana"}, KeycloakClients: []string{"grafana"}}}
	}
	f.h.recordOp("grafana", running(OpEnable, false))
	f.h.recordOp("other", running(OpRestore, false))
	f.h.recordOp("a-del", running(OpDelete, true))
	f.h.recordOp("b-del", running(OpDelete, false))
	f.h.recordOp("c-plain", OpRecord{Op: OpRebind, OpID: "x", At: t0, Running: true})
	f.h.recordOp("d-backup", running(OpBackup, true)) // any op past its point of no return
	f.h.loadOps()
	for _, r := range []OpRecord{*f.h.LastOp("grafana"), opFile(t, f.h, "grafana")} {
		if r.Running || r.OK || !r.Interrupted || !r.Stoppable || r.Status != 500 || !strings.HasPrefix(r.Error, "interrupted:") || r.Actor != "alice" {
			t.Fatalf("interrupted: %+v", r)
		}
		if g := stepOf(r, "groups"); g.State != StepDone || g.EndedAt == nil || !g.EndedAt.Equal(t1) {
			t.Fatalf("done step: %+v", g)
		}
		if stepOf(r, "images").State != StepStopped || stepOf(r, "start").State != StepWaiting {
			t.Fatalf("steps: %+v", r.Steps)
		}
		if r.Created == nil || !slices.Equal(r.Created.Groups, []string{"users_grafana"}) || !slices.Equal(r.Created.KeycloakClients, []string{"grafana"}) {
			t.Fatalf("created: %+v", r.Created)
		}
	}
	for id, want := range map[string]bool{"other": false, "a-del": false, "b-del": true, "c-plain": false, "d-backup": false} {
		if r := f.h.LastOp(id); r == nil || !r.Interrupted || r.Stoppable != want {
			t.Fatalf("%s: stoppable want %v: %+v", id, want, r)
		}
	}
	// An interrupted operation is a failure (state error, FailedOps).
	if f.h.FailedOps()["grafana"] != OpEnable {
		t.Fatal("interrupted enable not listed as failed")
	}
}

// TestProgressRedactsExtras: the values an error carries for redaction
// (withSecrets: a restore's archive secrets) never reach a step detail,
// in memory or on disk — also in later writes.
func TestProgressRedactsExtras(t *testing.T) {
	f := newFixture(t)
	p := f.h.newProgress("grafana", OpRestore, enableSteps())
	p.begin("op1", "alice", nil)
	p.Fail("groups", withSecrets(errors.New("x s3cret-archive-value"), []string{"s3cret-archive-value"}))
	p.Start("images")
	p.Percent("images", 50, "copying s3cret-archive-value")
	p.Done("images")
	b, _ := os.ReadFile(f.h.opPath("grafana"))
	mem, _ := json.Marshal(f.h.LastOp("grafana"))
	for _, out := range []string{string(b), string(mem)} {
		if strings.Contains(out, "s3cret") {
			t.Fatalf("an extra secret in the record: %s", out)
		}
	}
	if s := stepOf(opFile(t, f.h, "grafana"), "groups"); s.State != StepFailed || !strings.HasPrefix(s.Detail, "x ") {
		t.Fatalf("failed step: %+v", s)
	}
}

// TestProgressPercentStartsAtOnce: a Percent that moves a waiting step
// to running is written at once, even within the throttle.
func TestProgressPercentStartsAtOnce(t *testing.T) {
	f := newFixture(t)
	clk := &testClock{t: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)}
	f.h.progressNow = clk.now
	f.h.afterFunc = func(time.Duration, func()) func() bool { return func() bool { return true } }
	p := f.h.newProgress("grafana", OpEnable, enableSteps())
	p.begin("op1", "alice", nil)
	p.Done("groups")
	p.Percent("images", 5, "pulling")
	s := stepOf(opFile(t, f.h, "grafana"), "images")
	if s.State != StepRunning || s.Percent == nil || *s.Percent != 5 || s.StartedAt == nil {
		t.Fatalf("waiting → running not written at once: %+v", s)
	}
	p.Percent("images", 6, "pulling")
	if s := stepOf(opFile(t, f.h, "grafana"), "images"); *s.Percent != 5 {
		t.Fatalf("a running step's percent not throttled: %+v", s)
	}
}

// TestFinalRecordKeepsNextOp: an operation's fn releases the instance's
// lock before its final record is written; an operation accepted in
// between keeps its running record (the first one's outcome is only
// logged).
func TestFinalRecordKeepsNextOp(t *testing.T) {
	f := newFixture(t)
	released, bStarted, releaseB := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var relOnce sync.Once
	freeB := func() { relOnce.Do(func() { close(releaseB) }) }
	defer freeB() // a failure never leaves B blocking the fixture's Wait
	_, aDone, err := f.h.startOp("grafana", OpBackup, directory.Human("alice"), enableSteps(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		unlock, err := f.h.lockApp("grafana")
		if err != nil {
			return nil, nil, err
		}
		ready()
		progressFrom(ctx).Start("groups")
		unlock()
		close(released)
		<-bStarted // B accepted between A's lock release and A's final record
		return nil, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	<-released
	b, err := f.h.startAsync("grafana", OpEnable, directory.Human("bob"), enableSteps(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		unlock, err := f.h.lockApp("grafana")
		if err != nil {
			return nil, nil, err
		}
		defer unlock()
		ready()
		close(bStarted)
		<-releaseB
		return nil, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	<-aDone // A's final record was attempted
	for _, r := range []OpRecord{*f.h.LastOp("grafana"), opFile(t, f.h, "grafana")} {
		if r.OpID != b.OpID || !r.Running || r.Actor != "bob" {
			t.Fatalf("B's running record overwritten: %+v", r)
		}
	}
	freeB()
	f.h.Wait()
	if r := opFile(t, f.h, "grafana"); r.OpID != b.OpID || r.Running || !r.OK {
		t.Fatalf("B's final: %+v", r)
	}
}
