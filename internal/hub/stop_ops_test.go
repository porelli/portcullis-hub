package hub

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
)

// Disable, restart and the AI switches report their steps and can be
// stopped (contract §11.7 "Stop", §15.11 "Switching on").

// blockStep makes the first Start of step key (of any operation on h)
// wait until release is closed; reached is closed when it got there.
func blockStep(t *testing.T, h *Hub, key string) (reached, release chan struct{}) {
	t.Helper()
	reached, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	h.testHookStepStart = func(op, k string) {
		if k != key {
			return
		}
		once.Do(func() {
			close(reached)
			<-release
		})
	}
	return reached, release
}

// stopAndWait stops id's running operation (blocked at reached) as bob,
// releases it and returns its final record.
func stopAndWait(t *testing.T, h *Hub, id, opID string, reached, release chan struct{}) OpRecord {
	t.Helper()
	<-reached
	rec, err := h.StopOp(id, directory.Human("bob"))
	if err != nil || rec == nil || !rec.Stopping || rec.StoppedBy != "bob" {
		t.Fatalf("stop: %+v %v", rec, err)
	}
	close(release)
	return waitOp(t, h, id, opID)
}

func stepKeys(r OpRecord) []string {
	var out []string
	for _, s := range r.Steps {
		out = append(out, s.Key)
	}
	return out
}

// runningOther: other enabled (by alice) and its containers running.
func (f *stopFix) runningOther(t *testing.T) {
	t.Helper()
	if _, err := f.h.EnableAs("other", directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	if !f.otherRunning() {
		t.Fatal("other not running after the enable")
	}
}

func (f *stopFix) otherRunning() bool {
	f.engine.mu.Lock()
	defer f.engine.mu.Unlock()
	if len(f.engine.containers) == 0 {
		return false
	}
	for _, c := range f.engine.containers {
		if c.State != "running" {
			return false
		}
	}
	return true
}

func (f *stopFix) ups() int {
	n := 0
	for _, c := range f.runner.Calls() {
		if c == "up:"+projectName("other") {
			n++
		}
	}
	return n
}

// TestDisableSteps: a disable reports stop and callbacks (Keycloak
// wired), each done, and the instance ends disabled.
func TestDisableSteps(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	a, err := f.h.StartDisable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "other", a.OpID)
	if !r.OK || r.Op != OpDisable || r.Actor != "alice" || f.h.IsEnabled("other") || f.otherRunning() {
		t.Fatalf("record: %+v enabled=%v", r, f.h.IsEnabled("other"))
	}
	if got := stepKeys(r); !slices.Equal(got, []string{StepStop, StepCallbacks}) {
		t.Fatalf("steps %v", got)
	}
	for _, s := range r.Steps {
		if s.State != StepDone {
			t.Errorf("step %s: %s", s.Key, s.State)
		}
	}
	if stepOf(r, StepCallbacks).Label != "Keycloak callbacks" {
		t.Errorf("label %q", stepOf(r, StepCallbacks).Label)
	}
	// Not enabled: refused at once, nothing recorded.
	if _, err := f.h.StartDisable("other", directory.Human("alice")); statusOf(err) != 400 {
		t.Fatalf("disable a disabled app: %v", err)
	}
	if r2 := f.h.LastOp("other"); r2 == nil || r2.OpID != a.OpID {
		t.Errorf("a refusal was recorded: %+v", r2)
	}
}

// TestStopDisable: a Stop at either step turns the app back on: enabled,
// running again; the stop step undone; audited disable.stop.
func TestStopDisable(t *testing.T) {
	for _, at := range []string{StepStop, StepCallbacks} {
		t.Run(at, func(t *testing.T) {
			f := stopFixture(t)
			f.runningOther(t)
			ups := f.ups()
			reached, release := blockStep(t, f.h, at)
			a, err := f.h.StartDisable("other", directory.Human("alice"))
			if err != nil {
				t.Fatal(err)
			}
			r := stopAndWait(t, f.h, "other", a.OpID, reached, release)
			if !r.Stopped() || r.Error != "" || r.Stoppable {
				t.Fatalf("record: %+v", r)
			}
			if !f.h.IsEnabled("other") || !f.otherRunning() || f.ups() <= ups {
				t.Fatalf("not back on: enabled=%v running=%v ups %d→%d", f.h.IsEnabled("other"), f.otherRunning(), ups, f.ups())
			}
			if s := stepOf(r, StepStop).State; s != StepUndone {
				t.Errorf("stop step %s", s)
			}
			if s := stepOf(r, UndoStart).State; s != StepDone {
				t.Errorf("undo:start %s (%v)", s, stepKeys(r))
			}
			if at == StepCallbacks && stepOf(r, UndoCallbacks).State != StepDone {
				t.Errorf("undo:callbacks %+v", stepOf(r, UndoCallbacks))
			}
			if e := f.audit.last(); e.Action != "disable.stop" || e.Detail != at || e.Actor != "bob" || e.Result != "ok" {
				t.Errorf("audit %+v", e)
			}
			if st := f.instanceState("other"); st != StateEnabled {
				t.Errorf("state %q", st)
			}
		})
	}
}

// TestStopDisableRestoresCallbacks: the extra-domain sign-in callbacks a
// stopped disable removed are added back.
func TestStopDisableRestoresCallbacks(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "grafana.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	// Stop once the callbacks are removed: right before the commit.
	f.idp.mu.Lock()
	f.idp.callbacks = nil
	f.idp.mu.Unlock()
	f.h.testHookCommit = func(id, stage string) {
		if id == "grafana-b" && stage == "disable" {
			once.Do(func() { close(reached); <-release })
		}
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	a, err := f.h.StartDisable("grafana-b", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, f.h, "grafana-b", a.OpID, reached, release)
	if !r.Stopped() || !f.h.IsEnabled("grafana-b") {
		t.Fatalf("record %+v enabled=%v", r, f.h.IsEnabled("grafana-b"))
	}
	cb := "https://grafana.team-b.example.org/oauth2/callback"
	f.idp.mu.Lock()
	got := strings.Join(f.idp.callbacks, " | ")
	f.idp.mu.Unlock()
	if got != "+ -"+cb+" | +"+cb+" -" {
		t.Errorf("callbacks = %s", got)
	}
	if stepOf(r, StepCallbacks).State != StepUndone || stepOf(r, UndoCallbacks).State != StepDone {
		t.Errorf("steps %+v", r.Steps)
	}
}

// TestDisableAfterCommitFinishing: a Stop after the disable's commit gate
// is refused "finishing"; the disable completes.
func TestDisableAfterCommitFinishing(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.h.testHookCommit = func(id, stage string) {
		if stage == "disable:after" {
			once.Do(func() { close(reached); <-release })
		}
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	a, err := f.h.StartDisable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if rec, err := f.h.StopOp("other", directory.Human("bob")); statusOf(err) != 409 || !strings.Contains(err.Error(), "finishing") || rec == nil || !rec.Running {
		t.Fatalf("stop after the gate: %+v %v", rec, err)
	}
	close(release)
	if r := waitOp(t, f.h, "other", a.OpID); !r.OK || f.h.IsEnabled("other") {
		t.Fatalf("record %+v", r)
	}
}

// TestDisableSyncKeepsName: Disable (the Hub's own callers) runs the same
// operation to its end: the record has the steps and no actor.
func TestDisableSyncKeepsName(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	if err := f.h.Disable("other"); err != nil {
		t.Fatal(err)
	}
	r := f.h.LastOp("other")
	if r == nil || !r.OK || r.Op != OpDisable || r.Actor != "" || stepOf(*r, StepStop).State != StepDone || f.h.IsEnabled("other") {
		t.Fatalf("record %+v", r)
	}
}

// TestRestartSteps: a restart reports down, images, start, healthy and
// settings (create is not one of its steps).
func TestRestartSteps(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	a, err := f.h.StartRestart("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "other", a.OpID)
	if !r.OK || r.Op != OpRestart || !f.otherRunning() {
		t.Fatalf("record %+v", r)
	}
	if got := stepKeys(r); !slices.Equal(got, []string{StepDown, StepImages, StepStart, StepHealthy, StepSettings}) {
		t.Fatalf("steps %v", got)
	}
	for _, s := range r.Steps {
		if s.State != StepDone {
			t.Errorf("step %s: %s", s.Key, s.State)
		}
	}
	if _, err := f.h.StartRestart("nope", directory.Human("alice")); statusOf(err) != 404 {
		t.Errorf("unknown: %v", err)
	}
	if _, err := f.h.StartRestart("grafana", directory.Human("alice")); statusOf(err) != 400 {
		t.Errorf("not enabled: %v", err)
	}
}

// TestStopRestart: a Stop at any step leaves the app running as before
// (brought up again with its current files); audited restart.stop.
func TestStopRestart(t *testing.T) {
	for _, at := range []string{StepDown, StepImages, StepStart, StepHealthy, StepSettings} {
		t.Run(at, func(t *testing.T) {
			f := stopFixture(t)
			f.runningOther(t)
			reached, release := blockStep(t, f.h, at)
			a, err := f.h.StartRestart("other", directory.Human("alice"))
			if err != nil {
				t.Fatal(err)
			}
			r := stopAndWait(t, f.h, "other", a.OpID, reached, release)
			if !r.Stopped() || r.Error != "" {
				t.Fatalf("record %+v", r)
			}
			if !f.otherRunning() || !f.h.IsEnabled("other") {
				t.Fatalf("not running after the Stop")
			}
			if stepOf(r, UndoStart).State != StepDone || stepOf(r, StepDown).State != StepUndone {
				t.Errorf("steps %+v", r.Steps)
			}
			if e := f.audit.last(); e.Action != "restart.stop" || e.Detail != at || e.Result != "ok" {
				t.Errorf("audit %+v", e)
			}
		})
	}
}

// TestStopRestartNotRunning: a restart of an app that wasn't running,
// stopped once it started it, leaves it down.
func TestStopRestartNotRunning(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	f.engine.mu.Lock()
	f.engine.containers = nil
	f.engine.mu.Unlock()
	reached, release := blockStep(t, f.h, StepHealthy)
	a, err := f.h.StartRestart("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, f.h, "other", a.OpID, reached, release)
	if !r.Stopped() || f.otherRunning() {
		t.Fatalf("record %+v running=%v", r, f.otherRunning())
	}
	if r.Before["running"] != "false" || stepOf(r, UndoDown).State != StepDone {
		t.Errorf("record %+v", r)
	}
}

// TestRestartSyncAndOwed: the Hub's own Restart (a queued restart) takes
// the same path — steps recorded, no actor — and clears the owed
// restart as before.
func TestRestartSyncAndOwed(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	f.h.setOwed("other", settings.EffectRestart)
	f.h.Restart(*f.h.Template("other"))
	r := f.h.LastOp("other")
	if r == nil || !r.OK || r.Op != OpRestart || r.Actor != "" || len(r.Steps) != 5 {
		t.Fatalf("record %+v", r)
	}
	f.h.owedMu.Lock()
	owed := f.h.owedLocked("other")
	f.h.owedMu.Unlock()
	if owed != "" {
		t.Errorf("still owed: %q", owed)
	}
	if err := f.h.RestartApp("other"); err != nil {
		t.Fatal(err)
	}
	if r := f.h.LastOp("other"); r == nil || !r.OK || len(r.Steps) != 5 {
		t.Fatalf("RestartApp record %+v", r)
	}
}

// TestRestartKilledByStop: the pull and compose run on the operation's
// context: a Stop while compose up runs kills it.
func TestRestartKilledByStop(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	killed := make(chan bool, 1)
	f.runner.upCtxHook = func(ctx context.Context) {
		once.Do(func() {
			close(reached)
			select {
			case <-ctx.Done():
				killed <- true
			case <-time.After(5 * time.Second):
				killed <- false
			}
		})
	}
	a, err := f.h.StartRestart("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	if !<-killed {
		t.Error("compose up was not cancelled by the Stop")
	}
	close(release)
	if r := waitOp(t, f.h, "other", a.OpID); !r.Stopped() || !f.otherRunning() {
		t.Fatalf("record %+v", r)
	}
}

// TestAISwitchSteps: on an enabled instance a companion switch runs in
// the background with the steps revoke, scopes, restart, hooks.
func TestAISwitchSteps(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	op, res, err := a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true), Mode: ptr("read_write")}}}, root)
	if err != nil || op == nil || res != nil || op.Op != OpAI {
		t.Fatalf("start: %+v %+v %v", op, res, err)
	}
	r := waitOp(t, a.h, "aiapp", op.OpID)
	if !r.OK {
		t.Fatalf("record %+v", r)
	}
	if got := stepKeys(r); !slices.Equal(got, []string{StepRevoke, StepScopes, StepRestart, StepHooks}) {
		t.Fatalf("steps %v", got)
	}
	for _, s := range r.Steps {
		if s.State != StepDone {
			t.Errorf("step %s: %s", s.Key, s.State)
		}
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled || c.Mode != "read_write" {
		t.Errorf("state %+v", c)
	}
	// Nothing to change: answered at once with the tab, no operation.
	op, res, err = a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true)}}}, root)
	if err != nil || op != nil || res == nil {
		t.Fatalf("unchanged: %+v %+v %v", op, res, err)
	}
	// A refusal: synchronous, nothing recorded.
	if _, _, err := a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"nope": {Enabled: ptr(true)}}}, root); statusOf(err) != 404 {
		t.Errorf("unknown companion: %v", err)
	}
	if last := a.h.LastOp("aiapp"); last == nil || last.OpID != r.OpID {
		t.Errorf("record %+v", last)
	}
}

// TestAISwitchDisabledStaysSync: on a disabled instance the switch is
// synchronous (the tab), as is a provider selection.
func TestAISwitchDisabledStaysSync(t *testing.T) {
	a := newInstAIFixture(t, nil)
	op, res, err := a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true)}}}, root)
	if err != nil || op != nil || res == nil || res.Restarts {
		t.Fatalf("disabled: %+v %+v %v", op, res, err)
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled {
		t.Errorf("state %+v", c)
	}
}

// TestStopAISwitchKeepsOwed: a switch stopped after its save (before its
// hooks ran) never clears what it owes: the owed on_change of the switch
// stays until a switch path runs it.
func TestStopAISwitchKeepsOwed(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	reached, release := blockStep(t, a.h, StepHooks)
	var mid state.AICompanion
	a.h.testHookAIAfterSave = func() { mid = a.companion("aiapp", "tok") }
	op, _, err := a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true)}}}, root)
	if err != nil || op == nil {
		t.Fatal(err)
	}
	<-reached
	if !mid.Enabled || !mid.OnChangePending {
		t.Fatalf("the switch's commit owes no on_change: %+v", mid)
	}
	if _, err := a.h.StopOp("aiapp", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	// The switch back's on_change fails: still owed afterwards.
	a.failHook("/toggle", 1, "toggle broke")
	close(release)
	r := waitOp(t, a.h, "aiapp", op.OpID)
	if r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	if c := a.companion("aiapp", "tok"); !c.OnChangePending {
		t.Errorf("owed on_change dropped: %+v", c)
	}
}

// TestStopAISwitchOn: a Stop of a switch-on at any step puts the
// companion back off through the switch path (revoke_all, scope dropped,
// router gone, on_change false); audited ai.stop.
func TestStopAISwitchOn(t *testing.T) {
	for _, at := range []string{StepRevoke, StepScopes, StepRestart, StepHooks} {
		t.Run(at, func(t *testing.T) {
			a := newInstAIFixture(t, nil)
			a.enable(t, "aiapp")
			reached, release := blockStep(t, a.h, at)
			op, _, err := a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true), Mode: ptr("read_write")}}}, root)
			if err != nil || op == nil {
				t.Fatalf("start %v", err)
			}
			<-reached
			rec, err := a.h.StopOp("aiapp", directory.Human("bob"))
			if err != nil || !rec.Stopping {
				t.Fatalf("stop %+v %v", rec, err)
			}
			close(release)
			r := waitOp(t, a.h, "aiapp", op.OpID)
			if !r.Stopped() || r.Error != "" {
				t.Fatalf("record %+v", r)
			}
			if c := a.companion("aiapp", "tok"); c.Enabled {
				t.Errorf("still on: %+v", c)
			}
			if _, ok := a.kc.scope("mcp:aiapp.tok"); ok {
				t.Error("scope kept")
			}
			if strings.Contains(a.override(t, "aiapp"), "portcullis-mcp-aiapp--tok") {
				t.Error("router kept")
			}
			if !strings.HasPrefix(r.Before["companion:tok"], "off ") {
				t.Errorf("before %v", r.Before)
			}
			if at != StepRevoke {
				if s := stepOf(r, UndoSwitch).State; s != StepDone {
					t.Errorf("undo:switch %s (%v)", s, stepKeys(r))
				}
				if got := a.stdins("/toggle"); len(got) == 0 || !strings.Contains(got[len(got)-1], `"enabled":false`) {
					t.Errorf("on_change %v", got)
				}
			}
			if e := a.audits("ai.stop"); len(e) != 1 || e[0].Detail != at || e[0].Actor != "bob" || e[0].Result != "ok" {
				t.Errorf("audit %+v", e)
			}
		})
	}
}

// TestStopAIModeChange: a Stop of a mode change puts the previous mode
// back, the companion still on.
func TestStopAIModeChange(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	before := a.companion("aiapp", "tok").Mode
	other := "read_write"
	if before == other {
		other = "read_only"
	}
	reached, release := blockStep(t, a.h, StepHooks)
	op, _, err := a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Mode: ptr(other)}}}, root)
	if err != nil || op == nil {
		t.Fatal(err)
	}
	r := stopAndWait(t, a.h, "aiapp", op.OpID, reached, release)
	if !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled || c.Mode != before {
		t.Errorf("state %+v, want on %s", c, before)
	}
	if _, ok := a.kc.scope("mcp:aiapp.tok"); !ok {
		t.Error("scope gone")
	}
}

// TestStopAIUndoFailsThenRetries: a failing switch back (its on_change
// hook fails) leaves the record failed and stoppable; Stop again retries.
func TestStopAIUndoFailsThenRetries(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	reached, release := blockStep(t, a.h, StepHooks)
	op, _, err := a.h.StartInstanceAI("aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true)}}}, root)
	if err != nil || op == nil {
		t.Fatal(err)
	}
	<-reached
	if _, err := a.h.StopOp("aiapp", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	a.failHook("/toggle", 1, "toggle broke")
	close(release)
	r := waitOp(t, a.h, "aiapp", op.OpID)
	if r.Stopped() || !r.Stoppable || stepOf(r, UndoSwitch).State != StepFailed {
		t.Fatalf("record %+v", r)
	}
	// The on_change the failed switch back owes stays owed (never cleared
	// by a failed or stopped switch).
	if c := a.companion("aiapp", "tok"); c.Enabled || !c.OnChangePending {
		t.Errorf("after the failed undo: %+v", c)
	}
	a.mu.Lock()
	delete(a.hookFail, "/toggle")
	a.mu.Unlock()
	if _, err := a.h.StopOp("aiapp", directory.Human("carol")); err != nil {
		t.Fatal(err)
	}
	r = waitOp(t, a.h, "aiapp", op.OpID)
	if !r.Stopped() || stepOf(r, UndoSwitch).State != StepDone {
		t.Fatalf("retry %+v", r)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled || c.OnChangePending {
		t.Errorf("state %+v", c)
	}
}

// TestRecordExpectedVolumesSkipsForeign: a volume named like the project's
// that exists already without the project label is never in the ledger
// (a Stop keeps it).
func TestRecordExpectedVolumesSkipsForeign(t *testing.T) {
	f := stopFixture(t)
	f.engine.addVolume(madeVolume, "", "", 0)
	f.runner.createHook = func(string) {
		f.engine.mu.Lock()
		f.engine.containers = []docker.Container{container("w1", projectName("other"), "web", "created")}
		f.engine.mu.Unlock()
	}
	r := f.enableStopped(t, StepStart)
	if !r.Stopped() || slices.Contains(r.Created.Volumes, madeVolume) {
		t.Fatalf("record %+v", r)
	}
	if !slices.Contains(f.engine.volumeNames(), madeVolume) {
		t.Error("the foreign volume was removed")
	}
}

// TestHeldHookOwnOp: a hook failure held for a running operation is
// dropped or written only by that operation's end.
func TestHeldHookOwnOp(t *testing.T) {
	f := newFixture(t)
	f.h.recordOp("grafana", OpRecord{Op: OpEnable, OpID: "op-b", Running: true})
	f.h.finishOpGuarded("grafana", OpHook, errFake("hook broke"), false, true)
	p := f.h.newProgress("grafana", OpEnable, nil)
	p.rec.OpID = "op-a"
	f.h.finishAsync("grafana", OpEnable, p, nil, nil, nil)
	f.h.opsMu.Lock()
	held, ok := f.h.heldHook["grafana"]
	f.h.opsMu.Unlock()
	if !ok || held.opID != "op-b" {
		t.Fatalf("op-b's held failure dropped by op-a's end: %+v %v", held, ok)
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }

// TestStoppedRestartStaysOwed: a Stop (or a failure) of a restart the
// delivery engine owes leaves the restart owed — never dropped — and a
// later run applies and clears it.
func TestStoppedRestartStaysOwed(t *testing.T) {
	f := stopFixture(t)
	f.runningOther(t)
	owed := func() string {
		f.h.owedMu.Lock()
		defer f.h.owedMu.Unlock()
		return f.h.owedLocked("other")
	}
	f.h.setOwed("other", settings.EffectRestart)
	reached, release := blockStep(t, f.h, StepStart)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.h.Restart(*f.h.Template("other"))
	}()
	<-reached
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if r := f.h.LastOp("other"); r == nil || !r.Stopped() {
		t.Fatalf("record %+v", r)
	}
	if got := owed(); got != settings.EffectRestart {
		t.Fatalf("owed %q after a stopped restart, want %q", got, settings.EffectRestart)
	}
	// A failed restart leaves it owed too.
	f.h.testHookStepStart = nil
	f.runner.mu.Lock()
	f.runner.upErr = errFake("up broke")
	f.runner.mu.Unlock()
	f.h.Restart(*f.h.Template("other"))
	if r := f.h.LastOp("other"); r == nil || r.OK || owed() != settings.EffectRestart {
		t.Fatalf("failed restart: %+v owed %q", r, owed())
	}
	f.runner.mu.Lock()
	f.runner.upErr = nil
	f.runner.mu.Unlock()
	// The next start queues it again; it runs and clears it.
	f.h.requeueOwed()
	deadline := time.Now().Add(10 * time.Second)
	for owed() != "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	f.h.Wait()
	if got := owed(); got != "" {
		t.Fatalf("still owed after the re-queued restart: %q", got)
	}
	if r := f.h.LastOp("other"); r == nil || !r.OK || r.Op != OpRestart {
		t.Errorf("record %+v", r)
	}
}
