package hub

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
)

// stopFixture: template other (Keycloak client "other", groups
// users_other — created by the enable — and admin_other, which exists
// already), a volume of its project from before (kept by every Stop);
// compose's create makes the volume portcullis-other_data (its compose
// declares it) and the two
// containers, its up starts them, its down removes them.
type stopFix struct {
	*fixture
	t      *testing.T
	groups *fakeGroups
	audit  *fakeAudit
}

const keptVolume = "portcullis-other_old"
const madeVolume = "portcullis-other_data"

func stopFixture(t *testing.T) *stopFix {
	t.Helper()
	f := newFixture(t)
	m := strings.Replace(otherManifest, "  access_group: users_other\n", "  access_group: users_other\n  admin_group: admin_other\n", 1)
	writeFile(t, filepath.Join(f.src, "other", "manifest.yaml"), m)
	// Its web service keeps its data in the named volume data
	// (portcullis-other_data once compose creates it).
	writeFile(t, filepath.Join(f.src, "other", "compose.yml"), strings.Replace(otherCompose, "    image: x\n", "    image: x\n    volumes:\n      - data:/data\n", 1)+"volumes:\n  data: {}\n")
	f.h.Discover()
	if f.h.Template("other") == nil {
		t.Fatal("other not discovered")
	}
	withReadyWait(t, 5*time.Second, 5*time.Millisecond)
	g := &fakeGroups{existing: map[string]bool{"admin_other": true}}
	f.h.SetGroups(g)
	a := &fakeAudit{}
	f.h.SetAudit(a)
	proj := projectName("other")
	f.engine.addVolume(keptVolume, proj, "old", 0)
	f.runner.createHook = func(string) {
		f.engine.addVolume(madeVolume, proj, "data", 0)
		f.engine.mu.Lock()
		f.engine.containers = []docker.Container{container("w1", proj, "web", "created"), container("k1", proj, "worker", "created")}
		f.engine.mu.Unlock()
	}
	f.runner.upHook = func(string) {
		f.engine.mu.Lock()
		for i := range f.engine.containers {
			f.engine.containers[i].State = "running"
		}
		f.engine.mu.Unlock()
	}
	f.runner.onDown = func(string) {
		f.engine.mu.Lock()
		f.engine.containers = nil
		f.engine.mu.Unlock()
	}
	return &stopFix{fixture: f, t: t, groups: g, audit: a}
}

// blockAt makes the first Start of step key wait until release is
// closed; reached is closed when it got there.
func (f *stopFix) blockAt(key string) (reached, release chan struct{}) {
	reached, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release) // a failed test: never leave the operation blocked
		}
	})
	f.h.testHookStepStart = func(op, k string) {
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

func (f *stopFix) downs() int {
	n := 0
	for _, c := range f.runner.Calls() {
		if c == "down:"+projectName("other") || c == "downbyname:"+projectName("other") {
			n++
		}
	}
	return n
}

func (f *stopFix) instanceState(id string) string {
	for _, v := range f.h.Instances() {
		if v.ID == id {
			return v.State
		}
	}
	return ""
}

// nothingLeft: none of what the record says it created exists any more;
// what existed before is kept; the instance is not enabled.
func (f *stopFix) nothingLeft(t *testing.T, r OpRecord, stopper string) {
	t.Helper()
	if f.h.IsEnabled("other") {
		t.Error("enabled after a Stop")
	}
	vols := f.engine.volumeNames()
	for _, v := range r.Created.Volumes {
		if slices.Contains(vols, v) {
			t.Errorf("created volume %s still there", v)
		}
	}
	if !slices.Contains(vols, keptVolume) {
		t.Errorf("the volume from before was removed: %v", vols)
	}
	f.idp.mu.Lock()
	deleted := slices.Clone(f.idp.deleted)
	f.idp.mu.Unlock()
	for _, c := range r.Created.KeycloakClients {
		if !slices.Contains(deleted, c+":other") {
			t.Errorf("created client %s not deleted: %v", c, deleted)
		}
	}
	calls := f.groups.Calls()
	for _, g := range r.Created.Groups {
		if !slices.Contains(calls, "-"+g+":"+stopper) {
			t.Errorf("created group %s not deleted as %s: %v", g, stopper, calls)
		}
	}
	if slices.Contains(calls, "-admin_other:"+stopper) {
		t.Errorf("the group from before was deleted: %v", calls)
	}
	for _, s := range r.Steps {
		if strings.HasPrefix(s.Key, UndoPrefix) && s.State != StepDone {
			t.Errorf("undo step %s: %s", s.Key, s.State)
		}
	}
}

// TestStopEnableAtEveryStep: a Stop at any step of an enable undoes
// exactly what it created — containers (compose down), the volumes,
// Keycloak client and groups of its ledger — keeping what existed
// before; the record ends stopped (ok false, no error), the instance
// not enabled and not in state error.
func TestStopEnableAtEveryStep(t *testing.T) {
	for _, c := range []struct {
		at                  string
		groups, client, vol bool
		down                bool
	}{
		{at: "groups"},
		{at: "keycloak", groups: true},
		{at: "images", groups: true, client: true},
		{at: "create", groups: true, client: true, vol: true, down: true},
		{at: "start", groups: true, client: true, vol: true, down: true},
		{at: "healthy", groups: true, client: true, vol: true, down: true},
		{at: "settings", groups: true, client: true, vol: true, down: true},
	} {
		t.Run(c.at, func(t *testing.T) {
			f := stopFixture(t)
			reached, release := f.blockAt(c.at)
			a, err := f.h.StartEnable("other", directory.Human("alice"))
			if err != nil {
				t.Fatal(err)
			}
			<-reached
			rec, err := f.h.StopOp("other", directory.Human("bob"))
			if err != nil || rec == nil || !rec.Running || !rec.Stopping || rec.StoppedBy != "bob" {
				t.Fatalf("stop: %+v %v", rec, err)
			}
			close(release)
			r := waitOp(t, f.h, "other", a.OpID)
			if !r.Stopped() || r.OK || r.Error != "" || r.Stoppable || r.Actor != "alice" || r.StoppedBy != "bob" {
				t.Fatalf("record: %+v", r)
			}
			if s := stepOf(r, c.at).State; s != StepStopped && s != StepUndone {
				t.Errorf("step %s: %s", c.at, s)
			}
			if got := len(r.Created.Groups) > 0; got != c.groups || (got && !slices.Equal(r.Created.Groups, []string{"users_other"})) {
				t.Errorf("created groups: %v", r.Created.Groups)
			}
			if got := len(r.Created.KeycloakClients) > 0; got != c.client {
				t.Errorf("created clients: %v", r.Created.KeycloakClients)
			}
			if got := slices.Equal(r.Created.Volumes, []string{madeVolume}); got != c.vol {
				t.Errorf("created volumes: %v", r.Created.Volumes)
			}
			if (f.downs() > 0) != c.down || (c.down && stepOf(r, "undo:down").State != StepDone) {
				t.Errorf("downs %d, undo:down %+v", f.downs(), stepOf(r, "undo:down"))
			}
			if c.groups && (stepOf(r, "groups").State != StepUndone || stepOf(r, "undo:groups").State != StepDone) {
				t.Errorf("groups %+v undo %+v", stepOf(r, "groups"), stepOf(r, "undo:groups"))
			}
			if c.client && stepOf(r, "keycloak").State != StepUndone {
				t.Errorf("keycloak %+v", stepOf(r, "keycloak"))
			}
			if stepOf(r, "images").State == StepUndone {
				t.Error("images undone: downloaded images are kept")
			}
			f.nothingLeft(t, r, "bob")
			if st := f.instanceState("other"); st == StateError || st == "" {
				t.Errorf("instance state %q", st)
			}
			if fo := f.h.FailedOps(); len(fo) != 0 {
				t.Errorf("failed ops: %v", fo)
			}
		})
	}
}

// TestStopEnableUndoFailsThenRetries: an undo step that fails leaves the
// record failed and stoppable with that step failed (instance state
// error); Stop again runs only the undo steps not done yet.
func TestStopEnableUndoFailsThenRetries(t *testing.T) {
	f := stopFixture(t)
	reached, release := f.blockAt("healthy")
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	f.idp.mu.Lock()
	f.idp.deleteErr = errors.New("keycloak is down")
	f.idp.mu.Unlock()
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	close(release)
	r := waitOp(t, f.h, "other", a.OpID)
	if r.OK || r.Stopped() || !r.Failed() || !r.Stoppable || r.Stopping || !strings.Contains(r.Error, "keycloak is down") {
		t.Fatalf("undo failed: %+v", r)
	}
	if stepOf(r, "undo:down").State != StepDone || stepOf(r, "undo:volumes").State != StepDone || stepOf(r, "undo:keycloak").State != StepFailed {
		t.Fatalf("steps: %+v", r.Steps)
	}
	if s := stepOf(r, "undo:groups").State; s == StepDone {
		t.Fatalf("undo:groups ran after a failed step: %s", s)
	}
	if st := f.instanceState("other"); st != StateError {
		t.Errorf("state %q, want error", st)
	}
	downs := f.downs()
	f.idp.mu.Lock()
	f.idp.deleteErr = nil
	f.idp.mu.Unlock()
	rec, err := f.h.StopOp("other", directory.Human("carol"))
	if err != nil || rec == nil || !rec.Stopping || !rec.Running || rec.StoppedBy != "carol" {
		t.Fatalf("stop again: %+v %v", rec, err)
	}
	r = waitOp(t, f.h, "other", a.OpID)
	if !r.Stopped() || r.Error != "" || r.Stoppable {
		t.Fatalf("retried: %+v", r)
	}
	if f.downs() != downs {
		t.Errorf("compose down ran again (%d → %d)", downs, f.downs())
	}
	f.nothingLeft(t, r, "carol")
	if st := f.instanceState("other"); st == StateError {
		t.Error("still in state error")
	}
	if _, err := f.h.StopOp("other", directory.Human("carol")); statusOf(err) != 409 {
		t.Fatalf("stop after the end: %v", err)
	}
}

// TestStopInterruptedEnable: an enable the Hub stopped in the middle
// (its record running at load: interrupted) is undone from its ledger
// by a Stop, in the background, as the stopping admin.
func TestStopInterruptedEnable(t *testing.T) {
	f := stopFixture(t)
	f.groups.set(func(g *fakeGroups) { g.existing["users_other"] = true })
	proj := projectName("other")
	f.engine.addVolume(madeVolume, proj, "data", 0)
	f.engine.containers = []docker.Container{container("w1", proj, "web", "running")}
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	done := func(k string) Step { return Step{Key: k, Label: k, State: StepDone, StartedAt: &t0, EndedAt: &t0} }
	f.h.recordOp("other", OpRecord{Op: OpEnable, OpID: "crashed1", At: t0, Running: true, Actor: "alice", Stoppable: true,
		Steps: []Step{done("groups"), done("keycloak"), done("images"), done("create"), {Key: "start", Label: "start", State: StepRunning, StartedAt: &t0},
			{Key: "healthy", Label: "healthy", State: StepWaiting}, {Key: "settings", Label: "settings", State: StepWaiting}},
		Created: &Created{Groups: []string{"users_other"}, KeycloakClients: []string{"other"}, Volumes: []string{madeVolume}}})
	f.h.loadOps()
	if r := f.h.LastOp("other"); r == nil || !r.Interrupted || !r.Stoppable {
		t.Fatalf("not interrupted: %+v", r)
	}
	rec, err := f.h.StopOp("other", directory.Human("bob"))
	if err != nil || rec == nil || !rec.Running || !rec.Stopping || rec.OpID != "crashed1" || rec.StoppedBy != "bob" {
		t.Fatalf("stop: %+v %v", rec, err)
	}
	r := waitOp(t, f.h, "other", "crashed1")
	if !r.Stopped() || r.Interrupted || r.Error != "" {
		t.Fatalf("record: %+v", r)
	}
	if f.downs() == 0 {
		t.Error("no compose down")
	}
	if stepOf(r, "start").State != StepUndone || stepOf(r, "images").State != StepDone || stepOf(r, "create").State != StepUndone || stepOf(r, "groups").State != StepUndone {
		t.Errorf("steps: %+v", r.Steps)
	}
	f.nothingLeft(t, r, "bob")
	if f.h.appBusy("other") {
		t.Error("lock still held")
	}
}

// TestEnableSecondRequest409: while an enable runs, another enable (or
// the synchronous EnableAs) is refused 409 with the running record.
func TestEnableSecondRequest409(t *testing.T) {
	f := stopFixture(t)
	reached, release := f.blockAt("images")
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	for _, try := range []func() error{
		func() error { _, err := f.h.StartEnable("other", directory.Human("bob")); return err },
		func() error { _, err := f.h.EnableAs("other", directory.Human("bob")); return err },
	} {
		err := try()
		var be *BusyError
		if !errors.As(err, &be) || errStatus(err) != 409 || be.Record == nil || !be.Record.Running || be.Record.OpID != a.OpID || be.Record.Actor != "alice" || len(be.Record.Steps) == 0 {
			t.Fatalf("second request: %v %+v", err, be)
		}
	}
	if _, err := f.h.StartEnable("nope", directory.Human("bob")); statusOf(err) != 404 {
		t.Fatalf("unknown instance: %v", err)
	}
	close(release)
	r := waitOp(t, f.h, "other", a.OpID)
	if !r.OK || !f.h.IsEnabled("other") {
		t.Fatalf("enable: %+v", r)
	}
	for _, k := range []string{"groups", "keycloak", "images", "create", "start", "healthy", "settings"} {
		if stepOf(r, k).State != StepDone {
			t.Errorf("step %s: %+v", k, stepOf(r, k))
		}
	}
	if !slices.Equal(r.Created.Groups, []string{"users_other"}) || !slices.Equal(r.Created.KeycloakClients, []string{"other"}) || !slices.Equal(r.Created.Volumes, []string{madeVolume}) {
		t.Errorf("created: %+v", r.Created)
	}
}

// TestStopAudited: every Stop is audited <op>.stop — detail the running
// step, actor the stopping admin with via / client — ok when accepted,
// refused (409 with the record) when already stopping or nothing runs;
// 404 without a record.
func TestStopAudited(t *testing.T) {
	f := stopFixture(t)
	reached, release := f.blockAt("images")
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	ai := directory.Actor{User: "bob", Via: "ai", Client: "claude-code"}
	if _, err := f.h.StopOp("other", ai); err != nil {
		t.Fatal(err)
	}
	e := f.audit.last()
	if e.Action != "enable.stop" || e.Target != "other" || !strings.Contains(e.Detail, "images") || e.Actor != "bob" || e.Via != "ai" || e.Client != "claude-code" || e.Result != "ok" {
		t.Fatalf("audit: %+v", e)
	}
	rec, err := f.h.StopOp("other", directory.Human("carol"))
	if statusOf(err) != 409 || rec == nil || !rec.Stopping {
		t.Fatalf("second stop: %+v %v", rec, err)
	}
	if e := f.audit.last(); e.Action != "enable.stop" || e.Result != "refused" || e.Actor != "carol" {
		t.Fatalf("refused audit: %+v", e)
	}
	close(release)
	waitOp(t, f.h, "other", a.OpID)
	rec, err = f.h.StopOp("other", directory.Human("carol"))
	if statusOf(err) != 409 || rec == nil || rec.Running {
		t.Fatalf("stop after the end: %+v %v", rec, err)
	}
	if e := f.audit.last(); e.Result != "refused" {
		t.Fatalf("audit: %+v", e)
	}
	if _, err := f.h.StopOp("grafana", directory.Human("carol")); statusOf(err) != 404 {
		t.Fatalf("no record: %v", err)
	}
	if _, err := f.h.StopOp("nope", directory.Human("carol")); statusOf(err) != 404 {
		t.Fatalf("unknown: %v", err)
	}
	f.groups.set(func(g *fakeGroups) { g.actorErr = errors.New("not an administrator") })
	if _, err := f.h.StopOp("other", directory.Human("dana")); err == nil || statusOf(err) == 409 {
		t.Fatalf("a non-admin: %v", err)
	}
}

// TestStopEnableKeepsExistingClient: a Keycloak client that existed
// before the enable is not in its ledger and survives the Stop.
func TestStopEnableKeepsExistingClient(t *testing.T) {
	f := stopFixture(t)
	f.idp.mu.Lock()
	f.idp.clients = map[string]bool{"other": true}
	f.idp.mu.Unlock()
	reached, release := f.blockAt("start")
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	close(release)
	r := waitOp(t, f.h, "other", a.OpID)
	if !r.Stopped() || len(r.Created.KeycloakClients) != 0 {
		t.Fatalf("record: %+v", r)
	}
	f.idp.mu.Lock()
	defer f.idp.mu.Unlock()
	if len(f.idp.deleted) != 0 {
		t.Errorf("deleted %v", f.idp.deleted)
	}
}

// enableStopped starts an enable of other blocked at step key, stops it
// as bob, releases it and returns the final record.
func (f *stopFix) enableStopped(t *testing.T, key string) OpRecord {
	t.Helper()
	reached, release := f.blockAt(key)
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	close(release)
	return waitOp(t, f.h, "other", a.OpID)
}

// TestStopRacesCommit (I1): a Stop accepted right before the commit
// gate is undone (never committed); one right after it is refused
// "finishing" and the enable completes.
func TestStopRacesCommit(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			f := stopFixture(t)
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			f.h.testHookCommit = func(id, s string) {
				if s == stage {
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
			a, err := f.h.StartEnable("other", directory.Human("alice"))
			if err != nil {
				t.Fatal(err)
			}
			<-reached
			rec, err := f.h.StopOp("other", directory.Human("bob"))
			if stage == "before" {
				if err != nil || !rec.Stopping {
					t.Fatalf("stop: %+v %v", rec, err)
				}
			} else if statusOf(err) != 409 || !strings.Contains(err.Error(), "finishing") || rec == nil || !rec.Running || rec.Stoppable {
				t.Fatalf("stop after the gate: %+v %v", rec, err)
			}
			close(release)
			r := waitOp(t, f.h, "other", a.OpID)
			if stage == "before" {
				if !r.Stopped() {
					t.Fatalf("record: %+v", r)
				}
				f.nothingLeft(t, r, "bob")
				return
			}
			if !r.OK || r.Stopping || r.StoppedBy != "" || !f.h.IsEnabled("other") {
				t.Fatalf("finished: %+v enabled=%v", r, f.h.IsEnabled("other"))
			}
		})
	}
}

// undoFailed leaves other with an enable whose undo failed at
// undo:keycloak (Keycloak refused the delete), then lets Keycloak work.
func (f *stopFix) undoFailed(t *testing.T) OpRecord {
	t.Helper()
	f.idp.mu.Lock()
	f.idp.deleteErr = errors.New("keycloak is down")
	f.idp.mu.Unlock()
	r := f.enableStopped(t, "healthy")
	if !r.Stoppable || stepOf(r, "undo:keycloak").State != StepFailed {
		t.Fatalf("undo did not fail: %+v", r)
	}
	f.idp.mu.Lock()
	f.idp.deleteErr = nil
	f.idp.mu.Unlock()
	return r
}

// holdResume blocks the first resumeStop before it takes the lock;
// reached is closed when it got there.
func (f *stopFix) holdResume() (reached, release chan struct{}) {
	reached, release = make(chan struct{}), make(chan struct{})
	// The first caller only (a sync.Once would block the others too).
	var first atomic.Bool
	f.h.testHookResume = func(string) {
		if first.CompareAndSwap(false, true) {
			close(reached)
			<-release
		}
	}
	f.t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	return reached, release
}

// TestStopResumeConcurrent (I3): two Stops of one undo-failed record:
// exactly one is accepted and the undo runs once.
func TestStopResumeConcurrent(t *testing.T) {
	f := stopFixture(t)
	r := f.undoFailed(t)
	reached, release := f.holdResume()
	type answer struct {
		rec *OpRecord
		err error
	}
	first := make(chan answer, 1)
	go func() {
		rec, err := f.h.StopOp("other", directory.Human("carol"))
		first <- answer{rec, err}
	}()
	<-reached
	rec, err := f.h.StopOp("other", directory.Human("dave"))
	if err != nil || !rec.Stopping {
		t.Fatalf("second stop: %+v %v", rec, err)
	}
	end := waitOp(t, f.h, "other", r.OpID)
	if !end.Stopped() || end.StoppedBy != "dave" {
		t.Fatalf("record: %+v", end)
	}
	close(release)
	a := <-first
	if statusOf(a.err) != 409 || a.rec == nil || a.rec.Running {
		t.Fatalf("the stale stop: %+v %v", a.rec, a.err)
	}
	f.idp.mu.Lock()
	deleted := slices.Clone(f.idp.deleted)
	f.idp.mu.Unlock()
	if len(deleted) != 1 {
		t.Errorf("client deleted %d times: %v", len(deleted), deleted)
	}
	if n := strings.Count(strings.Join(f.groups.Calls(), ","), "-users_other:"); n != 1 {
		t.Errorf("group deleted %d times: %v", n, f.groups.Calls())
	}
}

// TestStopResumeStale (I3): a Stop that read an undo-failed record, then
// waited while another enable ran, is refused: it never undoes the new
// enable.
func TestStopResumeStale(t *testing.T) {
	f := stopFixture(t)
	f.undoFailed(t)
	reached, release := f.holdResume()
	first := make(chan error, 1)
	go func() {
		_, err := f.h.StopOp("other", directory.Human("carol"))
		first <- err
	}()
	<-reached
	f.h.testHookStepStart = nil
	if _, err := f.h.EnableAs("other", directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	downs := f.downs()
	close(release)
	if err := <-first; statusOf(err) != 409 || !strings.Contains(err.Error(), "changed meanwhile") {
		t.Fatalf("the stale stop: %v", err)
	}
	f.h.Wait()
	if !f.h.IsEnabled("other") || f.downs() != downs {
		t.Fatalf("the new enable was undone: enabled=%v downs %d→%d", f.h.IsEnabled("other"), downs, f.downs())
	}
	if r := f.h.LastOp("other"); r == nil || !r.OK || r.Stopping {
		t.Fatalf("record: %+v", r)
	}
}

// TestStopMidRegisterClient (M3): a Stop while Keycloak creates the
// client: the client it made is in the ledger and deleted.
func TestStopMidRegisterClient(t *testing.T) {
	f := stopFixture(t)
	reached, release := make(chan struct{}), make(chan struct{})
	f.idp.mu.Lock()
	f.idp.registerHook = func(string) { close(reached); <-release }
	f.idp.mu.Unlock()
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	close(release)
	r := waitOp(t, f.h, "other", a.OpID)
	if !r.Stopped() || !slices.Equal(r.Created.KeycloakClients, []string{"other"}) || stepOf(r, "keycloak").State != StepUndone {
		t.Fatalf("record: %+v", r)
	}
	if f.downs() != 0 {
		t.Error("compose ran")
	}
	f.nothingLeft(t, r, "bob")
}

// TestStopKillsCreate (M3, I2): the declared volume is in the ledger
// before compose create runs; a create killed after it made it and an
// undeclared one leaves both in the ledger, and the undo removes both.
func TestStopKillsCreate(t *testing.T) {
	f := stopFixture(t)
	const extra = "portcullis-other_extra"
	reached, release := make(chan struct{}), make(chan struct{})
	f.runner.createHook = func(string) {
		proj := projectName("other")
		f.engine.addVolume(madeVolume, proj, "data", 0)
		f.engine.addVolume(extra, proj, "extra", 0)
		f.engine.mu.Lock()
		f.engine.containers = []docker.Container{container("w1", proj, "web", "created")}
		f.engine.mu.Unlock()
		close(reached)
		<-release
	}
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if r := f.h.LastOp("other"); r == nil || !slices.Equal(r.Created.Volumes, []string{madeVolume}) {
		t.Fatalf("expected volume not in the ledger before the create: %+v", r.Created)
	}
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	close(release)
	r := waitOp(t, f.h, "other", a.OpID)
	if !r.Stopped() || !slices.Equal(r.Created.Volumes, []string{madeVolume, extra}) || f.downs() == 0 {
		t.Fatalf("record: %+v downs %d", r, f.downs())
	}
	f.nothingLeft(t, r, "bob")
	if slices.Contains(f.engine.volumeNames(), extra) {
		t.Error("the undeclared volume is still there")
	}
}

// TestStopGroupKeptUnavailable (M1): a group Users & Groups kept because
// it didn't answer is a failed undo:groups (retried by Stop again); one
// kept because it is protected is done, with the warning.
func TestStopGroupKeptUnavailable(t *testing.T) {
	f := stopFixture(t)
	f.groups.set(func(g *fakeGroups) {
		g.delWarn = func(name string) string {
			return "group " + name + " was kept: users & groups is not available (down) — delete it on the Users & Groups page"
		}
	})
	r := f.enableStopped(t, "images")
	if !r.Stoppable || r.Stopped() || stepOf(r, "undo:groups").State != StepFailed || !strings.Contains(r.Error, "not available") {
		t.Fatalf("unavailable: %+v", r)
	}
	f.groups.set(func(g *fakeGroups) {
		g.delWarn = func(name string) string { return "group " + name + " was kept: a built-in group" }
	})
	if _, err := f.h.StopOp("other", directory.Human("bob")); err != nil {
		t.Fatal(err)
	}
	r = waitOp(t, f.h, "other", r.OpID)
	if !r.Stopped() || stepOf(r, "undo:groups").State != StepDone || !slices.ContainsFunc(r.Warnings, func(w string) bool { return strings.Contains(w, "built-in") }) {
		t.Fatalf("protected: %+v", r)
	}
}

// TestStartIdleWhileStopping (M4): while a Stop's undo runs, a waiting
// forward step never starts; the undo's steps do.
func TestStartIdleWhileStopping(t *testing.T) {
	f := newFixture(t)
	p := f.h.newProgress("grafana", OpEnable, enableSteps())
	p.begin("op1", "alice", nil)
	p.mu.Lock()
	p.rec.Stopping = true
	p.mu.Unlock()
	p.Start("images")
	p.AddStep("undo:down", "")
	p.Start("undo:down")
	r := p.snapshot()
	if stepOf(r, "images").State != StepWaiting || stepOf(r, "undo:down").State != StepRunning {
		t.Fatalf("steps: %+v", r.Steps)
	}
}

// TestStopEnableAIClient (ruling 6a): an AI page's ai_client the enable
// created is in its ledger and deleted (owner-tagged) by the Stop, with
// the ordinary client.
func TestStopEnableAIClient(t *testing.T) {
	kc, c := hubAIRealm(t)
	a := chatFixture23(t, nil)
	a.h.SetAIKeycloak(c)
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	a.h.testHookStepStart = func(op, k string) {
		if k == StepImages {
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
	op, err := a.h.StartEnable("ai-chat", root)
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if kc.ClientByClientID(chatMCPID) == nil {
		t.Fatal("ai_client not created")
	}
	if _, err := a.h.StopOp("ai-chat", root); err != nil {
		t.Fatal(err)
	}
	close(release)
	r := waitOp(t, a.h, "ai-chat", op.OpID)
	if !r.Stopped() || !slices.Contains(r.Created.KeycloakClients, chatMCPID) || !slices.Contains(r.Created.KeycloakClients, "ai-chat") {
		t.Fatalf("record: %+v", r)
	}
	if kc.ClientByClientID(chatMCPID) != nil {
		t.Error("the ai_client is still there")
	}
	a.idp.mu.Lock()
	defer a.idp.mu.Unlock()
	if !slices.Contains(a.idp.deleted, "ai-chat:ai-chat") {
		t.Errorf("the ordinary client not deleted: %v", a.idp.deleted)
	}
}

// TestStartHookFailureAsyncEnable (ruling 6b): a start hook that fails
// during a background enable is still the instance's record once the
// enable ended (op hook, state error), as for a synchronous one.
func TestStartHookFailureAsyncEnable(t *testing.T) {
	f, _, _ := hookFixture(t)
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("no\n"), ExitCode: 2, ExecID: "e2"}, nil
	})
	if _, err := f.h.StartEnable(hookID, directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if !f.h.IsEnabled(hookID) {
		t.Fatal("not enabled")
	}
	op := f.h.LastOp(hookID)
	if op == nil || op.Op != OpHook || op.OK || !strings.HasPrefix(op.Error, "hook ") {
		t.Fatalf("op record = %+v", op)
	}
	if fo := f.h.FailedOps(); fo[hookID] != OpHook {
		t.Errorf("failed ops = %v", fo)
	}
}

// TestStopOpExpect (Task 7 security review): a Stop meant for one
// operation never lands on another — refused 409 ErrOpChanged with the
// current record, nothing stopped, audited refused; the right op id stops
// it. "" is any (the HTTP route).
func TestStopOpExpect(t *testing.T) {
	f := stopFixture(t)
	reached, release := f.blockAt("images")
	a, err := f.h.StartEnable("other", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	rec, err := f.h.StopOpExpect("other", directory.Human("bob"), "0123456789abcdef")
	if !errors.Is(err, ErrOpChanged) || errStatus(err) != 409 || rec == nil || rec.OpID != a.OpID {
		t.Fatalf("another op id: %v %+v", err, rec)
	}
	// Under p.mu too (the record read first, then another run's).
	if err := f.h.cancelOpExpect("other", directory.Human("bob"), "0123456789abcdef"); !errors.Is(err, ErrOpChanged) {
		t.Fatalf("cancelOpExpect: %v", err)
	}
	if r := f.h.LastOp("other"); !r.Running || r.Stopping {
		t.Fatalf("stopped by a refused Stop: %+v", r)
	}
	if e := f.audit.lastOf("enable.stop"); e.Result != "refused" || e.Actor != "bob" {
		t.Errorf("audit %+v", e)
	}
	rec, err = f.h.StopOpExpect("other", directory.Human("bob"), a.OpID)
	if err != nil || !rec.Stopping {
		t.Fatalf("the right op id: %v %+v", err, rec)
	}
	close(release)
	if r := waitOp(t, f.h, "other", a.OpID); r.OK || r.StoppedBy != "bob" {
		t.Fatalf("record %+v", r)
	}
}
