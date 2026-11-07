package hub

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
)

// stopFixture: template other (Keycloak client "other", groups
// users_other — created by the enable — and admin_other, which exists
// already), a volume of its project from before (kept by every Stop);
// compose's create makes the volume portcullis-other_data and the two
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
		{at: "create", groups: true, client: true, down: true},
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
