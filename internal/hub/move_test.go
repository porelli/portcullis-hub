package hub

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/state"
)

// upCount counts the primary's ups of project p.
func upCount(calls []string, p string) int {
	n := 0
	for _, c := range calls {
		if c == "up:"+p {
			n++
		}
	}
	return n
}

func workerHas(w *workerFake, prefix string) bool {
	return slices.ContainsFunc(w.Calls(), func(c string) bool { return strings.HasPrefix(c, prefix) })
}

// enabledOnPrimary: plainapp created and running on the primary.
func enabledOnPrimary(t *testing.T, p *placedFixture) {
	t.Helper()
	if err := p.create(t, "plainapp", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable("plainapp"); err != nil {
		t.Fatal(err)
	}
}

func (p *placedFixture) instance(id string) state.Instance {
	p.h.mu.RLock()
	defer p.h.mu.RUnlock()
	return p.h.st.Instances[id]
}

// TestMoveHappyPath: primary → nas: backup, restore and start on the
// worker, relays on the primary, MovedFrom kept.
func TestMoveHappyPath(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	r, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin)
	if err != nil {
		t.Fatalf("%v %+v", err, r)
	}
	in := p.instance("plainapp")
	if in.Server != "nas" || in.State != "" || in.Move != nil || in.MovedFrom == nil || in.MovedFrom.Server != "" {
		t.Errorf("state %+v", in)
	}
	if !workerHas(p.w, "create ") || !workerHas(p.w, "up ") || p.w.lastBundle() == nil {
		t.Errorf("worker %v", p.w.Calls())
	}
	if p.h.relayTokenSHA("plainapp") == "" {
		t.Error("no relay token")
	}
}

// TestMoveFailureAtEveryPhase: a failure at check, backup, restore or
// the switch before the route leaves the source running, the routing on
// the source, and no second routed copy.
func TestMoveFailureAtEveryPhase(t *testing.T) {
	for _, phase := range []string{MoveCheck, MoveBackup, MoveRestore, MoveSwitch, "restore-apply"} {
		t.Run(phase, func(t *testing.T) {
			p := newPlacedFixture(t)
			enabledOnPrimary(t, p)
			ups := upCount(p.runner.Calls(), "portcullis-plainapp")
			if phase == "restore-apply" {
				p.h.testHookApplyRestore = func(stage string) error {
					if stage == "volumes" {
						return errors.New("the target's volume create failed")
					}
					return nil
				}
			} else {
				p.h.testHookMove = func(ph string) error {
					if ph == phase {
						return errors.New("boom at " + ph)
					}
					return nil
				}
			}
			_, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin)
			if err == nil {
				t.Fatal("moved")
			}
			in := p.instance("plainapp")
			if in.Server != "" || in.State != "" || in.Move != nil || p.h.serverOf("plainapp") != "" {
				t.Errorf("routing not back on the source: %+v", in)
			}
			if phase != MoveCheck && upCount(p.runner.Calls(), "portcullis-plainapp") <= ups {
				t.Errorf("the source wasn't started again: %v", p.runner.Calls())
			}
			if workerHas(p.w, "up ") {
				t.Errorf("a second copy started on the worker: %v", p.w.Calls())
			}
		})
	}
}

// TestMoveStopMidRestore: a Stop during the restore puts everything back
// on the source and starts it.
func TestMoveStopMidRestore(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	ups := upCount(p.runner.Calls(), "portcullis-plainapp")
	p.h.testHookMove = func(ph string) error {
		if ph == MoveRestore {
			if err := p.h.cancelOp("plainapp", admin); err != nil {
				t.Error(err)
			}
		}
		return nil
	}
	_, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin)
	if !isStopErr(err) {
		t.Fatalf("%v", err)
	}
	if in := p.instance("plainapp"); in.Server != "" || in.State != "" {
		t.Errorf("state %+v", in)
	}
	if upCount(p.runner.Calls(), "portcullis-plainapp") <= ups || workerHas(p.w, "up ") {
		t.Errorf("primary %v worker %v", p.runner.Calls(), p.w.Calls())
	}
	if r := p.h.LastOp("plainapp"); r == nil || !r.Stopped() {
		t.Errorf("op %+v", r)
	}
}

// TestMoveRecoveryAfterHubRestart (Review Focus 2): a move interrupted
// before the switch routes to the source again and starts it there;
// nothing is started on the target; its half-restored volumes are left.
func TestMoveRecoveryAfterHubRestart(t *testing.T) {
	for _, phase := range []string{MoveBackup, MoveRestore, MoveSwitch} {
		t.Run(phase, func(t *testing.T) {
			p := newPlacedFixture(t)
			enabledOnPrimary(t, p)
			ups := upCount(p.runner.Calls(), "portcullis-plainapp")
			p.h.mu.Lock()
			in := p.h.st.Instances["plainapp"]
			in.State, in.Server = state.InstanceMoving, "nas"
			in.Move = &state.Move{From: "", To: "nas", Archive: "plainapp/20261115T000000Z.tar", Phase: phase, StartedAt: time.Now()}
			p.h.st.Instances["plainapp"] = in
			p.h.noteServersLocked()
			p.h.mu.Unlock()
			p.h.RecoverMoves()
			in = p.instance("plainapp")
			if in.Server != "" || in.State != "" || in.Move != nil || p.h.serverOf("plainapp") != "" {
				t.Errorf("state %+v", in)
			}
			if upCount(p.runner.Calls(), "portcullis-plainapp") <= ups {
				t.Errorf("the source isn't started: %v", p.runner.Calls())
			}
			if workerHas(p.w, "up ") {
				t.Errorf("routed to the target: %v", p.w.Calls())
			}
			if phase == MoveSwitch && !workerHas(p.w, "down ") {
				t.Errorf("the target wasn't taken down: %v", p.w.Calls())
			}
		})
	}
}

// TestMoveRefusesBoundFolders: 409 "unbind folders first; folder
// contents aren't moved", nothing done.
func TestMoveRefusesBoundFolders(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	p.h.mu.Lock()
	s := p.h.st.Settings["plainapp"]
	if s.Values == nil {
		s.Values = map[string]any{}
	}
	s.Values["media"] = "folder:photos"
	p.h.st.Settings["plainapp"] = s
	p.h.mu.Unlock()
	calls := len(p.runner.Calls())
	_, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin)
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "unbind folders first; folder contents aren't moved") {
		t.Errorf("%v", err)
	}
	if len(p.runner.Calls()) != calls || len(p.w.Calls()) != 0 {
		t.Errorf("something ran: %v %v", p.runner.Calls()[calls:], p.w.Calls())
	}
}

// TestUndoWithin7Days: an undo switches back to the source (typed id),
// stops the target; after 7 days it is 409.
func TestUndoWithin7Days(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin); err != nil {
		t.Fatal(err)
	}
	if err := p.h.UndoMove(context.Background(), "plainapp", "nope", admin); errStatus(err) != 400 {
		t.Errorf("no typed id: %v", err)
	}
	ups := upCount(p.runner.Calls(), "portcullis-plainapp")
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	// The copy it left (on nas) is now the leftover.
	if in := p.instance("plainapp"); in.Server != "" || in.MovedFrom == nil || in.MovedFrom.Server != "nas" {
		t.Errorf("state %+v", in)
	}
	if r := p.h.LastOp("plainapp"); r == nil || r.Op != OpMoveUndo || !r.OK || len(r.Steps) != 3 {
		t.Errorf("undo op %+v", r)
	}
	if !workerHas(p.w, "down ") || upCount(p.runner.Calls(), "portcullis-plainapp") <= ups {
		t.Errorf("worker %v primary %v", p.w.Calls(), p.runner.Calls())
	}
	// Moved again, 8 days ago: refused.
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin); err != nil {
		t.Fatal(err)
	}
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.MovedFrom.At = time.Now().Add(-8 * 24 * time.Hour)
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); errStatus(err) != 409 || !strings.Contains(err.Error(), "older than 7 days") {
		t.Errorf("after 8 days: %v", err)
	}
}

// TestMoveToPrimaryRemovesRelays: a worker instance moved to the primary
// has its relays down and their files gone.
func TestMoveToPrimaryRemovesRelays(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "plainapp", "nas"); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable("plainapp"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.h.relayComposePath("plainapp")); err != nil {
		t.Fatalf("no relay file: %v", err)
	}
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	if in := p.instance("plainapp"); in.Server != "" || in.MovedFrom == nil || in.MovedFrom.Server != "nas" {
		t.Errorf("state %+v", in)
	}
	for _, f := range []string{p.h.relayComposePath("plainapp"), p.h.relayEnvPath("plainapp")} {
		if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still there", f)
		}
	}
	if !slices.Contains(p.runner.Calls(), "downbyname:portcullis-plainapp") {
		t.Errorf("relays not down: %v", p.runner.Calls())
	}
}

// writeFakeArchive writes a minimal archive (its manifest only).
func writeFakeArchive(t *testing.T, h *Hub, id, reason string, at time.Time) string {
	t.Helper()
	dir := filepath.Join(h.backupsDir(), id)
	os.MkdirAll(dir, 0o700)
	name := at.UTC().Format(backupTimeFmt) + ".tar"
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := json.Marshal(BackupManifest{Version: backupVersion, Instance: id, Template: id, CreatedAt: at.UTC(), Reason: reason,
		Volumes: map[string]string{}, Files: map[string]string{"config/instance.yaml": strings.Repeat("a", 64)}})
	tw := tar.NewWriter(f)
	tw.WriteHeader(&tar.Header{Name: manifestMember, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(m))})
	tw.Write(m)
	tw.Close()
	f.Close()
	return id + "/" + name
}

// TestScheduledPruneKeepsManual: the 3 newest scheduled archives are
// kept; manual, delete, restore and move archives are never touched.
func TestScheduledPruneKeepsManual(t *testing.T) {
	f := newFixture(t)
	base := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	var sched []string
	for i := 0; i < 5; i++ {
		at := base.Add(time.Duration(i) * 24 * time.Hour)
		a := writeFakeArchive(t, f.h, "grafana", BackupScheduled, at)
		sched = append(sched, a)
		if err := f.h.listScheduled("grafana", a, at); err != nil {
			t.Fatal(err)
		}
	}
	others := []string{
		writeFakeArchive(t, f.h, "grafana", BackupManual, base.Add(-time.Hour)),
		writeFakeArchive(t, f.h, "grafana", BackupMove, base.Add(-2*time.Hour)),
		writeFakeArchive(t, f.h, "grafana", BackupDelete, base.Add(-3*time.Hour)),
		// Copied in, calling itself scheduled, old (review B2-L2): kept.
		writeFakeArchive(t, f.h, "grafana", BackupScheduled, base.Add(-48*time.Hour)),
	}
	if err := f.h.pruneScheduled("grafana"); err != nil {
		t.Fatal(err)
	}
	all, _ := f.h.ListBackups("grafana")
	var got []string
	for _, e := range all {
		got = append(got, e.Archive)
	}
	want := append(append([]string{}, sched[2:]...), others...)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("kept %v\nwant %v", got, want)
	}
}

// TestScheduleSkipsOfflineServer: at the hour, a server that isn't ready
// is skipped with an op-record note per instance; nothing runs.
func TestScheduleSkipsOfflineServer(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "plainapp", "nas"); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable("plainapp"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 3, 15, 0, 0, time.Local)
	p.h.mu.Lock()
	s := p.h.st.Servers["nas"]
	s.BackupSchedule = state.BackupSchedule{Mode: "daily", Hour: 3}
	p.h.st.Servers["nas"] = s
	p.h.mu.Unlock()
	p.h.setServer("nas", &serverRT{Name: "NAS", State: ServerOffline, RT: p.w})
	calls := len(p.w.Calls())
	p.h.backupSchedulesTick(context.Background(), now)
	r := p.h.LastOp("plainapp")
	if r == nil || r.Op != OpBackup || r.OK || !strings.Contains(r.Error, "scheduled backup skipped: server NAS is offline") {
		t.Errorf("op %+v", r)
	}
	if len(p.w.Calls()) != calls {
		t.Errorf("the offline worker got %v", p.w.Calls()[calls:])
	}
	// Not due at another hour; once per slot.
	if scheduleDue(state.BackupSchedule{Mode: "daily", Hour: 4}, now) || !scheduleDue(state.BackupSchedule{Mode: "weekly", Hour: 3, Weekday: int(now.Weekday())}, now) ||
		scheduleDue(state.BackupSchedule{Mode: "off", Hour: 3}, now) {
		t.Error("scheduleDue")
	}
}
