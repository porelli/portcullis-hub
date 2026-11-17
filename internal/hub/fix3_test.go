package hub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
)

func placedEnabled(t *testing.T, p *placedFixture, id string) {
	t.Helper()
	if err := p.create(t, id, "nas"); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable(id); err != nil {
		t.Fatal(err)
	}
}

// TestPlacementRecheckedAtEnable (review B2-H1): a template update that
// makes a placed instance primary-only (an AI page: provider secrets)
// refuses the next start — no bundle, no env reaches the worker — stops
// it there and shows server_placement_invalid.
func TestPlacementRecheckedAtEnable(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	bundles := len(p.w.bundles)
	chat := readFixture(t, filepath.Join("testdata", "ai", "chatapp"))
	writeFile(t, filepath.Join(p.src, "plainapp", "manifest.yaml"), chat[0])
	writeFile(t, filepath.Join(p.src, "plainapp", "compose.yml"), chat[1])
	p.h.Discover()
	if v := p.h.Template("plainapp"); v == nil || v.Manifest.AI == nil || v.Manifest.AI.Chat == nil {
		t.Fatal("the updated template isn't an AI page")
	}
	err := p.h.RestartApp("plainapp")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "can't run on a worker any more") {
		t.Fatalf("restart: %v", err)
	}
	if len(p.w.bundles) != bundles {
		t.Errorf("a bundle (its env) reached the worker")
	}
	if !workerHas(p.w, "down ") {
		t.Errorf("not stopped on the worker: %v", p.w.Calls())
	}
	if in := p.h.serversDoctorIn(); in == nil || in.PlacementInvalid["plainapp"] == "" {
		t.Errorf("doctor %+v", in)
	}
	// Every push re-checks too.
	if err := p.h.pushBundle(context.Background(), "plainapp", p.w); errStatus(err) != 409 {
		t.Errorf("push: %v", err)
	}
}

// TestNarrowingWhileWorkerOffline (review B2-H2): the relays follow the
// Hub's desired labels before (and whether or not) the worker answers;
// a relay that can't be updated is stopped.
func TestNarrowingWhileWorkerOffline(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	// The template narrows: another middleware on its router.
	compose := strings.Replace(mustReadS(t, filepath.Join(p.src, "plainapp", "compose.yml")),
		"      traefik.http.services.plain.", "      traefik.http.routers.plain-narrow.rule: Host(`${PORTCULLIS_HOST_PLAIN:-plain.portcullis.local}`) && PathPrefix(`/narrow`)\n      traefik.http.services.plain.", 1)
	writeFile(t, filepath.Join(p.src, "plainapp", "compose.yml"), compose)
	p.h.Discover()
	p.h.setServer("nas", &serverRT{Name: "NAS", State: ServerOffline, RT: p.w})
	v := p.h.Template("plainapp")
	if v == nil {
		t.Fatal("the narrowed template didn't load")
	}
	err := p.h.composeUp(context.Background(), v)
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("up: %v", err)
	}
	relay, _ := os.ReadFile(p.h.relayComposePath("plainapp"))
	if !strings.Contains(string(relay), "/narrow") {
		t.Errorf("the relay wasn't updated while the worker is offline:\n%s", relay)
	}
	// The relay can't be updated: it is stopped.
	p.h.cfg.RelayImage = ""
	before := len(p.runner.Calls())
	if err := p.h.composeUp(context.Background(), v); err == nil {
		t.Fatal("up without a relay image")
	}
	if !slices.Contains(p.runner.Calls()[before:], "downbyname:portcullis-plainapp") {
		t.Errorf("relay not stopped: %v", p.runner.Calls()[before:])
	}
}

func mustReadS(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRelayExposureDrift (review B2-H2): reconcile compares the relays'
// labels (what Traefik routes) with the desired ones: a dropped
// middleware is public_access drift.
func TestRelayExposureDrift(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	_, relays := relayCheck(t, p.h, "plainapp")
	labels := map[string]string{}
	for k, v := range relays["web"] {
		labels[k] = v
	}
	labels[docker.LabelProject], labels[docker.LabelService] = "portcullis-plainapp", "web"
	// The worker runs it (its state is the worker's).
	p.w.Lock()
	p.w.Units = []runtime.Unit{{ID: "w-1", Project: "portcullis-plainapp", Instance: "plainapp", Service: "web", State: "running"}}
	p.w.Unlock()
	set := func(l map[string]string) {
		p.engine.mu.Lock()
		p.engine.containers = []docker.Container{{ID: "relay-1", State: "running", Labels: l}}
		p.engine.mu.Unlock()
	}
	has := func() bool {
		for _, d := range p.h.Reconcile(context.Background()).Items {
			if d.ID == "plainapp" && d.Kind == DriftPublicAccess {
				return true
			}
		}
		return false
	}
	set(labels)
	if has() {
		t.Fatal("drift on a relay carrying the desired labels")
	}
	bad := map[string]string{}
	dropped := ""
	for k, v := range labels {
		if strings.HasSuffix(k, ".tls.options") && dropped == "" {
			dropped = k
			continue
		}
		bad[k] = v
	}
	if dropped == "" {
		t.Fatalf("no tls.options label on the relay: %v", labels)
	}
	set(bad)
	if !has() {
		t.Errorf("no public_access drift for a relay without %s", dropped)
	}
}

// TestQuarantinedInstanceRefused (review A2-M1): the agent's quarantine
// (/v1/info) refuses starts and pushes, shows the doctor problem, and
// only LiftQuarantine (audited) ends it.
func TestQuarantinedInstanceRefused(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.w.mu.Lock()
	p.w.info.Quarantined = map[string]string{"plainapp": "a symlink in a bind source"}
	p.w.mu.Unlock()
	p.h.refreshServerFacts(context.Background(), "nas")
	bundles := len(p.w.bundles)
	if err := p.h.RestartApp("plainapp"); errStatus(err) != 409 || !strings.Contains(err.Error(), "quarantined") {
		t.Errorf("restart: %v", err)
	}
	if len(p.w.bundles) != bundles {
		t.Error("a bundle was pushed to a quarantined instance")
	}
	if in := p.h.serversDoctorIn(); in == nil || !strings.Contains(in.Quarantined["plainapp"], "symlink") {
		t.Errorf("doctor %+v", in)
	}
	if err := p.h.LiftQuarantine(context.Background(), admin, "plainapp"); err != nil {
		t.Fatal(err)
	}
	if !workerHas(p.w, "signal unquarantine plainapp") {
		t.Errorf("worker %v", p.w.Calls())
	}
	if err := p.h.RestartApp("plainapp"); err != nil {
		t.Errorf("restart after the lift: %v", err)
	}
}

// TestMoveRecoveryHoldsLock (review B2-M1): while an instance is moving,
// starts other than its move or recovery are refused; recovery takes the
// target down from the restore on.
func TestMoveRecoveryHoldsLock(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.State, in.Server = state.InstanceMoving, "nas"
	in.Move = &state.Move{From: "", To: "nas", Phase: MoveRestore, StartedAt: time.Now()}
	p.h.st.Instances["plainapp"] = in
	p.h.noteServersLocked()
	p.h.mu.Unlock()
	if err := p.h.Enable("plainapp"); errStatus(err) != 409 || !strings.Contains(err.Error(), "being moved") {
		t.Errorf("enable while moving: %v", err)
	}
	if err := p.h.composeUp(context.Background(), p.h.Template("plainapp")); errStatus(err) != 409 {
		t.Errorf("a queued start while moving: %v", err)
	}
	if workerHas(p.w, "up ") {
		t.Fatal("the half-restored target started")
	}
	p.h.RecoverMoves()
	if !workerHas(p.w, "down ") {
		t.Errorf("the target wasn't taken down at the restore phase: %v", p.w.Calls())
	}
	if in := p.instance("plainapp"); in.State != "" || in.Server != "" {
		t.Errorf("state %+v", in)
	}
}

// TestMoveStuckWhenTargetDownFails (review B2-M2): the target can't be
// taken down after a failed start → the source isn't started (routed
// to neither), doctor server_move_stuck, retried until it works.
func TestMoveStuckWhenTargetDownFails(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	ups := upCount(p.runner.Calls(), "portcullis-plainapp")
	p.h.testHookMove = func(ph string) error {
		if ph == MoveSwitch {
			p.w.Fake.Err = errors.New("the worker is gone")
			return errors.New("the start failed")
		}
		return nil
	}
	_, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin)
	if err == nil || !strings.Contains(err.Error(), "runs nowhere") {
		t.Fatalf("%v", err)
	}
	in := p.instance("plainapp")
	if in.State != state.InstanceMoving || in.Move == nil || in.Move.Phase != MoveStuck {
		t.Errorf("state %+v", in)
	}
	if upCount(p.runner.Calls(), "portcullis-plainapp") != ups {
		t.Errorf("the source started with the target maybe up: %v", p.runner.Calls())
	}
	if d := p.h.serversDoctorIn(); d == nil || d.Stuck["plainapp"] == "" {
		t.Errorf("doctor %+v", d)
	}
	// The worker answers again: the next tick settles it.
	p.w.Fake.Err = nil
	p.h.testHookMove = nil
	p.h.serversTick(context.Background())
	if in := p.instance("plainapp"); in.State != "" || in.Server != "" {
		t.Errorf("after the retry %+v", in)
	}
	if upCount(p.runner.Calls(), "portcullis-plainapp") <= ups {
		t.Error("the source wasn't started after the retry")
	}
}

// TestBundlesRemoved (review B2-M4): a placed delete and a finished move
// off a worker remove the worker's bundle.
func TestBundlesRemoved(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	if !workerHas(p.w, "signal remove-project plainapp") {
		t.Errorf("move: bundle not removed: %v", p.w.Calls())
	}
	q := newPlacedFixture(t)
	placedEnabled(t, q, "plainapp")
	if _, err := q.h.DeleteInstance("plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	if !workerHas(q.w, "signal remove-project plainapp") {
		t.Errorf("delete: bundle not removed: %v", q.w.Calls())
	}
}

// TestRelayTokenRevokedOnSwitch (review B2-M5): link.json follows token
// changes: after a move to the primary the relay is gone from it.
func TestRelayTokenRevokedOnSwitch(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	tok := p.h.relayTokenSHA("plainapp")
	if !linkHasRelay(t, p, tok) {
		t.Fatal("the relay isn't in link.json")
	}
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	if linkHasRelay(t, p, tok) {
		t.Error("the old token is still in link.json")
	}
}

func linkHasRelay(t *testing.T, p *placedFixture, sum string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p.h.cfg.LinkDocDir, "link.json"))
	if err != nil {
		t.Fatal(err)
	}
	return sum != "" && strings.Contains(string(b), sum)
}

// TestMoveLeftoverOnlyRecordedVolumes (review B2-L1): only the volumes
// pinned at move time are removed; a leftover on the current server is
// refused.
func TestMoveLeftoverOnlyRecordedVolumes(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.w.Lock()
	p.w.Volumes["portcullis-plainapp_data"] = runtimeVolume("portcullis-plainapp_data", "portcullis-plainapp")
	p.w.Volumes["portcullis-plainapp_extra"] = runtimeVolume("portcullis-plainapp_extra", "portcullis-plainapp")
	p.w.Unlock()
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.Server, in.MovedFrom = "", &state.MovedFrom{Server: "nas", At: time.Now(), Volumes: []string{"portcullis-plainapp_data"}}
	p.h.st.Instances["plainapp"] = in
	p.h.noteServersLocked()
	p.h.mu.Unlock()
	if err := p.h.RemoveMoveLeftover(context.Background(), "plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	p.w.Lock()
	_, data := p.w.Volumes["portcullis-plainapp_data"]
	_, extra := p.w.Volumes["portcullis-plainapp_extra"]
	p.w.Unlock()
	if data || !extra {
		t.Errorf("data removed %v, extra kept %v", !data, extra)
	}
	p.h.mu.Lock()
	in = p.h.st.Instances["plainapp"]
	in.Server, in.MovedFrom = "nas", &state.MovedFrom{Server: "nas", At: time.Now()}
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
	if err := p.h.RemoveMoveLeftover(context.Background(), "plainapp", "plainapp", admin); errStatus(err) != 409 {
		t.Errorf("a leftover on the current server: %v", err)
	}
	if err := p.h.RemoveMoveLeftover(context.Background(), "plainapp", "plainapp", directoryActor("")); errStatus(err) != 401 {
		t.Errorf("no actor: %v", err)
	}
}

// TestKickerTrailing (review A2-L4): a throttled kick arms one trailing
// kick; none is lost.
func TestKickerTrailing(t *testing.T) {
	n := make(chan struct{}, 10)
	k := newKicker(context.Background(), 50*time.Millisecond, func() { n <- struct{}{} })
	k()
	k()
	k()
	<-n
	select {
	case <-n:
	case <-time.After(time.Second):
		t.Fatal("the trailing kick was lost")
	}
	select {
	case <-n:
		t.Error("more than one trailing kick")
	case <-time.After(150 * time.Millisecond):
	}
}

// TestScheduleSlotPersisted (review B2-L3): a Hub restart within the hour
// doesn't run the schedule twice.
func TestScheduleSlotPersisted(t *testing.T) {
	p := newPlacedFixture(t)
	now := time.Date(2026, 11, 16, 3, 15, 0, 0, time.Local)
	p.h.mu.Lock()
	p.h.st.PrimaryBackups = state.BackupSchedule{Mode: "daily", Hour: 3}
	p.h.mu.Unlock()
	p.h.backupSchedulesTick(context.Background(), now)
	p.h.mu.RLock()
	slot := p.h.st.ScheduleSlots[""]
	p.h.mu.RUnlock()
	if slot != scheduleSlot(now) {
		t.Errorf("slot %q", slot)
	}
	if b, _ := os.ReadFile(filepath.Join(p.data, "state.yaml")); !strings.Contains(string(b), "schedule_slots") {
		t.Error("the slot isn't persisted")
	}
}

func runtimeVolume(name, project string) runtime.Volume {
	return runtime.Volume{Name: name, Labels: map[string]string{docker.LabelProject: project}}
}

func directoryActor(u string) directory.Actor { return directory.Actor{User: u} }

// TestRenewOweSaveFailure (review A2-L2): when the replaced serial can't
// be recorded as owed, it is revoked at once.
func TestRenewOweSaveFailure(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	before, _ := sf.server("nas")
	sf.h.srvT.oweSaveErr = func(serial string) error {
		if serial == before.CertSerial {
			return errors.New("disk full")
		}
		return nil
	}
	sf.h.mu.Lock()
	s := sf.h.st.Servers["nas"]
	s.CertNotAfter = time.Now().Add(9 * 24 * time.Hour)
	sf.h.st.Servers["nas"] = s
	sf.h.mu.Unlock()
	sf.link.handshake("nas", time.Now())
	sf.h.pollServer(context.Background(), "nas")
	if !slices.Contains(sf.ca.revokedList(), before.CertSerial) {
		t.Errorf("the replaced serial wasn't revoked at once: %v", sf.ca.revokedList())
	}
}

// TestRevokeRotatesWithoutTemplateByOwnerTag (review A2-L3): with no
// recorded clients, only the clients tagged with the instance are
// deleted — never another instance's, core's or an AI one.
func TestRevokeRotatesWithoutTemplateByOwnerTag(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	lister := &listingIdP{fakeIdP: sf.idp, owned: map[string][]string{"gone": {"gone", "gone-2"}, "other": {"other"}}}
	sf.h.idp = lister
	sf.h.mu.Lock()
	sf.h.st.Instances["gone"] = state.Instance{ID: "gone", Template: "no-such-template", Server: "nas"}
	sf.h.noteServersLocked()
	sf.h.mu.Unlock()
	sf.h.RevokeServer(context.Background(), admin, "nas")
	s, _ := sf.server("nas")
	sf.idp.mu.Lock()
	deleted := strings.Join(sf.idp.deleted, ",")
	sf.idp.mu.Unlock()
	if !s.Revoke.Rotated || deleted != "gone:gone,gone-2:gone" {
		t.Errorf("rotated %v deleted %s", s.Revoke.Rotated, deleted)
	}
}

type listingIdP struct {
	*fakeIdP
	owned map[string][]string
}

func (l *listingIdP) ClientIDsOwnedBy(_ context.Context, owner string) ([]string, error) {
	return l.owned[owner], nil
}

// TestFailedMoveRecordsTargetLeftover (review B2-L5): a failed restore
// records the target's half-restored volumes; a next move there waits for
// their removal, which then lets it go.
func TestFailedMoveRecordsTargetLeftover(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable("filesapp"); err != nil {
		t.Fatal(err)
	}
	// The restore made the instance's volume on the target, then failed.
	vol := p.h.volumeNamesFor(p.h.Template("filesapp"), "filesapp")["data"]
	p.h.testHookApplyRestore = func(stage string) error {
		if stage == "volumes" {
			p.w.Lock()
			p.w.Volumes[vol] = runtimeVolume(vol, "portcullis-filesapp")
			p.w.Unlock()
			return errors.New("the target's volume upload failed")
		}
		return nil
	}
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin); err == nil {
		t.Fatal("moved")
	}
	p.h.testHookApplyRestore = nil
	in := p.instance("filesapp")
	if in.MoveTargetLeftover == nil || in.MoveTargetLeftover.Server != "nas" || !slices.Contains(in.MoveTargetLeftover.Volumes, vol) {
		t.Fatalf("leftover %+v", in.MoveTargetLeftover)
	}
	// The failed restore removed the bundle it pushed (no env left there).
	p.w.mu.Lock()
	held := p.w.held["filesapp"]
	p.w.mu.Unlock()
	if held {
		t.Error("the failed restore left its bundle on the worker")
	}
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin); errStatus(err) != 409 || !strings.Contains(err.Error(), "still holds a previous copy of filesapp") {
		t.Errorf("a move onto the leftover: %v", err)
	}
	if err := p.h.RemoveMoveLeftover(context.Background(), "filesapp", "filesapp", admin); err != nil {
		t.Fatal(err)
	}
	p.w.Lock()
	_, still := p.w.Volumes[vol]
	p.w.Unlock()
	if still {
		t.Error("the leftover volume is still on the worker")
	}
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin); err != nil {
		t.Errorf("after the removal: %v", err)
	}
}

// TestReservedIDOnWorker (fix round 3 review): "worker" and any id whose
// project is the agent's own are refused at placement.
func TestReservedIDOnWorker(t *testing.T) {
	p := newPlacedFixture(t)
	p.w.mu.Lock()
	p.w.info.OwnProject = "portcullis-plainapp"
	p.w.mu.Unlock()
	err := p.create(t, "plainapp", "nas")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "reserved on a worker") {
		t.Errorf("own project: %v", err)
	}
	if err := p.h.checkReservedID("worker", "nas"); errStatus(err) != 409 {
		t.Errorf("worker: %v", err)
	}
	if err := p.h.checkReservedID("worker", ""); err != nil {
		t.Errorf("on the primary: %v", err)
	}
}

// TestImageRefNoSecrets (fix round 3 review): an image reference naming
// a variable outside the allowlist is refused; the secret is in neither
// the error nor the audit; allowed variables and defaults resolve.
func TestImageRefNoSecrets(t *testing.T) {
	p := newPlacedFixture(t)
	writeFile(t, filepath.Join(p.project, ".env"), "CORE_VAR=core-value\nREGISTRY_TOKEN=s3cr3t-token-value\n")
	writeFile(t, filepath.Join(p.src, "plainapp", "compose.yml"), strings.Replace(mustReadS(t, filepath.Join(p.src, "plainapp", "compose.yml")),
		"image: plain:1", "image: registry.example/${REGISTRY_TOKEN}/plain:1", 1))
	p.h.Discover()
	audit := &fakeAudit{}
	p.h.SetAudit(audit)
	err := p.create(t, "plainapp", "nas")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "uses a variable that can't be resolved here") {
		t.Fatalf("%v", err)
	}
	audit.mu.Lock()
	all := fmt.Sprint(audit.entries)
	audit.mu.Unlock()
	if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(all, "s3cr3t") {
		t.Error("the secret leaked")
	}
	for in, want := range map[string]string{
		"x/${PORTCULLIS_DOMAIN}/a:1": "x/example.org/a:1",
		"x/a:${TAG:-1.2}":            "x/a:1.2",
		"x/a:${REGISTRY_TOKEN:-1}":   "x/a:1",
	} {
		if got, ok := expandRef(in, map[string]string{"PORTCULLIS_DOMAIN": "example.org", "REGISTRY_TOKEN": "s3cr3t"}); !ok || got != want {
			t.Errorf("%s: %q %v", in, got, ok)
		}
	}
	if _, ok := expandRef("x/$SECRET/a", nil); ok {
		t.Error("$SECRET resolved")
	}
}

// TestUndoRemovesWorkerBundle (fix round 3 review): an undo away from a
// worker removes the bundle it leaves there.
func TestUndoRemovesWorkerBundle(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	if _, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin); err != nil {
		t.Fatal(err)
	}
	if err := p.h.UndoMove(context.Background(), "plainapp", "plainapp", admin); err != nil {
		t.Fatal(err)
	}
	if !workerHas(p.w, "signal remove-project plainapp") {
		t.Errorf("worker %v", p.w.Calls())
	}
}
