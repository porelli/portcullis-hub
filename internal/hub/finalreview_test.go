package hub

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
)

// Final review (final-review-hub.md, final-review-fakes.md): each test
// runs the real backend and agent in process (realWorker) unless noted.

// TestVolumesOnlyBundleValidates (H1/B1): a kept copy's volumes-only
// bundle carries the template id and the compose keys pinned at move
// time, so it passes agentapi.ValidateManifest for a default and a named
// instance; a copy with no pinned key fails loudly.
func TestVolumesOnlyBundleValidates(t *testing.T) {
	for _, c := range []struct {
		id   string
		copy state.MovedFrom
	}{
		{"filesapp", state.MovedFrom{Server: "nas", Volumes: []string{"portcullis_filesapp-data"}, Keys: map[string]string{"portcullis_filesapp-data": "data"}, Template: "filesapp"}},
		{"filesapp-2", state.MovedFrom{Server: "nas", Volumes: []string{"portcullis-filesapp-2_data", "portcullis-filesapp-2_cache"},
			Keys: map[string]string{"portcullis-filesapp-2_data": "data", "portcullis-filesapp-2_cache": "cache"}, Template: "filesapp"}},
	} {
		files, m, err := volumesOnlyBundle(c.id, c.copy)
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		if err := agentapi.ValidateManifest(m, agentapi.MaxBundle); err != nil || m.Template != "filesapp" || !m.AdoptVolumes {
			t.Errorf("%s: %v %+v", c.id, err, m)
		}
		if b := files[bundleCompose]; !strings.Contains(string(b), "services: {}") {
			t.Errorf("%s: %s", c.id, b)
		}
	}
	if _, _, err := volumesOnlyBundle("filesapp", state.MovedFrom{Server: "nas", Volumes: []string{"portcullis_filesapp-data"}}); err == nil {
		t.Error("a copy without pinned keys built a bundle")
	}
}

// TestMoveRecordsKeysAndTemplate (H1): the kept copy pins its volumes'
// compose keys and the template id; its removal against the real agent
// works (the agent's own validation accepts the bundle).
func TestMoveRecordsKeysAndTemplate(t *testing.T) {
	p, vol := movedToPrimary(t)
	in := p.instance("filesapp")
	if in.MovedFrom.Keys[vol] != "data" || in.MovedFrom.Template != "filesapp" {
		t.Fatalf("pins %+v", in.MovedFrom)
	}
	if err := p.h.RemoveMoveLeftover(context.Background(), "filesapp", "filesapp", admin); err != nil {
		t.Fatal(err)
	}
	if !p.w.wt.Got(`^PUT /v1/projects/filesapp/bundle$`) || !p.w.wt.Got(`^DELETE /v1/volumes/`) {
		t.Errorf("requests %v", p.w.wt.Requests())
	}
}

// TestMoveRefusedBeforePushIsNotStuck (H2): an unpinned override is
// refused at the move's check (placedImages), before the backup: the
// instance runs on its source again, no move record, nothing stuck; a
// Stop before any push is the same.
func TestMoveRefusedBeforePushIsNotStuck(t *testing.T) {
	p := newPlacedFixture(t)
	enabledOnPrimary(t, p)
	if _, _, err := p.h.SaveUserOverride("plainapp", "services:\n  web:\n    image: plain:2\n"); err != nil {
		t.Fatal(err)
	}
	_, err := p.h.MoveInstance(context.Background(), "plainapp", "nas", admin)
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "pinned by digest") {
		t.Fatalf("move: %v", err)
	}
	in := p.instance("plainapp")
	if in.Move != nil || in.State == state.InstanceMoving || in.Server != "" {
		t.Errorf("state %+v", in)
	}
	if d := p.h.serversDoctorIn(); d != nil && d.Stuck["plainapp"] != "" {
		t.Error("stuck")
	}
	if p.w.wt.Got(`^POST /v1/projects/plainapp/down$`) {
		t.Error("a down was sent to an untouched target")
	}
	// A Stop at the restore, before any push: no down, not stuck.
	if _, _, err := p.h.SaveUserOverride("plainapp", ""); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.h.testHookMove = func(ph string) error {
		if ph == MoveRestore {
			cancel()
			return context.Canceled
		}
		return nil
	}
	defer func() { p.h.testHookMove = nil }()
	_ = p.h.moveInstance(withProgress(ctx, p.h.newProgress("plainapp", OpMove, movePlan())), "plainapp", "nas", admin, func() {})
	if in := p.instance("plainapp"); in.Move != nil || in.Server != "" {
		t.Errorf("after the stop %+v", in)
	}
	if p.w.wt.Got(`^POST /v1/projects/plainapp/down$`) {
		t.Error("a down was sent to an untouched target")
	}
}

// TestDeleteRemovesKeptCopies (M1): a delete removes the kept copy on a
// worker first (through the real agent); a copy that can't be removed
// refuses the delete, nothing deleted.
func TestDeleteRemovesKeptCopies(t *testing.T) {
	p, vol := movedToPrimary(t)
	// The worker refuses the removal: the delete is refused.
	p.w.eng.Lock()
	p.w.eng.ErrOn = map[string]error{"remove-volume " + vol: errors.New("volume is in use")}
	p.w.eng.Unlock()
	if _, err := p.h.DeleteInstance("filesapp", "filesapp", admin); errStatus(err) != 409 || !strings.Contains(err.Error(), "old copies") {
		t.Fatalf("delete with an unremovable copy: %v", err)
	}
	if in, ok := p.h.InstanceView("filesapp"); !ok || in.MovedFrom == nil {
		t.Fatalf("deleted anyway: %+v", in)
	}
	p.w.eng.Lock()
	p.w.eng.ErrOn = nil
	p.w.eng.Unlock()
	if _, err := p.h.DeleteInstance("filesapp", "filesapp", admin); err != nil {
		t.Fatal(err)
	}
	p.w.Lock()
	_, still := p.w.eng.Volumes[vol]
	p.w.Unlock()
	if still {
		t.Error("the kept copy's volume stayed on the worker")
	}
}

// TestCreateOnWorkerRefusesHiddenLeftoverVolumes (M1, the agent's
// backstop): a worker that holds volumes labelled with the id's project
// and no bundle or tombstone refuses its first bundle (409): a create
// there never adopts an earlier instance's data.
func TestCreateOnWorkerRefusesHiddenLeftoverVolumes(t *testing.T) {
	p := newPlacedFixture(t)
	vol := p.h.volumeNamesFor(p.h.Template("filesapp"), "filesapp")["data"]
	p.w.Lock()
	p.w.eng.Volumes[vol] = runtime.Volume{Name: vol, Labels: map[string]string{docker.LabelProject: "portcullis-filesapp", docker.LabelVolume: "data"}}
	p.w.Unlock()
	if err := p.create(t, "filesapp", "nas"); err != nil {
		t.Fatal(err)
	}
	err := p.h.Enable("filesapp")
	if !agentErr(err, http.StatusConflict) && !strings.Contains(errString(err), "earlier filesapp") {
		t.Fatalf("enable over hidden volumes: %v", err)
	}
	if p.w.holds("filesapp") {
		t.Error("the bundle was taken")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestRevokeClosesLiveBackend (M2): a backend taken before the
// revocation refuses every later call; the agent gets nothing more; a
// push to a revoking server is refused before it is sent.
func TestRevokeClosesLiveBackend(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	sf.place("plainapp", "nas")
	b, ok := sf.h.backendOf("nas")
	if !ok {
		t.Fatal("no backend")
	}
	if err := sf.h.RevokeServer(context.Background(), admin, "nas"); err != nil {
		t.Fatal(err)
	}
	if !b.Revoked() {
		t.Error("the old backend wasn't revoked")
	}
	before := len(sf.agent.Calls())
	if _, err := b.AgentInfo(context.Background()); err == nil {
		t.Error("a call on the revoked backend went through")
	}
	if err := b.Create(context.Background(), runtime.Project{Name: "portcullis-plainapp", Instance: "plainapp"}); err == nil {
		t.Error("a create on the revoked backend went through")
	}
	if len(sf.agent.Calls()) != before {
		t.Errorf("the agent got calls after the revocation: %v", sf.agent.Calls()[before:])
	}
	if err := sf.h.pushAllowed("nas"); errStatus(err) != 409 {
		t.Errorf("push to a revoked server: %v", err)
	}
}

// TestRotationWaitsForLinkDrop (M2): while link's status still lists
// the revoked peer, nothing is rotated; once it's gone, the next pass
// rotates.
func TestRotationWaitsForLinkDrop(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	sf.place("other", "nas")
	old := sf.h.relayTokenSHA("other")
	if err := sf.h.RevokeServer(context.Background(), admin, "nas"); err != nil {
		t.Fatal(err)
	}
	if s, _ := sf.server("nas"); s.Revoke == nil || s.Revoke.Rotated {
		t.Fatalf("rotated with the peer still in link: %+v", s.Revoke)
	}
	if sf.h.relayTokenSHA("other") != old {
		t.Error("the relay token was rotated before link dropped the peer")
	}
	sf.link.drop("nas")
	sf.h.advanceRevoke(context.Background(), "nas")
	if s, _ := sf.server("nas"); !s.Revoke.Rotated {
		t.Errorf("not rotated after the drop: %+v", s.Revoke)
	}
}

// TestPushRacingRevokeCarriesNoRotatedSecret (M2; re-review: asserts,
// never skips): pushes run in a loop; at least one lands before the
// revocation; from the revocation on every push is refused before it is
// sent, so the token rotated after it never reaches the worker.
func TestPushRacingRevokeCarriesNoRotatedSecret(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	landed := func() int {
		p.w.mu.Lock()
		defer p.w.mu.Unlock()
		return len(p.w.bundles)
	}
	before := landed()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var refusedAfter atomic.Int32
	var revoked atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			after := revoked.Load()
			if err := p.h.pushBundle(context.Background(), "plainapp", p.w); err != nil && after {
				if errStatus(err) != 409 {
					t.Errorf("a push after the revocation: %v (want the 409 refusal)", err)
				}
				refusedAfter.Add(1)
			}
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for landed() == before {
		if time.Now().After(deadline) {
			close(stop)
			wg.Wait()
			t.Fatal("no push landed before the revocation")
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.h.mu.Lock()
	p.h.beginRevokeLocked("nas", false)
	p.h.mu.Unlock()
	revoked.Store(true)
	// The pushes run one after another: once one started after the
	// revocation is refused, every push before it has ended (one in
	// flight at the revocation read its env before it) — no sleep.
	for refusedAfter.Load() < 1 {
		if time.Now().After(deadline) {
			close(stop)
			wg.Wait()
			t.Fatal("no push after the revocation was refused")
		}
		time.Sleep(time.Millisecond)
	}
	settled := landed()
	// What the rotation writes into the instance's env (a new client
	// secret) from here on.
	rotated := "rotated-" + strings.Repeat("9f8e", 8)
	env := readEnvRaw(p.h.envPath("plainapp"))
	env["PORTCULLIS_OIDC_CLIENT_SECRET_ROTATED"] = rotated
	if err := writeEnvMap(p.h.envPath("plainapp"), env); err != nil {
		t.Fatal(err)
	}
	for refusedAfter.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if refusedAfter.Load() < 3 {
		t.Fatalf("pushes after the revocation weren't refused (%d)", refusedAfter.Load())
	}
	if n := landed(); n != settled {
		t.Errorf("%d pushes landed after the revocation", n-settled)
	}
	p.w.mu.Lock()
	defer p.w.mu.Unlock()
	if len(p.w.bundles) == 0 || p.w.bundles[len(p.w.bundles)-1][bundleEnv] == "" {
		t.Fatal("the landed bundles carry no env to check")
	}
	for _, b := range p.w.bundles {
		if strings.Contains(b[bundleEnv], rotated) {
			t.Error("a push carried the rotated secret")
		}
	}
}

// TestOrphanUpStartsNoRelay (L1): after a revocation, an enable or up of
// its instance is refused before its relays come back.
func TestOrphanUpStartsNoRelay(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.h.mu.Lock()
	p.h.beginRevokeLocked("nas", false)
	p.h.mu.Unlock()
	before := len(p.runner.Calls())
	err := p.h.composeUp(context.Background(), p.h.Template("plainapp"))
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "orphaned") {
		t.Fatalf("up of an orphan: %v", err)
	}
	for _, c := range p.runner.Calls()[before:] {
		if strings.Contains(c, "portcullis-plainapp") && (strings.HasPrefix(c, "up") || strings.HasPrefix(c, "create")) {
			t.Errorf("a relay came back: %s", c)
		}
	}
	if err := p.h.relaysUp(context.Background(), "plainapp"); errStatus(err) != 409 {
		t.Errorf("relaysUp of an orphan: %v", err)
	}
}

// TestWorkerNotFoundIsGone (B4, B5): a bundle the worker no longer holds
// is gone for the removal (its 404), and a by-name down of a project it
// never held is nothing to take down.
func TestWorkerNotFoundIsGone(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.h.removeWorkerBundle(context.Background(), "nas", "plainapp"); err != nil {
		t.Errorf("removing a bundle the worker doesn't hold: %v", err)
	}
	if err := p.create(t, "plainapp", "nas"); err != nil {
		t.Fatal(err)
	}
	if err := p.h.downByName(context.Background(), "plainapp"); err != nil {
		t.Errorf("by-name down of a never-held project: %v", err)
	}
	if err := p.h.rollbackUp(p.h.Template("plainapp")); err != nil {
		t.Errorf("rollback of a refused push: %v", err)
	}
}

// TestStaleSecretsFileNotPushed (I2): a settings secrets file left in
// the primary's appfiles before the instance was placed is never part of
// its bundle (the agent would refuse every push for it).
func TestStaleSecretsFileNotPushed(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "plainapp", "nas"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(p.h.cfg.AppFilesDir, "plainapp", "people")
	os.MkdirAll(dir, 0o750)
	os.WriteFile(filepath.Join(dir, "people.secrets.json"), []byte(`{"x":"stale-secret"}`), 0o600)
	os.WriteFile(filepath.Join(dir, "people.json"), []byte(`{}`), 0o640)
	if err := p.h.Enable("plainapp"); err != nil {
		t.Fatal(err)
	}
	b := p.w.lastBundle()
	if _, ok := b["appfiles/people/people.secrets.json"]; ok || b["appfiles/people/people.json"] == "" {
		t.Errorf("bundle files %v", slices.Sorted(maps2keys(b)))
	}
}

// TestWorkerTextSanitizedEverywhere (L4): newlines and bidi controls in
// a worker's quarantine reason and arch never reach the doctor input,
// the error text or a log line.
func TestWorkerTextSanitizedEverywhere(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	evil := "bad\nline ‮gnp.exe"
	p.w.quarantine("plainapp", evil)
	p.w.mu.Lock()
	p.w.info.Arch = "arm64\n‮"
	p.w.mu.Unlock()
	logs := captureLog(t)
	p.h.refreshServerFacts(context.Background(), "nas")
	err := p.h.RestartApp("plainapp")
	in := p.h.serversDoctorIn()
	for what, s := range map[string]string{"error": errString(err), "doctor": in.Quarantined["plainapp"], "log": logs.String(), "arch": p.h.serverInfo("nas").Arch} {
		if strings.ContainsAny(s, "‮") || (what != "log" && strings.Contains(s, "\n")) {
			t.Errorf("%s carries a control: %q", what, s)
		}
	}
}

// TestPreflightCancellable (L5): a preflight pull the worker holds on to
// (prepareUp's, before the start) ends with the op's context — a Stop
// doesn't wait for the pull.
func TestPreflightCancellable(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "plainapp", "nas"); err != nil {
		t.Fatal(err)
	}
	pinned := "other.example/plain:2@sha256:" + strings.Repeat("8", 64)
	if _, _, err := p.h.SaveUserOverride("plainapp", "services:\n  web:\n    image: "+pinned+"\n"); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	p.w.wt.Hook(`^POST /v1/images/pull$`, -1, func(r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := p.h.prepareUpCtx(ctx, p.h.Template("plainapp"))
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("prepareUp: %v after %v", err, time.Since(start))
	}
	if !p.w.wt.Got(`^POST /v1/images/pull$`) {
		t.Error("no preflight pull was sent")
	}
}
