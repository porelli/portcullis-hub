package hub

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/leader"
	"github.com/portcullis/hub/internal/publish"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

// objSink is a kube-like sink: the objects in memory, the reader pods
// behind per document.
type objSink struct {
	mu      sync.Mutex
	data    map[publish.Doc][]byte
	rev     map[publish.Doc]string
	behind  map[publish.Doc][]string
	refuse  map[publish.Doc]error
	updates int
}

func newObjSink() *objSink {
	return &objSink{data: map[publish.Doc][]byte{}, rev: map[publish.Doc]string{}, behind: map[publish.Doc][]string{}, refuse: map[publish.Doc]error{}}
}

func (s *objSink) Publish(_ context.Context, d publish.Doc, b []byte) (string, error) {
	if err := publish.Check(d, b, publish.MaxDoc); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuse[d]; err != nil {
		return "", err
	}
	s.updates++
	s.data[d], s.rev[d] = bytes.Clone(b), publish.Rev(b)
	return s.rev[d], nil
}

func (s *objSink) Remove(_ context.Context, d publish.Doc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuse[d]; err != nil {
		return err
	}
	delete(s.data, d)
	s.rev[d] = publish.Rev(nil)
	return nil
}

func (s *objSink) Confirmed(ctx context.Context, d publish.Doc, rev string) (bool, error) {
	b, err := s.Behind(ctx, d, rev)
	return len(b) == 0, err
}

func (s *objSink) Behind(_ context.Context, d publish.Doc, _ string) ([]publish.Lag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []publish.Lag
	for _, p := range s.behind[d] {
		out = append(out, publish.Lag{Pod: p})
	}
	return out, nil
}

// kubePublish puts f's Hub on an object sink as initPublish does under
// Kubernetes (the mirror on the data directory), with a fake clock.
func kubePublish(f *fixture) (*objSink, *time.Time) {
	s := newObjSink()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tr := publish.NewTracker(s)
	tr.Now = func() time.Time { return now }
	mirror := publish.FileSink{Dirs: map[publish.Doc]string{}}
	for _, d := range publish.All {
		if d != publish.VPN {
			mirror.Dirs[d] = f.data
		}
	}
	f.h.pub, f.h.pubMirror = tr, &mirror
	return s, &now
}

// TestPublishTooLargeKeepsLast: a policy file of 1 000 001 bytes is
// ErrTooLarge; the object keeps the previous document and its .rev, the
// Hub's own copy is untouched (nothing written partially), and the
// doctor raises published_doc_too_large naming the document and size.
// The next good publish clears it.
func TestPublishTooLargeKeepsLast(t *testing.T) {
	f, _, _ := doctorFixture(t)
	s, _ := kubePublish(f)
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	good := bytes.Clone(s.data[publish.GroupGatePolicy])
	if len(good) == 0 || s.rev[publish.GroupGatePolicy] != publish.Rev(good) {
		t.Fatalf("the policy wasn't published: %d bytes", len(good))
	}
	onDisk, _ := os.ReadFile(filepath.Join(f.data, "group-gate-policy.json"))
	if !bytes.Equal(onDisk, good) {
		t.Fatal("the Hub's own copy differs from the published one")
	}
	updates := s.updates
	err := f.h.publish(publish.GroupGatePolicy, bytes.Repeat([]byte(" "), publish.MaxDoc+1))
	if !errors.Is(err, publish.ErrTooLarge) {
		t.Fatalf("err %v", err)
	}
	if s.updates != updates || !bytes.Equal(s.data[publish.GroupGatePolicy], good) || s.rev[publish.GroupGatePolicy] != publish.Rev(good) {
		t.Error("the object changed")
	}
	if b, _ := os.ReadFile(filepath.Join(f.data, "group-gate-policy.json")); !bytes.Equal(b, good) {
		t.Error("the Hub's own copy changed")
	}
	es, _ := os.ReadDir(f.data)
	for _, e := range es {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("partial file %s", e.Name())
		}
	}
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fd := findKind(r, doctor.KindPublishedDocTooLarge)
	if fd == nil || !strings.Contains(fd.Title, "group-gate-policy") || !strings.Contains(fd.Title, "1000001") || fd.Severity != doctor.Problem {
		t.Fatalf("finding %+v", fd)
	}
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	r, _ = f.h.Doctor(context.Background())
	if findKind(r, doctor.KindPublishedDocTooLarge) != nil {
		t.Error("not cleared by a good publish")
	}
}

// TestPublishedStaleAfter120s: a reader pod that doesn't confirm for
// more than 120 s raises published_doc_stale naming the document and
// the pod; it clears once the pod confirms.
func TestPublishedStaleAfter120s(t *testing.T) {
	f, _, _ := doctorFixture(t)
	s, now := kubePublish(f)
	s.behind[publish.PortalApps] = []string{"group-gate-5f-a1"}
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	*now = now.Add(100 * time.Second)
	f.h.pub.Check(ctx)
	r, err := f.h.Doctor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if findKind(r, doctor.KindPublishedDocStale) != nil {
		t.Fatal("stale before 120 s")
	}
	*now = now.Add(21 * time.Second)
	f.h.pub.Check(ctx)
	r, _ = f.h.Doctor(ctx)
	fd := findKind(r, doctor.KindPublishedDocStale)
	if fd == nil || !strings.Contains(fd.Title, "portal-apps") || !strings.Contains(fd.Why, "group-gate-5f-a1") || fd.Severity != doctor.Problem {
		t.Fatalf("finding %+v", fd)
	}
	// The other documents were confirmed at once.
	for _, x := range r.Findings {
		if x.Kind == doctor.KindPublishedDocStale && x.FP != fd.FP {
			t.Errorf("another stale finding %+v", x)
		}
	}
	s.mu.Lock()
	s.behind[publish.PortalApps] = nil
	s.mu.Unlock()
	f.h.pub.Check(ctx)
	r, _ = f.h.Doctor(ctx)
	if findKind(r, doctor.KindPublishedDocStale) != nil {
		t.Error("not cleared once the pod confirms")
	}
}

// TestPublishDockerFiles: on Docker every document is today's file (the
// sink is a FileSink on the data directory, vpn.json in the VPN volume).
func TestPublishDockerFiles(t *testing.T) {
	f := newFixture(t)
	fs, ok := f.h.pub.Sink.(publish.FileSink)
	if !ok || f.h.pubMirror != nil || f.h.pub.Max != 0 {
		t.Fatalf("sink %T mirror %v max %d", f.h.pub.Sink, f.h.pubMirror, f.h.pub.Max)
	}
	for _, d := range publish.All {
		if d != publish.VPN && fs.Dirs[d] != f.data {
			t.Errorf("%s in %q", d, fs.Dirs[d])
		}
	}
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"group-gate-policy.json", "portal-apps.json", "signin-keycloak.json", "impersonation.json"} {
		fi, err := os.Stat(filepath.Join(f.data, n))
		if err != nil || fi.Mode().Perm() != 0644 {
			t.Errorf("%s: %v %v", n, fi, err)
		}
	}
}

// blockSink blocks every publish until release is closed.
type blockSink struct {
	entered chan publish.Doc
	release chan struct{}
}

func (b *blockSink) Publish(ctx context.Context, d publish.Doc, data []byte) (string, error) {
	b.entered <- d
	select {
	case <-b.release:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return publish.Rev(data), nil
}

func (b *blockSink) Confirmed(context.Context, publish.Doc, string) (bool, error) { return true, nil }

// TestPublishNeverUnderMu: while a publish blocks (a stalled API
// server), h.mu can still be taken within 100 ms: the policy pass and
// the impersonation loop publish after releasing it.
func TestPublishNeverUnderMu(t *testing.T) {
	f := newFixture(t)
	for name, run := range map[string]func(){
		"writePolicy":        func() { f.h.WritePolicy() },
		"impersonation tick": func() { f.h.impersonationTick(context.Background()) },
	} {
		b := &blockSink{entered: make(chan publish.Doc, 32), release: make(chan struct{})}
		f.h.pub, f.h.pubMirror = publish.NewTracker(b), nil
		f.h.imp.fileMu.Lock()
		f.h.imp.fileFailed = true // the tick publishes
		f.h.imp.fileMu.Unlock()
		finished := make(chan struct{})
		go func() { run(); close(finished) }()
		select {
		case <-b.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: nothing published", name)
		}
		locked := make(chan struct{})
		go func() { f.h.mu.Lock(); f.h.mu.Unlock(); close(locked) }()
		select {
		case <-locked:
		case <-time.After(100 * time.Millisecond):
			t.Errorf("%s: h.mu blocked while a publish is in flight", name)
		}
		close(b.release)
		<-locked
		<-finished
	}
}

// TestImpersonationNewerSnapshotWins: an older snapshot never replaces
// a newer published one.
func TestImpersonationNewerSnapshotWins(t *testing.T) {
	f := newFixture(t)
	s, _ := kubePublish(f)
	f.h.mu.RLock()
	old := f.h.impSnapLocked()
	f.h.mu.RUnlock()
	f.h.mu.RLock()
	newer := f.h.impSnapLocked()
	f.h.mu.RUnlock()
	newer.b = []byte(`{"newer":true}` + "\n")
	if err := f.h.publishImp(newer); err != nil {
		t.Fatal(err)
	}
	if err := f.h.publishImp(old); err != nil {
		t.Fatal(err)
	}
	if string(s.data[publish.Impersonation]) != string(newer.b) {
		t.Errorf("the older snapshot replaced the newer: %s", s.data[publish.Impersonation])
	}
}

// TestTooLargePolicyStillPublishesTheRest: a policy file refused for
// its size (persistent) doesn't hold back the other documents.
func TestTooLargePolicyStillPublishesTheRest(t *testing.T) {
	f := newFixture(t)
	s, _ := kubePublish(f)
	s.refuse[publish.GroupGatePolicy] = publish.ErrTooLarge
	before := f.h.gatePolicy.Load()
	err := f.h.WritePolicy()
	if !errors.Is(err, publish.ErrTooLarge) {
		t.Fatalf("err %v", err)
	}
	for _, d := range []publish.Doc{publish.SignInKeycloak, publish.Impersonation, publish.PortalApps} {
		if len(s.data[d]) == 0 {
			t.Errorf("%s not published", d)
		}
	}
	if f.h.gatePolicy.Load() != before {
		t.Error("the refused policy is kept as published")
	}
}

// TestHubCopyFirst (S2): the Hub's own copy is written before the
// object. A copy that can't be written publishes nothing (an error); an
// object update that fails puts the copy back. The Hub's read-back and
// what readers enforce never diverge.
func TestHubCopyFirst(t *testing.T) {
	f := newFixture(t)
	s, _ := kubePublish(f)
	copyPath := filepath.Join(f.data, "mcp-credentials.json")
	if err := f.h.publish(publish.MCPCredentials, []byte("v1\n")); err != nil {
		t.Fatal(err)
	}
	// The copy fails: nothing is published.
	f.h.pubMirror.Dirs[publish.MCPCredentials] = filepath.Join(f.data, "missing", "dir")
	if err := f.h.publish(publish.MCPCredentials, []byte("v2\n")); err == nil || !strings.Contains(err.Error(), "nothing published") {
		t.Fatalf("a failed copy didn't fail the publish: %v", err)
	}
	if string(s.data[publish.MCPCredentials]) != "v1\n" {
		t.Errorf("published despite the failed copy: %q", s.data[publish.MCPCredentials])
	}
	f.h.pubMirror.Dirs[publish.MCPCredentials] = f.data
	// The object update fails: the copy is put back.
	s.refuse[publish.MCPCredentials] = errors.New("the API server is down")
	if err := f.h.publish(publish.MCPCredentials, []byte("v3\n")); err == nil {
		t.Fatal("a failed update passed")
	}
	if b, _ := os.ReadFile(copyPath); string(b) != "v1\n" || string(s.data[publish.MCPCredentials]) != "v1\n" {
		t.Errorf("diverged: copy %q, object %q", b, s.data[publish.MCPCredentials])
	}
	// A first document whose update fails: the copy is removed again.
	if err := f.h.publish(publish.MCPGate, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(f.data, "portal-apps.json"))
	s.refuse[publish.PortalApps] = errors.New("down")
	if f.h.publish(publish.PortalApps, []byte("{}\n")) == nil {
		t.Fatal("passed")
	}
	if _, err := os.Stat(filepath.Join(f.data, "portal-apps.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a copy of an unpublished document stayed: %v", err)
	}
	// A failed withdraw puts the copy back: both keep v1.
	s.refuse[publish.MCPCredentials] = errors.New("the API server is down")
	if f.h.unpublish(publish.MCPCredentials) == nil {
		t.Fatal("a failed withdraw passed")
	}
	if b, _ := os.ReadFile(copyPath); string(b) != "v1\n" || string(s.data[publish.MCPCredentials]) != "v1\n" {
		t.Errorf("withdraw diverged: copy %q, object %q", b, s.data[publish.MCPCredentials])
	}
	// Withdrawn: the copy goes with the object.
	s.refuse[publish.MCPCredentials] = nil
	if err := f.h.unpublish(publish.MCPCredentials); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(copyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("withdrawn, the copy stayed: %v", err)
	}
}

// TestKubeRuntimeWithoutDocSinkRefused: under Kubernetes a runtime that
// can't publish refuses the start.
func TestKubeRuntimeWithoutDocSinkRefused(t *testing.T) {
	h := &Hub{cfg: Config{Runtime: runtime.KindKubernetes, DataDir: t.TempDir()}}
	if err := h.initPublish(); err == nil || !strings.Contains(err.Error(), "can't publish") {
		t.Errorf("err %v", err)
	}
}

// TestImpersonationOlderNeverAfterNewerFailed (N1, S1): the newer
// snapshot fails; the older one, arriving late, is never published, the
// caller gets the newer one's error and the file stays due.
func TestImpersonationOlderNeverAfterNewerFailed(t *testing.T) {
	f := newFixture(t)
	s, _ := kubePublish(f)
	before := bytes.Clone(s.data[publish.Impersonation])
	f.h.mu.RLock()
	old := f.h.impSnapLocked()
	newer := f.h.impSnapLocked()
	f.h.mu.RUnlock()
	old.b, newer.b = []byte(`{"old":true}`+"\n"), []byte(`{"newer":true}`+"\n")
	s.mu.Lock()
	s.refuse[publish.Impersonation] = errors.New("the API server is down")
	s.mu.Unlock()
	if err := f.h.publishImp(newer); err == nil {
		t.Fatal("the newer publish passed")
	}
	s.mu.Lock()
	s.refuse[publish.Impersonation] = nil
	s.mu.Unlock()
	if err := f.h.publishImp(old); err == nil || !strings.Contains(err.Error(), "down") {
		t.Errorf("the older call returned %v, want the newer one's error", err)
	}
	if !bytes.Equal(s.data[publish.Impersonation], before) {
		t.Errorf("the older snapshot was published: %s", s.data[publish.Impersonation])
	}
	if !f.h.impFileFailed() || !f.h.impersonationFileDue(f.h.impNow()) {
		t.Error("the failure was cleared: the newer state isn't retried")
	}
	// The next snapshot publishes and clears it.
	f.h.mu.RLock()
	next := f.h.impSnapLocked()
	f.h.mu.RUnlock()
	if err := f.h.publishImp(next); err != nil || f.h.impFileFailed() {
		t.Errorf("next: %v, failed %v", err, f.h.impFileFailed())
	}
}

// TestImpersonationSupersededWaitsForNewer (S1): an older publish in
// flight, cancelled by a newer snapshot, returns the newer one's
// outcome: its error when it fails, nil when it is published.
func TestImpersonationSupersededWaitsForNewer(t *testing.T) {
	for _, newerFails := range []bool{true, false} {
		f := newFixture(t)
		b := &blockSink{entered: make(chan publish.Doc, 4), release: make(chan struct{})}
		gate := &switchSink{first: b, then: newObjSink()}
		if newerFails {
			gate.then.refuse[publish.Impersonation] = errors.New("refused")
		}
		f.h.pub, f.h.pubMirror = publish.NewTracker(gate), nil
		f.h.mu.RLock()
		old := f.h.impSnapLocked()
		newer := f.h.impSnapLocked()
		f.h.mu.RUnlock()
		got := make(chan error, 1)
		go func() { got <- f.h.publishImp(old) }()
		<-b.entered // the older publish is in flight
		gate.switchOver()
		nerr := f.h.publishImp(newer)
		oerr := <-got
		if newerFails && (nerr == nil || oerr == nil || oerr.Error() != nerr.Error()) {
			t.Errorf("newer fails: older %v, newer %v", oerr, nerr)
		}
		if !newerFails && (nerr != nil || oerr != nil) {
			t.Errorf("newer published: older %v, newer %v", oerr, nerr)
		}
		if newerFails != f.h.impFileFailed() {
			t.Errorf("newer fails %v: file failed %v", newerFails, f.h.impFileFailed())
		}
	}
}

// switchSink sends publishes to first until switchOver, then to then.
type switchSink struct {
	mu    sync.Mutex
	first publish.Sink
	then  *objSink
	over  bool
}

func (s *switchSink) switchOver() { s.mu.Lock(); s.over = true; s.mu.Unlock() }

func (s *switchSink) sink() publish.Sink {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.over {
		return s.then
	}
	return s.first
}

func (s *switchSink) Publish(ctx context.Context, d publish.Doc, b []byte) (string, error) {
	return s.sink().Publish(ctx, d, b)
}

func (s *switchSink) Confirmed(ctx context.Context, d publish.Doc, rev string) (bool, error) {
	return s.sink().Confirmed(ctx, d, rev)
}

// TestNoticeActionOnlyAfterConfirmed (N2): the Keycloak notice action
// is set only once the file holding the notice is published and its
// readers confirm it: not while the publish fails, not while a reader
// is behind.
func TestNoticeActionOnlyAfterConfirmed(t *testing.T) {
	x := newImpFixture(t)
	x.h.SetImpersonationApps(func(context.Context, state.Impersonation) ([]signinhistory.OpenedApp, bool) { return nil, true })
	x.mustStart(t, "root", "alice")
	s, _ := kubePublish(x.f)
	s.mu.Lock()
	s.refuse[publish.Impersonation] = errors.New("the API server is down")
	s.mu.Unlock()
	if err := x.h.StopImpersonation(x.ctx, "alice", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if n := x.kc.noticed(); len(n) != 0 {
		t.Fatalf("the action was set while the publish failed: %v", n)
	}
	s.mu.Lock()
	s.refuse[publish.Impersonation] = nil
	s.behind[publish.Impersonation] = []string{"keycloak-0"}
	s.mu.Unlock()
	x.h.impersonationTick(x.ctx)
	if n := x.kc.noticed(); len(n) != 0 {
		t.Fatalf("the action was set before the readers confirmed: %v", n)
	}
	s.mu.Lock()
	s.behind[publish.Impersonation] = nil
	s.mu.Unlock()
	x.h.impersonationTick(x.ctx)
	if n := x.kc.noticed(); !slices.Equal(n, []string{"alice"}) {
		t.Fatalf("notices = %v", n)
	}
	s.mu.Lock()
	pubd := bytes.Clone(s.data[publish.Impersonation])
	s.mu.Unlock()
	doc := checkImpFileStrict(t, pubd, x.clock())
	if len(doc.Notices["alice"]) != 1 {
		t.Errorf("the published file lacks the notice: %+v", doc)
	}
}

// standBySink closes the write gate in the middle of d's object update
// (the stand-by cuts it) and fails it; other documents go to objSink.
type standBySink struct {
	*objSink
	d publish.Doc
}

func (s standBySink) Publish(ctx context.Context, d publish.Doc, b []byte) (string, error) {
	if d == s.d {
		fsutil.SetWriteGate(func() error { return leader.ErrStandingBy })
		return "", leader.ErrStandingBy
	}
	return s.objSink.Publish(ctx, d, b)
}

// TestCopyAheadRepublishedAtStart (N3, the mcp-credentials revoking
// case): the copy is written, the object update is cut by a stand-by,
// putting the copy back is refused by the gate. The divergence is a
// Problem; in the same process the restore is retried once writes are
// possible again; and a new Hub on the same data publishes its copy
// first thing, so the object equals what it reads back.
func TestCopyAheadRepublishedAtStart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		f := newFixture(t)
		s, _ := kubePublish(f)
		t.Cleanup(func() { fsutil.SetWriteGate(nil) })
		copyPath := filepath.Join(f.data, "mcp-credentials.json")
		if err := f.h.publish(publish.MCPCredentials, []byte("v1 active\n")); err != nil {
			t.Fatal(err)
		}
		tr := f.h.pub
		f.h.pub = publish.NewTracker(standBySink{s, publish.MCPCredentials})
		f.h.pub.Now = tr.Now
		if err := f.h.publish(publish.MCPCredentials, []byte("v2 revoking\n")); !errors.Is(err, leader.ErrStandingBy) {
			t.Fatalf("err %v", err)
		}
		if b, _ := os.ReadFile(copyPath); string(b) != "v2 revoking\n" || string(s.data[publish.MCPCredentials]) != "v1 active\n" {
			t.Fatalf("setup: copy %q object %q", b, s.data[publish.MCPCredentials])
		}
		in := f.h.doctorPublishedIn()
		if in == nil || len(in.Stale) != 1 || in.Stale[0].Doc != "mcp-credentials" || !strings.Contains(in.Stale[0].Err, "differ from the Hub's own copy") {
			t.Fatalf("the divergence isn't a Problem: %+v", in)
		}
		fsutil.SetWriteGate(nil)
		if !restart {
			// The same Hub, writing again: the restore is retried.
			f.h.pub.Sink = s
			f.h.retryUnsynced()
			if b, _ := os.ReadFile(copyPath); string(b) != "v1 active\n" || f.h.doctorPublishedIn() != nil {
				t.Errorf("in process: copy %q, doctor %+v", b, f.h.doctorPublishedIn())
			}
			continue
		}
		// A new Hub on the same data directory, as Init runs it.
		h2, err := newTestHub(f.h.cfg, f.runner, f.engine, f.idp)
		if err != nil {
			t.Fatal(err)
		}
		h2.pub = publish.NewTracker(s)
		h2.pubMirror = f.h.pubMirror
		h2.RepublishFromCopies()
		if string(s.data[publish.MCPCredentials]) != "v2 revoking\n" {
			t.Errorf("after the start the object is %q, the copy v2", s.data[publish.MCPCredentials])
		}
		// A missing copy withdraws its object at start.
		os.Remove(filepath.Join(f.data, "portal-apps.json"))
		s.data[publish.PortalApps] = []byte("stale\n")
		h2.RepublishFromCopies()
		if _, ok := s.data[publish.PortalApps]; ok {
			t.Error("a missing copy left its object")
		}
		// A failed republish is a Problem and retried.
		s.refuse[publish.MCPCredentials] = errors.New("down")
		h2.RepublishFromCopies()
		if in := h2.doctorPublishedIn(); in == nil || len(in.Stale) != 1 {
			t.Errorf("a failed republish isn't reported: %+v", in)
		}
		s.refuse[publish.MCPCredentials] = nil
		h2.retryUnsynced()
		if in := h2.doctorPublishedIn(); in != nil {
			t.Errorf("not cleared by the retry: %+v", in)
		}
	}
}

// TestInitRepublishesFirst: Init starts with RepublishFromCopies.
func TestInitRepublishesFirst(t *testing.T) {
	f := newFixture(t)
	s, _ := kubePublish(f)
	os.WriteFile(filepath.Join(f.data, "mcp-credentials.json"), []byte("copy\n"), 0o640)
	f.h.Init()
	if string(s.data[publish.MCPCredentials]) != "copy\n" {
		t.Errorf("Init didn't publish the copy: %q", s.data[publish.MCPCredentials])
	}
}
