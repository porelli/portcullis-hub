package hub

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/publish"
	"github.com/portcullis/hub/internal/runtime"
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

// TestHubCopyFailureIsPublished: the object is the authority; a failed
// Hub-side copy is no publish error, and the doctor input names it.
func TestHubCopyFailureIsPublished(t *testing.T) {
	f := newFixture(t)
	s, _ := kubePublish(f)
	f.h.pubMirror.Dirs[publish.PortalApps] = filepath.Join(f.data, "missing", "dir")
	if err := f.h.publish(publish.PortalApps, []byte("{}\n")); err != nil {
		t.Fatalf("a copy failure failed the publish: %v", err)
	}
	if string(s.data[publish.PortalApps]) != "{}\n" {
		t.Error("not published")
	}
	in := f.h.doctorPublishedIn()
	if in == nil || len(in.CopyFailed) != 1 || in.CopyFailed[0].Doc != "portal-apps" {
		t.Fatalf("doctor input %+v", in)
	}
	f.h.pubMirror.Dirs[publish.PortalApps] = f.data
	f.h.publish(publish.PortalApps, []byte("{}\n"))
	if in := f.h.doctorPublishedIn(); in != nil {
		t.Errorf("not cleared: %+v", in)
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
