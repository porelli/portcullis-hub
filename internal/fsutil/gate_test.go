package fsutil_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/state"
)

var errStandingBy = errors.New("this Hub is standing by: another Hub is the active writer")

// closeGate installs a gate answering errStandingBy for the test.
func closeGate(t *testing.T) {
	t.Helper()
	fsutil.SetWriteGate(func() error { return errStandingBy })
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
}

func digest(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// TestWriteGateOpenByDefault: Docker, Podman and the helper subcommands
// never set a gate; every writer behaves as the os function it wraps.
func TestWriteGateOpenByDefault(t *testing.T) {
	if err := fsutil.CheckWrite(); err != nil {
		t.Fatalf("CheckWrite with no gate = %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "a")
	if err := fsutil.WriteFileAtomic(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.AppendFile(p, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "xy" {
		t.Errorf("got %q", b)
	}
	// A gate set and cleared again: open.
	fsutil.SetWriteGate(func() error { return errStandingBy })
	fsutil.SetWriteGate(nil)
	if err := fsutil.MkdirAll(filepath.Join(dir, "d", "e"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestWriteGateRefusesEveryWriter: with the gate closed every writer
// returns the gate's error first and nothing on disk changes.
func TestWriteGateRefusesEveryWriter(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.yaml")
	st := &state.AppState{}
	if err := st.Save(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	// An open write handle taken while leading stops at its next write.
	held, err := fsutil.OpenFile(filepath.Join(dir, "held"), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	root, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, stateBefore := digest(t, p), digest(t, statePath)
	entriesBefore, _ := os.ReadDir(dir)

	closeGate(t)
	writers := map[string]func() error{
		"WriteFileAtomic":      func() error { return fsutil.WriteFileAtomic(p, []byte("after"), 0o600) },
		"WriteFileAtomicGroup": func() error { return fsutil.WriteFileAtomicGroup(p, []byte("after"), 0o640, os.Getgid()) },
		"WriteFile":            func() error { return fsutil.WriteFile(p, []byte("after"), 0o600) },
		"AppendFile":           func() error { return fsutil.AppendFile(p, []byte("after"), 0o600) },
		"state.Save":           func() error { st.Enabled = []string{"x"}; return st.Save(statePath) },
		"CopyFile":             func() error { return fsutil.CopyFile(statePath, p) },
		"OpenFile":             func() error { _, err := fsutil.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0); return err },
		"Create":               func() error { _, err := fsutil.Create(filepath.Join(dir, "new")); return err },
		"CreateTemp":           func() error { _, err := fsutil.CreateTemp(dir, "t-*"); return err },
		"MkdirTemp":            func() error { _, err := fsutil.MkdirTemp(dir, "t-*"); return err },
		"Mkdir":                func() error { return fsutil.Mkdir(filepath.Join(dir, "new"), 0o700) },
		"MkdirAll":             func() error { return fsutil.MkdirAll(filepath.Join(dir, "new", "deep"), 0o700) },
		"Remove":               func() error { return fsutil.Remove(p) },
		"RemoveAll":            func() error { return fsutil.RemoveAll(filepath.Join(dir, "sub")) },
		"Rename":               func() error { return fsutil.Rename(p, p+".moved") },
		"Symlink":              func() error { return fsutil.Symlink(p, filepath.Join(dir, "link")) },
		"Chmod":                func() error { return fsutil.Chmod(p, 0o644) },
		"Chown":                func() error { return fsutil.Chown(p, -1, os.Getgid()) },
		"Lchown":               func() error { return fsutil.Lchown(p, -1, os.Getgid()) },
		"Chtimes":              func() error { return fsutil.Chtimes(p, time.Unix(0, 0), time.Unix(0, 0)) },
		"File.Write":           func() error { _, err := held.Write([]byte("x")); return err },
		"File.WriteString":     func() error { _, err := held.WriteString("x"); return err },
		"File.WriteAt":         func() error { _, err := held.WriteAt([]byte("x"), 0); return err },
		"File.ReadFrom(io.Copy)": func() error {
			_, err := io.Copy(held, strings.NewReader("x"))
			return err
		},
		"File.Chmod":        func() error { return held.Chmod(0o644) },
		"File.Chown":        func() error { return held.Chown(-1, os.Getgid()) },
		"File.Truncate":     func() error { return held.Truncate(0) },
		"Root.OpenFile":     func() error { _, err := root.OpenFile("f", os.O_WRONLY|os.O_TRUNC, 0); return err },
		"Root.Create":       func() error { _, err := root.Create("new"); return err },
		"Root.WriteFile":    func() error { return root.WriteFile("f", []byte("after"), 0o600) },
		"Root.Mkdir":        func() error { return root.Mkdir("new", 0o700) },
		"Root.MkdirAll":     func() error { return root.MkdirAll("new/deep", 0o700) },
		"Root.Remove":       func() error { return root.Remove("f") },
		"Root.RemoveAll":    func() error { return root.RemoveAll("sub") },
		"Root.Rename":       func() error { return root.Rename("f", "g") },
		"Root.Symlink":      func() error { return root.Symlink("f", "link") },
		"Root.Chmod":        func() error { return root.Chmod("f", 0o644) },
		"Root.Chown":        func() error { return root.Chown("f", -1, os.Getgid()) },
		"fsutil.CheckWrite": fsutil.CheckWrite,
	}
	for name, w := range writers {
		if err := w(); !errors.Is(err, errStandingBy) {
			t.Errorf("%s = %v, want the gate's error", name, err)
		}
	}
	if digest(t, p) != before || digest(t, statePath) != stateBefore {
		t.Error("a refused write changed a file")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "held")); fi.Size() != 0 {
		t.Errorf("held file has %d bytes", fi.Size())
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode changed: %v", fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != len(entriesBefore) {
		t.Errorf("entries %d, want %d", len(entries), len(entriesBefore))
	}

	// Reads still work while standing by.
	if _, err := os.ReadFile(p); err != nil {
		t.Error(err)
	}
	if f, err := fsutil.OpenFile(p, os.O_RDONLY, 0); err != nil {
		t.Errorf("read-only OpenFile = %v", err)
	} else {
		f.Close()
	}
	if _, err := root.ReadFile("f"); err != nil {
		t.Error(err)
	}
}

// TestTryLockIgnoresGate: the data directory's lock comes before the gate
// (contract §20.5 start order); a standby Hub can still take it.
func TestTryLockIgnoresGate(t *testing.T) {
	closeGate(t)
	release, err := fsutil.TryLock(filepath.Join(t.TempDir(), ".hub.lock"))
	if err != nil {
		t.Fatalf("TryLock with the gate closed = %v", err)
	}
	release()
}

// TestWriteFileAtomicRechecksBeforeRename: the gate open at the start and
// closed by the rename (the write outlived the lead): the error, the old
// file intact, no temp file left.
func TestWriteFileAtomicRechecksBeforeRename(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := digest(t, p)
	calls := 0
	fsutil.SetWriteGate(func() error {
		if calls++; calls == 1 {
			return nil
		}
		return errStandingBy
	})
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	if err := fsutil.WriteFileAtomic(p, []byte("after"), 0o600); !errors.Is(err, errStandingBy) {
		t.Fatalf("WriteFileAtomic = %v", err)
	}
	if calls != 2 {
		t.Errorf("gate asked %d times, want 2", calls)
	}
	if digest(t, p) != before {
		t.Error("the target changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("%d entries: a temp file was left", len(entries))
	}
}

// TestRemoveAllLikeOS: the gated walk keeps os.RemoveAll's behaviour (a
// missing name is nil, a file, a tree, a symlink removed not followed).
func TestRemoveAllLikeOS(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	os.MkdirAll(outside, 0o700)
	os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600)
	tree := filepath.Join(dir, "tree")
	os.MkdirAll(filepath.Join(tree, "a", "b"), 0o700)
	os.WriteFile(filepath.Join(tree, "a", "b", "f"), []byte("x"), 0o600)
	os.Symlink(outside, filepath.Join(tree, "link"))
	for _, n := range []string{"", filepath.Join(dir, "missing")} {
		if err := fsutil.RemoveAll(n); err != nil {
			t.Errorf("RemoveAll(%q) = %v", n, err)
		}
	}
	if err := fsutil.RemoveAll(tree); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(tree); !os.IsNotExist(err) {
		t.Errorf("tree still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("the symlink was followed: %v", err)
	}
	f := filepath.Join(dir, "file")
	os.WriteFile(f, []byte("x"), 0o600)
	root, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.RemoveAll("file"); err != nil {
		t.Fatal(err)
	}
	if err := root.RemoveAll("missing/x"); err != nil {
		t.Errorf("Root.RemoveAll(missing) = %v", err)
	}
	if err := root.RemoveAll("../escape"); err == nil {
		t.Error("Root.RemoveAll escaped the root")
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("file still there: %v", err)
	}
}

// TestOutboundRequestsGated: CheckRequest and GateTransport let reads
// through and refuse every other method while standing by.
func TestOutboundRequestsGated(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	hc := &http.Client{Transport: fsutil.GateTransport(http.DefaultTransport)}
	closeGate(t)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if err := fsutil.CheckRequest(m); !errors.Is(err, errStandingBy) {
			t.Errorf("CheckRequest(%s) = %v", m, err)
		}
		req, _ := http.NewRequest(m, srv.URL, strings.NewReader("x"))
		if _, err := hc.Do(req); !errors.Is(err, errStandingBy) {
			t.Errorf("%s through GateTransport = %v", m, err)
		}
	}
	if hits != 0 {
		t.Errorf("%d writes reached the server", hits)
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if err := fsutil.CheckRequest(m); err != nil {
			t.Errorf("CheckRequest(%s) = %v", m, err)
		}
	}
	if resp, err := hc.Get(srv.URL); err != nil || hits != 1 {
		t.Errorf("GET = %v, hits %d", err, hits)
	} else {
		resp.Body.Close()
	}
}

// TestWriteContext: cancelled at once when the gate is closed, and the
// moment the lost channel closes.
func TestWriteContext(t *testing.T) {
	lost := make(chan struct{})
	fsutil.SetWriteGateLost(lost)
	t.Cleanup(func() { fsutil.SetWriteGateLost(nil) })
	ctx, cancel := fsutil.WriteContext(context.Background())
	defer cancel()
	if ctx.Err() != nil {
		t.Fatal("cancelled while leading")
	}
	close(lost)
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("not cancelled when the gate was lost")
	}
	closeGate(t)
	ctx2, cancel2 := fsutil.WriteContext(context.Background())
	defer cancel2()
	if ctx2.Err() == nil {
		t.Error("a WriteContext while standing by isn't cancelled")
	}
}
