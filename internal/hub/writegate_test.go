package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/leader"
)

// TestRunGitAsksTheGate: clone, pull and reset write a checkout and are
// refused while standing by (contract §20.5); rev-parse only reads.
func TestRunGitAsksTheGate(t *testing.T) {
	standBy := errors.New("this Hub is standing by: another Hub is the active writer")
	fsutil.SetWriteGate(func() error { return standBy })
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	dir := t.TempDir()
	for _, args := range [][]string{
		{"clone", "--depth=1", "--", "https://example.invalid/x.git", dir + "/x"},
		{"-C", dir, "pull", "--ff-only"},
		{"-C", dir, "reset", "--keep", "HEAD"},
	} {
		if _, err := runGit(time.Second, args...); !errors.Is(err, standBy) {
			t.Errorf("git %v = %v, want the gate's error", args, err)
		}
	}
	if _, err := runGit(5*time.Second, "-C", dir, "rev-parse", "HEAD"); errors.Is(err, standBy) {
		t.Error("rev-parse was refused")
	}
}

// TestGitKilledAtStandBy: a writing git that started while leading is
// killed (its process group: the child that would write too) the moment
// the fence stands by; the fence runs on an injected clock.
func TestGitKilledAtStandBy(t *testing.T) {
	bin := t.TempDir()
	mark := filepath.Join(t.TempDir(), "written")
	// The fake git: a child sleeps, then writes (a checkout landing late).
	script := "#!/bin/sh\n(sleep 2; echo late > \"$GIT_MARK\") &\nwait\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GIT_MARK", mark)

	cs := fake.NewSimpleClientset(&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "portcullis-hub", Namespace: "portcullis"}})
	var cut atomic.Bool
	cs.PrependReactor("*", "leases", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		if cut.Load() {
			return true, nil, errors.New("connection refused")
		}
		return false, nil, nil
	})
	clk := clocktesting.NewFakeClock(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	f := leader.New(leader.Config{Client: cs, Namespace: "portcullis", Name: "portcullis-hub", Identity: "hub-0", Clock: clk})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	if err := f.WaitLeading(wctx); err != nil {
		t.Fatal(err)
	}
	cut.Store(true)
	fsutil.SetWriteGate(f.Check)
	fsutil.SetWriteGateLost(f.Lost())
	t.Cleanup(func() { fsutil.SetWriteGate(nil); fsutil.SetWriteGateLost(nil) })

	done := make(chan error, 1)
	started := time.Now()
	go func() {
		_, err := runGit(time.Minute, "clone", "--", "https://example.invalid/x.git", filepath.Join(t.TempDir(), "x"))
		done <- err
	}()
	time.Sleep(300 * time.Millisecond) // git is running
	clk.Step(10 * time.Second)         // renewal + 10 s: stand by
	select {
	case err := <-done:
		if !errors.Is(err, leader.ErrStandingBy) {
			t.Errorf("git = %v, want ErrStandingBy", err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("git still running after the stand-by")
	}
	if d := time.Since(started); d > 2*time.Second {
		t.Errorf("git ended after %s", d)
	}
	time.Sleep(2500 * time.Millisecond) // past the child's write
	if _, err := os.Stat(mark); !os.IsNotExist(err) {
		t.Errorf("the killed git's child still wrote: %v", err)
	}
}
