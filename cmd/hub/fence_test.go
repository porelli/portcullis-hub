package main

import (
	"context"
	"errors"
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

// TestDockerFenceIsOpen: Docker and Podman (no Lease) lead from the
// start: startFence returns at once, the gate is open, writes behave as
// before and lost never runs.
func TestDockerFenceIsOpen(t *testing.T) {
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	lost := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { startFence(ctx, leader.Always(), func() { lost <- struct{}{} }); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startFence waited with Always")
	}
	if err := fsutil.CheckWrite(); err != nil {
		t.Fatalf("gate = %v", err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(t.TempDir(), "state.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-lost:
		t.Error("lost ran for Always")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPodNameFromEnv(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if got, err := podNameFromEnv(env("portcullis-hub-7d9-x")); err != nil || got != "portcullis-hub-7d9-x" {
		t.Errorf("POD_NAME: %q %v", got, err)
	}
	for _, v := range []string{"", " "} {
		if _, err := podNameFromEnv(env(v)); err == nil {
			t.Errorf("POD_NAME %q accepted (no hostname fallback)", v)
		}
	}
}

// TestStartFenceStandBy: on Kubernetes startFence installs the fence as
// the gate and its Lost channel; at renewal + 10 s (injected clock) a
// running WriteContext is cancelled, writes are refused and lost runs.
func TestStartFenceStandBy(t *testing.T) {
	t.Cleanup(func() { fsutil.SetWriteGate(nil); fsutil.SetWriteGateLost(nil) })
	cs := fake.NewSimpleClientset(&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: "portcullis"}})
	var cut atomic.Bool
	cs.PrependReactor("*", "leases", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		if cut.Load() {
			return true, nil, errors.New("connection refused")
		}
		return false, nil, nil
	})
	clk := clocktesting.NewFakeClock(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	f := leader.New(leader.Config{Client: cs, Namespace: "portcullis", Name: leaseName, Identity: "hub-0", Clock: clk})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lost := make(chan struct{})
	startFence(ctx, f, func() { close(lost) })
	cut.Store(true)
	wctx, wcancel := fsutil.WriteContext(context.Background())
	defer wcancel()
	if err := fsutil.CheckWrite(); err != nil {
		t.Fatalf("gate while leading = %v", err)
	}
	clk.Step(10 * time.Second)
	for _, c := range []struct {
		name string
		ch   <-chan struct{}
	}{{"WriteContext", wctx.Done()}, {"lost", lost}, {"Lost", f.Lost()}} {
		select {
		case <-c.ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s not closed at the stand-by", c.name)
		}
	}
	if err := fsutil.CheckWrite(); !errors.Is(err, leader.ErrStandingBy) {
		t.Errorf("gate after the stand-by = %v", err)
	}
}
