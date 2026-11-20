package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

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
	host := func(h string, err error) func() (string, error) { return func() (string, error) { return h, err } }
	if got, err := podNameFromEnv(env("portcullis-hub-7d9-x"), host("h", nil)); err != nil || got != "portcullis-hub-7d9-x" {
		t.Errorf("POD_NAME: %q %v", got, err)
	}
	if got, err := podNameFromEnv(env(""), host("pod-from-hostname", nil)); err != nil || got != "pod-from-hostname" {
		t.Errorf("hostname: %q %v", got, err)
	}
	if _, err := podNameFromEnv(env(" "), host("", errors.New("no"))); err == nil {
		t.Error("no identity accepted")
	}
}
