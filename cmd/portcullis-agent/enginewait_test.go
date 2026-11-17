package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

// slowEngine answers /version as Docker only from ready on (the socket
// proxy still starting before), or never (ready zero), or as Podman.
type slowEngine struct {
	ready  time.Time
	podman bool
}

func (e slowEngine) Components(context.Context) ([]docker.Component, error) {
	if e.podman {
		return []docker.Component{{Name: "Podman Engine", Version: "5.4.2"}}, nil
	}
	if e.ready.IsZero() || time.Now().Before(e.ready) {
		return nil, errors.New("dial tcp socket-proxy-agent:2375: connection refused")
	}
	return []docker.Component{{Name: "Engine", Version: "29.0.0"}}, nil
}

// TestWaitEngineBeforeStart (core e2e dind): the start waits for the
// guard's first verification (an engine ready after 2 s: started); one
// that never verifies is refused with the time-out (and the last error);
// another runtime is refused as a failed check.
func TestWaitEngineBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := docker.NewGuard(runtime.KindDocker)
	go g.Run(ctx, slowEngine{ready: time.Now().Add(2 * time.Second)}, 200*time.Millisecond)
	start := time.Now()
	if err := waitEngine(ctx, g, 30*time.Second); err != nil {
		t.Fatalf("ready after 2 s: %v", err)
	}
	if d := time.Since(start); d < 1500*time.Millisecond || d > 10*time.Second {
		t.Errorf("waited %s", d)
	}

	never := docker.NewGuard(runtime.KindDocker)
	go never.Run(ctx, slowEngine{}, 100*time.Millisecond)
	err := waitEngine(ctx, never, 700*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "wasn't verified within 700ms (timed out)") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("never verified: %v", err)
	}

	other := docker.NewGuard(runtime.KindDocker)
	go other.Run(ctx, slowEngine{podman: true}, 100*time.Millisecond)
	if err := waitEngine(ctx, other, 5*time.Second); err == nil || !strings.Contains(err.Error(), "failed its start-time check") {
		t.Errorf("another runtime: %v", err)
	}
}
