package hub

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/state"
)

// Security ruling: a VPN re-render's key is committed only after the
// override was written; a narrowing change that can't be written stops
// the instance (fail closed) until a render succeeds; a widening one only
// retries.
func TestVPNRenderFailClosed(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	v.h.vpnrt.mu.Lock()
	before := v.h.vpnrt.rendered["cloud"]
	v.h.vpnrt.mu.Unlock()
	if !strings.Contains(before, "100.64.0.0/10") {
		t.Fatalf("key %q", before)
	}
	var failing atomic.Bool
	v.h.mu.Lock()
	v.h.testOverrideWriteErr = func(path string) error {
		if failing.Load() && strings.HasSuffix(path, "cloud.override.yml") {
			return errors.New("disk full")
		}
		return nil
	}
	v.h.mu.Unlock()
	downs := func() int {
		n := 0
		for _, c := range v.runner.Calls() {
			if strings.HasPrefix(c, "downbyname") && strings.Contains(c, "portcullis-cloud") {
				n++
			}
		}
		return n
	}

	// Narrowing (mesh unwired: its range leaves the allowlist) fails.
	failing.Store(true)
	if err := v.h.SetVPNProvider(ctx, root, "mesh", false, 0); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	v.h.vpnrt.mu.Lock()
	kept := v.h.vpnrt.rendered["cloud"]
	v.h.vpnrt.mu.Unlock()
	if kept != before {
		t.Fatalf("a failed write committed the key: %q", kept)
	}
	if downs() != 1 || !slices.Equal(v.h.vpnFailedClosed(), []string{"cloud"}) {
		t.Fatalf("not failed closed: downs %d closed %v calls %v", downs(), v.h.vpnFailedClosed(), v.runner.Calls())
	}
	audited := false
	for _, e := range v.audit.entries {
		if e.Action == "vpn.reach_failed_closed" && e.Target == "cloud" && e.Result == "error" && strings.Contains(e.Error, "disk full") {
			audited = true
		}
	}
	if !audited {
		t.Fatal("no vpn.reach_failed_closed audit")
	}
	if op := v.h.LastOp("cloud"); op == nil || op.OK || !strings.Contains(op.Error, "stopped") {
		t.Fatalf("op %+v", op)
	}
	// Retried with backoff, not stopped twice.
	v.h.vpnRangesChanged()
	if downs() != 1 {
		t.Fatal("stopped again before the retry was due")
	}
	v.advance(6 * time.Second)
	v.writeStatus(t, true)
	v.h.vpnRangesChanged()
	if downs() != 1 {
		t.Fatal("a closed instance was stopped twice")
	}
	// Recovery: the next render succeeds; the instance starts again.
	failing.Store(false)
	v.advance(11 * time.Second)
	v.writeStatus(t, true)
	v.h.vpnRangesChanged()
	v.h.Wait()
	if len(v.h.vpnFailedClosed()) != 0 {
		t.Fatal("still failed closed")
	}
	if ov := overrideOf(t, v, "cloud"); strings.Contains(ov, "100.64.0.0/10") {
		t.Fatalf("recovered override still accepts mesh:\n%s", ov)
	}
	ups := 0
	for _, c := range v.runner.Calls() {
		if strings.HasPrefix(c, "up") && strings.Contains(c, "portcullis-cloud") {
			ups++
		}
	}
	if ups == 0 {
		t.Fatalf("not started again: %v", v.runner.Calls())
	}

	// Widening (mesh wired again) failing: retried and logged, never stopped.
	failing.Store(true)
	n := downs()
	v.wire(t, "mesh")
	v.h.runVPNProvider(ctx, "mesh")
	v.h.vpnRangesChanged()
	v.h.Wait()
	if downs() != n || len(v.h.vpnFailedClosed()) != 0 {
		t.Fatalf("a widening failure stopped the instance")
	}
	v.h.vpnrt.mu.Lock()
	f := v.h.vpnrt.renderFail["cloud"]
	v.h.vpnrt.mu.Unlock()
	if f == nil || f.closed {
		t.Fatalf("widening failure not retried: %+v", f)
	}
}

func TestVPNNarrows(t *testing.T) {
	for _, c := range []struct {
		prev, next string
		want       bool
	}{
		{"|", "10.0.0.0/8|", true},
		{"10.0.0.0/8|", "|", false},
		{"10.0.0.0/8,100.64.0.0/10|", "10.0.0.0/8|", true},
		{"10.0.0.0/8|", "10.0.0.0/8,100.64.0.0/10|", false},
		{"10.0.0.0/8|", "0.0.0.0/32|", true},
		{"0.0.0.0/32|", "10.0.0.0/8|", false},
		{"10.0.0.0/8|1|2", "10.0.0.0/8|", false},
	} {
		if got := vpnNarrows(c.prev, c.next); got != c.want {
			t.Errorf("%q → %q: %v", c.prev, c.next, got)
		}
	}
}
