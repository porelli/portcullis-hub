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
	k := func(r, gw, edge, pl string) string {
		return "r=" + r + "|via=|gw=" + gw + "|edge=" + edge + "|pl=" + pl
	}
	kv := func(via string) string { return "r=10.0.0.0/8|via=" + via + "|gw=|edge=|pl=0" }
	for _, c := range []struct {
		name, prev, next string
		want             bool
	}{
		{"internet → vpn", k("", "", "", "0"), k("10.0.0.0/8", "", "", "0"), true},
		{"vpn → internet", k("10.0.0.0/8", "", "", "0"), k("", "", "", "0"), false},
		{"a range dropped", k("10.0.0.0/8,100.64.0.0/10", "", "", "0"), k("10.0.0.0/8", "", "", "0"), true},
		{"a range added", k("10.0.0.0/8", "", "", "0"), k("10.0.0.0/8,100.64.0.0/10", "", "", "0"), false},
		{"to no client", k("10.0.0.0/8", "", "", "0"), k("0.0.0.0/32", "", "", "0"), true},
		{"from no client", k("0.0.0.0/32", "", "", "0"), k("10.0.0.0/8", "", "", "0"), false},
		{"gateway lost", k("", "172.31.254.16", "172.31.254.3:9001", "0"), k("", "", "", "0"), true},
		{"gateway moved", k("", "172.31.254.16", "172.31.254.3:9001", "0"), k("", "172.31.254.17", "172.31.254.3:9002", "0"), true},
		{"gateway added", k("", "", "", "0"), k("", "172.31.254.16", "172.31.254.3:9001", "0"), false},
		{"public links off", k("", "", "", "1"), k("", "", "", "0"), true},
		{"public links on", k("", "", "", "0"), k("", "", "", "1"), false},
		{"an unknown field changes", k("", "", "", "0") + "|x=1", k("", "", "", "0") + "|x=2", true},
		{"an unknown field appears", k("", "", "", "0"), k("", "", "", "0") + "|x=1", true},
		{"equal", k("10.0.0.0/8", "a", "b", "1"), k("10.0.0.0/8", "a", "b", "1"), false},
		{"via * → [builtin]", kv("*"), kv("builtin"), true},
		{"via [builtin] → *", kv("builtin"), kv("*"), false},
		{"via [a,b] → [a]", kv("a,b"), kv("a"), true},
		{"via [a] → [a,b]", kv("a"), kv("a,b"), false},
	} {
		if got := vpnNarrows(c.prev, c.next); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// A narrowing change while an earlier failure is in backoff fails
// closed at once (compared against the committed key).
func TestVPNNarrowingDuringBackoff(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	if err := v.h.Enable("wgplain"); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	v.wire(t, "wgplain")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	var failing atomic.Bool
	v.h.mu.Lock()
	v.h.testOverrideWriteErr = func(path string) error {
		if failing.Load() && strings.HasSuffix(path, "cloud.override.yml") {
			return errors.New("disk full")
		}
		return nil
	}
	v.h.mu.Unlock()
	failing.Store(true)
	// A widening failure first (nothing to widen here: force a re-render
	// with the same ranges by marking it failed): backoff, not closed.
	v.h.vpnrt.mu.Lock()
	v.h.vpnrt.renderFail["cloud"] = &vpnRenderRetry{next: v.clock().Add(time.Minute), delay: time.Minute}
	v.h.vpnrt.mu.Unlock()
	v.h.vpnRangesChanged()
	if len(v.h.vpnFailedClosed()) != 0 {
		t.Fatal("closed without a narrowing change")
	}
	// Now a narrowing change inside the backoff window: closed at once.
	if err := v.h.SetVPNProvider(ctx, root, "wgplain", false, 0); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	if !slices.Equal(v.h.vpnFailedClosed(), []string{"cloud"}) {
		t.Fatalf("a narrowing change in backoff didn't fail closed: %v", v.h.vpnFailedClosed())
	}
}
