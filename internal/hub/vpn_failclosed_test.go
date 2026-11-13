package hub

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
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

// I4: a failed stop while failing closed isn't taken for closed: it is
// retried (under the instance's lifecycle lock) until it succeeds.
func TestVPNFailClosedStopRetried(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	v.h.mu.Lock()
	v.h.testOverrideWriteErr = func(path string) error {
		if strings.HasSuffix(path, "cloud.override.yml") {
			return errors.New("disk full")
		}
		return nil
	}
	v.h.mu.Unlock()
	v.runner.mu.Lock()
	v.runner.byNameErr = errors.New("engine unverified")
	v.runner.mu.Unlock()
	if err := v.h.SetVPNProvider(ctx, root, "mesh", false, 0); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	v.h.vpnrt.mu.Lock()
	f := v.h.vpnrt.renderFail["cloud"]
	closing, closed := f != nil && f.closing, f != nil && f.closed
	v.h.vpnrt.mu.Unlock()
	if !closing || closed {
		t.Fatalf("closing %v closed %v after a failed stop", closing, closed)
	}
	if !v.h.vpnRenderRetryDue() {
		t.Fatal("a failed stop isn't retried")
	}
	v.runner.mu.Lock()
	v.runner.byNameErr = nil
	v.runner.mu.Unlock()
	v.h.vpnRangesChanged()
	v.h.vpnrt.mu.Lock()
	closed = f.closed
	v.h.vpnrt.mu.Unlock()
	if !closed {
		t.Fatal("the retried stop didn't close it")
	}
	n := 0
	for _, e := range v.audit.entries {
		if e.Action == "vpn.reach_failed_closed" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d audits, want the failure and the stop", n)
	}
}

// I2: the committed render keys survive a restart, and at start running
// labels the rendering narrowed restart the instance.
func TestVPNRenderKeysPersistAndStartCheck(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	v.h.vpnrt.mu.Lock()
	want := v.h.vpnrt.rendered["cloud"]
	clear(v.h.vpnrt.rendered) // a restart forgets memory
	v.h.vpnrt.mu.Unlock()
	v.h.loadVPNRendered()
	v.h.vpnrt.mu.Lock()
	got := v.h.vpnrt.rendered["cloud"]
	v.h.vpnrt.mu.Unlock()
	if got == "" || got != want {
		t.Fatalf("persisted key %q, want %q", got, want)
	}
	ups := func() int {
		n := 0
		for _, c := range v.runner.Calls() {
			if strings.HasPrefix(c, "up:portcullis-cloud") {
				n++
			}
		}
		return n
	}
	// A narrowing after the "restart" restarts the instance.
	n := ups()
	if err := v.h.SetVPNProvider(ctx, root, "mesh", false, 0); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	if ups() == n {
		t.Fatal("a narrowing after a restart wasn't applied")
	}
	// Start check: a running container still on the old, wider labels.
	v.engine.mu.Lock()
	c := container("cloud-old", "portcullis-cloud", "cloud", "running")
	c.Labels["traefik.http.routers.cloud.entrypoints"] = "websecure,vpnsecure"
	v.engine.containers = append(v.engine.containers, c)
	v.engine.mu.Unlock()
	n = ups()
	v.h.vpnStartCheck(ctx, v.h.engine)
	v.h.Wait()
	if ups() == n {
		t.Fatal("the start check didn't restart an instance with wider running labels")
	}
}

// I7: the access follows inputs that move without a Hub call: the
// built-in subnet (status.json), a provider's ranges (a cidr setting:
// also re-checked for overlaps) and the core env's mode.
func TestVPNTickFollowsMovedInputs(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	// The built-in subnet moves.
	st := `{"version":1,"written":"` + v.clock().Format(time.RFC3339) + `","mode":"apps","edge":{"ok":true,"error":""},"people":{"ok":true,"error":"","public_key":"` + vpnServerKey + `","port":51820,"subnet":"10.215.0.0/22","mtu":1280,"peers":[]}}`
	writeFile(t, v.status, st)
	v.h.vpnTick(ctx)
	v.h.Wait()
	if ov := overrideOf(t, v, "cloud"); !strings.Contains(ov, "10.215.0.0/22") || strings.Contains(ov, "10.213.0.0/22") {
		t.Fatalf("built-in subnet not followed:\n%s", ov)
	}
	// The provider's range moves onto a container network: re-rendered,
	// and left out of vpn.json.
	v.engine.mu.Lock()
	v.engine.networks = []docker.Network{{Name: "app_default", Subnets: []netip.Prefix{netip.MustParsePrefix("100.100.0.0/16")}}}
	v.engine.mu.Unlock()
	v.h.mu.Lock()
	v.h.findLocked("mesh").Manifest.VPN.Ranges = []string{"100.100.0.0/16"}
	v.h.mu.Unlock()
	v.advance(31 * time.Second) // the overlap re-check is throttled
	writeFile(t, v.status, strings.Replace(st, vpnT0.Format(time.RFC3339), v.clock().Format(time.RFC3339), 1))
	v.h.vpnTick(ctx)
	v.h.Wait()
	if ov := overrideOf(t, v, "cloud"); !strings.Contains(ov, "100.100.0.0/16") {
		t.Fatalf("provider range not followed:\n%s", ov)
	}
	for _, p := range v.doc(t).Providers {
		if p.ID == "mesh" {
			t.Fatal("an overlapping provider published")
		}
	}
	// The core env's mode moves to server: grafana-like internet apps go
	// VPN-only (mesh's own non-control routers).
	writeFile(t, filepath.Join(v.project, ".env"), "CORE_VAR=core-value\nPORTCULLIS_VPN_BUILTIN=on\nPORTCULLIS_VPN_NET=172.31.254.0/26\nPORTCULLIS_VPN_MODE=server\n")
	v.writeStatus(t, true)
	v.h.vpnTick(ctx)
	v.h.Wait()
	if ov := overrideOf(t, v, "mesh"); !strings.Contains(ov, "portcullis-vpnonly-mesh") {
		t.Fatalf("mode change not followed:\n%s", ov)
	}
}
