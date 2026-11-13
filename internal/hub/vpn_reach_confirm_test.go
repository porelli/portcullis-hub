package hub

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// aiNoConfirm is a Portcullis MCP actor that consumed no confirmation.
var aiNoConfirm = directory.Actor{User: "root", Via: directory.ViaAI, Client: "claude"}

func storedReach(v *vpnFixture, id string) (state.Reach, bool) {
	v.h.mu.RLock()
	defer v.h.mu.RUnlock()
	r, ok := v.h.st.Reach[id]
	return r, ok
}

// An empty via is stored as [] (no provider, deny-all), never as "*":
// it narrows, so it needs no confirmation; only an explicit ["*"] is
// every provider. The decision is SetInstanceReach's own, on the value
// it stores.
func TestReachEmptyViaNeverAny(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	mesh := state.Reach{Mode: state.ReachVPN, Via: []string{"mesh"}}
	empty := state.Reach{Mode: state.ReachVPN, Via: []string{}}
	anyR := state.Reach{Mode: state.ReachVPN, Via: []string{"*"}}

	// internet → [] without a confirmation: stored as [], narrowing.
	if !v.h.ReachChangeNarrows("cloud", empty) {
		t.Fatal("internet → [] isn't a narrowing")
	}
	if err := v.h.SetInstanceReach(ctx, aiNoConfirm, "cloud", empty); err != nil {
		t.Fatal(err)
	}
	if r, ok := storedReach(v, "cloud"); !ok || r.Mode != state.ReachVPN || len(r.Via) != 0 {
		t.Fatalf("stored %+v %v, want vpn via []", r, ok)
	}
	v.h.Wait()
	if ov := overrideOf(t, v, "cloud"); !strings.Contains(ov, `ipallowlist.sourcerange": "0.0.0.0/32"`) {
		t.Fatalf("[] isn't deny-all:\n%s", ov)
	}
	// [] → ["*"] widens: refused without a confirmation, stored unchanged.
	if v.h.ReachChangeNarrows("cloud", anyR) {
		t.Fatal("[] → * counted as narrowing")
	}
	if err := v.h.SetInstanceReach(ctx, aiNoConfirm, "cloud", anyR); statusCode(err) != 409 {
		t.Fatalf("[] → * without a confirmation: %v", err)
	}
	if r, _ := storedReach(v, "cloud"); len(r.Via) != 0 {
		t.Fatalf("a refused widening was stored: %+v", r)
	}
	// With a consumed confirmation (or by a person) it goes through.
	conf := aiNoConfirm
	conf.Confirmation = "c-1"
	if err := v.h.SetInstanceReach(ctx, conf, "cloud", mesh); err != nil {
		t.Fatal(err)
	}
	// [mesh] → [] narrows: no confirmation needed.
	if !v.h.ReachChangeNarrows("cloud", empty) {
		t.Fatal("[mesh] → [] isn't a narrowing")
	}
	if err := v.h.SetInstanceReach(ctx, aiNoConfirm, "cloud", empty); err != nil {
		t.Fatal(err)
	}
	if r, _ := storedReach(v, "cloud"); r.Via == nil || len(r.Via) != 0 {
		t.Fatalf("stored %+v, want via []", r)
	}
	// A person in the browser needs no MCP confirmation.
	if err := v.h.SetInstanceReach(ctx, root, "cloud", anyR); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
}

// The check and the store are one step under the Hub's lock: an AI
// change made without a confirmation never widens, whatever runs
// between its classing and its store.
func TestReachConfirmNoCheckThenActGap(t *testing.T) {
	v := newReachFixture(t, VPNModeApps)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	setReach(t, v, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"*"}})
	// An AI call classed W (* → [mesh] narrows) while a person flips the
	// reach between * and [] (from [] the same call widens).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			via := []string{"*"}
			if i%2 == 0 {
				via = []string{}
			}
			_ = v.h.SetInstanceReach(ctx, root, "cloud", state.Reach{Mode: state.ReachVPN, Via: via})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			_ = v.h.SetInstanceReach(ctx, aiNoConfirm, "cloud", state.Reach{Mode: state.ReachVPN, Via: []string{"mesh"}})
		}
	}()
	wg.Wait()
	v.h.Wait()
	// Every AI change that went through started from * (a narrowing);
	// none from [] (a widening) or from [mesh] to itself is fine too.
	for _, e := range v.audit.entries {
		if e.Action != "instance.reach" || e.Via != directory.ViaAI {
			continue
		}
		if e.Result == "ok" && !slices.Contains([]string{"vpn via=* -> vpn via=mesh"}, e.Detail) {
			t.Errorf("an unconfirmed AI change widened: %q", e.Detail)
		}
	}
}
