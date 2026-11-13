package vpn

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestNextFreeQuarantine(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	sub := netip.MustParsePrefix("10.213.0.0/22")
	a, err := NextFree(sub, nil, nil, now)
	if err != nil || a.String() != "10.213.0.2" {
		t.Fatalf("%v %v", a, err)
	}
	q := map[netip.Addr]time.Time{
		netip.MustParseAddr("10.213.0.2"): now.Add(-6 * 24 * time.Hour),
		netip.MustParseAddr("10.213.0.3"): now.Add(-8 * 24 * time.Hour),
	}
	if a, _ := NextFree(sub, nil, q, now); a.String() != "10.213.0.3" {
		t.Fatalf("got %v, want the 8-day-old address reused", a)
	}
	// /30: .0 network, .1 server, .2 the only host, .3 broadcast.
	s30 := netip.MustParsePrefix("10.9.0.0/30")
	if a, _ := NextFree(s30, nil, nil, now); a.String() != "10.9.0.2" {
		t.Fatalf("%v", a)
	}
	if _, err := NextFree(s30, map[netip.Addr]bool{netip.MustParseAddr("10.9.0.2"): true}, nil, now); !errors.Is(err, ErrSubnetFull) {
		t.Fatalf("%v", err)
	}
	// Never .1 or broadcast, whatever is used.
	s29 := netip.MustParsePrefix("10.9.0.0/29")
	used := map[netip.Addr]bool{}
	for {
		a, err := NextFree(s29, used, nil, now)
		if err != nil {
			break
		}
		if a.String() == "10.9.0.0" || a.String() == "10.9.0.1" || a.String() == "10.9.0.7" {
			t.Fatalf("handed out %v", a)
		}
		used[a] = true
	}
	if len(used) != 5 {
		t.Fatalf("%d addresses of a /29", len(used))
	}
	if ServerAddr(sub).String() != "10.213.0.1" {
		t.Fatal("server")
	}
}

func TestGatewayAddrSlots(t *testing.T) {
	n := netip.MustParsePrefix("172.31.254.0/26")
	for slot, want := range map[int]string{0: "172.31.254.16", 1: "172.31.254.17", 46: "172.31.254.62"} {
		a, err := GatewayAddr(n, slot)
		if err != nil || a.String() != want {
			t.Errorf("slot %d: %v %v", slot, a, err)
		}
	}
	if _, err := GatewayAddr(n, 47); err == nil {
		t.Error("slot 47")
	}
	if _, err := GatewayAddr(n, -1); err == nil {
		t.Error("slot -1")
	}
	if _, err := GatewayAddr(netip.MustParsePrefix("172.31.254.0/27"), 0); err == nil {
		t.Error("/27")
	}
	if EdgePort(0) != 9001 || EdgePort(46) != 9047 {
		t.Error("edge ports")
	}
}

func TestStaleAfterFloor(t *testing.T) {
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	if got := StaleAfter(at, 15*time.Second); !got.Equal(at.Add(3 * time.Minute)) {
		t.Error(got)
	}
	if got := StaleAfter(at, 2*time.Minute); !got.Equal(at.Add(6 * time.Minute)) {
		t.Error(got)
	}
}

func TestRanges(t *testing.T) {
	ps, err := ParseRanges([]string{"100.64.0.0/10", "10.8.0.0/24"})
	if err != nil || len(ps) != 2 {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"100.64.0.1/10"}, {"fd00::/8"}, {"10.0.0.0/31"}, {"10.0.0.0/8", "10.1.0.0/16"}, {"x"}} {
		if _, err := ParseRanges(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	a, b, ok := FirstOverlap(ps, []netip.Prefix{netip.MustParsePrefix("10.8.0.128/25")})
	if !ok || a.String() != "10.8.0.0/24" || b.String() != "10.8.0.128/25" {
		t.Fatal(a, b, ok)
	}
	if _, _, ok := FirstOverlap(ps, []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}); ok {
		t.Fatal("no overlap")
	}
}
