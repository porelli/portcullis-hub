package servers

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestAllocIPSkipsQuarantine(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	ip, err := AllocIP(LinkSubnet, nil, nil, now)
	if err != nil || ip != a("10.214.0.10") {
		t.Fatalf("first: %v %v", ip, err)
	}
	q := map[netip.Addr]time.Time{a("10.214.0.10"): now.Add(-Quarantine + time.Minute)}
	if ip, _ := AllocIP(LinkSubnet, nil, q, now); ip != a("10.214.0.11") {
		t.Errorf("quarantined .10 handed out: %v", ip)
	}
	q[a("10.214.0.10")] = now.Add(-Quarantine)
	if ip, _ := AllocIP(LinkSubnet, nil, q, now); ip != a("10.214.0.10") {
		t.Errorf("after 7 d: %v", ip)
	}
	used := []netip.Addr{a("10.214.0.10"), a("10.214.0.12")}
	if ip, _ := AllocIP(LinkSubnet, used, nil, now); ip != a("10.214.0.11") {
		t.Errorf("lowest free: %v", ip)
	}
	var all []netip.Addr
	for i := 10; i <= 250; i++ {
		all = append(all, a(fmt.Sprintf("10.214.0.%d", i)))
	}
	if _, err := AllocIP(LinkSubnet, all, nil, now); err == nil {
		t.Error("full range: no error")
	}
	if ip, _ := AllocIP(LinkSubnet, all[:240], nil, now); ip != a("10.214.0.250") {
		t.Errorf("last: %v", ip)
	}
	for _, p := range []string{"10.214.1.0/24", "10.214.0.0/23", "fd00::/64"} {
		if _, err := AllocIP(netip.MustParsePrefix(p), nil, nil, now); err == nil {
			t.Errorf("subnet %s accepted (the link subnet is fixed)", p)
		}
	}
	for _, s := range []string{"10.214.0.10", "10.214.0.250"} {
		if !TunnelIPOK(a(s)) {
			t.Errorf("%s not a worker address", s)
		}
	}
	for _, s := range []string{"10.214.0.1", "10.214.0.9", "10.214.0.251", "10.214.0.255", "10.214.1.10", "::ffff:10.214.0.10"} {
		if TunnelIPOK(a(s)) {
			t.Errorf("%s taken for a worker address", s)
		}
	}
}
