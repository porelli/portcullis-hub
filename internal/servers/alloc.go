package servers

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// The link subnet is fixed in v1 (pre-flight P3): link is .1, workers get
// .10–.250. A revoked server's address is quarantined for Quarantine.
var (
	LinkSubnet = netip.MustParsePrefix("10.214.0.0/24")
	LinkAddr   = netip.MustParseAddr("10.214.0.1")
)

const (
	FirstHost  = 10
	LastHost   = 250
	Quarantine = 7 * 24 * time.Hour
)

// ErrSubnetFull: no worker address is free.
var ErrSubnetFull = errors.New("the link subnet has no free worker address")

// TunnelIPOK reports whether a is a worker address of the link subnet
// (.10–.250; IPv4 only, never 4-in-6).
func TunnelIPOK(a netip.Addr) bool {
	if !a.Is4() || !LinkSubnet.Contains(a) {
		return false
	}
	last := a.As4()[3]
	return last >= FirstHost && last <= LastHost
}

// AllocIP is the lowest free worker address of subnet (which must be the
// link subnet): never one in used, nor one quarantined less than
// Quarantine before now.
func AllocIP(subnet netip.Prefix, used []netip.Addr, quarantined map[netip.Addr]time.Time, now time.Time) (netip.Addr, error) {
	if subnet != LinkSubnet {
		return netip.Addr{}, fmt.Errorf("subnet %s: the link subnet is %s", subnet, LinkSubnet)
	}
	taken := make(map[netip.Addr]bool, len(used))
	for _, u := range used {
		taken[u] = true
	}
	base := subnet.Addr().As4()
	for i := FirstHost; i <= LastHost; i++ {
		b := base
		b[3] = byte(i)
		a := netip.AddrFrom4(b)
		if taken[a] {
			continue
		}
		if at, ok := quarantined[a]; ok && now.Sub(at) < Quarantine {
			continue
		}
		return a, nil
	}
	return netip.Addr{}, ErrSubnetFull
}
