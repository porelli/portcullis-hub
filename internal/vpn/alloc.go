package vpn

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ErrSubnetFull: no address of the built-in subnet is free.
var ErrSubnetFull = errors.New("the VPN subnet has no free address")

// NextFree is the lowest free host address of subnet: never the network
// address, the server (.1) or the broadcast address, nor one in used, nor
// one removed (quarantined) less than Quarantine before now.
func NextFree(subnet netip.Prefix, used map[netip.Addr]bool, quarantined map[netip.Addr]time.Time, now time.Time) (netip.Addr, error) {
	subnet = subnet.Masked()
	if !subnet.Addr().Is4() || subnet.Bits() > 30 {
		return netip.Addr{}, fmt.Errorf("subnet %s: an IPv4 prefix of /30 or wider", subnet)
	}
	server := subnet.Addr().Next()
	for a := server.Next(); subnet.Contains(a); a = a.Next() {
		if !subnet.Contains(a.Next()) { // the broadcast address
			break
		}
		if used[a] {
			continue
		}
		if at, ok := quarantined[a]; ok && now.Sub(at) < Quarantine {
			continue
		}
		return a, nil
	}
	return netip.Addr{}, ErrSubnetFull
}

// ServerAddr is the built-in server's tunnel address (.1).
func ServerAddr(subnet netip.Prefix) netip.Addr { return subnet.Masked().Addr().Next() }

// GatewayAddr is wired provider slot's gateway address on the
// portcullis-vpn network: .16 for slot 0 up to .62 for slot 46.
func GatewayAddr(net netip.Prefix, slot int) (netip.Addr, error) {
	net = net.Masked()
	if !net.Addr().Is4() || net.Bits() > 26 {
		return netip.Addr{}, fmt.Errorf("the VPN network %s must be an IPv4 /26 or wider", net)
	}
	if slot < 0 || slot > GatewayLast-GatewayFirst {
		return netip.Addr{}, fmt.Errorf("slot %d: at most %d wired providers", slot, GatewayLast-GatewayFirst+1)
	}
	b := net.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n += uint32(GatewayFirst + slot)
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), nil
}

// EdgePort is slot's edge listener port on wg (9001 + slot).
func EdgePort(slot int) int { return EdgePortBase + slot }

// StaleAfter is when a map refreshed at refreshedAt goes stale:
// 3 × refresh, at least StaleFloor.
func StaleAfter(refreshedAt time.Time, refresh time.Duration) time.Time {
	return refreshedAt.Add(max(3*refresh, StaleFloor))
}
