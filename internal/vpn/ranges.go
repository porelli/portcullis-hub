package vpn

import (
	"fmt"
	"net/netip"
)

// ParseRanges parses client ranges: IPv4 prefixes in canonical form
// (no host bits), /8–/30, pairwise disjoint.
func ParseRanges(rs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(rs))
	for _, r := range rs {
		p, err := netip.ParsePrefix(r)
		if err != nil || !p.Addr().Is4() || p.Masked() != p || p.Bits() < 8 || p.Bits() > 30 || p.String() != r {
			return nil, fmt.Errorf("range %q is not an IPv4 prefix between /8 and /30", r)
		}
		for _, q := range out {
			if q.Overlaps(p) {
				return nil, fmt.Errorf("range %s overlaps %s", q, p)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// FirstOverlap is the first pair (one of a, one of b) that overlap.
func FirstOverlap(a, b []netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	for _, x := range a {
		for _, y := range b {
			if x.Overlaps(y) {
				return x, y, true
			}
		}
	}
	return netip.Prefix{}, netip.Prefix{}, false
}

// Strings is ps as strings.
func Strings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
