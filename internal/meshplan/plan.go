// Package meshplan computes the node mesh's peer plans (contract §20.11):
// for every node of the cluster, its pcmesh peers (endpoint, allowed_ips,
// keepalive) and whether it forwards. Pure: no I/O, deterministic output
// (peers sorted by id, allowed_ips by address). Vectors:
// testdata/meshplan_vectors.json.
package meshplan

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"slices"
	"sort"
)

// The mesh's fixed numbers (§20.11).
const (
	Port      = 51830
	Keepalive = 25
)

// Prefix is the mesh subnet.
var Prefix = netip.MustParsePrefix("10.215.0.0/24")

// Node is one node of the mesh: its id, site, mesh address, its LAN
// endpoint and its public UDP endpoint (zero: none, behind NAT) and its
// WireGuard public key.
type Node struct {
	ID, Site string
	MeshIP   netip.Addr
	LAN      netip.AddrPort
	Public   netip.AddrPort // zero = behind NAT
	Pub      string
}

// Peer is one entry of a node's plan (Endpoint zero: none, the peer is
// learnt from its handshakes).
type Peer struct {
	ID, Pub    string
	Endpoint   netip.AddrPort // zero = none
	AllowedIPs []netip.Prefix
	Keepalive  int
}

// NodePlan is a node's PUT /v1/mesh/peers.
type NodePlan struct {
	Peers   []Peer
	Forward bool
}

// SiteError is the §20.11 refusal: a site of a multi-site mesh has no
// node reachable on UDP 51830.
type SiteError struct{ Site string }

func (e *SiteError) Error() string { return Refusal(e.Site) }

// Refusal is the §20.11 refusal text for site.
func Refusal(site string) string {
	return fmt.Sprintf("site %s needs one node reachable on UDP %d first (a cloud node, or one forwarded port)", site, Port)
}

// ValidKey: s is a WireGuard public key exactly as the nodeagent accepts
// it (§20.4): canonical standard base64 (re-encoding gives s back) of 32
// bytes, not all zero.
func ValidKey(s string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return false
	}
	return !bytes.Equal(b, make([]byte, 32))
}

// KeyID is the identity two keys are compared by: the decoded 32 bytes
// (so non-canonical spellings of one key are the same key), else s itself.
func KeyID(s string) string {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return string(b)
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return string(b)
	}
	return s
}

func reachable(n Node) bool { return n.Public.IsValid() }

// Gateway is site's gateway: its lowest-id reachable node (ids compared as
// strings); false when the site has none.
func Gateway(nodes []Node, site string) (string, bool) {
	best, ok := "", false
	for _, n := range nodes {
		if n.Site == site && reachable(n) && (!ok || n.ID < best) {
			best, ok = n.ID, true
		}
	}
	return best, ok
}

// MissingGateways are the sites (sorted) of a multi-site mesh without a
// reachable node; nothing is validated (a joining node's key may be
// unknown yet).
func MissingGateways(nodes []Node) []string {
	set := map[string]bool{}
	for _, n := range nodes {
		set[n.Site] = true
	}
	if len(set) < 2 {
		return nil
	}
	var out []string
	for s := range set {
		if _, ok := Gateway(nodes, s); !ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Plan is every node's plan, keyed by id. With two or more sites every
// site needs a reachable node, else the refusal for the first such site by
// name (*SiteError).
func Plan(nodes []Node) (map[string]NodePlan, error) {
	plans, missing, err := Degraded(nodes)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		return nil, &SiteError{Site: missing[0]}
	}
	return plans, nil
}

// Bootstrap is a joining node's bootstrap plan (§20.2, §20.11): its plan
// computed as if it were behind NAT (its public endpoint isn't known to
// answer until the Hub reaches it), among the existing nodes. A site
// without a gateway isn't refused here (the joining node may be its
// gateway): the Hub decides once the node reports itself, and a NATed
// pair without a gateway is left out of the plan.
func Bootstrap(nodes []Node, joining Node) (NodePlan, error) {
	j := joining
	j.Public = netip.AddrPort{}
	all := make([]Node, 0, len(nodes)+1)
	for _, n := range nodes {
		if n.ID != j.ID {
			all = append(all, n)
		}
	}
	all = append(all, j)
	plans, _, err := degraded(all, j.ID)
	if err != nil {
		return NodePlan{}, err
	}
	return plans[j.ID], nil
}

// validate (keyless: the one node whose key may be unknown, a joining
// node's bootstrap plan): every key a WireGuard key, unique ids, every mesh address inside 10.215.0.0/24 (not its
// network or broadcast address) and used once, every pcmesh key used
// once (a repeated key would let one node take another's traffic).
func validate(nodes []Node, keyless string) error {
	ids := map[string]bool{}
	byIP := map[netip.Addr]string{}
	byKey := map[string]string{}
	for _, n := range nodes {
		if n.ID == "" || ids[n.ID] {
			return fmt.Errorf("node id %q is empty or repeated", n.ID)
		}
		ids[n.ID] = true
		a := n.MeshIP
		if !a.IsValid() || !a.Is4() || !Prefix.Contains(a) || a.As4()[3] == 0 || a.As4()[3] == 255 {
			return fmt.Errorf("node %s: mesh ip %s outside %s", n.ID, a, Prefix)
		}
		if o, ok := byIP[a]; ok {
			return fmt.Errorf("mesh ip %s is used by both %s and %s", a, o, n.ID)
		}
		byIP[a] = n.ID
		if n.Pub != "" {
			k := KeyID(n.Pub) // by its bytes: every spelling is one key
			if o, ok := byKey[k]; ok {
				return fmt.Errorf("the pcmesh key of %s is already used by %s", n.ID, o)
			}
			byKey[k] = n.ID
		}
		if n.ID != keyless && !ValidKey(n.Pub) {
			return fmt.Errorf("node %s: its pcmesh key isn't a WireGuard key", n.ID)
		}
	}
	return nil
}

// Degraded is Plan without the gateway refusal: the sites (sorted) that
// lack a reachable node in a multi-site mesh are returned instead, and a
// NATed pair at different sites goes through the gateway of whichever of
// its two sites has one (the first by name, as in Plan), or is left out.
// The Hub uses it to keep removing peers while a site has lost its
// gateway (doctor mesh_site_no_gateway); a validation fault is still err.
func Degraded(nodes []Node) (map[string]NodePlan, []string, error) {
	return degraded(nodes, "")
}

func degraded(nodes []Node, keyless string) (map[string]NodePlan, []string, error) {
	if err := validate(nodes, keyless); err != nil {
		return nil, nil, err
	}
	siteSet := map[string]bool{}
	for _, n := range nodes {
		siteSet[n.Site] = true
	}
	sites := make([]string, 0, len(siteSet))
	for s := range siteSet {
		sites = append(sites, s)
	}
	sort.Strings(sites)
	gw := map[string]string{}
	var missing []string
	for _, s := range sites {
		if g, ok := Gateway(nodes, s); ok {
			gw[s] = g
		} else if len(sites) >= 2 {
			missing = append(missing, s)
		}
	}
	// entries[x][y]: x's peer entry for y.
	entries := map[string]map[string]*Peer{}
	forward := map[string]bool{}
	for _, x := range nodes {
		entries[x.ID] = map[string]*Peer{}
	}
	ka := func(x Node) int {
		if reachable(x) {
			return 0
		}
		return Keepalive
	}
	for _, x := range nodes {
		for _, y := range nodes {
			if x.ID == y.ID {
				continue
			}
			same := x.Site == y.Site
			if !same && !reachable(x) && !reachable(y) {
				continue // relayed below
			}
			ep := y.Public
			if same && y.LAN.IsValid() {
				ep = y.LAN
			}
			entries[x.ID][y.ID] = &Peer{ID: y.ID, Pub: y.Pub, Endpoint: ep,
				AllowedIPs: []netip.Prefix{netip.PrefixFrom(y.MeshIP, 32)}, Keepalive: ka(x)}
		}
	}
	// A NATed pair at different sites: both directions through one gateway
	// (C2), the gateway of the pair's site whose name sorts first.
	for i, x := range nodes {
		for _, y := range nodes[i+1:] {
			if x.Site == y.Site || reachable(x) || reachable(y) {
				continue
			}
			first, second := x.Site, y.Site
			if second < first {
				first, second = second, first
			}
			g, ok := gw[first]
			if !ok {
				if g, ok = gw[second]; !ok {
					continue // no path while neither site has a gateway
				}
			}
			ex, ey := entries[x.ID][g], entries[y.ID][g]
			if ex == nil || ey == nil {
				continue // unreachable: a gateway is reachable, so both have it
			}
			ex.AllowedIPs = append(ex.AllowedIPs, netip.PrefixFrom(y.MeshIP, 32))
			ey.AllowedIPs = append(ey.AllowedIPs, netip.PrefixFrom(x.MeshIP, 32))
			forward[g] = true
		}
	}
	out := make(map[string]NodePlan, len(nodes))
	for _, x := range nodes {
		peers := make([]Peer, 0, len(entries[x.ID]))
		for _, p := range entries[x.ID] {
			slices.SortFunc(p.AllowedIPs, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
			peers = append(peers, *p)
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
		out[x.ID] = NodePlan{Peers: peers, Forward: forward[x.ID]}
	}
	return out, missing, nil
}
