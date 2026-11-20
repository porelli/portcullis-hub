package meshplan

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/jsonstrict"
)

func loadVectors(t *testing.T) []meshPlanVector {
	t.Helper()
	b, err := os.ReadFile("testdata/meshplan_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []meshPlanVector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func toNode(n meshNode) Node {
	out := Node{ID: n.ID, Site: n.Site, Pub: n.Pub}
	out.MeshIP, _ = netip.ParseAddr(n.MeshIP)
	if n.LAN.Valid {
		out.LAN = n.LAN.V
	}
	if n.Public.Valid {
		out.Public = n.Public.V
	}
	return out
}

func wantPlan(nodes []meshNode, p meshNodePlan) NodePlan {
	pub := map[string]string{}
	for _, n := range nodes {
		pub[n.ID] = n.Pub
	}
	out := NodePlan{Peers: []Peer{}, Forward: p.Forward}
	for _, q := range p.Peers {
		e := Peer{ID: q.ID, Pub: pub[q.ID], AllowedIPs: q.AllowedIPs, Keepalive: q.Keepalive}
		if q.Endpoint.Valid {
			e.Endpoint = q.Endpoint.V
		}
		out.Peers = append(out.Peers, e)
	}
	return out
}

// TestMeshPlanVectors: every vector: Plan(nodes) == want, or the exact
// want_error; a bootstrap case: Bootstrap(the others, the joining node)
// == the joining node's want.
func TestMeshPlanVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		var nodes []Node
		var joining Node
		for _, n := range v.Nodes {
			if n.ID == v.Bootstrap {
				joining = toNode(n)
				continue
			}
			nodes = append(nodes, toNode(n))
		}
		if v.Bootstrap != "" {
			got, err := Bootstrap(nodes, joining)
			if err != nil {
				t.Errorf("%s: %v", v.Name, err)
				continue
			}
			if want := wantPlan(v.Nodes, v.Want.V[v.Bootstrap]); !reflect.DeepEqual(got, want) {
				t.Errorf("%s:\n got %+v\nwant %+v", v.Name, got, want)
			}
			continue
		}
		got, err := Plan(nodes)
		if v.WantError != "" {
			if err == nil || err.Error() != v.WantError {
				t.Errorf("%s: err %v, want %q", v.Name, err, v.WantError)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if len(got) != len(v.Want.V) {
			t.Errorf("%s: %d plans, want %d", v.Name, len(got), len(v.Want.V))
		}
		for id, wp := range v.Want.V {
			if want := wantPlan(v.Nodes, wp); !reflect.DeepEqual(got[id], want) {
				t.Errorf("%s: %s\n got %+v\nwant %+v", v.Name, id, got[id], want)
			}
		}
	}
}

func n(id, site string, ip int, public bool) Node {
	nd := Node{ID: id, Site: site, MeshIP: netip.AddrFrom4([4]byte{10, 215, 0, byte(ip)}),
		LAN: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, byte(len(site)), byte(ip)}), Port), Pub: testKey(id)}
	if public {
		nd.Public = netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(ip)}), Port)
	}
	return nd
}

// testKey is a WireGuard key made from id.
func testKey(id string) string {
	b := make([]byte, 32)
	copy(b, "key:"+id)
	return base64.StdEncoding.EncodeToString(b)
}

func peerOf(p NodePlan, id string) (Peer, bool) {
	for _, q := range p.Peers {
		if q.ID == id {
			return q, true
		}
	}
	return Peer{}, false
}

func slash32(x Node) netip.Prefix { return netip.PrefixFrom(x.MeshIP, 32) }

// TestNATedPairRelaysViaGateway: a@main NAT, b@edge NAT, gw(edge)=e1:
// both directions go through e1 (edge sorts first): a's peer e1 lists
// b/32, b's peer e1 lists a/32; a has no direct peer b.
func TestNATedPairRelaysViaGateway(t *testing.T) {
	a, b := n("a", "main", 2, false), n("b", "edge", 6, false)
	m1, e1 := n("m1", "main", 1, true), n("e1", "edge", 5, true)
	nodes := []Node{a, b, m1, e1}
	plans, err := Plan(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := Gateway(nodes, "edge"); !ok || g != "e1" {
		t.Fatalf("gateway(edge) = %q %v", g, ok)
	}
	pa, ok := peerOf(plans["a"], "e1")
	if !ok || !slices.Contains(pa.AllowedIPs, slash32(b)) || pa.Endpoint != e1.Public {
		t.Errorf("a's peer e1: %+v", pa)
	}
	pb, ok := peerOf(plans["b"], "e1")
	if !ok || !slices.Contains(pb.AllowedIPs, slash32(a)) || pb.Endpoint != e1.LAN {
		t.Errorf("b's peer e1: %+v", pb)
	}
	if _, ok := peerOf(plans["a"], "b"); ok {
		t.Error("a has a direct peer b")
	}
	if _, ok := peerOf(plans["b"], "a"); ok {
		t.Error("b has a direct peer a")
	}
	// Never through main's gateway: one hop for both directions (C2).
	if pm, _ := peerOf(plans["b"], "m1"); slices.Contains(pm.AllowedIPs, slash32(a)) {
		t.Errorf("b reaches a through m1: %+v", pm)
	}
	if !plans["e1"].Forward || plans["m1"].Forward {
		t.Errorf("forward e1 %v m1 %v", plans["e1"].Forward, plans["m1"].Forward)
	}
	// The gateway's own entries reach both directly.
	if p, _ := peerOf(plans["e1"], "a"); !slices.Equal(p.AllowedIPs, []netip.Prefix{slash32(a)}) {
		t.Errorf("e1's peer a %+v", p)
	}
}

// relaysAPair: x is the hop of some pair in plans (a peer entry of
// another node lists x and an address that isn't x's).
func relaysAPair(plans map[string]NodePlan, nodes []Node, x string) bool {
	for _, o := range nodes {
		if p, ok := peerOf(plans[o.ID], x); ok && len(p.AllowedIPs) > 1 {
			return true
		}
	}
	return false
}

// TestForwardOnlyOnGateways: forward is true exactly on a site's gateway
// that relays at least one pair (Task 2 concern 4): never on a non-gateway,
// never on a gateway that relays nothing (one site; a site whose NATed
// nodes go through the other site's gateway; no NATed pair).
func TestForwardOnlyOnGateways(t *testing.T) {
	cases := map[string][]Node{
		"one site, NATed nodes":           {n("n1", "main", 1, true), n("n2", "main", 2, false), n("n3", "main", 3, false)},
		"two sites, no NATed pair":        {n("n1", "main", 1, true), n("n2", "main", 2, false), n("e1", "edge", 5, true)},
		"two sites, a NATed pair":         {n("n1", "main", 1, true), n("n2", "main", 2, false), n("e1", "edge", 5, true), n("e2", "edge", 6, false)},
		"three sites":                     {n("n1", "main", 1, true), n("n2", "main", 2, false), n("e1", "edge", 5, true), n("e2", "edge", 6, false), n("t1", "tb", 9, true), n("t2", "tb", 10, false)},
		"two gateways at a site":          {n("n1", "main", 1, true), n("n2", "main", 2, false), n("e1", "edge", 5, true), n("e2", "edge", 6, true), n("e3", "edge", 7, false)},
		"every node public, three sites":  {n("n1", "main", 1, true), n("e1", "edge", 5, true), n("t1", "tb", 9, true)},
		"NATed at main only, cloud edge":  {n("n1", "main", 1, true), n("n2", "main", 2, false), n("n3", "main", 3, false), n("e1", "edge", 5, true)},
		"main relays tb (main before tb)": {n("n1", "main", 1, true), n("n2", "main", 2, false), n("t1", "tb", 9, true), n("t2", "tb", 10, false)},
	}
	for name, nodes := range cases {
		plans, err := Plan(nodes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		gws := map[string]bool{}
		for _, x := range nodes {
			if g, ok := Gateway(nodes, x.Site); ok {
				gws[g] = true
			}
		}
		forwards := 0
		for _, x := range nodes {
			want := gws[x.ID] && relaysAPair(plans, nodes, x.ID)
			if plans[x.ID].Forward != want {
				t.Errorf("%s: %s forward %v, want %v", name, x.ID, plans[x.ID].Forward, want)
			}
			if plans[x.ID].Forward {
				forwards++
			}
		}
		pairs := name == "two sites, a NATed pair" || name == "three sites" || name == "two gateways at a site" || name == "main relays tb (main before tb)"
		if (forwards > 0) != pairs {
			t.Errorf("%s: %d forwarding nodes", name, forwards)
		}
	}
}

// TestKeepaliveOnlyBehindNAT: keepalive 25 on every peer of a node iff the
// node itself has no public endpoint, else 0.
func TestKeepaliveOnlyBehindNAT(t *testing.T) {
	nodes := []Node{n("n1", "main", 1, true), n("n2", "main", 2, false), n("e1", "edge", 5, true), n("e2", "edge", 6, false), n("t1", "tb", 9, true)}
	plans, err := Plan(nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range nodes {
		want := 0
		if !x.Public.IsValid() {
			want = 25
		}
		if len(plans[x.ID].Peers) != len(nodes)-1 && x.Public.IsValid() {
			t.Errorf("%s: %d peers", x.ID, len(plans[x.ID].Peers))
		}
		for _, p := range plans[x.ID].Peers {
			if p.Keepalive != want {
				t.Errorf("%s's peer %s: keepalive %d, want %d", x.ID, p.ID, p.Keepalive, want)
			}
		}
	}
}

// TestDegradedNoGateway: a site that lost its gateway is reported, not
// refused, so a removal can still be pushed: its NATed nodes keep their
// direct peers, and Plan refuses with the §20.11 text.
func TestDegradedNoGateway(t *testing.T) {
	nodes := []Node{n("n1", "main", 1, true), n("n2", "main", 2, false), n("e2", "edge", 6, false), n("e3", "edge", 7, false)}
	plans, missing, err := Degraded(nodes)
	if err != nil || !slices.Equal(missing, []string{"edge"}) {
		t.Fatalf("missing %v err %v", missing, err)
	}
	// e2 ↔ n2 relay through main's gateway (edge has none).
	if p, _ := peerOf(plans["e2"], "n1"); !slices.Contains(p.AllowedIPs, slash32(nodes[1])) {
		t.Errorf("e2's peer n1 %+v", p)
	}
	if p, _ := peerOf(plans["e2"], "e3"); p.Endpoint != nodes[3].LAN {
		t.Errorf("e2's peer e3 %+v", p)
	}
	_, err = Plan(nodes)
	var se *SiteError
	if !errors.As(err, &se) || se.Site != "edge" || err.Error() != "site edge needs one node reachable on UDP 51830 first (a cloud node, or one forwarded port)" {
		t.Errorf("Plan: %v", err)
	}
	// Both sites without a gateway: the pair is left out.
	nodes = []Node{n("n2", "main", 2, false), n("e2", "edge", 6, false)}
	plans, missing, err = Degraded(nodes)
	if err != nil || !slices.Equal(missing, []string{"edge", "main"}) || len(plans["n2"].Peers) != 0 {
		t.Errorf("%v %v %+v", missing, err, plans)
	}
}

// TestPlanDeterministic: the input order never changes the output.
func TestPlanDeterministic(t *testing.T) {
	nodes := []Node{n("n1", "main", 1, true), n("n2", "main", 2, false), n("e1", "edge", 5, true), n("e2", "edge", 6, false), n("t1", "tb", 9, true), n("t2", "tb", 10, false)}
	want, err := Plan(nodes)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		shuf := slices.Clone(nodes)
		for j := range shuf {
			k := (j*7 + i) % len(shuf)
			shuf[j], shuf[k] = shuf[k], shuf[j]
		}
		got, err := Plan(shuf)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal(fmt.Sprint("order ", i, " changed the plan"))
		}
	}
}

// altSpelling is a non-canonical spelling of k (a 32-byte key): the last
// character's two padding bits set, the same 32 bytes.
func altSpelling(k string) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(a, k[42])
	return k[:42] + string(a[i^1]) + k[43:]
}

// TestValidKeyAndKeyID: ValidKey is the nodeagent's check (canonical
// base64 of 32 bytes, not all zero); KeyID makes every spelling of one
// key the same key.
func TestValidKeyAndKeyID(t *testing.T) {
	k := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	alt := altSpelling(k)
	if alt == k || !ValidKey(k) || ValidKey(alt) {
		t.Fatalf("canonical %v, alt %q %v", ValidKey(k), alt, ValidKey(alt))
	}
	if KeyID(k) != KeyID(alt) || KeyID(k) != KeyID(strings.TrimRight(k, "=")) {
		t.Error("spellings of one key differ")
	}
	for _, bad := range []string{"", "x", strings.Repeat("A", 43) + "=", strings.TrimRight(k, "="), "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==", " " + k} {
		if ValidKey(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if KeyID("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=") == KeyID(k) {
		t.Error("two keys collide")
	}
}

// TestPlanRefusesBadKeys: the package checks keys itself (Q-M5): a
// missing or non-WireGuard key is refused by Plan; only Bootstrap's
// joining node may lack one.
func TestPlanRefusesBadKeys(t *testing.T) {
	a, b := n("n1", "main", 1, true), n("n2", "main", 2, false)
	for _, k := range []string{"", "k-n2", altSpelling(testKey("n2")), base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		b.Pub = k
		if _, err := Plan([]Node{a, b}); err == nil || err.Error() != "node n2: its pcmesh key isn't a WireGuard key" {
			t.Errorf("%q: %v", k, err)
		}
	}
	if _, err := Bootstrap([]Node{a}, Node{ID: "j", Site: "main", MeshIP: netip.MustParseAddr("10.215.0.9")}); err != nil {
		t.Errorf("a keyless joiner: %v", err)
	}
	a.Pub = ""
	if _, err := Bootstrap([]Node{a}, Node{ID: "j", Site: "main", MeshIP: netip.MustParseAddr("10.215.0.9")}); err == nil {
		t.Error("a keyless existing node passed")
	}
}
