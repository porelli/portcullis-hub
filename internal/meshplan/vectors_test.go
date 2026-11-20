package meshplan

import (
	"net/netip"
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/portcullis/hub/internal/jsonstrict"
)

type meshNode struct {
	ID     string                              `json:"id"`
	Site   string                              `json:"site"`
	MeshIP string                              `json:"mesh_ip"`
	LAN    jsonstrict.Nullable[netip.AddrPort] `json:"lan"`
	Public jsonstrict.Nullable[netip.AddrPort] `json:"public"`
	Pub    string                              `json:"pub"`
}

type meshPeer struct {
	ID         string                              `json:"id"`
	Endpoint   jsonstrict.Nullable[netip.AddrPort] `json:"endpoint"`
	AllowedIPs []netip.Prefix                      `json:"allowed_ips"`
	Keepalive  int                                 `json:"keepalive"`
}

type meshNodePlan struct {
	Peers   []meshPeer `json:"peers"`
	Forward bool       `json:"forward"`
}

type meshPlanVector struct {
	Name      string                                       `json:"name"`
	Bootstrap string                                       `json:"bootstrap,omitempty"`
	Nodes     []meshNode                                   `json:"nodes"`
	Want      jsonstrict.Nullable[map[string]meshNodePlan] `json:"want,omitempty"`
	WantError string                                       `json:"want_error,omitempty"`
}

// The §20.11 refusal (verbatim) and the three validation texts.
var refusalRe = regexp.MustCompile(`^(site [a-z][a-z0-9-]* needs one node reachable on UDP 51830 first \(a cloud node, or one forwarded port\)|mesh ip 10\.215\.0\.[0-9]+ is used by both [a-z0-9-]+ and [a-z0-9-]+|node [a-z0-9-]+: mesh ip [0-9.]+ outside 10\.215\.0\.0/24|the pcmesh key of [a-z0-9-]+ is already used by [a-z0-9-]+)$`)

// simulatePaths follows every ordered pair x → y through the plans as
// WireGuard routes it (C2): x sends to the peer whose allowed_ips hold y; a
// relay must forward and reach y directly; y accepts the packet only from
// the peer whose allowed_ips hold x, which must be the hop it came from.
// Every hop needs an endpoint on one side, and a /32 sits on one peer only.
func simulatePaths(t *testing.T, v meshPlanVector) {
	t.Helper()
	ip := map[string]netip.Prefix{}
	for _, n := range v.Nodes {
		ip[n.ID] = netip.PrefixFrom(netip.MustParseAddr(n.MeshIP), 32)
	}
	plans := v.Want.V
	holder := func(of, addr string) (meshPeer, bool) {
		var found []meshPeer
		for _, p := range plans[of].Peers {
			if slices.Contains(p.AllowedIPs, ip[addr]) {
				found = append(found, p)
			}
		}
		if len(found) > 1 {
			t.Errorf("%s: %s lists %s on %d peers", v.Name, of, addr, len(found))
		}
		if len(found) == 0 {
			return meshPeer{}, false
		}
		return found[0], true
	}
	entry := func(of, peer string) (meshPeer, bool) {
		for _, p := range plans[of].Peers {
			if p.ID == peer {
				return p, true
			}
		}
		return meshPeer{}, false
	}
	relays := map[string]bool{}
	link := func(a, b string) bool {
		ab, ok1 := entry(a, b)
		ba, ok2 := entry(b, a)
		return ok1 && ok2 && (ab.Endpoint.Valid || ba.Endpoint.Valid)
	}
	for _, x := range v.Nodes {
		for _, y := range v.Nodes {
			if x.ID == y.ID {
				continue
			}
			first, ok := holder(x.ID, y.ID)
			if !ok {
				t.Errorf("%s: %s has no route to %s", v.Name, x.ID, y.ID)
				continue
			}
			hop := first.ID
			if !link(x.ID, hop) {
				t.Errorf("%s: %s → %s: no tunnel to %s", v.Name, x.ID, y.ID, hop)
			}
			if hop != y.ID {
				relays[hop] = true
				if !plans[hop].Forward {
					t.Errorf("%s: %s → %s relays through %s, which doesn't forward", v.Name, x.ID, y.ID, hop)
				}
				if p, ok := holder(hop, y.ID); !ok || p.ID != y.ID || !link(hop, y.ID) {
					t.Errorf("%s: %s → %s: the relay %s doesn't reach %s directly", v.Name, x.ID, y.ID, hop, y.ID)
				}
				if p, ok := holder(hop, x.ID); !ok || p.ID != x.ID {
					t.Errorf("%s: %s → %s: the relay %s doesn't accept %s from it", v.Name, x.ID, y.ID, hop, x.ID)
				}
			}
			from := x.ID // direct: the packet arrives from x itself
			if hop != y.ID {
				from = hop
			}
			if p, ok := holder(y.ID, x.ID); !ok || p.ID != from {
				t.Errorf("%s: %s → %s arrives from %s, but %s takes %s only from %q", v.Name, x.ID, y.ID, from, y.ID, x.ID, p.ID)
			}
		}
	}
	// forward exactly on a node that relays at least one pair (N5).
	for _, n := range v.Nodes {
		if plans[n.ID].Forward && !relays[n.ID] {
			t.Errorf("%s: %s forwards but relays no pair", v.Name, n.ID)
		}
	}
}

// checkBootstrap: a bootstrap case (§20.2, §20.11) wants only the joining
// node's plan, computed as if it were NATed: no forward, keepalive 25 on
// every peer, and an endpoint on every peer (a NATed node must start each
// handshake itself).
func checkBootstrap(t *testing.T, v meshPlanVector) {
	t.Helper()
	p, ok := v.Want.V[v.Bootstrap]
	if len(v.Want.V) != 1 || !ok {
		t.Errorf("%s: a bootstrap case wants exactly the plan of %s", v.Name, v.Bootstrap)
		return
	}
	reported := false
	for _, n := range v.Nodes {
		if n.ID == v.Bootstrap {
			reported = n.Public.Valid
		}
	}
	if !reported {
		t.Errorf("%s: the joining node %s must report a public endpoint (else the case pins nothing)", v.Name, v.Bootstrap)
	}
	if p.Forward || len(p.Peers) == 0 {
		t.Errorf("%s: bootstrap plan %+v", v.Name, p)
	}
	for _, peer := range p.Peers {
		if peer.Keepalive != 25 || !peer.Endpoint.Valid {
			t.Errorf("%s: bootstrap peer %+v: want keepalive 25 and an endpoint", v.Name, peer)
		}
	}
}

// TestMeshPlanVectorsShape: meshplan_vectors.json (contract §20.11)
// decodes strictly; a case has exactly one of want / want_error; a plan
// names every node, its peers sorted by id, never itself, keepalive 0 or
// 25, allowed_ips inside 10.215.0.0/24.
func TestMeshPlanVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/meshplan_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []meshPlanVector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 14 {
		t.Fatalf("%d vectors", len(vs))
	}
	mesh := netip.MustParsePrefix("10.215.0.0/24")
	errs, boots := 0, 0
	for _, v := range vs {
		if v.Want.Valid == (v.WantError != "") {
			t.Errorf("%s: exactly one of want and want_error", v.Name)
			continue
		}
		if !v.Want.Valid {
			errs++
			if !refusalRe.MatchString(v.WantError) {
				t.Errorf("%s: want_error %q isn't the §20.11 refusal or a validation text", v.Name, v.WantError)
			}
			continue
		}
		if v.Bootstrap != "" {
			boots++
			checkBootstrap(t, v)
		} else {
			simulatePaths(t, v)
		}
		if v.Bootstrap == "" && len(v.Want.V) != len(v.Nodes) {
			t.Errorf("%s: %d plans for %d nodes", v.Name, len(v.Want.V), len(v.Nodes))
		}
		for _, n := range v.Nodes {
			p, ok := v.Want.V[n.ID]
			if !ok && v.Bootstrap != "" {
				continue
			}
			if !ok {
				t.Errorf("%s: no plan for %s", v.Name, n.ID)
				continue
			}
			ids := []string{}
			for _, peer := range p.Peers {
				ids = append(ids, peer.ID)
				if peer.ID == n.ID || (peer.Keepalive != 0 && peer.Keepalive != 25) || len(peer.AllowedIPs) == 0 {
					t.Errorf("%s: %s's peer %+v", v.Name, n.ID, peer)
				}
				for _, a := range peer.AllowedIPs {
					if a.Bits() != 32 || !mesh.Contains(a.Addr()) {
						t.Errorf("%s: %s's peer %s allows %s", v.Name, n.ID, peer.ID, a)
					}
				}
			}
			if !slices.IsSorted(ids) {
				t.Errorf("%s: %s's peers %v not sorted by id", v.Name, n.ID, ids)
			}
		}
	}
	if boots < 2 {
		t.Errorf("%d bootstrap cases, want ≥ 2 (as if NATed; a new site without a gateway yet)", boots)
	}
	if errs < 4 {
		t.Errorf("%d want_error cases, want ≥ 4 (no gateway, duplicate ip, outside the mesh, duplicate key)", errs)
	}
}
