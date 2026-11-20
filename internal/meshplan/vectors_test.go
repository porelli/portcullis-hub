package meshplan

import (
	"net/netip"
	"os"
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
	Nodes     []meshNode                                   `json:"nodes"`
	Want      jsonstrict.Nullable[map[string]meshNodePlan] `json:"want,omitempty"`
	WantError string                                       `json:"want_error,omitempty"`
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
	errs := 0
	for _, v := range vs {
		if v.Want.Valid == (v.WantError != "") {
			t.Errorf("%s: exactly one of want and want_error", v.Name)
			continue
		}
		if !v.Want.Valid {
			errs++
			continue
		}
		if len(v.Want.V) != len(v.Nodes) {
			t.Errorf("%s: %d plans for %d nodes", v.Name, len(v.Want.V), len(v.Nodes))
		}
		for _, n := range v.Nodes {
			p, ok := v.Want.V[n.ID]
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
	if errs < 3 {
		t.Errorf("%d want_error cases, want ≥ 3 (no gateway, duplicate ip, outside the mesh)", errs)
	}
}
