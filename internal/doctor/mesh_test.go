package doctor

import (
	"slices"
	"strings"
	"testing"
)

// TestMeshKinds: mesh_site_no_gateway (Problem) per site without a
// reachable node, mesh_peer_stale (Warning) per node naming it; nothing
// without the input or with an empty one.
func TestMeshKinds(t *testing.T) {
	run := func(in *Inputs, kind string) []Finding {
		return meshCheck{kind: kind}.Run(in)
	}
	if f := run(&Inputs{}, KindMeshPeerStale); f != nil {
		t.Errorf("no input: %v", f)
	}
	empty := &Inputs{Mesh: &MeshIn{}}
	if len(run(empty, KindMeshPeerStale))+len(run(empty, KindMeshSiteNoGateway)) != 0 {
		t.Error("an empty input raised a finding")
	}
	in := &Inputs{Mesh: &MeshIn{Stale: map[string]string{"n3": "i/o timeout", "n2": ""}, NoGateway: []string{"edge"}}}
	f := run(in, KindMeshPeerStale)
	if len(f) != 2 || f[0].Severity != Warning || !strings.Contains(f[0].Title, "n2") || !strings.Contains(f[1].Why, "i/o timeout") || f[0].FP == f[1].FP {
		t.Errorf("stale %+v", f)
	}
	g := run(in, KindMeshSiteNoGateway)
	if len(g) != 1 || g[0].Severity != Problem || !strings.Contains(g[0].Title, "edge") {
		t.Errorf("no gateway %+v", g)
	}
	n := 0
	for _, k := range Kinds() {
		if slices.Contains(MeshKinds, k) {
			n++
		}
	}
	if n != 4 {
		t.Errorf("registered %d of the 4 mesh kinds", n)
	}
}

// TestMeshRTTHighAndTwoSites: mesh_rtt_high at 80 % of the limit (80 ms
// from a server, 200 ms from an agent; the boundary raises, one below
// doesn't), naming both nodes; ha_two_sites_no_tiebreaker only with
// exactly 2 sites, its title the §20.11 text.
func TestMeshRTTHighAndTwoSites(t *testing.T) {
	run := func(in *Inputs, kind string) []Finding { return meshCheck{kind: kind}.Run(in) }
	in := &Inputs{Mesh: &MeshIn{RTT: []MeshRTT{
		{From: "n2", To: "n1", FromServer: true, Ms: 79},
		{From: "n3", To: "n1", FromServer: true, Ms: 80},
		{From: "a1", To: "n1", Ms: 199},
		{From: "a2", To: "n1", Ms: 200},
		{From: "n1", To: "n1", FromServer: true, Ms: 900},
	}}}
	f := run(in, KindMeshRTTHigh)
	if len(f) != 2 || f[0].Severity != Warning || f[0].Title != "The mesh round trip from a2 to server n1 is 200 ms: near the 250 ms limit." ||
		f[1].Title != "The mesh round trip from n3 to server n1 is 80 ms: near the 100 ms limit." || f[0].FP == f[1].FP {
		t.Errorf("rtt %+v", f)
	}
	for _, c := range []struct {
		sites []string
		want  int
	}{{nil, 0}, {[]string{"main"}, 0}, {[]string{"main", "edge"}, 1}, {[]string{"main", "edge", "edge"}, 1}, {[]string{"main", "edge", "tb"}, 0}} {
		g := run(&Inputs{Mesh: &MeshIn{Sites: c.sites}}, KindHATwoSitesNoTiebreaker)
		if len(g) != c.want {
			t.Errorf("%v: %+v", c.sites, g)
		}
		if len(g) == 1 && (g[0].Severity != Warning || g[0].Title != "Only main can survive on its own: add a tie-breaker at a third location (a small cloud VM or a Pi elsewhere).") {
			t.Errorf("two sites %+v", g[0])
		}
	}
}
