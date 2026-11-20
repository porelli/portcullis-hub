package doctor

import (
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
		if k == KindMeshPeerStale || k == KindMeshSiteNoGateway {
			n++
		}
	}
	if n != 2 {
		t.Errorf("registered %d of the 2 mesh kinds", n)
	}
}
