package doctor

import (
	"sort"
	"strings"
)

// The node mesh (contract §20.11, §16 HA kinds): two kinds that run only
// on a Kubernetes primary (Inputs.Mesh set). Task 16 lists them in
// HAKinds with the other HA kinds.
const (
	KindMeshSiteNoGateway = "mesh_site_no_gateway"
	KindMeshPeerStale     = "mesh_peer_stale"
)

// MeshKinds are the mesh kinds.
var MeshKinds = []string{KindMeshSiteNoGateway, KindMeshPeerStale}

// MeshIn is the Hub's mesh push state: the nodes whose nodeagent missed
// its peer plan for more than 5 min (id → the last error) and the sites
// of a multi-site mesh without a node reachable on UDP 51830.
type MeshIn struct {
	Stale     map[string]string
	NoGateway []string
}

func init() {
	for _, k := range MeshKinds {
		Register(meshCheck{kind: k})
	}
}

type meshCheck struct{ kind string }

func (c meshCheck) Kind() string { return c.kind }

func (c meshCheck) Run(in *Inputs) []Finding {
	m := in.Mesh
	if m == nil {
		return nil
	}
	var out []Finding
	switch c.kind {
	case KindMeshSiteNoGateway:
		sites := append([]string(nil), m.NoGateway...)
		sort.Strings(sites)
		for _, s := range sites {
			out = append(out, Finding{FP: Fingerprint(c.kind, s), Kind: c.kind, Severity: Problem,
				Title: "Site " + s + " has no node reachable on UDP 51830.",
				Why:   "Its nodes behind NAT can't reach the other sites: a NATed pair at different sites goes through a site's gateway, its lowest-id node with a public UDP endpoint, and " + s + " has none left. New nodes there are refused.",
				Class: FixExplain,
				Steps: []string{"Add a node reachable on UDP 51830 at " + s + " (a cloud node), or forward UDP 51830 on its router to one of its nodes.",
					"Or remove the site's nodes if it is gone."},
				Inputs: Digest(s)})
		}
	case KindMeshPeerStale:
		ids := make([]string, 0, len(m.Stale))
		for id := range m.Stale {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			why := strings.TrimSpace(m.Stale[id])
			if why == "" {
				why = "no answer"
			}
			out = append(out, Finding{FP: Fingerprint(c.kind, id), Kind: c.kind, Severity: Warning,
				Title: "Node " + id + " missed the node mesh's last peer plan.",
				Why:   "The Hub couldn't give its nodeagent the current peer list (PUT /v1/mesh/peers) for more than 5 minutes (" + why + "): it may not reach a node added or keep a removed one. The Hub retries every tick.",
				Class: FixExplain,
				Steps: []string{"Check that the machine is up and that portcullis-nodeagent runs on it (systemctl status portcullis-nodeagent).",
					"Check its pcmesh tunnel (wg show pcmesh)."},
				Inputs: Digest(id + " " + why)})
		}
	}
	return out
}
