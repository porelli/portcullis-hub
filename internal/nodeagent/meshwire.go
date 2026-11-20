package nodeagent

import (
	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/meshplan"
)

// WirePlan is a meshplan plan as PUT /v1/mesh/peers carries it (endpoint
// "<ip:port>" or null, allowed_ips as CIDRs; peers already sorted by id).
func WirePlan(p meshplan.NodePlan) MeshPlan {
	out := MeshPlan{Peers: make([]MeshPeer, 0, len(p.Peers)), Forward: p.Forward}
	for _, q := range p.Peers {
		e := MeshPeer{ID: q.ID, Pub: q.Pub, AllowedIPs: make([]string, 0, len(q.AllowedIPs)), Keepalive: q.Keepalive}
		if q.Endpoint.IsValid() {
			e.Endpoint = jsonstrict.Some(q.Endpoint.String())
		}
		for _, a := range q.AllowedIPs {
			e.AllowedIPs = append(e.AllowedIPs, a.String())
		}
		out.Peers = append(out.Peers, e)
	}
	return out
}
