package doctor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/servers"
)

// The node mesh and the sites (contract §20.11, §14.5 HA kinds): four
// kinds that run only on a Kubernetes primary (Inputs.Mesh set). Task 16
// lists them in HAKinds with the other HA kinds.
const (
	KindMeshSiteNoGateway      = "mesh_site_no_gateway"
	KindMeshPeerStale          = "mesh_peer_stale"
	KindMeshRTTHigh            = "mesh_rtt_high"
	KindHATwoSitesNoTiebreaker = "ha_two_sites_no_tiebreaker"
)

// MeshKinds are the mesh kinds, in HAKinds' order (§14.5).
var MeshKinds = []string{KindMeshSiteNoGateway, KindMeshPeerStale, KindMeshRTTHigh, KindHATwoSitesNoTiebreaker}

// MeshIn is the Hub's mesh state: the nodes whose nodeagent missed its
// peer plan for more than 5 min (id → the last error), the sites of a
// multi-site mesh without a node reachable on UDP 51830, the measured
// round trips to the servers and the cluster's sites.
type MeshIn struct {
	Stale     map[string]string
	NoGateway []string
	// RTT: each node's last round trip (p95 of 20, ms) to each server.
	RTT []MeshRTT
	// Sites: the sites the cluster's nodes are at.
	Sites []string
}

// MeshRTT is one measured round trip from node From (a server when
// FromServer) to server To.
type MeshRTT struct {
	From, To   string
	FromServer bool
	Ms         int
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
	case KindMeshRTTHigh:
		rs := append([]MeshRTT(nil), m.RTT...)
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].From != rs[j].From {
				return rs[i].From < rs[j].From
			}
			return rs[i].To < rs[j].To
		})
		for _, r := range rs {
			if r.From == r.To {
				continue
			}
			role, what := "agent", "an agent"
			if r.FromServer {
				role, what = "server", "a server"
			}
			limit := servers.RTTLimit(role)
			if !servers.RTTHigh(r.Ms, limit) {
				continue
			}
			out = append(out, Finding{FP: Fingerprint(c.kind, r.From+">"+r.To), Kind: c.kind, Severity: Warning,
				Title: fmt.Sprintf("The mesh round trip from %s to server %s is %d ms: near the %d ms limit.", r.From, r.To, r.Ms, limit),
				Why: fmt.Sprintf("%s is %s: it must stay within %d ms of every server (etcd across sites needs it; the p95 of 20 rounds over pcmesh). "+
					"At 80 %% of the limit a slower day refuses the next join and slows the cluster's writes.", r.From, what, limit),
				Class: FixExplain,
				Steps: []string{"Check the link between the two sites (its latency and loss, and that the pair doesn't relay through a far gateway).",
					"Or move the node closer, or make it an agent (agents may be 250 ms from the servers)."},
				Inputs: Digest(fmt.Sprintf("%s %s %t", r.From, r.To, r.FromServer))})
		}
	case KindHATwoSitesNoTiebreaker:
		set := map[string]bool{}
		for _, s := range m.Sites {
			set[s] = true
		}
		if len(set) != 2 {
			break
		}
		names := make([]string, 0, 2)
		for s := range set {
			names = append(names, s)
		}
		sort.Strings(names)
		out = append(out, Finding{FP: Fingerprint(c.kind, strings.Join(names, " ")), Kind: c.kind, Severity: Warning,
			Title: servers.WarnTieBreaker,
			Why: "The cluster spans exactly two sites (" + strings.Join(names, " and ") + "). The servers stay at main: the site holding 2 of the 3 voters is the only one that survives on its own, " +
				"so losing main stops the cluster even though the other site is up.",
			Class:  FixExplain,
			Steps:  []string{"Add a node at a third location (a small cloud VM or a Pi elsewhere): the Hub suggests it as a server there."},
			Inputs: Digest(strings.Join(names, " "))})
	}
	return out
}
