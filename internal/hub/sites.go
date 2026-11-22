package hub

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/meshplan"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/servers"
)

// Sites and the round trips between them (contract §20.11):
//   - each cluster tick reads every Ready node's GET /v1/mesh/rtt (the
//     nodeagent's p95 of 20 echo rounds per peer, over pcmesh, through
//     the nodeagent client's fsutil.Do) and keeps it for the gauge
//     portcullis_mesh_rtt_ms{from,to} (pre-flight P47: the Hub exports it
//     on its metrics listener), the doctor (mesh_rtt_high) and the sites
//     view;
//   - a joining node's round trips are checked after mesh_ready and
//     before k3s_joined (P23, servers.CheckRTT against the healthy
//     servers): a refusal ends the enrolment as a revoke, its peer out of
//     every plan;
//   - Sites is the per-site view of the HA page (§20.1 "sites").

// rttStale: a node's round trips not read again for this long are
// dropped (no gauge, no finding: never a stale figure).
const rttStale = 5 * time.Minute

// joinRTTWait: how long a joining node's nodeagent may take to answer
// for every healthy server (its cache is up to a minute old and it
// measures every 30 s: the real plan lands just before mesh_ready).
const joinRTTWait = 3 * time.Minute

// rttMaxMs: a figure above this (10 min) is nonsense and dropped.
const rttMaxMs = 600_000

// rttCallWait bounds one nodeagent's RTT read of the cluster tick.
const rttCallWait = 10 * time.Second

// meshRTT is the last round trips read per node (from → to → ms).
type meshRTT struct {
	// busy: a collection runs (one at a time, beside the cluster tick).
	busy atomic.Bool
	mu   sync.Mutex
	v    map[string]map[string]int
	at   map[string]time.Time
}

func (r *meshRTT) set(from string, v map[string]int, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.v == nil {
		r.v, r.at = map[string]map[string]int{}, map[string]time.Time{}
	}
	r.v[from], r.at[from] = v, at
}

// snapshot is a copy of the figures read since now−rttStale, of the nodes
// in keep only (nil keep: all).
func (r *meshRTT) snapshot(now time.Time, keep map[string]bool) map[string]map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]map[string]int{}
	for from, m := range r.v {
		if now.Sub(r.at[from]) > rttStale || (keep != nil && !keep[from]) {
			continue
		}
		c := map[string]int{}
		for to, ms := range m {
			if keep == nil || keep[to] {
				c[to] = ms
			}
		}
		out[from] = c
	}
	return out
}

// cleanRTT keeps a nodeagent's answer's figures for the known nodes only
// (a node's words are never a label or a key the Hub didn't know), never
// its own, never negative; an absurd one (over rttMaxMs) is dropped
// unless keepHigh (the join: it is "too far", never "no answer").
func cleanRTT(from string, raw map[string]int, known map[string]bool, keepHigh bool) map[string]int {
	out := map[string]int{}
	for to, ms := range raw {
		if to == from || !known[to] || ms < 0 || (ms > rttMaxMs && !keepHigh) {
			continue
		}
		out[to] = ms
	}
	return out
}

// rttNodes: the snapshot's nodes the Hub manages (not revoked or removed)
// and their mesh addresses (the Hub's record first).
func (h *Hub) rttNodes(snap nodeadm.Snapshot) (known map[string]bool, mesh map[string]string) {
	known, mesh = map[string]bool{}, map[string]string{}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, n := range snap.Nodes {
		if servers.ValidID(n.Name) != nil || h.st.Mesh[n.Name].Removed {
			continue
		}
		s, listed := h.st.Servers[n.Name]
		if listed && (!s.ClusterNode() || s.State == ServerRevoked) {
			continue
		}
		known[n.Name] = true
		ip := n.Addresses.Mesh
		if listed && s.MeshIP != "" {
			ip = s.MeshIP
		}
		mesh[n.Name] = ip
	}
	return known, mesh
}

// startCollectRTT runs collectRTT in its own goroutine, one at a time: the
// cluster tick (revokes, watches) never waits on a nodeagent's RTT. The
// clock is read here, on the tick's goroutine: the collection never reads
// the Hub's clock (a test's injected one is set without a lock).
func (h *Hub) startCollectRTT(ctx context.Context, snap nodeadm.Snapshot) {
	if !h.cl.rtt.busy.CompareAndSwap(false, true) {
		return
	}
	at := h.now()
	go func() {
		defer h.cl.rtt.busy.Store(false)
		h.collectRTT(ctx, snap, at)
	}()
}

// collectRTT reads every Ready node's round trips (in parallel, each call
// bounded; one silent nodeagent never holds the others), recorded as read
// at at.
func (h *Hub) collectRTT(ctx context.Context, snap nodeadm.Snapshot, at time.Time) {
	known, mesh := h.rttNodes(snap)
	var wg sync.WaitGroup
	for _, n := range snap.Nodes {
		if !known[n.Name] || !n.Ready {
			continue
		}
		id, ip := n.Name, mesh[n.Name]
		wg.Add(1)
		go func() {
			defer wg.Done()
			ag, err := h.nodeagentAPI(ctx, id, ip)
			if err != nil {
				return
			}
			c, cancel := context.WithTimeout(ctx, rttCallWait)
			raw, err := ag.RTT(c)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("servers: the mesh round trips of %s: %v", id, err)
				}
				return
			}
			h.cl.rtt.set(id, cleanRTT(id, raw, known, false), at)
		}()
	}
	wg.Wait()
}

// MeshRTT is the round trips read in the last 5 min of the nodes the
// cluster lists (from → to → ms; the gauge's series).
func (h *Hub) MeshRTT() map[string]map[string]int {
	if h.clusterNodesOn() != nil {
		return nil
	}
	snap := h.lastSnapshot()
	if snap == nil {
		return nil
	}
	known, _ := h.rttNodes(*snap)
	return h.cl.rtt.snapshot(h.now(), known)
}

// healthyServers are the snapshot's Ready servers but id.
func healthyServers(snap nodeadm.Snapshot, id string) []string {
	var out []string
	for _, n := range snap.Nodes {
		if n.Role == "server" && n.Ready && n.Name != id {
			out = append(out, n.Name)
		}
	}
	sort.Strings(out)
	return out
}

// joinRTT is the enrolment's RTT check (after mesh_ready, before
// k3s_joined): the joining node's round trips to every healthy server
// within its role's limit. done false: not every server answered yet, or
// no server is healthy to measure against (asked again at the next poll,
// until since+joinRTTWait); a refusal is err with the §20.11 text. The
// 80 % warnings go to the op.
func (h *Hub) joinRTT(ctx context.Context, id, role, meshIP string, snap nodeadm.Snapshot, since time.Time, p *Progress) (done bool, err error) {
	hs := healthyServers(snap, id)
	late := h.now().After(since.Add(joinRTTWait))
	ag, err := h.nodeagentAPI(ctx, id, meshIP)
	var raw map[string]int
	if err == nil {
		c, cancel := context.WithTimeout(ctx, clusterCallWait)
		raw, err = ag.RTT(c)
		cancel()
	}
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if late {
			return false, statusErr(http.StatusConflict, "no mesh round trips from %s: its nodeagent doesn't answer GET /v1/mesh/rtt (%s): the node can't join", id, clipRunes(err.Error(), 160))
		}
		p.DetailThrottled(StepK3sJoined, "waiting for the node's mesh round trips")
		return false, nil
	}
	known := map[string]bool{}
	for _, n := range snap.Nodes {
		known[n.Name] = true
	}
	rtt := cleanRTT(id, raw, known, true)
	h.cl.rtt.set(id, cleanRTT(id, raw, known, false), h.now())
	if len(hs) == 0 {
		// Nothing to measure against is never a pass (review I1).
		if late {
			return false, statusErr(http.StatusConflict, "%s", ErrNoHealthyServer)
		}
		p.DetailThrottled(StepK3sJoined, "waiting for a healthy server to measure the round trip against")
		return false, nil
	}
	for _, s := range hs {
		if _, ok := rtt[s]; !ok && !late {
			p.DetailThrottled(StepK3sJoined, "waiting for the node's round trip to "+s)
			return false, nil
		}
		// Exactly the round timeout is lost echoes, not distance (a server
		// that got the joiner's peer only after its first rounds; found
		// live, Task 30): measured again until joinRTTWait, then judged.
		if v, ok := rtt[s]; ok && v == rttLostFigure && !late {
			p.DetailThrottled(StepK3sJoined, "the node's round trip to "+s+" still loses echoes: measuring again")
			return false, nil
		}
	}
	warnings, err := servers.CheckRTT(role, hs, rtt)
	if err != nil {
		return false, statusErr(http.StatusConflict, "%s", err.Error())
	}
	for _, w := range warnings {
		p.Warn(w)
	}
	p.Detail(StepK3sJoined, "")
	return true, nil
}

// rttLostFigure is the nodeagent's round timeout in ms (internal/nodeagent/
// host rttTimeout): a p95 of exactly it means lost rounds.
const rttLostFigure = 1000

// ErrNoHealthyServer is the join's refusal when no server was healthy to
// measure the round trip against for joinRTTWait.
const ErrNoHealthyServer = "no healthy server to measure the round trip against: the node can't join"

// SiteView is one site of the HA page (GET /api/ha "sites", §20.1): its
// nodes, servers and ingress nodes (ids, sorted), its mesh gateway (the
// lowest-id reachable node, "" = none: null) and its worst round trip to
// a healthy server (RTTms, nil = none measured: null). Primary is main
// only (it can't be changed in this version).
type SiteView struct {
	Name    string
	Primary bool
	Nodes   []string
	Servers []string
	Gateway string
	Ingress []string
	RTTms   *int
}

// MarshalJSON is the contract's shape (gateway and rtt_ms null when none).
func (v SiteView) MarshalJSON() ([]byte, error) {
	var gw *string
	if v.Gateway != "" {
		gw = &v.Gateway
	}
	nz := func(l []string) []string {
		if l == nil {
			return []string{}
		}
		return l
	}
	return json.Marshal(struct {
		Name    string   `json:"name"`
		Primary bool     `json:"primary"`
		Nodes   []string `json:"nodes"`
		Servers []string `json:"servers"`
		Gateway *string  `json:"gateway"`
		Ingress []string `json:"ingress"`
		RTTms   *int     `json:"rtt_ms"`
	}{v.Name, v.Primary, nz(v.Nodes), nz(v.Servers), gw, nz(v.Ingress), v.RTTms})
}

// Sites is the cluster's sites from a fresh snapshot (main first, then by
// name). A node's site is the Hub's record (its entry, or the mesh's pin
// of a node of init), else its label, else main.
func (h *Hub) Sites(ctx context.Context) ([]SiteView, error) {
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return nil, err
	}
	c, cancel := context.WithTimeout(ctx, clusterCallWait)
	snap, err := h.clusterSnapshot(c, api)
	cancel()
	if err != nil {
		return nil, nodeadmErr(err)
	}
	return h.sitesOf(snap), nil
}

// nodeSites is each managed node's site from the Hub's records (its
// entry, else the mesh's pin of a node of init) and whether it is an
// ingress node (its entry's labels; a node of init: the mesh's pin, its
// Node's label at first sight). A node
// the Hub has no record of is never placed by its own labels (a kubelet
// may set them, review M2): it is unrecorded, left out of the view and
// flagged.
func (h *Hub) nodeSites(snap nodeadm.Snapshot) (site map[string]string, ingress map[string]bool, unrecorded []string) {
	known, _ := h.rttNodes(snap)
	site, ingress = map[string]string{}, map[string]bool{}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, n := range snap.Nodes {
		if !known[n.Name] {
			continue
		}
		if s, ok := h.st.Servers[n.Name]; ok && s.ClusterNode() {
			site[n.Name] = nonEmpty(s.Site, servers.PrimarySite)
			ingress[n.Name] = s.Labels != nil && s.Labels.Ingress
		} else if r, ok := h.st.Mesh[n.Name]; ok && r.Site != "" {
			site[n.Name] = r.Site
			ingress[n.Name] = r.Ingress
		} else {
			unrecorded = append(unrecorded, n.Name)
		}
	}
	sort.Strings(unrecorded)
	return site, ingress, unrecorded
}

// unrecordedText is an unrecorded node's flag (doctor mesh_peer_stale).
const unrecordedText = "the Hub has no record of its site: left out of the sites view"

func (h *Hub) sitesOf(snap nodeadm.Snapshot) []SiteView {
	siteOfID, ingress, _ := h.nodeSites(snap)
	est, _ := sanitizeEstablished(h.meshInputsOf(snap))
	known := map[string]bool{}
	for id := range siteOfID {
		known[id] = true
	}
	rtt := h.cl.rtt.snapshot(h.now(), known)
	hs := healthyServers(snap, "")
	by := map[string]*SiteView{}
	for _, n := range snap.Nodes {
		site, ok := siteOfID[n.Name]
		if !ok {
			continue
		}
		v := by[site]
		if v == nil {
			v = &SiteView{Name: site, Primary: site == servers.PrimarySite}
			by[site] = v
		}
		v.Nodes = append(v.Nodes, n.Name)
		if n.Role == "server" {
			v.Servers = append(v.Servers, n.Name)
		}
		if ingress[n.Name] {
			v.Ingress = append(v.Ingress, n.Name)
		}
		for _, s := range hs {
			if ms, ok := rtt[n.Name][s]; ok && s != n.Name && (v.RTTms == nil || ms > *v.RTTms) {
				m := ms
				v.RTTms = &m
			}
		}
	}
	out := make([]SiteView, 0, len(by))
	for _, v := range by {
		slices.Sort(v.Nodes)
		slices.Sort(v.Servers)
		slices.Sort(v.Ingress)
		if g, ok := meshplan.Gateway(est, v.Name); ok {
			v.Gateway = g
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// doctorSitesIn fills the doctor's mesh input with the round trips to the
// servers and the sites, from the last snapshot (nothing before one).
func (h *Hub) doctorSitesIn(in *doctor.MeshIn) {
	snap := h.lastSnapshot()
	if snap == nil {
		return
	}
	siteOfID, _, unrecorded := h.nodeSites(*snap)
	for _, id := range unrecorded {
		if in.Stale == nil {
			in.Stale = map[string]string{}
		}
		if _, ok := in.Stale[id]; !ok {
			in.Stale[id] = unrecordedText
		}
	}
	set := map[string]bool{}
	for _, s := range siteOfID {
		set[s] = true
	}
	for s := range set {
		in.Sites = append(in.Sites, s)
	}
	sort.Strings(in.Sites)
	role := map[string]string{}
	for _, n := range snap.Nodes {
		role[n.Name] = n.Role
	}
	healthy := map[string]bool{}
	for _, s := range healthyServers(*snap, "") {
		healthy[s] = true
	}
	known := map[string]bool{}
	for id := range siteOfID {
		known[id] = true
	}
	for from, m := range h.cl.rtt.snapshot(h.now(), known) {
		for to, ms := range m {
			if healthy[to] { // the limits are the healthy servers' (§20.11)
				in.RTT = append(in.RTT, doctor.MeshRTT{From: from, To: to, FromServer: role[from] == "server", Ms: ms})
			}
		}
	}
	sort.Slice(in.RTT, func(i, j int) bool {
		if in.RTT[i].From != in.RTT[j].From {
			return in.RTT[i].From < in.RTT[j].From
		}
		return in.RTT[i].To < in.RTT[j].To
	})
}
