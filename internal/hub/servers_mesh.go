package hub

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/meshplan"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/servers"
)

// The node mesh across sites and NAT (contract §20.11, §20.4 PUT
// /v1/mesh/peers, §20.2 the bootstrap plan): the Hub computes every
// node's peer plan (internal/meshplan) from the cluster snapshot and the
// nodes' pcmesh reports and pushes it to every nodeagent over pcmesh, as
// hub.control, through fsutil.Do (the write fence). It pushes on every
// join, removal and change of a node's endpoints, and every cluster tick
// to the nodes whose last push failed. One unreachable nodeagent never
// blocks the others; a node that missed its plan for more than 5 min is
// doctor mesh_peer_stale, a site of a multi-site mesh without a reachable
// node mesh_site_no_gateway. A joining node at a site without a reachable
// node is refused (the §20.11 text) and never gets k3s material: its
// enrolment fails at mesh_ready, before nodeadm can reach it.

// MeshStaleAfter is how long a node may miss its plan before doctor
// mesh_peer_stale names it.
const MeshStaleAfter = 5 * time.Minute

// meshPushWait bounds one PUT /v1/mesh/peers.
const meshPushWait = 15 * time.Second

// meshState is the Hub's view of the pushes.
type meshState struct {
	mu sync.Mutex
	// run serialises the computations and pushes.
	run sync.Mutex
	// pubs: the pcmesh keys read from nodeagents' GET /v1/health (nodes
	// without an enrolment report: the nodes of init), id → key.
	pubs map[string]string
	// want / applied: the hash of each node's current plan and of the one
	// it last took.
	want, applied map[string]string
	// failing: since when a node's nodeagent refuses or misses its plan.
	failing map[string]time.Time
	lastErr map[string]string
	// removed: nodes taken out of every plan (meshRemovePeer) while the
	// snapshot may still list them.
	removed map[string]bool
	// refused: joining nodes the plan refuses (id → the refusal text).
	refused map[string]string
	// noGateway: the sites without a reachable node (last computation).
	noGateway []string
}

func (m *meshState) init() {
	if m.pubs == nil {
		m.pubs, m.want, m.applied = map[string]string{}, map[string]string{}, map[string]string{}
		m.failing, m.lastErr, m.removed, m.refused = map[string]time.Time{}, map[string]string{}, map[string]bool{}, map[string]string{}
	}
}

// meshAgent is the part of a nodeagent the mesh uses.
type meshAgent interface {
	Health(ctx context.Context) (nodeagent.Health, error)
	PutMeshPeers(ctx context.Context, p nodeagent.MeshPlan) error
}

func (h *Hub) meshAgentOf(ctx context.Context, id, meshIP string) (meshAgent, error) {
	return h.nodeagentAPI(ctx, id, meshIP)
}

// endpoint parses a report's "<ip:port>" (zero: none or malformed).
func endpoint(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
		return netip.AddrPort{}
	}
	return ap
}

// firstEndpoint is the first IPv4 address of l on UDP 51830 (zero: none).
func firstEndpoint(l []string) netip.AddrPort {
	for _, s := range l {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return netip.AddrPortFrom(a, meshplan.Port)
		}
	}
	return netip.AddrPort{}
}

func validMeshKey(s string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32
}

func siteOf(labels map[string]string) string {
	if s := labels[nodeadm.LabelSite]; s != "" {
		return s
	}
	return servers.PrimarySite
}

// recordMeshReports keeps each enrolling node's pcmesh report in its
// entry (the snapshot drops it once the node is a Kubernetes Node).
func (h *Hub) recordMeshReports(snap nodeadm.Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	changed := false
	for _, e := range snap.Enrolling {
		s, ok := h.st.Servers[e.ID]
		if !ok || !s.ClusterNode() || s.State != ServerEnrolling {
			continue
		}
		lan, pub := "", ""
		if e.Mesh.LAN.Valid {
			lan = e.Mesh.LAN.V
		}
		if e.Mesh.Public.Valid {
			pub = e.Mesh.Public.V
		}
		if s.MeshPub == e.Mesh.Pub && s.MeshLAN == lan && s.MeshPublic == pub {
			continue
		}
		s.MeshPub, s.MeshLAN, s.MeshPublic = e.Mesh.Pub, lan, pub
		h.st.Servers[e.ID] = s
		changed = true
	}
	if changed {
		h.saveLocked()
	}
}

// meshInputs are the plan's nodes: the established ones (the snapshot's
// Nodes, but revoked or removed ones) and the joining ones (enrolling,
// with the Hub's entry still enrolling). fetch lists the nodes whose key
// must be read from their nodeagent first.
type meshInputs struct {
	established, joining []meshplan.Node
	meshIP               map[string]string
	ready                map[string]bool
	fetch                []string
}

func (h *Hub) meshInputsOf(snap nodeadm.Snapshot) meshInputs {
	in := meshInputs{meshIP: map[string]string{}, ready: map[string]bool{}}
	h.mu.RLock()
	defer h.mu.RUnlock()
	h.cl.ms.mu.Lock()
	defer h.cl.ms.mu.Unlock()
	ms := &h.cl.ms
	ms.init()
	node := func(id, site, mesh, pub, lan, public string) (meshplan.Node, bool) {
		a, err := netip.ParseAddr(mesh)
		if err != nil {
			return meshplan.Node{}, false
		}
		n := meshplan.Node{ID: id, Site: site, MeshIP: a, LAN: endpoint(lan), Public: endpoint(public), Pub: pub}
		if !validMeshKey(n.Pub) {
			if k := ms.pubs[id]; k != "" {
				n.Pub = k
			} else {
				in.fetch = append(in.fetch, id)
			}
		}
		in.meshIP[id] = mesh
		return n, true
	}
	for _, sn := range snap.Nodes {
		if ms.removed[sn.Name] || servers.ValidID(sn.Name) != nil {
			continue
		}
		s, listed := h.st.Servers[sn.Name]
		if listed && (!s.ClusterNode() || s.State == ServerRevoked) {
			continue
		}
		mesh := sn.Addresses.Mesh
		if mesh == "" {
			mesh = s.MeshIP
		}
		lan, public := s.MeshLAN, s.MeshPublic
		if !listed || s.MeshPub == "" {
			// No enrolment report (a node of init): its addresses on 51830.
			if ap := firstEndpoint(sn.Addresses.LAN); ap.IsValid() {
				lan = ap.String()
			}
			if ap := firstEndpoint(sn.Addresses.Public); ap.IsValid() {
				public = ap.String()
			}
		}
		if n, ok := node(sn.Name, siteOf(sn.Labels), mesh, s.MeshPub, lan, public); ok {
			in.established = append(in.established, n)
			in.ready[sn.Name] = sn.Ready
		}
	}
	for _, e := range snap.Enrolling {
		s, listed := h.st.Servers[e.ID]
		if ms.removed[e.ID] || !listed || !s.ClusterNode() || s.State != ServerEnrolling || snap.Node(e.ID) != nil {
			continue
		}
		lan, public := "", ""
		if e.Mesh.LAN.Valid {
			lan = e.Mesh.LAN.V
		}
		if e.Mesh.Public.Valid {
			public = e.Mesh.Public.V
		}
		site := e.Site
		if site == "" {
			site = s.Site
		}
		if n, ok := node(e.ID, nonEmpty(site, servers.PrimarySite), nonEmpty(e.MeshIP, s.MeshIP), e.Mesh.Pub, lan, public); ok {
			in.joining = append(in.joining, n)
		}
	}
	sort.Slice(in.joining, func(i, j int) bool { return in.joining[i].ID < in.joining[j].ID })
	return in
}

// fetchPubs reads the pcmesh key of the nodes without one from their
// nodeagent's GET /v1/health (its id must answer).
func (h *Hub) fetchPubs(ctx context.Context, in meshInputs) error {
	var mu sync.Mutex
	var errs []string
	var wg sync.WaitGroup
	for _, id := range in.fetch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ag, err := h.meshAgentOf(ctx, id, in.meshIP[id])
			if err == nil {
				c, cancel := context.WithTimeout(ctx, meshPushWait)
				var hl nodeagent.Health
				hl, err = ag.Health(c)
				cancel()
				if err == nil && (hl.ID != id || !validMeshKey(hl.MeshPub)) {
					err = fmt.Errorf("its nodeagent answered as %q with key %q", clipRunes(hl.ID, 40), clipRunes(hl.MeshPub, 60))
				}
				if err == nil {
					h.cl.ms.mu.Lock()
					h.cl.ms.pubs[id] = hl.MeshPub
					h.cl.ms.mu.Unlock()
					return
				}
			}
			mu.Lock()
			errs = append(errs, fmt.Sprintf("%s: %v", id, clipRunes(err.Error(), 160)))
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("the pcmesh key of %s", strings.Join(errs, "; "))
	}
	return nil
}

// planMesh: the established nodes' plan (Degraded: a site that lost its
// gateway is reported, never a reason to keep a removed peer), plus each
// joining node the plan admits; a joining node that leaves a site (its
// own included) without a reachable node, or that fails validation, is
// refused with the text.
func planMesh(in meshInputs) (plans map[string]meshplan.NodePlan, noGateway []string, refused map[string]string, err error) {
	_, missing, err := meshplan.Degraded(in.established)
	if err != nil {
		return nil, nil, nil, err
	}
	refused = map[string]string{}
	include := slices.Clone(in.established)
	for _, j := range in.joining {
		trial := append(slices.Clone(include), j)
		_, m2, err := meshplan.Degraded(trial)
		if err != nil {
			refused[j.ID] = err.Error()
			continue
		}
		bad := ""
		for _, s := range m2 {
			if s == j.Site || !slices.Contains(missing, s) {
				bad = s
				break
			}
		}
		if bad != "" {
			refused[j.ID] = meshplan.Refusal(bad)
			continue
		}
		include = trial
	}
	plans, noGateway, err = meshplan.Degraded(include)
	return plans, noGateway, refused, err
}

func planHash(p nodeagent.MeshPlan) string {
	b, _ := json.Marshal(p)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// pushMesh computes every node's plan from the current snapshot and pushes
// it to every nodeagent (PUT /v1/mesh/peers), the joining nodes last. One
// unreachable nodeagent doesn't fail it (that node is retried each tick
// and is mesh_peer_stale after 5 min); err is a snapshot or planning
// fault, or the list of nodes that didn't take their plan.
func (h *Hub) pushMesh(ctx context.Context) error {
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return err
	}
	c, cancel := context.WithTimeout(ctx, clusterCallWait)
	snap, err := h.clusterSnapshot(c, api)
	cancel()
	if err != nil {
		return fmt.Errorf("the cluster snapshot: %v", clipRunes(err.Error(), 200))
	}
	return h.syncMesh(ctx, snap, true)
}

// syncMesh plans from snap and pushes to every node (force) or to the
// nodes whose plan changed or whose last push failed.
func (h *Hub) syncMesh(ctx context.Context, snap nodeadm.Snapshot, force bool) error {
	h.cl.ms.run.Lock()
	defer h.cl.ms.run.Unlock()
	h.recordMeshReports(snap)
	in := h.meshInputsOf(snap)
	if len(in.fetch) > 0 {
		if err := h.fetchPubs(ctx, in); err != nil {
			// Fail static: a node without its key would drop out of every
			// plan; the current plans stay until the key is read.
			return err
		}
		in = h.meshInputsOf(snap)
	}
	plans, noGateway, refused, err := planMesh(in)
	if err != nil {
		return fmt.Errorf("the mesh plan: %v", err)
	}
	joining := map[string]bool{}
	for _, j := range in.joining {
		joining[j.ID] = true
	}
	now := h.now()
	ms := &h.cl.ms
	ms.mu.Lock()
	ms.noGateway = noGateway
	ms.refused = refused
	wire := map[string]nodeagent.MeshPlan{}
	for id, p := range plans {
		wire[id] = nodeagent.WirePlan(p)
		ms.want[id] = planHash(wire[id])
	}
	for id := range ms.want {
		if _, ok := plans[id]; !ok {
			delete(ms.want, id)
			delete(ms.applied, id)
			delete(ms.failing, id)
			delete(ms.lastErr, id)
		}
	}
	// Forget removed ids neither the snapshot nor a joining entry lists.
	for id := range ms.removed {
		if snap.Node(id) == nil && snap.EnrollingNode(id) == nil {
			delete(ms.removed, id)
		}
	}
	var first, last []string
	for id := range plans {
		if !force && ms.applied[id] == ms.want[id] {
			continue
		}
		if joining[id] {
			last = append(last, id)
		} else {
			first = append(first, id)
		}
	}
	ms.mu.Unlock()
	sort.Strings(first)
	sort.Strings(last)
	if len(noGateway) > 0 {
		log.Printf("servers: the node mesh: %s", meshplan.Refusal(noGateway[0]))
	}
	push := func(ids []string) []string {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var failed []string
		for _, id := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := h.pushOne(ctx, id, in.meshIP[id], wire[id])
				ms.mu.Lock()
				if err == nil {
					ms.applied[id] = planHash(wire[id])
					delete(ms.failing, id)
					delete(ms.lastErr, id)
				} else {
					if ms.failing[id].IsZero() {
						ms.failing[id] = now
					}
					ms.lastErr[id] = clipRunes(err.Error(), 200)
				}
				ms.mu.Unlock()
				if err != nil {
					mu.Lock()
					failed = append(failed, id)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		return failed
	}
	failed := append(push(first), push(last)...)
	if len(failed) > 0 {
		sort.Strings(failed)
		return fmt.Errorf("the mesh plan didn't reach %s (retried every tick)", strings.Join(failed, ", "))
	}
	return nil
}

func (h *Hub) pushOne(ctx context.Context, id, meshIP string, p nodeagent.MeshPlan) error {
	ag, err := h.meshAgentOf(ctx, id, meshIP)
	if err != nil {
		return err
	}
	c, cancel := context.WithTimeout(ctx, meshPushWait)
	defer cancel()
	return ag.PutMeshPeers(c, p)
}

// meshTick is the cluster tick's part: the nodes whose plan changed or
// whose last push failed get it now.
func (h *Hub) meshTick(ctx context.Context, snap nodeadm.Snapshot) {
	if err := h.syncMesh(ctx, snap, false); err != nil {
		log.Printf("servers: %v", err)
	}
}

// bootstrapMeshPlan is a new node's bootstrap plan (POST /v1/codes): its
// plan as if it were NATed among the established nodes. A node whose
// joining would leave another site without a reachable node is refused
// here (409, the §20.11 text): nothing is issued. Its own site may lack
// one (it may be the gateway); that is decided once it reports itself.
// No network call: a node whose pcmesh key the Hub doesn't know yet is
// left out of the bootstrap plan (the real plan, pushed before
// mesh_ready, has every node).
func (h *Hub) bootstrapMeshPlan(_ context.Context, id, site, meshIP string, snap nodeadm.Snapshot) (nodeadm.MeshPlan, error) {
	in := h.meshInputsOf(snap)
	a, err := netip.ParseAddr(meshIP)
	if err != nil {
		return nodeadm.MeshPlan{}, err
	}
	joining := meshplan.Node{ID: id, Site: site, MeshIP: a}
	_, before, err := meshplan.Degraded(in.established)
	if err != nil {
		return nodeadm.MeshPlan{}, err
	}
	asNATed := append(slices.Clone(in.established), joining)
	_, after, err := meshplan.Degraded(asNATed)
	if err != nil {
		return nodeadm.MeshPlan{}, err
	}
	for _, s := range after {
		if s != site && !slices.Contains(before, s) {
			return nodeadm.MeshPlan{}, statusErr(http.StatusConflict, "%s", meshplan.Refusal(s))
		}
	}
	p, err := meshplan.Bootstrap(in.established, joining)
	if err != nil {
		return nodeadm.MeshPlan{}, err
	}
	w := nodeagent.WirePlan(p)
	out := nodeadm.MeshPlan{Peers: make([]nodeadm.MeshPeer, 0, len(w.Peers)), Forward: w.Forward}
	for _, q := range w.Peers {
		if validMeshKey(q.Pub) {
			out.Peers = append(out.Peers, nodeadm.MeshPeer(q))
		}
	}
	return out, nil
}

// meshReadyOf is the enrolment's mesh_ready (P17): the joining node took
// its real plan and so did every other node with it as a peer (a node
// that isn't Ready or is already mesh_peer_stale doesn't hold the join
// up: it gets the plan at a later tick). A refusal of the plan (a site
// without a reachable node) fails the enrolment with its text.
func (h *Hub) meshReadyOf(ctx context.Context, id string) (bool, error) {
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return false, err
	}
	c, cancel := context.WithTimeout(ctx, clusterCallWait)
	snap, err := h.clusterSnapshot(c, api)
	cancel()
	if err != nil {
		return false, nil // retried at the next poll
	}
	if err := h.syncMesh(ctx, snap, false); err != nil {
		log.Printf("servers: the enrolment of %s: %v", id, err)
	}
	in := h.meshInputsOf(snap)
	now := h.now()
	ms := &h.cl.ms
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if why, ok := ms.refused[id]; ok {
		return false, statusErr(http.StatusConflict, "%s", why)
	}
	want, ok := ms.want[id]
	if !ok || ms.applied[id] != want {
		return false, nil
	}
	for _, n := range in.established {
		if n.ID == id || !in.ready[n.ID] {
			continue
		}
		if ms.applied[n.ID] != ms.want[n.ID] && !(!ms.failing[n.ID].IsZero() && now.Sub(ms.failing[n.ID]) > MeshStaleAfter) {
			return false, nil
		}
	}
	return true, nil
}

// meshRemove takes node id out of every plan and pushes the plans now.
func (h *Hub) meshRemove(ctx context.Context, id string) error {
	h.cl.ms.mu.Lock()
	h.cl.ms.init()
	h.cl.ms.removed[id] = true
	delete(h.cl.ms.pubs, id)
	h.cl.ms.mu.Unlock()
	return h.pushMesh(ctx)
}

// MeshStatus is the doctor's mesh input (Task 16 folds both kinds into
// doctor.HAKinds): the nodes that missed their plan for more than 5 min
// (id → why) and the sites without a reachable node.
type MeshStatus struct {
	Stale     map[string]string
	NoGateway []string
}

// MeshStatus reads the last push state.
func (h *Hub) MeshStatus() MeshStatus {
	now := h.now()
	ms := &h.cl.ms
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := MeshStatus{Stale: map[string]string{}, NoGateway: slices.Clone(ms.noGateway)}
	for id, t := range ms.failing {
		if now.Sub(t) > MeshStaleAfter {
			out.Stale[id] = ms.lastErr[id]
		}
	}
	return out
}
