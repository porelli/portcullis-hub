package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/meshplan"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// The node mesh across sites and NAT (contract §20.11, §20.4 PUT
// /v1/mesh/peers, §20.2 the bootstrap plan): the Hub computes every
// node's peer plan (internal/meshplan) and pushes it to every nodeagent
// over pcmesh, as hub.control, through fsutil.Do (the write fence). It
// pushes on every join, removal and change of a node's endpoints, and
// every cluster tick to the nodes whose last push failed. One unreachable
// nodeagent never blocks the others.
//
// What the plan trusts:
//   - a node's mesh address and site are the Hub's own records (its
//     Server entry; a node of init: pinned at first sight in state.Mesh);
//     a Node object that disagrees is flagged and left out, alone;
//   - its key is its enrolment report's (recorded once valid and unique,
//     frozen once its plan was pushed), or a node of init's nodeagent's
//     (read once over mTLS pinned to its id, then persisted);
//   - a public endpoint must be a public address (the front door's rule)
//     and is only *offered* until a peer at another site holds a
//     WireGuard handshake from it (GET /v1/health "peers"): then it is
//     reachable; without one within 2 min it is unreachable and the node
//     is planned as NATed. A site of a multi-site mesh with no reachable
//     node is mesh_site_no_gateway, and a joiner that would leave a site
//     so is refused with the §20.11 text before nodeadm can reach it (no
//     k3s material).

// MeshStaleAfter is how long a node may miss its plan before doctor
// mesh_peer_stale names it.
const MeshStaleAfter = 5 * time.Minute

// MeshConfirmWait is how long an offered public endpoint has to show a
// handshake from another site before it counts as unreachable.
const MeshConfirmWait = 2 * time.Minute

// MeshReachableStale: a reachable endpoint without a confirming
// handshake for this long is offered again (confirmed anew, or found
// unreachable).
const MeshReachableStale = 5 * time.Minute

// MeshRetryUnreachable: an unreachable endpoint is offered again this
// long after it was found so (a port forward can come back).
const MeshRetryUnreachable = 30 * time.Minute

// Flapping: an endpoint that changes more than meshFlapChanges times in
// meshFlapWindow is unreachable for MeshRetryUnreachable.
const (
	meshFlapChanges = 3
	meshFlapWindow  = 10 * time.Minute
)

// handshakeFresh: a handshake at most this old (by the reporting node's
// own clock) confirms an endpoint.
const handshakeFresh = 3 * time.Minute

// meshPushWait bounds one nodeagent call.
const meshPushWait = 15 * time.Second

// linkCIDR is the Docker workers' link subnet (never a mesh endpoint).
var linkCIDR = netip.MustParsePrefix("10.214.0.0/24")

// meshState is the Hub's in-memory view of the pushes (the durable part
// is state.Mesh and the Server entries).
type meshState struct {
	mu sync.Mutex
	// run serialises the computations and pushes.
	run sync.Mutex
	// want / applied: the hash of each node's current plan and of the one
	// it last took.
	want, applied map[string]string
	// failing: since when a node's nodeagent refuses or misses its plan.
	failing map[string]time.Time
	lastErr map[string]string
	// refused: joining nodes the plan refuses (id → the refusal text).
	refused map[string]string
	// flagged: reports refused or ignored when recorded (id → why);
	// inputFlags: the nodes the last computation left out or whose
	// endpoint it dropped (id → why). Both are doctor mesh_peer_stale.
	flagged, inputFlags map[string]string
	// noGateway: the sites without a reachable node (last computation,
	// the sites a joiner was refused for included).
	noGateway []string
	// refusedSites: sites a joiner was refused for (no reachable node),
	// kept until one of the site's nodes is a gateway.
	refusedSites map[string]bool
	// offered: nodes whose public endpoint awaits its confirmation.
	offered []string
	// wire: the plans of the last computation (applied == want: what the
	// node holds); firstPush: when this Hub (a fresh start or a takeover)
	// first reached the push stage, from which an offer's 2 min run at
	// the earliest; loaded: applied was read from state.Mesh.
	wire      map[string]nodeagent.MeshPlan
	firstPush time.Time
	loaded    bool
	// allowDoc admits the documentation ranges as public (tests only).
	allowDoc bool
}

func (m *meshState) init() {
	if m.want == nil {
		m.want, m.applied, m.failing, m.lastErr = map[string]string{}, map[string]string{}, map[string]time.Time{}, map[string]string{}
		m.refused, m.flagged, m.inputFlags = map[string]string{}, map[string]string{}, map[string]string{}
		m.refusedSites = map[string]bool{}
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

// validMeshKey is the nodeagent's own check (§20.4): canonical base64 of
// 32 bytes, not all zero.
func validMeshKey(s string) bool { return meshplan.ValidKey(s) }

func siteOf(labels map[string]string) string {
	if s := labels[nodeadm.LabelSite]; s != "" {
		return s
	}
	return servers.PrimarySite
}

// ── endpoints ──

var (
	docRanges = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	// notPublic: what IsGlobalUnicast admits but the internet doesn't
	// route to a host (the front door's list, core domains/frontdoor).
	notPublic = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4")}
)

// meshExcluded are the cluster's own networks: the mesh, the link, the
// pod and the service CIDRs (the core env's, else k3s's defaults).
func (h *Hub) meshExcluded() []netip.Prefix {
	out := []netip.Prefix{meshplan.Prefix, linkCIDR}
	core := readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env"))
	for k, def := range map[string]string{VarPodCIDR: "10.42.0.0/16", VarServiceCIDR: "10.43.0.0/16"} {
		p, err := netip.ParsePrefix(strings.TrimSpace(core[k]))
		if err != nil {
			p = netip.MustParsePrefix(def)
		}
		out = append(out, p.Masked())
	}
	return out
}

// publicEndpointOK: a public endpoint is an IPv4 address the front door
// would publish (global unicast, not private, CGNAT, special-purpose,
// documentation or one of the cluster's networks) with a port.
func publicEndpointOK(ap netip.AddrPort, allowDoc bool, excluded []netip.Prefix) error {
	ip := ap.Addr()
	if !ip.Is4() || ap.Port() == 0 {
		return fmt.Errorf("%s isn't an IPv4 address and port", ap)
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%s isn't a public address", ip)
	}
	for _, n := range notPublic {
		if n.Contains(ip) {
			return fmt.Errorf("%s isn't a public address (%s)", ip, n)
		}
	}
	if !allowDoc {
		for _, n := range docRanges {
			if n.Contains(ip) {
				return fmt.Errorf("%s is a documentation address (%s)", ip, n)
			}
		}
	}
	for _, n := range excluded {
		if n.Contains(ip) {
			return fmt.Errorf("%s is in the cluster's network %s", ip, n)
		}
	}
	return nil
}

// lanEndpointOK: a LAN endpoint may be private, but never loopback,
// link-local, multicast, unspecified, broadcast or one of the cluster's
// networks, and it is the mesh port.
func lanEndpointOK(ap netip.AddrPort, excluded []netip.Prefix) error {
	ip := ap.Addr()
	if !ip.Is4() || ap.Port() != meshplan.Port {
		return fmt.Errorf("%s isn't an IPv4 address on UDP %d", ap, meshplan.Port)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("%s can't be a LAN endpoint", ip)
	}
	for _, n := range excluded {
		if n.Contains(ip) {
			return fmt.Errorf("%s is in the cluster's network %s", ip, n)
		}
	}
	return nil
}

func parseEndpoint(s string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// firstAddr is the first IPv4 address of l on UDP 51830 ("": none).
func firstAddr(l []string) string {
	for _, s := range l {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return netip.AddrPortFrom(a, meshplan.Port).String()
		}
	}
	return ""
}

// ── the records ──

// recordMeshReports keeps the facts the plan trusts:
//   - each enrolling node's pcmesh report in its entry (the snapshot drops
//     it once the node is a Kubernetes Node). Its key is recorded only
//     when it is a WireGuard key no other node holds (by its 32 bytes:
//     the earlier recorded key wins), and it is frozen once the node's
//     plan was pushed or it passed mesh_ready: a later report with
//     another key is ignored and flagged, never a plan change;
//   - a node of init's mesh address and site, pinned at first sight;
//   - records of nodes the cluster no longer lists are dropped.
func (h *Hub) recordMeshReports(snap nodeadm.Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ms := &h.cl.ms
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.init()
	if h.st.Mesh == nil {
		h.st.Mesh = map[string]state.MeshNode{}
	}
	changed := false
	listedIDs := map[string]bool{}
	for _, sn := range snap.Nodes {
		listedIDs[sn.Name] = true
		if _, ok := h.st.Servers[sn.Name]; ok || servers.ValidID(sn.Name) != nil {
			continue
		}
		r := h.st.Mesh[sn.Name]
		if r.MeshIP == "" && sn.Addresses.Mesh != "" {
			r.MeshIP, r.Site = sn.Addresses.Mesh, siteOf(sn.Labels)
			h.st.Mesh[sn.Name] = r
			changed = true
		}
	}
	for _, e := range snap.Enrolling {
		listedIDs[e.ID] = true
	}
	for id, r := range h.st.Mesh {
		if _, entry := h.st.Servers[id]; !listedIDs[id] && (!entry || r.Removed) {
			delete(h.st.Mesh, id)
			changed = true
		}
	}
	for id := range ms.flagged {
		if !listedIDs[id] {
			delete(ms.flagged, id)
		}
	}
	used := map[string]string{} // KeyID → the node holding it
	for id, s := range h.st.Servers {
		if s.ClusterNode() && s.MeshPub != "" && s.State != ServerRevoked {
			used[meshplan.KeyID(s.MeshPub)] = id
		}
	}
	for id, r := range h.st.Mesh {
		if r.Pub != "" {
			used[meshplan.KeyID(r.Pub)] = id
		}
	}
	now := h.now().UTC()
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
		pushed := !s.MeshPlanPushedAt.IsZero()
		frozen := s.MeshPub != "" && (pushed || s.Enrol == nil || (s.Enrol.Step != StepEnrolled && s.Enrol.Step != StepMeshReady))
		holder := used[meshplan.KeyID(e.Mesh.Pub)]
		why := ""
		switch {
		case frozen && s.MeshPub != e.Mesh.Pub:
			why = "its enrolment report changed its pcmesh key after its plan was pushed: ignored"
		case frozen:
			why = "its enrolment report changed its endpoints after its plan was pushed: ignored (enrol it again to change them)"
		case !meshplan.ValidKey(e.Mesh.Pub):
			why = "its enrolment report's pcmesh key isn't a WireGuard key: not recorded"
		case holder != "" && holder != e.ID:
			why = fmt.Sprintf("its enrolment report's pcmesh key is node %s's: not recorded", holder)
		}
		if why != "" {
			if ms.flagged[e.ID] != why {
				log.Printf("servers: node %s: %s", e.ID, why)
			}
			ms.flagged[e.ID] = why
			continue
		}
		delete(ms.flagged, e.ID)
		if s.MeshPub != e.Mesh.Pub {
			s.MeshKeyAt = now
		}
		s.MeshPub, s.MeshLAN, s.MeshPublic = e.Mesh.Pub, lan, pub
		used[meshplan.KeyID(s.MeshPub)] = e.ID
		h.st.Servers[e.ID] = s
		changed = true
	}
	if changed {
		h.saveLocked()
	}
}

// meshInputs are the plan's nodes: the established ones (the snapshot's
// Nodes, but revoked or removed ones) and the joining ones (enrolling,
// with the Hub's entry still enrolling).
type meshInputs struct {
	established, joining []meshplan.Node
	meshIP               map[string]string
	ready                map[string]bool
	// fetch: established nodes whose key the Hub never saw.
	fetch []string
	// keyAt: when each node's key was recorded (zero: a node of init).
	keyAt map[string]time.Time
	// public: each node's valid public endpoint before its reachability
	// is applied; reach: that endpoint's state.
	public map[string]netip.AddrPort
	reach  map[string]string
	// flags: nodes left out, or whose endpoint was dropped (id → why).
	flags map[string]string
}

func (h *Hub) meshInputsOf(snap nodeadm.Snapshot) meshInputs {
	in := meshInputs{meshIP: map[string]string{}, ready: map[string]bool{}, keyAt: map[string]time.Time{},
		public: map[string]netip.AddrPort{}, reach: map[string]string{}, flags: map[string]string{}}
	excluded := h.meshExcluded()
	h.mu.RLock()
	defer h.mu.RUnlock()
	h.cl.ms.mu.Lock()
	allowDoc := h.cl.ms.allowDoc
	h.cl.ms.mu.Unlock()
	// endpoints checks a node's reported endpoints: a bad one is dropped
	// and flagged; the public one gets its reachability.
	endpoints := func(id, lan, public string) (netip.AddrPort, netip.AddrPort) {
		var l, p netip.AddrPort
		var why []string
		if lan != "" {
			if ap, ok := parseEndpoint(lan); !ok {
				why = append(why, "its LAN endpoint is malformed")
			} else if err := lanEndpointOK(ap, excluded); err != nil {
				why = append(why, "its LAN endpoint "+err.Error())
			} else {
				l = ap
			}
		}
		if public != "" {
			if ap, ok := parseEndpoint(public); !ok {
				why = append(why, "its public endpoint is malformed")
			} else if err := publicEndpointOK(ap, allowDoc, excluded); err != nil {
				why = append(why, "its public endpoint "+err.Error())
			} else {
				p = ap
			}
		}
		if len(why) > 0 {
			in.flags[id] = strings.Join(why, "; ") + ": dropped from the mesh plan"
		}
		if p.IsValid() {
			in.public[id] = p
			r := h.st.Mesh[id]
			reach := state.ReachOffered
			if r.Public == p.String() && r.Reach != "" {
				reach = r.Reach
			}
			in.reach[id] = reach
			if reach == state.ReachUnreachable {
				p = netip.AddrPort{} // planned as NATed
			}
		}
		return l, p
	}
	for _, sn := range snap.Nodes {
		id := sn.Name
		if servers.ValidID(id) != nil || h.st.Mesh[id].Removed {
			continue
		}
		s, listed := h.st.Servers[id]
		if listed && (!s.ClusterNode() || s.State == ServerRevoked) {
			continue
		}
		var mesh, site, pub, lan, public string
		var keyAt time.Time
		if listed {
			mesh, site = s.MeshIP, nonEmpty(s.Site, servers.PrimarySite)
			pub, lan, public, keyAt = s.MeshPub, s.MeshLAN, s.MeshPublic, s.MeshKeyAt
			if pub == "" {
				// An entry without a report (an init node the Hub took
				// over): its addresses as a node of init.
				pub = h.st.Mesh[id].Pub
				lan, public = firstAddr(sn.Addresses.LAN), firstAddr(sn.Addresses.Public)
			}
		} else {
			r := h.st.Mesh[id]
			mesh, site, pub = r.MeshIP, nonEmpty(r.Site, servers.PrimarySite), r.Pub
			lan, public = firstAddr(sn.Addresses.LAN), firstAddr(sn.Addresses.Public)
		}
		// The Hub's records win; a Node object that disagrees is left out.
		if sn.Addresses.Mesh != "" && mesh != "" && sn.Addresses.Mesh != mesh {
			in.flags[id] = fmt.Sprintf("its Node object names mesh ip %s, the Hub's record %s: left out of the mesh plan", clipRunes(sn.Addresses.Mesh, 40), mesh)
			continue
		}
		if l := sn.Labels[nodeadm.LabelSite]; l != "" && l != site {
			in.flags[id] = fmt.Sprintf("its Node object names site %s, the Hub's record %s: left out of the mesh plan", clipRunes(l, 40), site)
			continue
		}
		a, err := netip.ParseAddr(mesh)
		if err != nil {
			in.flags[id] = "it has no mesh address on record: left out of the mesh plan"
			continue
		}
		l, p := endpoints(id, lan, public)
		if !validMeshKey(pub) {
			in.fetch = append(in.fetch, id)
		}
		in.meshIP[id] = mesh
		in.established = append(in.established, meshplan.Node{ID: id, Site: site, MeshIP: a, LAN: l, Public: p, Pub: pub})
		in.ready[id] = sn.Ready
		in.keyAt[id] = keyAt
	}
	for _, e := range snap.Enrolling {
		s, listed := h.st.Servers[e.ID]
		if h.st.Mesh[e.ID].Removed || !listed || !s.ClusterNode() || s.State != ServerEnrolling || snap.Node(e.ID) != nil {
			continue
		}
		// A joining node's mesh address and site are the Hub's own; its key
		// only its recorded report's, else its current one (never read from
		// its nodeagent, never a reason to hold the others' plans).
		a, err := netip.ParseAddr(s.MeshIP)
		if err != nil {
			continue
		}
		pub, lan, public, keyAt := s.MeshPub, s.MeshLAN, s.MeshPublic, s.MeshKeyAt
		if pub == "" {
			pub, keyAt = e.Mesh.Pub, time.Time{}
			lan, public = "", ""
			if e.Mesh.LAN.Valid {
				lan = e.Mesh.LAN.V
			}
			if e.Mesh.Public.Valid {
				public = e.Mesh.Public.V
			}
		}
		l, p := endpoints(e.ID, lan, public)
		in.meshIP[e.ID] = s.MeshIP
		in.keyAt[e.ID] = keyAt
		in.joining = append(in.joining, meshplan.Node{ID: e.ID, Site: nonEmpty(s.Site, servers.PrimarySite), MeshIP: a, LAN: l, Public: p, Pub: pub})
	}
	sort.Slice(in.joining, func(i, j int) bool { return in.joining[i].ID < in.joining[j].ID })
	return in
}

// fetchPubs reads the pcmesh key of the nodes the Hub never saw from their
// nodeagent's GET /v1/health (its id must answer) and persists it.
func (h *Hub) fetchPubs(ctx context.Context, in meshInputs) (map[string]string, error) {
	var mu sync.Mutex
	var errs []string
	got, failed := map[string]string{}, map[string]string{}
	var wg sync.WaitGroup
	for _, id := range in.fetch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ag, err := h.meshAgentOf(ctx, id, in.meshIP[id])
			var hl nodeagent.Health
			if err == nil {
				c, cancel := context.WithTimeout(ctx, meshPushWait)
				hl, err = ag.Health(c)
				cancel()
				if err == nil && (hl.ID != id || !validMeshKey(hl.MeshPub)) {
					err = fmt.Errorf("its nodeagent answered as %q with key %q", clipRunes(hl.ID, 40), clipRunes(hl.MeshPub, 60))
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", id, clipRunes(err.Error(), 160)))
				failed[id] = clipRunes(err.Error(), 160)
			} else {
				got[id] = hl.MeshPub
			}
		}()
	}
	wg.Wait()
	if len(got) > 0 {
		h.mu.Lock()
		if h.st.Mesh == nil {
			h.st.Mesh = map[string]state.MeshNode{}
		}
		for id, k := range got {
			r := h.st.Mesh[id]
			r.Pub = k
			h.st.Mesh[id] = r
		}
		h.saveLocked()
		h.mu.Unlock()
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return failed, fmt.Errorf("the pcmesh key of %s", strings.Join(errs, "; "))
	}
	return failed, nil
}

// ── reachability ──

// updateReach keeps each public endpoint's state in a multi-site mesh
// (persisted in state.Mesh):
//   - a new or changed endpoint is offered;
//   - an offered one is reachable once a node at another site reports a
//     fresh handshake with it on that endpoint, else unreachable after
//     MeshConfirmWait;
//   - a reachable one without such a handshake for MeshReachableStale is
//     offered again;
//   - an unreachable one is offered again after MeshRetryUnreachable.
func (h *Hub) updateReach(ctx context.Context, in meshInputs) {
	all := append(slices.Clone(in.established), in.joining...)
	siteOfID := map[string]string{}
	sites := map[string]bool{}
	for _, n := range all {
		siteOfID[n.ID] = n.Site
		sites[n.Site] = true
	}
	if len(sites) < 2 {
		return
	}
	now := h.now().UTC()
	h.mu.Lock()
	if h.st.Mesh == nil {
		h.st.Mesh = map[string]state.MeshNode{}
	}
	var watch []string // offered or reachable: their handshakes are read
	changed := false
	for id, p := range in.public {
		if _, ok := siteOfID[id]; !ok {
			continue
		}
		r := h.st.Mesh[id]
		switch {
		case r.Reach == "":
			r.Public, r.Reach, r.OfferedAt, r.CheckedAt = p.String(), state.ReachOffered, now, time.Time{}
		case r.Public != p.String():
			// A change: offered again, but an offer's clock keeps running
			// (OfferedAt isn't reset); a flapping endpoint is held
			// unreachable.
			var recent []time.Time
			for _, t := range r.Changes {
				if now.Sub(t) < meshFlapWindow {
					recent = append(recent, t)
				}
			}
			r.Changes = append(recent, now)
			r.Public = p.String()
			switch {
			case len(r.Changes) > meshFlapChanges:
				r.Reach, r.CheckedAt, r.HoldUntil = state.ReachUnreachable, now, now.Add(MeshRetryUnreachable)
				log.Printf("servers: the node mesh: %s's public endpoint changed %d times in %s: unreachable for %s", id, len(r.Changes), meshFlapWindow, MeshRetryUnreachable)
			case now.Before(r.HoldUntil):
				r.Reach = state.ReachUnreachable
			case r.Reach == state.ReachOffered && !r.OfferedAt.IsZero():
				// still the same offer
			default:
				r.Reach, r.OfferedAt = state.ReachOffered, now
			}
		case r.Reach == state.ReachUnreachable && now.Sub(r.CheckedAt) >= MeshRetryUnreachable && !now.Before(r.HoldUntil):
			r.Reach, r.OfferedAt = state.ReachOffered, now
			log.Printf("servers: the node mesh: offering %s's public endpoint %s again", id, r.Public)
		default:
			if r.Reach != state.ReachUnreachable {
				watch = append(watch, id)
			}
			continue
		}
		h.st.Mesh[id] = r
		changed = true
		if r.Reach != state.ReachUnreachable {
			watch = append(watch, id)
		}
	}
	if changed {
		h.saveLocked()
	}
	h.mu.Unlock()
	if len(watch) == 0 {
		return
	}
	// The confirmers' views of their peers: only established nodes the
	// plan kept (sanitizeEstablished) that hold their pushed plan; a
	// joining, refused or flagged node's report never counts. Parallel; a
	// silent one confirms nothing.
	est, _ := sanitizeEstablished(in)
	h.cl.ms.mu.Lock()
	var confirmers []meshplan.Node
	held := map[string]nodeagent.MeshPlan{} // the plans nodes hold now
	for id, w := range h.cl.ms.wire {
		if a := h.cl.ms.applied[id]; a != "" && a == h.cl.ms.want[id] {
			held[id] = w
		}
	}
	for _, n := range est {
		if _, ok := held[n.ID]; ok && in.flags[n.ID] == "" {
			confirmers = append(confirmers, n)
		}
	}
	firstPush := h.cl.ms.firstPush
	h.cl.ms.mu.Unlock()
	var mu sync.Mutex
	views := map[string]nodeagent.Health{}
	var wg sync.WaitGroup
	for _, n := range confirmers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ag, err := h.meshAgentOf(ctx, n.ID, in.meshIP[n.ID])
			if err != nil {
				return
			}
			c, cancel := context.WithTimeout(ctx, meshPushWait)
			hl, err := ag.Health(c)
			cancel()
			if err == nil && hl.ID == n.ID {
				mu.Lock()
				views[n.ID] = hl
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	changed = false
	for _, x := range watch {
		r := h.st.Mesh[x]
		confirmed := ""
		for y, hl := range views {
			if siteOfID[y] != siteOfID[x] && dialledIn(held, y, x, r.Public) && handshakeConfirms(hl, x, r.Public) {
				confirmed = y
				break
			}
		}
		switch {
		case confirmed != "":
			if r.Reach != state.ReachReachable {
				log.Printf("servers: the node mesh: %s's public endpoint %s answers (a handshake from %s)", x, r.Public, confirmed)
			}
			r.Reach, r.CheckedAt = state.ReachReachable, now
		case r.Reach == state.ReachOffered && !firstPush.IsZero() && now.Sub(laterOf(r.OfferedAt, firstPush)) >= MeshConfirmWait:
			r.Reach, r.CheckedAt = state.ReachUnreachable, now
			log.Printf("servers: the node mesh: no handshake with %s on %s within %s: it is planned as behind NAT", x, r.Public, MeshConfirmWait)
		case r.Reach == state.ReachReachable && now.Sub(r.CheckedAt) > MeshReachableStale:
			r.Reach, r.OfferedAt = state.ReachOffered, now
			log.Printf("servers: the node mesh: no fresh handshake with %s on %s for %s: offered again", x, r.Public, MeshReachableStale)
		default:
			continue
		}
		h.st.Mesh[x] = r
		changed = true
	}
	if changed {
		h.saveLocked()
	}
}

// dialledIn: confirmer y's handshake with x proves x answers on ep only
// when y dialled x: the plan y holds lists x on ep, and the plan x holds
// lists y with no endpoint (x waits to be dialled: it can't have started
// the session, so a port-preserving NAT's outbound mapping proves
// nothing).
func dialledIn(held map[string]nodeagent.MeshPlan, y, x, ep string) bool {
	yp, ok1 := held[y]
	xp, ok2 := held[x]
	if !ok1 || !ok2 {
		return false
	}
	var toX, toY *nodeagent.MeshPeer
	for i := range yp.Peers {
		if yp.Peers[i].ID == x {
			toX = &yp.Peers[i]
		}
	}
	for i := range xp.Peers {
		if xp.Peers[i].ID == y {
			toY = &xp.Peers[i]
		}
	}
	return toX != nil && toY != nil && toX.Endpoint.Valid && toX.Endpoint.V == ep && !toY.Endpoint.Valid
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// waitToBeDialled: while x's public endpoint is offered, x waits to be
// dialled by its peers at other sites (their entries in x's plan lose
// their endpoint), so a handshake proves the endpoint answers. Of two
// offered nodes the lower id waits and the higher one dials (the lower is
// confirmed first, then the other way round).
func waitToBeDialled(wire map[string]nodeagent.MeshPlan, siteOfID map[string]string, offered []string) {
	isOffered := map[string]bool{}
	for _, id := range offered {
		isOffered[id] = true
	}
	for _, x := range offered {
		p, ok := wire[x]
		if !ok {
			continue
		}
		peers := slices.Clone(p.Peers)
		for i, q := range peers {
			if siteOfID[q.ID] != siteOfID[x] && (!isOffered[q.ID] || x < q.ID) {
				peers[i].Endpoint = jsonstrict.Nullable[string]{}
			}
		}
		p.Peers = peers
		wire[x] = p
	}
}

// handshakeConfirms: hl (a node's GET /v1/health) holds a handshake with
// peer x on endpoint ep at most handshakeFresh old by its own clock.
func handshakeConfirms(hl nodeagent.Health, x, ep string) bool {
	ps, ok := hl.Peers[x]
	if !ok || !ps.LatestHandshake.Valid || !ps.Endpoint.Valid {
		return false
	}
	got, ok := parseEndpoint(ps.Endpoint.V)
	if !ok || got.String() != ep {
		return false
	}
	at, err := time.Parse(time.RFC3339, ps.LatestHandshake.V)
	if err != nil {
		return false
	}
	ref, err := time.Parse(time.RFC3339, hl.Time)
	if err != nil {
		return false
	}
	d := ref.Sub(at)
	return d >= -time.Minute && d <= handshakeFresh
}

// ── planning ──

// planMesh: the established nodes' plan (Degraded: a site that lost its
// gateway is reported, never a reason to keep a removed peer), plus each
// joining node the plan admits. A joining node is refused (with a clear
// text) when its key isn't a WireGuard key or another node holds it (the
// earlier recorded one keeps it), or when it would leave a site (its own
// included) without a reachable node (the §20.11 text).
func planMesh(in meshInputs) (plans map[string]meshplan.NodePlan, noGateway []string, refused, dropped map[string]string, err error) {
	est, dropped := sanitizeEstablished(in)
	_, missing, err := meshplan.Degraded(est)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	refused = map[string]string{}
	taken := map[string]bool{}
	for _, n := range in.established {
		taken[meshplan.KeyID(n.Pub)] = true
	}
	// The earlier recorded joiner first (an unrecorded one last).
	joiners := slices.Clone(in.joining)
	sort.SliceStable(joiners, func(i, j int) bool {
		a, b := in.keyAt[joiners[i].ID], in.keyAt[joiners[j].ID]
		switch {
		case a.IsZero() != b.IsZero():
			return !a.IsZero()
		case !a.Equal(b):
			return a.Before(b)
		}
		return joiners[i].ID < joiners[j].ID
	})
	include := slices.Clone(est)
	gwSites := map[string]bool{}
	for _, j := range joiners {
		if !validMeshKey(j.Pub) {
			refused[j.ID] = fmt.Sprintf("the pcmesh key node %s reported isn't a WireGuard key: it can't join", j.ID)
			continue
		}
		if taken[meshplan.KeyID(j.Pub)] {
			refused[j.ID] = fmt.Sprintf("the pcmesh key node %s reported is used by another node: it can't join", j.ID)
			continue
		}
		taken[meshplan.KeyID(j.Pub)] = true
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
			gwSites[bad] = true
			continue
		}
		include = trial
	}
	plans, noGateway, err = meshplan.Degraded(include)
	for s := range gwSites {
		if !slices.Contains(noGateway, s) {
			noGateway = append(noGateway, s)
		}
	}
	sort.Strings(noGateway)
	return plans, noGateway, refused, dropped, err
}

// sanitizeEstablished: the established nodes the plan can take. One whose
// key isn't a WireGuard key, whose mesh address is outside the mesh, or
// that shares a key (by its 32 bytes) or a mesh address with a node
// recorded earlier (a node of init first, ties by id) is left out and
// named, alone: the rest of the plan still goes out.
func sanitizeEstablished(in meshInputs) ([]meshplan.Node, map[string]string) {
	order := slices.Clone(in.established)
	sort.SliceStable(order, func(i, j int) bool {
		a, b := in.keyAt[order[i].ID], in.keyAt[order[j].ID]
		if !a.Equal(b) {
			return a.Before(b)
		}
		return order[i].ID < order[j].ID
	})
	keyHolder := map[string]string{}
	ipHolder := map[netip.Addr]string{}
	dropped := map[string]string{}
	var keep []meshplan.Node
	for _, n := range order {
		a := n.MeshIP
		switch k := meshplan.KeyID(n.Pub); {
		case !validMeshKey(n.Pub):
			dropped[n.ID] = "its pcmesh key isn't known or isn't a WireGuard key: left out of the mesh plan"
		case !a.Is4() || !meshplan.Prefix.Contains(a) || a.As4()[3] == 0 || a.As4()[3] == 255:
			dropped[n.ID] = fmt.Sprintf("its mesh ip %s is outside %s: left out of the mesh plan", a, meshplan.Prefix)
		case keyHolder[k] != "":
			dropped[n.ID] = fmt.Sprintf("its pcmesh key is node %s's too: left out of the mesh plan", keyHolder[k])
		case ipHolder[a] != "":
			dropped[n.ID] = fmt.Sprintf("its mesh ip %s is node %s's too: left out of the mesh plan", a, ipHolder[a])
		default:
			keyHolder[k], ipHolder[a] = n.ID, n.ID
			keep = append(keep, n)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].ID < keep[j].ID })
	return keep, dropped
}

func planHash(p nodeagent.MeshPlan) string {
	b, _ := json.Marshal(p)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ── pushing ──

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
	h.loadApplied()
	in := h.meshInputsOf(snap)
	var keyless map[string]string
	if len(in.fetch) > 0 {
		var err error
		if keyless, err = h.fetchPubs(ctx, in); err != nil {
			// A node never seen whose key can't be read is left out and
			// flagged; it never holds up the others (a node seen once is
			// planned with its last-known key).
			log.Printf("servers: %v", err)
		}
	}
	in = h.meshInputsOf(snap)
	h.updateReach(ctx, in)
	in = h.meshInputsOf(snap)
	for id, why := range keyless {
		in.flags[id] = "its nodeagent didn't give its pcmesh key (" + why + "): left out of the mesh plan until it does"
	}
	plans, noGateway, refused, dropped, err := planMesh(in)
	if err != nil {
		return fmt.Errorf("the mesh plan: %v", err)
	}
	joining := map[string]bool{}
	for _, j := range in.joining {
		joining[j.ID] = true
	}
	var offered []string
	for id, r := range in.reach {
		if _, planned := plans[id]; planned && r == state.ReachOffered && len(siteSet(in)) >= 2 {
			offered = append(offered, id)
		}
	}
	sort.Strings(offered)
	now := h.now()
	ms := &h.cl.ms
	ms.mu.Lock()
	ms.init()
	est, _ := sanitizeEstablished(in)
	for site := range ms.refusedSites {
		if _, ok := meshplan.Gateway(est, site); ok {
			delete(ms.refusedSites, site)
		}
	}
	for _, why := range refused {
		for _, site := range noGateway {
			if why == meshplan.Refusal(site) {
				ms.refusedSites[site] = true
			}
		}
	}
	for site := range ms.refusedSites {
		if !slices.Contains(noGateway, site) {
			noGateway = append(noGateway, site)
		}
	}
	sort.Strings(noGateway)
	ms.noGateway = noGateway
	ms.refused = refused
	ms.offered = offered
	ms.inputFlags = map[string]string{}
	for id, why := range dropped {
		ms.inputFlags[id] = why
	}
	for id, why := range in.flags {
		ms.inputFlags[id] = why
	}
	wire := map[string]nodeagent.MeshPlan{}
	for id, p := range plans {
		wire[id] = nodeagent.WirePlan(p)
	}
	siteOfID := map[string]string{}
	for _, n := range append(slices.Clone(in.established), in.joining...) {
		siteOfID[n.ID] = n.Site
	}
	waitToBeDialled(wire, siteOfID, offered)
	for id := range wire {
		ms.want[id] = planHash(wire[id])
	}
	ms.wire = wire
	if ms.firstPush.IsZero() {
		ms.firstPush = now
	}
	for id := range ms.want {
		if _, ok := plans[id]; !ok {
			delete(ms.want, id)
			delete(ms.applied, id)
			delete(ms.failing, id)
			delete(ms.lastErr, id)
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
	// Persisted: what each node holds, and a joiner's first push (its key
	// and endpoints frozen from then on).
	h.mu.Lock()
	ms.mu.Lock()
	if h.st.Mesh == nil {
		h.st.Mesh = map[string]state.MeshNode{}
	}
	saved := false
	for id, w := range wire {
		hash := planHash(w)
		if ms.applied[id] != hash {
			continue
		}
		if r := h.st.Mesh[id]; r.Applied != hash {
			r.Applied = hash
			h.st.Mesh[id] = r
			saved = true
		}
		if s, ok := h.st.Servers[id]; ok && s.ClusterNode() && s.MeshPlanPushedAt.IsZero() {
			s.MeshPlanPushedAt = now.UTC()
			h.st.Servers[id] = s
			saved = true
		}
	}
	ms.mu.Unlock()
	if saved {
		h.saveLocked()
	}
	h.mu.Unlock()
	if len(failed) > 0 {
		sort.Strings(failed)
		return fmt.Errorf("the mesh plan didn't reach %s (retried every tick)", strings.Join(failed, ", "))
	}
	return nil
}

// loadApplied reads, once per Hub (a start or a takeover), the plan hash
// each node last took from state.Mesh: an unchanged plan isn't pushed
// again.
func (h *Hub) loadApplied() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ms := &h.cl.ms
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.init()
	if ms.loaded {
		return
	}
	ms.loaded = true
	for id, r := range h.st.Mesh {
		if r.Applied != "" && ms.applied[id] == "" {
			ms.applied[id] = r.Applied
		}
	}
}

func siteSet(in meshInputs) map[string]bool {
	out := map[string]bool{}
	for _, n := range in.established {
		out[n.Site] = true
	}
	for _, n := range in.joining {
		out[n.Site] = true
	}
	return out
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
// A node whose key the Hub never saw is read now; one that doesn't answer
// is left out of the bootstrap plan (the real plan, pushed before
// mesh_ready, has every node).
func (h *Hub) bootstrapMeshPlan(ctx context.Context, id, site, meshIP string, snap nodeadm.Snapshot) (nodeadm.MeshPlan, error) {
	h.recordMeshReports(snap)
	in := h.meshInputsOf(snap)
	if len(in.fetch) > 0 {
		if _, err := h.fetchPubs(ctx, in); err != nil {
			log.Printf("servers: the bootstrap plan of %s: %v (left out)", id, err)
		}
		in = h.meshInputsOf(snap)
	}
	a, err := netip.ParseAddr(meshIP)
	if err != nil {
		return nodeadm.MeshPlan{}, err
	}
	joining := meshplan.Node{ID: id, Site: site, MeshIP: a}
	est, _ := sanitizeEstablished(in)
	before := meshplan.MissingGateways(est)
	for _, s := range meshplan.MissingGateways(append(slices.Clone(est), joining)) {
		if s != site && !slices.Contains(before, s) {
			return nodeadm.MeshPlan{}, statusErr(http.StatusConflict, "%s", meshplan.Refusal(s))
		}
	}
	p, err := meshplan.Bootstrap(est, joining)
	if err != nil {
		return nodeadm.MeshPlan{}, err
	}
	w := nodeagent.WirePlan(p)
	out := nodeadm.MeshPlan{Peers: make([]nodeadm.MeshPeer, 0, len(w.Peers)), Forward: w.Forward}
	for _, q := range w.Peers {
		out.Peers = append(out.Peers, nodeadm.MeshPeer(q))
	}
	return out, nil
}

// meshReadyOf is the enrolment's mesh_ready (P17): every public endpoint
// of a multi-site mesh is confirmed (or found unreachable, and the plan
// redone), the joining node took its real plan and so did every other
// node with it as a peer (a node that isn't Ready or is already
// mesh_peer_stale doesn't hold the join up: it gets the plan at a later
// tick). A refusal of the plan (a site without a reachable node) fails the
// enrolment with its text.
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
	est, _ := sanitizeEstablished(in)
	candidates := slices.Clone(est)
	for _, j := range in.joining {
		if _, refused := ms.refused[j.ID]; !refused {
			candidates = append(candidates, j)
		}
	}
	if meshWaitsOn(candidates, id, ms.offered) {
		return false, nil // an endpoint its plan depends on is still unproven
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

// meshWaitsOn: joiner id's plan depends on an offered endpoint: its own,
// or the gateway candidate (the node Gateway picks with the offered
// endpoints counted) of any site, its own included. nodes are the nodes
// the plan takes: the sanitised established ones and the admitted
// joiners (a left-out or refused node is never a candidate).
func meshWaitsOn(nodes []meshplan.Node, id string, offered []string) bool {
	if len(offered) == 0 {
		return false
	}
	if slices.Contains(offered, id) {
		return true
	}
	sites := map[string]bool{}
	for _, n := range nodes {
		sites[n.Site] = true
	}
	for s := range sites {
		if g, ok := meshplan.Gateway(nodes, s); ok && slices.Contains(offered, g) {
			return true
		}
	}
	return false
}

// meshRemove takes node id out of every plan (persisted, until the
// cluster no longer lists it) and pushes the plans now.
func (h *Hub) meshRemove(ctx context.Context, id string) error {
	h.mu.Lock()
	if h.st.Mesh == nil {
		h.st.Mesh = map[string]state.MeshNode{}
	}
	r := h.st.Mesh[id]
	r.Removed = true
	h.st.Mesh[id] = r
	h.saveLocked()
	h.mu.Unlock()
	return h.pushMesh(ctx)
}

// MeshStatus is the doctor's mesh input (Task 16 folds both kinds into
// doctor.HAKinds): the nodes that missed their plan for more than 5 min,
// or that the plan leaves out or whose report it refused (id → why), and
// the sites without a reachable node.
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
	for id, why := range ms.inputFlags {
		out.Stale[id] = why
	}
	for id, why := range ms.flagged {
		out.Stale[id] = why
	}
	return out
}
