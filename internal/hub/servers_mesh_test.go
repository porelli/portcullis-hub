package hub

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/meshplan"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/state"
)

// siteNode is an established node at site with its addresses (public ""
// = behind NAT).
func siteNode(name, role, site, mesh, lan, public string) nodeadm.Node {
	n := nodeadm.Node{Name: name, Role: role, Ready: true, Labels: map[string]string{nodeadm.LabelClass: "home", nodeadm.LabelSite: site},
		Addresses: nodeadm.NodeAddresses{Mesh: mesh, LAN: []string{lan}, Public: []string{}}}
	if public != "" {
		n.Addresses.Public = []string{public}
	}
	return n
}

// twoSites: n1 (main, public), n2 (main, NATed), e1 (edge, public).
func twoSites() []nodeadm.Node {
	return []nodeadm.Node{
		siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"),
		siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""),
		siteNode("e1", "server", "edge", "10.215.0.5", "198.18.0.5", "203.0.113.5"),
	}
}

func meshNodeOf(id, site, mesh, lan, public string) meshplan.Node {
	n := meshplan.Node{ID: id, Site: site, MeshIP: netip.MustParseAddr(mesh), LAN: netip.MustParseAddrPort(lan + ":51830"), Pub: fakeMeshKey(id)}
	if public != "" {
		n.Public = netip.MustParseAddrPort(public + ":51830")
	}
	return n
}

func (f *fakeNodeadm) meshOf(id string) (nodeagent.MeshPlan, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.mesh[id]
	return p, ok
}

func (f *fakeNodeadm) setRefuse(k string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.refuse, k)
	} else {
		f.refuse[k] = err
	}
}

// enrolAt makes the fake cluster take id through its enrolment (the
// pcmesh report at the 3rd read, the Node at the readyAt-th, Ready
// right after).
func enrolAt(cf *clusterFixture, id, site, mesh, lan, public string, readyAt int) {
	cf.na.onCluster = func(n int, s *nodeadm.Snapshot) {
		switch {
		case n == 3:
			rep := nodeadm.MeshReport{Pub: fakeMeshKey(id), LAN: jsonstrict.Some(lan + ":51830")}
			if public != "" {
				rep.Public = jsonstrict.Some(public + ":51830")
			}
			s.Enrolling = []nodeadm.Enrolling{{ID: id, Role: "agent", Class: "home", Site: site, MeshIP: mesh, Mesh: rep}}
		case n == readyAt:
			s.Enrolling = nil
			s.Nodes = append(s.Nodes, siteNode(id, "agent", site, mesh, lan, public))
		}
	}
}

// TestPushMeshOnJoin: a NATed node joining edge: its code carries its
// bootstrap plan (as if NATed); once it reports itself, every nodeagent
// gets the plan meshplan computes with it, the existing nodes before the
// new one (they must hold its peer before the Hub can reach it over
// pcmesh); mesh_ready passes only then, and the relay goes through e1.
func TestPushMeshOnJoin(t *testing.T) {
	cf := newClusterFixture(t, twoSites()...)
	// The cluster tick reads the init nodes' keys (their health) first.
	cf.h.settleClusterNodes(context.Background())
	enrolAt(cf, "e2", "edge", "10.215.0.4", "198.18.0.4", "", 1<<30)
	cf.stopEnrol(t, "e2")
	out, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "e2", Site: "edge", Role: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Site != "edge" {
		t.Fatalf("%+v", out)
	}
	est := []meshplan.Node{
		meshNodeOf("n1", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"),
		meshNodeOf("n2", "main", "10.215.0.2", "192.0.2.2", ""),
		meshNodeOf("e1", "edge", "10.215.0.5", "198.18.0.5", "203.0.113.5"),
	}
	boot, err := meshplan.Bootstrap(est, meshplan.Node{ID: "e2", Site: "edge", MeshIP: netip.MustParseAddr("10.215.0.4")})
	if err != nil {
		t.Fatal(err)
	}
	cf.na.mu.Lock()
	codeMesh := slices.Clone(cf.na.codeMesh)
	cf.na.mu.Unlock()
	if len(codeMesh) != 1 || !reflect.DeepEqual(codeMesh[0], toNodeadmPlan(nodeagent.WirePlan(boot))) {
		t.Errorf("the code's bootstrap plan %+v, want %+v", codeMesh, boot)
	}
	// mesh_ready: every agent holds its plan.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if r := cf.h.LastOp(serverOpKey("e2")); r != nil && meshStep(r, StepMeshReady) == StepDone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mesh_ready never passed: %+v", cf.h.LastOp(serverOpKey("e2")))
		}
		time.Sleep(5 * time.Millisecond)
	}
	all := append(slices.Clone(est), meshNodeOf("e2", "edge", "10.215.0.4", "198.18.0.4", ""))
	want, err := meshplan.Plan(all)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range all {
		got, ok := cf.na.meshOf(n.ID)
		if !ok || !reflect.DeepEqual(got, nodeagent.WirePlan(want[n.ID])) {
			t.Errorf("%s got %+v\nwant %+v", n.ID, got, nodeagent.WirePlan(want[n.ID]))
		}
	}
	if p, _ := cf.na.meshOf("n2"); !peerAllows(p, "e1", "10.215.0.4/32") {
		t.Errorf("n2 doesn't reach e2 through e1: %+v", p)
	}
	if p, _ := cf.na.meshOf("e1"); !p.Forward {
		t.Error("e1 doesn't forward")
	}
	cf.na.mu.Lock()
	order := slices.Clone(cf.na.meshOrder)
	cf.na.mu.Unlock()
	last := slices.Index(order, "e2")
	for _, id := range []string{"n1", "n2", "e1"} {
		if i := slices.Index(order, id); i < 0 || i > last {
			t.Errorf("push order %v: %s must come before e2", order, id)
		}
	}
	// The report is kept for when the snapshot drops it.
	if s, _ := cf.h.serverEntry("e2"); s.MeshPub != fakeMeshKey("e2") || s.MeshLAN != "198.18.0.4:51830" || s.MeshPublic != "" {
		t.Errorf("the entry's report %q %q %q", s.MeshPub, s.MeshLAN, s.MeshPublic)
	}
}

func toNodeadmPlan(w nodeagent.MeshPlan) nodeadm.MeshPlan {
	out := nodeadm.MeshPlan{Peers: []nodeadm.MeshPeer{}, Forward: w.Forward}
	for _, q := range w.Peers {
		out.Peers = append(out.Peers, nodeadm.MeshPeer(q))
	}
	return out
}

func peerAllows(p nodeagent.MeshPlan, peer, cidr string) bool {
	for _, q := range p.Peers {
		if q.ID == peer {
			return slices.Contains(q.AllowedIPs, cidr)
		}
	}
	return false
}

func meshStep(r *OpRecord, key string) string {
	for _, s := range r.Steps {
		if s.Key == key {
			return s.State
		}
	}
	return ""
}

// TestPushMeshPartialFailure: one nodeagent down → the others take the
// plan and pushMesh names only it; the down node is retried every tick
// and, after 5 min of missing it, MeshStatus (doctor mesh_peer_stale)
// names it; once it answers it is cleared. A joining node isn't held up
// by a node already stale.
func TestPushMeshPartialFailure(t *testing.T) {
	cf := newClusterFixture(t, twoSites()...)
	var mu sync.Mutex
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cf.h.srvT.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	cf.na.setRefuse("mesh:n2", errors.New("dial tcp 10.215.0.2:7443: i/o timeout"))
	err := cf.h.pushMesh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "didn't reach n2 ") || strings.Contains(err.Error(), "n1") {
		t.Fatalf("pushMesh: %v", err)
	}
	for _, id := range []string{"n1", "e1"} {
		if _, ok := cf.na.meshOf(id); !ok {
			t.Errorf("%s didn't get its plan", id)
		}
	}
	if st := cf.h.MeshStatus(); len(st.Stale) != 0 {
		t.Errorf("stale before 5 min: %v", st.Stale)
	}
	advance(4 * time.Minute)
	cf.h.settleClusterNodes(context.Background())
	if st := cf.h.MeshStatus(); len(st.Stale) != 0 {
		t.Errorf("stale at 4 min: %v", st.Stale)
	}
	advance(2 * time.Minute)
	cf.h.settleClusterNodes(context.Background())
	st := cf.h.MeshStatus()
	if len(st.Stale) != 1 || !strings.Contains(st.Stale["n2"], "i/o timeout") {
		t.Errorf("stale after 6 min: %v", st.Stale)
	}
	// A join while n2 is stale isn't held up by it.
	enrolAt(cf, "e2", "edge", "10.215.0.4", "198.18.0.4", "", 8)
	cf.na.mu.Lock()
	cf.na.reads = 0
	cf.na.mu.Unlock()
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "e2", Site: "edge", Role: "agent"}); err != nil {
		t.Fatal(err)
	}
	r := waitServerOp(t, cf.h, serverOpKey("e2"))
	if !r.OK {
		t.Fatalf("the join with n2 stale: %+v", r)
	}
	// n2 answers again: the next tick gives it the plan and clears it.
	cf.na.setRefuse("mesh:n2", nil)
	cf.h.settleClusterNodes(context.Background())
	if st := cf.h.MeshStatus(); len(st.Stale) != 0 {
		t.Errorf("still stale: %v", st.Stale)
	}
	if p, ok := cf.na.meshOf("n2"); !ok || !peerAllows(p, "e1", "10.215.0.4/32") {
		t.Errorf("n2's plan after it came back: %+v", p)
	}
}

// TestMeshSiteWithoutGateway: fail closed. A node joining a new site
// while main has no reachable node is refused at once (no code); a NATed
// node joining a site without a reachable node is refused at mesh_ready
// with the §20.11 text, never pushed to the others, and revoked (its k3s
// material never released); a site that loses its gateway is reported
// (mesh_site_no_gateway) while the removal is still pushed.
func TestMeshSiteWithoutGateway(t *testing.T) {
	ctx := context.Background()
	// Main behind NAT only: a node at edge is refused before any code.
	cf := newClusterFixture(t, siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""))
	_, _, err := cf.h.AddClusterNode(ctx, admin, AddClusterNodeRequest{ID: "e1", Site: "edge", Role: "agent"})
	if err == nil || err.Error() != "site main needs one node reachable on UDP 51830 first (a cloud node, or one forwarded port)" {
		t.Fatalf("add at edge with main NATed: %v", err)
	}
	if c := cf.na.Calls(); slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "codes:") }) {
		t.Errorf("a code was issued: %v", c)
	}

	// A NATed node, the first at tb: refused once it reports itself.
	cf = newClusterFixture(t, twoSites()...)
	enrolAt(cf, "t1", "tb", "10.215.0.9", "198.18.1.9", "", 1<<30)
	if _, _, err := cf.h.AddClusterNode(ctx, admin, AddClusterNodeRequest{ID: "t1", Site: "tb", Role: "agent"}); err != nil {
		t.Fatal(err)
	}
	r := waitServerOp(t, cf.h, serverOpKey("t1"))
	if r.OK || !strings.Contains(r.Error, "site tb needs one node reachable on UDP 51830 first (a cloud node, or one forwarded port)") || meshStep(&r, StepMeshReady) != StepFailed {
		t.Fatalf("op %+v", r)
	}
	if _, ok := cf.na.meshOf("t1"); ok {
		t.Error("the refused node got a plan")
	}
	for _, id := range []string{"n1", "n2", "e1"} {
		if p, _ := cf.na.meshOf(id); slices.ContainsFunc(p.Peers, func(q nodeagent.MeshPeer) bool { return q.ID == "t1" }) {
			t.Errorf("%s has the refused node as a peer", id)
		}
	}
	if c := cf.na.Calls(); !slices.Contains(c, "remove:t1:revoke") {
		t.Errorf("the refused node wasn't revoked: %v", c)
	}

	// e1, edge's only gateway, is revoked: its peer goes from every plan
	// and edge is reported without a gateway.
	cf = newClusterFixture(t, append(twoSites(), siteNode("e2", "agent", "edge", "10.215.0.6", "198.18.0.6", ""))...)
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cf.h.RemoveClusterNode(ctx, admin, "e1", "e1", nodeadm.Revoke); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"n1", "n2", "e2"} {
		if p, _ := cf.na.meshOf(id); slices.ContainsFunc(p.Peers, func(q nodeagent.MeshPeer) bool { return q.ID == "e1" }) {
			t.Errorf("%s still has the revoked e1: %+v", id, p)
		}
	}
	if st := cf.h.MeshStatus(); !slices.Equal(st.NoGateway, []string{"edge"}) {
		t.Errorf("no gateway %v", st.NoGateway)
	}
}

// TestMeshKeyFromHealth: a node without an enrolment report (a node of
// init) is planned with the key its nodeagent's health names; while that
// can't be read nothing is pushed (fail static: it would drop out of
// every plan).
func TestMeshKeyFromHealth(t *testing.T) {
	cf := newClusterFixture(t, twoSites()...)
	cf.na.setRefuse("health:n2", errors.New("connection refused"))
	if err := cf.h.pushMesh(context.Background()); err == nil || !strings.Contains(err.Error(), "pcmesh key of n2") {
		t.Fatalf("pushMesh: %v", err)
	}
	cf.na.mu.Lock()
	n := len(cf.na.meshOrder)
	cf.na.mu.Unlock()
	if n != 0 {
		t.Errorf("%d pushes without n2's key", n)
	}
	// An add meanwhile isn't held up: n2 (key unknown) is left out of
	// the bootstrap plan, which never calls a nodeagent.
	cf.stopEnrol(t, "e2")
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "e2", Site: "edge", Role: "agent"}); err != nil {
		t.Fatal(err)
	}
	cf.na.mu.Lock()
	boot := cf.na.codeMesh[0]
	cf.na.mu.Unlock()
	if slices.ContainsFunc(boot.Peers, func(q nodeadm.MeshPeer) bool { return q.ID == "n2" }) || len(boot.Peers) != 2 {
		t.Errorf("bootstrap plan without n2's key: %+v", boot)
	}
	cf.na.setRefuse("health:n2", nil)
	if err := cf.h.pushMesh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p, _ := cf.na.meshOf("n1"); len(p.Peers) < 2 || p.Peers[1].Pub != fakeMeshKey("n2") {
		t.Errorf("n1's plan %+v", p)
	}
}

// TestMeshReadyWaitsForPeers: mesh_ready needs the joining node's plan
// and every Ready node's plan with it: a node that refuses it holds the
// join until it is stale (5 min); a NotReady one doesn't.
func TestMeshReadyWaitsForPeers(t *testing.T) {
	cf := newClusterFixture(t, twoSites()...)
	var mu sync.Mutex
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cf.h.srvT.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	cf.h.mu.Lock()
	if cf.h.st.Servers == nil {
		cf.h.st.Servers = map[string]state.Server{}
	}
	cf.h.st.Servers["e2"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.4"}
	cf.h.mu.Unlock()
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "e2", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.4",
		Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("e2"), LAN: jsonstrict.Some("198.18.0.4:51830")}}}
	cf.na.mu.Unlock()
	ctx := context.Background()
	cf.na.setRefuse("mesh:n2", errors.New("timeout"))
	if ok, err := cf.h.meshReadyOf(ctx, "e2"); ok || err != nil {
		t.Fatalf("ready with n2 missing its plan: %v %v", ok, err)
	}
	mu.Lock()
	now = now.Add(6 * time.Minute)
	mu.Unlock()
	if ok, err := cf.h.meshReadyOf(ctx, "e2"); !ok || err != nil {
		t.Errorf("not ready with n2 stale: %v %v", ok, err)
	}
	// A NotReady node doesn't hold it up either (fresh failure).
	cf = newClusterFixture(t, twoSites()...)
	cf.h.mu.Lock()
	if cf.h.st.Servers == nil {
		cf.h.st.Servers = map[string]state.Server{}
	}
	cf.h.st.Servers["e2"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.4"}
	cf.h.mu.Unlock()
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "e2", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.4",
		Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("e2"), LAN: jsonstrict.Some("198.18.0.4:51830")}}}
	cf.na.snap.Node("n2").Ready = false
	cf.na.mu.Unlock()
	cf.na.setRefuse("mesh:n2", errors.New("timeout"))
	if ok, err := cf.h.meshReadyOf(ctx, "e2"); !ok || err != nil {
		t.Errorf("held up by a NotReady node: %v %v", ok, err)
	}
	// The joining node itself must have taken its plan.
	cf.na.setRefuse("mesh:e2", errors.New("timeout"))
	cf.h.cl.ms.mu.Lock()
	delete(cf.h.cl.ms.applied, "e2")
	cf.h.cl.ms.mu.Unlock()
	if ok, _ := cf.h.meshReadyOf(ctx, "e2"); ok {
		t.Error("ready without the joining node's plan")
	}
}

// TestMeshJoinerKeyRefused: a joining node whose reported key is another
// node's, or isn't a WireGuard key, is refused at mesh_ready with a clear
// error and never enters any plan; a removal is still pushed meanwhile.
func TestMeshJoinerKeyRefused(t *testing.T) {
	ctx := context.Background()
	for name, key := range map[string]string{"e1's key": fakeMeshKey("e1"), "not a key": "x"} {
		cf := newClusterFixture(t, append(twoSites(), siteNode("e3", "agent", "edge", "10.215.0.7", "198.18.0.7", ""))...)
		cf.h.settleClusterNodes(ctx)
		cf.h.mu.Lock()
		if cf.h.st.Servers == nil {
			cf.h.st.Servers = map[string]state.Server{}
		}
		cf.h.st.Servers["e2"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.4"}
		cf.h.mu.Unlock()
		cf.na.mu.Lock()
		cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "e2", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.4",
			Mesh: nodeadm.MeshReport{Pub: key, LAN: jsonstrict.Some("198.18.0.4:51830")}}}
		cf.na.mu.Unlock()
		ok, err := cf.h.meshReadyOf(ctx, "e2")
		if ok || err == nil || !strings.Contains(err.Error(), "the pcmesh key node e2 reported") {
			t.Errorf("%s: mesh_ready %v %v", name, ok, err)
		}
		// The removal of e3 is pushed; e2 is in no plan, e1 keeps its key.
		if err := cf.h.meshRemove(ctx, "e3"); err != nil {
			t.Errorf("%s: the removal wasn't pushed: %v", name, err)
		}
		for _, id := range []string{"n1", "n2", "e1"} {
			p, _ := cf.na.meshOf(id)
			for _, q := range p.Peers {
				if q.ID == "e2" || q.ID == "e3" {
					t.Errorf("%s: %s has peer %s", name, id, q.ID)
				}
				if q.ID == "e1" && q.Pub != fakeMeshKey("e1") {
					t.Errorf("%s: %s's e1 key %q", name, id, q.Pub)
				}
			}
		}
		if _, ok := cf.na.meshOf("e2"); ok {
			t.Errorf("%s: the refused joiner got a plan", name)
		}
	}
}
