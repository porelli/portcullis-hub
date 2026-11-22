package hub

import (
	"context"
	"errors"
	"fmt"
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
	enrolAt(cf, "e2", "edge", "10.215.0.3", "198.18.0.4", "", 1<<30)
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
	boot, err := meshplan.Bootstrap(est, meshplan.Node{ID: "e2", Site: "edge", MeshIP: netip.MustParseAddr("10.215.0.3")})
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
	all := append(slices.Clone(est), meshNodeOf("e2", "edge", "10.215.0.3", "198.18.0.4", ""))
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
	if p, _ := cf.na.meshOf("n2"); !peerAllows(p, "e1", "10.215.0.3/32") {
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
	enrolAt(cf, "e2", "edge", "10.215.0.3", "198.18.0.4", "", 8)
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
	if p, ok := cf.na.meshOf("n2"); !ok || !peerAllows(p, "e1", "10.215.0.3/32") {
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
// init) is planned with the key its nodeagent's health names; one whose
// key was never read (its nodeagent down) is left out and flagged
// mesh_peer_stale, and never holds up the others' plans.
func TestMeshKeyFromHealth(t *testing.T) {
	cf := newClusterFixture(t, twoSites()...)
	cf.na.setRefuse("health:n2", errors.New("connection refused"))
	if err := cf.h.pushMesh(context.Background()); err != nil {
		t.Fatalf("pushMesh: %v", err)
	}
	for _, id := range []string{"n1", "e1"} {
		p, ok := cf.na.meshOf(id)
		if !ok || peerKeyOf(p, "n2") != "" {
			t.Errorf("%s's plan without n2: %v %+v", id, ok, p)
		}
	}
	if _, ok := cf.na.meshOf("n2"); ok {
		t.Error("n2 got a plan")
	}
	if why := cf.h.MeshStatus().Stale["n2"]; !strings.Contains(why, "didn't give its pcmesh key (") || !strings.Contains(why, "connection refused") {
		t.Errorf("flag %q", why)
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
	cf.h.st.Servers["e2"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.3"}
	cf.h.mu.Unlock()
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "e2", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.3",
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
	cf.h.st.Servers["e2"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.3"}
	cf.h.mu.Unlock()
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "e2", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.3",
		Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("e2"), LAN: jsonstrict.Some("198.18.0.4:51830")}}}
	cf.na.snap.Node("n2").Ready = false
	cf.na.mu.Unlock()
	cf.na.setRefuse("mesh:n2", errors.New("timeout"))
	// The first round pushes the plans; the next one sees the handshakes
	// that confirm the public endpoints.
	ok, err := false, error(nil)
	for i := 0; i < 3 && !ok && err == nil; i++ {
		ok, err = cf.h.meshReadyOf(ctx, "e2")
	}
	if !ok || err != nil {
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
		cf.h.st.Servers["e2"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.3"}
		cf.h.mu.Unlock()
		cf.na.mu.Lock()
		cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "e2", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.3",
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

// altKey is a non-canonical spelling of the fake key k (same 32 bytes).
func altKey(k string) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	return k[:42] + string(a[strings.IndexByte(a, k[42])^1]) + k[43:]
}

func enrollingE2(cf *clusterFixture, key, step string) {
	cf.h.mu.Lock()
	if cf.h.st.Servers == nil {
		cf.h.st.Servers = map[string]state.Server{}
	}
	cf.h.st.Servers["e2"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.3",
		Enrol: &state.Enrol{Step: step}}
	cf.h.mu.Unlock()
	setReport(cf, key)
}

func setReport(cf *clusterFixture, key string) {
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "e2", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.3",
		Mesh: nodeadm.MeshReport{Pub: key, LAN: jsonstrict.Some("198.18.0.4:51830")}}}
	cf.na.mu.Unlock()
}

func peerKeyOf(p nodeagent.MeshPlan, id string) string {
	for _, q := range p.Peers {
		if q.ID == id {
			return q.Pub
		}
	}
	return ""
}

// TestMeshKeyRecordedOnceValid: a report's key is recorded only when it is
// a canonical WireGuard key no other node uses (a non-canonical spelling
// of e1's key is e1's key: refused, flagged); it is frozen once the node
// passed mesh_ready: a later report with another key is ignored and
// flagged, and the plans keep the recorded key.
func TestMeshKeyRecordedOnceValid(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	cf.h.settleClusterNodes(ctx) // the init nodes' keys
	enrollingE2(cf, fakeMeshKey("e1"), StepMeshReady)
	if ok, err := cf.h.meshReadyOf(ctx, "e2"); ok || err == nil || !strings.Contains(err.Error(), "the pcmesh key node e2 reported is used by another node") {
		t.Errorf("e1's key: %v %v", ok, err)
	}
	if s, _ := cf.h.serverEntry("e2"); s.MeshPub != "" {
		t.Errorf("recorded %q", s.MeshPub)
	}
	if why := cf.h.MeshStatus().Stale["e2"]; !strings.Contains(why, "node e1's") {
		t.Errorf("flag %q", why)
	}
	if p, _ := cf.na.meshOf("n1"); peerKeyOf(p, "e1") != fakeMeshKey("e1") || peerKeyOf(p, "e2") != "" {
		t.Errorf("n1's plan %+v", p)
	}
	// A non-canonical spelling (of e1's key, or of a fresh one) is no
	// WireGuard key: the nodeagent would refuse it too.
	for _, k := range []string{altKey(fakeMeshKey("e1")), altKey(fakeMeshKey("e2"))} {
		cf = newClusterFixture(t, twoSites()...)
		cf.h.settleClusterNodes(ctx)
		enrollingE2(cf, k, StepMeshReady)
		if ok, err := cf.h.meshReadyOf(ctx, "e2"); ok || err == nil || !strings.Contains(err.Error(), "isn't a WireGuard key") {
			t.Errorf("%q: %v %v", k, ok, err)
		}
		if why := cf.h.MeshStatus().Stale["e2"]; !strings.Contains(why, "isn't a WireGuard key") {
			t.Errorf("flag %q", why)
		}
		if p, _ := cf.na.meshOf("e1"); peerKeyOf(p, "e2") != "" {
			t.Errorf("e1 has the refused e2: %+v", p)
		}
	}
	// Frozen after mesh_ready.
	cf = newClusterFixture(t, twoSites()...)
	cf.h.settleClusterNodes(ctx)
	enrollingE2(cf, fakeMeshKey("e2"), StepMeshReady)
	if ok, err := readyWithin(cf, "e2", 6); !ok || err != nil {
		t.Fatalf("e2's own key: %v %v", ok, err)
	}
	cf.h.setEnrolStep("e2", StepK3sJoined)
	other := fakeMeshKey("e2x")
	setReport(cf, other)
	if err := cf.h.pushMesh(ctx); err != nil { // not the tick: it would end the op-less enrolment
		t.Fatal(err)
	}
	if s, _ := cf.h.serverEntry("e2"); s.MeshPub != fakeMeshKey("e2") {
		t.Errorf("the frozen key changed to %q", s.MeshPub)
	}
	if p, _ := cf.na.meshOf("e1"); peerKeyOf(p, "e2") != fakeMeshKey("e2") {
		t.Errorf("e1's peer e2 key %q", peerKeyOf(p, "e2"))
	}
	if why := cf.h.MeshStatus().Stale["e2"]; !strings.Contains(why, "changed its pcmesh key after its plan was pushed") {
		t.Errorf("flag %q", why)
	}
}

// TestMeshEstablishedSharedKey: two established nodes sharing a key (by
// its bytes): the one whose key was recorded later is left out of the
// plan and flagged; the rest of the plan (a removal included) goes out.
func TestMeshEstablishedSharedKey(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, append(twoSites(), siteNode("e3", "agent", "edge", "10.215.0.7", "198.18.0.7", ""))...)
	cf.h.mu.Lock()
	cf.h.st.Servers = map[string]state.Server{"e3": {Kind: state.KindClusterNode, State: ServerReady, Site: "edge", MeshIP: "10.215.0.7",
		MeshPub: fakeMeshKey("n2"), MeshLAN: "198.18.0.7:51830", MeshKeyAt: time.Now()}}
	cf.h.mu.Unlock()
	err := cf.h.pushMesh(ctx)
	if err != nil {
		t.Fatalf("the plan didn't go out: %v", err)
	}
	for _, id := range []string{"n1", "n2", "e1"} {
		p, ok := cf.na.meshOf(id)
		if !ok || peerKeyOf(p, "e3") != "" {
			t.Errorf("%s: %v %+v", id, ok, p)
		}
	}
	if p, _ := cf.na.meshOf("n1"); peerKeyOf(p, "n2") != fakeMeshKey("n2") {
		t.Errorf("n2 lost its place: %+v", p)
	}
	if _, ok := cf.na.meshOf("e3"); ok {
		t.Error("the later node got a plan")
	}
	if why := cf.h.MeshStatus().Stale["e3"]; !strings.Contains(why, "node n2's too") {
		t.Errorf("flag %q", why)
	}
	if err := cf.h.meshRemove(ctx, "e1"); err != nil {
		t.Errorf("a removal with the shared key present: %v", err)
	}
	if p, _ := cf.na.meshOf("n1"); peerKeyOf(p, "e1") != "" {
		t.Errorf("e1 still in n1's plan")
	}
}

// TestDedupeByKeyBytes: established nodes compare keys by their 32 bytes
// (two spellings of one key are one key); the later-recorded one is left
// out, a node of init (zero time) wins, ties by id.
func TestDedupeByKeyBytes(t *testing.T) {
	k := fakeMeshKey("n2")
	in := meshInputs{keyAt: map[string]time.Time{"a": time.Unix(200, 0), "b": time.Unix(100, 0)},
		established: []meshplan.Node{
			meshNodeOf("a", "main", "10.215.0.3", "192.0.2.3", ""), meshNodeOf("b", "main", "10.215.0.4", "192.0.2.4", ""),
			meshNodeOf("c", "main", "10.215.0.5", "192.0.2.5", "")}}
	in.established[0].Pub, in.established[1].Pub, in.established[2].Pub = k, k, fakeMeshKey("c")
	keep, dupes := sanitizeEstablished(in)
	if len(keep) != 2 || keep[0].ID != "b" || keep[1].ID != "c" || !strings.Contains(dupes["a"], "node b's") {
		t.Errorf("keep %v dupes %v", keep, dupes)
	}
	in.keyAt = map[string]time.Time{"a": time.Unix(200, 0)} // b: a node of init
	if _, dupes := sanitizeEstablished(in); !strings.Contains(dupes["a"], "node b's") {
		t.Errorf("init node lost: %v", dupes)
	}
	// Another spelling of b's key is no WireGuard key (the nodeagent's
	// rule): left out, and never mistaken for a different key.
	in.established[0].Pub = altKey(k)
	if _, dupes := sanitizeEstablished(in); !strings.Contains(dupes["a"], "isn't a WireGuard key") {
		t.Errorf("non-canonical spelling: %v", dupes)
	}
	in.established[0].Pub = k
	plans, _, _, dupes, err := planMesh(in)
	if err != nil || len(plans) != 2 || dupes["a"] == "" {
		t.Errorf("planMesh %v %v %v", plans, dupes, err)
	}
}

// fakeClockHub sets a movable clock on the Hub.
func fakeClockHub(cf *clusterFixture) func(time.Duration) {
	var mu sync.Mutex
	now := time.Now().UTC()
	cf.h.srvT.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	return func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
}

func (cf *clusterFixture) meshRecord(id string) state.MeshNode {
	cf.h.mu.RLock()
	defer cf.h.mu.RUnlock()
	return cf.h.st.Mesh[id]
}

func (cf *clusterFixture) closeEndpoint(ep string) {
	cf.na.mu.Lock()
	if cf.na.closed == nil {
		cf.na.closed = map[string]bool{}
	}
	cf.na.closed[ep] = true
	cf.na.mu.Unlock()
}

// TestMeshHomeMainForwardsOnlyWeb (S-I1): a home main whose router
// forwards only 80/443: its node's ingress address is offered on 51830,
// no node at edge ever holds a handshake from it, so after 2 min it is
// unreachable, main has no gateway, and the cloud node joining edge is
// refused at mesh_ready with the §20.11 text (revoked, no k3s material)
// instead of hanging at mesh_pending.
func TestMeshHomeMainForwardsOnlyWeb(t *testing.T) {
	cf := newClusterFixture(t,
		siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"),
		siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""))
	advance := fakeClockHub(cf)
	cf.stopEnrol(t, "e1") // a failure never leaves the op running
	cf.closeEndpoint("203.0.113.1:51830")
	cf.h.settleClusterNodes(context.Background())
	enrolAt(cf, "e1", "edge", "10.215.0.3", "198.18.0.3", "203.0.113.5", 1<<30)
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "e1", Site: "edge", Role: "agent", Class: "cloud"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for cf.meshRecord("n1").Reach != state.ReachOffered {
		if time.Now().After(deadline) {
			t.Fatalf("n1 never offered: %+v", cf.meshRecord("n1"))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if r := cf.h.LastOp(serverOpKey("e1")); r == nil || !r.Running {
		t.Fatalf("the join didn't wait for the confirmation: %+v", r)
	}
	advance(MeshConfirmWait + time.Second)
	r := waitServerOp(t, cf.h, serverOpKey("e1"))
	want := "site main needs one node reachable on UDP 51830 first (a cloud node, or one forwarded port)"
	if r.OK || !strings.Contains(r.Error, want) || meshStep(&r, StepMeshReady) != StepFailed {
		t.Fatalf("op %+v", r)
	}
	if rec := cf.meshRecord("n1"); rec.Reach != state.ReachUnreachable || rec.Public != "203.0.113.1:51830" {
		t.Errorf("n1's record %+v", rec)
	}
	if rec := cf.meshRecord("e1"); rec.Reach != state.ReachReachable {
		t.Errorf("e1's record %+v (n1 holds a handshake from it)", rec)
	}
	if c := cf.na.Calls(); !slices.Contains(c, "remove:e1:revoke") {
		t.Errorf("e1 wasn't revoked: %v", c)
	}
	if st := cf.h.MeshStatus(); !slices.Contains(st.NoGateway, "main") {
		t.Errorf("no gateway %v", st.NoGateway)
	}
	for _, id := range []string{"n1", "n2"} {
		if p, _ := cf.na.meshOf(id); peerKeyOf(p, "e1") != "" {
			t.Errorf("%s kept the refused e1", id)
		}
	}
}

// TestMeshEndpointBecomesReachable: an offered public endpoint with a
// fresh handshake from another site, on that endpoint, is reachable (and
// stays so past the 2 min); the node is a gateway. The record survives a
// restart (state.Mesh).
func TestMeshEndpointBecomesReachable(t *testing.T) {
	cf := newClusterFixture(t, twoSites()...)
	advance := fakeClockHub(cf)
	ctx := context.Background()
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := cf.meshRecord("n1"); rec.Reach != state.ReachOffered {
		t.Fatalf("first push: %+v", rec)
	}
	// Both offered: the lower id (e1) waits and is dialled first, then
	// n1 waits for the now reachable e1.
	for i := 0; i < 3; i++ {
		if err := cf.h.pushMesh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"n1", "e1"} {
		if rec := cf.meshRecord(id); rec.Reach != state.ReachReachable {
			t.Errorf("%s: %+v", id, rec)
		}
	}
	// 10 min later: two reachable nodes can't prove each other with a
	// session either may have started (N1), so a stale one is offered
	// again, waits to be dialled and is confirmed again within a few
	// ticks; it is never found unreachable while it answers.
	advance(10 * time.Minute)
	for i := 0; i < 4; i++ {
		if err := cf.h.pushMesh(ctx); err != nil {
			t.Fatal(err)
		}
		if rec := cf.meshRecord("n1"); rec.Reach == state.ReachUnreachable {
			t.Fatalf("n1 unreachable while it answers: %+v", rec)
		}
	}
	if rec := cf.meshRecord("n1"); rec.Reach != state.ReachReachable {
		t.Errorf("n1 after 10 min: %+v", rec)
	}
	if p, _ := cf.na.meshOf("e1"); peerKeyOf(p, "n1") == "" || p.Peers[0].ID != "n1" || p.Peers[0].Endpoint.V != "203.0.113.1:51830" {
		t.Errorf("e1's plan %+v", p)
	}
	if st := cf.h.MeshStatus(); len(st.NoGateway) != 0 {
		t.Errorf("no gateway %v", st.NoGateway)
	}
}

// TestMeshRestartWithInitNodeDown (Q-I1, Q-M4): the init nodes' keys
// and a removal are persisted; after a restart (the in-memory state gone)
// with n2 down, the removal of e3 is still pushed (n2 planned with its
// last-known key, named as missing its plan) and a removed init node
// doesn't come back.
func TestMeshRestartWithInitNodeDown(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, append(twoSites(), siteNode("e3", "agent", "edge", "10.215.0.7", "198.18.0.7", ""))...)
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := cf.meshRecord("n2"); rec.Pub != fakeMeshKey("n2") || rec.MeshIP != "10.215.0.2" || rec.Site != "main" {
		t.Fatalf("n2's record %+v", rec)
	}
	cf.h.cl.ms = meshState{allowDoc: true} // a restart
	cf.na.setRefuse("health:n2", errors.New("down"))
	cf.na.setRefuse("mesh:n2", errors.New("down"))
	err := cf.h.meshRemove(ctx, "e3")
	if err == nil || !strings.Contains(err.Error(), "didn't reach n2 ") {
		t.Fatalf("remove e3 with n2 down: %v", err)
	}
	for _, id := range []string{"n1", "e1"} {
		p, _ := cf.na.meshOf(id)
		if peerKeyOf(p, "e3") != "" || peerKeyOf(p, "n2") != fakeMeshKey("n2") {
			t.Errorf("%s's plan %+v", id, p)
		}
	}
	cf.h.cl.ms = meshState{allowDoc: true} // another restart: e3 still listed
	if err := cf.h.pushMesh(ctx); err == nil || strings.Contains(err.Error(), "pcmesh key") {
		t.Errorf("push: %v", err)
	}
	if p, _ := cf.na.meshOf("n1"); peerKeyOf(p, "e3") != "" {
		t.Error("the removed e3 came back after a restart")
	}
}

// TestMeshNodeObjectDisagrees (Q-I2): the Hub's records are the truth. A
// Node object claiming another node's mesh ip, or another site, is left
// out alone and flagged; every other node still gets its plan.
func TestMeshNodeObjectDisagrees(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, append(twoSites(), siteNode("e3", "agent", "edge", "10.215.0.7", "198.18.0.7", ""))...)
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	// e3 (a node of init) now claims n2's mesh ip; e1 relabels itself.
	cf.na.mu.Lock()
	cf.na.snap.Node("e3").Addresses.Mesh = "10.215.0.2"
	cf.na.snap.Node("e1").Labels[nodeadm.LabelSite] = "main"
	cf.na.mu.Unlock()
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatalf("one node's lie stopped the push: %v", err)
	}
	st := cf.h.MeshStatus()
	if !strings.Contains(st.Stale["e3"], "mesh ip 10.215.0.2, the Hub's record 10.215.0.7") || !strings.Contains(st.Stale["e1"], "site main, the Hub's record edge") {
		t.Errorf("flags %v", st.Stale)
	}
	p, _ := cf.na.meshOf("n1")
	if peerKeyOf(p, "e3") != "" || peerKeyOf(p, "e1") != "" || peerKeyOf(p, "n2") != fakeMeshKey("n2") {
		t.Errorf("n1's plan %+v", p)
	}
	// A Hub-added node: its entry's site and mesh ip win the same way.
	cf.h.mu.Lock()
	if cf.h.st.Servers == nil {
		cf.h.st.Servers = map[string]state.Server{}
	}
	cf.h.st.Servers["e3"] = state.Server{Kind: state.KindClusterNode, State: ServerReady, Site: "edge", MeshIP: "10.215.0.7",
		MeshPub: fakeMeshKey("e3"), MeshLAN: "198.18.0.7:51830", MeshKeyAt: time.Now()}
	cf.h.mu.Unlock()
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cf.h.MeshStatus().Stale["e3"], "the Hub's record 10.215.0.7") {
		t.Errorf("listed e3: %v", cf.h.MeshStatus().Stale)
	}
}

// TestMeshEndpointRules (Q-I3): a public endpoint must be an address the
// front door would publish; a LAN endpoint may be private but not
// loopback, link-local, multicast or the cluster's networks. A bad one is
// dropped (the node planned without it) and flagged.
func TestMeshEndpointRules(t *testing.T) {
	ex := []netip.Prefix{meshplan.Prefix, linkCIDR, netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("10.43.0.0/16")}
	for ep, ok := range map[string]bool{
		"8.8.8.8:51830": true, "8.8.8.8:40000": true, "203.0.113.1:51830": false, "10.0.0.1:51830": false, "192.168.1.1:51830": false,
		"100.64.1.1:51830": false, "127.0.0.1:51830": false, "169.254.1.1:51830": false, "0.0.0.0:51830": false, "224.0.0.1:51830": false,
		"198.18.0.1:51830": false, "240.0.0.1:51830": false, "10.215.0.9:51830": false, "8.8.8.8:0": false, "[2001:4860::1]:51830": false,
	} {
		if err := publicEndpointOK(netip.MustParseAddrPort(ep), false, ex); (err == nil) != ok {
			t.Errorf("public %s: %v", ep, err)
		}
	}
	for ep, ok := range map[string]bool{
		"192.168.1.5:51830": true, "10.0.0.5:51830": true, "172.16.0.5:51830": true, "192.168.1.5:40000": false, "127.0.0.1:51830": false,
		"169.254.1.1:51830": false, "224.0.0.1:51830": false, "0.0.0.0:51830": false, "10.215.0.9:51830": false, "10.214.0.9:51830": false,
		"10.42.1.1:51830": false, "10.43.0.10:51830": false, "255.255.255.255:51830": false,
	} {
		if err := lanEndpointOK(netip.MustParseAddrPort(ep), ex); (err == nil) != ok {
			t.Errorf("lan %s: %v", ep, err)
		}
	}
	// A node of init whose public address is a mesh address, and a LAN on
	// loopback: both dropped and flagged, the node planned NATed.
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	cf.na.mu.Lock()
	cf.na.snap.Node("n1").Addresses = nodeadm.NodeAddresses{Mesh: "10.215.0.1", LAN: []string{"127.0.0.1"}, Public: []string{"10.215.0.9"}}
	cf.na.snap.Nodes = append(cf.na.snap.Nodes, siteNode("n3", "server", "main", "10.215.0.4", "192.0.2.4", "203.0.113.4"))
	cf.na.mu.Unlock()
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if why := cf.h.MeshStatus().Stale["n1"]; !strings.Contains(why, "LAN endpoint 127.0.0.1 can't be a LAN endpoint") || !strings.Contains(why, "public endpoint 10.215.0.9 isn't a public address") {
		t.Errorf("flag %q", why)
	}
	p, _ := cf.na.meshOf("e1")
	for _, q := range p.Peers {
		if q.ID == "n1" && q.Endpoint.Valid {
			t.Errorf("e1 reaches n1 on %s", q.Endpoint.V)
		}
	}
}

// TestMeshJoinerKeyEarlierWins (Q-M1, Q-M3): a second joiner reporting the
// key the first one recorded is refused, the first one isn't; a key is
// frozen once its plan was pushed, before the step moves on.
func TestMeshJoinerKeyEarlierWins(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	cf.h.settleClusterNodes(ctx)
	enrollingE2(cf, fakeMeshKey("e2"), StepMeshReady)
	for i := 0; i < 3; i++ {
		cf.h.meshReadyOf(ctx, "e2")
	}
	cf.h.mu.Lock()
	cf.h.st.Servers["e4"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.8", Enrol: &state.Enrol{Step: StepMeshReady}}
	cf.h.mu.Unlock()
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = append(cf.na.snap.Enrolling, nodeadm.Enrolling{ID: "e4", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.8",
		Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("e2"), LAN: jsonstrict.Some("198.18.0.8:51830")}})
	cf.na.mu.Unlock()
	if ok, err := cf.h.meshReadyOf(ctx, "e2"); !ok || err != nil {
		t.Errorf("the first joiner: %v %v", ok, err)
	}
	if _, err := cf.h.meshReadyOf(ctx, "e4"); err == nil || !strings.Contains(err.Error(), "is used by another node") {
		t.Errorf("the second joiner: %v", err)
	}
	// e2's plan was pushed: a new key is ignored though its step is still
	// mesh_ready.
	cf.na.mu.Lock()
	cf.na.snap.Enrolling[0].Mesh.Pub = fakeMeshKey("e2b")
	cf.na.mu.Unlock()
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if s, _ := cf.h.serverEntry("e2"); s.MeshPub != fakeMeshKey("e2") {
		t.Errorf("e2's key moved to %q", s.MeshPub)
	}
	// Q-M2: once neither joiner is listed, their flags go.
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = nil
	cf.na.mu.Unlock()
	cf.h.mu.Lock()
	delete(cf.h.st.Servers, "e2")
	delete(cf.h.st.Servers, "e4")
	cf.h.mu.Unlock()
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if st := cf.h.MeshStatus(); st.Stale["e2"] != "" || st.Stale["e4"] != "" {
		t.Errorf("stale flags kept: %v", st.Stale)
	}
}

// TestMeshReachabilityRechecked: a reachable endpoint whose cross-site
// handshakes stop for more than 5 min is offered again, then (still
// silent) unreachable after 2 min; an unreachable one is offered again
// after 30 min and, answering, is reachable again.
func TestMeshReachabilityRechecked(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	advance := fakeClockHub(cf)
	push := func() {
		t.Helper()
		if err := cf.h.pushMesh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		push()
	}
	if r := cf.meshRecord("n1"); r.Reach != state.ReachReachable {
		t.Fatalf("n1 %+v", r)
	}
	cf.closeEndpoint("203.0.113.1:51830") // the port forward goes
	advance(4 * time.Minute)
	push()
	if r := cf.meshRecord("n1"); r.Reach != state.ReachReachable {
		t.Errorf("at 4 min: %+v", r)
	}
	advance(2 * time.Minute)
	push()
	if r := cf.meshRecord("n1"); r.Reach != state.ReachOffered {
		t.Errorf("at 6 min without a handshake: %+v", r)
	}
	advance(MeshConfirmWait + time.Second)
	push()
	if r := cf.meshRecord("n1"); r.Reach != state.ReachUnreachable {
		t.Errorf("2 min later: %+v", r)
	}
	if p, _ := cf.na.meshOf("e1"); p.Peers[0].ID != "n1" || p.Peers[0].Endpoint.Valid {
		t.Errorf("e1 still uses n1's endpoint: %+v", p)
	}
	cf.na.mu.Lock()
	delete(cf.na.closed, "203.0.113.1:51830") // it comes back
	cf.na.mu.Unlock()
	advance(29 * time.Minute)
	push()
	if r := cf.meshRecord("n1"); r.Reach != state.ReachUnreachable {
		t.Errorf("at 29 min: %+v", r)
	}
	advance(2 * time.Minute)
	push() // offered again: planned direct
	if r := cf.meshRecord("n1"); r.Reach != state.ReachOffered {
		t.Errorf("at 31 min: %+v", r)
	}
	push()
	if r := cf.meshRecord("n1"); r.Reach != state.ReachReachable {
		t.Errorf("answering again: %+v", r)
	}
}

// TestMeshJoinerCantConfirm: only an established node that holds its
// pushed plan confirms an endpoint. A joining node claiming a handshake
// with n1 on its closed 51830 confirms nothing: n1 ends unreachable.
func TestMeshJoinerCantConfirm(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	advance := fakeClockHub(cf)
	cf.closeEndpoint("203.0.113.1:51830")
	enrollingE2(cf, fakeMeshKey("e2"), StepMeshReady)
	cf.na.mu.Lock()
	cf.na.liar = map[string]bool{"e2": true}
	cf.na.mu.Unlock()
	for i := 0; i < 3; i++ {
		cf.h.meshReadyOf(ctx, "e2")
	}
	if r := cf.meshRecord("n1"); r.Reach != state.ReachOffered {
		t.Fatalf("n1 confirmed by the joiner: %+v", r)
	}
	advance(MeshConfirmWait + time.Second)
	cf.h.meshReadyOf(ctx, "e2")
	if r := cf.meshRecord("n1"); r.Reach != state.ReachUnreachable {
		t.Errorf("n1 after 2 min: %+v", r)
	}
	// An established liar (n2, same site as n1 anyway, and e1 honest)
	// changes nothing either: e1, at another site and honest, is the only
	// one that could confirm.
	if r := cf.meshRecord("e1"); r.Reach != state.ReachReachable {
		t.Errorf("e1 (confirmed by n1, established): %+v", r)
	}
}

// TestMeshFlappingNodeDoesntBlockJoin: n3's public endpoint changes on
// every snapshot. It isn't a gateway candidate (n1 is main's), so a join
// at edge isn't held up by it; after more than 3 changes in 10 min it is
// held unreachable for 30 min.
func TestMeshFlappingNodeDoesntBlockJoin(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, append(twoSites(), siteNode("n3", "server", "main", "10.215.0.4", "192.0.2.4", "203.0.113.40"))...)
	advance := fakeClockHub(cf)
	flips := 0
	cf.na.onCluster = func(_ int, s *nodeadm.Snapshot) {
		flips++
		s.Node("n3").Addresses.Public = []string{fmt.Sprintf("203.0.113.%d", 40+flips%2)}
	}
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cf.h.pushMesh(ctx); err != nil { // n1, e1 confirmed
		t.Fatal(err)
	}
	// n3 never answers: it stays offered until its flaps hold it.
	cf.closeEndpoint("203.0.113.40:51830")
	cf.closeEndpoint("203.0.113.41:51830")
	enrollingE2(cf, fakeMeshKey("e2"), StepMeshReady)
	ok := false
	for i := 0; i < 2 && !ok; i++ { // n3 has at most 3 changes by then: still offered
		var err error
		if ok, err = cf.h.meshReadyOf(ctx, "e2"); err != nil {
			t.Fatal(err)
		}
		advance(10 * time.Second)
	}
	if !ok {
		t.Errorf("the join waited on the flapping n3: %+v", cf.meshRecord("n3"))
	}
	for i := 0; i < 4; i++ { // more flaps within 10 min
		if err := cf.h.pushMesh(ctx); err != nil {
			t.Fatal(err)
		}
		advance(10 * time.Second)
	}
	r := cf.meshRecord("n3")
	if r.Reach != state.ReachUnreachable || !r.HoldUntil.After(cf.h.now().Add(25*time.Minute)) {
		t.Errorf("n3 after its flaps: %+v", r)
	}
	// Held: a further change within the 30 min doesn't offer it again.
	advance(5 * time.Minute)
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if r := cf.meshRecord("n3"); r.Reach != state.ReachUnreachable {
		t.Errorf("n3 offered again while held: %+v", r)
	}
	// A flapping gateway candidate does hold a join up: its own endpoint.
	if !meshWaitsOn([]meshplan.Node{meshNodeOf("n1", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1")}, "e9", []string{"n1"}) {
		t.Error("a join didn't wait on an offered gateway candidate")
	}
}

// TestMeshEndpointsFrozenAfterPush: once a joiner's plan was pushed, a
// report changing its endpoints is ignored and flagged.
func TestMeshEndpointsFrozenAfterPush(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	cf.h.settleClusterNodes(ctx)
	enrollingE2(cf, fakeMeshKey("e2"), StepMeshReady)
	for i := 0; i < 3; i++ {
		cf.h.meshReadyOf(ctx, "e2")
	}
	cf.na.mu.Lock()
	cf.na.snap.Enrolling[0].Mesh.Public = jsonstrict.Some("8.8.8.8:51830")
	cf.na.mu.Unlock()
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if s, _ := cf.h.serverEntry("e2"); s.MeshPublic != "" {
		t.Errorf("e2's public moved to %q", s.MeshPublic)
	}
	if why := cf.h.MeshStatus().Stale["e2"]; !strings.Contains(why, "changed its endpoints after its plan was pushed") {
		t.Errorf("flag %q", why)
	}
}

// readyWithin runs mesh_ready up to n rounds.
func readyWithin(cf *clusterFixture, id string, n int) (bool, error) {
	for i := 0; i < n; i++ {
		ok, err := cf.h.meshReadyOf(context.Background(), id)
		if ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// TestMeshOutboundHandshakeProvesNothing (N1): a home n1 whose router
// forwards only 443 but keeps the source port: its outbound session to the
// reachable e1 shows e1 the peer n1 at exactly n1's offered endpoint. That
// proves nothing (n1 dialled), so n1 stays offered, waits to be dialled
// (no endpoint for its peers elsewhere) and is unreachable after 2 min;
// a NATed node joining tb is then refused with the §20.11 text.
func TestMeshOutboundHandshakeProvesNothing(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t,
		siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"),
		siteNode("e1", "server", "edge", "10.215.0.5", "198.18.0.5", "203.0.113.5"))
	advance := fakeClockHub(cf)
	cf.closeEndpoint("203.0.113.1:51830")
	cf.na.mu.Lock()
	cf.na.outbound = map[string]string{"n1": "203.0.113.1:51830"} // port-preserving NAT
	cf.na.mu.Unlock()
	for i := 0; i < 4; i++ {
		if err := cf.h.pushMesh(ctx); err != nil {
			t.Fatal(err)
		}
		if r := cf.meshRecord("n1"); r.Reach != state.ReachOffered {
			t.Fatalf("round %d: n1 %+v", i, r)
		}
	}
	if p, _ := cf.na.meshOf("n1"); p.Peers[0].ID != "e1" || p.Peers[0].Endpoint.Valid {
		t.Errorf("offered n1 doesn't wait to be dialled: %+v", p)
	}
	advance(MeshConfirmWait + time.Second)
	if err := cf.h.pushMesh(ctx); err != nil {
		t.Fatal(err)
	}
	if r := cf.meshRecord("n1"); r.Reach != state.ReachUnreachable {
		t.Fatalf("n1 after 2 min: %+v", r)
	}
	cf.h.mu.Lock()
	if cf.h.st.Servers == nil {
		cf.h.st.Servers = map[string]state.Server{}
	}
	cf.h.st.Servers["t1"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "tb", MeshIP: "10.215.0.9", Enrol: &state.Enrol{Step: StepMeshReady}}
	cf.h.mu.Unlock()
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = []nodeadm.Enrolling{{ID: "t1", Role: "agent", Class: "home", Site: "tb", MeshIP: "10.215.0.9",
		Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("t1"), LAN: jsonstrict.Some("198.18.1.9:51830")}}}
	cf.na.mu.Unlock()
	_, err := readyWithin(cf, "t1", 3)
	if err == nil || !strings.Contains(err.Error(), "site tb needs one node reachable on UDP 51830 first") {
		t.Errorf("the NATed tb joiner: %v", err)
	}
}

// TestMeshFailoverMidConfirmation (N3): a Hub takeover in the middle of an
// offer: the new Hub loads what the nodes hold and the freeze from state,
// and an offered endpoint is never found unreachable before a full 2 min
// after the new Hub's first push; a frozen joiner stays frozen.
func TestMeshFailoverMidConfirmation(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	advance := fakeClockHub(cf)
	cf.closeEndpoint("203.0.113.1:51830")
	cf.h.settleClusterNodes(ctx)
	enrollingE2(cf, fakeMeshKey("e2"), StepMeshReady)
	cf.h.meshReadyOf(ctx, "e2")
	if s, _ := cf.h.serverEntry("e2"); s.MeshPlanPushedAt.IsZero() {
		t.Fatal("e2's first push wasn't recorded")
	}
	applied := cf.meshRecord("n2").Applied
	if applied == "" {
		t.Fatal("n2's applied plan wasn't persisted")
	}
	advance(90 * time.Second)
	cf.h.cl.ms = meshState{allowDoc: true} // the takeover: memory gone
	advance(60 * time.Second)              // 2.5 min since n1 was offered
	cf.na.mu.Lock()
	cf.na.meshOrder = nil
	cf.na.snap.Enrolling[0].Mesh.Pub = fakeMeshKey("e2x")
	cf.na.mu.Unlock()
	cf.h.meshReadyOf(ctx, "e2")
	cf.h.meshReadyOf(ctx, "e2") // the new Hub has pushed: its clock runs from here
	if r := cf.meshRecord("n1"); r.Reach != state.ReachOffered {
		t.Errorf("n1 judged right after the takeover: %+v", r)
	}
	if s, _ := cf.h.serverEntry("e2"); s.MeshPub != fakeMeshKey("e2") {
		t.Errorf("e2 unfrozen by the takeover: %q", s.MeshPub)
	}
	cf.na.mu.Lock()
	again := slices.Contains(cf.na.meshOrder, "n2")
	cf.na.mu.Unlock()
	if !again || cf.meshRecord("n2").Applied != applied {
		t.Errorf("the new leader didn't push n2's plan once (pushed %v, applied %q)", again, cf.meshRecord("n2").Applied)
	}
	advance(MeshConfirmWait + time.Second)
	cf.h.meshReadyOf(ctx, "e2")
	if r := cf.meshRecord("n1"); r.Reach != state.ReachUnreachable {
		t.Errorf("n1 2 min after the new Hub's first push: %+v", r)
	}
}

// confirmAll pushes until every public endpoint of the fixture is
// reachable (both offered at first: one round each way).
func confirmAll(t *testing.T, cf *clusterFixture, ids ...string) {
	t.Helper()
	for i := 0; i < 4; i++ {
		if err := cf.h.pushMesh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range ids {
		if r := cf.meshRecord(id); r.Reach != state.ReachReachable {
			t.Fatalf("%s not confirmed: %+v", id, r)
		}
	}
}

// TestMeshUnpushedNodeCantConfirm: an established node that doesn't hold
// its current plan (its push failed) confirms nothing, even claiming a
// handshake on exactly the endpoint the plan it didn't take would dial.
func TestMeshUnpushedNodeCantConfirm(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	advance := fakeClockHub(cf)
	confirmAll(t, cf, "n1", "e1")
	// n1's address changes to one nothing answers on; e1 can't take the
	// plan that dials it, and lies.
	cf.closeEndpoint("203.0.113.9:51830")
	cf.na.setRefuse("mesh:e1", errors.New("timeout"))
	cf.na.mu.Lock()
	cf.na.snap.Node("n1").Addresses.Public = []string{"203.0.113.9"}
	cf.na.claims = map[string]map[string]string{"e1": {"n1": "203.0.113.9:51830"}}
	cf.na.mu.Unlock()
	for i := 0; i < 3; i++ {
		cf.h.pushMesh(ctx)
	}
	if r := cf.meshRecord("n1"); r.Reach != state.ReachOffered {
		t.Fatalf("n1 confirmed by e1 without its plan: %+v", r)
	}
	advance(MeshConfirmWait + time.Second)
	cf.h.pushMesh(ctx)
	if r := cf.meshRecord("n1"); r.Reach != state.ReachUnreachable {
		t.Errorf("n1: %+v", r)
	}
}

// TestMeshRefusedNodeIsNoGatewayCandidate (N2): a refused joiner with a
// public address and a lower id than edge's real gateway candidate never
// stands in for it: e2 still waits while e1's (new) endpoint is unproven.
func TestMeshRefusedNodeIsNoGatewayCandidate(t *testing.T) {
	cf := newClusterFixture(t, twoSites()...)
	fakeClockHub(cf)
	confirmAll(t, cf, "n1", "e1")
	cf.closeEndpoint("203.0.113.6:51830")
	cf.na.mu.Lock()
	cf.na.snap.Node("e1").Addresses.Public = []string{"203.0.113.6"} // offered again, never answers
	cf.na.mu.Unlock()
	enrollingE2(cf, fakeMeshKey("e2"), StepMeshReady)
	cf.h.mu.Lock()
	cf.h.st.Servers["e0"] = state.Server{Kind: state.KindClusterNode, State: ServerEnrolling, Site: "edge", MeshIP: "10.215.0.8", Enrol: &state.Enrol{Step: StepMeshReady}}
	cf.h.mu.Unlock()
	cf.na.mu.Lock()
	cf.na.snap.Enrolling = append(cf.na.snap.Enrolling, nodeadm.Enrolling{ID: "e0", Role: "agent", Class: "home", Site: "edge", MeshIP: "10.215.0.8",
		Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("n1"), LAN: jsonstrict.Some("198.18.0.8:51830"), Public: jsonstrict.Some("203.0.113.8:51830")}})
	cf.na.mu.Unlock()
	if _, err := readyWithin(cf, "e0", 2); err == nil || !strings.Contains(err.Error(), "used by another node") {
		t.Fatalf("e0: %v", err)
	}
	if r := cf.meshRecord("n1"); r.Reach != state.ReachReachable {
		t.Fatalf("main's gateway n1 %+v", r)
	}
	if ok, err := readyWithin(cf, "e2", 4); ok || err != nil {
		t.Errorf("e2 passed while edge's gateway candidate e1 is unproven: %v %v", ok, err)
	}
	if r := cf.meshRecord("e1"); r.Reach != state.ReachOffered {
		t.Errorf("e1 %+v", r)
	}
}

// TestMeshStaleAppliedIsNoProof: a persisted Applied hash is a record, not
// proof. After a takeover, e1's record says it holds its plan, but it
// never got it (its push now fails): it confirms nothing, even forging a
// handshake on the endpoint that plan would dial. A node out of the plan
// loses its record.
func TestMeshStaleAppliedIsNoProof(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	advance := fakeClockHub(cf)
	confirmAll(t, cf, "n1", "e1")
	// n1 moves to a closed address: the plan e1 would hold dials it there.
	cf.closeEndpoint("203.0.113.9:51830")
	cf.na.mu.Lock()
	cf.na.snap.Node("n1").Addresses.Public = []string{"203.0.113.9"}
	cf.na.mu.Unlock()
	cf.h.pushMesh(ctx) // n1 offered; e1's new plan (dialling it) computed and pushed
	want := cf.meshRecord("e1").Applied
	// The takeover: e1's record names that plan, but e1 is reset (it lost
	// it) and every push to it fails from now on.
	cf.h.cl.ms = meshState{allowDoc: true}
	cf.na.setRefuse("mesh:e1", errors.New("timeout"))
	cf.na.mu.Lock()
	delete(cf.na.mesh, "e1")
	cf.na.claims = map[string]map[string]string{"e1": {"n1": "203.0.113.9:51830"}}
	cf.na.mu.Unlock()
	for i := 0; i < 3; i++ {
		cf.h.pushMesh(ctx)
	}
	if r := cf.meshRecord("n1"); r.Reach != state.ReachOffered {
		t.Fatalf("n1 confirmed by e1 on a stale record: %+v", r)
	}
	if got := cf.meshRecord("e1").Applied; got != want {
		t.Errorf("e1's record moved without a push: %q", got)
	}
	advance(MeshConfirmWait + time.Second)
	cf.h.pushMesh(ctx)
	if r := cf.meshRecord("n1"); r.Reach != state.ReachUnreachable {
		t.Errorf("n1: %+v", r)
	}
	// Revoked: out of the plan, its record goes.
	cf.na.setRefuse("mesh:e1", nil)
	if _, _, err := cf.h.RemoveClusterNode(ctx, admin, "e1", "e1", nodeadm.Revoke); err != nil {
		t.Fatal(err)
	}
	if got := cf.meshRecord("e1").Applied; got != "" {
		t.Errorf("revoked e1 kept its record %q", got)
	}
}

// TestMeshForwardedEndpointJoinsNewSite (Task 30 fix round 1, the NAT
// model of §20.11): a node behind NAT, the first at its site, reports no
// public endpoint and was refused (TestMeshSiteWithoutGateway). With the
// operator's forwarded endpoint given at the add it is that site's
// gateway: offered, confirmed by a handshake from another site, and the
// other sites dial it there. A bad endpoint is refused before anything is
// recorded or any code issued.
func TestMeshForwardedEndpointJoinsNewSite(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, twoSites()...)
	cf.h.settleClusterNodes(ctx)
	for _, bad := range []string{"192.168.1.9:40000", "10.215.0.9:51830", "203.0.113.9", "203.0.113.9:0", "[2001:db8::1]:51830"} {
		_, _, err := cf.h.AddClusterNode(ctx, admin, AddClusterNodeRequest{ID: "t1", Site: "tb", Role: "agent", PublicEndpoint: bad})
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 400 || !strings.Contains(err.Error(), "public_endpoint") {
			t.Errorf("forwarded endpoint %q: %v", bad, err)
		}
		if _, ok := cf.h.serverEntry("t1"); ok {
			t.Fatalf("forwarded endpoint %q: an entry was recorded", bad)
		}
	}
	if c := cf.na.Calls(); slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "codes:") }) {
		t.Fatalf("a code was issued for a refused endpoint: %v", c)
	}
	cf = newClusterFixture(t, twoSites()...)
	cf.h.settleClusterNodes(ctx)
	enrolAt(cf, "t1", "tb", "10.215.0.9", "198.18.1.9", "", 1<<30)
	cf.stopEnrol(t, "t1")
	if _, _, err := cf.h.AddClusterNode(ctx, admin, AddClusterNodeRequest{ID: "t1", Site: "tb", Role: "agent", PublicEndpoint: "203.0.113.9:40000"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := cf.h.serverEntry("t1"); s.MeshForward != "203.0.113.9:40000" {
		t.Fatalf("the entry's forwarded endpoint %q", s.MeshForward)
	}
	// nodeadm's gateway rule needs it too (its join refuses a NATed site).
	if c := cf.na.Calls(); !slices.Contains(c, "forward:t1:203.0.113.9:40000") {
		t.Fatalf("the code request didn't name the forwarded endpoint: %v", c)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		r := cf.h.LastOp(serverOpKey("t1"))
		if r != nil && meshStep(r, StepMeshReady) == StepDone {
			break
		}
		if r != nil && !r.Running && !r.OK {
			t.Fatalf("the join failed: %+v", r)
		}
		if time.Now().After(deadline) {
			t.Fatalf("mesh_ready never passed: %+v", r)
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, id := range []string{"n1", "e1"} {
		p, _ := cf.na.meshOf(id)
		i := slices.IndexFunc(p.Peers, func(q nodeagent.MeshPeer) bool { return q.ID == "t1" })
		if i < 0 || p.Peers[i].Endpoint.V != "203.0.113.9:40000" {
			t.Errorf("%s doesn't dial t1 at its forwarded endpoint: %+v", id, p)
		}
	}
	if rec := cf.meshRecord("t1"); rec.Reach != state.ReachReachable || rec.Public != "203.0.113.9:40000" {
		t.Errorf("t1's endpoint %+v", rec)
	}
	if st := cf.h.MeshStatus(); len(st.NoGateway) != 0 {
		t.Errorf("no gateway %v", st.NoGateway)
	}
}

// TestMeshFirstNodeOfNewSiteJudges (Task 30 fix round 1, found live): the
// first node of a new site still joins, so no established node at another
// site can confirm the first site's public endpoint; that node judges it
// (its plan dials the endpoint, which waits to be dialled), so n1 is
// reachable and the join isn't refused for leaving main without a
// gateway. (Where an established judge exists a joiner never confirms:
// TestMeshJoinerCantConfirm; a closed endpoint is still found unreachable:
// TestMeshHomeMainForwardsOnlyWeb.)
func TestMeshFirstNodeOfNewSiteJudges(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"))
	advance := fakeClockHub(cf)
	cf.h.settleClusterNodes(ctx)
	enrolAt(cf, "t1", "tb", "10.215.0.9", "198.18.1.9", "", 1<<30)
	cf.stopEnrol(t, "t1")
	if _, _, err := cf.h.AddClusterNode(ctx, admin, AddClusterNodeRequest{ID: "t1", Site: "tb", Role: "agent", PublicEndpoint: "203.0.113.9:40000"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = cf.h.pushMesh(ctx)
	}
	advance(MeshConfirmWait + time.Minute)
	for i := 0; i < 3; i++ {
		_ = cf.h.pushMesh(ctx)
	}
	if r := cf.meshRecord("n1"); r.Reach != state.ReachReachable {
		t.Fatalf("n1 with only the joiner at another site: %+v", r)
	}
	if st := cf.h.MeshStatus(); slices.Contains(st.NoGateway, "main") {
		t.Fatalf("main without a gateway: %v", st.NoGateway)
	}
	if r := cf.h.LastOp(serverOpKey("t1")); r != nil && !r.Running && !r.OK {
		t.Fatalf("the join was refused: %+v", r)
	}
}

// TestMeshUnreachableRetryDueAtAdd (Task 30 fix round 1, found live): a
// single-site cluster's gateway found unreachable (an earlier failed join
// at a new site) is offered again once its retry is due, also for the
// add's bootstrap plan: updateReach runs only in a multi-site mesh, so
// without it a second site could never be added again. Before the retry
// is due the add is refused.
func TestMeshUnreachableRetryDueAtAdd(t *testing.T) {
	ctx := context.Background()
	cf := newClusterFixture(t, siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"))
	advance := fakeClockHub(cf)
	cf.h.settleClusterNodes(ctx)
	cf.h.mu.Lock()
	r := cf.h.st.Mesh["n1"]
	r.Public, r.Reach, r.CheckedAt = "203.0.113.1:51830", state.ReachUnreachable, cf.h.now().UTC()
	cf.h.st.Mesh["n1"] = r
	cf.h.mu.Unlock()
	if _, _, err := cf.h.AddClusterNode(ctx, admin, AddClusterNodeRequest{ID: "t1", Site: "tb", Role: "agent", PublicEndpoint: "203.0.113.9:40000"}); err == nil ||
		!strings.Contains(err.Error(), "site main needs one node reachable") {
		t.Fatalf("before the retry: %v", err)
	}
	advance(MeshRetryUnreachable + time.Second)
	cf.stopEnrol(t, "t1")
	if _, _, err := cf.h.AddClusterNode(ctx, admin, AddClusterNodeRequest{ID: "t1", Site: "tb", Role: "agent", PublicEndpoint: "203.0.113.9:40000"}); err != nil {
		t.Fatalf("after the retry is due: %v", err)
	}
}
