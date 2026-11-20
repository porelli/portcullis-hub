package hub

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// TestTwoSitesWarnTiebreaker: with main holding the 3 servers, the first
// node of a second site is an agent and the add answers the tie-breaker
// warning verbatim.
func TestTwoSitesWarnTiebreaker(t *testing.T) {
	cf := newClusterFixture(t,
		siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"),
		siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""),
		siteNode("n3", "server", "main", "10.215.0.3", "192.0.2.3", ""))
	cf.h.settleClusterNodes(context.Background())
	cf.stopEnrol(t, "e1")
	out, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "e1", Site: "edge", Class: "cloud"})
	if err != nil {
		t.Fatal(err)
	}
	want := "Only main can survive on its own: add a tie-breaker at a third location (a small cloud VM or a Pi elsewhere)."
	if out.Role != "agent" || !slices.Equal(out.Warnings, []string{want}) || out.Storage {
		t.Errorf("%+v", out)
	}
}

// TestThreeSitesNoMajority: main 2 servers, edge 1, tb an agent only: a
// new node at tb is a server (no site keeps a majority); at main an agent
// with the warning naming tb.
func TestThreeSitesNoMajority(t *testing.T) {
	nodes := []nodeadm.Node{
		siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"),
		siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""),
		siteNode("e1", "server", "edge", "10.215.0.5", "198.18.0.5", "203.0.113.5"),
		siteNode("t1", "agent", "tb", "10.215.0.7", "198.18.1.7", "203.0.113.7"),
	}
	cf := newClusterFixture(t, nodes...)
	cf.h.settleClusterNodes(context.Background())
	cf.stopEnrol(t, "t2")
	out, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "t2", Site: "tb"})
	if err != nil || out.Role != "server" || out.Notice != ServerJoinNotice {
		t.Fatalf("at tb: %+v %v", out, err)
	}
	if slices.Contains(out.Warnings, servers.WarnTieBreaker) {
		t.Errorf("3 sites warned about 2: %v", out.Warnings)
	}

	cf = newClusterFixture(t, nodes...)
	cf.h.settleClusterNodes(context.Background())
	cf.stopEnrol(t, "n4")
	out, _, err = cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n4"})
	if err != nil || out.Role != "agent" || !slices.Equal(out.Warnings, []string{"main holds a majority of the servers: add the next server at tb."}) {
		t.Fatalf("at main: %+v %v", out, err)
	}
}

// joinFor makes the fake cluster report id enrolling (its pcmesh key) at
// the 3rd read; the Node never registers.
func joinFor(cf *clusterFixture, id, role, mesh string) {
	cf.na.onCluster = func(n int, s *nodeadm.Snapshot) {
		if n == 3 {
			s.Enrolling = []nodeadm.Enrolling{{ID: id, Role: role, Class: "home", Site: "main", MeshIP: mesh, Mesh: nodeadm.MeshReport{Pub: fakeMeshKey(id)}}}
		}
	}
}

func opStepState(r OpRecord, key string) string {
	for _, s := range r.Steps {
		if s.Key == key {
			return s.State
		}
	}
	return ""
}

// TestServerTooFarRefusedBeforeJoin: a server 120 ms from one healthy
// server is refused after mesh_ready, at k3s_joined, with the §20.11
// text: never past the RTT gate (no Node, no labels), its enrolment
// revoked (the k3s material rotated), its peer out of every plan. A
// server that isn't Ready is skipped; an agent may be 250 ms away, and
// 80 % of the limit warns.
func TestServerTooFarRefusedBeforeJoin(t *testing.T) {
	three := func() []nodeadm.Node {
		return []nodeadm.Node{serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true)}
	}
	cf := newClusterFixture(t, three()...)
	cf.h.settleClusterNodes(context.Background())
	cf.na.rtt = map[string]map[string]int{"n4": {"n1": 2, "n2": 3, "n3": 120}}
	joinFor(cf, "n4", "server", "10.215.0.4")
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n4", Role: "server"}); err != nil {
		t.Fatal(err)
	}
	r := waitServerOp(t, cf.h, serverOpKey("n4"))
	want := "too far for one cluster: 120 ms (servers need 100 ms or less)"
	if r.OK || r.Error != want {
		t.Fatalf("op %+v, want %q", r, want)
	}
	if opStepState(r, StepMeshReady) != StepDone || opStepState(r, StepK3sJoined) != "failed" || opStepState(r, StepNodeReady) == StepDone {
		t.Errorf("steps %+v", r.Steps)
	}
	c := cf.na.Calls()
	if !slices.Contains(c, "remove:n4:revoke") || slices.Contains(c, "labels:n4") {
		t.Errorf("calls %v: want the enrolment revoked, nothing past the gate", c)
	}
	for _, id := range []string{"n1", "n2", "n3"} {
		p, _ := cf.na.meshOf(id)
		for _, q := range p.Peers {
			if q.ID == "n4" {
				t.Errorf("%s still peers with n4: %+v", id, p)
			}
		}
	}
	if s, _ := cf.serverEntry("n4"); s.State != ServerRevoked {
		t.Errorf("entry %+v", s)
	}
	if a := cf.actions(); !slices.ContainsFunc(a, func(x string) bool { return strings.HasPrefix(x, "server.enrol_refused:") }) {
		t.Errorf("audit %v", a)
	}

	// An agent: 240 ms passes with the 80 % warning; a NotReady server
	// (n3, 900 ms) is skipped.
	nodes := three()
	nodes[2].Ready = false
	cf = newClusterFixture(t, nodes...)
	cf.h.settleClusterNodes(context.Background())
	cf.na.rtt = map[string]map[string]int{"a1": {"n1": 2, "n2": 240, "n3": 900}}
	cf.na.onCluster = func(n int, s *nodeadm.Snapshot) {
		switch n {
		case 3:
			s.Enrolling = []nodeadm.Enrolling{{ID: "a1", Role: "agent", Class: "home", Site: "main", MeshIP: "10.215.0.4", Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("a1")}}}
		case 12:
			s.Enrolling = nil
			s.Nodes = append(s.Nodes, nodeadm.Node{Name: "a1", Role: "agent", Ready: true, Labels: map[string]string{nodeadm.LabelClass: "home", nodeadm.LabelSite: "main", nodeadm.LabelStorage: "true"},
				Addresses: nodeadm.NodeAddresses{Mesh: "10.215.0.4"}})
		}
	}
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "a1", Role: "agent"}); err != nil {
		t.Fatal(err)
	}
	r = waitServerOp(t, cf.h, serverOpKey("a1"))
	if !r.OK || !slices.Contains(r.Warnings, "mesh round trip to n2 is 240 ms: near the 250 ms limit") {
		t.Errorf("agent op %+v", r)
	}
}

// untilK3sJoined waits until node id's enrolment is at k3s_joined, then
// checks it is still running a moment later (the gate waits).
func untilK3sJoined(t *testing.T, cf *clusterFixture, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if r := cf.h.LastOp(serverOpKey(id)); r != nil && opStepState(*r, StepK3sJoined) == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never reached k3s_joined: %+v", cf.h.LastOp(serverOpKey(id)))
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	if r := cf.h.LastOp(serverOpKey(id)); r == nil || !r.Running {
		t.Fatalf("refused before the wait: %+v", r)
	}
}

// assertRevokedOut: node id's enrolment was revoked (never only voided),
// nothing past the gate, its peer in no plan of others.
func assertRevokedOut(t *testing.T, cf *clusterFixture, id string, others ...string) {
	t.Helper()
	c := cf.na.Calls()
	if !slices.Contains(c, "remove:"+id+":revoke") || slices.Contains(c, "labels:"+id) {
		t.Errorf("calls %v: want %s revoked, nothing past the gate", c, id)
	}
	for _, o := range others {
		p, _ := cf.na.meshOf(o)
		for _, q := range p.Peers {
			if q.ID == id {
				t.Errorf("%s still peers with %s: %+v", o, id, p)
			}
		}
	}
}

// TestJoinRTTMissingServer: a healthy server the node never answers for
// holds the join until joinRTTWait, then refuses with the §20.11 text.
func TestJoinRTTMissingServer(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true))
	cf.h.settleClusterNodes(context.Background())
	step := fakeClockHub(cf)
	cf.na.rtt = map[string]map[string]int{"n3": {"n1": 2}}
	joinFor(cf, "n3", "server", "10.215.0.3")
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n3"}); err != nil {
		t.Fatal(err)
	}
	untilK3sJoined(t, cf, "n3")
	step(joinRTTWait + time.Second)
	r := waitServerOp(t, cf.h, serverOpKey("n3"))
	if r.OK || r.Error != "no mesh answer from n2: the node can't join" {
		t.Errorf("op %+v", r)
	}
	assertRevokedOut(t, cf, "n3", "n1", "n2")
}

// TestJoinRTTNodeagentSilent (review I2): a joining node whose nodeagent
// doesn't answer GET /v1/mesh/rtt waits, then is refused (fail closed),
// revoked, its peer out of every plan.
func TestJoinRTTNodeagentSilent(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true))
	cf.h.settleClusterNodes(context.Background())
	step := fakeClockHub(cf)
	cf.na.refuse["rtt:n4"] = errors.New("connection refused")
	joinFor(cf, "n4", "agent", "10.215.0.4")
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n4"}); err != nil {
		t.Fatal(err)
	}
	untilK3sJoined(t, cf, "n4")
	step(joinRTTWait + time.Second)
	r := waitServerOp(t, cf.h, serverOpKey("n4"))
	if r.OK || r.Error != "no mesh round trips from n4: its nodeagent doesn't answer GET /v1/mesh/rtt (connection refused): the node can't join" {
		t.Errorf("op %+v", r)
	}
	assertRevokedOut(t, cf, "n4", "n1", "n2", "n3")
}

// TestJoinRTTNoHealthyServer (review I1): no healthy server to measure
// against is never a pass: the gate waits, and checks the servers once
// they are back (a far node is then refused); none for joinRTTWait is
// refused with ErrNoHealthyServer.
func TestJoinRTTNoHealthyServer(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", false))
	cf.h.settleClusterNodes(context.Background())
	step := fakeClockHub(cf)
	cf.na.rtt = map[string]map[string]int{"n2": {"n1": 2}}
	joinFor(cf, "n2", "server", "10.215.0.2")
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
		t.Fatal(err)
	}
	untilK3sJoined(t, cf, "n2")
	step(joinRTTWait + time.Second)
	r := waitServerOp(t, cf.h, serverOpKey("n2"))
	if r.OK || r.Error != ErrNoHealthyServer || ErrNoHealthyServer != "no healthy server to measure the round trip against: the node can't join" {
		t.Errorf("op %+v", r)
	}
	assertRevokedOut(t, cf, "n2")

	// The server comes back while the gate waits: it is measured then.
	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", false))
	cf.h.settleClusterNodes(context.Background())
	cf.na.rtt = map[string]map[string]int{"n2": {"n1": 120}}
	joinFor(cf, "n2", "server", "10.215.0.2")
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
		t.Fatal(err)
	}
	untilK3sJoined(t, cf, "n2")
	cf.na.mu.Lock()
	cf.na.snap.Node("n1").Ready = true
	cf.na.mu.Unlock()
	r = waitServerOp(t, cf.h, serverOpKey("n2"))
	if r.OK || r.Error != "too far for one cluster: 120 ms (servers need 100 ms or less)" {
		t.Errorf("back: op %+v", r)
	}
}

// TestJoinRTTAbsurdIsTooFar (review M1): a figure past rttMaxMs is "too
// far" at once, never "no answer" after the wait.
func TestJoinRTTAbsurdIsTooFar(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	cf.h.settleClusterNodes(context.Background())
	cf.na.rtt = map[string]map[string]int{"n2": {"n1": 700_000}}
	joinFor(cf, "n2", "server", "10.215.0.2")
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
		t.Fatal(err)
	}
	r := waitServerOp(t, cf.h, serverOpKey("n2"))
	if r.OK || r.Error != "too far for one cluster: 700000 ms (servers need 100 ms or less)" {
		t.Errorf("op %+v", r)
	}
}

// TestRTTCollectionBesideTheTick (review M4): a hung nodeagent's RTT
// never holds the cluster tick, and one collection runs at a time.
func TestRTTCollectionBesideTheTick(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true))
	block := make(chan struct{})
	cf.na.mu.Lock()
	cf.na.rttBlock = block
	cf.na.mu.Unlock()
	start := time.Now()
	cf.h.settleClusterNodes(context.Background())
	cf.h.settleClusterNodes(context.Background())
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the tick waited %s on the RTT", d)
	}
	if !cf.h.cl.rtt.busy.Load() {
		t.Error("no collection running")
	}
	close(block)
	deadline := time.Now().Add(5 * time.Second)
	for cf.h.cl.rtt.busy.Load() || len(cf.h.MeshRTT()) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("collection never finished: %v", cf.h.MeshRTT())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestDoctorRTTHealthyOnly (review M3): mesh_rtt_high judges the round
// trips to healthy servers only.
func TestDoctorRTTHealthyOnly(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", false))
	cf.na.rtt = map[string]map[string]int{"n1": {"n2": 2, "n3": 95}, "n2": {"n1": 90, "n3": 99}}
	cf.h.settleClusterNodes(context.Background())
	snap, _ := cf.na.Cluster(context.Background())
	cf.h.collectRTT(context.Background(), snap, cf.h.now())
	in := cf.h.doctorMeshIn()
	if in == nil || len(in.RTT) != 2 || in.RTT[0].To != "n2" || in.RTT[1].To != "n1" {
		t.Errorf("doctor input %+v", in)
	}
}

// TestStorageOnlyAtPrimary: storage at another site is 400 with the
// §20.11 text and nothing is issued; at edge storage defaults off.
func TestStorageOnlyAtPrimary(t *testing.T) {
	cf := newClusterFixture(t, siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"))
	cf.h.settleClusterNodes(context.Background())
	yes := true
	_, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "e1", Site: "edge", Storage: &yes})
	if errStatus(err) != 400 || err.Error() != "storage nodes must be at the primary site (main) in this version" {
		t.Fatalf("%v", err)
	}
	for _, c := range cf.na.Calls() {
		if strings.HasPrefix(c, "codes:") {
			t.Errorf("a code was issued: %v", cf.na.Calls())
		}
	}
	if _, ok := cf.serverEntry("e1"); ok {
		t.Error("an entry was kept")
	}
	cf.stopEnrol(t, "e1")
	out, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "e1", Site: "edge", Class: "cloud"})
	if err != nil || out.Storage {
		t.Errorf("default at edge: %+v %v", out, err)
	}
}

// TestSitesView: the snapshot, the mesh and the round trips give one view
// per site, main first and the only primary, with its gateway (null
// without a reachable node) and its worst round trip to a healthy server
// (null when none is measured); the gauge and the doctor read the same
// figures.
func TestSitesView(t *testing.T) {
	ing := func(n nodeadm.Node) nodeadm.Node { n.Labels[nodeadm.LabelIngress] = "true"; return n }
	cf := newClusterFixture(t,
		ing(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1")),
		siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", ""),
		ing(siteNode("e1", "server", "edge", "10.215.0.5", "198.18.0.5", "203.0.113.5")),
		siteNode("e2", "agent", "edge", "10.215.0.6", "198.18.0.6", ""),
		siteNode("t1", "agent", "tb", "10.215.0.7", "198.18.1.7", ""))
	cf.na.rtt = map[string]map[string]int{
		"n1": {"n2": 2, "e1": 40},
		"n2": {"n1": 3, "e1": 41, "bogus": 1, "e2": -4},
		"e1": {"n1": 40, "n2": 85},
		"e2": {"n1": 60, "n2": 61, "e1": 1},
		"t1": {},
	}
	// x1: no mesh address, so no record of its site: its label is never
	// believed (review M2).
	x1 := siteNode("x1", "agent", "evil", "", "198.18.2.1", "")
	cf.na.snap.Nodes = append(cf.na.snap.Nodes, x1)
	cf.na.rtt["x1"] = map[string]int{}
	cf.h.settleClusterNodes(context.Background())
	snap, _ := cf.na.Cluster(context.Background())
	cf.h.collectRTT(context.Background(), snap, cf.h.now()) // the tick's runs beside it
	sites, err := cf.h.Sites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(sites)
	want := `[{"name":"main","primary":true,"nodes":["n1","n2"],"servers":["n1","n2"],"gateway":"n1","ingress":["n1"],"rtt_ms":41},` +
		`{"name":"edge","primary":false,"nodes":["e1","e2"],"servers":["e1"],"gateway":"e1","ingress":["e1"],"rtt_ms":85},` +
		`{"name":"tb","primary":false,"nodes":["t1"],"servers":[],"gateway":null,"ingress":[],"rtt_ms":null}]`
	if string(b) != want {
		t.Errorf("sites\n%s\nwant\n%s", b, want)
	}

	// The gauge: every figure of a known node, none of a bogus id.
	reg := prometheus.NewRegistry()
	reg.MustRegister(cf.h.UsageCollector())
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "portcullis_mesh_rtt_ms" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var from, to string
			for _, l := range m.GetLabel() {
				if l.GetName() == "from" {
					from = l.GetValue()
				} else {
					to = l.GetValue()
				}
			}
			got[from+">"+to] = m.GetGauge().GetValue()
		}
	}
	if len(got) != 9 || got["n2>e2"] != 0 || got["n1>e1"] != 40 || got["e2>n2"] != 61 || got["n2>bogus"] != 0 {
		t.Errorf("gauge %v", got)
	}

	// The doctor: e1 (a server) 85 ms from n2 is high; e2 (an agent) 61 ms
	// isn't; 3 sites: no tie-breaker finding.
	in := cf.h.doctorMeshIn()
	if in == nil || !slices.Equal(in.Sites, []string{"edge", "main", "tb"}) || in.Stale["x1"] == "" {
		t.Fatalf("doctor input %+v", in)
	}
	var kinds []string
	for _, x := range doctor.Run(&doctor.Inputs{Mesh: in}, nil).Findings {
		if x.Kind == doctor.KindMeshRTTHigh || x.Kind == doctor.KindHATwoSitesNoTiebreaker {
			kinds = append(kinds, x.Kind+" "+x.Title)
		}
	}
	if !slices.Equal(kinds, []string{"mesh_rtt_high The mesh round trip from e1 to server n2 is 85 ms: near the 100 ms limit."}) {
		t.Errorf("findings %v", kinds)
	}
	// Figures not read again for 5 min go (never a stale figure).
	step := fakeClockHub(cf)
	step(rttStale + time.Second)
	if m := cf.h.MeshRTT(); len(m) != 0 {
		t.Errorf("stale figures kept: %v", m)
	}
}

// TestCleanRTT: a nodeagent's answer keeps only known peers (never its
// own id, an unknown or a malformed one), and sane figures.
func TestCleanRTT(t *testing.T) {
	got := cleanRTT("n1", map[string]int{"n1": 1, "n2": 5, "n9": 3, "x\"}": 2, "n3": -1, "n4": rttMaxMs + 1, "n5": 0},
		map[string]bool{"n1": true, "n2": true, "n3": true, "n4": true, "n5": true}, false)
	if len(got) != 2 || got["n2"] != 5 || got["n5"] != 0 {
		t.Errorf("%v", got)
	}
}

// TestSitesFromHubRecords (review M2): a node the Hub added is placed by
// its entry (site, ingress), never by its Node's labels; n1 (no entry, not
// pinned yet) is left out.
func TestSitesFromHubRecords(t *testing.T) {
	n2 := siteNode("n2", "server", "edge", "10.215.0.2", "192.0.2.2", "")
	n2.Labels[nodeadm.LabelIngress] = "true"
	n3 := siteNode("n3", "agent", "main", "10.215.0.3", "192.0.2.3", "")
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), n2, n3)
	cf.h.mu.Lock()
	cf.h.st.Servers = map[string]state.Server{
		"n2": {Kind: state.KindClusterNode, State: ServerReady, Role: "server", Site: "main", MeshIP: "10.215.0.2", Labels: &state.NodeLabels{}},
		"n3": {Kind: state.KindClusterNode, State: ServerReady, Role: "agent", Site: "main", MeshIP: "10.215.0.3", Labels: &state.NodeLabels{Ingress: true}},
	}
	cf.h.mu.Unlock()
	snap, _ := cf.na.Cluster(context.Background())
	v := cf.h.sitesOf(snap)
	if len(v) != 1 || v[0].Name != "main" || !slices.Equal(v[0].Nodes, []string{"n2", "n3"}) || !slices.Equal(v[0].Ingress, []string{"n3"}) {
		t.Errorf("%+v", v)
	}
}
