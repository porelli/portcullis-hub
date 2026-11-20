package hub

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// fakeNodeadm is nodeadm's internal API: a snapshot the test moves on,
// the calls made, and refusals per call.
type fakeNodeadm struct {
	mu     sync.Mutex
	snap   nodeadm.Snapshot
	calls  []string
	codes  []string
	refuse map[string]error // "drain", "remove:cooperative", …
	// ca is the pki_node CA's sha256 the codes name.
	ca string
	// onCluster runs on each snapshot read (the test's clock of the node).
	onCluster func(n int, s *nodeadm.Snapshot)
	reads     int
	// mesh: each nodeagent's last PUT /v1/mesh/peers; meshOrder the PUTs.
	mesh      map[string]nodeagent.MeshPlan
	meshOrder []string
	// codeMesh: each code's bootstrap plan.
	codeMesh []nodeadm.MeshPlan
	// closed: endpoints ("<ip:port>") nothing answers on (no handshake);
	// liar: nodes whose health claims a handshake on every endpoint.
	closed map[string]bool
	liar   map[string]bool
	// outbound: a node's source address as its peers see it when it dials;
	// claims: forged handshakes a node reports (node → peer → endpoint).
	outbound map[string]string
	claims   map[string]map[string]string
}

const testSecret = "q5idMrnFv0N4pQ2KjXHAzmYEjbEkpmCaKEHY_moMciM"

func (f *fakeNodeadm) record(c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	return f.refuse[c]
}

func (f *fakeNodeadm) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeNodeadm) IssueCode(_ context.Context, r nodeadm.CodeRequest) (nodeadm.CodeAnswer, error) {
	if err := f.record("codes:" + r.ServerID + ":" + r.Role + ":" + r.MeshIP); err != nil {
		return nodeadm.CodeAnswer{}, err
	}
	hex := strings.Repeat("a", 64)
	f.mu.Lock()
	ca := f.ca
	f.mu.Unlock()
	c := servers.JoinCodeV2{V: 2, Kind: "cluster", Endpoint: "https://example.org/node", Servers: []string{"10.215.0.1"}, ServerID: r.ServerID,
		Role: r.Role, Class: r.Class, Site: r.Site, CASHA256: ca, ScriptSHA256: hex, AgentSHA256: servers.AgentSHA256{AMD64: hex, ARM64: hex},
		MeshIP: r.MeshIP, Secret: testSecret}.EncodeV2()
	f.mu.Lock()
	f.codes = append(f.codes, c)
	f.codeMesh = append(f.codeMesh, r.Mesh)
	f.mu.Unlock()
	return nodeadm.CodeAnswer{Code: servers.JoinCodeSecret(c), ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)}, nil
}

func (f *fakeNodeadm) Cluster(context.Context) (nodeadm.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.onCluster != nil {
		f.onCluster(f.reads, &f.snap)
	}
	s := f.snap
	s.Nodes = slices.Clone(s.Nodes)
	s.Enrolling = slices.Clone(s.Enrolling)
	return s, nil
}

func (f *fakeNodeadm) SetLabels(_ context.Context, id string, l nodeadm.Labels) error {
	if err := f.record("labels:" + id); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.snap.Node(id); n != nil {
		n.Labels = map[string]string{nodeadm.LabelClass: l.Class, nodeadm.LabelSite: l.Site}
		if l.Storage {
			n.Labels[nodeadm.LabelStorage] = "true"
		}
		if l.Ingress {
			n.Labels[nodeadm.LabelIngress] = "true"
		}
	}
	return nil
}

func (f *fakeNodeadm) Cordon(_ context.Context, id string) error   { return f.record("cordon:" + id) }
func (f *fakeNodeadm) Uncordon(_ context.Context, id string) error { return f.record("uncordon:" + id) }
func (f *fakeNodeadm) Drain(_ context.Context, id string) error    { return f.record("drain:" + id) }
func (f *fakeNodeadm) Remove(_ context.Context, id string, m nodeadm.RemoveMode) error {
	return f.record("remove:" + id + ":" + string(m))
}

type fakeNodeagent struct {
	f  *fakeNodeadm
	id string
}

func (a fakeNodeagent) Uninstall(context.Context) error { return a.f.record("uninstall:" + a.id) }

// fakeMeshKey is node id's pcmesh key in the fakes.
func fakeMeshKey(id string) string {
	b := make([]byte, 32)
	copy(b, id)
	return base64.StdEncoding.EncodeToString(b)
}

func (a fakeNodeagent) Health(context.Context) (nodeagent.Health, error) {
	a.f.mu.Lock()
	err := a.f.refuse["health:"+a.id]
	a.f.mu.Unlock()
	if err != nil {
		return nodeagent.Health{}, err
	}
	// A handshake with peer q when this node dialled it (its plan has an
	// endpoint for q nothing closed), or when q dialled this node (q's
	// plan has an endpoint for it): then the device holds q's source,
	// outbound[q] (a port-preserving NAT's mapping) when set. A liar claims
	// one on every endpoint its plan names.
	now := time.Now().UTC()
	fresh := jsonstrict.Some(now.Add(-10 * time.Second).Format(time.RFC3339))
	peers := map[string]nodeagent.PeerStatus{}
	a.f.mu.Lock()
	for _, q := range a.f.mesh[a.id].Peers {
		ps := nodeagent.PeerStatus{}
		switch {
		case q.Endpoint.Valid && (!a.f.closed[q.Endpoint.V] || a.f.liar[a.id]):
			ps.LatestHandshake, ps.Endpoint = fresh, q.Endpoint
		default:
			for _, back := range a.f.mesh[q.ID].Peers {
				if back.ID == a.id && back.Endpoint.Valid && !a.f.closed[back.Endpoint.V] {
					ps.LatestHandshake = fresh
					if src := a.f.outbound[q.ID]; src != "" {
						ps.Endpoint = jsonstrict.Some(src)
					}
				}
			}
		}
		if ep := a.f.claims[a.id][q.ID]; ep != "" { // a forged report
			ps.LatestHandshake, ps.Endpoint = fresh, jsonstrict.Some(ep)
		}
		peers[q.ID] = ps
	}
	a.f.mu.Unlock()
	return nodeagent.Health{ID: a.id, MeshPub: fakeMeshKey(a.id), K3s: "running", Time: now.Format(time.RFC3339), Peers: peers}, nil
}

// PutMeshPeers records the plan (not in calls: the removal and enrolment
// tests assert those exactly).
func (a fakeNodeagent) PutMeshPeers(_ context.Context, p nodeagent.MeshPlan) error {
	a.f.mu.Lock()
	defer a.f.mu.Unlock()
	if err := a.f.refuse["mesh:"+a.id]; err != nil {
		return err
	}
	if a.f.mesh == nil {
		a.f.mesh = map[string]nodeagent.MeshPlan{}
	}
	a.f.mesh[a.id] = p
	a.f.meshOrder = append(a.f.meshOrder, a.id)
	return nil
}

func serverNode(name, mesh string, ready bool) nodeadm.Node {
	return nodeadm.Node{Name: name, Role: "server", Ready: ready, Labels: map[string]string{nodeadm.LabelClass: "home", nodeadm.LabelSite: "main"},
		Addresses: nodeadm.NodeAddresses{Mesh: mesh}}
}

type clusterFixture struct {
	*fixture
	na    *fakeNodeadm
	audit *fakeAudit
}

func newClusterFixture(t *testing.T, nodes ...nodeadm.Node) *clusterFixture {
	t.Helper()
	f := newFixture(t)
	f.h.cfg.Runtime = runtime.KindKubernetes
	f.h.cfg.Domain = "example.org"
	nca := newTestNodeCA(t)
	f.h.SetNodeSigner(nca)
	na := &fakeNodeadm{snap: nodeadm.Snapshot{V: 1, Nodes: nodes}, refuse: map[string]error{}, ca: caSHA256(nca.cert)}
	f.h.SetNodeadm(na)
	f.h.cl.poll = 2 * time.Millisecond
	f.h.cl.ms.allowDoc = true // the tests' public addresses are TEST-NET
	f.h.cl.agentFor = func(id, _ string) NodeagentAPI { return fakeNodeagent{na, id} }
	a := &fakeAudit{}
	f.h.SetAudit(a)
	return &clusterFixture{fixture: f, na: na, audit: a}
}

func (cf *clusterFixture) actions() []string {
	cf.audit.mu.Lock()
	defer cf.audit.mu.Unlock()
	var out []string
	for _, e := range cf.audit.entries {
		out = append(out, e.Action+":"+e.Result)
	}
	return out
}

func (cf *clusterFixture) stopEnrol(t *testing.T, id string) {
	t.Helper()
	t.Cleanup(func() { cf.h.StopServerEnrol(id, admin, ""); waitServerOp(t, cf.h, serverOpKey(id)) })
}

// TestAddClusterNodeSuggestsRole: with 1 server the new node is a server
// (with the cluster-admin sentence); with 3 healthy servers an agent; the
// admin's override is kept, and a 4th server warns about the even count.
func TestAddClusterNodeSuggestsRole(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	cf.stopEnrol(t, "n2")
	out, code, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"})
	if err != nil || out.Role != "server" || out.Notice != ServerJoinNotice || !strings.HasPrefix(code.Reveal(), "pcj2.") || len(out.Warnings) != 0 {
		t.Fatalf("1 server: %+v %v", out, err)
	}
	if out.Site != "main" || out.Class != "home" || !out.Storage || out.Ingress || out.Command != "curl -fsSL https://example.org/node/join.sh | sudo sh" {
		t.Errorf("defaults: %+v", out)
	}
	if c := cf.na.Calls(); !slices.Contains(c, "codes:n2:server:10.215.0.2") {
		t.Errorf("nodeadm calls %v: want a code for n2 at 10.215.0.2", c)
	}

	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true))
	cf.stopEnrol(t, "n4")
	cf.stopEnrol(t, "n5")
	out, _, err = cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n4"})
	if err != nil || out.Role != "agent" || out.Notice != "" {
		t.Fatalf("3 servers: %+v %v", out, err)
	}
	out, _, err = cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n5", Role: "server", Class: "cloud", Site: "main"})
	if err != nil || out.Role != "server" || !slices.Equal(out.Warnings, []string{"an even number of servers doesn't add failure tolerance"}) || out.Notice != ServerJoinNotice || !out.Ingress {
		t.Fatalf("override: %+v %v", out, err)
	}
	if s, _ := cf.serverEntry("n5"); s.Kind != "cluster-node" || s.Role != "server" || s.Class != "cloud" || s.MeshIP != "10.215.0.5" {
		t.Errorf("state %+v", s)
	}
}

func (cf *clusterFixture) serverEntry(id string) (s0 serverEntryT, ok bool) {
	s, ok := cf.h.serverEntry(id)
	return serverEntryT{Kind: s.Kind, Role: s.Role, Class: s.Class, MeshIP: s.MeshIP, State: s.State}, ok
}

type serverEntryT struct{ Kind, Role, Class, MeshIP, State string }

// TestServerJoinDialogText: the answer for a server carries the
// cluster-admin sentence verbatim.
func TestServerJoinDialogText(t *testing.T) {
	if ServerJoinNotice != "Joining as a server gives this machine full control of the cluster (cluster-admin)." {
		t.Fatal(ServerJoinNotice)
	}
	cf := newClusterFixture(t)
	cf.na.snap.Nodes = []nodeadm.Node{serverNode("n1", "10.215.0.1", true)}
	cf.stopEnrol(t, "n2")
	out, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2", Role: "server"})
	if err != nil || out.Notice != ServerJoinNotice {
		t.Fatalf("%+v %v", out, err)
	}
}

// TestEnrolStepsFromSnapshot: the snapshots in order take the op through
// enrolled → mesh_ready → k3s_joined → node_ready → storage_ready → done;
// no code in the state, the op record or the audit. A Stop before
// k3s_joined voids the code (DELETE …?mode=cooperative) and leaves
// nothing; a Stop after it removes the node.
func TestEnrolStepsFromSnapshot(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	cf.na.onCluster = func(n int, s *nodeadm.Snapshot) {
		switch {
		case n == 3:
			s.Enrolling = []nodeadm.Enrolling{{ID: "n2", Role: "server", Class: "home", Site: "main", MeshIP: "10.215.0.2", Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("n2")}}}
		case n == 6:
			s.Enrolling = nil
			nd := serverNode("n2", "10.215.0.2", false)
			nd.Labels = map[string]string{}
			s.Nodes = append(s.Nodes, nd)
		case n == 9:
			s.Node("n2").Ready = true
		}
	}
	_, code, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2", Name: "Node 2"})
	if err != nil {
		t.Fatal(err)
	}
	r := waitServerOp(t, cf.h, serverOpKey("n2"))
	if !r.OK || r.Op != OpServerEnrol {
		t.Fatalf("op %+v", r)
	}
	var keys []string
	for _, s := range r.Steps {
		keys = append(keys, s.Key)
		if s.State != StepDone {
			t.Errorf("step %s is %s", s.Key, s.State)
		}
	}
	if !slices.Equal(keys, []string{"enrolled", "mesh_ready", "k3s_joined", "node_ready", "storage_ready", "done"}) {
		t.Errorf("steps %v", keys)
	}
	if s, _ := cf.serverEntry("n2"); s.State != ServerReady {
		t.Errorf("state %+v", s)
	}
	if c := cf.na.Calls(); !slices.Contains(c, "labels:n2") {
		t.Errorf("the missing labels weren't set: %v", c)
	}
	if a := cf.actions(); !slices.Equal(a, []string{"server.add:ok", "server.enrolled:ok"}) {
		t.Errorf("audit %v", a)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(testSecret)
	assertNoClusterSecret(t, cf, []string{code.Reveal(), testSecret, string(raw)})

	// A Stop before k3s_joined: the code voided, nothing left.
	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
		t.Fatal(err)
	}
	if err := cf.h.StopServerEnrol("n2", admin, ""); err != nil {
		t.Fatal(err)
	}
	r = waitServerOp(t, cf.h, serverOpKey("n2"))
	if r.OK || r.StoppedBy != admin.User {
		t.Errorf("op %+v, want stopped", r)
	}
	if c := cf.na.Calls(); !slices.Contains(c, "remove:n2:cooperative") || slices.Contains(c, "drain:n2") || slices.Contains(c, "remove:n2:revoke") {
		t.Errorf("calls %v: want the code voided, no drain", c)
	}
	if s, _ := cf.serverEntry("n2"); s.State != ServerRevoked {
		t.Errorf("a voided entry is watched (revoked): %+v", s)
	}

	// A Stop once k3s joined: revoked (never a cordon or drain).
	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	joined := make(chan struct{})
	var once sync.Once
	cf.na.onCluster = func(n int, s *nodeadm.Snapshot) {
		if n == 2 {
			nd := serverNode("n2", "10.215.0.2", false)
			s.Nodes = append(s.Nodes, nd)
		}
		if n >= 4 {
			once.Do(func() { close(joined) })
		}
	}
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
		t.Fatal(err)
	}
	<-joined
	if err := cf.h.StopServerEnrol("n2", admin, ""); err != nil {
		t.Fatal(err)
	}
	waitServerOp(t, cf.h, serverOpKey("n2"))
	c := cf.na.Calls()
	if !slices.Contains(c, "remove:n2:revoke") || !slices.Contains(c, "uninstall:n2") || slices.Contains(c, "cordon:n2") || slices.Contains(c, "uncordon:n2") {
		t.Errorf("calls %v: want nodeadm's revoke and the uninstall", c)
	}
	if s, _ := cf.serverEntry("n2"); s.State != ServerRevoked {
		t.Errorf("entry %+v", s)
	}
}

func assertNoClusterSecret(t *testing.T, cf *clusterFixture, secrets []string) {
	t.Helper()
	var hay []string
	filepath.Walk(cf.h.cfg.DataDir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			hay = append(hay, p+": "+string(b))
		}
		return nil
	})
	cf.audit.mu.Lock()
	for _, e := range cf.audit.entries {
		hay = append(hay, e.Detail+" "+e.Error)
	}
	cf.audit.mu.Unlock()
	for _, h := range hay {
		for _, s := range secrets {
			if s != "" && strings.Contains(h, s) {
				t.Errorf("a secret is stored: %.120s", h)
			}
		}
	}
}

// TestRemoveRefusedBelowQuorum: removing a server while 3 healthy servers
// exist is 409 with nodeadm's text and changes nothing; with more, a
// nodeadm quorum_minimum refusal fails the op with the same text and
// uncordons the node.
func TestRemoveRefusedBelowQuorum(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true))
	_, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n3", nodeadm.Cooperative)
	if errStatus(err) != 409 || err.Error() != "removing n3 would leave fewer than 3 servers" {
		t.Fatalf("%d %v", errStatus(err), err)
	}
	if c := cf.na.Calls(); len(c) != 0 {
		t.Errorf("nodeadm was asked %v", c)
	}
	if _, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n2", nodeadm.Cooperative); errStatus(err) != 400 {
		t.Errorf("a wrong typed id: %v", err)
	}

	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true), serverNode("n4", "10.215.0.4", true))
	cf.na.refuse["drain:n4"] = &nodeadm.APIError{Status: 409, Kind: nodeadm.KindQuorumMinimum, Text: "removing n4 would leave fewer than 3 servers"}
	a, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n4", "n4", nodeadm.Cooperative)
	if err != nil || a == nil || a.Op != OpNodeRemove {
		t.Fatalf("%+v %v", a, err)
	}
	r := waitServerOp(t, cf.h, serverOpKey("n4"))
	if r.OK || r.Error != "removing n4 would leave fewer than 3 servers" || r.Status != 409 {
		t.Errorf("op %+v", r)
	}
	if c := cf.na.Calls(); !slices.Equal(c, []string{"cordon:n4", "drain:n4", "uncordon:n4"}) {
		t.Errorf("calls %v", c)
	}
	if a := cf.actions(); !slices.Equal(a, []string{"server.removed:refused"}) {
		t.Errorf("audit %v", a)
	}
}

// TestRemoveAndRevokeClusterNode: a removal runs cordon → drain → DELETE
// cooperative → the nodeagent's uninstall and drops the entry; a revoke
// is DELETE …?mode=revoke at once.
func TestRemoveAndRevokeClusterNode(t *testing.T) {
	nodes := []nodeadm.Node{serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true), serverNode("n4", "10.215.0.4", true)}
	cf := newClusterFixture(t, nodes...)
	if _, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n4", "n4", nodeadm.Cooperative); err != nil {
		t.Fatal(err)
	}
	if r := waitServerOp(t, cf.h, serverOpKey("n4")); !r.OK {
		t.Fatalf("op %+v", r)
	}
	if c := cf.na.Calls(); !slices.Equal(c, []string{"cordon:n4", "drain:n4", "remove:n4:cooperative", "uninstall:n4"}) {
		t.Errorf("calls %v", c)
	}
	cf = newClusterFixture(t, nodes[:3]...)
	if _, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n3", nodeadm.Revoke); err != nil {
		t.Fatal(err)
	}
	if c := cf.na.Calls(); !slices.Equal(c, []string{"remove:n3:revoke"}) {
		t.Errorf("calls %v", c)
	}
	if a := cf.actions(); !slices.Equal(a, []string{"server.revoked:ok"}) {
		t.Errorf("audit %v", a)
	}
	if _, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n9", "n9", nodeadm.Revoke); errStatus(err) != 404 {
		t.Errorf("an unknown node: %v", err)
	}
}

// TestWorkersRefusedOnKube: a Docker worker on Kubernetes is refused with
// the R9 text; a cluster node on Docker is refused too.
func TestWorkersRefusedOnKube(t *testing.T) {
	cf := newClusterFixture(t)
	_, _, err := cf.h.AddServer(context.Background(), admin, "nas", "NAS")
	if errStatus(err) != 409 || err.Error() != "Docker workers can't join a Kubernetes cluster: add it as a cluster node" {
		t.Errorf("worker on kube: %d %v", errStatus(err), err)
	}
	f := newFixture(t)
	f.h.SetNodeadm(&fakeNodeadm{})
	_, _, err = f.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"})
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "cluster nodes need a Kubernetes primary") {
		t.Errorf("cluster node on docker: %d %v", errStatus(err), err)
	}
}

// TestSettleInterruptedClusterEnrol: a Hub restart during an enrolment
// before k3s joined voids the code and drops the entry.
func TestSettleInterruptedClusterEnrol(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	cf.na.refuse["remove:n2:cooperative"] = errors.New("nodeadm down")
	cf.h.mu.Lock()
	cf.h.st.Servers = map[string]state.Server{"n2": {Kind: "cluster-node", State: ServerEnrolling, Enrol: &state.Enrol{Step: StepEnrolled}}}
	cf.h.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	if _, ok := cf.serverEntry("n2"); !ok {
		t.Fatal("dropped although nodeadm didn't take the void")
	}
	delete(cf.na.refuse, "remove:n2:cooperative")
	cf.h.settleClusterNodes(context.Background())
	if s, _ := cf.serverEntry("n2"); s.State != ServerRevoked {
		t.Fatalf("after the void: %+v, want revoked (watched)", s)
	}
	if c := cf.na.Calls(); slices.Contains(c, "remove:n2:revoke") {
		t.Errorf("a never-enrolled code was revoked: %v", c)
	}
}

// TestRevokeParkedIsAccepted (I1): nodeadm's parked revoke (409
// quorum_minimum, the vector "revoke: etcd without quorum") and its 503
// "goes on in the background" are accepted: the mesh peer removed at
// once, the entry kept revoked with the parked line, audited ok; the
// entry goes once the cluster no longer lists the node.
func TestRevokeParkedIsAccepted(t *testing.T) {
	const parkedText = "removing n3 would leave etcd 1 healthy of 3 members: parked; security steps done; the server stays an etcd member until quorum returns; a compromised server needs rotate-ca"
	for _, refusal := range []*nodeadm.APIError{
		{Status: 409, Kind: nodeadm.KindQuorumMinimum, Text: parkedText},
		{Status: 503, Text: "the revocation of n3 goes on in the background: retry to see it finish"},
	} {
		cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", false), serverNode("n3", "10.215.0.3", false))
		var meshGone []string
		cf.h.cl.meshRemove = func(_ context.Context, id string) error { meshGone = append(meshGone, id); return nil }
		cf.na.refuse["remove:n3:revoke"] = refusal
		_, parked, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n3", nodeadm.Revoke)
		if err != nil || parked != refusal.Text {
			t.Fatalf("%d: %q %v", refusal.Status, parked, err)
		}
		if !slices.Equal(meshGone, []string{"n3"}) {
			t.Errorf("mesh peer removed %v", meshGone)
		}
		if s, ok := cf.serverEntry("n3"); !ok || s.State != ServerRevoked {
			t.Errorf("entry %+v %v", s, ok)
		}
		var view ServerView
		for _, v := range cf.h.Servers(context.Background()) {
			if v.ID == "n3" {
				view = v
			}
		}
		if view.State != ServerRevoked || view.Error != "revoked; waiting for quorum to remove its etcd member" {
			t.Errorf("view %+v", view)
		}
		cf.audit.mu.Lock()
		last := cf.audit.entries[len(cf.audit.entries)-1]
		cf.audit.mu.Unlock()
		if last.Action != "server.revoked" || last.Result != "ok" || !strings.Contains(last.Detail, "parked") {
			t.Errorf("audit %+v", last)
		}
		cf.h.settleClusterNodes(context.Background())
		if _, ok := cf.serverEntry("n3"); !ok {
			t.Error("dropped while the cluster still lists it")
		}
		cf.na.mu.Lock()
		cf.na.snap.Nodes = cf.na.snap.Nodes[:2]
		cf.na.mu.Unlock()
		clock := &offsetClock{}
		cf.h.srvT.now = clock.now
		cf.h.settleClusterNodes(context.Background())
		if _, ok := cf.serverEntry("n3"); !ok {
			t.Error("dropped at once: a Node may still register within 10 min")
		}
		clock.add(NodeGoneWait + time.Second)
		cf.h.settleClusterNodes(context.Background())
		_, kept := cf.serverEntry("n3")
		if refusal.Status == 409 && kept {
			t.Error("a confirmed (parked) revocation kept 10 min after the cluster dropped it")
		}
		if refusal.Status == 503 {
			// Unconfirmed: time alone never drops it; asked again.
			if !kept {
				t.Error("an unconfirmed revocation dropped on time alone")
			}
			delete(cf.na.refuse, "remove:n3:revoke") // nodeadm now answers done
			cf.h.settleClusterNodes(context.Background())
			if _, kept := cf.serverEntry("n3"); kept {
				t.Error("kept after nodeadm confirmed and 10 min without a Node")
			}
		}
	}
}

// TestEnrolEndNeverVoidsAJoinedNode (I2): the three ends of an enrolment.
// No node listed → only the code voided; a node listed in the poll the
// Stop lands on → removed (cordon, drain, remove, uninstall); a restart
// at step k3s_joined with the node listed → removed too.
func TestEnrolEndNeverVoidsAJoinedNode(t *testing.T) {
	// nodeadm's revoke and the uninstall; never a void, a cordon or an
	// uncordon (security review round 3).
	revoked := func(c []string) bool {
		return slices.Contains(c, "remove:n2:revoke") && slices.Contains(c, "uninstall:n2") && !slices.Contains(c, "remove:n2:cooperative") &&
			!slices.Contains(c, "cordon:n2") && !slices.Contains(c, "uncordon:n2")
	}
	// 1. Nothing joined: a void only.
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
		t.Fatal(err)
	}
	cf.h.StopServerEnrol("n2", admin, "")
	waitServerOp(t, cf.h, serverOpKey("n2"))
	if c := cf.na.Calls(); !slices.Contains(c, "remove:n2:cooperative") || slices.Contains(c, "cordon:n2") || slices.Contains(c, "uninstall:n2") {
		t.Errorf("void: %v", c)
	}

	// 2. The node registers in the poll the Stop lands on (the op never
	// saw it): removed, never only voided.
	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	stopped := make(chan struct{})
	var once sync.Once
	cf.na.onCluster = func(n int, s *nodeadm.Snapshot) {
		if n >= 3 {
			once.Do(func() {
				s.Nodes = append(s.Nodes, serverNode("n2", "10.215.0.2", false))
				close(stopped)
			})
		}
	}
	if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
		t.Fatal(err)
	}
	<-stopped
	cf.h.StopServerEnrol("n2", admin, "")
	waitServerOp(t, cf.h, serverOpKey("n2"))
	if c := cf.na.Calls(); !revoked(c) {
		t.Errorf("joined in the last poll: %v", c)
	}

	// 3. A restart at k3s_joined with the node listed.
	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true))
	cf.h.mu.Lock()
	cf.h.st.Servers = map[string]state.Server{"n2": {Kind: "cluster-node", State: ServerEnrolling, MeshIP: "10.215.0.2", Enrol: &state.Enrol{Step: StepK3sJoined}}}
	cf.h.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	if c := cf.na.Calls(); !revoked(c) {
		t.Errorf("restart at k3s_joined: %v", c)
	}
}

// TestSettleInterruptedRemoval (M9): an interrupted removal is a Stop:
// before its DELETE (the node listed) the node is uncordoned and ready
// again; after it the uninstall is finished and the entry goes.
func TestSettleInterruptedRemoval(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n4", "10.215.0.4", true))
	cf.h.mu.Lock()
	cf.h.st.Servers = map[string]state.Server{"n4": {Kind: "cluster-node", State: ServerRemoving, MeshIP: "10.215.0.4"},
		"n5": {Kind: "cluster-node", State: ServerRemoving, MeshIP: "10.215.0.5"}}
	cf.h.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	if s, _ := cf.serverEntry("n4"); s.State != ServerReady {
		t.Errorf("n4 %+v", s)
	}
	if _, ok := cf.serverEntry("n5"); ok {
		t.Error("n5 left")
	}
	if c := cf.na.Calls(); !slices.Equal(c, []string{"uncordon:n4", "uninstall:n5"}) {
		t.Errorf("calls %v", c)
	}
}

// TestAddClusterNodeChecksTheCode (M8): a code naming another CA or
// endpoint is voided and nothing is added.
func TestAddClusterNodeChecksTheCode(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	cf.na.ca = strings.Repeat("c", 64)
	_, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"})
	if errStatus(err) != 502 {
		t.Fatalf("%v", err)
	}
	if _, ok := cf.serverEntry("n2"); ok {
		t.Error("added")
	}
	if c := cf.na.Calls(); !slices.Contains(c, "remove:n2:cooperative") {
		t.Errorf("not voided: %v", c)
	}
	if a := cf.actions(); !slices.Equal(a, []string{"server.add:error"}) {
		t.Errorf("audit %v", a)
	}
}

// TestInitNodesListed (M5): the cluster's nodes the Hub didn't add are
// listed from the last snapshot.
func TestInitNodesListed(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	cf.h.settleClusterNodes(context.Background())
	var ids []string
	for _, v := range cf.h.Servers(context.Background()) {
		ids = append(ids, v.ID+":"+v.Kind+":"+v.Role)
	}
	if !slices.Equal(ids, []string{"primary::", "n1:cluster-node:server"}) {
		t.Errorf("list %v", ids)
	}
}

// TestNodeadmStatusesMapped (M11): a nodeadm 403 is a 502 (never the
// fresh sign-in's 403); its 503 names nodeadm.
func TestNodeadmStatusesMapped(t *testing.T) {
	if err := nodeadmErr(&nodeadm.APIError{Status: 403, Text: "this client may not call this route"}); errStatus(err) != 502 || err.Error() != "nodeadm refused the Hub's certificate" {
		t.Errorf("403: %v", err)
	}
	if err := nodeadmErr(&nodeadm.APIError{Status: 503, Kind: "not_leader", Text: "this nodeadm isn't the leader: retry"}); errStatus(err) != 503 || err.Error() != "nodeadm: this nodeadm isn't the leader: retry" {
		t.Errorf("503: %v", err)
	}
}

// TestStopBetweenReleaseAndRegistration (re-review N1): a Stop once the
// machine enrolled (nodeadm may have released its k3s material) but
// before its Node registers is a revoke, never a void: nodeadm's revoke,
// the nodeagent's uninstall, the entry kept revoked and watched. A Node
// that registers afterwards is removed for good; with none for 10 min
// the entry goes, and the list never shows the node again.
func TestStopBetweenReleaseAndRegistration(t *testing.T) {
	start := func(t *testing.T) *clusterFixture {
		cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
		inJoin := make(chan struct{})
		var once sync.Once
		cf.na.onCluster = func(n int, s *nodeadm.Snapshot) {
			if n == 2 {
				s.Enrolling = []nodeadm.Enrolling{{ID: "n2", Role: "server", Class: "home", Site: "main", MeshIP: "10.215.0.2", Mesh: nodeadm.MeshReport{Pub: fakeMeshKey("n2")}}}
			}
			if n >= 4 {
				once.Do(func() { close(inJoin) }) // waiting in k3s_joined
			}
		}
		if _, _, err := cf.h.AddClusterNode(context.Background(), admin, AddClusterNodeRequest{ID: "n2"}); err != nil {
			t.Fatal(err)
		}
		<-inJoin
		if err := cf.h.StopServerEnrol("n2", admin, ""); err != nil {
			t.Fatal(err)
		}
		if r := waitServerOp(t, cf.h, serverOpKey("n2")); r.OK {
			t.Fatalf("op %+v", r)
		}
		c := cf.na.Calls()
		if !slices.Contains(c, "remove:n2:revoke") || slices.Contains(c, "remove:n2:cooperative") || !slices.Contains(c, "uninstall:n2") {
			t.Fatalf("calls %v: want a revoke and the uninstall, never a void", c)
		}
		if s, ok := cf.serverEntry("n2"); !ok || s.State != ServerRevoked {
			t.Fatalf("entry %+v %v", s, ok)
		}
		return cf
	}

	// The Node registers afterwards: removed for good.
	cf := start(t)
	cf.na.mu.Lock()
	cf.na.onCluster = nil
	cf.na.snap.Enrolling = nil
	cf.na.snap.Nodes = append(cf.na.snap.Nodes, serverNode("n2", "10.215.0.2", true))
	cf.na.calls = nil
	cf.na.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	if c := cf.na.Calls(); !slices.Equal(c, []string{"remove:n2:revoke"}) {
		t.Errorf("registered after the revoke: %v, want nodeadm's revoke again (never a cordon, a drain or an uncordon)", c)
	}
	if s, _ := cf.serverEntry("n2"); s.State != ServerRevoked {
		t.Errorf("entry %+v, want kept revoked", s)
	}
	for _, v := range cf.h.Servers(context.Background()) {
		if v.ID == "n2" && v.State != ServerRevoked {
			t.Errorf("listed as %s", v.State)
		}
	}

	// No Node for 10 min: the entry goes.
	cf = start(t)
	clock := &offsetClock{}
	cf.h.srvT.now = clock.now
	cf.na.mu.Lock()
	cf.na.onCluster = nil
	cf.na.snap.Enrolling = nil
	cf.na.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	clock.add(NodeGoneWait - time.Minute)
	cf.h.settleClusterNodes(context.Background())
	if _, ok := cf.serverEntry("n2"); !ok {
		t.Error("dropped before 10 min without a Node")
	}
	clock.add(2 * time.Minute)
	cf.h.settleClusterNodes(context.Background())
	if _, ok := cf.serverEntry("n2"); ok {
		t.Error("kept past 10 min without a Node")
	}
}

// TestRevokedNodeNotListedAgain (re-review N2): after a revoke the cached
// snapshot no longer lists the node.
func TestRevokedNodeNotListedAgain(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true))
	cf.h.settleClusterNodes(context.Background()) // caches the snapshot
	if _, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n3", nodeadm.Revoke); err != nil {
		t.Fatal(err)
	}
	for _, v := range cf.h.Servers(context.Background()) {
		if v.ID == "n3" && v.State != ServerRevoked {
			t.Errorf("n3 listed as %s after its revoke: %+v", v.State, v)
		}
	}
}

// TestRevokedNodeAppearsIsRevokedAgain (round 3, ruling 1 and 4): a
// watched, revoked entry whose Node is listed is revoked again through
// nodeadm (never cordoned, drained or uncordoned, even when nodeadm
// refuses), kept revoked, and dropped only after NodeGoneWait without a
// Node.
func TestRevokedNodeAppearsIsRevokedAgain(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true), serverNode("n4", "10.215.0.4", true))
	clock := &offsetClock{}
	cf.h.srvT.now = clock.now
	if _, _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n4", "n4", nodeadm.Revoke); err != nil {
		t.Fatal(err)
	}
	// nodeadm refuses the next revoke: still never an uncordon.
	cf.na.refuse["remove:n4:revoke"] = &nodeadm.APIError{Status: 502, Text: "down"}
	cf.h.settleClusterNodes(context.Background())
	delete(cf.na.refuse, "remove:n4:revoke")
	cf.h.settleClusterNodes(context.Background())
	c := cf.na.Calls()
	if n := len(slices.DeleteFunc(slices.Clone(c), func(x string) bool { return x != "remove:n4:revoke" })); n != 3 {
		t.Errorf("calls %v: want three revokes", c)
	}
	for _, x := range c {
		if strings.HasPrefix(x, "cordon:") || strings.HasPrefix(x, "uncordon:") || strings.HasPrefix(x, "drain:") || x == "remove:n4:cooperative" {
			t.Errorf("a revoked node got %s", x)
		}
	}
	cf.na.mu.Lock()
	cf.na.snap.Nodes = cf.na.snap.Nodes[:3]
	cf.na.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	clock.add(NodeGoneWait - time.Second)
	cf.h.settleClusterNodes(context.Background())
	if _, ok := cf.serverEntry("n4"); !ok {
		t.Fatal("dropped before 10 min without a Node")
	}
	clock.add(2 * time.Second)
	cf.h.settleClusterNodes(context.Background())
	if _, ok := cf.serverEntry("n4"); ok {
		t.Error("kept past 10 min without a Node, confirmed")
	}
}

// TestUnknownNodeIsNotProof (round 3, ruling 3): nodeadm's unknown_node
// to a revoke never confirms it: with no Node listed for hours, the entry
// stays until nodeadm answers the revoke done.
func TestUnknownNodeIsNotProof(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	clock := &offsetClock{}
	cf.h.srvT.now = clock.now
	cf.h.mu.Lock()
	cf.h.st.Servers = map[string]state.Server{"n2": {Kind: "cluster-node", State: ServerEnrolling, MeshIP: "10.215.0.2", Enrol: &state.Enrol{Step: StepK3sJoined}}}
	cf.h.mu.Unlock()
	cf.na.refuse["remove:n2:revoke"] = &nodeadm.APIError{Status: 404, Kind: nodeadm.KindUnknownNode, Text: "unknown node n2"}
	for i := 0; i < 5; i++ {
		cf.h.settleClusterNodes(context.Background())
		clock.add(time.Hour)
	}
	if s, ok := cf.serverEntry("n2"); !ok || s.State != ServerRevoked {
		t.Fatalf("entry %+v %v: unknown_node and time alone dropped it", s, ok)
	}
	delete(cf.na.refuse, "remove:n2:revoke")
	cf.h.settleClusterNodes(context.Background()) // confirmed now; the gone clock runs on
	clock.add(NodeGoneWait)
	cf.h.settleClusterNodes(context.Background())
	if _, ok := cf.serverEntry("n2"); ok {
		t.Error("kept after nodeadm confirmed")
	}
}

// TestVoidIsWatched (round 3, ruling 2): a code a fresh snapshot reports
// unused is voided, never revoked; if its machine registers afterwards
// (the read-to-void window), it is revoked with the uninstall.
func TestVoidIsWatched(t *testing.T) {
	cf := newClusterFixture(t, serverNode("n1", "10.215.0.1", true))
	cf.h.mu.Lock()
	cf.h.st.Servers = map[string]state.Server{"n2": {Kind: "cluster-node", State: ServerEnrolling, MeshIP: "10.215.0.2", Enrol: &state.Enrol{Step: StepEnrolled}}}
	cf.h.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	if c := cf.na.Calls(); !slices.Equal(c, []string{"remove:n2:cooperative"}) {
		t.Fatalf("void: %v", c)
	}
	var view ServerView
	for _, v := range cf.h.Servers(context.Background()) {
		if v.ID == "n2" {
			view = v
		}
	}
	if view.State != ServerRevoked || view.Error != VoidedText {
		t.Errorf("view %+v", view)
	}
	cf.na.mu.Lock()
	cf.na.snap.Nodes = append(cf.na.snap.Nodes, serverNode("n2", "10.215.0.2", true))
	cf.na.calls = nil
	cf.na.mu.Unlock()
	cf.h.settleClusterNodes(context.Background())
	if c := cf.na.Calls(); !slices.Equal(c, []string{"remove:n2:revoke", "uninstall:n2"}) {
		t.Errorf("registered after its void: %v", c)
	}
}
