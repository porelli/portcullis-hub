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

	"github.com/portcullis/hub/internal/nodeadm"
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
	// onCluster runs on each snapshot read (the test's clock of the node).
	onCluster func(n int, s *nodeadm.Snapshot)
	reads     int
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
	c := servers.JoinCodeV2{V: 2, Kind: "cluster", Endpoint: "https://example.org/node", Servers: []string{"10.215.0.1"}, ServerID: r.ServerID,
		Role: r.Role, Class: r.Class, Site: r.Site, CASHA256: hex, ScriptSHA256: hex, AgentSHA256: servers.AgentSHA256{AMD64: hex, ARM64: hex},
		MeshIP: r.MeshIP, Secret: testSecret}.EncodeV2()
	f.mu.Lock()
	f.codes = append(f.codes, c)
	f.mu.Unlock()
	return nodeadm.CodeAnswer{Code: c, ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)}, nil
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
	na := &fakeNodeadm{snap: nodeadm.Snapshot{V: 1, Nodes: nodes}, refuse: map[string]error{}}
	f.h.SetNodeadm(na)
	f.h.cl.poll = 2 * time.Millisecond
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
	if err != nil || out.Role != "server" || out.Notice != ServerJoinNotice || !strings.HasPrefix(code, "pcj2.") || len(out.Warnings) != 0 {
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
			s.Enrolling = []nodeadm.Enrolling{{ID: "n2", Role: "server", Class: "home", Site: "main", MeshIP: "10.215.0.2"}}
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
	assertNoClusterSecret(t, cf, []string{code, testSecret, string(raw)})

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
	if c := cf.na.Calls(); !slices.Contains(c, "remove:n2:cooperative") || slices.Contains(c, "drain:n2") {
		t.Errorf("calls %v: want the code voided, no drain", c)
	}
	if _, ok := cf.serverEntry("n2"); ok {
		t.Error("the entry is left")
	}

	// A Stop once k3s joined: the node removed as a removal does.
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
	if i, j, k := slices.Index(c, "cordon:n2"), slices.Index(c, "drain:n2"), slices.Index(c, "remove:n2:cooperative"); i < 0 || j < i || k < j || !slices.Contains(c, "uninstall:n2") {
		t.Errorf("calls %v: want cordon → drain → remove → uninstall", c)
	}
	if _, ok := cf.serverEntry("n2"); ok {
		t.Error("the entry is left")
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
	_, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n3", nodeadm.Cooperative)
	if errStatus(err) != 409 || err.Error() != "removing n3 would leave fewer than 3 servers" {
		t.Fatalf("%d %v", errStatus(err), err)
	}
	if c := cf.na.Calls(); len(c) != 0 {
		t.Errorf("nodeadm was asked %v", c)
	}
	if _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n2", nodeadm.Cooperative); errStatus(err) != 400 {
		t.Errorf("a wrong typed id: %v", err)
	}

	cf = newClusterFixture(t, serverNode("n1", "10.215.0.1", true), serverNode("n2", "10.215.0.2", true), serverNode("n3", "10.215.0.3", true), serverNode("n4", "10.215.0.4", true))
	cf.na.refuse["drain:n4"] = &nodeadm.APIError{Status: 409, Kind: nodeadm.KindQuorumMinimum, Text: "removing n4 would leave fewer than 3 servers"}
	a, err := cf.h.RemoveClusterNode(context.Background(), admin, "n4", "n4", nodeadm.Cooperative)
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
	if _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n4", "n4", nodeadm.Cooperative); err != nil {
		t.Fatal(err)
	}
	if r := waitServerOp(t, cf.h, serverOpKey("n4")); !r.OK {
		t.Fatalf("op %+v", r)
	}
	if c := cf.na.Calls(); !slices.Equal(c, []string{"cordon:n4", "drain:n4", "remove:n4:cooperative", "uninstall:n4"}) {
		t.Errorf("calls %v", c)
	}
	cf = newClusterFixture(t, nodes[:3]...)
	if _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n3", "n3", nodeadm.Revoke); err != nil {
		t.Fatal(err)
	}
	if c := cf.na.Calls(); !slices.Equal(c, []string{"remove:n3:revoke"}) {
		t.Errorf("calls %v", c)
	}
	if a := cf.actions(); !slices.Equal(a, []string{"server.revoked:ok"}) {
		t.Errorf("audit %v", a)
	}
	if _, err := cf.h.RemoveClusterNode(context.Background(), admin, "n9", "n9", nodeadm.Revoke); errStatus(err) != 404 {
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
	if _, ok := cf.serverEntry("n2"); ok {
		t.Fatal("still listed after the void")
	}
}
