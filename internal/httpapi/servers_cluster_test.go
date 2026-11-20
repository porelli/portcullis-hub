package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/servers"
)

// clusterNodeadm is nodeadm for the route tests: 3 healthy servers, codes
// for whatever is asked, the calls recorded.
type clusterNodeadm struct {
	mu     sync.Mutex
	calls  []string
	nodes  []nodeadm.Node
	ca     string           // the pki_node CA's sha256 the codes name
	refuse map[string]error // "remove:n3:revoke", …
}

func (f *clusterNodeadm) rec(c string) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

func (f *clusterNodeadm) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *clusterNodeadm) IssueCode(_ context.Context, r nodeadm.CodeRequest) (nodeadm.CodeAnswer, error) {
	f.rec("codes:" + r.ServerID + ":" + r.Role)
	h := strings.Repeat("b", 64)
	return nodeadm.CodeAnswer{Code: servers.JoinCodeSecret(servers.JoinCodeV2{V: 2, Kind: "cluster", Endpoint: "https://example.org/node", Servers: []string{"10.215.0.1"},
		ServerID: r.ServerID, Role: r.Role, Class: r.Class, Site: r.Site, CASHA256: f.ca, ScriptSHA256: h, AgentSHA256: servers.AgentSHA256{AMD64: h, ARM64: h},
		MeshIP: r.MeshIP, Secret: "q5idMrnFv0N4pQ2KjXHAzmYEjbEkpmCaKEHY_moMciM"}.EncodeV2()), ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)}, nil
}

func (f *clusterNodeadm) Cluster(context.Context) (nodeadm.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return nodeadm.Snapshot{V: 1, Nodes: append([]nodeadm.Node(nil), f.nodes...)}, nil
}
func (f *clusterNodeadm) SetLabels(_ context.Context, id string, _ nodeadm.Labels) error {
	f.rec("labels:" + id)
	return nil
}
func (f *clusterNodeadm) Cordon(_ context.Context, id string) error {
	f.rec("cordon:" + id)
	return nil
}
func (f *clusterNodeadm) Uncordon(_ context.Context, id string) error {
	f.rec("uncordon:" + id)
	return nil
}
func (f *clusterNodeadm) Drain(_ context.Context, id string) error { f.rec("drain:" + id); return nil }
func (f *clusterNodeadm) Remove(_ context.Context, id string, m nodeadm.RemoveMode) error {
	f.rec("remove:" + id + ":" + string(m))
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refuse["remove:"+id+":"+string(m)]
}

// clusterAgent is a node's nodeagent for the route tests: it answers,
// with a key from its id, and takes any mesh plan.
type clusterAgent struct {
	f  *clusterNodeadm
	id string
}

func (a clusterAgent) Uninstall(context.Context) error { return nil }
func (a clusterAgent) Health(context.Context) (nodeagent.Health, error) {
	k := make([]byte, 32)
	copy(k, a.id)
	return nodeagent.Health{ID: a.id, MeshPub: base64.StdEncoding.EncodeToString(k), K3s: "running"}, nil
}
func (a clusterAgent) PutMeshPeers(context.Context, nodeagent.MeshPlan) error { return nil }
func (a clusterAgent) RTT(context.Context) (map[string]int, error) {
	a.f.mu.Lock()
	defer a.f.mu.Unlock()
	out := map[string]int{}
	for _, n := range a.f.nodes {
		if n.Name != a.id {
			out[n.Name] = 1
		}
	}
	return out, nil
}

func clusterServer(name string) nodeadm.Node {
	return nodeadm.Node{Name: name, Role: "server", Ready: true, Labels: map[string]string{}, Addresses: nodeadm.NodeAddresses{Mesh: "10.215.0." + name[1:]}}
}

type clusterEnv struct {
	*instEnv
	fa *fakeFreshAuth
	na *clusterNodeadm
}

func newClusterEnv(t *testing.T) *clusterEnv {
	t.Helper()
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		cfg: func(c *hub.Config) {
			c.Runtime = runtime.KindKubernetes
			c.Domain = "example.org"
			os.MkdirAll(c.ProjectDir, 0o755)
			os.WriteFile(filepath.Join(c.ProjectDir, ".env"), []byte("PORTCULLIS_KUBE_CONTEXT=default\n"), 0o644)
		},
		rt: &runtimetest.Fake{K: runtime.KindKubernetes, InfoVal: runtime.Info{Verified: true}},
	})
	ca := newServersCA(t)
	e.s.Hub.SetNodeSigner(ca)
	sum := sha256.Sum256(ca.cert.Raw)
	na := &clusterNodeadm{nodes: []nodeadm.Node{clusterServer("n1"), clusterServer("n2"), clusterServer("n3")}, ca: hex.EncodeToString(sum[:]),
		refuse: map[string]error{}}
	e.s.Hub.SetNodeadm(na)
	e.s.Hub.SetNodeagents(func(id, _ string) hub.NodeagentAPI { return clusterAgent{na, id} })
	fa := &fakeFreshAuth{}
	e.s.Hub.SetFreshAuth(hub.ListenerHub, fa)
	e.s.Hub.SetFreshAuthReadyForTest(true)
	t.Cleanup(func() {
		for _, id := range []string{"n4", "n5"} {
			e.s.Hub.StopServerEnrol(id, directory.Human("root"), "")
		}
		deadline := time.Now().Add(10 * time.Second)
		for _, id := range []string{"n4", "n5"} {
			for time.Now().Before(deadline) {
				if r := e.s.Hub.ServerOp(id, ""); r == nil || !r.Running {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	})
	return &clusterEnv{instEnv: e, fa: fa, na: na}
}

// TestAddClusterNodeNeedsFreshSignIn: POST /api/servers kind cluster-node
// without the proof is 403 "a fresh sign-in is required" (contract §17.3
// †), nodeadm is never asked for a code and no successful server.add is
// audited; with it, 201 with the code once (no-store), the role, the
// warnings and the one-liner, and server.add audited ok without the code.
func TestAddClusterNodeNeedsFreshSignIn(t *testing.T) {
	e := newClusterEnv(t)
	code, body := e.do(t, "root", "POST", "/api/servers", `{"id":"n4","kind":"cluster-node"}`)
	if code != 403 || !strings.Contains(body, "a fresh sign-in is required") {
		t.Fatalf("no proof: %d %s", code, body)
	}
	if c := e.na.Calls(); len(c) != 0 {
		t.Errorf("nodeadm was asked %v", c)
	}
	for _, a := range e.auditActions(t, "server.add") {
		if strings.HasPrefix(a, "server.add:ok") {
			t.Errorf("audited %s without a fresh sign-in", a)
		}
	}
	for _, bad := range []string{
		`{"id":"n4","kind":"cluster-node","role":"boss",` + proofJSON + `}`,
		`{"id":"n4","kind":"pod",` + proofJSON + `}`,
		`{"id":"n4","role":"server",` + proofJSON + `}`, // a worker takes no role
		`{"id":"n4","kind":"cluster-node","site":"edge","storage":true,` + proofJSON + `}`,
		`{"id":"n4","kind":"cluster-node","token":"x",` + proofJSON + `}`,
	} {
		if code, body := e.do(t, "root", "POST", "/api/servers", bad); code != 400 {
			t.Errorf("%s: %d %s", bad, code, body)
		}
	}
	if e.fa.calls.Load() != 0 {
		t.Errorf("a bad request spent the proof")
	}
	resp, body := doAs(t, e.hub, "root", "POST", "/api/servers", `{"id":"n4","name":"Four","kind":"cluster-node","role":"server",`+proofJSON+`}`)
	if resp.StatusCode != 201 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("add: %d %s", resp.StatusCode, body)
	}
	var a struct {
		Code, Role, Notice, Command, Op, Poll string
		Warnings                              []string
	}
	json.Unmarshal([]byte(body), &a)
	if !strings.HasPrefix(a.Code, "pcj2.") || a.Role != "server" || a.Op != "server_enrol" || !strings.HasPrefix(a.Poll, "/api/servers/n4/op?op_id=") ||
		a.Notice != "Joining as a server gives this machine full control of the cluster (cluster-admin)." ||
		a.Command != "curl -fsSL https://example.org/node/join.sh | sudo sh" ||
		len(a.Warnings) != 1 || a.Warnings[0] != "an even number of servers doesn't add failure tolerance" {
		t.Errorf("answer %s", body)
	}
	if got := e.auditActions(t, "server.add"); len(got) == 0 || got[len(got)-1] != "server.add:ok:root:n4" {
		t.Errorf("audit %v", got)
	}
	raw, _ := os.ReadFile(e.audit)
	if strings.Contains(string(raw), a.Code) || strings.Contains(string(raw), "q5idMrnFv0N4pQ2KjXHAzmYEjbEkpmCaKEHY") {
		t.Error("the code is in the audit")
	}
	// The list says what Add adds here and never carries the code.
	code, body = e.do(t, "root", "GET", "/api/servers", "")
	if code != 200 || !strings.Contains(body, `"add_kind":"cluster-node"`) || !strings.Contains(body, `"kind":"cluster-node"`) || strings.Contains(body, "pcj2.") {
		t.Errorf("list %d %s", code, body)
	}
	// A Docker worker is refused here (R9).
	code, body = e.do(t, "root", "POST", "/api/servers", `{"id":"nas",`+proofJSON+`}`)
	if code != 409 || !strings.Contains(body, "Docker workers can't join a Kubernetes cluster: add it as a cluster node") {
		t.Errorf("worker on kube: %d %s", code, body)
	}
}

// TestClusterNodeRoutesRemoveRevoke: on Kubernetes DELETE /api/servers/{id}
// starts node_remove (typed id, fresh sign-in), revoke is nodeadm's revoke
// mode; a server below quorum is 409 with nodeadm's text.
func TestClusterNodeRoutesRemoveRevoke(t *testing.T) {
	e := newClusterEnv(t)
	code, body := e.do(t, "root", "DELETE", "/api/servers/n3", `{"confirm":"n3",`+proofJSON+`}`)
	if code != 409 || !strings.Contains(body, "removing n3 would leave fewer than 3 servers") {
		t.Errorf("below quorum: %d %s", code, body)
	}
	code, body = e.do(t, "root", "POST", "/api/servers/n3/revoke", `{"confirm":"n2",`+proofJSON+`}`)
	if code != 400 {
		t.Errorf("a wrong typed id: %d %s", code, body)
	}
	code, body = e.do(t, "root", "POST", "/api/servers/n3/revoke", `{"confirm":"n3",`+proofJSON+`}`)
	if code != 200 || !strings.Contains(body, `"revoked"`) {
		t.Errorf("revoke: %d %s", code, body)
	}
	e.na.mu.Lock()
	e.na.nodes = append(e.na.nodes, clusterServer("n4"), clusterServer("n5"))
	e.na.mu.Unlock()
	code, body = e.do(t, "root", "DELETE", "/api/servers/n5", `{"confirm":"n5",`+proofJSON+`}`)
	if code != 202 || !strings.Contains(body, `"op":"node_remove"`) {
		t.Fatalf("remove: %d %s", code, body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r := e.s.Hub.ServerOp("n5", ""); r != nil && !r.Running {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := strings.Join(e.na.Calls(), ",")
	if !strings.Contains(got, "remove:n3:revoke") || !strings.Contains(got, "cordon:n5,drain:n5,remove:n5:cooperative") {
		t.Errorf("calls %s", got)
	}
}

// TestClusterNodeRoutesNeverOverMCP: adding, removing and revoking a
// server (a cluster node on Kubernetes) are routes without a tool, so no
// MCP client ever reaches them (TestToolParity holds the rest).
func TestClusterNodeRoutesNeverOverMCP(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	for _, r := range []string{"POST /api/servers", "DELETE /api/servers/{id}", "POST /api/servers/{id}/revoke"} {
		if serverNoToolRoutes[r] == "" {
			t.Errorf("%s isn't in serverNoToolRoutes", r)
		}
		for _, scope := range []string{ScopeAdmin, ScopePeople} {
			for _, tl := range e.s.tools(scope) {
				for _, tw := range append([]string{tl.Twin}, tl.AlsoTwins...) {
					if tw == r {
						t.Errorf("tool %s mirrors %s", tl.Name, r)
					}
				}
			}
		}
	}
}

// TestHostClusterNodeTwins: the socket's twins run the running Hub's add
// (actor cli, no fresh sign-in: the host operator), answer the code once,
// and refuse a mismatched typed id.
func TestHostClusterNodeTwins(t *testing.T) {
	e := newClusterEnv(t)
	srv := httptest.NewServer(HostHandler(e.s.Hub))
	defer srv.Close()
	post := func(path, body string) (int, string) {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, body := post("/host/servers/cluster-node", `{"id":"n4"}`)
	if code != 201 || !strings.Contains(body, `"code":"pcj2.`) || !strings.Contains(body, `"role":"agent"`) {
		t.Fatalf("add: %d %s", code, body)
	}
	if got := e.auditActions(t, "server.add"); len(got) != 1 || got[0] != "server.add:ok:cli:n4" {
		t.Errorf("audit %v", got)
	}
	if code, _ := post("/host/servers/cluster-node", `{"id":"n5","code":"x"}`); code != 400 {
		t.Errorf("an unknown key: %d", code)
	}
	if code, body := post("/host/servers/n3/revoke", `{"confirm":"n2"}`); code != 400 {
		t.Errorf("typed mismatch: %d %s", code, body)
	}
}

// TestClusterRevokeParkedRoute (I1): a parked revoke answers 202 with
// nodeadm's text and the list shows the node revoked, waiting for quorum.
func TestClusterRevokeParkedRoute(t *testing.T) {
	e := newClusterEnv(t)
	parked := "removing n3 would leave etcd 1 healthy of 3 members: parked; security steps done; the server stays an etcd member until quorum returns; a compromised server needs rotate-ca"
	e.na.refuse["remove:n3:revoke"] = &nodeadm.APIError{Status: 409, Kind: nodeadm.KindQuorumMinimum, Text: parked}
	code, body := e.do(t, "root", "POST", "/api/servers/n3/revoke", `{"confirm":"n3",`+proofJSON+`}`)
	if code != 202 || !strings.Contains(body, `"parked":true`) || !strings.Contains(body, "parked; security steps done") {
		t.Fatalf("parked revoke: %d %s", code, body)
	}
	code, body = e.do(t, "root", "GET", "/api/servers", "")
	if code != 200 || !strings.Contains(body, "revoked; waiting for quorum to remove its etcd member") {
		t.Errorf("list %d %s", code, body)
	}
	if got := e.auditActions(t, "server.revoked"); len(got) == 0 || got[len(got)-1] != "server.revoked:ok:root:n3" {
		t.Errorf("audit %v", got)
	}
}

// TestClusterRefusalsSpareTheProof (M2): the R9 refusals answer 409
// before the fresh sign-in proof is checked.
func TestClusterRefusalsSpareTheProof(t *testing.T) {
	e := newClusterEnv(t)
	if code, body := e.do(t, "root", "POST", "/api/servers", `{"id":"nas",`+proofJSON+`}`); code != 409 || !strings.Contains(body, "Docker workers can't join") {
		t.Errorf("worker on kube: %d %s", code, body)
	}
	d := newServersEnv(t)
	if code, body := d.do(t, "root", "POST", "/api/servers", `{"id":"n4","kind":"cluster-node",`+proofJSON+`}`); code != 409 || !strings.Contains(body, "cluster nodes need a Kubernetes primary") {
		t.Errorf("cluster node on docker: %d %s", code, body)
	}
	if e.fa.calls.Load() != 0 || d.fa.calls.Load() != 0 {
		t.Errorf("a proof was spent: %d %d", e.fa.calls.Load(), d.fa.calls.Load())
	}
	// The host twins aren't there on Docker (M6).
	srv := httptest.NewServer(HostHandler(d.s.Hub))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/host/servers")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("GET /host/servers on docker: %d", resp.StatusCode)
	}
}

// TestClusterNodeSettingsNameOnly (M7): a cluster node takes a name, not
// Local networks or a backup schedule; its detail has neither.
func TestClusterNodeSettingsNameOnly(t *testing.T) {
	e := newClusterEnv(t)
	if code, body := e.do(t, "root", "POST", "/api/servers", `{"id":"n4","kind":"cluster-node",`+proofJSON+`}`); code != 201 {
		t.Fatalf("add %d %s", code, body)
	}
	if code, body := e.do(t, "root", "PUT", "/api/servers/n4/settings", `{"backup_schedule":{"mode":"daily","hour":3}}`); code != 409 || !strings.Contains(body, "name only") {
		t.Errorf("schedule: %d %s", code, body)
	}
	if code, body := e.do(t, "root", "PUT", "/api/servers/n4/settings", `{"name":"Four"}`); code != 200 || !strings.Contains(body, `"local_networks":[]`) {
		t.Errorf("name: %d %s", code, body)
	}
}
