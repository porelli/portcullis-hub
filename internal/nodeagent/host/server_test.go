package host

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// TestOnlyFixedOperations: the routing table is §20.4's list with its
// clients; any other method or path is 404.
func TestOnlyFixedOperations(t *testing.T) {
	want := []Route{
		{"GET", "/v1/health", []string{na.CNHub, na.CNNodeadm}},
		{"GET", "/v1/checks", []string{na.CNHub}},
		{"PUT", "/v1/mesh/peers", []string{na.CNHub}},
		{"GET", "/v1/mesh/rtt", []string{na.CNHub}},
		{"GET", "/v1/probes", []string{na.CNHub, na.CNFrontdoor}},
		{"PUT", "/v1/probes/targets", []string{na.CNNodeadm}},
		{"POST", "/v1/etcd/remove-member", []string{na.CNNodeadm}},
		{"POST", "/v1/k3s/uninstall", []string{na.CNHub}},
		{"POST", "/v1/k3s/token-rotate", []string{na.CNNodeadm}},
	}
	if len(Routes) != len(want) {
		t.Fatalf("%d routes", len(Routes))
	}
	for i := range want {
		if Routes[i].Method != want[i].Method || Routes[i].Path != want[i].Path || !slices.Equal(Routes[i].Clients, want[i].Clients) {
			t.Errorf("route %d: %+v, want %+v", i, Routes[i], want[i])
		}
	}
	r := newRig(t, "server")
	s := r.server()
	hub := r.client(r.ca, na.CNHub)
	for _, x := range [][2]string{{"GET", "/"}, {"GET", "/v1"}, {"GET", "/v1/exec"}, {"POST", "/v1/health"}, {"GET", "/v1/mesh/peers"},
		{"DELETE", "/v1/k3s/uninstall"}, {"GET", "/v1/health/"}, {"GET", "/v1/health?x=1"}, {"GET", "/V1/health"}, {"GET", "/v1/../v1/health"}} {
		if code, _ := do(t, hub, x[0], s.URL+x[1], ""); code != 404 {
			t.Errorf("%s %s: %d, want 404", x[0], x[1], code)
		}
	}
	code, body := do(t, hub, "GET", s.URL+"/v1/health", "")
	var h na.Health
	if code != 200 || json.Unmarshal([]byte(body), &h) != nil || h.ID != "n2" || h.MeshIP != "10.215.0.2" || h.MeshPub != r.pub || h.K3s != "absent" {
		t.Errorf("health %d %s", code, body)
	}
	// Each route's clients only.
	cns := []string{na.CNHub, na.CNFrontdoor, na.CNNodeadm, "link.control", "n3.cluster.portcullis.internal"}
	for _, rt := range Routes {
		if rt.Path == "/v1/k3s/uninstall" {
			continue // a 204 starts the uninstall
		}
		for _, cn := range cns {
			code, _ := do(t, r.client(r.ca, cn), rt.Method, s.URL+rt.Path, "{}")
			if allowed := slices.Contains(rt.Clients, cn); allowed == (code == 403) {
				t.Errorf("%s %s as %s: %d", rt.Method, rt.Path, cn, code)
			}
		}
	}
	// Another CA: refused at the handshake.
	other := newCA(t)
	if code, _ := do(t, r.client(other, na.CNHub), "GET", s.URL+"/v1/health", ""); code != 0 {
		t.Errorf("another CA's certificate: %d", code)
	}
	// A body over 1 MiB.
	big := `{"peers":[],"forward":false,"x":"` + strings.Repeat("a", na.MaxBody) + `"}`
	if code, _ := do(t, hub, "PUT", s.URL+"/v1/mesh/peers", big); code != http.StatusRequestEntityTooLarge {
		t.Errorf("over 1 MiB: %d", code)
	}
}

// TestFrontdoorCertOnlyProbes: frontdoor.control reads GET /v1/probes and
// nothing else.
func TestFrontdoorCertOnlyProbes(t *testing.T) {
	r := newRig(t, "server")
	s := r.server()
	fd := r.client(r.ca, na.CNFrontdoor)
	if code, body := do(t, fd, "GET", s.URL+"/v1/probes", ""); code != 200 || !strings.Contains(body, `"rounds":[]`) {
		t.Errorf("GET /v1/probes: %d %s", code, body)
	}
	if code, _ := do(t, fd, "PUT", s.URL+"/v1/mesh/peers", `{"peers":[],"forward":false}`); code != 403 {
		t.Errorf("PUT /v1/mesh/peers as the front door: %d", code)
	}
	if code, _ := do(t, fd, "GET", s.URL+"/v1/health", ""); code != 403 {
		t.Errorf("GET /v1/health as the front door: %d", code)
	}
}

type callVector struct {
	Name    string `json:"name"`
	Call    string `json:"call"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Body    string `json:"body"`
	Via     string `json:"via"`
	ViaMesh string `json:"via_mesh"`
	Node    string `json:"node"`
	NodeMsh string `json:"node_mesh"`
	Token   string `json:"token"`
	Step    string `json:"step"`
}

// TestNodeagentCallVectors: nodeadm's calls (core's
// nodeagent_call_vectors.json) decode strictly and are answered for
// nodeadm.control.
func TestNodeagentCallVectors(t *testing.T) {
	b, err := os.ReadFile("../testdata/nodeagent_call_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Calls []map[string]any `json:"calls"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, "server")
	r.a.cfg.Addresses = func(ctx2 ctxT) (map[string]DocNode, error) {
		return map[string]DocNode{"n3": {Mesh: "10.215.0.3", State: "removed"}}, nil
	}
	etcd := &fakeEtcd{members: []Member{{ID: 1, Name: "n2-1a2b3c4d", PeerURLs: []string{"https://10.215.0.2:2380"}}, {ID: 3, Name: "n3-5e6f7a8b", PeerURLs: []string{"https://10.215.0.3:2380"}}}}
	r.a.cfg.Etcd = etcd
	sup := &fakeSup{}
	r.a.cfg.Supervisor = sup
	installK3s(t, r, "server", "K10"+strings.Repeat("a", 64)+"::server:old")
	s := r.server()
	c := r.client(r.ca, na.CNNodeadm)
	for _, v := range doc.Calls {
		path, body := v["path"].(string), v["body"].(string)
		switch v["call"] {
		case "etcd_remove_member":
			var q na.EtcdRemove
			if err := decode([]byte(body), &q); err != nil || q.Node == "" {
				t.Errorf("%s: %v", v["name"], err)
			}
			// The vector removes n2 via n1; on this node (n2) the same
			// shape for n3 is accepted.
			body = `{"mesh_ip":"10.215.0.3","node":"n3"}`
		case "token_rotate":
			var q na.TokenRotate
			if err := decode([]byte(body), &q); err != nil || q.Step != "rotate" || !K10Re.MatchString(q.NewToken) {
				t.Errorf("%s: %v", v["name"], err)
			}
			// The vector's token pins the vectors' CA: this node's CA here.
			m := K10Re.FindStringSubmatch(q.NewToken)
			body = strings.Replace(body, m[1], caHash, 1)
		}
		code, out := do(t, c, v["method"].(string), s.URL+path, body)
		if code/100 != 2 {
			t.Errorf("%s: %d %s", v["name"], code, out)
		}
	}
	if g := etcd.gone(); len(g) != 1 || g[0] != 3 {
		t.Errorf("etcd removed %v", g)
	}
	if sup.calls != 1 {
		t.Errorf("supervisor calls %d", sup.calls)
	}
}
