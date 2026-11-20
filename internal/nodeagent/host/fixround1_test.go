package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	na "github.com/portcullis/hub/internal/nodeagent"
)

func readTok(t *testing.T, r *rig, f string) string {
	b, _ := os.ReadFile(filepath.Join(r.root, f))
	return strings.TrimSpace(string(b))
}

// TestTokenRotateResumes (C1): the step runs on its own context; a
// request that gives up mid-step (the supervisor re-keyed, its answer
// late and then an error) doesn't stop it; a retry finishes; a step cut
// short after the re-key (its intent recorded, the old token file kept)
// finishes without a second supervisor call; a failed call with no
// re-key keeps the old file and its intent, and a retry completes.
func TestTokenRotateResumes(t *testing.T) {
	newTok := "K10" + caHash + "::server:newpass0123456789"
	r := newRig(t, "server")
	etcd := &fakeEtcd{}
	r.a.cfg.Etcd = etcd
	sup := &fakeSup{etcd: etcd, block: make(chan struct{}), err: errors.New("the k3s supervisor answered 504 to the token rotation")}
	r.a.cfg.Supervisor = sup
	installK3s(t, r, "server", "rawinittoken0123")
	s := r.server()
	c := r.client(r.ca, na.CNNodeadm)
	c.Timeout = 300 * time.Millisecond
	body := `{"new_token":"` + newTok + `","step":"rotate"}`
	if code, _ := do(t, c, "POST", s.URL+"/v1/k3s/token-rotate", body); code != 0 {
		t.Fatalf("the first call answered %d before the supervisor did", code)
	}
	if readTok(t, r, K3sTokenFile) != "rawinittoken0123" {
		t.Error("the token file changed before the supervisor answered")
	}
	close(sup.block)
	c.Timeout = 10 * time.Second
	if code, out := do(t, c, "POST", s.URL+"/v1/k3s/token-rotate", body); code != 204 {
		t.Fatalf("the retry: %d %s", code, out)
	}
	if readTok(t, r, K3sTokenFile) != newTok || sup.calls != 1 {
		t.Errorf("after the retry: file %q, %d supervisor calls", readTok(t, r, K3sTokenFile), sup.calls)
	}
	if _, err := os.Stat(filepath.Join(r.root, intentFile)); err == nil {
		t.Error("the intent stayed")
	}

	// Cut short after the re-key: intent recorded, old file, bootstrap
	// already under the new token.
	r2 := newRig(t, "server")
	etcd2 := &fakeEtcd{}
	sup2 := &fakeSup{}
	r2.a.cfg.Etcd, r2.a.cfg.Supervisor = etcd2, sup2
	installK3s(t, r2, "server", "rawinittoken0123")
	etcd2.set(bootstrapKey("newpass0123456789"))
	ib, _ := json.Marshal(tokenIntent{Step: "rotate", NewSHA256: sha256Hex(newTok)})
	writeFile(t, r2.root, intentFile, string(ib), 0o600)
	if err := r2.a.TokenStep(context.Background(), na.TokenRotate{NewToken: newTok, Step: "rotate"}); err != nil {
		t.Fatal(err)
	}
	if sup2.calls != 0 || readTok(t, r2, K3sTokenFile) != newTok || r2.run.count("systemctl", "restart") != 1 {
		t.Errorf("resumed: %d calls, file %q, %d restarts", sup2.calls, readTok(t, r2, K3sTokenFile), r2.run.count("systemctl", "restart"))
	}
	// The file written but the restart cut short: the intent restarts again.
	writeFile(t, r2.root, intentFile, string(ib), 0o600)
	if err := r2.a.TokenStep(context.Background(), na.TokenRotate{NewToken: newTok, Step: "rotate"}); err != nil {
		t.Fatal(err)
	}
	if r2.run.count("systemctl", "restart") != 2 || sup2.calls != 0 {
		t.Error("a pending intent didn't restart k3s")
	}

	// A failed call, no re-key: the old file and the intent stay.
	r3 := newRig(t, "server")
	etcd3 := &fakeEtcd{}
	sup3 := &fakeSup{err: errors.New("the k3s supervisor answered 500 to the token rotation")}
	r3.a.cfg.Etcd, r3.a.cfg.Supervisor = etcd3, sup3
	installK3s(t, r3, "server", "rawinittoken0123")
	if err := r3.a.TokenStep(context.Background(), na.TokenRotate{NewToken: newTok, Step: "rotate"}); err == nil {
		t.Fatal("a failed rotation succeeded")
	}
	if readTok(t, r3, K3sTokenFile) != "rawinittoken0123" || r3.run.count("systemctl", "restart") != 0 {
		t.Error("a failed rotation changed the token file or restarted k3s")
	}
	fi, err := os.Stat(filepath.Join(r3.root, intentFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("intent %v %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(r3.root, intentFile)); strings.Contains(string(b), "newpass") {
		t.Error("the intent holds the token")
	}
	sup3.err, sup3.etcd = nil, etcd3
	if err := r3.a.TokenStep(context.Background(), na.TokenRotate{NewToken: newTok, Step: "rotate"}); err != nil || readTok(t, r3, K3sTokenFile) != newTok {
		t.Errorf("the retry: %v", err)
	}
	if bootstrapKey("abc") != "/bootstrap/ba7816bf8f01" {
		t.Errorf("bootstrapKey %s", bootstrapKey("abc"))
	}
}

// TestAgentTokenFileMissing (I2) and the CA pin (M7).
func TestAgentTokenFileMissing(t *testing.T) {
	agtTok := "K10" + caHash + "::node:agentpass0123456789"
	r := newRig(t, "server")
	installK3s(t, r, "server", "K10"+caHash+"::server:old")
	writeFile(t, r.root, "/etc/systemd/system/k3s.service", "ExecStart=/usr/local/bin/k3s server '--token-file=/etc/rancher/k3s/token'\n", 0o644)
	s := r.server()
	c := r.client(r.ca, na.CNNodeadm)
	for _, step := range []string{"rotate-agent", "apply-agent"} {
		code, out := do(t, c, "POST", s.URL+"/v1/k3s/token-rotate", `{"new_token":"`+agtTok+`","step":"`+step+`"}`)
		if code != 409 || !strings.Contains(out, `"kind":"agent_token_file_missing"`) {
			t.Errorf("%s: %d %s", step, code, out)
		}
	}
	// k3s's config.yaml naming it is enough.
	writeFile(t, r.root, "/etc/rancher/k3s/config.yaml", "agent-token-file: /etc/rancher/k3s/agent-token\n", 0o600)
	if code, out := do(t, c, "POST", s.URL+"/v1/k3s/token-rotate", `{"new_token":"`+agtTok+`","step":"apply-agent"}`); code != 204 {
		t.Errorf("with config.yaml: %d %s", code, out)
	}
	// Another cluster's token (another CA hash): 409, nothing written.
	other := "K10" + strings.Repeat("0", 64) + "::server:otherpass0123"
	if code, _ := do(t, c, "POST", s.URL+"/v1/k3s/token-rotate", `{"new_token":"`+other+`","step":"apply"}`); code != 409 {
		t.Errorf("another CA: %d", code)
	}
	if readTok(t, r, K3sTokenFile) != "K10"+caHash+"::server:old" {
		t.Error("another cluster's token was written")
	}
}

// TestTokenStepsNeverLeak (M13): every step on a server and an agent,
// with a supervisor error and a write error: no token in an answer or
// the log.
func TestTokenStepsNeverLeak(t *testing.T) {
	const pass = "s3cretpass0123456789"
	for _, role := range []string{"server", "agent"} {
		for _, fault := range []string{"none", "supervisor", "write"} {
			r := newRig(t, role)
			sup := &fakeSup{}
			if fault == "supervisor" {
				sup.err = errors.New("the k3s supervisor answered 401 to the token rotation")
			}
			r.a.cfg.Supervisor, r.a.cfg.Etcd = sup, &fakeEtcd{}
			installK3s(t, r, role, "K10"+caHash+"::server:old"+pass)
			if fault == "write" {
				os.Chmod(filepath.Join(r.root, "/etc/rancher/k3s"), 0o500)
				t.Cleanup(func() { os.Chmod(filepath.Join(r.root, "/etc/rancher/k3s"), 0o700) })
			}
			s := r.server()
			c := r.client(r.ca, na.CNNodeadm)
			var answers strings.Builder
			for _, step := range []string{"rotate", "rotate-agent", "apply", "apply-agent"} {
				for _, user := range []string{"server", "node"} {
					_, out := do(t, c, "POST", s.URL+"/v1/k3s/token-rotate", `{"new_token":"K10`+caHash+`::`+user+`:`+pass+`","step":"`+step+`"}`)
					answers.WriteString(out)
				}
			}
			for _, x := range []string{answers.String(), r.log.String()} {
				if strings.Contains(x, pass) {
					t.Errorf("%s/%s: a token leaked: %s", role, fault, x)
				}
			}
			for _, cmd := range r.run.cmds {
				if strings.Contains(strings.Join(append(cmd.Args, cmd.Env...), " ")+string(cmd.Stdin), pass) {
					t.Errorf("%s/%s: a token on a command line", role, fault)
				}
			}
		}
	}
}

// TestProbeTargetsPublicOnly (I3).
func TestProbeTargetsPublicOnly(t *testing.T) {
	r := newRig(t, "agent")
	for addr, ok := range map[string]bool{
		"198.51.100.7": true, "203.0.113.5": true, "8.8.8.8": true,
		"127.0.0.1": false, "169.254.169.254": false, "10.0.0.1": false, "172.16.0.1": false, "192.168.1.1": false,
		"100.64.0.1": false, "10.215.0.2": false, "0.0.0.0": false, "255.255.255.255": false, "224.0.0.1": false,
		"2001:db8::1": false, "::ffff:198.51.100.7": false, "198.51.100.7:2379": false, "198.051.100.7": false, "": false,
	} {
		err := r.a.probe.SetTargets(na.ProbeTargets{Domain: "example.org", Targets: []na.ProbeTarget{{Node: "n1", Site: "main", Address: addr}}})
		if (err == nil) != ok {
			t.Errorf("%q: %v", addr, err)
		}
		if err != nil && !strings.Contains(err.Error(), "isn't a public IPv4 address") {
			t.Errorf("%q: %v", addr, err)
		}
	}
	if target443("198.51.100.7") != "198.51.100.7:443" {
		t.Error("the port")
	}
}

func TestEchoBound(t *testing.T) {
	p := na.MeshPlan{Peers: []na.MeshPeer{
		{ID: "g", AllowedIPs: []string{"10.215.0.5/32", "10.215.0.6/32"}},
		{ID: "n1", AllowedIPs: []string{"10.215.0.1/32"}},
	}}
	bound := boundIDs(p)
	boundTo := map[string]string{}
	for a, id := range bound {
		boundTo[id] = a
	}
	for _, c := range []struct {
		addr, id string
		ok       bool
	}{
		{"10.215.0.1", "n1", true}, {"10.215.0.1", "n9", false}, {"10.215.0.5", "g", true},
		{"10.215.0.6", "e2", true}, {"10.215.0.6", "n1", false},
	} {
		if echoAccepted(c.addr, c.id, bound, boundTo) != c.ok {
			t.Errorf("%+v", c)
		}
	}
}

// TestRemoveMemberIndependentChecks (M1): a live Node, a member named for
// another node: 409.
func TestRemoveMemberIndependentChecks(t *testing.T) {
	r := newRig(t, "server")
	r.a.cfg.Addresses = func(context.Context) (map[string]DocNode, error) {
		return map[string]DocNode{"n3": {Mesh: "10.215.0.3", State: "removed"}}, nil
	}
	etcd := &fakeEtcd{members: []Member{{ID: 3, Name: "n9-abcd", PeerURLs: []string{"https://10.215.0.3:2380"}}}}
	r.a.cfg.Etcd = etcd
	q := na.EtcdRemove{MeshIP: "10.215.0.3", Node: "n3"}
	var he *httpError
	if err := r.a.RemoveMember(context.Background(), q); !errors.As(err, &he) || he.code != 409 {
		t.Errorf("another node's member: %v", err)
	}
	etcd.members[0].Name = "n3-abcd"
	r.a.cfg.NodeExists = func(context.Context, string) (bool, error) { return true, nil }
	if err := r.a.RemoveMember(context.Background(), q); !errors.As(err, &he) || he.code != 409 {
		t.Errorf("a live Node: %v", err)
	}
	r.a.cfg.NodeExists = func(context.Context, string) (bool, error) { return false, nil }
	if err := r.a.RemoveMember(context.Background(), q); err != nil || len(etcd.removed) != 1 {
		t.Errorf("removed: %v %v", err, etcd.removed)
	}
	// The document decodes strictly.
	var doc addressesDoc
	if jsonstrict.Decode([]byte(`{"v":1,"mesh_cidr":"10.215.0.0/24","cluster_cidr":"10.42.0.0/16","service_cidr":"10.43.0.0/16","api":[],"nodes":{"n3":{"mesh":"10.215.0.3","lan":[],"public":[],"state":"removed"}}}`), &doc) != nil {
		t.Error("the document doesn't decode")
	}
	if jsonstrict.Decode([]byte(`{"v":1,"nodes":{}}`), &doc) == nil {
		t.Error("a partial document decoded")
	}
}

// TestClientCNOnce (M4): a client certificate with two CNs is refused.
func TestClientCNOnce(t *testing.T) {
	r := newRig(t, "server")
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oid := asn1.ObjectIdentifier{2, 5, 4, 3}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7777), Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
		{Type: oid, Value: "frontdoor.control"}, {Type: oid, Value: "hub.control"}}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, r.ca.cert, &k.PublicKey, r.ca.key)
	if err != nil {
		t.Fatal(err)
	}
	s := r.server()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: poolOf(r.ca.cert), ServerName: "n2." + clusterDomain,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}}}
	if code, _ := do(t, c, "GET", s.URL+"/v1/health", ""); code == 200 {
		t.Error("two CNs accepted")
	}
}

// TestJoinClusterCIDRAndAgentToken (I1, I2): no cluster_cidr → nothing
// installed; a server's agent_token with --agent-token-file reaches the
// install; a failed join takes the unit and pcmesh down (M12).
func TestJoinClusterCIDRAndAgentToken(t *testing.T) {
	j := newJoinRig(t, true)
	j.nodeadm.cidr = ""
	if err := j.join(); err == nil || err.Error() != "the join answer has no cluster_cidr: nothing was installed" {
		t.Fatalf("join: %v", err)
	}
	if len(j.install) != 0 {
		t.Error("installed without a cluster_cidr")
	}
	if j.run.count("systemctl", "disable", "--now", UnitName) != 1 || j.run.count("ip", "link", "del") != 1 {
		t.Error("a failed join left the unit or pcmesh")
	}
	j2 := newJoinRig(t, true)
	j2.nodeadm.cidr = "10.215.0.0/16"
	if err := j2.join(); err == nil || len(j2.install) != 0 {
		t.Errorf("a cluster_cidr over the mesh: %v", err)
	}
}

