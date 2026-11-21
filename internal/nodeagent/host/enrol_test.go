package host

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	na "github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/pkinode"
	"github.com/portcullis/hub/internal/servers"
)

// fakeNodeadm is nodeadm's public /node paths: the nonce, the enrol
// (proof checked, the CSR signed) and the signed join.
type fakeNodeadm struct {
	t       *testing.T
	ca      *testCA
	secret  []byte
	id      string
	proofOK bool // false: every enrol is 403 proof_invalid
	token   string
	pending int // mesh_pending answers before the material
	cidr    string
	mu      sync.Mutex
	nonces  map[string]bool
	bodies  bytes.Buffer // every request body and header seen
	joins   int
	server  *httptest.Server
	pub     string // the enrolled mesh key
}

func (f *fakeNodeadm) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies.Write(b)
	for k, v := range r.Header {
		f.bodies.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	errJSON := func(code int, msg, kind string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": msg, "kind": kind})
	}
	switch r.URL.Path {
	case "/node/v1/nonce":
		n := make([]byte, 32)
		for i := range n {
			n[i] = byte(i * 7)
		}
		n[0] = byte(len(f.nonces))
		s := base64.RawURLEncoding.EncodeToString(n)
		f.nonces[s] = true
		json.NewEncoder(w).Encode(map[string]string{"nonce": s})
	case "/node/v1/enrol":
		var q struct {
			ServerID string `json:"server_id"`
			Nonce    string `json:"nonce"`
			Proof    string `json:"proof"`
			CSR      string `json:"csr"`
			Mesh     struct {
				Pub string `json:"pub"`
			} `json:"mesh"`
		}
		json.Unmarshal(b, &q)
		nonce, _ := base64.RawURLEncoding.DecodeString(q.Nonce)
		blk, _ := pem.Decode([]byte(q.CSR))
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil || csr.CheckSignature() != nil || !f.nonces[q.Nonce] {
			errJSON(403, "the join code's proof doesn't match", "proof_invalid")
			return
		}
		delete(f.nonces, q.Nonce)
		want := ProofFor(f.secret, nonce, q.ServerID, csr.RawSubjectPublicKeyInfo)
		got, _ := base64.RawURLEncoding.DecodeString(q.Proof)
		if !f.proofOK || !bytes.Equal(got, want) || q.ServerID != f.id {
			errJSON(403, "the join code's proof doesn't match", "proof_invalid")
			return
		}
		f.pub = q.Mesh.Pub
		der := f.ca.sign(f.t, q.ServerID+"."+clusterDomain, csr.PublicKey)
		json.NewEncoder(w).Encode(map[string]any{
			"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"ca":          string(f.ca.pem), "not_after": "2026-11-21T00:00:00Z",
			"mesh": na.MeshPlan{Peers: []na.MeshPeer{{ID: "n1", Pub: peerKey(f.t), Endpoint: ep("203.0.113.1:51830"),
				AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25}}},
		})
	case "/node/v1/join":
		h := r.Header
		der, _ := base64.StdEncoding.DecodeString(h.Get("Portcullis-Node-Cert"))
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			errJSON(403, "unsigned", "")
			return
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: poolOf(f.ca.cert), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			errJSON(403, "unsigned", "")
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(h.Get("Portcullis-Node-Signature"))
		d := sha256.Sum256(CanonicalBytes(f.id, r.Method, r.RequestURI, h.Get("Portcullis-Node-Time"), h.Get("Portcullis-Node-Nonce"), b))
		if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), d[:], sig) {
			errJSON(403, "unsigned", "")
			return
		}
		f.joins++
		if f.joins <= f.pending {
			errJSON(409, "the node mesh isn't ready yet: retry", "mesh_pending")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		srv := "https://10.215.0.1:6443"
		ans := map[string]any{"role": "agent", "server_url": srv, "token": f.token, "cluster_cidr": f.cidr, "flags": []string{
			"--flannel-conf=" + FlannelConf, "--flannel-iface=pcmesh", "--kubelet-arg=address=10.215.0.4", "--kubelet-arg=pod-max-pids=1024",
			"--node-ip=10.215.0.4", UnlabelledTaintFlag,
			"--node-name=n4", "--server=" + srv, "--token-file=" + K3sTokenFile}}
		if f.cidr == "" {
			delete(ans, "cluster_cidr")
		}
		json.NewEncoder(w).Encode(ans)
	default:
		w.WriteHeader(404)
	}
}

type joinRig struct {
	*rig
	nodeadm *fakeNodeadm
	code    string
	secret  string
	out     *logBuf
	install []K3sJoin
}

// newJoinRig is a fresh machine (no state) and a fake nodeadm.
func newJoinRig(t *testing.T, proofOK bool) *joinRig {
	root := t.TempDir()
	ca := newCA(t)
	wg := &fakeWG{}
	run := &fakeRun{wg: wg}
	lb := &logBuf{}
	writeFile(t, root, "/sys/module/wireguard/version", "1.0.0", 0o644)
	writeFile(t, root, "/proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\n", 0o644)
	fn := &fakeNodeadm{t: t, ca: ca, id: "n4", proofOK: proofOK, nonces: map[string]bool{}, pending: 1, cidr: "10.60.0.0/16",
		token: "K10" + caHash + "::abcdef.0123456789abcdef"}
	fn.secret = make([]byte, 32)
	for i := range fn.secret {
		fn.secret[i] = byte(200 - i)
	}
	fn.server = httptest.NewTLSServer(http.HandlerFunc(fn.handler))
	t.Cleanup(fn.server.Close)
	code := servers.JoinCodeV2{V: 2, Kind: "cluster", Endpoint: fn.server.URL + "/node", Servers: []string{"10.215.0.1"},
		ServerID: "n4", Role: "agent", Class: "cloud", Site: "edge", CASHA256: pkinode.DERSHA256(ca.cert.Raw),
		ScriptSHA256: strings.Repeat("a", 64), AgentSHA256: servers.AgentSHA256{AMD64: strings.Repeat("b", 64), ARM64: strings.Repeat("c", 64)},
		MeshIP: "10.215.0.4", Secret: base64.RawURLEncoding.EncodeToString(fn.secret)}
	r := &rig{t: t, root: root, ca: ca, wg: wg, run: run, log: lb}
	r.a = New(Config{Root: root, Version: "0.0.0-test", Run: run, WG: wg, Log: slog.New(slog.NewTextHandler(lb, nil)),
		Interfaces: func() ([]Iface, error) { return []Iface{{Name: "eth0", Addrs: []string{"10.0.0.7/24"}}}, nil },
		FSType:     func(string) (string, error) { return "ext4", nil }, Exit: func() {}})
	return &joinRig{rig: r, nodeadm: fn, code: code.EncodeV2(), secret: code.Secret, out: &logBuf{}}
}

func (j *joinRig) join() error {
	return j.a.Join(context.Background(), strings.NewReader(j.code+"\n"), j.out, JoinDeps{
		HTTP:    j.nodeadm.server.Client(),
		Install: func(_ context.Context, k K3sJoin) error { j.install = append(j.install, k); return nil },
		RTT:     func(context.Context, []string) map[string]int { return map[string]int{"n1": 12} },
		Retry:   time.Millisecond,
	})
}

// TestJoinRefusesBadProof: nodeadm answers proof_invalid → "the join code
// was refused", k3s never installed, nothing started.
func TestJoinRefusesBadProof(t *testing.T) {
	j := newJoinRig(t, false)
	err := j.join()
	if !errors.Is(err, ErrCodeRefused) || err.Error() != "the join code was refused" {
		t.Fatalf("join: %v", err)
	}
	if len(j.install) != 0 || j.run.count("systemctl", "enable") != 0 || j.run.count("sh") != 0 {
		t.Error("something was installed or started")
	}
	if _, err := os.Stat(filepath.Join(j.root, stateFile)); err == nil {
		t.Error("a state was written")
	}
	// The binary's exit status: 1 with that text (cmd/portcullis-nodeagent
	// prints "nodeagent join: " + the error).
}

// TestJoinCAMismatch: the enrol answer's CA isn't ca_sha256 → abort,
// nothing installed.
func TestJoinCAMismatch(t *testing.T) {
	j := newJoinRig(t, true)
	c, _ := servers.DecodeJoinCodeV2(j.code)
	c.CASHA256 = strings.Repeat("d", 64)
	j.code = c.EncodeV2()
	if err := j.join(); !errors.Is(err, ErrCAMismatch) {
		t.Fatalf("join: %v", err)
	}
	if len(j.install) != 0 || j.run.count("systemctl", "enable") != 0 {
		t.Error("something was installed")
	}
}

// TestJoinNeverLogsSecrets: a whole join (one mesh_pending retry); its
// output, its log and every request to nodeadm hold neither the code's
// secret nor the k3s token nor a private key; the token reaches k3s's
// install only; the bootstrap plan and the unit are in place.
func TestJoinNeverLogsSecrets(t *testing.T) {
	j := newJoinRig(t, true)
	if err := j.join(); err != nil {
		t.Fatalf("join: %v\n%s", err, j.out.String())
	}
	if len(j.install) != 1 || string(j.install[0].Token) != j.nodeadm.token || j.install[0].Role != "agent" || j.nodeadm.joins != 2 ||
		j.install[0].ClusterCIDR != "10.60.0.0/16" || j.install[0].AgentToken != "" {
		t.Fatalf("install %+v, joins %d", j.install, j.nodeadm.joins)
	}
	meshPriv := strings.TrimSpace(string(must(os.ReadFile(filepath.Join(j.root, MeshKeyFile)))))
	k, err := wgtypes.ParseKey(meshPriv)
	if err != nil || k.PublicKey().String() != j.nodeadm.pub {
		t.Error("the enrolled mesh key isn't the node's")
	}
	nodeKey := string(must(os.ReadFile(filepath.Join(j.root, nodePEMFile))))
	keyBody := strings.Split(nodeKey, "\n")[1]
	if !strings.HasPrefix(nodeKey, "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("node.pem doesn't start with the key")
	}
	secretHex := hex.EncodeToString(j.nodeadm.secret)
	keySHA := sha256.Sum256(j.nodeadm.secret)
	leaks := map[string]string{"the code's secret": j.secret, "the secret (hex)": secretHex, "the secret's sha256": hex.EncodeToString(keySHA[:]),
		"the code": j.code[5:60], "the k3s token": "0123456789abcdef", "the mesh private key": meshPriv, "the node key": keyBody}
	for where, s := range map[string]string{"output": j.out.String(), "log": j.log.String(), "requests": j.nodeadm.bodies.String()} {
		for what, l := range leaks {
			if strings.Contains(s, l) {
				t.Errorf("the %s holds %s", where, what)
			}
		}
	}
	for _, c := range j.run.cmds {
		line := c.Name + " " + strings.Join(c.Args, " ") + " " + strings.Join(c.Env, " ") + " " + string(c.Stdin)
		for what, l := range leaks {
			if strings.Contains(line, l) {
				t.Errorf("a command holds %s: %s", what, c.Name)
			}
		}
	}
	for _, f := range []string{nodePEMFile, MeshKeyFile, stateFile, caFile} {
		fi, err := os.Stat(filepath.Join(j.root, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, err, fi)
		}
	}
	if fi, _ := os.Stat(filepath.Join(j.root, StateDir)); fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir %v", fi.Mode())
	}
	d, _ := j.wg.Device("pcmesh")
	if len(d.Peers) != 1 || d.ListenPort != 51830 {
		t.Errorf("pcmesh %+v", d)
	}
	if j.run.count("systemctl", "enable", "--now", UnitName) != 1 {
		t.Error("the nodeagent unit wasn't started")
	}
	// The API answers and errors on the joined node hold no secret either.
	j.a.cfg.Supervisor = &fakeSup{err: errors.New("the k3s supervisor answered 401 to the token rotation")}
	s := j.server()
	c := j.client(j.ca, na.CNNodeadm)
	var answers bytes.Buffer
	for _, body := range []string{
		`{"new_token":"K10` + caHash + `::node:0123456789abcdef","step":"apply"}`,
		`{"new_token":"K10` + caHash + `::server:0123456789abcdef","step":"apply"}`,
		`{"new_token":"0123456789abcdef","step":"apply"}`,
		`{"new_token":"K10` + caHash + `::node:0123456789abcdef","step":"apply","x":"0123456789abcdef"}`,
		`{"new_token":"K10` + caHash + `::node:0123456789abcdef"}`,
	} {
		_, out := do(t, c, "POST", s.URL+"/v1/k3s/token-rotate", body)
		answers.WriteString(out)
	}
	_, out := do(t, j.client(j.ca, na.CNHub), "GET", s.URL+"/v1/health", "")
	answers.WriteString(out)
	_, out = do(t, j.client(j.ca, na.CNHub), "GET", s.URL+"/v1/checks", "")
	answers.WriteString(out)
	for what, l := range leaks {
		if strings.Contains(answers.String(), l) || strings.Contains(j.log.String(), l) {
			t.Errorf("an answer or the log holds %s", what)
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// TestJoinFlagsRefused: a token on argv or another node's identity in the
// join answer's flags is refused.
func TestJoinFlagsRefused(t *testing.T) {
	st := State{ID: "n4", MeshIP: "10.215.0.4", Role: "server"}
	srv := "https://10.215.0.1:6443"
	ok := []string{"--server=" + srv, "--token-file=" + K3sTokenFile, "--node-ip=10.215.0.4", "--node-name=n4",
		UnlabelledTaintFlag, NoForceDetachFlag, "--etcd-arg=listen-client-urls=https://10.215.0.4:2379,https://127.0.0.1:2379"}
	if err := checkFlags(ok, srv, st, "10.42.0.0/16"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"--token=K10abc::server:x", "--agent-token=x", "--token-file=/tmp/t", "--node-name=n5",
		"--node-ip=10.215.0.5", "--server=https://10.215.0.9:6443", "--data-dir=/", "--kubelet-arg=x y", "-t", "--node-label=$(id)",
		"--write-kubeconfig-mode=0644", "--kube-apiserver-arg=anonymous-auth=true", "--kubelet-arg=read-only-port=10255", "--config=/tmp/c",
		"--node-label=portcullis.io/class=huge", "--node-ip=10.215.0.4",
		// R-NODELABELS: no placement label or portcullis.io/ taint from the join.
		"--node-label=portcullis.io/class=home", "--node-label=portcullis.io/site=main", "--node-label=topology.kubernetes.io/zone=main",
		"--node-label=portcullis.io/ingress=true", "--node-label=portcullis.io/storage=true", "--node-taint=portcullis.io/small=true:NoSchedule",
		// Near-misses of the two core 49b5697 flags.
		"--node-taint=nodeadm.portcullis/unlabelled=true:NoExecute", "--node-taint=nodeadm.portcullis/unlabelled=false:NoSchedule",
		"--node-taint=nodeadm.portcullis/unlabelled:NoSchedule", "--node-taint=nodeadm.portcullis/unlabeled=true:NoSchedule",
		"--node-taint=nodeadm.portcullis/unlabelled=true:NoSchedule,x", "--kube-controller-manager-arg=disable-force-detach-on-timeout=false",
		"--kube-controller-manager-arg=disable-force-detach-on-timeout", "--kube-controller-manager-arg=disable-force-detach-on-timeout=true,x=y",
		"--kube-controller-manager-arg=terminated-pod-gc-threshold=1", "--kube-apiserver-arg=disable-force-detach-on-timeout=true"} {
		err := checkFlags(append(append([]string{}, ok...), bad), srv, st, "10.42.0.0/16")
		if err == nil {
			t.Errorf("accepted %q", bad)
		} else if _, v, cut := strings.Cut(bad, "="); cut && len(v) > 3 && strings.Contains(err.Error(), v) {
			t.Errorf("the refusal echoes the value: %v", err)
		}
	}
	// --cluster-cidr: the answer's cluster_cidr only, on a server only.
	if err := checkFlags(append(append([]string{}, ok...), "--cluster-cidr=10.42.0.0/16"), srv, st, "10.42.0.0/16"); err != nil {
		t.Errorf("--cluster-cidr: %v", err)
	}
	if checkFlags(append(append([]string{}, ok...), "--cluster-cidr=10.99.0.0/16"), srv, st, "10.42.0.0/16") == nil {
		t.Error("another --cluster-cidr accepted")
	}
	if checkFlags([]string{"--server=" + srv, "--token-file=" + K3sTokenFile, "--node-ip=10.215.0.4", "--node-name=n4", UnlabelledTaintFlag, "--cluster-cidr=10.42.0.0/16"}, srv,
		State{ID: "n4", MeshIP: "10.215.0.4", Role: "agent"}, "10.42.0.0/16") == nil {
		t.Error("an agent took --cluster-cidr")
	}
	// An agent doesn't take a server's flags (the force-detach one included);
	// it does take the registration taint, which every join must carry.
	agent := State{ID: "n4", MeshIP: "10.215.0.4", Role: "agent"}
	agentOK := []string{"--server=" + srv, "--token-file=" + K3sTokenFile, "--node-ip=10.215.0.4", "--node-name=n4", UnlabelledTaintFlag}
	if err := checkFlags(agentOK, srv, agent, "10.42.0.0/16"); err != nil {
		t.Errorf("an agent's flags: %v", err)
	}
	for _, f := range []string{"--secrets-encryption", NoForceDetachFlag} {
		if checkFlags(append(append([]string{}, agentOK...), f), srv, agent, "10.42.0.0/16") == nil {
			t.Errorf("an agent took %s", f)
		}
	}
	if err := checkFlags(agentOK[:4], srv, agent, "10.42.0.0/16"); err == nil || !strings.Contains(err.Error(), "--node-taint") {
		t.Errorf("a join without the registration taint: %v", err)
	}
	for _, u := range []string{"http://10.215.0.1:6443", "https://198.51.100.1:6443", "https://10.215.0.1:6444", "https://10.215.0.1:6443/x"} {
		if checkServerURL(u, nil) == nil {
			t.Errorf("server_url %q accepted", u)
		}
	}
}

// TestInstallK3s: the pinned downloads checked, the token only in its
// 0600 file, `sh install.sh agent <flags>` with paths in the environment.
func TestInstallK3s(t *testing.T) {
	r := newRig(t, "agent")
	script, bin := []byte("#!/bin/sh\necho install\n"), []byte("k3s binary")
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/install.sh":
			w.Write(script)
		case "/rel/k3s", "/rel/k3s-arm64":
			w.Write(bin)
		}
	}))
	defer srv.Close()
	old := k3sPins
	t.Cleanup(func() { k3sPins = old })
	k3sPins.scriptURL, k3sPins.scriptSHA256, k3sPins.releaseBase = srv.URL+"/install.sh", sum(script), srv.URL+"/rel/"
	k3sPins.sha256 = map[string]string{"amd64": sum(bin), "arm64": sum(bin)}
	tok := secret("K10" + caHash + "::abcdef.0123456789abcdef")
	j := K3sJoin{Role: "agent", ServerURL: "https://10.215.0.1:6443", Token: tok, ClusterCIDR: "10.60.0.0/16",
		Flags: []string{"--server=https://10.215.0.1:6443", "--token-file=" + K3sTokenFile}}
	var out bytes.Buffer
	if err := r.a.installK3s(context.Background(), srv.Client(), &out, j); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(r.root, K3sTokenFile)); strings.TrimSpace(string(b)) != string(tok) {
		t.Error("the token file")
	}
	if fi, _ := os.Stat(filepath.Join(r.root, K3sTokenFile)); fi.Mode().Perm() != 0o600 {
		t.Error("the token file's mode")
	}
	if b, _ := os.ReadFile(filepath.Join(r.root, FlannelConf)); string(b) != `{"Network":"10.60.0.0/16","EnableIPv4":true,"EnableIPv6":false,"Backend":{"Type":"wireguard","ListenPort":51840,"PersistentKeepaliveInterval":25,"Mode":"separate"}}`+"\n" {
		t.Errorf("flannel conf %s", b)
	}
	var sh *Cmd
	for i, c := range r.run.cmds {
		if c.Name == "sh" {
			sh = &r.run.cmds[i]
		}
	}
	if sh == nil || sh.Args[1] != "agent" || sh.Args[2] != "--server=https://10.215.0.1:6443" {
		t.Fatalf("install run %+v", sh)
	}
	if strings.Contains(strings.Join(append(sh.Args, sh.Env...), " "), "0123456789abcdef") {
		t.Error("the token on argv or in the environment")
	}
	// A server's agent token: its 0600 file.
	rs := newRig(t, "server")
	js := j
	js.Role, js.AgentToken = "server", secret("K10"+caHash+"::node:agentpass0123")
	if err := rs.a.installK3s(context.Background(), srv.Client(), &out, js); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(rs.root, K3sAgentToken)); strings.TrimSpace(string(b)) != string(js.AgentToken) {
		t.Error("the agent token file")
	}
	if fi, _ := os.Stat(filepath.Join(rs.root, K3sAgentToken)); fi.Mode().Perm() != 0o600 {
		t.Error("the agent token file's mode")
	}
	for _, c := range rs.run.cmds {
		if strings.Contains(strings.Join(append(c.Args, c.Env...), " "), "agentpass") {
			t.Error("the agent token on argv or in the environment")
		}
	}
	// A wrong sha256: nothing installed.
	k3sPins.sha256 = map[string]string{"amd64": strings.Repeat("0", 64), "arm64": strings.Repeat("0", 64)}
	r2 := newRig(t, "agent")
	err := r2.a.installK3s(context.Background(), srv.Client(), &out, j)
	if err == nil || !strings.Contains(err.Error(), "doesn't match its pinned sha256") {
		t.Errorf("a wrong binary: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r2.root, K3sTokenFile)); err == nil {
		t.Error("the token was written before the downloads were checked")
	}
}

// TestJoinFlagsCoreFixture: every server flag of core's shared fixture
// (tests/fixtures/k3s-server-flags.txt, which nodeadm's join answer
// follows) passes, with the join's substitutions (no --cluster-init, the
// answer's --server).
func TestJoinFlagsCoreFixture(t *testing.T) {
	core, set := os.LookupEnv("PORTCULLIS_CORE_DIR")
	if !set {
		core = filepath.Join("..", "..", "..", "..", "portcullis")
	}
	b, err := os.ReadFile(filepath.Join(core, "tests", "fixtures", "k3s-server-flags.txt"))
	if err != nil {
		if set {
			t.Fatalf("PORTCULLIS_CORE_DIR is set but the fixture isn't readable: %v", err)
		}
		t.Skipf("no core checkout: %v", err)
	}
	srv := "https://10.215.0.2:6443"
	flags := []string{"--server=" + srv}
	cidr := ""
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "--cluster-init" {
			continue
		}
		if v, ok := strings.CutPrefix(l, "--cluster-cidr="); ok {
			cidr = v
		}
		flags = append(flags, l)
	}
	if err := checkFlags(flags, srv, State{ID: "node-1", MeshIP: "10.215.0.1", Role: "server"}, cidr); err != nil {
		t.Errorf("core's server flags: %v", err)
	}
}
