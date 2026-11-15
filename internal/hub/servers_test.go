package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/linkdoc"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/version"
	"github.com/portcullis/hub/internal/vpn"
)

// ── a test pki_node CA (enroll's /internal/nodes/sign|revoke) ─────────

type testNodeCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  string

	mu        sync.Mutex
	revokeErr error
	revoked   []string
	// onRevoke runs at every revoke attempt (before its outcome);
	// onSign at every sign, before it answers.
	onRevoke func(serial string)
	onSign   func(role string)
	signs    []string // role:cn
	issued   []string // the serials signed
}

func newTestNodeCA(t *testing.T) *testNodeCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org Node CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testNodeCA{key: k, cert: c, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func colonHex(n *big.Int) string {
	b := n.Bytes()
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func (c *testNodeCA) SignNode(_ context.Context, role, cn, csrPEM string) (*NodeCert, error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil {
		return nil, errors.New("no CSR")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != cn || len(csr.DNSNames) != 0 {
		return nil, errors.New("bad CSR")
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-30 * time.Second),
		NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	switch role {
	case RoleNodeWorker:
		tpl.DNSNames = []string{cn}
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case RoleNodeControl:
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, errors.New("role refused")
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.signs = append(c.signs, role+":"+cn)
	c.issued = append(c.issued, colonHex(serial))
	hook := c.onSign
	c.mu.Unlock()
	if hook != nil {
		hook(role)
	}
	return &NodeCert{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Serial: colonHex(serial),
		CA: c.pem, NotAfter: tpl.NotAfter}, nil
}

func (c *testNodeCA) RevokeNode(_ context.Context, serial string) error {
	c.mu.Lock()
	hook, err := c.onRevoke, c.revokeErr
	c.mu.Unlock()
	if hook != nil {
		hook(serial)
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.revoked = append(c.revoked, serial)
	c.mu.Unlock()
	return nil
}

// ── link's status.json ───────────────────────────────────────────────

const testLinkPub = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="

type fakeLink struct {
	t     *testing.T
	path  string
	mu    sync.Mutex
	peers map[string]time.Time
	off   bool
}

func (l *fakeLink) write() {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := vpn.Status{Version: vpn.StatusVersion, Written: time.Now().UTC(), Mode: "apps", Edge: vpn.RoleStatus{OK: true}}
	if !l.off {
		st.Link = &vpn.LinkState{OK: true, PublicKey: testLinkPub, Port: 51821, Peers: []vpn.LinkPeer{}}
		for id, at := range l.peers {
			a := at.UTC()
			st.Link.Peers = append(st.Link.Peers, vpn.LinkPeer{ID: id, IP: "10.214.0.10", Handshake: &a})
		}
	}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(l.path+".tmp", b, 0o600); err != nil {
		l.t.Error(err)
		return
	}
	os.Rename(l.path+".tmp", l.path)
}

func (l *fakeLink) handshake(id string, at time.Time) {
	l.mu.Lock()
	l.peers[id] = at
	l.mu.Unlock()
	l.write()
}

// ── a fake agent (the enrolment side of internal/agent) ─────────────

type fakeAgent struct {
	t      *testing.T
	ca     *testNodeCA
	ln     net.Listener
	srv    *http.Server
	onWG   func()
	mu     sync.Mutex
	id     string
	secret []byte
	skew   time.Duration
	// enrolling cert (self-signed) and, once PUT, the node cert.
	enrolKey  *ecdsa.PrivateKey
	enrolCert *x509.Certificate
	node      *tls.Certificate
	pending   *ecdsa.PrivateKey
	nonce     []byte
	wgPub     string
	network   *agentapi.NetworkParams
	calls     []string
	left      bool
	failCert  bool   // PUT /v1/identity/cert answers 400
	onCert    func() // runs at PUT /v1/identity/cert, before it answers
	onLeave   func() // runs at POST /v1/leave
}

func newFakeAgent(t *testing.T, ca *testNodeCA) *fakeAgent {
	t.Helper()
	a := &fakeAgent{t: t, ca: ca}
	a.enrolKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "enrolling"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &a.enrolKey.PublicKey, a.enrolKey)
	a.enrolCert, _ = x509.ParseCertificate(der)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", a.info)
	mux.HandleFunc("GET /v1/enrol/nonce", a.nonceH)
	mux.HandleFunc("POST /v1/enrol", a.enrol)
	mux.HandleFunc("PUT /v1/identity/cert", a.cert)
	mux.HandleFunc("PUT /v1/network", a.net)
	mux.HandleFunc("PUT /v1/identity/wg", a.wg)
	mux.HandleFunc("POST /v1/identity/csr", a.csr)
	mux.HandleFunc("POST /v1/leave", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.left = true
		hook := a.onLeave
		a.mu.Unlock()
		if hook != nil {
			hook()
		}
		w.WriteHeader(204)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a.ln = ln
	tcfg := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.node != nil {
				return a.node, nil
			}
			return &tls.Certificate{Certificate: [][]byte{a.enrolCert.Raw}, PrivateKey: a.enrolKey}, nil
		},
		// The Hub sends [hub.control, pki_node CA]: the CA must be ours.
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) < 1 {
				return errors.New("no client cert")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil || leaf.Subject.CommonName != ControlCN || leaf.CheckSignatureFrom(ca.cert) != nil {
				return errors.New("not hub.control under the pinned CA")
			}
			if len(raw) >= 2 && !bytes.Equal(raw[len(raw)-1], ca.cert.Raw) {
				return errors.New("another CA in the chain")
			}
			return nil
		}}
	a.srv = &http.Server{Handler: mux, TLSConfig: tcfg, ErrorLog: log.New(ioDiscard{}, "", 0)}
	go a.srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { a.srv.Close() })
	return a
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func (a *fakeAgent) call(c string) {
	a.mu.Lock()
	a.calls = append(a.calls, c)
	a.mu.Unlock()
}

func (a *fakeAgent) Calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

func writeAgentJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (a *fakeAgent) info(w http.ResponseWriter, r *http.Request) {
	a.call("info")
	a.mu.Lock()
	skew := a.skew
	a.mu.Unlock()
	writeAgentJSON(w, 200, agentapi.Info{AgentVersion: version.Version, API: "v1", Runtime: "docker", Arch: "amd64", CPUs: 4, MemBytes: 8 << 30,
		DataDir: "/srv/worker-data", Clock: time.Now().Add(skew).UTC()})
}

func (a *fakeAgent) nonceH(w http.ResponseWriter, r *http.Request) {
	a.call("nonce")
	n := make([]byte, servers.NonceLen)
	rand.Read(n)
	a.mu.Lock()
	a.nonce = n
	a.mu.Unlock()
	writeAgentJSON(w, 200, agentapi.EnrolNonce{Nonce: n})
}

func (a *fakeAgent) newCSR(cn string) (string, error) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return "", err
	}
	a.pending = k
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func (a *fakeAgent) enrol(w http.ResponseWriter, r *http.Request) {
	a.call("enrol")
	var req agentapi.EnrolProof
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil {
		writeAgentJSON(w, 400, agentapi.Error{Error: err.Error()})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	spki := sha256.Sum256(a.enrolCert.RawSubjectPublicKeyInfo)
	nonce := a.nonce
	a.nonce = nil
	if nonce == nil || !servers.VerifyProof(a.secret, nonce, a.id, spki[:], req.Proof) {
		writeAgentJSON(w, 403, agentapi.Error{Error: "enrolment proof refused"})
		return
	}
	csr, err := a.newCSR(req.CSRCN)
	if err != nil {
		writeAgentJSON(w, 500, agentapi.Error{Error: "csr"})
		return
	}
	_, pub, _ := servers.NewWGKeyPair()
	a.wgPub = pub
	writeAgentJSON(w, 200, agentapi.IdentityCSR{CSR: csr, WGPublicKey: pub})
}

func (a *fakeAgent) cert(w http.ResponseWriter, r *http.Request) {
	a.call("cert")
	a.mu.Lock()
	hook := a.onCert
	a.mu.Unlock()
	if hook != nil {
		hook()
	}
	var req agentapi.IdentityCert
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil {
		writeAgentJSON(w, 400, agentapi.Error{Error: err.Error()})
		return
	}
	blk, _ := pem.Decode([]byte(req.Certificate))
	c, err := x509.ParseCertificate(blk.Bytes)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failCert {
		writeAgentJSON(w, 400, agentapi.Error{Error: "no"})
		return
	}
	if err != nil || req.CA != a.ca.pem || a.pending == nil || !c.PublicKey.(*ecdsa.PublicKey).Equal(&a.pending.PublicKey) {
		writeAgentJSON(w, 400, agentapi.Error{Error: "certificate refused"})
		return
	}
	a.node = &tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: a.pending, Leaf: c}
	a.pending = nil
	w.WriteHeader(204)
}

func (a *fakeAgent) net(w http.ResponseWriter, r *http.Request) {
	a.call("network")
	var req agentapi.NetworkParams
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil {
		writeAgentJSON(w, 400, agentapi.Error{Error: err.Error()})
		return
	}
	a.mu.Lock()
	a.network = &req
	a.mu.Unlock()
	w.WriteHeader(204)
}

func (a *fakeAgent) wg(w http.ResponseWriter, r *http.Request) {
	a.call("wg")
	var req agentapi.IdentityWG
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil || req.LinkPub != testLinkPub {
		writeAgentJSON(w, 400, agentapi.Error{Error: "link_pub"})
		return
	}
	writeAgentJSON(w, 200, map[string]string{})
	if a.onWG != nil {
		go a.onWG()
	}
}

func (a *fakeAgent) csr(w http.ResponseWriter, r *http.Request) {
	a.call("csr")
	a.mu.Lock()
	defer a.mu.Unlock()
	csr, err := a.newCSR(servers.NodeName(a.id))
	if err != nil {
		writeAgentJSON(w, 500, agentapi.Error{Error: "csr"})
		return
	}
	writeAgentJSON(w, 200, agentapi.IdentityCSR{CSR: csr, WGPublicKey: a.wgPub})
}

// takeCode gives the agent what a worker join would: the join code.
func (a *fakeAgent) takeCode(t *testing.T, code string) servers.JoinCode {
	t.Helper()
	jc, err := servers.DecodeJoinCode(code)
	if err != nil {
		t.Fatalf("join code: %v", err)
	}
	a.mu.Lock()
	a.id, a.secret = jc.ServerID, jc.SecretBytes()
	a.mu.Unlock()
	return jc
}

type dialTo string

func (d dialTo) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", string(d))
}

// ── the fixture ──────────────────────────────────────────────────────

type serversFixture struct {
	*fixture
	ca    *testNodeCA
	link  *fakeLink
	agent *fakeAgent
	audit *fakeAudit
	clock *offsetClock
}

// offsetClock is the Hub's servers clock: real time plus an offset.
type offsetClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *offsetClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *offsetClock) add(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

var admin = directory.Actor{User: "alice"}

func newServersFixture(t *testing.T) *serversFixture {
	t.Helper()
	f := newFixture(t)
	sf := &serversFixture{fixture: f, ca: newTestNodeCA(t), audit: &fakeAudit{}, clock: &offsetClock{}}
	dir := t.TempDir()
	sf.link = &fakeLink{t: t, path: filepath.Join(dir, "status.json"), peers: map[string]time.Time{}}
	sf.link.write()
	f.h.cfg.LinkDocDir = filepath.Join(dir, "link-doc")
	os.MkdirAll(f.h.cfg.LinkDocDir, 0o750)
	f.h.cfg.LinkDocGID = os.Getgid()
	f.h.cfg.VPNStatusFile = sf.link.path
	f.h.cfg.RelayImage = "ghcr.io/porelli/portcullis-relay:edge"
	f.h.SetNodeSigner(sf.ca)
	f.h.SetAudit(sf.audit)
	sf.agent = newFakeAgent(t, sf.ca)
	f.h.srvT = serverTimings{now: sf.clock.now, enrolPoll: 5 * time.Millisecond, infoWait: time.Second, swapWait: 400 * time.Millisecond,
		callWait: 3 * time.Second, dial: dialTo(sf.agent.ln.Addr().String())}
	// The worker's handshake on its new key, a moment after the switch.
	sf.agent.onWG = func() { sf.link.handshake(sf.agent.id, time.Now().Add(3*time.Second)) }
	return sf
}

func (sf *serversFixture) linkDoc(t *testing.T) *linkdoc.Doc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(sf.h.cfg.LinkDocDir, linkdoc.FileName))
	if err != nil {
		t.Fatalf("link.json: %v", err)
	}
	d, err := linkdoc.Parse(b)
	if err != nil {
		t.Fatalf("link.json: %v", err)
	}
	return d
}

func (sf *serversFixture) server(id string) (state.Server, bool) {
	sf.h.mu.RLock()
	defer sf.h.mu.RUnlock()
	s, ok := sf.h.st.Servers[id]
	return s, ok
}

// owed lists the owed serials as server:serial.
func (sf *serversFixture) owed() []string {
	sf.h.mu.RLock()
	defer sf.h.mu.RUnlock()
	var out []string
	for _, o := range sf.h.st.OwedSerials {
		out = append(out, o.Server+":"+o.Serial)
	}
	return out
}

func (sf *serversFixture) actions() []string {
	sf.audit.mu.Lock()
	defer sf.audit.mu.Unlock()
	var out []string
	for _, e := range sf.audit.entries {
		out = append(out, e.Action+":"+e.Result)
	}
	return out
}

func waitServerOp(t *testing.T, h *Hub, key string) OpRecord {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if r := h.LastOp(key); r != nil && !r.Running {
			return *r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("op %s still running", key)
	return OpRecord{}
}

// enrol adds server id and lets the fake worker join.
func (sf *serversFixture) enrol(t *testing.T, id string) servers.JoinCode {
	t.Helper()
	code, _, err := sf.h.AddServer(context.Background(), admin, id, strings.ToUpper(id))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	jc := sf.agent.takeCode(t, code)
	sf.link.handshake(id, time.Now().Add(time.Second))
	if r := waitServerOp(t, sf.h, serverOpKey(id)); !r.OK {
		t.Fatalf("enrolment failed: %s", r.Error)
	}
	return jc
}

// place puts instance id on server.
func (sf *serversFixture) place(id, server string) {
	sf.h.mu.Lock()
	in := sf.h.st.Instances[id]
	in.ID, in.Template, in.Server = id, id, server
	sf.h.st.Instances[id] = in
	sf.h.noteServersLocked()
	sf.h.mu.Unlock()
}

// ── tests ─────────────────────────────────────────────────────────────

// TestAddServerCodeShownOnce: the code is returned once; its secret and
// bootstrap key are in no state field, op record, log line, audit entry
// or link.json (only the secret's sha256 and the bootstrap public key).
func TestAddServerCodeShownOnce(t *testing.T) {
	sf := newServersFixture(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	code, exp, err := sf.h.AddServer(context.Background(), admin, "nas", "NAS")
	if err != nil {
		t.Fatal(err)
	}
	jc, err := servers.DecodeJoinCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 14*time.Minute || d > 15*time.Minute+time.Second {
		t.Errorf("expires in %s", d)
	}
	sum := sha256.Sum256(sf.ca.cert.Raw)
	if jc.CASHA256 != hex.EncodeToString(sum[:]) || jc.Endpoint != "example.org:51821" || jc.LinkPub != testLinkPub ||
		jc.ServerID != "nas" || jc.TunnelIP.String() != "10.214.0.10" {
		t.Errorf("code %v ca %s endpoint %s", jc, jc.CASHA256, jc.Endpoint)
	}
	s, _ := sf.server("nas")
	ssum := sha256.Sum256(jc.SecretBytes())
	if s.State != ServerEnrolling || s.Enrol == nil || s.Enrol.SecretSHA256 != hex.EncodeToString(ssum[:]) || s.Enrol.Used {
		t.Errorf("state %+v", s)
	}
	d := sf.linkDoc(t)
	if len(d.Peers) != 1 || d.Peers[0].State != linkdoc.StateEnrolling || d.Peers[0].PublicKey != s.Enrol.BootstrapPub {
		t.Errorf("link.json %+v", d.Peers)
	}
	// Let the op record exist, then look everywhere.
	time.Sleep(20 * time.Millisecond)
	stateB, _ := os.ReadFile(filepath.Join(sf.data, "state.yaml"))
	opB, _ := os.ReadFile(filepath.Join(sf.data, "ops", "_server.nas.json"))
	linkB, _ := os.ReadFile(filepath.Join(sf.h.cfg.LinkDocDir, linkdoc.FileName))
	sf.audit.mu.Lock()
	auditB, _ := json.Marshal(sf.audit.entries)
	sf.audit.mu.Unlock()
	if len(opB) == 0 {
		t.Error("no op record")
	}
	for name, hay := range map[string]string{"state": string(stateB), "op": string(opB), "link": string(linkB), "audit": string(auditB), "log": logs.String()} {
		for what, needle := range map[string]string{"code": code, "secret": jc.Secret, "bootstrap key": jc.BootstrapKey} {
			if strings.Contains(hay, needle) {
				t.Errorf("the %s is in the %s", what, name)
			}
		}
	}
	if a := sf.actions(); len(a) != 1 || a[0] != "server.add:ok" {
		t.Errorf("audit %v", a)
	}
	// A second add of the same id: 409, nothing changed.
	if _, _, err := sf.h.AddServer(context.Background(), admin, "nas", ""); errStatus(err) != 409 {
		t.Errorf("again: %v", err)
	}
	for _, id := range []string{"primary", "Nas", "a-", ""} {
		if _, _, err := sf.h.AddServer(context.Background(), admin, id, ""); errStatus(err) != 400 {
			t.Errorf("%q: %v", id, err)
		}
	}
	if _, _, err := sf.h.AddServer(context.Background(), directory.Actor{}, "pi", ""); errStatus(err) != 401 {
		t.Errorf("no actor: %v", err)
	}
	sf.h.StopServerEnrol("nas", admin, "")
	waitServerOp(t, sf.h, serverOpKey("nas"))
}

// TestEnrolHappyPath: join → handshake → verify against a fake agent:
// the P6 order, the pins, the new key in link.json, ready, audited.
func TestEnrolHappyPath(t *testing.T) {
	sf := newServersFixture(t)
	jc := sf.enrol(t, "nas")
	if got, want := strings.Join(sf.agent.Calls(), ","), "info,nonce,enrol,cert,network,wg"; !strings.HasPrefix(got, want) {
		t.Errorf("calls %s, want %s", got, want)
	}
	s, _ := sf.server("nas")
	sf.agent.mu.Lock()
	node, wgPub, nw := sf.agent.node, sf.agent.wgPub, sf.agent.network
	sf.agent.mu.Unlock()
	spki := sha256.Sum256(node.Leaf.RawSubjectPublicKeyInfo)
	if s.State != ServerReady || s.Enrol != nil || s.SPKI != hex.EncodeToString(spki[:]) || s.CertSerial != colonHex(node.Leaf.SerialNumber) ||
		s.WGPublicKey != wgPub || s.CertNotAfter.IsZero() || s.AgentVersion != version.Version {
		t.Errorf("state %+v", s)
	}
	if nw == nil || nw.ProxySubnet.String() != defaultProxySubnet || nw.ProxyIPRange.String() != defaultProxyIPRange || nw.TraefikIP.String() != defaultTraefikIP {
		t.Errorf("network %+v", nw)
	}
	d := sf.linkDoc(t)
	if len(d.Peers) != 1 || d.Peers[0].State != linkdoc.StateReady || d.Peers[0].PublicKey != wgPub || d.Peers[0].IP != jc.TunnelIP {
		t.Errorf("link.json %+v", d.Peers)
	}
	if sf.ca.signs[len(sf.ca.signs)-1] != RoleNodeWorker+":nas.node.portcullis.internal" {
		t.Errorf("signs %v", sf.ca.signs)
	}
	if a := sf.actions(); strings.Join(a, " ") != "server.add:ok server.enrolled:ok" {
		t.Errorf("audit %v", a)
	}
	// Placed instances reach the worker through the pinned backend.
	sf.place("grafana", "nas")
	rt, err := sf.h.rtFor("grafana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Info(context.Background()); err != nil {
		t.Errorf("info through the pinned backend: %v", err)
	}
	var v ServerView
	for _, x := range sf.h.Servers(context.Background()) {
		if x.ID == "nas" {
			v = x
		}
	}
	if v.State != ServerReady || v.Name != "NAS" || v.Arch != "amd64" || len(v.Instances) != 1 {
		t.Errorf("view %+v", v)
	}
	if r := sf.h.LastOp(serverOpKey("nas")); r == nil || len(r.Steps) != 3 || r.Steps[2].State != StepDone {
		t.Errorf("op %+v", r)
	}
}

// TestEnrolRefusals: an expired code, a used code, a wrong proof →
// server.enrol_refused and the bootstrap peer gone (before the handshake
// nothing is left; after it the server is revoked).
func TestEnrolRefusals(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		sf := newServersFixture(t)
		if _, _, err := sf.h.AddServer(context.Background(), admin, "nas", ""); err != nil {
			t.Fatal(err)
		}
		sf.clock.add(16 * time.Minute)
		r := waitServerOp(t, sf.h, serverOpKey("nas"))
		if r.OK || !strings.Contains(r.Error, "expired") {
			t.Errorf("op %+v", r)
		}
		if _, ok := sf.server("nas"); ok {
			t.Error("the server is still listed")
		}
		if d := sf.linkDoc(t); len(d.Peers) != 0 {
			t.Errorf("peers %+v", d.Peers)
		}
		if a := sf.actions(); strings.Join(a, " ") != "server.add:ok server.enrol_refused:refused" {
			t.Errorf("audit %v", a)
		}
		if len(sf.agent.Calls()) != 0 {
			t.Errorf("the worker was called: %v", sf.agent.Calls())
		}
	})
	t.Run("used", func(t *testing.T) {
		sf := newServersFixture(t)
		code, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
		if err != nil {
			t.Fatal(err)
		}
		sf.agent.takeCode(t, code)
		sf.h.mu.Lock()
		s := sf.h.st.Servers["nas"]
		s.Enrol.Used = true
		sf.h.st.Servers["nas"] = s
		sf.h.mu.Unlock()
		sf.link.handshake("nas", time.Now().Add(time.Second))
		r := waitServerOp(t, sf.h, serverOpKey("nas"))
		if r.OK || !strings.Contains(r.Error, "already used") {
			t.Errorf("op %+v", r)
		}
		if s, _ := sf.server("nas"); s.State != ServerRevoked {
			t.Errorf("state %+v", s)
		}
		if d := sf.linkDoc(t); len(d.Peers) != 0 {
			t.Errorf("peers %+v", d.Peers)
		}
		if a := sf.actions(); strings.Join(a, " ") != "server.add:ok server.enrol_refused:refused" {
			t.Errorf("audit %v", a)
		}
	})
	t.Run("wrong proof", func(t *testing.T) {
		sf := newServersFixture(t)
		code, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
		if err != nil {
			t.Fatal(err)
		}
		sf.agent.takeCode(t, code)
		sf.agent.mu.Lock()
		sf.agent.secret = bytes.Repeat([]byte{1}, 32) // the worker has another secret
		sf.agent.mu.Unlock()
		sf.link.handshake("nas", time.Now().Add(time.Second))
		r := waitServerOp(t, sf.h, serverOpKey("nas"))
		if r.OK || !strings.Contains(r.Error, "refused the enrolment proof") {
			t.Errorf("op %+v", r)
		}
		s, _ := sf.server("nas")
		if s.State != ServerRevoked || s.CertSerial != "" || s.SPKI != "" {
			t.Errorf("state %+v", s)
		}
		if d := sf.linkDoc(t); len(d.Peers) != 0 {
			t.Errorf("peers %+v", d.Peers)
		}
		if a := sf.actions(); strings.Join(a, " ") != "server.add:ok server.enrol_refused:refused" {
			t.Errorf("audit %v", a)
		}
		for _, c := range sf.agent.Calls() {
			if c == "cert" || c == "network" || c == "wg" {
				t.Errorf("%s after a refused proof", c)
			}
		}
		if len(sf.ca.signs) != 1 { // the control certificate only
			t.Errorf("signs %v", sf.ca.signs)
		}
	})
	t.Run("stop during join", func(t *testing.T) {
		sf := newServersFixture(t)
		if _, _, err := sf.h.AddServer(context.Background(), admin, "nas", ""); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if err := sf.h.StopServerEnrol("nas", admin, ""); err != nil {
			t.Fatal(err)
		}
		waitServerOp(t, sf.h, serverOpKey("nas"))
		if _, ok := sf.server("nas"); ok {
			t.Error("a stopped join left the server")
		}
		if d := sf.linkDoc(t); len(d.Peers) != 0 {
			t.Errorf("peers %+v", d.Peers)
		}
	})
}

// TestEnrolReportsClockSkew (Review Focus 1): the Hub compares the
// worker's /v1/info clock with its own; more than 5 minutes off fails
// with the NTP hint and the server is revoked. A worker a few minutes
// fast still enrols, and a code is judged by the Hub's clock only.
func TestEnrolReportsClockSkew(t *testing.T) {
	sf := newServersFixture(t)
	sf.agent.skew = 10 * time.Minute
	code, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
	if err != nil {
		t.Fatal(err)
	}
	sf.agent.takeCode(t, code)
	sf.link.handshake("nas", time.Now().Add(time.Second))
	r := waitServerOp(t, sf.h, serverOpKey("nas"))
	if r.OK || !strings.Contains(r.Error, "the worker's clock is 10m0s off; fix its time (NTP)") {
		t.Errorf("op %+v", r)
	}
	if s, _ := sf.server("nas"); s.State != ServerRevoked {
		t.Errorf("state %+v", s)
	}
	for _, c := range sf.agent.Calls() {
		if c != "info" {
			t.Errorf("%s after a skewed clock", c)
		}
	}

	sf2 := newServersFixture(t)
	sf2.agent.skew = 4 * time.Minute
	code, _, err = sf2.h.AddServer(context.Background(), admin, "pi", "")
	if err != nil {
		t.Fatal(err)
	}
	// Joined a minute after the code was shown.
	sf2.h.mu.Lock()
	s2 := sf2.h.st.Servers["pi"]
	s2.Enrol.IssuedAt, s2.Enrol.ExpiresAt = s2.Enrol.IssuedAt.Add(-time.Minute), s2.Enrol.ExpiresAt.Add(-time.Minute)
	sf2.h.st.Servers["pi"] = s2
	sf2.h.mu.Unlock()
	sf2.agent.takeCode(t, code)
	sf2.link.handshake("pi", time.Now().Add(2*time.Minute))
	if r := waitServerOp(t, sf2.h, serverOpKey("pi")); !r.OK {
		t.Errorf("a 4-minute skew: %s", r.Error)
	}
}

// TestRenewAtOneThird: at ⅓ remaining life the poll renews the worker's
// certificate (csr → sign → cert) and pins the new SPKI and serial.
func TestRenewAtOneThird(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	before, _ := sf.server("nas")
	ctx := context.Background()
	// 11 days left: no renewal.
	sf.h.mu.Lock()
	s := sf.h.st.Servers["nas"]
	s.CertNotAfter = time.Now().Add(11 * 24 * time.Hour)
	sf.h.st.Servers["nas"] = s
	sf.h.mu.Unlock()
	sf.link.handshake("nas", time.Now())
	sf.h.pollServer(ctx, "nas")
	if after, _ := sf.server("nas"); after.CertSerial != before.CertSerial {
		t.Fatal("renewed with more than a third left")
	}
	// 9 days left: renewed.
	sf.h.mu.Lock()
	s = sf.h.st.Servers["nas"]
	s.CertNotAfter = time.Now().Add(9 * 24 * time.Hour)
	sf.h.st.Servers["nas"] = s
	sf.h.mu.Unlock()
	sf.h.pollServer(ctx, "nas")
	after, _ := sf.server("nas")
	sf.agent.mu.Lock()
	node := sf.agent.node
	sf.agent.mu.Unlock()
	spki := sha256.Sum256(node.Leaf.RawSubjectPublicKeyInfo)
	if after.CertSerial == before.CertSerial || after.CertSerial != colonHex(node.Leaf.SerialNumber) || after.SPKI != hex.EncodeToString(spki[:]) ||
		time.Until(after.CertNotAfter) < 29*24*time.Hour || after.State != ServerReady {
		t.Errorf("after %+v", after)
	}
	if !strings.Contains(strings.Join(sf.actions(), " "), "server.renewed:ok") {
		t.Errorf("audit %v", sf.actions())
	}
	// The replaced certificate is owed, and the next drain revokes it.
	if owed := sf.owed(); len(owed) != 1 || owed[0] != "nas:"+before.CertSerial {
		t.Errorf("owed after the renewal %v", owed)
	}
	sf.h.drainOwed(ctx, "")
	if !slices.Contains(sf.ca.revokedList(), before.CertSerial) || len(sf.owed()) != 0 {
		t.Errorf("the old certificate isn't revoked: %v owed %v", sf.ca.revokedList(), sf.owed())
	}
	// The new pins work: the next call isn't a mismatch.
	sf.h.pollServer(ctx, "nas")
	if s, _ := sf.server("nas"); s.State != ServerReady {
		t.Errorf("after the renewal: %s", s.State)
	}
	b, _ := sf.h.backendOf("nas")
	if _, err := b.AgentInfo(ctx); err != nil {
		t.Errorf("info: %v", err)
	}
}

// TestOfflineAfterThreeMisses: a handshake older than 3 minutes is
// offline at once; three missed polls too; a good poll brings it back.
func TestOfflineAfterThreeMisses(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	sf.place("grafana", "nas")
	ctx := context.Background()
	sf.link.handshake("nas", time.Now().Add(-4*time.Minute))
	sf.h.pollServer(ctx, "nas")
	if s, _ := sf.server("nas"); s.State != ServerOffline {
		t.Fatalf("a stale handshake: %s", s.State)
	}
	if _, err := sf.h.rtFor("grafana"); err == nil || err.Error() != "server NAS is offline" {
		t.Errorf("rtFor: %v", err)
	}
	sf.link.handshake("nas", time.Now())
	sf.h.pollServer(ctx, "nas")
	if s, _ := sf.server("nas"); s.State != ServerReady {
		t.Fatalf("back: %s", s.State)
	}
	if _, err := sf.h.rtFor("grafana"); err != nil {
		t.Errorf("rtFor back: %v", err)
	}
	sf.agent.srv.Close()
	for i := 1; i <= 3; i++ {
		sf.h.pollServer(ctx, "nas")
		s, _ := sf.server("nas")
		if want := map[bool]string{true: ServerOffline, false: ServerReady}[i == 3]; s.State != want {
			t.Errorf("after %d misses: %s", i, s.State)
		}
	}
	// Offline stays a link.json peer (P23).
	if d := sf.linkDoc(t); len(d.Peers) != 1 || d.Peers[0].State != linkdoc.StateReady {
		t.Errorf("peers %+v", d.Peers)
	}
	var v ServerView
	for _, x := range sf.h.Servers(ctx) {
		if x.ID == "nas" {
			v = x
		}
	}
	if v.State != ServerOffline || v.Error == "" {
		t.Errorf("view %+v", v)
	}
}

// TestRevokeOrderAndRetry: enroll down at step 2 — step 1 (the peer out
// of link.json) happened before anything else, steps 3–5 are done, step 2
// is retried at the next tick.
func TestRevokeOrderAndRetry(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	sf.place("other", "nas")
	if err := sf.h.newRelayToken("other"); err != nil {
		t.Fatal(err)
	}
	sf.h.mu.Lock()
	sf.h.publishLinkLocked()
	sf.h.mu.Unlock()
	if d := sf.linkDoc(t); len(d.Relays) != 1 {
		t.Fatalf("relays %+v", d.Relays)
	}
	pinned, _ := sf.server("nas")
	var sawPeer []bool
	sf.ca.mu.Lock()
	sf.ca.revokeErr = errors.New("enroll is down")
	sf.ca.onRevoke = func(string) {
		d := sf.linkDoc(t)
		sawPeer = append(sawPeer, len(d.Peers)+len(d.Relays) > 0)
	}
	sf.ca.mu.Unlock()
	sf.runner.mu.Lock()
	callsBefore := len(sf.runner.calls)
	sf.runner.mu.Unlock()
	if err := sf.h.RevokeServer(context.Background(), admin, "nas"); err != nil {
		t.Fatal(err)
	}
	if len(sawPeer) != 1 || sawPeer[0] {
		t.Errorf("link.json still had the peer at step 2: %v", sawPeer)
	}
	s, _ := sf.server("nas")
	if owed := sf.owed(); s.State != ServerRevoked || s.Revoke == nil || len(owed) != 1 || owed[0] != "nas:"+pinned.CertSerial ||
		!s.Revoke.RelaysDone || !s.Revoke.Rotated || s.CertSerial != "" || s.SPKI != "" {
		t.Errorf("after the first pass %+v %+v", s, s.Revoke)
	}
	if !strings.Contains(strings.Join(sf.runner.Calls()[callsBefore:], ","), "downbyname:portcullis-other") {
		t.Errorf("relays not down: %v", sf.runner.Calls()[callsBefore:])
	}
	sf.h.mu.RLock()
	orphan := sf.h.st.Instances["other"].State
	sf.h.mu.RUnlock()
	if orphan != state.InstanceOrphaned {
		t.Errorf("instance state %q", orphan)
	}
	if _, err := sf.h.rtFor("other"); err == nil || err.Error() != "server NAS is revoked" {
		t.Errorf("rtFor: %v", err)
	}
	if a := sf.actions(); a[len(a)-1] != "server.revoked:ok" {
		t.Errorf("audit %v", a)
	}
	// Enroll is back: the next tick revokes the serial.
	sf.ca.mu.Lock()
	sf.ca.revokeErr = nil
	sf.ca.mu.Unlock()
	sf.h.serversTick(context.Background())
	s, _ = sf.server("nas")
	if len(sf.owed()) != 0 || len(sf.ca.revoked) != 1 || sf.ca.revoked[0] != pinned.CertSerial {
		t.Errorf("retry: %+v revoked %v", s.Revoke, sf.ca.revoked)
	}
	if err := sf.h.RevokeServer(context.Background(), admin, "nas"); errStatus(err) != 409 {
		t.Errorf("revoke again: %v", err)
	}
}

// TestRevokeRotatesClientSecretsAndTokens: step 5 gives each placed
// instance new Keycloak client secrets (registered) and a new relay token.
func TestRevokeRotatesClientSecretsAndTokens(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	sf.place("other", "nas")
	writeFile(t, sf.h.envPath("other"), "OTHER_SECRET=old-secret\nKEEP=1\n")
	if err := sf.h.newRelayToken("other"); err != nil {
		t.Fatal(err)
	}
	oldTok := sf.h.relayTokenSHA("other")
	if err := sf.h.RevokeServer(context.Background(), admin, "nas"); err != nil {
		t.Fatal(err)
	}
	env := readEnvRaw(sf.h.envPath("other"))
	if env["OTHER_SECRET"] == "" || env["OTHER_SECRET"] == "old-secret" || env["KEEP"] != "1" {
		t.Errorf("env %v", env)
	}
	if tok := sf.h.relayTokenSHA("other"); tok == "" || tok == oldTok {
		t.Error("the relay token wasn't rotated")
	}
	sf.idp.mu.Lock()
	var registered bool
	for _, sp := range sf.idp.specs {
		if sp.ClientID == "other" && sp.Secret == env["OTHER_SECRET"] {
			registered = true
		}
	}
	sf.idp.mu.Unlock()
	if !registered {
		t.Error("the new secret wasn't registered with Keycloak")
	}
	if fi, err := os.Stat(sf.h.relayEnvPath("other")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("relay env %v %v", fi, err)
	}
	// Keycloak down: the rotation is retried (not marked done).
	sf2 := newServersFixture(t)
	sf2.enrol(t, "nas")
	sf2.place("other", "nas")
	sf2.idp.mu.Lock()
	sf2.idp.registerErr = errors.New("keycloak down")
	sf2.idp.mu.Unlock()
	sf2.h.RevokeServer(context.Background(), admin, "nas")
	if s, _ := sf2.server("nas"); s.Revoke == nil || s.Revoke.Rotated {
		t.Errorf("rotation with Keycloak down: %+v", s.Revoke)
	}
	sf2.idp.mu.Lock()
	sf2.idp.registerErr = nil
	sf2.idp.mu.Unlock()
	sf2.h.serversTick(context.Background())
	if s, _ := sf2.server("nas"); !s.Revoke.Rotated {
		t.Errorf("retry: %+v", s.Revoke)
	}
}

// TestRemoveRefusesWithInstances: 409 while instances remain; else leave,
// the revocation, the entry gone, its address quarantined.
func TestRemoveRefusesWithInstances(t *testing.T) {
	sf := newServersFixture(t)
	jc := sf.enrol(t, "nas")
	sf.place("other", "nas")
	err := sf.h.RemoveServer(context.Background(), admin, "nas")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "still has 1 instance") {
		t.Fatalf("with an instance: %v", err)
	}
	if s, _ := sf.server("nas"); s.State != ServerReady {
		t.Errorf("state after the refusal: %s", s.State)
	}
	sf.place("other", "")
	if err := sf.h.RemoveServer(context.Background(), admin, "nas"); err != nil {
		t.Fatal(err)
	}
	sf.agent.mu.Lock()
	left := sf.agent.left
	sf.agent.mu.Unlock()
	if !left {
		t.Error("no leave")
	}
	if _, ok := sf.server("nas"); ok {
		t.Error("still listed")
	}
	if len(sf.ca.revoked) != 1 {
		t.Errorf("revoked %v", sf.ca.revoked)
	}
	if d := sf.linkDoc(t); len(d.Peers) != 0 {
		t.Errorf("peers %+v", d.Peers)
	}
	a := sf.actions()
	if a[len(a)-1] != "server.removed:ok" || a[len(a)-2] != "server.removed:refused" {
		t.Errorf("audit %v", a)
	}
	// The address stays quarantined.
	code, _, err := sf.h.AddServer(context.Background(), admin, "pi", "")
	if err != nil {
		t.Fatal(err)
	}
	if j, _ := servers.DecodeJoinCode(code); j.TunnelIP == jc.TunnelIP {
		t.Errorf("reused the quarantined %s", jc.TunnelIP)
	}
	sf.h.StopServerEnrol("pi", admin, "")
	waitServerOp(t, sf.h, serverOpKey("pi"))
	if err := sf.h.RemoveServer(context.Background(), admin, "nope"); errStatus(err) != 404 {
		t.Errorf("unknown: %v", err)
	}
}

// TestLinkJSONRewrittenAtStart: link.json isn't backed up; the start
// rewrites it from state, and settles interrupted enrolments (before the
// handshake: removed; after it: revoked).
func TestLinkJSONRewrittenAtStart(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	ready, _ := sf.server("nas")
	os.Remove(filepath.Join(sf.h.cfg.LinkDocDir, linkdoc.FileName))
	_, pubA, _ := servers.NewWGKeyPair()
	_, pubB, _ := servers.NewWGKeyPair()
	now := time.Now().UTC()
	sf.h.mu.Lock()
	sf.h.st.Servers["joining"] = state.Server{Name: "J", TunnelIP: "10.214.0.20", WGPublicKey: pubA, State: ServerEnrolling,
		Enrol: &state.Enrol{BootstrapPub: pubA, IssuedAt: now, ExpiresAt: now.Add(JoinCodeTTL), Step: StepJoin}}
	sf.h.st.Servers["midway"] = state.Server{Name: "M", TunnelIP: "10.214.0.21", WGPublicKey: pubB, State: ServerEnrolling,
		Enrol: &state.Enrol{BootstrapPub: pubB, IssuedAt: now, ExpiresAt: now.Add(JoinCodeTTL), Used: true, Step: StepVerify}}
	sf.h.mu.Unlock()
	sf.h.startServers(context.Background())
	d := sf.linkDoc(t)
	if len(d.Peers) != 1 || d.Peers[0].ID != "nas" || d.Peers[0].PublicKey != ready.WGPublicKey || d.Peers[0].State != linkdoc.StateReady {
		t.Errorf("peers %+v", d.Peers)
	}
	if _, ok := sf.server("joining"); ok {
		t.Error("an interrupted join is still listed")
	}
	if s, _ := sf.server("midway"); s.State != ServerRevoked {
		t.Errorf("midway %+v", s)
	}
	if _, err := sf.h.rtFor("x"); err != nil {
		t.Error(err)
	}
	if b, ok := sf.h.backendOf("nas"); !ok || b == nil {
		t.Error("no backend for the ready server")
	}
}

// TestServersOffWithoutLinkDoc: no link_doc, or link's status missing or
// without its link block → 503 "run ./portcullis link init on the
// primary"; nothing is recorded.
func TestServersOffWithoutLinkDoc(t *testing.T) {
	const want = "servers are off: run ./portcullis link init on the primary"
	for name, mod := range map[string]func(sf *serversFixture){
		"no link doc dir":      func(sf *serversFixture) { sf.h.cfg.LinkDocDir = "" },
		"link doc missing":     func(sf *serversFixture) { sf.h.cfg.LinkDocDir = filepath.Join(t.TempDir(), "absent") },
		"no status file":       func(sf *serversFixture) { os.Remove(sf.link.path) },
		"link role off":        func(sf *serversFixture) { sf.link.off = true; sf.link.write() },
		"no status configured": func(sf *serversFixture) { sf.h.cfg.VPNStatusFile = "" },
	} {
		t.Run(name, func(t *testing.T) {
			sf := newServersFixture(t)
			mod(sf)
			_, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
			if errStatus(err) != 503 || err.Error() != want {
				t.Errorf("%v", err)
			}
			if _, ok := sf.server("nas"); ok {
				t.Error("recorded")
			}
			if sf.h.LastOp(serverOpKey("nas")) != nil {
				t.Error("an op started")
			}
		})
	}
	// Primary instances are unaffected: the primary is listed, ready.
	sf := newServersFixture(t)
	sf.h.cfg.LinkDocDir = ""
	if v := sf.h.Servers(context.Background()); len(v) != 1 || v[0].ID != "primary" || v[0].State != ServerReady {
		t.Errorf("views %+v", v)
	}
}

// TestKubernetesPrimaryRefusesServers: a Kubernetes primary has Servers
// off: 409 "servers need a Docker or Podman primary".
func TestKubernetesPrimaryRefusesServers(t *testing.T) {
	sf := newServersFixture(t)
	sf.h.cfg.Runtime = runtime.KindKubernetes
	_, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
	if errStatus(err) != 409 || err.Error() != "servers need a Docker or Podman primary" {
		t.Errorf("%v", err)
	}
	if _, ok := sf.server("nas"); ok {
		t.Error("recorded")
	}
}

func (c *testNodeCA) revokedList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.revoked...)
}

// TestRevokeDuringEnrolment: a revocation while enroll is signing the
// worker's certificate cancels the enrolment and waits for it; the fresh
// serial is revoked at once, nothing is pinned, the worker never gets it.
func TestRevokeDuringEnrolment(t *testing.T) {
	sf := newServersFixture(t)
	revokeDone := make(chan error, 1)
	sf.ca.onSign = func(role string) {
		if role != RoleNodeWorker {
			return
		}
		go func() { revokeDone <- sf.h.RevokeServer(context.Background(), admin, "nas") }()
		for i := 0; i < 1000; i++ {
			if s, _ := sf.server("nas"); s.State == ServerRevoked {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Error("the revocation didn't start")
	}
	code, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
	if err != nil {
		t.Fatal(err)
	}
	sf.agent.takeCode(t, code)
	sf.link.handshake("nas", time.Now().Add(time.Second))
	if err := <-revokeDone; err != nil {
		t.Fatal(err)
	}
	// RevokeServer returned once the op's work had ended (its record is
	// written right after).
	r := waitServerOp(t, sf.h, serverOpKey("nas"))
	if r.OK || !strings.Contains(r.Error, "revoked") {
		t.Errorf("op %+v", r)
	}
	sf.ca.mu.Lock()
	fresh := sf.ca.issued[len(sf.ca.issued)-1]
	sf.ca.mu.Unlock()
	if !slices.Contains(sf.ca.revokedList(), fresh) {
		t.Errorf("the fresh serial %s isn't revoked: %v", fresh, sf.ca.revokedList())
	}
	s, _ := sf.server("nas")
	if s.State != ServerRevoked || s.CertSerial != "" || s.SPKI != "" || len(sf.owed()) != 0 {
		t.Errorf("state %+v %+v", s, s.Revoke)
	}
	if slices.Contains(sf.agent.Calls(), "cert") {
		t.Errorf("the worker got the certificate: %v", sf.agent.Calls())
	}
	if d := sf.linkDoc(t); len(d.Peers) != 0 {
		t.Errorf("peers %+v", d.Peers)
	}
}

// TestRenewRacingRevoke: a revocation while a renewal is being signed:
// the new serial is revoked at once and never pinned, the old one is
// revoked by the revocation.
func TestRenewRacingRevoke(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	pinned, _ := sf.server("nas")
	sf.h.mu.Lock()
	s := sf.h.st.Servers["nas"]
	s.CertNotAfter = time.Now().Add(9 * 24 * time.Hour)
	sf.h.st.Servers["nas"] = s
	sf.h.mu.Unlock()
	sf.ca.onSign = func(role string) {
		if role == RoleNodeWorker {
			if err := sf.h.RevokeServer(context.Background(), admin, "nas"); err != nil {
				t.Error(err)
			}
		}
	}
	sf.link.handshake("nas", time.Now())
	calls := len(sf.agent.Calls())
	sf.h.pollServer(context.Background(), "nas")
	sf.ca.mu.Lock()
	fresh := sf.ca.issued[len(sf.ca.issued)-1]
	sf.ca.mu.Unlock()
	rv := sf.ca.revokedList()
	if !slices.Contains(rv, fresh) || !slices.Contains(rv, pinned.CertSerial) || fresh == pinned.CertSerial {
		t.Errorf("revoked %v (pinned %s, fresh %s)", rv, pinned.CertSerial, fresh)
	}
	after, _ := sf.server("nas")
	if after.State != ServerRevoked || after.CertSerial != "" || after.SPKI != "" || len(sf.owed()) != 0 {
		t.Errorf("after %+v %+v", after, after.Revoke)
	}
	if slices.Contains(sf.agent.Calls()[calls:], "cert") {
		t.Errorf("the worker got the renewed certificate: %v", sf.agent.Calls()[calls:])
	}
	// A pending revocation keeps a serial whose revoke failed owed.
	sf.ca.mu.Lock()
	sf.ca.revokeErr = errors.New("enroll down")
	sf.ca.mu.Unlock()
	sf.h.discardSerial(context.Background(), "nas", "0a:0b")
	if owed := sf.owed(); !slices.Contains(owed, "nas:0a:0b") {
		t.Errorf("owed %v", owed)
	}
	sf.ca.mu.Lock()
	sf.ca.revokeErr = nil
	sf.ca.mu.Unlock()
	sf.h.serversTick(context.Background())
	if owed := sf.owed(); len(owed) != 0 || !slices.Contains(sf.ca.revokedList(), "0a:0b") {
		t.Errorf("retry: owed %v", owed)
	}
}

// TestRevokeRotatesAIClient: a placed instance's ai_client gets a new
// secret and is deleted and created again, so every session of it —
// offline ones included — ends; Rotated only once that is done.
func TestRevokeRotatesAIClient(t *testing.T) {
	kc, c := hubAIRealm(t)
	a := chatFixture23(t, nil)
	a.h.SetAIKeycloak(c)
	ctx := context.Background()
	tmpl := a.h.Template("ai-chat")
	writeFile(t, a.h.envPath("ai-chat"), "CHAT_MCP_SECRET=old-chat-secret\n")
	if _, err := a.h.ensureInstanceAIClient(ctx, tmpl); err != nil {
		t.Fatal(err)
	}
	old := kc.ClientByClientID(chatMCPID)
	if old == nil {
		t.Fatal("no ai_client")
	}
	oldSecret := readEnvFile(a.h.envPath("ai-chat"))["CHAT_MCP_SECRET"]
	kc.Users["alice"] = &kctest.User{ID: "u-alice", Username: "alice", Enabled: true}
	kc.AddOfflineSession("alice", time.Now(), time.Now(), old.ID)
	kc.AddConsent("alice", chatMCPID, time.Now(), "mcp:all")
	a.h.mu.Lock()
	a.h.st.Servers = map[string]state.Server{"nas": {Name: "NAS", TunnelIP: "10.214.0.10", State: ServerReady, CertSerial: "0a"}}
	in := a.h.st.Instances["ai-chat"]
	in.ID, in.Template, in.Server = "ai-chat", "ai-chat", "nas"
	a.h.st.Instances["ai-chat"] = in
	a.h.noteServersLocked()
	a.h.mu.Unlock()
	if err := a.h.RevokeServer(ctx, root, "nas"); err != nil {
		t.Fatal(err)
	}
	nw := kc.ClientByClientID(chatMCPID)
	secret := readEnvFile(a.h.envPath("ai-chat"))["CHAT_MCP_SECRET"]
	if nw == nil || nw.ID == old.ID || secret == "" || secret == oldSecret || nw.Secret != secret {
		t.Errorf("ai_client not rotated: old %s new %+v secret changed %v", old.ID, nw, secret != oldSecret)
	}
	if got := kc.OfflineClients("alice"); len(got) != 0 {
		t.Errorf("offline sessions left: %v", got)
	}
	if got := kc.UserConsents("alice"); slices.Contains(got, chatMCPID) {
		t.Errorf("consent left: %v", got)
	}
	a.h.mu.RLock()
	rv := a.h.st.Servers["nas"].Revoke
	a.h.mu.RUnlock()
	if rv == nil || !rv.Rotated {
		t.Errorf("revoke %+v", rv)
	}
}

// TestOwedSerials: every serial signed is owed until pinned or revoked —
// a pinned one leaves the list; one whose PUT /v1/identity/cert failed is
// revoked at the next tick; one of a server removed mid-renewal is still
// revoked.
func TestOwedSerials(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	enrolled, _ := sf.server("nas")
	if owed := sf.owed(); len(owed) != 0 {
		t.Fatalf("a pinned serial is owed: %v", owed)
	}
	due := func() {
		sf.h.mu.Lock()
		s := sf.h.st.Servers["nas"]
		s.CertNotAfter = time.Now().Add(9 * 24 * time.Hour)
		sf.h.st.Servers["nas"] = s
		sf.h.mu.Unlock()
		sf.link.handshake("nas", time.Now())
	}
	// The worker refuses the renewed certificate.
	due()
	sf.agent.mu.Lock()
	sf.agent.failCert = true
	sf.agent.mu.Unlock()
	sf.h.pollServer(context.Background(), "nas")
	sf.ca.mu.Lock()
	first := sf.ca.issued[len(sf.ca.issued)-1]
	sf.ca.mu.Unlock()
	if owed := sf.owed(); len(owed) != 1 || owed[0] != "nas:"+first {
		t.Fatalf("owed %v", owed)
	}
	if slices.Contains(sf.ca.revokedList(), first) {
		t.Fatal("revoked before the tick")
	}
	sf.agent.mu.Lock()
	sf.agent.failCert = false
	sf.agent.mu.Unlock()
	sf.h.serversTick(context.Background()) // drains, then the renewal succeeds
	if !slices.Contains(sf.ca.revokedList(), first) {
		t.Errorf("the refused certificate %s wasn't revoked: %v", first, sf.ca.revokedList())
	}
	// The renewed one is pinned; the one it replaced is owed.
	if owed := sf.owed(); len(owed) != 1 || owed[0] != "nas:"+enrolled.CertSerial {
		t.Errorf("owed after the tick %v", owed)
	}
	sf.h.drainOwed(context.Background(), "")
	// The server is removed while a renewal is signed (and enroll is
	// down at that moment): the serial is still revoked later.
	due()
	sf.ca.mu.Lock()
	sf.ca.onSign = func(role string) {
		sf.h.mu.Lock()
		delete(sf.h.st.Servers, "nas")
		sf.h.mu.Unlock()
		sf.ca.mu.Lock()
		sf.ca.revokeErr = errors.New("enroll down")
		sf.ca.mu.Unlock()
	}
	sf.ca.mu.Unlock()
	sf.h.pollServer(context.Background(), "nas")
	sf.ca.mu.Lock()
	second := sf.ca.issued[len(sf.ca.issued)-1]
	sf.ca.onSign, sf.ca.revokeErr = nil, nil
	sf.ca.mu.Unlock()
	if owed := sf.owed(); !slices.Contains(owed, "nas:"+second) {
		t.Fatalf("owed %v", owed)
	}
	sf.h.serversTick(context.Background())
	if !slices.Contains(sf.ca.revokedList(), second) || len(sf.owed()) != 0 {
		t.Errorf("revoked %v owed %v", sf.ca.revokedList(), sf.owed())
	}
}

// TestInflightSerialNotDrained: a tick's drain between sign and pin
// leaves the serial of the running renewal alone (it is pinned and
// works); once a renewal fails, the next tick revokes its serial.
func TestInflightSerialNotDrained(t *testing.T) {
	sf := newServersFixture(t)
	sf.enrol(t, "nas")
	enrolled, _ := sf.server("nas")
	ctx := context.Background()
	due := func() {
		sf.h.mu.Lock()
		s := sf.h.st.Servers["nas"]
		s.CertNotAfter = time.Now().Add(9 * 24 * time.Hour)
		sf.h.st.Servers["nas"] = s
		sf.h.mu.Unlock()
		sf.link.handshake("nas", time.Now())
	}
	var (
		winMu        sync.Mutex
		owedInWindow []string
	)
	sf.agent.mu.Lock()
	sf.agent.onCert = func() {
		winMu.Lock()
		owedInWindow = sf.owed()
		winMu.Unlock()
		sf.h.drainOwed(ctx, "") // a tick in the window
	}
	sf.agent.mu.Unlock()
	due()
	sf.h.pollServer(ctx, "nas")
	sf.ca.mu.Lock()
	fresh := sf.ca.issued[len(sf.ca.issued)-1]
	sf.ca.mu.Unlock()
	winMu.Lock()
	if len(owedInWindow) != 1 || owedInWindow[0] != "nas:"+fresh {
		t.Errorf("owed in the window %v", owedInWindow)
	}
	winMu.Unlock()
	if slices.Contains(sf.ca.revokedList(), fresh) {
		t.Fatal("the drain revoked the in-flight serial")
	}
	// Pinned; only the certificate it replaced is owed.
	if s, _ := sf.server("nas"); s.CertSerial != fresh || len(sf.owed()) != 1 || sf.owed()[0] != "nas:"+enrolled.CertSerial {
		t.Errorf("pinned %s owed %v", s.CertSerial, sf.owed())
	}
	b, _ := sf.h.backendOf("nas")
	if _, err := b.AgentInfo(ctx); err != nil {
		t.Errorf("the renewed certificate doesn't work: %v", err)
	}
	// A failing renewal: in flight during the op, revoked by the next
	// tick once it has failed.
	sf.agent.mu.Lock()
	sf.agent.failCert = true
	sf.agent.mu.Unlock()
	due()
	sf.h.pollServer(ctx, "nas")
	sf.ca.mu.Lock()
	failed := sf.ca.issued[len(sf.ca.issued)-1]
	sf.ca.mu.Unlock()
	if slices.Contains(sf.ca.revokedList(), failed) {
		t.Fatal("revoked while its op ran")
	}
	sf.agent.mu.Lock()
	sf.agent.onCert, sf.agent.failCert = nil, false
	sf.agent.mu.Unlock()
	sf.h.drainOwed(ctx, "")
	if !slices.Contains(sf.ca.revokedList(), failed) || len(sf.owed()) != 0 {
		t.Errorf("after the op: revoked %v owed %v", sf.ca.revokedList(), sf.owed())
	}
}

// TestAddRefusedWhileSerialsOwed: an id with serials still owed can't be
// enrolled again until they are revoked.
func TestAddRefusedWhileSerialsOwed(t *testing.T) {
	sf := newServersFixture(t)
	sf.h.mu.Lock()
	sf.h.st.OwedSerials = []state.OwedSerial{{Server: "nas", Serial: "0a:01", Since: time.Now()}}
	sf.h.mu.Unlock()
	_, _, err := sf.h.AddServer(context.Background(), admin, "nas", "")
	if errStatus(err) != 409 || err.Error() != "server nas is still being revoked: try again shortly" {
		t.Fatalf("%v", err)
	}
	if _, ok := sf.server("nas"); ok {
		t.Error("recorded")
	}
	sf.h.drainOwed(context.Background(), "")
	if _, _, err := sf.h.AddServer(context.Background(), admin, "nas", ""); err != nil {
		t.Errorf("after the drain: %v", err)
	}
	sf.h.StopServerEnrol("nas", admin, "")
	waitServerOp(t, sf.h, serverOpKey("nas"))
}
