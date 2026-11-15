package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/servers"
)

var agentIP = netip.MustParseAddr("10.214.0.10")

// upTunnel starts an agent tunnel at .10 whose peer is l (at peerIP).
func upTunnel(t *testing.T, l *linkSide, priv Key, peerIP netip.Addr) *Tunnel {
	t.Helper()
	tun, err := NewTunnel(TunnelConfig{PrivateKey: priv, Address: agentIP, LinkPub: l.priv.Public(), Endpoint: l.endpoint(), PeerIP: peerIP})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.Close)
	l.peer(t, priv.Public(), agentIP)
	return tun
}

func acceptAll(t *testing.T, ln net.Listener) {
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("x"))
			c.Close()
		}
	}()
}

func TestNetstackOnlyTwoListeners(t *testing.T) {
	l := newLink(t, "10.214.0.1")
	priv, _ := GenerateKey()
	tun := upTunnel(t, l, priv, netip.Addr{})
	for _, p := range []uint16{ControlPort, DataPort} {
		ln, err := tun.Listen(p)
		if err != nil {
			t.Fatal(err)
		}
		acceptAll(t, ln)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, p := range []uint16{ControlPort, DataPort} {
		c, err := l.dial(ctx, netip.AddrPortFrom(agentIP, p))
		if err != nil {
			t.Fatalf(":%d: %v", p, err)
		}
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil {
			t.Errorf(":%d read: %v", p, err)
		}
		c.Close()
	}
	for _, p := range []uint16{22, 80, 443, 2375, 2376, 7444, 9100, 3128, 7001} {
		dctx, dc := context.WithTimeout(ctx, 3*time.Second)
		c, err := l.dial(dctx, netip.AddrPortFrom(agentIP, p))
		dc()
		if err == nil {
			c.Close()
			t.Errorf(":%d accepted a connection", p)
		}
	}
}

func TestDataOnlyFromLink(t *testing.T) {
	for _, c := range []struct {
		linkAt string
		served bool
	}{{"10.214.0.1", true}, {"10.214.0.2", false}} {
		l := newLink(t, c.linkAt)
		priv, _ := GenerateKey()
		tun := upTunnel(t, l, priv, netip.MustParseAddr(c.linkAt))
		ln, err := tun.Listen(DataPort)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		served := make(chan bool, 1)
		go ServeData(ln, func(conn net.Conn) { served <- true; conn.Write([]byte("ok")); conn.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		conn, err := l.dial(ctx, netip.AddrPortFrom(agentIP, DataPort))
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", c.linkAt, err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(conn)
		conn.Close()
		if got := string(b) == "ok"; got != c.served {
			t.Errorf("from %s: served %v, want %v", c.linkAt, got, c.served)
		}
	}
}

// enrolling is an agent in the enrolling state over a fresh data dir.
func enrolling(t *testing.T, l *linkSide, ca *testCA, now func() time.Time) (*Agent, servers.JoinCode, string) {
	t.Helper()
	data := t.TempDir()
	boot, _ := GenerateKey()
	code := joinCode(t, l, ca, boot)
	st := Store{Dir: identityDir(data)}
	if err := st.SaveJoin(code); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{DataDir: data, Runtime: "docker", Now: now, SwitchDelay: 50 * time.Millisecond, SwitchTimeout: 3 * time.Second,
		Info: func(context.Context) (agentapi.Info, error) { return agentapi.Info{EngineVersion: "29.0"}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if a.State() != StateEnrolling {
		t.Fatalf("state %s", a.State())
	}
	return a, code, data
}

// client is the Hub's control client for an agent server at addr.
func client(dial func(ctx context.Context, network, addr string) (net.Conn, error), cert tls.Certificate, roots *x509.CertPool, serverSPKI *[]byte) *http.Client {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if roots == nil {
		cfg.InsecureSkipVerify = true // enrolling: the agent's self-signed certificate; its SPKI goes into the proof
	} else {
		cfg.RootCAs, cfg.ServerName = roots, "nas.node.portcullis.internal"
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if serverSPKI != nil {
			*serverSPKI = cs.PeerCertificates[0].RawSubjectPublicKeyInfo
		}
		return nil
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dial, TLSClientConfig: cfg, DisableKeepAlives: true}}
}

func do(t *testing.T, c *http.Client, method, url string, body any, out any) int {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, r)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: %v %s", method, url, err, b)
		}
	}
	if resp.StatusCode >= 300 {
		t.Logf("%s %s: %d %s", method, url, resp.StatusCode, b)
	}
	return resp.StatusCode
}

// serveLoopback serves a's control API with its TLS on loopback TCP.
func serveLoopback(t *testing.T, a *Agent) string {
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = a.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

func netDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func TestEnrolRefusals(t *testing.T) {
	l := newLink(t, "10.214.0.1")
	ca := newCA(t, "example.org Node CA")
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	a, code, _ := enrolling(t, l, ca, now)
	url := serveLoopback(t, a)
	var spkiSeen []byte
	c := client(netDial, ca.control(t, CNControl), nil, &spkiSeen)
	proof := func(n []byte) []byte { return servers.Proof(code.SecretBytes(), n, "nas", spkiSeen) }
	var n agentapi.EnrolNonce
	// 1. a wrong HMAC
	do(t, c, "GET", url+"/v1/enrol/nonce", nil, &n)
	bad := servers.Proof([]byte(strings.Repeat("x", 32)), n.Nonce, "nas", spkiSeen)
	if s := do(t, c, "POST", url+"/v1/enrol", agentapi.EnrolProof{Proof: bad, CSRCN: "nas.node.portcullis.internal"}, nil); s != 403 {
		t.Errorf("wrong proof: %d", s)
	}
	// 2. a reused nonce (even with a good proof)
	if s := do(t, c, "POST", url+"/v1/enrol", agentapi.EnrolProof{Proof: proof(n.Nonce), CSRCN: "nas.node.portcullis.internal"}, nil); s != 403 {
		t.Errorf("reused nonce: %d", s)
	}
	select {
	case <-a.Refused():
		t.Fatal("stopped after two failures")
	default:
	}
	// 3. an expired nonce: the third failure stops the agent
	do(t, c, "GET", url+"/v1/enrol/nonce", nil, &n)
	mu.Lock()
	clock = clock.Add(NonceTTL + time.Second)
	mu.Unlock()
	if s := do(t, c, "POST", url+"/v1/enrol", agentapi.EnrolProof{Proof: proof(n.Nonce), CSRCN: "nas.node.portcullis.internal"}, nil); s != 403 {
		t.Errorf("expired nonce: %d", s)
	}
	select {
	case <-a.Refused():
	case <-time.After(time.Second):
		t.Fatal("three failures didn't stop the agent")
	}
	if !strings.Contains(ErrEnrolRefused.Error(), "run ./portcullis worker join again") {
		t.Error(ErrEnrolRefused)
	}
	// The refusal survives a restart (review L1): no join code left, New refuses.
	if a.store.exists(joinFile) {
		t.Error("the join code survived the refusal")
	}
	if _, err := New(Config{DataDir: filepath.Dir(a.store.Dir), Runtime: "docker"}); !errors.Is(err, ErrEnrolRefused) {
		t.Errorf("restart after the refusal: %v", err)
	}
	// A proof bound to another channel (another SPKI) is refused too.
	b, _, _ := enrolling(t, l, ca, time.Now)
	burl := serveLoopback(t, b)
	c2 := client(netDial, ca.control(t, CNControl), nil, &spkiSeen)
	do(t, c2, "GET", burl+"/v1/enrol/nonce", nil, &n)
	other := servers.Proof(code.SecretBytes(), n.Nonce, "nas", []byte("another spki"))
	if s := do(t, c2, "POST", burl+"/v1/enrol", agentapi.EnrolProof{Proof: other, CSRCN: "nas.node.portcullis.internal"}, nil); s != 403 {
		t.Errorf("proof for another SPKI: %d", s)
	}
	// Before the proof only /v1/info and the enrol routes answer.
	for _, p := range []string{"/v1/projects/x/up", "/v1/containers", "/v1/metrics", "/v1/identity/csr"} {
		m := "GET"
		if strings.HasSuffix(p, "/up") || strings.HasSuffix(p, "/csr") {
			m = "POST"
		}
		if s := do(t, c2, m, burl+p, nil, nil); s != 403 {
			t.Errorf("%s while enrolling: %d", p, s)
		}
	}
	if s := do(t, c2, "GET", burl+"/v1/info", nil, nil); s != 200 {
		t.Errorf("info while enrolling: %d", s)
	}
	// Another CA (the chain lacks the pinned CA) never reaches a handler.
	other2 := newCA(t, "intruder")
	c3 := client(netDial, other2.control(t, CNControl), nil, nil)
	req, _ := http.NewRequest("GET", burl+"/v1/info", nil)
	if resp, err := c3.Do(req); err == nil {
		resp.Body.Close()
		t.Error("a control certificate of another CA was accepted")
	}
}

// TestEnrolProofAndSwap: the whole enrolment over the netstack (contract
// §17.5 steps 3–6): the proof, the CSR, the certificate, the network,
// the key switch with link's peer moved to the new key, then ready.
func TestEnrolProofAndSwap(t *testing.T) {
	l := newLink(t, "10.214.0.1")
	ca := newCA(t, "example.org Node CA")
	a, code, data := enrolling(t, l, ca, time.Now)
	boot, _ := ParseKey(code.BootstrapKey)
	tun := upTunnel(t, l, boot, netip.Addr{})
	a.AttachTunnel(tun)
	ln, err := tun.Listen(ControlPort)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer(a.Handler())
	go srv.Serve(tls.NewListener(ln, a.TLSConfig()))
	t.Cleanup(func() { srv.Close() })
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return l.dial(ctx, netip.AddrPortFrom(agentIP, ControlPort))
	}
	base := "https://10.214.0.10:7443"
	var spkiSeen []byte
	hub := ca.control(t, CNControl)
	c := client(dial, hub, nil, &spkiSeen)
	var n agentapi.EnrolNonce
	if s := do(t, c, "GET", base+"/v1/enrol/nonce", nil, &n); s != 200 || len(n.Nonce) != servers.NonceLen {
		t.Fatalf("nonce: %d %d", s, len(n.Nonce))
	}
	var csr agentapi.IdentityCSR
	if s := do(t, c, "POST", base+"/v1/enrol", agentapi.EnrolProof{Proof: servers.Proof(code.SecretBytes(), n.Nonce, "nas", spkiSeen), CSRCN: "nas.node.portcullis.internal"}, &csr); s != 200 {
		t.Fatalf("enrol: %d", s)
	}
	newWG, err := ParseKey(csr.WGPublicKey)
	if err != nil || newWG == boot.Public() {
		t.Fatalf("new wg key %q", csr.WGPublicKey)
	}
	// A certificate for another key or name is refused.
	wrong, _ := ca.issue(t, "nas.node.portcullis.internal", nil, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	if s := do(t, c, "PUT", base+"/v1/identity/cert", agentapi.IdentityCert{Certificate: pemOf(wrong), CA: pemOf(ca.cert)}, nil); s != 400 {
		t.Errorf("cert for another key: %d", s)
	}
	cert := ca.signCSR(t, csr.CSR)
	if s := do(t, c, "PUT", base+"/v1/identity/cert", agentapi.IdentityCert{Certificate: pemOf(cert), CA: pemOf(ca.cert)}, nil); s != 204 {
		t.Fatalf("cert: %d", s)
	}
	// From now on the agent presents the node certificate: verify it.
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	c = client(dial, hub, roots, nil)
	if s := do(t, c, "PUT", base+"/v1/identity/wg", agentapi.IdentityWG{LinkPub: l.priv.Public().String()}, nil); s != 409 {
		t.Errorf("wg before the network: %d", s)
	}
	np := agentapi.NetworkParams{ProxySubnet: netip.MustParsePrefix("172.31.254.0/26"), ProxyIPRange: netip.MustParsePrefix("172.31.254.32/27"), TraefikIP: netip.MustParseAddr("172.31.254.2")}
	if s := do(t, c, "PUT", base+"/v1/network", np, nil); s != 204 {
		t.Fatalf("network: %d", s)
	}
	if s := do(t, c, "PUT", base+"/v1/identity/wg", agentapi.IdentityWG{LinkPub: l.priv.Public().String()}, nil); s != 200 {
		t.Fatalf("wg: %d", s)
	}
	// The Hub writes the new key into link.json: link's peer moves.
	l.peer(t, newWG, agentIP)
	deadline := time.Now().Add(30 * time.Second)
	for a.State() != StateReady && time.Now().Before(deadline) {
		// keep traffic flowing so a handshake happens on the new key
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if cn, err := l.dial(ctx, netip.AddrPortFrom(agentIP, ControlPort)); err == nil {
			cn.Close()
		}
		cancel()
		time.Sleep(100 * time.Millisecond)
	}
	if a.State() != StateReady {
		t.Fatal("not ready after the key switch")
	}
	st := Store{Dir: identityDir(data)}
	if st.exists(joinFile) || st.exists(wgKeyNewFile) {
		t.Error("the join code or the bootstrap key survived")
	}
	for _, f := range []string{wgKeyFile, tlsKeyFile, tlsCertFile, caFile, pinsFile, networkFile} {
		fi, err := os.Stat(filepath.Join(identityDir(data), f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, err, fi)
		}
	}
	if fi, _ := os.Stat(identityDir(data)); fi.Mode().Perm() != 0o700 {
		t.Errorf("identity dir mode %v", fi.Mode().Perm())
	}
	// Ready: info and metrics; link.control only on metrics; enrolment over.
	if s := do(t, c, "GET", base+"/v1/info", nil, nil); s != 200 {
		t.Errorf("info: %d", s)
	}
	lc := client(dial, ca.control(t, CNLink), roots, nil)
	if s := do(t, lc, "GET", base+"/v1/metrics", nil, nil); s != 200 {
		t.Errorf("metrics as link.control: %d", s)
	}
	for _, p := range []string{"/v1/info", "/v1/projects/x/up", "/v1/containers"} {
		m := "GET"
		if strings.HasSuffix(p, "/up") {
			m = "POST"
		}
		if s := do(t, lc, m, base+p, nil, nil); s != 403 {
			t.Errorf("link.control on %s: %d", p, s)
		}
	}
	if s := do(t, c, "GET", base+"/v1/enrol/nonce", nil, nil); s != 403 && s != 409 {
		t.Errorf("enrol after ready: %d", s)
	}
	// Renewal: a CSR from a new key, swapped on PUT cert.
	var ren agentapi.IdentityCSR
	if s := do(t, c, "POST", base+"/v1/identity/csr", nil, &ren); s != 200 || ren.WGPublicKey != newWG.String() {
		t.Fatalf("renew csr: %d %+v", s, ren)
	}
	if s := do(t, c, "PUT", base+"/v1/identity/cert", agentapi.IdentityCert{Certificate: pemOf(ca.signCSR(t, ren.CSR)), CA: pemOf(ca.cert)}, nil); s != 204 {
		t.Errorf("renew cert: %d", s)
	}
	// A restart loads the ready identity.
	b, err := New(Config{DataDir: data, Runtime: "docker"})
	if err != nil || b.State() != StateReady {
		t.Fatalf("reload: %v", err)
	}
}

// TestKeySwitchFallsBack: no handshake on the new key → back to the
// bootstrap key, the enrolment can retry from PUT /v1/identity/wg.
func TestKeySwitchFallsBack(t *testing.T) {
	l := newLink(t, "10.214.0.1")
	ca := newCA(t, "ca")
	a, code, _ := enrolling(t, l, ca, time.Now)
	a.cfg.SwitchTimeout = 500 * time.Millisecond
	boot, _ := ParseKey(code.BootstrapKey)
	tun := upTunnel(t, l, boot, netip.Addr{})
	a.AttachTunnel(tun)
	a.mu.Lock()
	a.phase, a.hasPendingWG = phaseSwitched, true
	a.pendingWG, _ = GenerateKey()
	a.mu.Unlock()
	a.switchKey()
	a.mu.Lock()
	phase := a.phase
	a.mu.Unlock()
	if phase != phaseCertSet || a.State() != StateEnrolling {
		t.Fatalf("phase %s state %s", phase, a.State())
	}
	// The bootstrap key works again (link still has it as the peer).
	ln, _ := tun.Listen(ControlPort)
	acceptAll(t, ln)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cn, err := l.dial(ctx, netip.AddrPortFrom(agentIP, ControlPort))
	if err != nil {
		t.Fatalf("bootstrap key after the fallback: %v", err)
	}
	cn.Close()
}

func TestControlCertPins(t *testing.T) {
	ca := newCA(t, "example.org Node CA")
	pkiInt := newCA(t, "example.org Intermediate CA")
	now := time.Now()
	chain := func(c *x509.Certificate, issuer *x509.Certificate) [][]byte { return [][]byte{c.Raw, issuer.Raw} }
	leaf := func(ca *testCA, cn string, usage ...x509.ExtKeyUsage) *x509.Certificate {
		c, _ := ca.issue(t, cn, nil, now.Add(-time.Minute), now.Add(time.Hour), usage...)
		return c
	}
	for name, c := range map[string]struct {
		raw  [][]byte
		want string
	}{
		"hub.control":                 {chain(leaf(ca, CNControl, x509.ExtKeyUsageClientAuth), ca.cert), CNControl},
		"link.control":                {chain(leaf(ca, CNLink, x509.ExtKeyUsageClientAuth), ca.cert), CNLink},
		"a person's pki_int cert":     {chain(leaf(pkiInt, "alice", x509.ExtKeyUsageClientAuth), pkiInt.cert), ""},
		"hub.control from another CA": {chain(leaf(pkiInt, CNControl, x509.ExtKeyUsageClientAuth), pkiInt.cert), ""},
		"a node certificate":          {chain(leaf(ca, "x.node.portcullis.internal", x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth), ca.cert), ""},
		"server auth only":            {chain(leaf(ca, CNControl, x509.ExtKeyUsageServerAuth), ca.cert), ""},
		"no certificate":              {nil, ""},
		"the CA itself as a leaf":     {[][]byte{ca.cert.Raw}, ""},
	} {
		cn, err := verifyControl(c.raw, ca.cert, now)
		if c.want == "" && err == nil || c.want != "" && (err != nil || cn != c.want) {
			t.Errorf("%s: %q %v", name, cn, err)
		}
	}
	// While enrolling, the CA comes only from the chain by its sha256.
	if _, err := caFromChain(chain(leaf(ca, CNControl, x509.ExtKeyUsageClientAuth), ca.cert), pkiInt.sha()); err == nil {
		t.Error("a chain without the pinned CA accepted")
	}
	if got, err := caFromChain(chain(leaf(ca, CNControl, x509.ExtKeyUsageClientAuth), ca.cert), ca.sha()); err != nil || !got.Equal(ca.cert) {
		t.Errorf("pinned CA: %v", err)
	}
}

func TestAgentClockTolerance(t *testing.T) {
	ca := newCA(t, "ca")
	now := time.Now()
	ok, _ := ca.issue(t, CNControl, nil, now.Add(4*time.Minute), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	if _, err := verifyControl([][]byte{ok.Raw, ca.cert.Raw}, ca.cert, now); err != nil {
		t.Errorf("valid from now+4m: %v", err)
	}
	late, _ := ca.issue(t, CNControl, nil, now.Add(6*time.Minute), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	_, err := verifyControl([][]byte{late.Raw, ca.cert.Raw}, ca.cert, now)
	if err == nil || !strings.Contains(err.Error(), "clock") || !errors.Is(err, ErrClock) {
		t.Errorf("valid from now+6m: %v", err)
	}
	expired, _ := ca.issue(t, CNControl, nil, now.Add(-2*time.Hour), now.Add(-4*time.Minute), x509.ExtKeyUsageClientAuth)
	if _, err := verifyControl([][]byte{expired.Raw, ca.cert.Raw}, ca.cert, now); err != nil {
		t.Errorf("expired 4 min ago (within tolerance): %v", err)
	}
	other := newCA(t, "other")
	foreign, _ := other.issue(t, CNControl, nil, now.Add(6*time.Minute), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	if _, err := verifyControl([][]byte{foreign.Raw}, ca.cert, now); err == nil || errors.Is(err, ErrClock) {
		t.Errorf("another CA's future cert reads as a clock problem: %v", err)
	}
}
