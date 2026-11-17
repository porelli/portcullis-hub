package agent

import (
	"archive/tar"
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
	"github.com/portcullis/hub/internal/servers"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	wagent "github.com/portcullis/hub/internal/agent"
	"github.com/portcullis/hub/internal/agent/agenttest"
	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fixerspec"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
)

type pki struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	n    int64
}

func newPKI(t *testing.T, name string) *pki {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{key: k, cert: c, n: 100}
}

func (p *pki) issue(t *testing.T, cn string, usage ...x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.n++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.n * 7919), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	if strings.HasSuffix(cn, ".node.portcullis.internal") {
		tpl.DNSNames = []string{cn}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.cert, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func pemKey(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// fakeWorker is a real portcullis-agent (internal/agent) in the ready
// state, its identity written as enrolment leaves it, with an in-memory
// engine behind it, served over TLS on loopback.
type fakeWorker struct {
	ca       *pki
	node     *x509.Certificate
	control  tls.Certificate
	engine   *runtimetest.Fake
	srv      *httptest.Server
	dataDir  string
	listener string
}

func newWorker(t *testing.T) *fakeWorker {
	ca := newPKI(t, "example.org Node CA")
	node, nodeKey := ca.issue(t, "nas.node.portcullis.internal", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	ctl, ctlKey := ca.issue(t, wagent.CNControl, x509.ExtKeyUsageClientAuth)
	data := t.TempDir()
	id := filepath.Join(data, "identity")
	os.MkdirAll(id, 0o700)
	wg, _ := wagent.GenerateKey()
	link, _ := wagent.GenerateKey()
	sum := sha256.Sum256(ca.cert.Raw)
	pins, _ := json.Marshal(wagent.Pins{State: wagent.StateReady, ServerID: "nas", TunnelIP: "10.214.0.10", Endpoint: "example.org:51821",
		LinkPub: link.Public().String(), CASHA256: hex.EncodeToString(sum[:])})
	for name, b := range map[string][]byte{"pins.json": pins, "ca.crt": pemCert(ca.cert), "tls.crt": pemCert(node), "tls.key": pemKey(nodeKey), "wg.key": []byte(wg.String() + "\n")} {
		os.WriteFile(filepath.Join(id, name), b, 0o600)
	}
	engine := &runtimetest.Fake{Infos: map[string]runtime.UnitInfo{}, Volumes: map[string]runtime.Volume{}, LogsVal: map[string][]byte{}, States: map[string]runtime.State{}, Contents: map[string][]byte{}}
	api := wagent.NewAPI(wagent.APIConfig{DataDir: data, BindRoots: []string{"/srv"}, Runtime: engine, SelfImage: "sha256:agent", Config: agenttest.Config,
		HelperImage: "docker.io/library/alpine:3@sha256:" + strings.Repeat("a", 64)})
	a, err := wagent.New(wagent.Config{DataDir: data, Runtime: "docker", Routes: api,
		Info: func(context.Context) (agentapi.Info, error) {
			return agentapi.Info{EngineVersion: "29.0", EngineAPI: "1.45", DockerRootDir: "/var/lib/docker", SELinux: true}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = a.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &fakeWorker{ca: ca, node: node, control: tls.Certificate{Certificate: [][]byte{ctl.Raw}, PrivateKey: ctlKey, Leaf: ctl},
		engine: engine, srv: srv, dataDir: data, listener: srv.Listener.Addr().String()}
}

// dialTo dials the worker's loopback listener whatever the address (the
// tunnel stand-in), recording what was asked.
type dialTo struct{ addr, asked string }

func (d *dialTo) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.asked = addr
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.addr)
}

func (w *fakeWorker) backend(t *testing.T, mutate func(*Config)) (*Backend, *dialTo) {
	sum := sha256.Sum256(w.node.RawSubjectPublicKeyInfo)
	d := &dialTo{addr: w.listener}
	cfg := Config{ServerID: "nas", TunnelIP: netip.MustParseAddr("10.214.0.10"), CACert: w.ca.cert, SPKI: sum[:],
		Serial: hex.EncodeToString(w.node.SerialNumber.Bytes()), ControlCert: w.control, Dial: d, Kind: runtime.KindDocker}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg), d
}

const compose = `services:
  web:
    image: ghcr.io/example/app:1
    volumes: ["data:/data"]
    labels:
      traefik.http.services.app.loadbalancer.server.port: "8080"
volumes:
  data: {}
`

func pushBundle(t *testing.T, b *Backend) {
	files := fstest.MapFS{"compose.yml": {Data: []byte(compose), Mode: 0o644}, "env": {Data: []byte("A=1\n"), Mode: 0o600}}
	m := agentapi.BundleManifest{Instance: "app", Template: "app", Volumes: map[string]string{"data": "portcullis-app_data"}, Files: map[string]agentapi.FileEntry{}}
	for n, f := range files {
		s := sha256.Sum256(f.Data)
		m.Files[n] = agentapi.FileEntry{SHA256: hex.EncodeToString(s[:]), Mode: uint32(f.Mode), Size: int64(len(f.Data))}
	}
	if err := b.PushBundle(context.Background(), "app", files, m); err != nil {
		t.Fatalf("PushBundle: %v", err)
	}
}

func volTar(t *testing.T) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "data/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	tw.Write([]byte("hi"))
	tw.Close()
	return buf.Bytes()
}

// TestAgentBackendAgainstFakeAgent: every runtime.Instances method of the
// backend reaches the worker's engine through its route, end to end
// (pinned mTLS, the agent's scope checks, the wire types).
func TestAgentBackendAgainstFakeAgent(t *testing.T) {
	w := newWorker(t)
	b, d := w.backend(t, nil)
	ctx := context.Background()
	pushBundle(t, b)
	if d.asked != "10.214.0.10:7443" {
		t.Errorf("dialed %q", d.asked)
	}
	mine := map[string]string{docker.LabelProject: "portcullis-app", docker.LabelService: "web"}
	w.engine.Units = []runtime.Unit{{ID: "c1", Project: "portcullis-app", Instance: "app", Service: "web", State: "running", Labels: mine}}
	w.engine.Infos["c1"] = runtime.UnitInfo{ID: "c1", Labels: mine, Image: "sha256:x"}
	w.engine.LogsVal["c1"] = []byte("log line\n")
	w.engine.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	w.engine.Contents["portcullis-app_data"] = volTar(t)
	p := runtime.Project{Name: "portcullis-app", Instance: "app"}
	check := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	info, err := b.Info(ctx)
	check("Info", err)
	if info.Kind != runtime.KindDocker || !info.SELinux || len(info.ForbiddenRoots) != 1 || info.ForbiddenRoots[0] != "/var/lib/docker" || info.APIVersion != "1.45" {
		t.Errorf("info %+v", info)
	}
	check("Create", b.Create(ctx, p))
	var pulled int
	check("Up", b.Up(ctx, p, func(string, int64, int64, bool) { pulled++ }))
	check("Down", b.Down(ctx, p))
	check("DownByName", b.DownByName(ctx, "portcullis-app"))
	check("Pull", b.Pull(ctx, "ghcr.io/example/app:1", nil))
	check("EnsureImage", b.EnsureImage(ctx, "ghcr.io/example/app:1"))
	us, err := b.List(ctx, runtime.Filter{Instance: "app"})
	check("List", err)
	if len(us) != 1 || us[0].ID != "c1" {
		t.Errorf("units %+v", us)
	}
	ui, err := b.Inspect(ctx, "c1")
	check("Inspect", err)
	if ui.Image != "sha256:x" {
		t.Errorf("inspect %+v", ui)
	}
	logs, err := b.Logs(ctx, "c1", 10, true)
	check("Logs", err)
	if string(logs) != "log line\n" {
		t.Errorf("logs %q", logs)
	}
	_, err = b.Exec(ctx, "c1", runtime.ExecInput{Cmd: []string{"id"}, Timeout: time.Second})
	check("Exec", err)
	_, err = b.ExecSplit(ctx, "c1", runtime.ExecInput{Cmd: []string{"id"}, Timeout: time.Second})
	check("ExecSplit", err)
	if _, err := b.ExecRunning(ctx, "never-started"); err == nil {
		t.Error("ExecRunning of a foreign exec answered")
	}
	check("Signal", b.Signal(ctx, "c1", "HUP"))
	_, err = b.State(ctx, "c1")
	check("State", err)
	ectx, cancel := context.WithTimeout(ctx, 2*time.Second)
	b.Events(ectx, runtime.Filter{}, func(runtime.Event) {})
	cancel()
	vs, err := b.ListVolumes(ctx, runtime.Filter{})
	check("ListVolumes", err)
	if len(vs) != 1 {
		t.Errorf("volumes %+v", vs)
	}
	_, err = b.InspectVolume(ctx, "portcullis-app_data")
	check("InspectVolume", err)
	rc, err := b.VolumeOut(ctx, "app", "portcullis-app_data", "/data")
	check("VolumeOut", err)
	if rc != nil {
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, volTar(t)) {
			t.Errorf("VolumeOut %d bytes", len(got))
		}
	}
	check("VolumeIn", b.VolumeIn(ctx, "app", "portcullis-app_data", "/data", bytes.NewReader(volTar(t))))
	check("CreateVolume", b.CreateVolume(ctx, runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}))
	check("RemoveVolume", b.RemoveVolume(ctx, "portcullis-app_data"))
	spec := fixerspec.Run{Mode: "scan", Source: "/srv/photos"}.Spec("sha256:hub", wagent.AgentBinary)
	_, err = b.RunFixer(ctx, spec, nil)
	check("RunFixer", err)
	if err := b.RemoveHelper(ctx, "nope"); err == nil || !docker.IsNotFound(err) {
		t.Errorf("RemoveHelper of nothing: %v (want a not-found)", err)
	}
	check("DeliverFile", b.DeliverFile(ctx, "app", runtime.FileDelivery{Name: "settings", Data: []byte("{}"), Secrets: []byte("{}")}))
	calls := strings.Join(w.engine.Calls(), "\n")
	for _, want := range []string{"create portcullis-app", "up portcullis-app", "down portcullis-app", "down-by-name portcullis-app", "pull ghcr.io/example/app:1",
		"ensure-image ghcr.io/example/app:1", "exec c1", "exec-split c1", "signal c1 HUP", "fixer [" + wagent.AgentBinary + " folderfix scan"} {
		if !strings.Contains(calls, want) {
			t.Errorf("the engine never got %q:\n%s", want, calls)
		}
	}
	if _, err := os.Stat(filepath.Join(w.dataDir, "appfiles", "app", "settings", "settings.secrets.json")); err != nil {
		t.Errorf("delivered file: %v", err)
	}
	// Refusals come back with the agent's status.
	err = b.Create(ctx, runtime.Project{Name: "portcullis-other", Instance: "other"})
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != http.StatusNotFound {
		t.Errorf("an unbundled project: %v", err)
	}
	if err := b.DownByName(ctx, "portcullis"); err == nil {
		t.Error("core's project name accepted")
	}
}

// TestIdentityMismatch: a worker presenting another certificate than the
// pinned one (another server's, a renewed serial not in state, another
// CA) is refused before any request, and OnMismatch fires.
func TestIdentityMismatch(t *testing.T) {
	w := newWorker(t)
	other := newWorker(t)
	for name, mut := range map[string]func(*Config){
		"another serial":     func(c *Config) { c.Serial = "01" },
		"another SPKI":       func(c *Config) { c.SPKI = make([]byte, 32) },
		"another server id":  func(c *Config) { c.ServerID = "nas2" },
		"another server's":   func(c *Config) { c.Dial = &dialTo{addr: other.listener} },
		"another CA trusted": func(c *Config) { c.CACert = other.ca.cert },
	} {
		mismatch := false
		b, _ := w.backend(t, func(c *Config) { mut(c); c.OnMismatch = func() { mismatch = true } })
		_, err := b.AgentInfo(context.Background())
		var ae *Error
		if err == nil || !errors.As(err, &ae) || ae.Status != http.StatusBadGateway {
			t.Errorf("%s: %v", name, err)
		}
		if (name == "another serial" || name == "another SPKI") && (!mismatch || !errors.Is(err, ErrIdentityMismatch)) {
			t.Errorf("%s: mismatch %v err %v", name, mismatch, err)
		}
	}
	b, _ := w.backend(t, nil)
	if _, err := b.AgentInfo(context.Background()); err != nil {
		t.Errorf("the pinned identity: %v", err)
	}
}

// TestOversizedInfoCut: an /v1/info over 64 KiB is an error, never a
// partial decode; a JSON answer with an unknown key is refused too.
func TestOversizedInfoCut(t *testing.T) {
	w := newWorker(t)
	for name, body := range map[string]string{
		"oversized":   `{"agent_version":"` + strings.Repeat("x", agentapi.MaxInfo) + `"}`,
		"unknown key": `{"agent_version":"1.0.0","api":"v1","runtime":"docker","arch":"amd64","engine_version":"x","cpus":1,"mem_bytes":1,"docker_root_dir":"/","disk_total":0,"disk_free":0,"data_dir":"/d","data_total":0,"data_free":0,"unprivileged_port_start":1024,"clock":"2026-11-15T00:00:00Z","evil":1}`,
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { io.WriteString(rw, body) }),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{w.serverCert(t)}, ClientAuth: tls.RequireAnyClientCert}}
		go srv.ServeTLS(ln, "", "")
		b, _ := w.backend(t, func(c *Config) { c.Dial = &dialTo{addr: ln.Addr().String()} })
		if _, err := b.AgentInfo(context.Background()); err == nil {
			t.Errorf("%s: decoded", name)
		}
		srv.Close()
	}
}

func (w *fakeWorker) serverCert(t *testing.T) tls.Certificate {
	key, _ := os.ReadFile(filepath.Join(w.dataDir, "identity", "tls.key"))
	crt, _ := os.ReadFile(filepath.Join(w.dataDir, "identity", "tls.crt"))
	c, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAgentVersionGate: an agent outside {the Hub's minor, the one
// before} gets no call but /v1/info: 409 server_agent_incompatible.
func TestAgentVersionGate(t *testing.T) {
	w := newWorker(t)
	ctx := context.Background()
	for hub, ok := range map[string]bool{wagent.Version: true, "0.2.0": true, "0.3.0": false, "1.1.0": false, "edge": false} {
		b, _ := w.backend(t, func(c *Config) { c.HubVersion = hub })
		_, err := b.List(ctx, runtime.Filter{})
		var ae *Error
		if ok && err != nil {
			t.Errorf("hub %s: %v", hub, err)
		}
		if !ok && (!errors.As(err, &ae) || ae.Status != http.StatusConflict || !errors.Is(err, ErrIncompatible) || !strings.Contains(err.Error(), "server_agent_incompatible")) {
			t.Errorf("hub %s (agent %s): %v", hub, wagent.Version, err)
		}
		if _, err := b.AgentInfo(ctx); err != nil {
			t.Errorf("hub %s: /v1/info refused: %v", hub, err)
		}
	}
}

// TestAgentStatusPolicy (commit review): a worker's status passes only
// when it is 400/404/409/422/503 (message sanitized, capped); anything
// else is 502 "the server <id> answered unexpectedly".
func TestAgentStatusPolicy(t *testing.T) {
	w := newWorker(t)
	for _, c := range []struct {
		status int
		body   string
		want   int
		msg    string
	}{
		{401, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{302, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{999, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{500, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{403, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{409, `{"error":"in use\u001b[31m now"}`, 409, "in use [31m now"},
		{503, `not json`, 503, "the server nas refused the call"},
		{404, `{"error":"` + strings.Repeat("y", 500) + `"}`, 404, ""},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		info := `{"agent_version":"` + wagent.Version + `","api":"v1","runtime":"docker","arch":"amd64","engine_version":"x","cpus":1,"mem_bytes":1,"docker_root_dir":"/","disk_total":0,"disk_free":0,"data_dir":"/d","data_total":0,"data_free":0,"unprivileged_port_start":1024,"clock":"2026-11-15T00:00:00Z"}`
		srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/info" {
				io.WriteString(rw, info)
				return
			}
			rw.WriteHeader(c.status)
			io.WriteString(rw, c.body)
		}), TLSConfig: &tls.Config{Certificates: []tls.Certificate{w.serverCert(t)}, ClientAuth: tls.RequireAnyClientCert}}
		go srv.ServeTLS(ln, "", "")
		b, _ := w.backend(t, func(cfg *Config) { cfg.Dial = &dialTo{addr: ln.Addr().String()} })
		err := b.Down(context.Background(), runtime.Project{Instance: "app"})
		var ae *Error
		if !errors.As(err, &ae) || ae.Status != c.want || (c.msg != "" && ae.Msg != c.msg) || len([]rune(ae.Msg)) > 200 {
			t.Errorf("%d: %v (%+v)", c.status, err, ae)
		}
		srv.Close()
	}
}

// TestHelperCleanupBounded (review B-L6): a worker that never answers a
// helper's removal can't hold the Hub: deleteHelper ends at its timeout.
func TestHelperCleanupBounded(t *testing.T) {
	w := newWorker(t)
	block := make(chan struct{})
	defer close(block)
	orig := w.srv.Config.Handler
	w.srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/helpers/") {
			select {
			case <-block:
			case <-r.Context().Done():
			}
			return
		}
		orig.ServeHTTP(rw, r)
	})
	old := HelperCleanupTimeout
	HelperCleanupTimeout = 200 * time.Millisecond
	defer func() { HelperCleanupTimeout = old }()
	b, _ := w.backend(t, nil)
	start := time.Now()
	b.deleteHelper("h1")
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("deleteHelper took %s", d)
	}
}

// TestEnrollingPeerSPKIIsTheDER: in enrolling mode PeerSPKI is the DER
// SubjectPublicKeyInfo of the worker's certificate, the value the agent
// binds into the proof (internal/agent/enrol.go): a proof the Hub makes
// with it verifies the agent's way (CI e2e-servers: a hash here made every
// enrolment fail "the worker refused the enrolment proof").
func TestEnrollingPeerSPKIIsTheDER(t *testing.T) {
	w := newWorker(t)
	b, _ := w.backend(t, func(c *Config) { c.Enrolling = true })
	b.AgentInfo(context.Background())
	got := b.PeerSPKI()
	if !bytes.Equal(got, w.node.RawSubjectPublicKeyInfo) {
		t.Fatalf("PeerSPKI is %d bytes, not the certificate's DER SPKI (%d bytes)", len(got), len(w.node.RawSubjectPublicKeyInfo))
	}
	secret, nonce := bytes.Repeat([]byte{7}, servers.SecretLen), bytes.Repeat([]byte{9}, servers.NonceLen)
	if !servers.VerifyProof(secret, nonce, "nas", w.node.RawSubjectPublicKeyInfo, servers.Proof(secret, nonce, "nas", got)) {
		t.Fatal("the Hub's proof doesn't verify the agent's way")
	}
}

// TestPreflightPullOverTheWire: the placement pre-pull against the real
// agent API with no bundle: a pinned ref pulls, an unpinned one is the
// agent's 400, and a plain Pull of the same ref is refused (imageOK).
func TestPreflightPullOverTheWire(t *testing.T) {
	w := newWorker(t)
	b, _ := w.backend(t, nil)
	ref := "docker.io/library/busybox:1@sha256:" + strings.Repeat("e", 64)
	if err := b.Pull(context.Background(), ref, nil); err == nil {
		t.Fatal("a plain pull without a bundle was accepted")
	}
	if err := b.PreflightPull(context.Background(), ref); err != nil {
		t.Fatalf("PreflightPull: %v", err)
	}
	if !slices.Contains(w.engine.Calls(), "pull "+ref) {
		t.Errorf("the engine never pulled %s: %v", ref, w.engine.Calls())
	}
	if err := b.PreflightPull(context.Background(), "docker.io/library/busybox:1"); err == nil || !strings.Contains(err.Error(), "pinned by digest") {
		t.Errorf("an unpinned preflight: %v", err)
	}
}
