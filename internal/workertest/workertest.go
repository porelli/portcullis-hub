// Package workertest is the shared real-agent test harness (final review
// structural guard): a real portcullis-agent (internal/agent's Agent and
// API) in the ready state, its identity written as enrolment leaves it,
// with an in-memory engine (runtimetest.Fake) behind it, served over TLS
// on loopback, and the real Hub-side backend (internal/runtime/agent)
// pinned to it. Faults are injected at the HTTP layer (Fail, Hook: the
// agent's real error shape) or at the engine (runtimetest.Fake's ErrOn).
// Tests only.
package workertest

import (
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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	wagent "github.com/portcullis/hub/internal/agent"
	"github.com/portcullis/hub/internal/agent/agenttest"
	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
)

// PKI is a test CA.
type PKI struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
	n    int64
}

// NewPKI is a fresh CA named name.
func NewPKI(t testing.TB, name string) *PKI {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &PKI{Key: k, Cert: c, n: 100}
}

// Issue is a leaf for cn (a node name also gets its DNS name).
func (p *PKI) Issue(t testing.TB, cn string, usage ...x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.n++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.n * 7919), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	if strings.HasSuffix(cn, ".node.portcullis.internal") {
		tpl.DNSNames = []string{cn}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.Cert, &k.PublicKey, p.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

// PEMCert / PEMKey encode a certificate and a key.
func PEMCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func PEMKey(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Opts shape a worker; zero values are the defaults.
type Opts struct {
	ServerID  string   // "nas"
	TunnelIP  string   // "10.214.0.10"
	BindRoots []string // {"/srv", "/mnt"}
	Runtime   string   // "docker"
	// Info answers the engine's part of /v1/info (default: Docker 29,
	// API 1.45, root /var/lib/docker, SELinux); the agent fills its own
	// fields (version, runtime, bind roots, data dir, clock, quarantine).
	Info func(context.Context) (agentapi.Info, error)
	// HelperImage is the agent's pinned helper image.
	HelperImage string
}

// Worker is one in-process worker.
type Worker struct {
	ID, TunnelIP string
	CA           *PKI
	Node         *x509.Certificate
	Control      tls.Certificate
	Engine       *runtimetest.Fake
	API          *wagent.API
	Agent        *wagent.Agent
	Server       *httptest.Server
	DataDir      string

	mu       sync.Mutex
	requests []string
	faults   []*fault
}

type fault struct {
	re     *regexp.Regexp
	times  int // < 0: always
	status int
	msg    string
	hook   func(r *http.Request)
	drop   bool // the connection drops (no answer)
}

// DefaultHelperImage is the harness agent's helper image: the one the
// Hub's own backend pins (dockerrt.HelperImage), as in production.
var DefaultHelperImage = dockerrt.HelperImage

// NewWorker starts a ready worker (closed at the test's end).
func NewWorker(t testing.TB, o Opts) *Worker {
	t.Helper()
	if o.ServerID == "" {
		o.ServerID = "nas"
	}
	if o.TunnelIP == "" {
		o.TunnelIP = "10.214.0.10"
	}
	if o.BindRoots == nil {
		o.BindRoots = []string{"/srv", "/mnt"}
	}
	if o.Runtime == "" {
		o.Runtime = "docker"
	}
	if o.HelperImage == "" {
		o.HelperImage = DefaultHelperImage
	}
	if o.Info == nil {
		o.Info = func(context.Context) (agentapi.Info, error) {
			return agentapi.Info{EngineVersion: "29.0", EngineAPI: "1.45", DockerRootDir: "/var/lib/docker", SELinux: true, Arch: "amd64",
				CPUs: 4, MemBytes: 8 << 30, DiskTotal: 1 << 40, DiskFree: 1 << 39, UnprivilegedPortStart: 1024}, nil
		}
	}
	ca := NewPKI(t, "example.org Node CA")
	node, nodeKey := ca.Issue(t, o.ServerID+".node.portcullis.internal", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	ctl, ctlKey := ca.Issue(t, wagent.CNControl, x509.ExtKeyUsageClientAuth)
	data := t.TempDir()
	if real, err := filepath.EvalSymlinks(data); err == nil {
		data = real // the agent's walks refuse a symlinked path (macOS /var)
	}
	id := filepath.Join(data, "identity")
	os.MkdirAll(id, 0o700)
	wg, _ := wagent.GenerateKey()
	link, _ := wagent.GenerateKey()
	sum := sha256.Sum256(ca.Cert.Raw)
	pins, _ := json.Marshal(wagent.Pins{State: wagent.StateReady, ServerID: o.ServerID, TunnelIP: o.TunnelIP, Endpoint: "example.org:51821",
		LinkPub: link.Public().String(), CASHA256: hex.EncodeToString(sum[:])})
	for name, b := range map[string][]byte{"pins.json": pins, "ca.crt": PEMCert(ca.Cert), "tls.crt": PEMCert(node), "tls.key": PEMKey(nodeKey), "wg.key": []byte(wg.String() + "\n")} {
		os.WriteFile(filepath.Join(id, name), b, 0o600)
	}
	engine := &runtimetest.Fake{Infos: map[string]runtime.UnitInfo{}, Volumes: map[string]runtime.Volume{}, LogsVal: map[string][]byte{},
		States: map[string]runtime.State{}, Contents: map[string][]byte{}, DownRemovesUnits: true}
	api := wagent.NewAPI(wagent.APIConfig{DataDir: data, BindRoots: o.BindRoots, Runtime: engine, SelfImage: "sha256:agent", Config: agenttest.Config,
		HelperImage: o.HelperImage})
	// The info cmd/portcullis-agent serves: the engine's part, plus the
	// API's live quarantine (and its save error).
	engineInfo := o.Info
	info := func(ctx context.Context) (agentapi.Info, error) {
		i, err := engineInfo(ctx)
		if err != nil {
			return i, err
		}
		i.Quarantined = api.Quarantined()
		i.QuarantineError = api.QuarantineError()
		return i, nil
	}
	a, err := wagent.New(wagent.Config{DataDir: data, Runtime: o.Runtime, BindRoots: o.BindRoots, Routes: api, Info: info})
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{ID: o.ServerID, TunnelIP: o.TunnelIP, CA: ca, Node: node, Control: tls.Certificate{Certificate: [][]byte{ctl.Raw}, PrivateKey: ctlKey, Leaf: ctl},
		Engine: engine, API: api, Agent: a, DataDir: data}
	srv := httptest.NewUnstartedServer(w.middleware(a.Handler()))
	srv.TLS = a.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	w.Server = srv
	return w
}

// middleware records each request ("METHOD path") and applies faults.
func (w *Worker) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		w.mu.Lock()
		w.requests = append(w.requests, key)
		var hit *fault
		for _, f := range w.faults {
			if f.times != 0 && f.re.MatchString(key) {
				hit = f
				if f.times > 0 {
					f.times--
				}
				break
			}
		}
		w.mu.Unlock()
		if hit != nil {
			if hit.hook != nil {
				hit.hook(r)
			}
			if hit.drop {
				// The transport drops mid-request: no answer at all.
				panic(http.ErrAbortHandler)
			}
			if hit.status != 0 {
				rw.Header().Set("Content-Type", "application/json")
				rw.WriteHeader(hit.status)
				rw.Write(agentapi.ErrorBody(hit.msg))
				return
			}
		}
		next.ServeHTTP(rw, r)
	})
}

// Fail answers the next times requests matching pattern (a regexp over
// "METHOD /path"; times < 0: always) with status and the agent's error
// body msg, without reaching the agent.
func (w *Worker) Fail(pattern string, times, status int, msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults = append(w.faults, &fault{re: regexp.MustCompile(pattern), times: times, status: status, msg: msg})
}

// Hook runs fn on the next times matching requests, then lets them through.
func (w *Worker) Hook(pattern string, times int, fn func(r *http.Request)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults = append(w.faults, &fault{re: regexp.MustCompile(pattern), times: times, hook: fn})
}

// Drop drops the connection of the next times requests matching pattern
// (after reading nothing more: a lost tunnel), without reaching the agent.
func (w *Worker) Drop(pattern string, times int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults = append(w.faults, &fault{re: regexp.MustCompile(pattern), times: times, drop: true})
}

// ClearFaults drops every fault and hook.
func (w *Worker) ClearFaults() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults = nil
}

// Requests are the requests the worker got, in order ("PUT /v1/projects/x/bundle").
func (w *Worker) Requests() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.requests...)
}

// Got: some request matched pattern.
func (w *Worker) Got(pattern string) bool {
	re := regexp.MustCompile(pattern)
	for _, r := range w.Requests() {
		if re.MatchString(r) {
			return true
		}
	}
	return false
}

// Dialer dials the worker's loopback listener whatever the address (the
// tunnel stand-in), recording what was asked.
type Dialer struct {
	addr  string
	mu    sync.Mutex
	asked string
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.asked = addr
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.addr)
}

// Asked is the last address dialed.
func (d *Dialer) Asked() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.asked
}

// Config is the backend configuration pinned to w.
func (w *Worker) Config() (agentrt.Config, *Dialer) {
	sum := sha256.Sum256(w.Node.RawSubjectPublicKeyInfo)
	d := &Dialer{addr: w.Server.Listener.Addr().String()}
	return agentrt.Config{ServerID: w.ID, TunnelIP: netip.MustParseAddr(w.TunnelIP), CACert: w.CA.Cert, SPKI: sum[:],
		Serial: hex.EncodeToString(w.Node.SerialNumber.Bytes()), ControlCert: w.Control, Dial: d, Kind: runtime.KindDocker}, d
}

// Backend is the real Hub-side backend pinned to w (mutate adjusts its
// configuration first).
func (w *Worker) Backend(mutate func(*agentrt.Config)) (*agentrt.Backend, *Dialer) {
	cfg, d := w.Config()
	if mutate != nil {
		mutate(&cfg)
	}
	return agentrt.New(cfg), d
}

// DialerTo dials addr whatever the address asked.
func DialerTo(addr string) *Dialer { return &Dialer{addr: addr} }
