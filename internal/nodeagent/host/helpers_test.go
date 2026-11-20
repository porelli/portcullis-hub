package host

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
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
)

// ── a test pki_node ──

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var serial int64 = 100

func newCA(t testing.TB) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test pki_node CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// sign issues a certificate for pub with cn (and cn as DNS SAN).
func (ca *testCA) sign(t testing.TB, cn string, pub any) []byte {
	return ca.signFor(t, cn, pub, time.Now().Add(-time.Hour), time.Now().Add(12*time.Hour))
}

func (ca *testCA) signFor(t testing.TB, cn string, pub any, nb, na time.Time) []byte {
	serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (ca *testCA) tlsCert(t testing.TB, cn string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := ca.sign(t, cn, &k.PublicKey)
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: k}
}

// ── a fake host ──

type fakeWG struct {
	mu         sync.Mutex
	exists     bool
	dev        wgtypes.Device
	configures int
}

func (f *fakeWG) Device(name string) (*wgtypes.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.exists || name != na.MeshIface {
		return nil, os.ErrNotExist
	}
	d := f.dev
	d.Peers = append([]wgtypes.Peer(nil), f.dev.Peers...)
	return &d, nil
}

func (f *fakeWG) ConfigureDevice(name string, c wgtypes.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.exists {
		return os.ErrNotExist
	}
	f.configures++
	if c.PrivateKey != nil {
		f.dev.PrivateKey = *c.PrivateKey
	}
	if c.ListenPort != nil {
		f.dev.ListenPort = *c.ListenPort
	}
	for _, p := range c.Peers {
		i := -1
		for j, h := range f.dev.Peers {
			if h.PublicKey == p.PublicKey {
				i = j
			}
		}
		if p.Remove {
			if i >= 0 {
				f.dev.Peers = append(f.dev.Peers[:i], f.dev.Peers[i+1:]...)
			}
			continue
		}
		np := wgtypes.Peer{PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs}
		if p.PersistentKeepaliveInterval != nil {
			np.PersistentKeepaliveInterval = *p.PersistentKeepaliveInterval
		}
		if i >= 0 {
			f.dev.Peers[i] = np
		} else {
			f.dev.Peers = append(f.dev.Peers, np)
		}
	}
	return nil
}

func (f *fakeWG) peerConfigures() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.configures
}

type fakeRun struct {
	mu     sync.Mutex
	wg     *fakeWG
	cmds   []Cmd
	rules  []string // PORTCULLIS-MESH
	jump   bool
	active map[string]bool
	fail   map[string]error // by "name arg0"
}

func (f *fakeRun) Run(_ context.Context, c Cmd) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, c)
	key := c.Name
	if len(c.Args) > 0 {
		key += " " + c.Args[0]
	}
	if err := f.fail[key]; err != nil {
		return nil, err
	}
	switch {
	case c.Name == "ip" && strings.Join(c.Args, " ") == "link add dev pcmesh type wireguard":
		if f.wg != nil {
			f.wg.mu.Lock()
			f.wg.exists = true
			f.wg.mu.Unlock()
		}
	case c.Name == "iptables-restore":
		f.rules = nil
		for _, l := range strings.Split(string(c.Stdin), "\n") {
			if strings.HasPrefix(l, "-A ") {
				f.rules = append(f.rules, l)
			}
		}
	case c.Name == "iptables" && len(c.Args) >= 3 && c.Args[2] == "-S":
		if f.rules == nil {
			return nil, errors.New("iptables exited 1")
		}
		out := "-N " + meshChain + "\n"
		for _, r := range f.rules {
			out += strings.Replace(r, "ESTABLISHED,RELATED", "RELATED,ESTABLISHED", 1) + "\n"
		}
		return []byte(out), nil
	case c.Name == "iptables" && len(c.Args) >= 3 && c.Args[2] == "-C":
		if !f.jump {
			return nil, errors.New("iptables exited 1")
		}
	case c.Name == "iptables" && len(c.Args) >= 3 && c.Args[2] == "-I":
		f.jump = true
	case c.Name == "systemctl" && len(c.Args) >= 2 && c.Args[0] == "is-active":
		if !f.active[c.Args[len(c.Args)-1]] {
			return nil, errors.New("systemctl exited 3")
		}
	case c.Name == "systemctl" && len(c.Args) >= 2 && c.Args[0] == "enable":
		if f.active == nil {
			f.active = map[string]bool{}
		}
		f.active[c.Args[len(c.Args)-1]] = true
	}
	return nil, nil
}

func (f *fakeRun) count(name string, args ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.cmds {
		if c.Name == name && (len(args) == 0 || strings.HasPrefix(strings.Join(c.Args, " "), strings.Join(args, " "))) {
			n++
		}
	}
	return n
}

// logBuf is a concurrency-safe log capture.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type rig struct {
	t    *testing.T
	root string
	ca   *testCA
	wg   *fakeWG
	run  *fakeRun
	log  *logBuf
	a    *Agent
	pub  string // the node's pcmesh public key
	priv string
}

func writeFile(t testing.TB, root, path, data string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

// newRig is a joined node (id n2, 10.215.0.2) of role, its pcmesh up.
func newRig(t *testing.T, role string) *rig {
	t.Helper()
	root := t.TempDir()
	ca := newCA(t)
	wg := &fakeWG{}
	run := &fakeRun{wg: wg}
	lb := &logBuf{}
	r := &rig{t: t, root: root, ca: ca, wg: wg, run: run, log: lb}
	k, _ := wgtypes.GeneratePrivateKey()
	r.priv, r.pub = k.String(), k.PublicKey().String()
	writeFile(t, root, MeshKeyFile, r.priv+"\n", 0o600)
	st := State{V: 1, ID: "n2", MeshIP: "10.215.0.2", Role: role, Site: "main", Class: "home", Endpoint: "https://example.org/node", Servers: []string{"10.215.0.1"}}
	sb, _ := json.Marshal(st)
	writeFile(t, root, stateFile, string(sb), 0o600)
	writeFile(t, root, caFile, string(ca.pem), 0o600)
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := ca.sign(t, "n2."+clusterDomain, &nk.PublicKey)
	writeFile(t, root, nodePEMFile, string(nodeBundle(nk, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), 0o600)
	r.a = New(Config{Root: root, Version: "0.0.0-test", Run: run, WG: wg,
		Log:        slog.New(slog.NewTextHandler(lb, nil)),
		Interfaces: func() ([]Iface, error) { return []Iface{{Name: "eth0", Addrs: []string{"192.0.2.12/24"}}}, nil },
		FSType:     func(string) (string, error) { return "ext4", nil },
		NodeExists: func(context.Context, string) (bool, error) { return false, nil },
		Exit:       func() {}})
	if err := r.a.Load(); err != nil {
		t.Fatal(err)
	}
	if err := r.a.MeshUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

// server is the API over real mTLS; client(cn) a client with that CN.
func (r *rig) server() *httptest.Server {
	s := httptest.NewUnstartedServer(r.a.Handler(context.Background()))
	s.TLS = r.a.TLSConfig()
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	r.t.Cleanup(s.Close)
	return s
}

func (r *rig) client(ca *testCA, cn string) *http.Client {
	c := ca.tlsCert(r.t, cn)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: poolOf(r.ca.cert), ServerName: "n2." + clusterDomain, Certificates: []tls.Certificate{c}}}}
}

func do(t *testing.T, c *http.Client, method, u, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

func peerKey(t testing.TB) string {
	k, _ := wgtypes.GeneratePrivateKey()
	return k.PublicKey().String()
}

var _ = net.IPv4len
