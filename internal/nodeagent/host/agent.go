package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Host paths (under Config.Root in tests).
const (
	StateDir  = "/var/lib/portcullis/nodeagent"
	stateFile = StateDir + "/state.json"
	// nodePEMFile holds the node-cluster key and certificate together, so
	// a renewal swaps both with one rename.
	nodePEMFile   = StateDir + "/node.pem"
	intentFile    = StateDir + "/token-intent.json"
	caFile        = StateDir + "/ca.crt"
	planFile      = StateDir + "/plan.json"
	targetsFile   = StateDir + "/targets.json"
	MeshKeyFile   = "/etc/wireguard/pcmesh.key"
	K3sTokenFile  = "/etc/rancher/k3s/token"
	K3sAgentToken = "/etc/rancher/k3s/agent-token"
	FlannelConf   = "/etc/rancher/k3s/flannel-net-conf.json"
	K3sKubeconfig = "/etc/rancher/k3s/k3s.yaml"
	K3sBinary     = "/usr/local/bin/k3s"
	AgentBinary   = "/usr/local/lib/portcullis/nodeagent"
	UnitName      = "portcullis-nodeagent.service"
	unitFile      = "/etc/systemd/system/" + UnitName
	APIPort       = 7443
)

var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// State is what the join leaves on the node (state.json, 0600).
type State struct {
	V        int      `json:"v"`
	ID       string   `json:"id"`
	MeshIP   string   `json:"mesh_ip"`
	Role     string   `json:"role"`
	Site     string   `json:"site"`
	Class    string   `json:"class"`
	Endpoint string   `json:"endpoint"`
	Servers  []string `json:"servers"`
}

// WG is the part of wgctrl's client the agent uses.
type WG interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

// Config wires the agent to the host. Every zero field has the real
// default (New fills them).
type Config struct {
	Root    string // a prefix for every host path (tests)
	Version string
	Run     Runner
	WG      WG
	Now     func() time.Time
	Log     *slog.Logger
	// CoreNS is the core namespace (portcullis-cluster-addresses).
	CoreNS string
	// Interfaces lists the host's interfaces and their IPv4 prefixes.
	Interfaces func() ([]Iface, error)
	// FSType names the file system holding a path (zfs, btrfs, ext4, …).
	FSType func(path string) (string, error)
	// EchoDial opens the RTT echo's socket from the node's mesh address
	// (own) to a peer's addr:7444 (nil: UDP from own).
	EchoDial func(ctx context.Context, own, addr string) (net.Conn, error)
	// Dial is the probes' and the egress check's dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// EgressRoots verifies the egress host (nil: the system's).
	EgressRoots *x509.CertPool
	// Addresses reads portcullis-cluster-addresses through the node's k3s.
	Addresses func(ctx context.Context) (map[string]DocNode, error)
	// NodeExists says whether a Kubernetes Node of that name exists
	// (through the node's k3s).
	NodeExists func(ctx context.Context, name string) (bool, error)
	// HTTP reaches nodeadm's public /node paths (the certificate renewal;
	// nil: the system roots).
	HTTP *http.Client
	// Etcd is this server's etcd (its own client credentials).
	Etcd Etcd
	// Supervisor is the k3s supervisor's token API.
	Supervisor Supervisor
	// Exit stops the process after an uninstall (default os.Exit(0)).
	Exit func()
}

// Iface is one host interface.
type Iface struct {
	Name  string
	Addrs []string // CIDR form
}

// DocNode is one node of portcullis-cluster-addresses (§20.9).
type DocNode struct {
	Mesh   string   `json:"mesh"`
	LAN    []string `json:"lan"`
	Public []string `json:"public"`
	State  string   `json:"state"`
}

// Agent is the running host service.
type Agent struct {
	cfg Config
	fs  fsys
	log *slog.Logger

	mu    sync.Mutex
	st    *State
	ca    *x509.Certificate
	cert  *tls.Certificate
	plan  *meshPlanState
	probe *prober

	rttMu  sync.Mutex
	meshMu sync.Mutex // ApplyMesh, one at a time
	opMu   sync.Mutex // the k3s steps, one at a time
	rtt    rttCache
	uninst sync.Once
}

// New is an agent on cfg (the state is loaded by Load).
func New(cfg Config) *Agent {
	if cfg.Run == nil {
		cfg.Run = ExecRunner{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.CoreNS == "" {
		cfg.CoreNS = "portcullis"
	}
	if cfg.Interfaces == nil {
		cfg.Interfaces = hostInterfaces
	}
	if cfg.FSType == nil {
		cfg.FSType = fsType
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	a := &Agent{cfg: cfg, fs: fsys{cfg.Root}, log: cfg.Log}
	if cfg.Addresses == nil {
		a.cfg.Addresses = a.k3sAddresses
	}
	if cfg.NodeExists == nil {
		a.cfg.NodeExists = a.k3sNodeExists
	}
	if cfg.HTTP == nil {
		a.cfg.HTTP = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 15 * time.Second}}
	}
	if cfg.Etcd == nil {
		a.cfg.Etcd = &etcdGateway{fs: a.fs}
	}
	if cfg.Supervisor == nil {
		a.cfg.Supervisor = httpSupervisor{}
	}
	if cfg.Exit == nil {
		a.cfg.Exit = defaultExit
	}
	a.probe = newProber(a)
	return a
}

// Load reads the join's state, certificate, key and CA.
func (a *Agent) Load() error {
	b, err := a.fs.read(stateFile)
	if err != nil {
		return errors.New("this machine hasn't joined a cluster (no nodeagent state): run join first")
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil || st.V != 1 || !idRe.MatchString(st.ID) {
		return errors.New("the nodeagent state is unreadable")
	}
	caPEM, err := a.fs.read(caFile)
	if err != nil {
		return errors.New("the nodeagent has no pki_node CA")
	}
	ca, err := parseCertPEM(caPEM)
	if err != nil {
		return fmt.Errorf("the pki_node CA: %w", err)
	}
	bundle, err := a.fs.read(nodePEMFile)
	if err != nil {
		return errors.New("the nodeagent has no node-cluster certificate")
	}
	cert, err := nodeCert(bundle)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.st, a.ca, a.cert = &st, ca, cert
	a.mu.Unlock()
	a.loadPlan()
	a.probe.load()
	return nil
}

func (a *Agent) state() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st == nil {
		return State{}
	}
	s := *a.st
	return s
}

// nodeCert is the node-cluster key pair of a node.pem bundle.
func nodeCert(bundle []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return nil, errors.New("the node-cluster certificate and key don't match")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.New("the node-cluster certificate is unreadable")
	}
	cert.Leaf = leaf
	return &cert, nil
}

// nodeBundle is node.pem: the key, then the certificate.
func nodeBundle(k *ecdsa.PrivateKey, certPEM []byte) []byte {
	return append(keyPEM(k), certPEM...)
}

func parseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func keyPEM(k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err) // a P-256 key always marshals
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// httpError is an answer's status, text (no secret ever) and kind.
type httpError struct {
	code int
	msg  string
	kind string
}

func (e *httpError) Error() string { return e.msg }

func errStatus(code int, format string, args ...any) error {
	return &httpError{code: code, msg: fmt.Sprintf(format, args...)}
}

func errKind(code int, kind, format string, args ...any) error {
	return &httpError{code: code, msg: fmt.Sprintf(format, args...), kind: kind}
}

var errBadRequest = errStatus(http.StatusBadRequest, "malformed request")

// State is the node's joined state.
func (a *Agent) State() State { return a.state() }

// RunProbes probes every 10 s until ctx ends.
func (a *Agent) RunProbes(ctx context.Context) { a.probe.Run(ctx) }
