package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/version"
)

// Version is the agent's version: the build's (internal/version). The
// Hub accepts it when servers.Compatible says so.
var Version = version.Version

// Config is portcullis-agent run's configuration (env, contract §17.7).
type Config struct {
	// DataDir is AGENT_DATA: an absolute path, the same on the host.
	DataDir string
	// Runtime is AGENT_RUNTIME: docker or podman.
	Runtime string
	// BindRoots are AGENT_BIND_ROOTS, the worker's folder roots.
	BindRoots []string
	// Info reads the engine's part of /v1/info (the agent fills its own
	// fields); nil = an engine that can't be read (a failed poll).
	Info func(ctx context.Context) (agentapi.Info, error)
	// Routes serves the ready-state API (projects, containers, volumes,
	// helpers; Task 6). nil = 404 for everything but the identity routes.
	Routes http.Handler
	// OnNetwork applies PUT /v1/network (the worker's portcullis-proxy and
	// the agent's address on it; API.SetupNetwork); nil = stored only.
	OnNetwork func(ctx context.Context, n agentapi.NetworkParams) error
	// Unhealthy lists the bundled projects' containers whose health is
	// unhealthy (metrics: portcullis_agent_container_unhealthy); nil =
	// none reported.
	Unhealthy func(ctx context.Context) []UnitHealth
	// Now is the clock (tests).
	Now func() time.Time
	// SwitchDelay / SwitchTimeout: the WireGuard key switch after PUT
	// /v1/identity/wg (2 s) and the fallback to the bootstrap key without
	// a handshake on the new key (120 s).
	SwitchDelay, SwitchTimeout time.Duration
}

// enrolment phases inside the enrolling state.
const (
	phaseJoin     = "join"     // waiting for the Hub's control connection and proof
	phaseProven   = "proven"   // a good proof: pending TLS and WireGuard keys, a CSR given out
	phaseCertSet  = "cert"     // the node-worker certificate stored
	phaseSwitched = "switched" // PUT /v1/identity/wg: the new key in use, waiting for a handshake
)

// MaxEnrolFailures wrong proofs stop the agent.
const MaxEnrolFailures = 3

// ErrEnrolRefused ends Run after MaxEnrolFailures wrong proofs.
var ErrEnrolRefused = errors.New("enrolment refused; run ./portcullis worker join again")

// Agent is one portcullis-agent.
type Agent struct {
	cfg   Config
	store Store

	mu sync.Mutex
	// identity
	state, phase string
	pins         Pins
	join         servers.JoinCode
	ca           *x509.Certificate // pinned (ready) or learned from the chain (enrolling)
	tlsKey       *ecdsa.PrivateKey
	tlsCert      *x509.Certificate
	enrolKey     *ecdsa.PrivateKey // the enrolling self-signed certificate's
	enrolCert    *x509.Certificate
	// enrolment
	nonce        []byte
	nonceExpires time.Time
	failures     int
	pendingTLS   *ecdsa.PrivateKey
	pendingWG    Key
	hasPendingWG bool
	linkPub      Key
	switchedAt   time.Time

	tunnel  *Tunnel
	refused chan struct{}
	once    sync.Once

	metricsOnce sync.Once
	metrics     http.Handler
	// rootDir: the engine's data root as last read (metrics' disk gauges).
	rootDir string
}

// New loads the identity under <DataDir>/identity. An agent that never
// joined (state none) refuses to start.
func New(cfg Config) (*Agent, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SwitchDelay == 0 {
		cfg.SwitchDelay = 2 * time.Second
	}
	if cfg.SwitchTimeout == 0 {
		cfg.SwitchTimeout = 120 * time.Second
	}
	a := &Agent{cfg: cfg, store: Store{Dir: identityDir(cfg.DataDir)}, refused: make(chan struct{})}
	pins, err := a.store.Pins()
	if err != nil {
		return nil, errors.New("this worker hasn't joined: run ./portcullis worker join")
	}
	a.pins, a.state = pins, pins.State
	switch pins.State {
	case StateEnrolling:
		if a.join, err = a.store.Join(); err != nil {
			return nil, err
		}
		a.phase = phaseJoin
		if a.enrolKey, a.enrolCert, err = selfSigned(servers.NodeName(pins.ServerID), cfg.Now()); err != nil {
			return nil, err
		}
	case StateReady:
		if a.ca, err = a.store.cert(caFile); err != nil {
			return nil, fmt.Errorf("identity: %s: %v", caFile, err)
		}
		if a.tlsCert, err = a.store.cert(tlsCertFile); err != nil {
			return nil, fmt.Errorf("identity: %s: %v", tlsCertFile, err)
		}
		if a.tlsKey, err = a.store.tlsKey(tlsKeyFile); err != nil {
			return nil, fmt.Errorf("identity: %s: %v", tlsKeyFile, err)
		}
		if a.linkPub, err = ParseKey(pins.LinkPub); err != nil {
			return nil, err
		}
	case StateRefused:
		return nil, ErrEnrolRefused
	default:
		return nil, fmt.Errorf("identity: state %q", pins.State)
	}
	return a, nil
}

func identityDir(data string) string { return data + "/identity" }

// State is the agent's state (enrolling or ready).
func (a *Agent) State() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

// Refused is closed after MaxEnrolFailures wrong proofs.
func (a *Agent) Refused() <-chan struct{} { return a.refused }

// TunnelConfig is the tunnel the identity needs now: the bootstrap key
// while enrolling, the agent's own key once ready.
func (a *Agent) TunnelConfig(ctx context.Context) (TunnelConfig, error) {
	a.mu.Lock()
	pins := a.pins
	state := a.state
	join := a.join
	a.mu.Unlock()
	addr, err := netip.ParseAddr(pins.TunnelIP)
	if err != nil {
		return TunnelConfig{}, errors.New("identity: tunnel_ip")
	}
	link, err := ParseKey(pins.LinkPub)
	if err != nil {
		return TunnelConfig{}, err
	}
	ep, err := ResolveEndpoint(ctx, pins.Endpoint)
	if err != nil {
		return TunnelConfig{}, err
	}
	var priv Key
	if state == StateEnrolling {
		if priv, err = ParseKey(join.BootstrapKey); err != nil {
			return TunnelConfig{}, err
		}
	} else if priv, err = a.store.wgKey(wgKeyFile); err != nil {
		return TunnelConfig{}, fmt.Errorf("identity: %s: %v", wgKeyFile, err)
	}
	return TunnelConfig{PrivateKey: priv, Address: addr, LinkPub: link, Endpoint: ep}, nil
}

// Network is the stored PUT /v1/network parameters.
func (a *Agent) Network() (agentapi.NetworkParams, error) { return a.store.Network() }

// AttachTunnel gives the agent its running tunnel (the key switch drives
// it).
func (a *Agent) AttachTunnel(t *Tunnel) {
	a.mu.Lock()
	a.tunnel = t
	a.mu.Unlock()
}
