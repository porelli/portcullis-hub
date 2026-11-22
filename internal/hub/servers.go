package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/e2etest"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/vpn"
)

// Worker servers (contract §17.3, §17.5, §17.6): the registry in state,
// the views, Add / Revoke / Remove. Enrolment is servers_enrol.go, the
// 30 s loop servers_poll.go, revocation servers_revoke.go and link.json
// servers_link.go.

const (
	// OpServerEnrol is the enrolment operation (op key _server.<id>).
	OpServerEnrol  = "server_enrol"
	serverOpPrefix = "_server."
	StepJoin       = "join"
	StepHandshake  = "handshake"
	// JoinCodeTTL: a join code is valid this long by the Hub's clock.
	JoinCodeTTL = 15 * time.Minute
	// Offline: pollMisses missed polls or a handshake older than
	// handshakeMaxAge.
	pollMisses      = 3
	handshakeMaxAge = 3 * time.Minute
	// clockSkewMax: a worker clock further off fails enrolment.
	clockSkewMax = 5 * time.Minute
	// nodeCertLife is node-worker's TTL: renewal at ⅓ of it remaining.
	nodeCertLife = 30 * 24 * time.Hour
	// agentSwitchDelay: the agent switches keys this long after
	// answering PUT /v1/identity/wg.
	agentSwitchDelay = 2 * time.Second
	// Core's portcullis-proxy defaults (docker-compose.yml).
	defaultProxySubnet  = "172.31.250.0/24"
	defaultProxyIPRange = "172.31.250.128/25"
	defaultTraefikIP    = "172.31.250.2"
)

// serverOpKey is a server's op key (§11.7).
func serverOpKey(id string) string { return serverOpPrefix + id }

// serverTimings are the servers' clock, waits and dialer (zero = the
// defaults; tests set them).
type serverTimings struct {
	now       func() time.Time
	enrolPoll time.Duration // how often a join / handshake wait looks
	infoWait  time.Duration // how long the handshake step tries /v1/info
	swapWait  time.Duration // how long a handshake on the new key may take
	callWait  time.Duration // one agent call's timeout
	dial      agentrt.Dialer
	// beforeSetServer runs right before a backend is registered (tests:
	// a revocation racing it).
	beforeSetServer func(id string)
	// oweSaveErr fails the save of an owed serial (tests).
	oweSaveErr func(serial string) error
}

func (h *Hub) now() time.Time {
	if h.srvT.now != nil {
		return h.srvT.now()
	}
	if e2etest.Enabled && h.cfg.ClockOffset != nil {
		// Core's e2e only (a -tags e2etest build; a constant false
		// elsewhere, so the compiler drops this branch).
		return time.Now().Add(h.cfg.ClockOffset())
	}
	return time.Now()
}

func orDur(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (h *Hub) srvDialer() agentrt.Dialer {
	if h.srvT.dial != nil {
		return h.srvT.dial
	}
	return agentrt.LinkDialer{Proxy: h.cfg.LinkProxy}
}

// relayImageRe is HUB_RELAY_IMAGE: pinned by digest, or :edge.
var relayImageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(:[0-9]+)?/[a-z0-9._/-]+(@sha256:[0-9a-f]{64}|:edge)$`)

// RelayImageOK: ref is a relay image reference HUB_RELAY_IMAGE may hold.
func RelayImageOK(ref string) bool { return relayImageRe.MatchString(ref) }

// ErrNoRelayImage is the 503 while link_doc exists but HUB_RELAY_IMAGE
// isn't a usable relay image (review B-L3: checked at every use).
func errNoRelayImage() error {
	return statusErr(503, "servers are off: HUB_RELAY_IMAGE must be set to the relay image, pinned by digest (@sha256:…) or :edge")
}

// errServersOff: Servers is off (no link_doc, or link isn't running).
func errServersOff() error {
	return statusErr(503, "servers are off: run ./portcullis link init on the primary")
}

// serversOn: Servers is on — a Docker or Podman primary, the link_doc
// directory and link's healthy status (its public key and port go into
// join codes). Fail closed: anything else refuses.
func (h *Hub) serversOn() (*vpn.LinkState, error) {
	if h.kubeOn() {
		return nil, statusErr(409, "servers need a Docker or Podman primary")
	}
	if h.cfg.LinkDocDir == "" || !h.vpnStatusOn() {
		return nil, errServersOff()
	}
	if fi, err := os.Stat(h.cfg.LinkDocDir); err != nil || !fi.IsDir() {
		return nil, errServersOff()
	}
	if !RelayImageOK(h.cfg.RelayImage) {
		return nil, errNoRelayImage()
	}
	st, err := h.readWGStatus(h.now())
	if err != nil || st.Link == nil || !st.Link.OK || servers.ValidWGKey(st.Link.PublicKey) != nil || st.Link.Port < 1 || st.Link.Port > 65535 {
		return nil, errServersOff()
	}
	return st.Link, nil
}

// linkHandshakes are link's last handshakes by server id (nil: link's
// status is unreadable).
func (h *Hub) linkHandshakes() map[string]time.Time {
	if !h.vpnStatusOn() {
		return nil
	}
	st, err := h.readWGStatus(h.now())
	if err != nil || st.Link == nil {
		return nil
	}
	return st.LinkHandshakes()
}

// ServerView is one server as GET /api/servers lists it: never a join
// code, a key, a secret or a serial.
type ServerView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	State        string    `json:"state"`
	Error        string    `json:"error,omitempty"`
	Runtime      string    `json:"runtime"`
	Rootless     bool      `json:"rootless"`
	Arch         string    `json:"arch"`
	CPUs         int       `json:"cpus"`
	MemBytes     int64     `json:"mem_bytes"`
	DiskTotal    int64     `json:"disk_total"`
	DiskFree     int64     `json:"disk_free"`
	DataTotal    int64     `json:"data_total"`
	DataFree     int64     `json:"data_free"`
	Instances    []string  `json:"instances"`
	LastContact  time.Time `json:"last_contact,omitzero"`
	AgentVersion string    `json:"agent_version,omitempty"`
	CertNotAfter time.Time `json:"cert_not_after,omitzero"`
	TunnelIP     string    `json:"tunnel_ip,omitempty"`
	BindRoots    []string  `json:"bind_roots,omitempty"`
	// A cluster node's (kind cluster-node, §20.1): role, class, site, mesh
	// address and placement labels.
	Kind    string `json:"kind,omitempty"`
	Role    string `json:"role,omitempty"`
	Class   string `json:"class,omitempty"`
	Site    string `json:"site,omitempty"`
	MeshIP  string `json:"mesh_ip,omitempty"`
	Ingress bool   `json:"ingress,omitempty"`
	Storage bool   `json:"storage,omitempty"`
	// RevokeConfirmed: a revoked cluster node whose revocation nodeadm
	// answered done or parked with its security steps done (false: it
	// goes on, asked again every tick). `./portcullis node revoke` polls it.
	RevokeConfirmed bool `json:"revoke_confirmed,omitempty"`
}

// Servers lists every server, the primary first.
func (h *Hub) Servers(ctx context.Context) []ServerView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.serversLocked()
}

// serversLocked is Servers with mu held (read); it takes srvMu.
func (h *Hub) serversLocked() []ServerView {
	prim := ServerView{ID: servers.PrimaryID, Name: "Primary", State: ServerReady, Runtime: string(h.cfg.Runtime), Rootless: h.rootlessOn(), Instances: []string{}}
	ids := make([]string, 0, len(h.st.Servers))
	byServer := map[string][]string{}
	for iid, in := range h.st.Instances {
		byServer[in.Server] = append(byServer[in.Server], iid)
	}
	for id := range h.st.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []ServerView{prim}
	for _, id := range ids {
		s := h.st.Servers[id]
		v := ServerView{ID: id, Name: s.Name, State: s.State, LastContact: s.LastContact, AgentVersion: untrusted(s.AgentVersion, 40),
			CertNotAfter: s.CertNotAfter, TunnelIP: s.TunnelIP, Instances: []string{}}
		clusterViewFields(&v, s)
		out = append(out, v)
	}
	out = append(out, h.initNodeViewsLocked()...)
	for _, iid := range byServer[""] {
		out[0].Instances = append(out[0].Instances, iid)
	}
	h.srvMu.Lock()
	for i := range out[1:] {
		v := &out[i+1]
		v.Instances = append(v.Instances, byServer[v.ID]...)
		if ps := h.polls[v.ID]; ps != nil {
			// Worker-supplied text is untrusted (I2): one clipped line, no
			// control characters, in every view and tool answer.
			v.Error = untrusted(ps.reason, 300)
			if inf := ps.info; inf != nil {
				v.Runtime, v.Rootless, v.Arch, v.CPUs, v.MemBytes = untrusted(inf.Runtime, 20), inf.Rootless, untrusted(inf.Arch, 20), inf.CPUs, inf.MemBytes
				v.DiskTotal, v.DiskFree, v.DataTotal, v.DataFree = inf.DiskTotal, inf.DiskFree, inf.DataTotal, inf.DataFree
				v.BindRoots = make([]string, 0, len(inf.BindRoots))
				for _, r := range inf.BindRoots {
					v.BindRoots = append(v.BindRoots, untrusted(r, 200))
				}
			}
		}
	}
	h.srvMu.Unlock()
	for i := range out {
		sort.Strings(out[i].Instances)
	}
	return out
}

// validServerName: display text, 1–64 printable runes (default the id).
func validServerName(id, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return id, nil
	}
	if len([]rune(name)) > 64 {
		return "", statusErr(400, "a server name is at most 64 characters")
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", statusErr(400, "a server name is printable text")
		}
	}
	return name, nil
}

// AddServer adds a worker server (contract §17.5 step 1) and starts its
// enrolment op: the join code (shown once: it is in no state field, op
// record, log line or audit entry) and when it expires.
func (h *Hub) AddServer(ctx context.Context, actor directory.Actor, id, name string) (code string, expires time.Time, err error) {
	code, expires, _, err = h.AddServerOp(ctx, actor, id, name)
	return
}

// AddServerOp is AddServer, also returning the enrolment op's id.
func (h *Hub) AddServerOp(ctx context.Context, actor directory.Actor, id, name string) (code string, expires time.Time, opID string, err error) {
	defer func() {
		if err != nil {
			h.auditOp(actor, "server.add", id, "", err)
		}
	}()
	if actor.User == "" {
		return "", time.Time{}, "", statusErr(401, "no acting user")
	}
	if err := servers.ValidID(id); err != nil {
		return "", time.Time{}, "", statusErr(400, "%v", err)
	}
	if name, err = validServerName(id, name); err != nil {
		return "", time.Time{}, "", err
	}
	if h.kubeOn() {
		// R9: on Kubernetes, Servers manages cluster nodes only.
		return "", time.Time{}, "", statusErr(409, errWorkersOnKube)
	}
	link, err := h.serversOn()
	if err != nil {
		return "", time.Time{}, "", err
	}
	if h.nodeSigner() == nil {
		return "", time.Time{}, "", statusErr(503, "enroll isn't configured: node certificates can't be signed")
	}
	_, ca, err := h.controlCert(ctx)
	if err != nil {
		return "", time.Time{}, "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", time.Time{}, "", err
	}
	priv, pub, err := servers.NewWGKeyPair()
	if err != nil {
		return "", time.Time{}, "", err
	}
	now := h.now().UTC()
	expires = now.Add(JoinCodeTTL)
	sum := sha256.Sum256(secret)

	h.mu.Lock()
	if _, ok := h.st.Servers[id]; ok {
		h.mu.Unlock()
		return "", time.Time{}, "", statusErr(409, "server %s exists", id)
	}
	for _, o := range h.st.OwedSerials {
		if o.Server == id {
			h.mu.Unlock()
			return "", time.Time{}, "", statusErr(409, "server %s is still being revoked: try again shortly", id)
		}
	}
	ip, err := servers.AllocIP(servers.LinkSubnet, h.usedTunnelIPsLocked(), h.quarantineLocked(), now)
	if err != nil {
		h.mu.Unlock()
		return "", time.Time{}, "", statusErr(409, "%v", err)
	}
	if h.st.Servers == nil {
		h.st.Servers = map[string]state.Server{}
	}
	h.st.Servers[id] = state.Server{Name: name, TunnelIP: ip.String(), WGPublicKey: pub, State: ServerEnrolling,
		BackupSchedule: state.BackupSchedule{Mode: "off"},
		Enrol:          &state.Enrol{SecretSHA256: hex.EncodeToString(sum[:]), BootstrapPub: pub, IssuedAt: now, ExpiresAt: expires, Step: StepJoin}}
	if err := h.publishLinkLocked(); err != nil {
		delete(h.st.Servers, id)
		h.mu.Unlock()
		return "", time.Time{}, "", statusErr(500, "link.json: %v", err)
	}
	h.saveLocked()
	h.mu.Unlock()
	h.setServer(id, &serverRT{Name: name, State: ServerEnrolling})
	h.srvMu.Lock()
	if h.enrols == nil {
		h.enrols = map[string]*enrolRun{}
	}
	h.enrols[id] = &enrolRun{secret: secret, actor: actor}
	h.srvMu.Unlock()

	jc := servers.JoinCode{V: 1, Endpoint: fmt.Sprintf("%s:%d", h.cfg.Domain, link.Port), LinkPub: link.PublicKey, ServerID: id,
		TunnelIP: ip, BootstrapKey: priv, CASHA256: caSHA256(ca), Secret: base64.RawURLEncoding.EncodeToString(secret)}
	h.auditOp(actor, "server.add", id, fmt.Sprintf("name %q, tunnel address %s", name, ip), nil)
	a, _, err := h.startOp(serverOpKey(id), OpServerEnrol, actor, enrolPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		return nil, nil, h.runEnrol(ctx, id)
	})
	if err != nil {
		h.dropEnrol(id)
		h.mu.Lock()
		h.forgetServerLocked(id)
		h.mu.Unlock()
		return "", time.Time{}, "", err
	}
	return jc.Encode(), expires, a.OpID, nil
}

// usedTunnelIPsLocked: every listed server's address. Caller holds mu.
func (h *Hub) usedTunnelIPsLocked() []netip.Addr {
	var out []netip.Addr
	for _, s := range h.st.Servers {
		if a, err := netip.ParseAddr(s.TunnelIP); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// quarantineLocked: address → when its quarantine started (AllocIP's
// form). Caller holds mu.
func (h *Hub) quarantineLocked() map[netip.Addr]time.Time {
	out := map[netip.Addr]time.Time{}
	for k, until := range h.st.Quarantined {
		if a, err := netip.ParseAddr(k); err == nil {
			out[a] = until.Add(-servers.Quarantine)
		}
	}
	for _, s := range h.st.Servers {
		if a, err := netip.ParseAddr(s.TunnelIP); err == nil && !s.QuarantinedUntil.IsZero() {
			out[a] = s.QuarantinedUntil.Add(-servers.Quarantine)
		}
	}
	return out
}

// forgetServerLocked removes a server that never got past its join
// (no certificate was ever signed): its entry and its link.json peer.
// Caller holds mu (write).
func (h *Hub) forgetServerLocked(id string) {
	delete(h.st.Servers, id)
	if err := h.publishLinkLocked(); err != nil {
		log.Printf("servers: link.json after removing %s: %v", id, err)
	}
	h.saveLocked()
	h.setServer(id, nil)
}

// placedLocked are the instances placed on server. Caller holds mu.
func (h *Hub) placedLocked(server string) []string {
	var out []string
	for id, in := range h.st.Instances {
		if in.Server == server {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// networkParams are the primary's portcullis-proxy parameters (core
// .env, else core's defaults): PUT /v1/network at enrolment (P6).
func (h *Hub) networkParams() (p agentapi.NetworkParams, err error) {
	core := readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env"))
	get := func(k, def string) string {
		if v := strings.TrimSpace(core[k]); v != "" {
			return v
		}
		return def
	}
	if p.ProxySubnet, err = netip.ParsePrefix(get("PORTCULLIS_PROXY_SUBNET", defaultProxySubnet)); err != nil {
		return p, statusErr(500, "the core env's PORTCULLIS_PROXY_SUBNET isn't a prefix")
	}
	if p.ProxyIPRange, err = netip.ParsePrefix(get("PORTCULLIS_PROXY_IP_RANGE", defaultProxyIPRange)); err != nil {
		return p, statusErr(500, "the core env's PORTCULLIS_PROXY_IP_RANGE isn't a prefix")
	}
	if p.TraefikIP, err = netip.ParseAddr(get("PORTCULLIS_TRAEFIK_IP", defaultTraefikIP)); err != nil {
		return p, statusErr(500, "the core env's PORTCULLIS_TRAEFIK_IP isn't an address")
	}
	return p, nil
}

// relayEnvPath is an instance's relay env file (PORTCULLIS_RELAY_TOKEN,
// 0600; never in state.yaml). link.json holds the token's sha256.
func (h *Hub) relayEnvPath(id string) string {
	return filepath.Join(h.cfg.DataDir, "env", id+".relay.env")
}

// RelayTokenVar is the relay env's token variable.
const RelayTokenVar = "PORTCULLIS_RELAY_TOKEN"

// relayTokenSHA is the sha256 hex of instance id's relay token ("" =
// none).
func (h *Hub) relayTokenSHA(id string) string {
	tok := readEnvRaw(h.relayEnvPath(id))[RelayTokenVar]
	if tok == "" {
		return ""
	}
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])
}

// newRelayToken writes a fresh relay token (32 random bytes, base64url)
// into instance id's relay env.
func (h *Hub) newRelayToken(id string) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	env := readEnvRaw(h.relayEnvPath(id))
	env[RelayTokenVar] = base64.RawURLEncoding.EncodeToString(b)
	if err := fsutil.MkdirAll(filepath.Dir(h.relayEnvPath(id)), 0o700); err != nil {
		return err
	}
	return writeEnvMap(h.relayEnvPath(id), env)
}

// serverName is a server's display name (its id when unknown).
func (h *Hub) serverName(id string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if s, ok := h.st.Servers[id]; ok && s.Name != "" {
		return s.Name
	}
	return id
}

// serverBackend builds a ready server's backend from its pins (nil: no
// pins or no control certificate yet).
func (h *Hub) serverBackend(ctx context.Context, id string, s state.Server, kind runtime.Kind) (*agentrt.Backend, error) {
	ip, err := netip.ParseAddr(s.TunnelIP)
	if err != nil || !servers.TunnelIPOK(ip) {
		return nil, errors.New("no valid tunnel address")
	}
	spki, err := hex.DecodeString(s.SPKI)
	if err != nil || len(spki) != sha256.Size || s.CertSerial == "" {
		return nil, errors.New("no pinned certificate")
	}
	cert, ca, err := h.controlCert(ctx)
	if err != nil {
		return nil, err
	}
	if kind == "" {
		kind = runtime.KindDocker
	}
	var env []string
	if h.rt != nil {
		env = h.rt.Env()
	}
	return agentrt.New(agentrt.Config{ServerID: id, TunnelIP: ip, CACert: ca, SPKI: spki, Serial: s.CertSerial, ControlCert: cert,
		Dial: h.srvDialer(), Kind: kind, Env: env, OnMismatch: func() { h.identityMismatch(id) }}), nil
}

// untrusted is text a worker supplied (an error, a version, a path), made
// safe to show and to hand an AI client (I2): control characters become
// spaces, the result is one line clipped to n bytes on a rune boundary.
// The UI escapes it besides; it is never markup.
func untrusted(s string, n int) string {
	b := []rune(s)
	for i, r := range b {
		if templates.IsControlRune(r) { // bidi controls too (L4)
			b[i] = ' '
		}
	}
	return clipRunes(strings.TrimSpace(string(b)), n)
}
