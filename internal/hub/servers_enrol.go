package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/version"
)

// Enrolment (contract §17.5 steps 3–6; pre-flight P5/P6), the op
// server_enrol: join → handshake → verify. Every connection is opened by
// the primary.

// enrolRun is an enrolment in progress: the join code's secret (memory
// only: a Hub restart voids the enrolment) and who added the server.
type enrolRun struct {
	secret []byte
	actor  directory.Actor
}

func enrolPlan() []Step {
	return []Step{
		{Key: StepJoin, Label: "Waiting for the worker to join"},
		{Key: StepHandshake, Label: "Connecting to the worker"},
		{Key: StepVerify, Label: "Verifying the worker and switching its keys"},
	}
}

func (h *Hub) enrolOf(id string) *enrolRun {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	return h.enrols[id]
}

func (h *Hub) dropEnrol(id string) {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if er := h.enrols[id]; er != nil {
		clear(er.secret)
	}
	delete(h.enrols, id)
}

// errEnrolRefused marks an enrolment refusal (audited
// server.enrol_refused).
type errEnrolRefused struct{ err error }

func (e errEnrolRefused) Error() string { return e.err.Error() }
func (e errEnrolRefused) Unwrap() error { return e.err }

func refused(format string, args ...any) error {
	return errEnrolRefused{statusErr(409, format, args...)}
}

// runEnrol is the server_enrol op. Before the handshake a refusal or a
// Stop leaves nothing (the server entry and its bootstrap peer go); from
// the handshake on, the server is revoked (§17.6).
func (h *Hub) runEnrol(ctx context.Context, id string) error {
	p := progressFrom(ctx)
	er := h.enrolOf(id)
	defer h.dropEnrol(id)
	if er == nil {
		return statusErr(409, "no enrolment of %s is in progress", id)
	}
	actor := er.actor

	p.Start(StepJoin)
	if err := h.waitJoin(ctx, id); err != nil {
		// Nothing was signed yet: the entry and its bootstrap peer go
		// (unless a revocation took it over meanwhile).
		h.mu.Lock()
		if s, ok := h.st.Servers[id]; ok && s.State == ServerEnrolling {
			h.forgetServerLocked(id)
		}
		h.mu.Unlock()
		if ctx.Err() != nil {
			p.Undone(StepJoin)
			return ErrStopped
		}
		h.auditOp(actor, "server.enrol_refused", id, "", err)
		return err
	}
	p.Done(StepJoin)

	// The code is single use: marked used before the first try.
	h.mu.Lock()
	s, ok := h.st.Servers[id]
	if !ok || s.Enrol == nil || s.State != ServerEnrolling {
		h.mu.Unlock()
		return statusErr(409, "server %s is no longer enrolling", id)
	}
	reused := s.Enrol.Used
	s.Enrol.Used, s.Enrol.Step = true, StepHandshake
	h.st.Servers[id] = s
	h.saveLocked()
	h.mu.Unlock()

	fail := func(step string, err error) error {
		h.revokeEnrolling(id)
		if ctx.Err() != nil {
			return ErrStopped
		}
		p.Fail(step, err)
		h.auditOp(actor, "server.enrol_refused", id, "", err)
		return err
	}
	p.Start(StepHandshake)
	if reused {
		return fail(StepHandshake, refused("the join code was already used: add the server again"))
	}
	b, info, err := h.enrolHandshake(ctx, id, s.TunnelIP)
	if err != nil {
		return fail(StepHandshake, err)
	}
	p.Done(StepHandshake)

	p.Start(StepVerify)
	h.setEnrolStep(id, StepVerify)
	if err := h.enrolVerify(ctx, id, b, er.secret); err != nil {
		return fail(StepVerify, err)
	}
	if !p.CloseStop() {
		return fail(StepVerify, ErrStopped)
	}
	// The commit: ready, pinned, its own key in link.json.
	kind := runtime.Kind(info.Runtime)
	h.mu.Lock()
	s = h.st.Servers[id]
	s.State, s.Enrol = ServerReady, nil
	s.LastContact, s.AgentVersion = h.now().UTC(), info.AgentVersion
	h.st.Servers[id] = s
	perr := h.publishLinkLocked()
	h.saveLocked()
	h.mu.Unlock()
	if perr != nil {
		log.Printf("servers: link.json after enrolling %s: %v", id, perr)
	}
	rb, err := h.serverBackend(ctx, id, s, kind)
	if err != nil {
		return fail(StepVerify, statusErr(500, "the enrolled server's backend: %v", err))
	}
	h.setServer(id, &serverRT{Name: s.Name, State: ServerReady, RT: rb})
	h.notePoll(id, &info, "")
	p.Done(StepVerify)
	h.auditOp(actor, "server.enrolled", id, fmt.Sprintf("agent %s, %s", clipRunes(info.AgentVersion, 40), clipRunes(info.Runtime, 20)), nil)
	h.watchServer(id, rb)
	return nil
}

func (h *Hub) setEnrolStep(id, step string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.st.Servers[id]; ok && s.Enrol != nil {
		s.Enrol.Step = step
		h.st.Servers[id] = s
		h.saveLocked()
	}
}

// waitJoin waits for the bootstrap peer's first handshake newer than the
// code, at most until the code expires (the Hub's clock only).
func (h *Hub) waitJoin(ctx context.Context, id string) error {
	for {
		h.mu.RLock()
		s, ok := h.st.Servers[id]
		h.mu.RUnlock()
		if !ok || s.Enrol == nil {
			return statusErr(409, "server %s is no longer enrolling", id)
		}
		if hs, ok := h.linkHandshakes()[id]; ok && hs.After(s.Enrol.IssuedAt) {
			return nil
		}
		if h.now().After(s.Enrol.ExpiresAt) {
			return refused("the join code expired before the worker joined: add the server again")
		}
		if !sleepCtx(ctx, orDur(h.srvT.enrolPoll, 2*time.Second)) {
			return ctx.Err()
		}
	}
}

// enrolHandshake opens control in the enrolling state (the agent checks
// the Hub's chain against ca_sha256; nothing of the worker is pinned
// yet), reads /v1/info and checks the worker's clock and version.
func (h *Hub) enrolHandshake(ctx context.Context, id, tunnel string) (*agentrt.Backend, agentapi.Info, error) {
	ip, err := netip.ParseAddr(tunnel)
	if err != nil {
		return nil, agentapi.Info{}, statusErr(500, "no tunnel address")
	}
	cert, ca, err := h.controlCert(ctx)
	if err != nil {
		return nil, agentapi.Info{}, err
	}
	b := agentrt.New(agentrt.Config{ServerID: id, TunnelIP: ip, CACert: ca, ControlCert: cert, Dial: h.srvDialer(), Enrolling: true})
	deadline := h.now().Add(orDur(h.srvT.infoWait, 60*time.Second))
	var info agentapi.Info
	for {
		cctx, cancel := context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
		info, err = b.AgentInfo(cctx)
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, info, ctx.Err()
		}
		if h.now().After(deadline) {
			if strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "certificate") {
				return nil, info, refused("the TLS handshake with the worker failed (%s): if the worker's clock is off, fix its time (NTP)", clipRunes(err.Error(), 160))
			}
			return nil, info, statusErr(502, "the worker doesn't answer: %s", clipRunes(err.Error(), 160))
		}
		if !sleepCtx(ctx, orDur(h.srvT.enrolPoll, 2*time.Second)) {
			return nil, info, ctx.Err()
		}
	}
	// Review Focus 1: the Hub judges by its own clock.
	if skew := info.Clock.Sub(h.now()); skew > clockSkewMax || skew < -clockSkewMax {
		if skew < 0 {
			skew = -skew
		}
		return nil, info, refused("the worker's clock is %s off; fix its time (NTP)", skew.Round(time.Second))
	}
	if !servers.Compatible(version.Version, info.AgentVersion) {
		return nil, info, refused("server_agent_incompatible: the worker's agent is %s, the Hub %s (the same or the previous minor): upgrade the worker", clipRunes(info.AgentVersion, 40), version.Version)
	}
	if k := runtime.Kind(info.Runtime); k != runtime.KindDocker && k != runtime.KindPodman {
		return nil, info, refused("the worker's runtime %q isn't docker or podman", clipRunes(info.Runtime, 20))
	}
	return b, info, nil
}

// enrolVerify: nonce → proof → CSR → sign → PUT cert → PUT network →
// PUT wg (P6), then the new key in link.json and a handshake on it. A
// missing handshake puts the bootstrap key back and retries the switch
// once.
func (h *Hub) enrolVerify(ctx context.Context, id string, b *agentrt.Backend, secret []byte) error {
	call := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
	}
	c, cancel := call()
	nonce, err := b.EnrolNonce(c)
	cancel()
	if err != nil {
		return err
	}
	spki := b.PeerSPKI()
	if len(spki) != sha256.Size {
		return refused("the worker presented no certificate")
	}
	name := servers.NodeName(id)
	c, cancel = call()
	csr, err := b.Enrol(c, servers.Proof(secret, nonce, id, spki), name)
	cancel()
	if err != nil {
		var ae *agentrt.Error
		if errors.As(err, &ae) && ae.AgentStatus == 403 {
			// The agent's message isn't passed (a worker is untrusted).
			return refused("the worker refused the enrolment proof: add the server again")
		}
		return err
	}
	if !bytes.Equal(b.PeerSPKI(), spki) {
		return refused("the worker's certificate changed during the enrolment")
	}
	if err := servers.ValidWGKey(csr.WGPublicKey); err != nil {
		return refused("the worker's WireGuard key: %v", err)
	}
	leaf, nc, err := h.signWorker(ctx, id, csr.CSR)
	if err != nil {
		return err
	}
	c, cancel = call()
	err = b.PutIdentityCert(c, agentapi.IdentityCert{Certificate: nc.Certificate, CA: nc.CA})
	cancel()
	if err != nil {
		return err
	}
	// Pinned from here on: a revocation revokes this certificate.
	h.pinServer(id, leaf, nc.Serial)
	np, err := h.networkParams()
	if err != nil {
		return err
	}
	c, cancel = call()
	err = b.PutNetwork(c, np)
	cancel()
	if err != nil {
		return err
	}
	link, err := h.serversOn()
	if err != nil {
		return err
	}
	for try := 0; try < 2; try++ {
		if err := h.putWG(ctx, b, link.PublicKey); err != nil {
			return err
		}
		at := h.now()
		if err := h.setPeerKey(id, csr.WGPublicKey); err != nil {
			return err
		}
		if h.waitHandshake(ctx, id, at.Add(agentSwitchDelay), orDur(h.srvT.swapWait, 120*time.Second)) {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		h.mu.RLock()
		boot := ""
		if s := h.st.Servers[id]; s.Enrol != nil {
			boot = s.Enrol.BootstrapPub
		}
		h.mu.RUnlock()
		if err := h.setPeerKey(id, boot); err != nil {
			return err
		}
	}
	return refused("no handshake on the worker's new WireGuard key")
}

// putWG sends PUT /v1/identity/wg, retried until the agent takes it (it
// refuses while it is still falling back to its bootstrap key).
func (h *Hub) putWG(ctx context.Context, b *agentrt.Backend, linkPub string) error {
	deadline := h.now().Add(orDur(h.srvT.swapWait, 120*time.Second) + 10*time.Second)
	for {
		c, cancel := context.WithTimeout(ctx, orDur(h.srvT.callWait, 15*time.Second))
		err := b.PutIdentityWG(c, linkPub)
		cancel()
		if err == nil || ctx.Err() != nil || h.now().After(deadline) {
			return err
		}
		if !sleepCtx(ctx, orDur(h.srvT.enrolPoll, 2*time.Second)) {
			return ctx.Err()
		}
	}
}

// setPeerKey puts key as the server's link.json peer key.
func (h *Hub) setPeerKey(id, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.st.Servers[id]
	if !ok || s.State == ServerRevoked || s.Revoke != nil {
		return statusErr(409, "server %s was revoked", id)
	}
	s.WGPublicKey = key
	h.st.Servers[id] = s
	if err := h.publishLinkLocked(); err != nil {
		return statusErr(500, "link.json: %v", err)
	}
	h.saveLocked()
	return nil
}

// waitHandshake waits up to d for a handshake of server id after since.
func (h *Hub) waitHandshake(ctx context.Context, id string, since time.Time, d time.Duration) bool {
	deadline := h.now().Add(d)
	for {
		if hs, ok := h.linkHandshakes()[id]; ok && hs.After(since) {
			return true
		}
		if h.now().After(deadline) {
			return false
		}
		if !sleepCtx(ctx, orDur(h.srvT.enrolPoll, 2*time.Second)) {
			return false
		}
	}
}

// signWorker has enroll sign a worker CSR (node-worker, CN the node
// name) and checks the answer: one certificate naming exactly the node
// name, issued by the pinned pki_node CA.
func (h *Hub) signWorker(ctx context.Context, id, csrPEM string) (*x509.Certificate, *NodeCert, error) {
	signer := h.nodeSigner()
	if signer == nil {
		return nil, nil, statusErr(503, "enroll isn't configured: node certificates can't be signed")
	}
	_, ca, err := h.controlCert(ctx)
	if err != nil {
		return nil, nil, err
	}
	name := servers.NodeName(id)
	nc, err := signer.SignNode(ctx, RoleNodeWorker, name, csrPEM)
	if err != nil {
		return nil, nil, err
	}
	leaf, err1 := parseOnePEMCert(nc.Certificate)
	nca, err2 := parseOnePEMCert(nc.CA)
	if err1 != nil || err2 != nil || !nca.Equal(ca) {
		return nil, nil, statusErr(502, "enroll's worker certificate is unusable")
	}
	if leaf.Subject.CommonName != name || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name || leaf.CheckSignatureFrom(ca) != nil {
		return nil, nil, statusErr(502, "enroll's worker certificate doesn't name exactly %s", name)
	}
	if !agentrt.SameSerial(leaf.SerialNumber, nc.Serial) {
		return nil, nil, statusErr(502, "enroll's serial isn't the certificate's")
	}
	return leaf, nc, nil
}

// pinServer pins a worker certificate (serial, SPKI, not after).
func (h *Hub) pinServer(id string, leaf *x509.Certificate, serial string) {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.st.Servers[id]; ok {
		s.CertSerial, s.SPKI, s.CertNotAfter = serial, hex.EncodeToString(sum[:]), leaf.NotAfter.UTC()
		h.st.Servers[id] = s
		h.saveLocked()
	}
}

// revokeEnrolling ends a failed or stopped enrolment past its join: the
// server is revoked (its peer out of link.json, a signed certificate
// revoked), listed as revoked until it is removed.
func (h *Hub) revokeEnrolling(id string) {
	h.mu.Lock()
	h.beginRevokeLocked(id, false)
	h.mu.Unlock()
	h.advanceRevoke(context.Background(), id)
}

// StopServerEnrol stops server id's enrolment op (POST
// /api/servers/{id}/op/stop): before the handshake nothing is left;
// from it on, the server is revoked.
func (h *Hub) StopServerEnrol(id string, actor directory.Actor, opID string) error {
	if servers.ValidID(id) != nil {
		return statusErr(400, "invalid server id")
	}
	return h.cancelOpExpect(serverOpKey(id), actor, opID)
}
