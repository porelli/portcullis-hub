package agent

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"time"

	"crypto/ecdsa"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/servers"
)

// NonceTTL: an enrolment nonce is single use and valid this long.
const NonceTTL = 60 * time.Second

// selfSigned is the enrolling certificate: a fresh key, CN/SAN the node
// name, valid around now. Its SPKI is bound into the enrolment proof.
func selfSigned(name string, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	k, err := NewTLSKey()
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return k, c, err
}

func (a *Agent) handleNonce(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.phase != phaseJoin {
		writeError(w, http.StatusConflict, "the proof was already given")
		return
	}
	n := make([]byte, servers.NonceLen)
	if _, err := rand.Read(n); err != nil {
		writeError(w, http.StatusInternalServerError, "no randomness")
		return
	}
	a.nonce, a.nonceExpires = n, a.cfg.Now().Add(NonceTTL)
	writeJSON(w, http.StatusOK, agentapi.EnrolNonce{Nonce: n})
}

// fail counts a refused enrolment step; the third stops the agent.
func (a *Agent) failLocked() {
	a.failures++
	if a.failures >= MaxEnrolFailures {
		// Survives a restart (review L1): the pins say refused and the
		// join code is gone; only a new worker join starts over.
		p := a.pins
		p.State = StateRefused
		a.store.SavePins(p)
		os.Remove(a.store.path(joinFile))
		a.pins, a.state = p, StateRefused
		a.once.Do(func() { close(a.refused) })
	}
}

func (a *Agent) handleEnrol(w http.ResponseWriter, r *http.Request) {
	var req agentapi.EnrolProof
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.phase != phaseJoin {
		writeError(w, http.StatusConflict, "the proof was already given")
		return
	}
	nonce, expires := a.nonce, a.nonceExpires
	a.nonce = nil // single use, whatever the outcome
	switch {
	case nonce == nil:
		a.failLocked()
		writeError(w, http.StatusForbidden, "no nonce (or it was used): ask for one first")
		return
	case a.cfg.Now().After(expires):
		a.failLocked()
		writeError(w, http.StatusForbidden, "the nonce expired")
		return
	case !servers.VerifyProof(a.join.SecretBytes(), nonce, a.join.ServerID, spki(a.enrolCert), req.Proof):
		a.failLocked()
		writeError(w, http.StatusForbidden, "enrolment proof refused")
		return
	}
	if want := servers.NodeName(a.join.ServerID); req.CSRCN != want {
		writeError(w, http.StatusBadRequest, "csr_cn must be "+want)
		return
	}
	tlsKey, err := NewTLSKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	wgKey, err := GenerateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	if err := a.store.saveTLSKey(tlsKeyNewFile, tlsKey); err != nil {
		writeError(w, http.StatusInternalServerError, "can't store the new key")
		return
	}
	if err := a.store.saveWGKey(wgKeyNewFile, wgKey); err != nil {
		writeError(w, http.StatusInternalServerError, "can't store the new key")
		return
	}
	csr, err := makeCSR(tlsKey, req.CSRCN)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CSR failed")
		return
	}
	a.pendingTLS, a.pendingWG, a.hasPendingWG = tlsKey, wgKey, true
	a.phase = phaseProven
	writeJSON(w, http.StatusOK, agentapi.IdentityCSR{CSR: csr, WGPublicKey: wgKey.Public().String()})
}

func makeCSR(k *ecdsa.PrivateKey, cn string) (string, error) {
	// The CN only: enroll refuses a CSR with any SAN (Vault adds the
	// node name as the SAN from the role).
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// checkNodeCert: cert is the node-worker certificate for the pending key:
// CN and the only SAN the node name, issued by ca for server and client
// auth (verified with the clock tolerance).
func (a *Agent) checkNodeCert(cert, ca *x509.Certificate, pending *ecdsa.PrivateKey) error {
	name := servers.NodeName(a.pins.ServerID)
	if cert.Subject.CommonName != name || len(cert.DNSNames) != 1 || cert.DNSNames[0] != name ||
		len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) != 0 {
		return errors.New("the certificate must name exactly " + name)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&pending.PublicKey) {
		return errors.New("the certificate is not for the agent's pending key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	now := a.cfg.Now()
	var err error
	for _, at := range []time.Time{now, now.Add(-ClockTolerance), now.Add(ClockTolerance)} {
		if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			break
		}
	}
	if err != nil {
		return errors.New("the certificate isn't issued by the pinned CA for server auth")
	}
	return nil
}

func (a *Agent) handleCert(w http.ResponseWriter, r *http.Request) {
	var req agentapi.IdentityCert
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, err1 := parseCertPEM(req.Certificate)
	ca, err2 := parseCertPEM(req.CA)
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, "certificate and ca must be one PEM certificate each")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	enrolling := a.state == StateEnrolling
	if (enrolling && a.phase != phaseProven) || a.pendingTLS == nil {
		writeError(w, http.StatusConflict, "no pending key: ask for a CSR first")
		return
	}
	if a.ca == nil || !ca.Equal(a.ca) {
		writeError(w, http.StatusBadRequest, "ca is not the pinned pki_node CA")
		return
	}
	if err := a.checkNodeCert(cert, a.ca, a.pendingTLS); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.store.write(tlsCertFile, certPEM(cert)); err != nil {
		writeError(w, http.StatusInternalServerError, "can't store the certificate")
		return
	}
	if err := a.store.saveTLSKey(tlsKeyFile, a.pendingTLS); err != nil {
		writeError(w, http.StatusInternalServerError, "can't store the key")
		return
	}
	os.Remove(a.store.path(tlsKeyNewFile))
	if enrolling {
		if err := a.store.write(caFile, certPEM(a.ca)); err != nil {
			writeError(w, http.StatusInternalServerError, "can't store the CA")
			return
		}
		a.phase = phaseCertSet
	}
	a.tlsCert, a.tlsKey, a.pendingTLS = cert, a.pendingTLS, nil
	w.WriteHeader(http.StatusNoContent)
}

func (a *Agent) handleCSR(w http.ResponseWriter, r *http.Request) {
	k, err := NewTLSKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.store.saveTLSKey(tlsKeyNewFile, k); err != nil {
		writeError(w, http.StatusInternalServerError, "can't store the new key")
		return
	}
	csr, err := makeCSR(k, servers.NodeName(a.pins.ServerID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CSR failed")
		return
	}
	wg, err := a.store.wgKey(wgKeyFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no WireGuard key")
		return
	}
	a.pendingTLS = k
	writeJSON(w, http.StatusOK, agentapi.IdentityCSR{CSR: csr, WGPublicKey: wg.Public().String()})
}

// validNetwork: an IPv4 proxy subnet, the dynamic range inside it, and
// the Traefik address inside the subnet but outside the range.
func validNetwork(n agentapi.NetworkParams) error {
	s, rg, ip := n.ProxySubnet, n.ProxyIPRange, n.TraefikIP
	switch {
	case !s.IsValid() || !s.Addr().Is4() || s.Masked() != s || s.Bits() > 29:
		return errors.New("proxy_subnet must be a masked IPv4 prefix of /29 or wider")
	case !rg.IsValid() || !rg.Addr().Is4() || rg.Masked() != rg || !s.Contains(rg.Addr()) || rg.Bits() < s.Bits():
		return errors.New("proxy_ip_range must be a masked prefix inside proxy_subnet")
	case !ip.Is4() || !s.Contains(ip) || rg.Contains(ip) || ip == s.Addr():
		return errors.New("traefik_ip must be in proxy_subnet, outside proxy_ip_range")
	}
	return nil
}

func (a *Agent) handleNetwork(w http.ResponseWriter, r *http.Request) {
	var req agentapi.NetworkParams
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validNetwork(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.phase != phaseCertSet {
		writeError(w, http.StatusConflict, "the network is set once, after the certificate")
		return
	}
	if a.cfg.OnNetwork != nil {
		if err := a.cfg.OnNetwork(r.Context(), req); err != nil {
			writeError(w, http.StatusBadGateway, "the worker's portcullis-proxy: "+clipMsg(err.Error()))
			return
		}
	}
	if err := a.store.saveNetwork(req); err != nil {
		writeError(w, http.StatusInternalServerError, "can't store the network")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Agent) handleWG(w http.ResponseWriter, r *http.Request) {
	var req agentapi.IdentityWG
	if err := agentapi.Decode(r.Body, agentapi.MaxJSON, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.phase != phaseCertSet || !a.hasPendingWG {
		writeError(w, http.StatusConflict, "the key switch comes after the certificate")
		return
	}
	if !a.store.exists(networkFile) {
		writeError(w, http.StatusConflict, "set the network first (PUT /v1/network)")
		return
	}
	if req.LinkPub != a.pins.LinkPub {
		writeError(w, http.StatusBadRequest, "link_pub is not the link key of the join code")
		return
	}
	a.phase = phaseSwitched
	go a.switchKey()
	writeJSON(w, http.StatusOK, map[string]string{})
}

// switchKey: SwitchDelay after the answer, the tunnel moves to the
// agent's own key; a handshake on it within SwitchTimeout makes the agent
// ready (the bootstrap key and the join code deleted), else it goes back
// to the bootstrap key and waits for another PUT /v1/identity/wg.
func (a *Agent) switchKey() {
	time.Sleep(a.cfg.SwitchDelay)
	a.mu.Lock()
	t, newKey := a.tunnel, a.pendingWG
	a.mu.Unlock()
	if t == nil {
		a.revert(nil)
		return
	}
	at := time.Now()
	if err := t.SwitchKey(newKey); err != nil {
		a.revert(t)
		return
	}
	deadline := at.Add(a.cfg.SwitchTimeout)
	for time.Now().Before(deadline) {
		if hs := t.LastHandshake(); hs.After(at) {
			if err := a.finish(newKey); err != nil {
				a.revert(t)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	a.revert(t)
}

func (a *Agent) revert(t *Tunnel) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if t != nil {
		if bk, err := ParseKey(a.join.BootstrapKey); err == nil {
			t.SwitchKey(bk)
		}
	}
	a.phase = phaseCertSet
}

func (a *Agent) finish(k Key) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.store.saveWGKey(wgKeyFile, k); err != nil {
		return err
	}
	p := a.pins
	p.State = StateReady
	if err := a.store.SavePins(p); err != nil {
		return err
	}
	// The bootstrap key and the secret are dead from here on.
	os.Remove(a.store.path(joinFile))
	os.Remove(a.store.path(wgKeyNewFile))
	a.pins, a.state, a.phase = p, StateReady, ""
	a.join = servers.JoinCode{}
	a.enrolKey, a.enrolCert, a.hasPendingWG = nil, nil, false
	if lp, err := ParseKey(p.LinkPub); err == nil {
		a.linkPub = lp
	}
	return nil
}
