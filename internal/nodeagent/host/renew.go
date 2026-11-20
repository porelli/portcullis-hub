package host

import (
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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
)

// The node-cluster certificate's renewal (Task 9 rulings I4, N1): two
// phases, each idempotent, resumable across a lost answer or a crash.
//
//  1. At ⅓ of its life left the nodeagent makes a fresh key and CSR and
//     saves them as node.pending.pem (0600, the directory fsynced) before
//     any call; then POST <endpoint>/v1/renew {server_id, csr}, signed with
//     its CURRENT node-cluster key exactly as /node/v1/join. A retry sends
//     the same CSR (nodeadm answers the same certificate for an identical
//     CSR from the same node). The answer {certificate, ca, not_after} is
//     checked (the CA, the leaf within ±5 min of the local clock) and
//     node.pem (the pending key + the new certificate) replaces the old
//     one with one rename; the served certificate is swapped under mu.
//  2. POST <endpoint>/v1/renew/confirm {server_id}, signed with the NEW
//     certificate's key (the /node paths are behind Traefik, which can't
//     ask for a client certificate per path: the signed request is the
//     proof of the new key); nodeadm revokes the old certificate only
//     then. Until it confirms both stay valid. node.pending.pem goes once
//     confirmed. The confirmation is retried with backoff.
//
// A crash anywhere resumes from the files: node.pending.pem whose key
// isn't node.pem's → phase 1 again (the same CSR); whose key is → phase 2.

const (
	RenewPath        = "/v1/renew"
	RenewConfirmPath = "/v1/renew/confirm"
	pendingPEMFile   = StateDir + "/node.pending.pem"
)

type renewReq struct {
	ServerID string `json:"server_id"`
	CSR      string `json:"csr"`
}

// errNothingPending is nodeadm's confirm refusal when no renewal of the
// signing certificate is pending (core fa8d345, nodeadm_api_vectors.json).
const errNothingPending = "no renewal of this certificate is pending"

type renewConfirmReq struct {
	ServerID string `json:"server_id"`
}

type renewAnswer struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	NotAfter    string `json:"not_after"`
}

// renewDue: less than ⅓ of the certificate's life left.
func renewDue(c *x509.Certificate, now time.Time) bool {
	return c.NotAfter.Sub(now) < c.NotAfter.Sub(c.NotBefore)/3
}

// pendingRenewal is node.pending.pem: the next key and its CSR.
type pendingRenewal struct {
	key    *ecdsa.PrivateKey
	csrPEM []byte
	csr    *x509.CertificateRequest
}

func (a *Agent) loadPending() (*pendingRenewal, error) {
	b, err := a.fs.read(pendingPEMFile)
	if err != nil {
		return nil, nil
	}
	p := &pendingRenewal{}
	for rest := b; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if ek, ok := k.(*ecdsa.PrivateKey); err == nil && ok {
				p.key = ek
			}
		case "CERTIFICATE REQUEST":
			if c, err := x509.ParseCertificateRequest(blk.Bytes); err == nil {
				p.csr, p.csrPEM = c, pem.EncodeToMemory(blk)
			}
		}
	}
	if p.key == nil || p.csr == nil || p.csr.CheckSignature() != nil {
		return nil, errors.New("node.pending.pem is unreadable")
	}
	if pub, ok := p.csr.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&p.key.PublicKey) {
		return nil, errors.New("node.pending.pem's CSR isn't its key's")
	}
	return p, nil
}

func (a *Agent) newPending(cn string) (*pendingRenewal, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return nil, err
	}
	csr, _ := x509.ParseCertificateRequest(der)
	p := &pendingRenewal{key: k, csr: csr, csrPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})}
	if err := a.fs.write(pendingPEMFile, append(keyPEM(k), p.csrPEM...), 0o600, 0o700); err != nil {
		return nil, err
	}
	return p, nil
}

func sameKey(c *x509.Certificate, k *ecdsa.PrivateKey) bool {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Equal(&k.PublicKey)
}

// RenewIfDue runs whatever phase of the renewal is owed: true when it
// changed something (a certificate installed or a renewal confirmed).
func (a *Agent) RenewIfDue(ctx context.Context) (bool, error) {
	a.mu.Lock()
	cur, ca, st := a.cert, a.ca, a.st
	a.mu.Unlock()
	if cur == nil || ca == nil || st == nil {
		return false, errors.New("the nodeagent has no node-cluster certificate")
	}
	pend, err := a.loadPending()
	if err != nil {
		// A broken pending file: start the renewal again (its CSR never
		// got a certificate this node holds).
		a.log.Warn("certificate renewal", "err", err.Error())
		a.fs.remove(pendingPEMFile)
		pend = nil
	}
	if pend != nil && sameKey(cur.Leaf, pend.key) {
		return true, a.confirmRenewal(ctx, cur, st)
	}
	now := a.cfg.Now()
	if pend == nil && !renewDue(cur.Leaf, now) {
		return false, nil
	}
	curKey, ok := cur.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return false, errors.New("the node-cluster key isn't P-256")
	}
	cn := st.ID + "." + clusterDomain
	if pend == nil {
		if pend, err = a.newPending(cn); err != nil {
			return false, err
		}
	}
	body, _ := json.Marshal(renewReq{ServerID: st.ID, CSR: string(pend.csrPEM)})
	u := strings.TrimSuffix(st.Endpoint, "/") + RenewPath
	signer := joinSigner{key: curKey, cert: cur.Leaf.Raw, id: st.ID, now: a.cfg.Now}
	hdr, err := signer.headers(http.MethodPost, u, body)
	if err != nil {
		return false, err
	}
	ans, err := a.call(ctx, JoinDeps{HTTP: a.cfg.HTTP}, http.MethodPost, u, body, hdr)
	if err != nil {
		return false, err
	}
	if ans.status != http.StatusOK {
		return false, fmt.Errorf("the renewal was refused (%d): %s", ans.status, ans.text)
	}
	var ra renewAnswer
	if err := jsonstrict.Decode(ans.body, &ra); err != nil {
		return false, errors.New("the renewal answer is unreadable")
	}
	if rca, err := parseCertPEM([]byte(ra.CA)); err != nil || !rca.Equal(ca) {
		return false, errors.New("the renewal answer's CA isn't the cluster's")
	}
	leaf, err := parseCertPEM([]byte(ra.Certificate))
	if err != nil || checkNodeLeafSkew(leaf, ca, cn, pend.csr.RawSubjectPublicKeyInfo, a.cfg.Now()) != nil || !leaf.NotAfter.After(cur.Leaf.NotAfter) {
		return false, errors.New("the renewal answer's certificate isn't this node's, from the cluster's CA")
	}
	bundle := nodeBundle(pend.key, []byte(ra.Certificate))
	next, err := nodeCert(bundle)
	if err != nil {
		return false, err
	}
	if err := a.fs.write(nodePEMFile, bundle, 0o600, 0o700); err != nil {
		return false, err
	}
	a.mu.Lock()
	a.cert = next
	a.mu.Unlock()
	a.log.Info("node-cluster certificate renewed (to be confirmed)", "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return true, a.confirmRenewal(ctx, next, st)
}

// confirmRenewal is phase 2: the signed confirmation with the new key;
// node.pending.pem goes once nodeadm answered 204 (or 200).
func (a *Agent) confirmRenewal(ctx context.Context, cur *tls.Certificate, st *State) error {
	key, ok := cur.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("the node-cluster key isn't P-256")
	}
	body, _ := json.Marshal(renewConfirmReq{ServerID: st.ID})
	u := strings.TrimSuffix(st.Endpoint, "/") + RenewConfirmPath
	hdr, err := joinSigner{key: key, cert: cur.Leaf.Raw, id: st.ID, now: a.cfg.Now}.headers(http.MethodPost, u, body)
	if err != nil {
		return err
	}
	ans, err := a.call(ctx, JoinDeps{HTTP: a.cfg.HTTP}, http.MethodPost, u, body, hdr)
	if err != nil {
		return fmt.Errorf("the renewal isn't confirmed yet: %v", err)
	}
	switch {
	case ans.status/100 == 2:
	case ans.status == http.StatusConflict && ans.text == errNothingPending:
		// Signed with the new certificate: nodeadm holds no pending
		// renewal for it (already confirmed): nothing is left to do.
		a.log.Info("the renewal was confirmed already")
	default:
		return fmt.Errorf("the renewal isn't confirmed yet (%d): %s", ans.status, ans.text)
	}
	if err := a.fs.remove(pendingPEMFile); err != nil {
		return err
	}
	a.log.Info("node-cluster certificate renewal confirmed")
	return nil
}

// RunRenewal checks every hour; while a renewal waits for its
// confirmation (or its answer), it retries with backoff (30 s doubling to
// the hour).
func (a *Agent) RunRenewal(ctx context.Context) {
	backoff := 30 * time.Second
	for {
		wait := time.Hour
		if _, err := a.RenewIfDue(ctx); err != nil {
			a.log.Warn("certificate renewal", "err", err.Error())
			if a.fs.exists(pendingPEMFile) {
				wait, backoff = backoff, min(2*backoff, time.Hour)
			}
		} else {
			backoff = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// checkNodeLeafSkew: checkNodeLeaf at now, now − 5 min or now + 5 min
// (the clock tolerance of every peer check).
func checkNodeLeafSkew(leaf, ca *x509.Certificate, cn string, spki []byte, now time.Time) error {
	var err error
	for _, at := range []time.Time{now, now.Add(-ClockTolerance), now.Add(ClockTolerance)} {
		if err = checkNodeLeaf(leaf, ca, cn, spki, at); err == nil {
			return nil
		}
	}
	return err
}
