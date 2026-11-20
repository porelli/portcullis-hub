package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// The node-cluster certificate's renewal (fix round 1, I4; contract owed):
// at ⅓ of its life left the nodeagent asks nodeadm
// POST <endpoint>/v1/renew (https://<d>/node/v1/renew) with a fresh key's
// CSR, signed with its current node-cluster key exactly as /node/v1/join
// (the Portcullis-Node-* headers over the canonical JSON), and swaps the
// key and certificate in place: node.pem with one rename, then the
// served certificate under mu (GetCertificate reads it per handshake).
// The answer is {"certificate", "ca", "not_after"} (core 482653d; the
// renew cases of nodeadm_api_vectors.json). nodeadm revokes the old
// certificate at once: the new one is in place before anything else
// uses the old.

// RenewPath is the renewal's path under the code's endpoint.
const RenewPath = "/v1/renew"

// renewReq / renewAnswer are the renewal's bodies (strict both ways).
type renewReq struct {
	ServerID string `json:"server_id"`
	CSR      string `json:"csr"`
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

// RenewIfDue renews the node-cluster certificate when it is due; false
// when nothing was due.
func (a *Agent) RenewIfDue(ctx context.Context) (bool, error) {
	a.mu.Lock()
	cur, ca, st := a.cert, a.ca, a.st
	a.mu.Unlock()
	if cur == nil || ca == nil || st == nil {
		return false, errors.New("the nodeagent has no node-cluster certificate")
	}
	now := a.cfg.Now()
	if !renewDue(cur.Leaf, now) {
		return false, nil
	}
	curKey, ok := cur.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return false, errors.New("the node-cluster key isn't P-256")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	cn := st.ID + "." + clusterDomain
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return false, err
	}
	csr, _ := x509.ParseCertificateRequest(der)
	body, _ := json.Marshal(renewReq{ServerID: st.ID, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
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
	if err != nil || checkNodeLeaf(leaf, ca, cn, csr.RawSubjectPublicKeyInfo, now) != nil || !leaf.NotAfter.After(cur.Leaf.NotAfter) {
		return false, errors.New("the renewal answer's certificate isn't this node's, from the cluster's CA")
	}
	bundle := nodeBundle(k, []byte(ra.Certificate))
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
	a.log.Info("node-cluster certificate renewed", "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return true, nil
}

// RunRenewal checks the certificate every hour until ctx ends (a failed
// renewal is retried the next hour).
func (a *Agent) RunRenewal(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if _, err := a.RenewIfDue(ctx); err != nil {
			a.log.Warn("certificate renewal", "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
