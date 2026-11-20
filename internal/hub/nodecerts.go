package hub

import (
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
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
)

// Node certificates (contract §17.5): the Hub's hub.control certificate
// (with its key in <data>/nodes/control.pem, 0600, never leaves the Hub;
// the last good pair in control.prev.pem) and
// the workers' node-worker certificates, signed by core's enroll
// (POST /internal/nodes/sign|revoke, the invite bearer). The Hub never
// holds a Vault token.

// Node roles enroll signs for the Hub.
const (
	RoleNodeWorker  = "node-worker"
	RoleNodeControl = "node-control"
	ControlCN       = "hub.control"
)

// NodeCert is enroll's answer: the PEM certificate, its serial (Vault's
// "0a:1b:…"), when it ends and the pki_node CA (PEM).
type NodeCert struct {
	Certificate, Serial, CA string
	NotAfter                time.Time
}

// NodeSigner signs and revokes node certificates (enroll).
type NodeSigner interface {
	SignNode(ctx context.Context, role, cn, csrPEM string) (*NodeCert, error)
	RevokeNode(ctx context.Context, serial string) error
}

// EnrollNodes is NodeSigner over enroll's internal listener: the invite
// API's host and secret file.
type EnrollNodes struct {
	Base       string // http://enroll:8444
	SecretFile string
	HTTP       *http.Client
}

// NewEnrollNodes takes the invite API URL (its scheme and host) and the
// invite secret file.
func NewEnrollNodes(inviteURL, secretFile string) (*EnrollNodes, error) {
	u, err := url.Parse(inviteURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("the invite API URL %q isn't valid", inviteURL)
	}
	return &EnrollNodes{Base: u.Scheme + "://" + u.Host, SecretFile: secretFile, HTTP: &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (e *EnrollNodes) post(ctx context.Context, p string, body, out any) error {
	// The write fence (contract §20.5): a Hub standing by issues nothing.
	if err := fsutil.CheckWrite(); err != nil {
		return err
	}
	b, err := os.ReadFile(e.SecretFile)
	if err != nil || len(strings.TrimSpace(string(b))) < 32 {
		return errors.New("enroll: the invite secret is unavailable")
	}
	j, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", e.Base+p, bytes.NewReader(j))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := fsutil.Do(e.HTTP, req)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		var eb struct {
			Error string `json:"error"`
		}
		json.Unmarshal(rb, &eb)
		return statusErr(502, "enroll answered %d: %s", resp.StatusCode, clipRunes(eb.Error, 200))
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

func (e *EnrollNodes) SignNode(ctx context.Context, role, cn, csrPEM string) (*NodeCert, error) {
	var r struct {
		Certificate string `json:"certificate"`
		Serial      string `json:"serial"`
		NotAfter    string `json:"not_after"`
		CA          string `json:"ca"`
	}
	if err := e.post(ctx, "/internal/nodes/sign", map[string]string{"role": role, "common_name": cn, "csr": csrPEM}, &r); err != nil {
		return nil, err
	}
	na, err := time.Parse(time.RFC3339, r.NotAfter)
	if err != nil {
		return nil, errors.New("enroll: not_after isn't RFC 3339")
	}
	return &NodeCert{Certificate: r.Certificate, Serial: r.Serial, CA: r.CA, NotAfter: na}, nil
}

func (e *EnrollNodes) RevokeNode(ctx context.Context, serial string) error {
	return e.post(ctx, "/internal/nodes/revoke", map[string]string{"serial": serial}, nil)
}

// SetNodeSigner wires enroll (cmd/hub/main.go).
func (h *Hub) SetNodeSigner(s NodeSigner) {
	h.srvMu.Lock()
	h.signer = s
	h.srvMu.Unlock()
}

func (h *Hub) nodeSigner() NodeSigner {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	return h.signer
}

func (h *Hub) nodesDir() string { return filepath.Join(h.cfg.DataDir, "nodes") }

// newNodeKey is a node key (EC P-256, the roles' key type) and its CSR
// for cn: the CN only (enroll refuses any SAN).
func newNodeKey(cn string) (*ecdsa.PrivateKey, string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return nil, "", err
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func parseOnePEMCert(p string) (*x509.Certificate, error) {
	blk, rest := pem.Decode([]byte(p))
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not exactly one PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// checkNodeCA: the pki_node CA is a self-signed CA (its own root, P1).
func checkNodeCA(c *x509.Certificate) error {
	if !c.IsCA || c.CheckSignatureFrom(c) != nil {
		return errors.New("the pki_node CA isn't a self-signed CA certificate")
	}
	return nil
}

// caSHA256 is the join code's ca_sha256: sha256 of the CA's DER (P5).
func caSHA256(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// VaultSerial is a serial as Vault writes it ("0a:1b:…", lower case).
func VaultSerial(n *big.Int) string {
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = hex.EncodeToString([]byte{x})
	}
	return strings.Join(parts, ":")
}

// renewDue: less than ⅓ of the certificate's life is left.
func renewDue(c *x509.Certificate, now time.Time) bool {
	life := c.NotAfter.Sub(c.NotBefore)
	return c.NotAfter.Sub(now) < life/3
}

// controlCert is the Hub's hub.control certificate (with the pki_node
// CA): loaded from <data>/nodes, (re)issued through enroll when missing
// or at ⅓ remaining life, a new key each time.
func (h *Hub) controlCert(ctx context.Context) (tls.Certificate, *x509.Certificate, error) {
	h.nodeMu.Lock()
	defer h.nodeMu.Unlock()
	dir := h.nodesDir()
	cert, ca, err := loadControl(dir)
	if err == nil && !renewDue(cert.Leaf, h.now()) {
		return cert, ca, nil
	}
	signer := h.nodeSigner()
	if signer == nil {
		if err == nil {
			return cert, ca, nil // due but no signer: keep using it until it ends
		}
		return tls.Certificate{}, nil, statusErr(503, "enroll isn't configured: node certificates can't be signed")
	}
	k, csr, kerr := newNodeKey(ControlCN)
	if kerr != nil {
		return tls.Certificate{}, nil, kerr
	}
	nc, serr := signer.SignNode(ctx, RoleNodeControl, ControlCN, csr)
	if serr != nil {
		if err == nil {
			return cert, ca, nil
		}
		return tls.Certificate{}, nil, serr
	}
	leaf, perr := parseOnePEMCert(nc.Certificate)
	nca, cerr := parseOnePEMCert(nc.CA)
	if perr != nil || cerr != nil || leaf.Subject.CommonName != ControlCN {
		return tls.Certificate{}, nil, statusErr(502, "enroll's control certificate is unusable")
	}
	if err := checkNodeCA(nca); err != nil {
		return tls.Certificate{}, nil, statusErr(502, "%v", err)
	}
	// The new leaf chains to pki_node and is for client auth (B-L5).
	if leaf.CheckSignatureFrom(nca) != nil || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return tls.Certificate{}, nil, statusErr(502, "enroll's control certificate isn't a pki_node client certificate")
	}
	if ca != nil && !ca.Equal(nca) {
		return tls.Certificate{}, nil, statusErr(502, "enroll answered with another pki_node CA than the pinned one")
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	// A renewal whose files can't be written (the fence closed meanwhile,
	// a full disk) keeps the old certificate while it is still valid: a
	// read (the HA page, the cluster tick) never fails for it.
	keepOld := func(werr error) (tls.Certificate, *x509.Certificate, error) {
		if err == nil && cert.Leaf != nil && h.now().Before(cert.Leaf.NotAfter) {
			log.Printf("servers: the renewed control certificate couldn't be saved (%v): the current one stays in use", werr)
			return cert, ca, nil
		}
		return tls.Certificate{}, nil, werr
	}
	if err := fsutil.MkdirAll(dir, 0o700); err != nil {
		return keepOld(err)
	}
	// The CA is the pinned one (checked above). The certificate and its
	// key are one file, control.pem, written by one atomic write: a
	// mismatched pair is never on disk. The current pair is kept first as
	// control.prev.pem, the last good one loadControl falls back to.
	if err == nil {
		if cur, rerr := os.ReadFile(filepath.Join(dir, controlPair)); rerr == nil {
			if werr := fsutil.WriteFileAtomic(filepath.Join(dir, controlPrev), cur, 0o600); werr != nil {
				return keepOld(werr)
			}
		}
	}
	if werr := fsutil.WriteFileAtomic(filepath.Join(dir, "ca.crt"), []byte(nc.CA), 0o600); werr != nil {
		return keepOld(werr)
	}
	pair := append([]byte(strings.TrimSpace(nc.Certificate)+"\n"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	if werr := fsutil.WriteFileAtomic(filepath.Join(dir, controlPair), pair, 0o600); werr != nil {
		return keepOld(werr)
	}
	// The control certificate it replaces is owed: the tick revokes it
	// (B-L5, as ruling 50 for the workers').
	if err == nil && cert.Leaf != nil {
		h.mu.Lock()
		if oerr := h.oweSerialLocked("", VaultSerial(cert.Leaf.SerialNumber)); oerr != nil {
			log.Printf("servers: recording the old control certificate for revocation: %v", oerr)
		}
		h.mu.Unlock()
	}
	return loadControl(dir)
}

// controlPair / controlPrev are the control certificate and its key in
// one PEM file (one atomic write), and the last good pair before it.
const (
	controlPair = "control.pem"
	controlPrev = "control.prev.pem"
)

// loadControl is the control pair (control.pem, else the last good one,
// control.prev.pem: a pair that doesn't load or match is never used)
// with the pinned CA.
func loadControl(dir string) (tls.Certificate, *x509.Certificate, error) {
	caB, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return tls.Certificate{}, nil, errors.New("no control certificate yet")
	}
	var c tls.Certificate
	var perr error = errors.New("no control certificate yet")
	for _, name := range []string{controlPair, controlPrev} {
		b, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		if c, err = tls.X509KeyPair(b, b); err == nil {
			perr = nil
			if name == controlPrev {
				log.Printf("servers: %s doesn't load: using the last good control certificate", controlPair)
			}
			break
		}
		perr = fmt.Errorf("%s: %w", name, err)
	}
	if perr != nil {
		return tls.Certificate{}, nil, perr
	}
	ca, err := parseOnePEMCert(string(caB))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	// The chain carries the CA: an enrolling agent learns it from there.
	c.Certificate = append(c.Certificate, ca.Raw)
	return c, ca, nil
}
