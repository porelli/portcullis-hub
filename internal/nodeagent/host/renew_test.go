package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	na "github.com/portcullis/hub/internal/nodeagent"
)

// fakeRenew is nodeadm's renew + confirm: the same certificate for an
// identical CSR (N1), the old serial revoked only at the confirmation,
// signed by the new key.
type fakeRenew struct {
	t        *testing.T
	ca       *testCA
	mu       sync.Mutex
	issued   map[string][]byte // CSR public key DER → certificate DER
	renews   int
	confirms int
	drop     int           // answers to drop (committed, then the connection cut)
	confirmF int           // confirmations to fail with 503
	skew     time.Duration // the certificates' validity shift (nodeadm's clock)
	revoked  bool
	signer   []byte // the certificate that signed the last call
	srv      *httptest.Server
}

func (f *fakeRenew) handler(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	h := req.Header
	der, _ := base64.StdEncoding.DecodeString(h.Get("Portcullis-Node-Cert"))
	cert, err := x509.ParseCertificate(der)
	sig, _ := base64.RawURLEncoding.DecodeString(h.Get("Portcullis-Node-Signature"))
	d := sha256.Sum256(CanonicalBytes("n2", req.Method, req.RequestURI, h.Get("Portcullis-Node-Time"), h.Get("Portcullis-Node-Nonce"), b))
	if err != nil || !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), d[:], sig) {
		w.WriteHeader(403)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signer = cert.Raw
	switch req.URL.Path {
	case "/node/v1/renew":
		f.renews++
		var q renewReq
		if jsonstrict.Decode(b, &q) != nil || q.ServerID != "n2" {
			w.WriteHeader(400)
			return
		}
		blk, _ := pem.Decode([]byte(q.CSR))
		csr, _ := x509.ParseCertificateRequest(blk.Bytes)
		k := string(csr.RawSubjectPublicKeyInfo)
		nd, ok := f.issued[k]
		if !ok {
			now := time.Now().Add(f.skew)
			nd = f.ca.signFor(f.t, "n2."+clusterDomain, csr.PublicKey, now.Add(-30*time.Second), now.Add(30*24*time.Hour))
			f.issued[k] = nd
		}
		if f.drop > 0 {
			f.drop--
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
			return
		}
		json.NewEncoder(w).Encode(renewAnswer{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nd})),
			CA: string(f.ca.pem), NotAfter: "2026-12-20T00:00:00Z"})
	case "/node/v1/renew/confirm":
		f.confirms++
		var q renewConfirmReq
		if jsonstrict.Decode(b, &q) != nil || q.ServerID != "n2" {
			w.WriteHeader(400)
			return
		}
		if f.confirmF > 0 {
			f.confirmF--
			w.WriteHeader(503)
			return
		}
		f.revoked = true
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

// renewRig: a server rig whose certificate is in its last third, and a
// fake nodeadm.
func renewRig(t *testing.T) (*rig, *fakeRenew) {
	r := newRig(t, "server")
	f := &fakeRenew{t: t, ca: r.ca, issued: map[string][]byte{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(f.srv.Close)
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := r.ca.signFor(t, "n2."+clusterDomain, &nk.PublicKey, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))
	writeFile(t, r.root, nodePEMFile, string(nodeBundle(nk, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), 0o600)
	setEndpoint(t, r, f.srv.URL+"/node")
	r.a.cfg.HTTP = f.srv.Client()
	return r, f
}

func setEndpoint(t *testing.T, r *rig, ep string) {
	b, _ := os.ReadFile(filepath.Join(r.root, stateFile))
	var st State
	json.Unmarshal(b, &st)
	st.Endpoint = ep
	b, _ = json.Marshal(st)
	writeFile(t, r.root, stateFile, string(b), 0o600)
	if err := r.a.Load(); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) leaf() *x509.Certificate {
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	return r.a.cert.Leaf
}

// TestRenew: not due → no call; due → the pending key and CSR saved
// first, the certificate installed on disk and on the wire, then the
// confirmation signed with the new key, the pending file gone; the core
// renew vectors decode.
func TestRenew(t *testing.T) {
	ctx := context.Background()
	r0 := newRig(t, "server")
	f0 := &fakeRenew{t: t, ca: r0.ca, issued: map[string][]byte{}}
	f0.srv = httptest.NewTLSServer(http.HandlerFunc(f0.handler))
	defer f0.srv.Close()
	setEndpoint(t, r0, f0.srv.URL+"/node")
	r0.a.cfg.HTTP = f0.srv.Client()
	if done, err := r0.a.RenewIfDue(ctx); done || err != nil || f0.renews != 0 {
		t.Fatalf("not due: %v %v %d", done, err, f0.renews)
	}

	r, f := renewRig(t)
	old := r.leaf()
	if done, err := r.a.RenewIfDue(ctx); !done || err != nil || f.renews != 1 || f.confirms != 1 || !f.revoked {
		t.Fatalf("due: %v %v renews %d confirms %d", done, err, f.renews, f.confirms)
	}
	nw := r.leaf()
	if nw.Equal(old) || !nw.NotAfter.After(old.NotAfter) {
		t.Error("the served certificate wasn't swapped")
	}
	if c, _ := x509.ParseCertificate(f.signer); !c.Equal(nw) {
		t.Error("the confirmation wasn't signed with the new certificate")
	}
	b, _ := os.ReadFile(filepath.Join(r.root, nodePEMFile))
	if disk, err := nodeCert(b); err != nil || !disk.Leaf.Equal(nw) {
		t.Errorf("node.pem: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(r.root, nodePEMFile)); fi.Mode().Perm() != 0o600 {
		t.Error("node.pem's mode")
	}
	if _, err := os.Stat(filepath.Join(r.root, pendingPEMFile)); err == nil {
		t.Error("node.pending.pem stayed after the confirmation")
	}
	s := r.server()
	resp, err := r.client(r.ca, na.CNHub).Get(s.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !resp.TLS.PeerCertificates[0].Equal(nw) {
		t.Error("the API serves the old certificate")
	}
	if done, _ := r.a.RenewIfDue(ctx); done || f.renews != 1 {
		t.Error("a renewed certificate renewed again")
	}
	// The core renew vectors (Hub copy of nodeadm_api_vectors.json).
	var d struct {
		Cases []struct {
			Name     string `json:"name"`
			Route    string `json:"route"`
			Response struct {
				Status int             `json:"status"`
				Body   json.RawMessage `json:"body"`
			} `json:"response"`
		} `json:"cases"`
	}
	vb, _ := os.ReadFile("../../nodeadm/testdata/nodeadm_api_vectors.json")
	json.Unmarshal(vb, &d)
	n := 0
	for _, c := range d.Cases {
		switch c.Route {
		case "POST /node/v1/renew":
			n++
			if c.Response.Status == 200 {
				var ra renewAnswer
				if err := jsonstrict.Decode(c.Response.Body, &ra); err != nil {
					t.Errorf("%s: %v", c.Name, err)
				}
			}
		case "POST /node/v1/join":
			if c.Name == "join" {
				var ja joinAnswer
				if err := jsonstrict.Decode(c.Response.Body, &ja); err != nil || ja.ClusterCIDR == "" {
					t.Errorf("the join vector's answer: %v", err)
				}
			}
		}
	}
	if n < 3 {
		t.Errorf("%d renew vectors", n)
	}
}

// TestRenewLostAnswer (N1): nodeadm commits the renewal and the answer is
// lost; the retry sends the same CSR (the saved key), gets the same
// certificate, installs it and confirms; nothing was revoked before.
func TestRenewLostAnswer(t *testing.T) {
	r, f := renewRig(t)
	f.drop = 1
	old := r.leaf()
	if _, err := r.a.RenewIfDue(context.Background()); err == nil {
		t.Fatal("a lost answer succeeded")
	}
	if !r.leaf().Equal(old) || f.revoked || len(f.issued) != 1 {
		t.Fatalf("after the lost answer: swapped %v revoked %v issued %d", !r.leaf().Equal(old), f.revoked, len(f.issued))
	}
	fi, err := os.Stat(filepath.Join(r.root, pendingPEMFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("node.pending.pem: %v", err)
	}
	// A restart in between (the pending file is the only memory).
	if err := r.a.Load(); err != nil {
		t.Fatal(err)
	}
	if done, err := r.a.RenewIfDue(context.Background()); !done || err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if len(f.issued) != 1 || f.renews != 2 || !f.revoked || r.leaf().Equal(old) {
		t.Errorf("the retry: issued %d renews %d revoked %v", len(f.issued), f.renews, f.revoked)
	}
	if want := f.issued[string(r.leaf().RawSubjectPublicKeyInfo)]; want == nil || !r.leaf().Equal(mustCert(want)) {
		t.Error("the retry's certificate isn't the one issued for the same CSR")
	}
}

func mustCert(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

// TestRenewCrashBeforeConfirm (N1): installed, then the confirmation
// fails and the process restarts: the new certificate is loaded, the
// renewal isn't asked again, the confirmation is retried with the new key
// until it lands; the old one is revoked only then.
func TestRenewCrashBeforeConfirm(t *testing.T) {
	r, f := renewRig(t)
	f.confirmF = 2
	old := r.leaf()
	if _, err := r.a.RenewIfDue(context.Background()); err == nil {
		t.Fatal("an unconfirmed renewal reported done")
	}
	if r.leaf().Equal(old) || f.revoked {
		t.Fatal("not installed, or revoked before the confirmation")
	}
	// The crash: a new process from the files.
	b := New(r.a.cfg)
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	if b.cert.Leaf.Equal(old) {
		t.Fatal("the restart loaded the old certificate")
	}
	if _, err := b.RenewIfDue(context.Background()); err == nil {
		t.Fatal("the second confirmation was to fail")
	}
	if done, err := b.RenewIfDue(context.Background()); !done || err != nil || !f.revoked {
		t.Fatalf("the confirmation retry: %v", err)
	}
	if f.renews != 1 || f.confirms != 3 {
		t.Errorf("renews %d confirms %d", f.renews, f.confirms)
	}
	if c, _ := x509.ParseCertificate(f.signer); !c.Equal(b.cert.Leaf) {
		t.Error("a confirmation not signed by the new certificate")
	}
	if _, err := os.Stat(filepath.Join(r.root, pendingPEMFile)); err == nil {
		t.Error("node.pending.pem stayed")
	}
}

// TestRenewClockSkew: a node 4 minutes behind or ahead of nodeadm
// installs the new certificate; 6 minutes is refused (and nothing is
// installed, the pending key kept for a retry).
func TestRenewClockSkew(t *testing.T) {
	for _, c := range []struct {
		skew time.Duration
		ok   bool
	}{{4 * time.Minute, true}, {-4 * time.Minute, true}, {6 * time.Minute, false}} {
		r, f := renewRig(t)
		// nodeadm's clock is skew ahead of the node's: the leaf's NotBefore
		// (nodeadm now − 30 s) sits in the node's future when skew > 30 s.
		f.skew = c.skew
		old := r.leaf()
		_, err := r.a.RenewIfDue(context.Background())
		if (err == nil) != c.ok || r.leaf().Equal(old) == c.ok {
			t.Errorf("skew %v: %v, swapped %v", c.skew, err, !r.leaf().Equal(old))
		}
		if !c.ok {
			if _, err := os.Stat(filepath.Join(r.root, pendingPEMFile)); err != nil {
				t.Errorf("skew %v: the pending key went", c.skew)
			}
		}
	}
}
