// Package fidomdstest builds synthetic FIDO MDS3 BLOBs for tests: a test
// root and signer, ES256 JWS BLOBs and entries, and an HTTP server that
// serves them (no real network).
package fidomdstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// CA is a certificate and its key.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

var serialN atomic.Int64

// NewCert makes a certificate named cn, signed by parent (nil = self-signed).
func NewCert(t testing.TB, cn string, parent *CA, isCA bool) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serialN.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: c, Key: key}
}

// B64 is c in standard base64 DER.
func B64(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }

// SignBlob is an MDS3 BLOB: an ES256 JWS over payload by signer, x5c =
// chain.
func SignBlob(t testing.TB, signer *CA, chain []*x509.Certificate, payload any) []byte {
	t.Helper()
	x5c := []string{}
	for _, c := range chain {
		x5c = append(x5c, B64(c))
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "x5c": x5c})
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, signer.Key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return []byte(signing + "." + enc.EncodeToString(sig))
}

// Report is a status report: a status and an effective date ("" = none).
type Report struct{ Status, Date string }

// R is a report with status s effective on date ("" = no date).
func R(s, date string) Report { return Report{Status: s, Date: date} }

// Reports are statuses with increasing effective dates from 2025-01-01.
func Reports(statuses ...string) []Report {
	var out []Report
	for i, s := range statuses {
		out = append(out, R(s, time.Date(2025, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)))
	}
	return out
}

// Entry is a BLOB entry (aaguid "" = none; root "" = no roots).
func Entry(aaguid string, attach, keyProt []string, root string, reports []Report) map[string]any {
	rs := []map[string]any{}
	for _, r := range reports {
		m := map[string]any{"status": r.Status}
		if r.Date != "" {
			m["effectiveDate"] = r.Date
		}
		rs = append(rs, m)
	}
	roots := []string{}
	if root != "" {
		roots = append(roots, root)
	}
	st := map[string]any{
		"description":                 "test " + aaguid,
		"protocolFamily":              "fido2",
		"schema":                      3,
		"attachmentHint":              attach,
		"keyProtection":               keyProt,
		"attestationRootCertificates": roots,
	}
	e := map[string]any{"metadataStatement": st, "statusReports": rs, "timeOfLastStatusChange": "2025-01-01"}
	if aaguid != "" {
		e["aaguid"], st["aaguid"] = aaguid, aaguid
	} else {
		e["attestationCertificateKeyIdentifiers"] = []string{"0123456789abcdef0123456789abcdef01234567"}
	}
	return e
}

// Payload is a BLOB payload.
func Payload(no int, next time.Time, entries ...map[string]any) map[string]any {
	if entries == nil {
		entries = []map[string]any{}
	}
	return map[string]any{"legalHeader": "test", "no": no, "nextUpdate": next.Format(time.DateOnly), "entries": entries}
}

// Server serves the stored BLOB, or the stored status code when not 0.
type Server struct {
	blob atomic.Pointer[[]byte]
	code atomic.Int32
	hits atomic.Int64
}

// Serve stores the BLOB to serve.
func (s *Server) Serve(b []byte) { s.blob.Store(&b) }

// Fail makes every request answer code (0 = serve again).
func (s *Server) Fail(code int) { s.code.Store(int32(code)) }

// Hits is how many requests it answered.
func (s *Server) Hits() int64 { return s.hits.Load() }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	if c := s.code.Load(); c != 0 {
		http.Error(w, "down", int(c))
		return
	}
	if b := s.blob.Load(); b != nil {
		w.Write(*b)
		return
	}
	http.Error(w, "nothing", http.StatusNotFound)
}
