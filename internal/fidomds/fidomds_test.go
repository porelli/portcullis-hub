package fidomds

import (
	"bytes"
	"context"
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
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
)

// testCA is a certificate and its key, built in the test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serialN atomic.Int64

func newCert(t *testing.T, cn string, parent *testCA, isCA bool) *testCA {
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
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

func b64(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }

// signBlob is an MDS3 BLOB: an ES256 JWS over payload, x5c = chain.
func signBlob(t *testing.T, signer *testCA, chain []*x509.Certificate, payload any) []byte {
	t.Helper()
	x5c := []string{}
	for _, c := range chain {
		x5c = append(x5c, b64(c))
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "x5c": x5c})
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, signer.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return []byte(signing + "." + enc.EncodeToString(sig))
}

const (
	aaguidKey    = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
	aaguidDevice = "08987058-cadc-4b81-b6e1-30de50dcbe96"
	aaguidSoft   = "11111111-2222-4333-8444-555555555555"
	aaguidRevKey = "22222222-3333-4444-8555-666666666666"
	aaguidComp   = "33333333-4444-4555-8666-777777777777"
	aaguidNotCrt = "44444444-5555-4666-8777-888888888888"
)

func entry(aaguid string, attach, keyProt []string, root string, statuses ...string) map[string]any {
	var reports []map[string]any
	for i, s := range statuses {
		reports = append(reports, map[string]any{"status": s, "effectiveDate": time.Date(2025, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)})
	}
	return map[string]any{
		"aaguid": aaguid,
		"metadataStatement": map[string]any{
			"aaguid":                      aaguid,
			"description":                 "test " + aaguid,
			"protocolFamily":              "fido2",
			"schema":                      3,
			"attachmentHint":              attach,
			"keyProtection":               keyProt,
			"attestationRootCertificates": []string{root},
		},
		"statusReports":          reports,
		"timeOfLastStatusChange": "2025-01-01",
	}
}

func payload(no int, next time.Time, entries ...map[string]any) map[string]any {
	if entries == nil {
		entries = []map[string]any{}
	}
	return map[string]any{
		"legalHeader": "test",
		"no":          no,
		"nextUpdate":  next.Format(time.DateOnly),
		"entries":     entries,
	}
}

// mdsServer serves *blob, or status code *code when it isn't 0.
type mdsServer struct {
	blob atomic.Pointer[[]byte]
	code atomic.Int32
}

func (s *mdsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c := s.code.Load(); c != 0 {
		http.Error(w, "down", int(c))
		return
	}
	w.Write(*s.blob.Load())
}

type fixture struct {
	root, leaf *testCA
	srv        *mdsServer
	f          *Fetcher
	now        time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := newCert(t, "MDS test root", nil, true)
	leaf := newCert(t, "MDS test signer", root, false)
	srv := &mdsServer{}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	fx := &fixture{root: root, leaf: leaf, srv: srv, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	fx.f = &Fetcher{
		URL:       ts.URL,
		CacheFile: filepath.Join(t.TempDir(), "signin", "mds.jwt"),
		Roots:     pool,
		HTTP:      ts.Client(),
		Now:       func() time.Time { return fx.now },
	}
	return fx
}

// fresh is a new Fetcher on the same cache (a new process).
func (fx *fixture) fresh() *Fetcher {
	return &Fetcher{URL: fx.f.URL, CacheFile: fx.f.CacheFile, Roots: fx.f.Roots, HTTP: fx.f.HTTP, Now: fx.f.Now}
}

func (fx *fixture) serve(t *testing.T, no int, entries ...map[string]any) []byte {
	b := signBlob(t, fx.leaf, []*x509.Certificate{fx.leaf.cert, fx.root.cert}, payload(no, fx.now.AddDate(0, 0, 20), entries...))
	fx.srv.blob.Store(&b)
	return b
}

func TestRefreshCachesVerifiedBlob(t *testing.T) {
	fx := newFixture(t)
	blob := fx.serve(t, 87)
	st, err := fx.f.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Serial != 87 || st.Stale || st.Err != "" || !st.FetchedAt.Equal(fx.now) {
		t.Errorf("status = %+v", st)
	}
	got, err := os.ReadFile(fx.f.CacheFile)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("cache = %q, %v", got, err)
	}
	for path, want := range map[string]os.FileMode{fx.f.CacheFile: 0600, filepath.Dir(fx.f.CacheFile): 0700} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, %v; want %v", path, fi.Mode().Perm(), err, want)
		}
	}
	// A new Fetcher reads (and verifies) the cache.
	f2 := fx.fresh()
	m, st, err := f2.Load()
	if err != nil || m.Parsed.Number != 87 || st.Serial != 87 {
		t.Fatalf("Load = %v %+v %v", m, st, err)
	}
}

// TestRefreshVerifiesSignature: a BLOB signed by another key (or chained
// to another root) is refused and the cache is untouched.
func TestRefreshVerifiesSignature(t *testing.T) {
	fx := newFixture(t)
	good := fx.serve(t, 10)
	if _, err := fx.f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := newCert(t, "other root", nil, true)
	otherLeaf := newCert(t, "other signer", other, false)
	p := payload(11, fx.now.AddDate(0, 0, 20), entry(aaguidKey, []string{"external"}, []string{"secure_element"}, b64(fx.root.cert), "FIDO_CERTIFIED"))
	for name, blob := range map[string][]byte{
		// Right chain, signed by another key.
		"wrong key": signBlob(t, otherLeaf, []*x509.Certificate{fx.leaf.cert, fx.root.cert}, p),
		// Another root's chain.
		"wrong root": signBlob(t, otherLeaf, []*x509.Certificate{otherLeaf.cert, other.cert}, p),
		// No x5c chain to the roots at all.
		"leaf only": signBlob(t, fx.leaf, []*x509.Certificate{fx.leaf.cert}, p),
		"garbage":   []byte("not.a.jwt"),
	} {
		fx.srv.blob.Store(&blob)
		st, err := fx.f.Refresh(context.Background())
		if err == nil {
			t.Errorf("%s: Refresh accepted it", name)
			continue
		}
		if st == nil || st.Serial != 10 || st.Err == "" {
			t.Errorf("%s: status = %+v", name, st)
		}
		if got, _ := os.ReadFile(fx.f.CacheFile); !bytes.Equal(got, good) {
			t.Errorf("%s: cache changed", name)
		}
		if m, _, err := fx.f.Load(); err != nil || m.Parsed.Number != 10 {
			t.Errorf("%s: Load = %v, %v", name, m, err)
		}
	}
}

// TestRefreshKeepsLastGood: server 500 → Load returns the previous BLOB;
// an older serial or an expired BLOB never replaces it either.
func TestRefreshKeepsLastGood(t *testing.T) {
	fx := newFixture(t)
	fx.serve(t, 5, entry(aaguidKey, []string{"external"}, []string{"secure_element"}, b64(fx.root.cert), "FIDO_CERTIFIED"))
	if _, err := fx.f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.srv.code.Store(500)
	st, err := fx.f.Refresh(context.Background())
	if err == nil || st.Serial != 5 || st.Err == "" {
		t.Fatalf("Refresh on 500 = %+v, %v", st, err)
	}
	m, st, err := fx.f.Load()
	if err != nil || m.Parsed.Number != 5 || st.Serial != 5 {
		t.Fatalf("Load = %v %+v %v", m, st, err)
	}
	if tr, _ := Trust(m, fx.now); len(tr) != 1 {
		t.Errorf("trust after 500 = %v", tr)
	}
	// Also from a fresh Fetcher (the file, not the memory).
	f2 := fx.fresh()
	if m, _, err := f2.Load(); err != nil || m.Parsed.Number != 5 {
		t.Fatalf("Load from file = %v, %v", m, err)
	}

	fx.srv.code.Store(0)
	fx.serve(t, 4) // a replayed older BLOB
	if _, err := fx.f.Refresh(context.Background()); err == nil {
		t.Error("older serial accepted")
	}
	exp := signBlob(t, fx.leaf, []*x509.Certificate{fx.leaf.cert, fx.root.cert}, payload(6, fx.now.AddDate(0, 0, -31)))
	fx.srv.blob.Store(&exp)
	if _, err := fx.f.Refresh(context.Background()); err == nil {
		t.Error("expired BLOB accepted")
	}
	if m, _, _ := fx.f.Load(); m.Parsed.Number != 5 {
		t.Errorf("cache serial = %d, want 5", m.Parsed.Number)
	}
}

func parsed(t *testing.T, next time.Time, entries ...map[string]any) *metadata.Metadata {
	t.Helper()
	b, _ := json.Marshal(payload(1, next, entries...))
	var p metadata.PayloadJSON
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	d, err := metadata.NewDecoder()
	if err != nil {
		t.Fatal(err)
	}
	m, err := d.Parse(&p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestTrustKinds: external+secure_element → security_key;
// internal+tee → passkey_device; external+software → absent; REVOKED /
// USER_KEY_PHYSICAL_COMPROMISE → present with Status "revoked" and its
// kind and roots; not certified → absent.
func TestTrustKinds(t *testing.T) {
	root := newCert(t, "attestation root", nil, true)
	r := b64(root.cert)
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	m := parsed(t, now.AddDate(0, 0, 10),
		entry(aaguidKey, []string{"external", "wired"}, []string{"hardware", "secure_element"}, r, "FIDO_CERTIFIED", "FIDO_CERTIFIED_L2"),
		entry(aaguidDevice, []string{"internal"}, []string{"hardware", "tee"}, r, "FIDO_CERTIFIED_L1"),
		entry(aaguidSoft, []string{"external"}, []string{"software"}, r, "FIDO_CERTIFIED"),
		entry(aaguidRevKey, []string{"external"}, []string{"secure_element"}, r, "FIDO_CERTIFIED", "REVOKED"),
		entry(aaguidComp, []string{"internal"}, []string{"tee"}, r, "FIDO_CERTIFIED_L1", "USER_KEY_PHYSICAL_COMPROMISE", "FIDO_CERTIFIED_L1"),
		entry(aaguidNotCrt, []string{"external"}, []string{"secure_element"}, r, "NOT_FIDO_CERTIFIED"),
	)
	got, stale := Trust(m, now)
	if stale {
		t.Fatal("stale")
	}
	roots := [][]byte{root.cert.Raw}
	want := map[string]AuthenticatorTrust{
		aaguidKey:    {Kind: KindSecurityKey, Status: StatusCertified, Roots: roots},
		aaguidDevice: {Kind: KindPasskeyDevice, Status: StatusCertified, Roots: roots},
		aaguidRevKey: {Kind: KindSecurityKey, Status: StatusRevoked, Roots: roots},
		aaguidComp:   {Kind: KindPasskeyDevice, Status: StatusRevoked, Roots: roots},
	}
	if len(got) != len(want) {
		t.Errorf("trust has %d entries, want %d: %+v", len(got), len(want), got)
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok || g.Kind != w.Kind || g.Status != w.Status || len(g.Roots) != 1 || !bytes.Equal(g.Roots[0], w.Roots[0]) {
			t.Errorf("%s = %+v (%t), want %+v", k, g, ok, w)
		}
	}
	// The JSON shape: roots in standard base64.
	b, _ := json.Marshal(got[aaguidKey])
	if want := `{"kind":"security_key","status":"certified","roots":["` + r + `"]}`; string(b) != want {
		t.Errorf("json = %s\nwant %s", b, want)
	}
}

// TestTrustStaleIsEmpty: now = NextUpdate + 31 days → Trust returns an
// empty map and stale == true; Load's Status.Stale == true.
func TestTrustStaleIsEmpty(t *testing.T) {
	fx := newFixture(t)
	fx.serve(t, 3, entry(aaguidKey, []string{"external"}, []string{"secure_element"}, b64(fx.root.cert), "FIDO_CERTIFIED"))
	if _, err := fx.f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, st, err := fx.f.Load()
	if err != nil || st.Stale {
		t.Fatalf("Load = %+v, %v", st, err)
	}
	if tr, stale := Trust(m, fx.now); stale || len(tr) != 1 {
		t.Fatalf("fresh trust = %v, %t", tr, stale)
	}
	next := m.Parsed.NextUpdate
	if tr, stale := Trust(m, next.Add(30*24*time.Hour)); stale || len(tr) != 1 {
		t.Errorf("30 days past = %v, %t: the grace is 30 days", tr, stale)
	}
	fx.now = next.Add(31 * 24 * time.Hour)
	tr, stale := Trust(m, fx.now)
	if !stale || tr == nil || len(tr) != 0 {
		t.Errorf("stale trust = %v, %t", tr, stale)
	}
	if _, st, err := fx.f.Load(); err != nil || !st.Stale {
		t.Errorf("Load status = %+v, %v; want Stale", st, err)
	}
	// Refresh failing while stale reports Stale too.
	fx.srv.code.Store(503)
	if st, err := fx.f.Refresh(context.Background()); err == nil || !st.Stale {
		t.Errorf("Refresh status = %+v, %v; want Stale", st, err)
	}
	if Trust(nil, fx.now); true {
		if tr, stale := Trust(nil, fx.now); len(tr) != 0 || stale {
			t.Errorf("Trust(nil) = %v, %t", tr, stale)
		}
	}
}

func TestLoadWithoutCache(t *testing.T) {
	fx := newFixture(t)
	if m, st, err := fx.f.Load(); err == nil || m != nil || st == nil || st.Serial != 0 {
		t.Errorf("Load without cache = %v %+v %v", m, st, err)
	}
	// A tampered cache is refused (never trusted unverified).
	os.MkdirAll(filepath.Dir(fx.f.CacheFile), 0700)
	os.WriteFile(fx.f.CacheFile, []byte("a.b.c"), 0600)
	if m, _, err := fx.f.Load(); err == nil || m != nil {
		t.Errorf("Load of a bad cache = %v, %v", m, err)
	}
}
