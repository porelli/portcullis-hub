package fidomds

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/portcullis/hub/internal/fidomds/fidomdstest"
)

const (
	aaguidKey     = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
	aaguidDevice  = "08987058-cadc-4b81-b6e1-30de50dcbe96"
	aaguidSoft    = "11111111-2222-4333-8444-555555555555"
	aaguidRevKey  = "22222222-3333-4444-8555-666666666666"
	aaguidComp    = "33333333-4444-4555-8666-777777777777"
	aaguidNotCrt  = "44444444-5555-4666-8777-888888888888"
	aaguidUpd     = "55555555-6666-4777-8888-999999999999"
	aaguidLateNC  = "66666666-7777-4888-8999-aaaaaaaaaaaa"
	aaguidHWOnly  = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
	aaguidNoRoot  = "88888888-9999-4aaa-8bbb-cccccccccccc"
	aaguidOOO     = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
	aaguidBoth    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	aaguidSWSE    = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	aaguidFuture  = "cccccccc-dddd-4eee-8fff-000000000000"
	aaguidRetired = "eeeeeeee-ffff-4000-8111-222222222222"
	aaguidRetOld  = "ffffffff-0000-4111-8222-333333333333"
	aaguidSunRev  = "01010101-0202-4303-8404-050505050505"
	aaguidSunCert = "02020202-0303-4404-8505-060606060606"
	aaguidRevNoRt = "03030303-0404-4505-8606-070707070707"
	aaguidNoDate  = "dddddddd-eeee-4fff-8000-111111111111"
)

var (
	ext = []string{"external"}
	se  = []string{"secure_element"}
)

func rep(s ...string) []fidomdstest.Report { return fidomdstest.Reports(s...) }

type fixture struct {
	root, leaf *fidomdstest.CA
	srv        *fidomdstest.Server
	f          *Fetcher
	now        time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := fidomdstest.NewCert(t, "MDS test root", nil, true)
	leaf := fidomdstest.NewCert(t, "MDS test signer", root, false)
	srv := &fidomdstest.Server{}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
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

func (fx *fixture) blob(t *testing.T, no int, entries ...map[string]any) []byte {
	return fidomdstest.SignBlob(t, fx.leaf, []*x509.Certificate{fx.leaf.Cert, fx.root.Cert}, fidomdstest.Payload(no, fx.now.AddDate(0, 0, 20), entries...))
}

func (fx *fixture) serve(t *testing.T, no int, entries ...map[string]any) []byte {
	b := fx.blob(t, no, entries...)
	fx.srv.Serve(b)
	return b
}

func (fx *fixture) keyEntry() map[string]any {
	return fidomdstest.Entry(aaguidKey, ext, se, fidomdstest.B64(fx.root.Cert), rep("FIDO_CERTIFIED"))
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
	hw := filepath.Join(filepath.Dir(fx.f.CacheFile), "mds.serial")
	if b, err := os.ReadFile(hw); err != nil || string(b) != "87\n" {
		t.Errorf("high-water = %q, %v", b, err)
	}
	for path, want := range map[string]os.FileMode{fx.f.CacheFile: 0600, hw: 0600, filepath.Dir(fx.f.CacheFile): 0700} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, %v; want %v", path, fi.Mode().Perm(), err, want)
		}
	}
	// A new Fetcher reads (and verifies) the cache.
	m, st, err := fx.fresh().Load()
	if err != nil || m.Parsed.Number != 87 || st.Serial != 87 {
		t.Fatalf("Load = %v %+v %v", m, st, err)
	}
}

// TestRefreshVerifiesSignature: a BLOB signed by another key (or chained
// to another root, or tampered with) is refused and the cache is
// untouched.
func TestRefreshVerifiesSignature(t *testing.T) {
	fx := newFixture(t)
	good := fx.serve(t, 10)
	if _, err := fx.f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := fidomdstest.NewCert(t, "other root", nil, true)
	otherLeaf := fidomdstest.NewCert(t, "other signer", other, false)
	p := fidomdstest.Payload(11, fx.now.AddDate(0, 0, 20), fx.keyEntry())
	tampered := fidomdstest.SignBlob(t, fx.leaf, []*x509.Certificate{fx.leaf.Cert, fx.root.Cert}, p)
	tampered[bytes.IndexByte(tampered, '.')+5] ^= 0x01 // a payload byte
	for name, blob := range map[string][]byte{
		"wrong key":  fidomdstest.SignBlob(t, otherLeaf, []*x509.Certificate{fx.leaf.Cert, fx.root.Cert}, p),
		"wrong root": fidomdstest.SignBlob(t, otherLeaf, []*x509.Certificate{otherLeaf.Cert, other.Cert}, p),
		"leaf only":  fidomdstest.SignBlob(t, fx.leaf, []*x509.Certificate{fx.leaf.Cert}, p),
		"tampered":   tampered,
		"garbage":    []byte("not.a.jwt"),
	} {
		fx.srv.Serve(blob)
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

// Roots nil = the FIDO production root: a BLOB signed under the test
// root is refused.
func TestNilRootsIsProductionRoot(t *testing.T) {
	fx := newFixture(t)
	fx.serve(t, 1, fx.keyEntry())
	fx.f.Roots = nil
	if _, err := fx.f.Refresh(context.Background()); err == nil {
		t.Fatal("a test-root BLOB verified against the FIDO production root")
	}
	if _, err := os.Stat(fx.f.CacheFile); !os.IsNotExist(err) {
		t.Errorf("cache written: %v", err)
	}
}

// TestRefreshKeepsLastGood: server 500 → Load returns the previous BLOB;
// an older serial or an expired BLOB never replaces it either.
func TestRefreshKeepsLastGood(t *testing.T) {
	fx := newFixture(t)
	fx.serve(t, 5, fx.keyEntry())
	if _, err := fx.f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.srv.Fail(500)
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
	if m, _, err := fx.fresh().Load(); err != nil || m.Parsed.Number != 5 {
		t.Fatalf("Load from file = %v, %v", m, err)
	}

	fx.srv.Fail(0)
	fx.serve(t, 4) // a replayed older BLOB
	if _, err := fx.f.Refresh(context.Background()); err == nil {
		t.Error("older serial accepted")
	}
	exp := fidomdstest.SignBlob(t, fx.leaf, []*x509.Certificate{fx.leaf.Cert, fx.root.Cert}, fidomdstest.Payload(6, fx.now.AddDate(0, 0, -31)))
	fx.srv.Serve(exp)
	if _, err := fx.f.Refresh(context.Background()); err == nil {
		t.Error("expired BLOB accepted")
	}
	if m, _, _ := fx.f.Load(); m.Parsed.Number != 5 {
		t.Errorf("cache serial = %d, want 5", m.Parsed.Number)
	}
}

// The high-water serial survives the cache: with the cache deleted, a
// lower serial is still refused; an equal or higher one is taken; a
// cache below it is never loaded; an unreadable one refuses everything.
func TestHighWaterSerial(t *testing.T) {
	fx := newFixture(t)
	fx.serve(t, 20, fx.keyEntry())
	if _, err := fx.f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	low := fx.blob(t, 19, fx.keyEntry())
	os.Remove(fx.f.CacheFile)
	f2 := fx.fresh()
	fx.srv.Serve(low)
	if _, err := f2.Refresh(context.Background()); err == nil {
		t.Fatal("serial 19 accepted below the high-water 20 with no cache")
	}
	if _, err := os.Stat(fx.f.CacheFile); !os.IsNotExist(err) {
		t.Errorf("cache written: %v", err)
	}
	// A cache put back below the high-water is refused.
	os.WriteFile(fx.f.CacheFile, low, 0600)
	if m, _, err := fx.fresh().Load(); err == nil || m != nil {
		t.Errorf("Load of a cache below the high-water = %v, %v", m, err)
	}
	os.Remove(fx.f.CacheFile)
	fx.serve(t, 20, fx.keyEntry())
	if st, err := fx.fresh().Refresh(context.Background()); err != nil || st.Serial != 20 {
		t.Fatalf("equal serial = %+v, %v", st, err)
	}
	fx.serve(t, 25)
	if _, err := fx.fresh().Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	hw := filepath.Join(filepath.Dir(fx.f.CacheFile), "mds.serial")
	if b, _ := os.ReadFile(hw); string(b) != "25\n" {
		t.Errorf("high-water = %q", b)
	}
	os.WriteFile(hw, []byte("junk"), 0600)
	fx.serve(t, 30)
	if _, err := fx.fresh().Refresh(context.Background()); err == nil {
		t.Error("an unreadable high-water serial let a BLOB in")
	}
	if _, _, err := fx.fresh().Load(); err == nil {
		t.Error("an unreadable high-water serial let the cache load")
	}
}

func parsed(t *testing.T, next time.Time, entries ...map[string]any) *metadata.Metadata {
	t.Helper()
	b, _ := json.Marshal(fidomdstest.Payload(1, next, entries...))
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

// TestTrustKinds: kinds and statuses (contract §8.1, ruling R1).
func TestTrustKinds(t *testing.T) {
	root := fidomdstest.NewCert(t, "attestation root", nil, true)
	r := fidomdstest.B64(root.Cert)
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	E := fidomdstest.Entry
	m := parsed(t, now.AddDate(0, 0, 10),
		E(aaguidKey, []string{"external", "wired"}, []string{"hardware", "secure_element"}, r, rep("FIDO_CERTIFIED", "FIDO_CERTIFIED_L2")),
		E(aaguidDevice, []string{"internal"}, []string{"hardware", "tee"}, r, rep("FIDO_CERTIFIED_L1")),
		E(aaguidSoft, ext, []string{"software"}, r, rep("FIDO_CERTIFIED")),
		E(aaguidRevKey, ext, se, r, rep("FIDO_CERTIFIED", "REVOKED")),
		// A compromise anywhere, even before a later certification.
		E(aaguidComp, []string{"internal"}, []string{"tee"}, r, rep("FIDO_CERTIFIED_L1", "USER_KEY_PHYSICAL_COMPROMISE", "FIDO_CERTIFIED_L1")),
		E(aaguidNotCrt, ext, se, r, rep("NOT_FIDO_CERTIFIED")),
		// R1: UPDATE_AVAILABLE isn't a certification status.
		E(aaguidUpd, ext, se, r, rep("FIDO_CERTIFIED_L1", "UPDATE_AVAILABLE")),
		E(aaguidLateNC, ext, se, r, rep("FIDO_CERTIFIED_L1", "NOT_FIDO_CERTIFIED", "UPDATE_AVAILABLE")),
		E(aaguidHWOnly, ext, []string{"hardware"}, r, rep("FIDO_CERTIFIED")),
		E(aaguidNoRoot, ext, se, "", rep("FIDO_CERTIFIED")),
		// A revoked entry is kept without roots (a revocation needs none).
		E(aaguidRevNoRt, ext, se, "", rep("FIDO_CERTIFIED", "REVOKED")),
		E("", ext, se, r, rep("FIDO_CERTIFIED")),
		// Out of order: the later date wins, not the later position.
		E(aaguidOOO, ext, se, r, []fidomdstest.Report{fidomdstest.R("FIDO_CERTIFIED_L1", "2025-03-01"), fidomdstest.R("NOT_FIDO_CERTIFIED", "2025-01-01")}),
		E(aaguidBoth, []string{"external", "internal"}, se, r, rep("FIDO_CERTIFIED")),
		E(aaguidSWSE, ext, []string{"software", "secure_element"}, r, rep("FIDO_CERTIFIED")),
		// A report not in effect yet doesn't count.
		E(aaguidFuture, ext, se, r, []fidomdstest.Report{fidomdstest.R("FIDO_CERTIFIED", "2025-01-01"), fidomdstest.R("REVOKED", "2027-01-01")}),
		// RETIRED is sticky: a later certification doesn't bring it back.
		E(aaguidRetired, ext, se, r, rep("FIDO_CERTIFIED_L1", "RETIRED")),
		E(aaguidRetOld, ext, se, r, rep("RETIRED", "FIDO_CERTIFIED_L2")),
		// A report past its sunset date no longer counts.
		E(aaguidSunRev, ext, se, r, []fidomdstest.Report{fidomdstest.R("FIDO_CERTIFIED", "2025-01-01"), fidomdstest.RS("REVOKED", "2025-02-01", "2026-01-01")}),
		E(aaguidSunCert, ext, se, r, []fidomdstest.Report{fidomdstest.RS("FIDO_CERTIFIED", "2025-01-01", "2026-01-01")}),
		// No effective date: in effect.
		E(aaguidNoDate, ext, se, r, []fidomdstest.Report{fidomdstest.R("FIDO_CERTIFIED", "2025-01-01"), fidomdstest.R("NOT_FIDO_CERTIFIED", "")}),
	)
	got, stale := Trust(m, now)
	if stale {
		t.Fatal("stale")
	}
	roots := [][]byte{root.Cert.Raw}
	want := map[string]AuthenticatorTrust{
		aaguidKey:    {Kind: KindSecurityKey, Status: StatusCertified, Roots: roots},
		aaguidDevice: {Kind: KindPasskeyDevice, Status: StatusCertified, Roots: roots},
		aaguidRevKey: {Kind: KindSecurityKey, Status: StatusRevoked, Roots: roots},
		aaguidComp:   {Kind: KindPasskeyDevice, Status: StatusRevoked, Roots: roots},
		aaguidUpd:    {Kind: KindSecurityKey, Status: StatusCertified, Roots: roots},
		aaguidOOO:    {Kind: KindSecurityKey, Status: StatusCertified, Roots: roots},
		aaguidBoth:   {Kind: KindPasskeyDevice, Status: StatusCertified, Roots: roots},
		aaguidFuture: {Kind: KindSecurityKey, Status: StatusCertified, Roots: roots},
		aaguidSunRev: {Kind: KindSecurityKey, Status: StatusCertified, Roots: roots},
	}
	if len(got) != len(want)+1 {
		t.Errorf("trust has %d entries, want %d: %v", len(got), len(want)+1, keys(got))
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok || g.Kind != w.Kind || g.Status != w.Status || len(g.Roots) != 1 || !bytes.Equal(g.Roots[0], w.Roots[0]) {
			t.Errorf("%s = %+v (%t), want %+v", k, g, ok, w)
		}
	}
	if g, ok := got[aaguidRevNoRt]; !ok || g.Kind != KindSecurityKey || g.Status != StatusRevoked || g.Roots == nil || len(g.Roots) != 0 {
		t.Errorf("revoked without roots = %+v (%t), want kept with empty (non-nil) roots", g, ok)
	}
	if b, _ := json.Marshal(got[aaguidRevNoRt]); string(b) != `{"kind":"security_key","status":"revoked","roots":[]}` {
		t.Errorf("revoked without roots json = %s", b)
	}
	// The future REVOKED takes effect once its date has come.
	later := parsed(t, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC),
		E(aaguidFuture, ext, se, r, []fidomdstest.Report{fidomdstest.R("FIDO_CERTIFIED", "2025-01-01"), fidomdstest.R("REVOKED", "2027-01-01")}))
	if g := mustTrust(t, later, time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC))[aaguidFuture]; g.Status != StatusRevoked {
		t.Errorf("after its date: %+v", g)
	}
	// The JSON shape: roots in standard base64.
	b, _ := json.Marshal(got[aaguidKey])
	if want := `{"kind":"security_key","status":"certified","roots":["` + r + `"]}`; string(b) != want {
		t.Errorf("json = %s\nwant %s", b, want)
	}
}

func mustTrust(t *testing.T, m *metadata.Metadata, now time.Time) map[string]AuthenticatorTrust {
	t.Helper()
	tr, stale := Trust(m, now)
	if stale {
		t.Fatalf("stale at %s", now)
	}
	return tr
}

func keys(m map[string]AuthenticatorTrust) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestTrustStaleIsEmpty: now = NextUpdate + 31 days → Trust returns an
// empty map and stale == true; Load's Status.Stale == true.
func TestTrustStaleIsEmpty(t *testing.T) {
	fx := newFixture(t)
	fx.serve(t, 3, fx.keyEntry())
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
	fx.srv.Fail(503)
	if st, err := fx.f.Refresh(context.Background()); err == nil || !st.Stale {
		t.Errorf("Refresh status = %+v, %v; want Stale", st, err)
	}
	if tr, stale := Trust(nil, fx.now); tr == nil || len(tr) != 0 || stale {
		t.Errorf("Trust(nil) = %v, %t", tr, stale)
	}
}

func TestLoadWithoutCache(t *testing.T) {
	fx := newFixture(t)
	if m, st, err := fx.f.Load(); err == nil || m != nil || st == nil || st.Serial != 0 {
		t.Errorf("Load without cache = %v %+v %v", m, st, err)
	}
	// A tampered cache (one byte of a real signed BLOB flipped) is
	// refused: never trusted unverified.
	b := fx.blob(t, 7, fx.keyEntry())
	b[len(b)-3] ^= 0x01 // a signature byte
	os.MkdirAll(filepath.Dir(fx.f.CacheFile), 0700)
	os.WriteFile(fx.f.CacheFile, b, 0600)
	if m, _, err := fx.fresh().Load(); err == nil || m != nil {
		t.Errorf("Load of a tampered cache = %v, %v", m, err)
	}
}

// Fetcher.Floor (the Hub's last published serial, production): a BLOB
// below it is refused with no high-water file, and so is a cache.
func TestFloorRefusesLower(t *testing.T) {
	fx := newFixture(t)
	fx.f.Floor = 30
	fx.serve(t, 29, fx.keyEntry())
	if _, err := fx.f.Refresh(context.Background()); err == nil {
		t.Fatal("serial 29 accepted below the floor 30")
	}
	fx.serve(t, 30, fx.keyEntry())
	if st, err := fx.f.Refresh(context.Background()); err != nil || st.Serial != 30 {
		t.Fatalf("serial 30 = %+v, %v", st, err)
	}
	f2 := fx.fresh()
	f2.Floor = 31
	if _, _, err := f2.Load(); err == nil {
		t.Error("a cache below the floor loaded")
	}
}

func TestHighWaterErrorIs(t *testing.T) {
	fx := newFixture(t)
	os.MkdirAll(filepath.Dir(fx.f.CacheFile), 0700)
	os.WriteFile(fx.f.HighWaterFile(), []byte("x"), 0600)
	fx.serve(t, 1)
	if _, err := fx.f.Refresh(context.Background()); !errors.Is(err, ErrHighWater) {
		t.Errorf("Refresh = %v, want ErrHighWater", err)
	}
}

// TestModels: every entry with an AAGUID maps to its description (display
// only: whatever its status, kind or roots, and for a stale BLOB too),
// cleaned of control and bidi characters and clipped to 128 runes.
func TestModels(t *testing.T) {
	root := fidomdstest.NewCert(t, "attestation root", nil, true)
	r := fidomdstest.B64(root.Cert)
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	E := fidomdstest.Entry
	desc := func(e map[string]any, d string) map[string]any {
		e["metadataStatement"].(map[string]any)["description"] = d
		return e
	}
	long := strings.Repeat("é", 200)
	// Stale: nextUpdate long past (Trust would be empty; Models isn't).
	m := parsed(t, now.AddDate(-1, 0, 0),
		E(aaguidKey, []string{"external", "wired"}, []string{"hardware", "secure_element"}, r, rep("FIDO_CERTIFIED")),
		E(aaguidSoft, ext, []string{"software"}, r, rep("FIDO_CERTIFIED")),
		E(aaguidRevKey, ext, se, "", rep("FIDO_CERTIFIED", "REVOKED")),
		E(aaguidNotCrt, ext, se, r, rep("NOT_FIDO_CERTIFIED")),
		desc(E(aaguidDevice, []string{"internal"}, []string{"tee"}, r, rep("FIDO_CERTIFIED_L1")), "Line\none \u202eevil\u202c"),
		desc(E(aaguidUpd, ext, se, r, rep("FIDO_CERTIFIED")), long),
		E("", ext, se, r, rep("FIDO_CERTIFIED")),
	)
	got := Models(m)
	want := map[string]string{
		aaguidKey:    "test " + aaguidKey,
		aaguidSoft:   "test " + aaguidSoft,
		aaguidRevKey: "test " + aaguidRevKey,
		aaguidNotCrt: "test " + aaguidNotCrt,
		aaguidDevice: "Lineone evil",
		aaguidUpd:    strings.Repeat("é", 128),
	}
	if len(got) != len(want) {
		t.Errorf("Models = %v, want %d entries", got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Models[%s] = %q, want %q", k, got[k], v)
		}
	}
	if n := Models(nil); n == nil || len(n) != 0 {
		t.Errorf("Models(nil) = %v, want empty", n)
	}
}
