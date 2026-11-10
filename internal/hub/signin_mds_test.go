package hub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/fidomds"
	"github.com/portcullis/hub/internal/fidomds/fidomdstest"
)

func testRootDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// mdsWith is a parsed BLOB number no with one certified security key.
func mdsWith(t *testing.T, no int, next time.Time, aaguid string, root []byte) *metadata.Metadata {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"legalHeader": "test", "no": no, "nextUpdate": next.Format(time.DateOnly),
		"entries": []any{map[string]any{
			"aaguid": aaguid,
			"metadataStatement": map[string]any{
				"aaguid": aaguid, "description": "key", "protocolFamily": "fido2", "schema": 3,
				"attachmentHint": []string{"external"}, "keyProtection": []string{"secure_element"},
				"attestationRootCertificates": []string{base64.StdEncoding.EncodeToString(root)},
			},
			"statusReports":          []any{map[string]any{"status": "FIDO_CERTIFIED_L1"}},
			"timeOfLastStatusChange": "2025-01-01",
		}},
	})
	var p metadata.PayloadJSON
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	d, _ := metadata.NewDecoder()
	m, err := d.Parse(&p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const (
	mdsKeyAAGUID   = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
	extraNewAAGUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

func writeExtra(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// TestExtraAuthenticatorsMerge: the file's entry overrides MDS; a new
// mtime bumps mds.serial; a bad file adds nothing.
func TestExtraAuthenticatorsMerge(t *testing.T) {
	f := newFixture(t)
	mdsRoot, extraRoot := testRootDER(t, "mds"), testRootDER(t, "extra")
	next := time.Now().AddDate(0, 0, 10).UTC().Truncate(24 * time.Hour)
	f.h.setMDS(mdsWith(t, 87, next, mdsKeyAAGUID, mdsRoot), &fidomds.Status{Serial: 87, NextUpdate: next})

	// MDS only.
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	doc := readKeycloakSignIn(t, f)
	want := map[string]fidomds.AuthenticatorTrust{mdsKeyAAGUID: {Kind: fidomds.KindSecurityKey, Status: fidomds.StatusCertified, Roots: [][]byte{mdsRoot}}}
	if !reflect.DeepEqual(doc.Authenticators, want) || doc.MDS.Serial != 87 || !doc.MDS.NextUpdate.Equal(next) {
		t.Fatalf("MDS only: %+v %+v", doc.Authenticators, doc.MDS)
	}

	path := filepath.Join(t.TempDir(), "extra.json")
	f.h.cfg.ExtraAuthenticators = path
	f.h.cfg.Dev = true
	r64 := base64.StdEncoding.EncodeToString(extraRoot)
	body := `{"` + mdsKeyAAGUID + `": {"kind": "passkey_device", "status": "revoked", "roots": ["` + r64 + `"]},
	          "` + extraNewAAGUID + `": {"kind": "security_key", "status": "certified", "roots": ["` + r64 + `"]}}`
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeExtra(t, path, body, t0)
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	doc = readKeycloakSignIn(t, f)
	want = map[string]fidomds.AuthenticatorTrust{
		mdsKeyAAGUID:   {Kind: fidomds.KindPasskeyDevice, Status: fidomds.StatusRevoked, Roots: [][]byte{extraRoot}},
		extraNewAAGUID: {Kind: fidomds.KindSecurityKey, Status: fidomds.StatusCertified, Roots: [][]byte{extraRoot}},
	}
	if !reflect.DeepEqual(doc.Authenticators, want) {
		t.Errorf("merged = %+v", doc.Authenticators)
	}
	if doc.MDS.Serial != 88 {
		t.Errorf("serial = %d, want 87 + 1", doc.MDS.Serial)
	}
	// Same mtime: same serial.
	f.h.WritePolicy()
	if doc = readKeycloakSignIn(t, f); doc.MDS.Serial != 88 {
		t.Errorf("unchanged file: serial = %d, want 88", doc.MDS.Serial)
	}
	// Touched: the serial grows.
	writeExtra(t, path, body, t0.Add(time.Minute))
	f.h.WritePolicy()
	if doc = readKeycloakSignIn(t, f); doc.MDS.Serial != 89 {
		t.Errorf("touched file: serial = %d, want 89", doc.MDS.Serial)
	}
	// A file that doesn't decode strictly adds nothing (MDS only); the
	// serial never goes back.
	for name, bad := range map[string]string{
		"unknown field":  `{"` + extraNewAAGUID + `": {"kind": "security_key", "status": "certified", "roots": ["` + r64 + `"], "x": 1}}`,
		"missing roots":  `{"` + extraNewAAGUID + `": {"kind": "security_key", "status": "certified"}}`,
		"bad kind":       `{"` + extraNewAAGUID + `": {"kind": "passkey_synced", "status": "certified", "roots": ["` + r64 + `"]}}`,
		"bad status":     `{"` + extraNewAAGUID + `": {"kind": "security_key", "status": "ok", "roots": ["` + r64 + `"]}}`,
		"bad aaguid":     `{"CB69481E-8FF7-4039-93EC-0A2729A154A8": {"kind": "security_key", "status": "certified", "roots": ["` + r64 + `"]}}`,
		"not a cert":     `{"` + extraNewAAGUID + `": {"kind": "security_key", "status": "certified", "roots": ["AAAA"]}}`,
		"trailing data":  `{} {}`,
		"not an object":  `[]`,
		"empty roots":    `{"` + extraNewAAGUID + `": {"kind": "security_key", "status": "certified", "roots": []}}`,
		"null entry":     `{"` + extraNewAAGUID + `": null}`,
		"duplicate keys": `{"` + extraNewAAGUID + `": {"kind": "security_key", "status": "certified", "roots": ["` + r64 + `"]}, "` + extraNewAAGUID + `": {"kind": "passkey_device", "status": "certified", "roots": ["` + r64 + `"]}}`,
	} {
		if _, _, err := readExtraAuthenticators(writeTemp(t, bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	writeExtra(t, path, `{"x": 1}`, t0.Add(2*time.Minute))
	f.h.WritePolicy()
	doc = readKeycloakSignIn(t, f)
	if len(doc.Authenticators) != 1 || doc.Authenticators[mdsKeyAAGUID].Kind != fidomds.KindSecurityKey || doc.MDS.Serial < 89 {
		t.Errorf("bad file: %+v %+v", doc.Authenticators, doc.MDS)
	}

	// The view shows the FIDO list's status.
	v, err := f.h.SignInView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.MDS.Serial != 87 || v.MDS.Stale || v.MDSWarning != "" {
		t.Errorf("view = %+v %q", v.MDS, v.MDSWarning)
	}
}

func writeTemp(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A stale FIDO list publishes no authenticators (extras still apply) and
// the view warns.
func TestMDSStalePublishesNone(t *testing.T) {
	f := newFixture(t)
	next := time.Now().AddDate(0, 0, -31).UTC().Truncate(24 * time.Hour)
	f.h.setMDS(mdsWith(t, 9, next, mdsKeyAAGUID, testRootDER(t, "mds")), &fidomds.Status{Serial: 9, NextUpdate: next})
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	doc := readKeycloakSignIn(t, f)
	if len(doc.Authenticators) != 0 || doc.Authenticators == nil || doc.MDS.Serial != 9 {
		t.Errorf("stale: %+v %+v", doc.Authenticators, doc.MDS)
	}
	v, _ := f.h.SignInView(context.Background())
	if !v.MDS.Stale || !strings.Contains(v.MDSWarning, "out of date") {
		t.Errorf("view = %+v %q", v.MDS, v.MDSWarning)
	}
	b, _ := os.ReadFile(filepath.Join(f.data, SignInKeycloakFile))
	if !strings.Contains(string(b), `"authenticators": {}`) {
		t.Errorf("authenticators not {}:\n%s", b)
	}
}

func TestMDSNextWait(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		st   fidomds.Status
		want time.Duration
	}{
		"never fetched":          {fidomds.Status{}, 0},
		"fetched an hour ago":    {fidomds.Status{FetchedAt: now.Add(-time.Hour), NextUpdate: now.Add(10 * day)}, 23 * time.Hour},
		"next update sooner":     {fidomds.Status{FetchedAt: now.Add(-time.Hour), NextUpdate: now.Add(2 * time.Hour)}, 2 * time.Hour},
		"a day old":              {fidomds.Status{FetchedAt: now.Add(-25 * time.Hour), NextUpdate: now.Add(10 * day)}, 0},
		"next update passed":     {fidomds.Status{FetchedAt: now.Add(-3 * time.Hour), NextUpdate: now.Add(-2 * time.Hour)}, 0},
		"late, fetched just now": {fidomds.Status{FetchedAt: now.Add(-time.Minute), NextUpdate: now.Add(-day)}, mdsRetry - time.Minute},
	} {
		if got := mdsNextWait(c.st, day, now); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// Without Config.Dev the extra file is never read (defence in depth:
// main refuses it without HUB_DEV=1 anyway).
func TestExtraAuthenticatorsIgnoredWithoutDev(t *testing.T) {
	f := newFixture(t)
	next := time.Now().AddDate(0, 0, 10).UTC().Truncate(24 * time.Hour)
	f.h.setMDS(mdsWith(t, 5, next, mdsKeyAAGUID, testRootDER(t, "mds")), &fidomds.Status{Serial: 5, NextUpdate: next})
	r64 := base64.StdEncoding.EncodeToString(testRootDER(t, "extra"))
	f.h.cfg.ExtraAuthenticators = writeTemp(t, `{"`+extraNewAAGUID+`": {"kind": "security_key", "status": "certified", "roots": ["`+r64+`"]}}`)
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	doc := readKeycloakSignIn(t, f)
	if _, ok := doc.Authenticators[extraNewAAGUID]; ok || len(doc.Authenticators) != 1 || doc.MDS.Serial != 5 {
		t.Errorf("without Dev: %+v %+v", doc.Authenticators, doc.MDS)
	}
}

// The development serial never goes back across a restart (the
// generation counter starts again from 0), and a new BLOB raises it.
func TestDevSerialMonotonicAcrossRestart(t *testing.T) {
	f := newFixture(t)
	next := time.Now().AddDate(0, 0, 10).UTC().Truncate(24 * time.Hour)
	root := testRootDER(t, "mds")
	f.h.setMDS(mdsWith(t, 87, next, mdsKeyAAGUID, root), &fidomds.Status{Serial: 87, NextUpdate: next})
	f.h.cfg.Dev = true
	r64 := base64.StdEncoding.EncodeToString(testRootDER(t, "extra"))
	path := filepath.Join(t.TempDir(), "extra.json")
	body := `{"` + extraNewAAGUID + `": {"kind": "security_key", "status": "certified", "roots": ["` + r64 + `"]}}`
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeExtra(t, path, body, t0)
	f.h.cfg.ExtraAuthenticators = path
	serial := func() int {
		t.Helper()
		if err := f.h.WritePolicy(); err != nil {
			t.Fatal(err)
		}
		return readKeycloakSignIn(t, f).MDS.Serial
	}
	serial() // generation 1
	writeExtra(t, path, body, t0.Add(time.Minute))
	before := serial() // 87 + 2
	if before != 89 {
		t.Fatalf("serial = %d, want 89", before)
	}
	// A restart: the in-memory generation is gone.
	f.h.mds.mu.Lock()
	f.h.mds.extraGen, f.h.mds.extraMtime, f.h.mds.pubLoaded, f.h.mds.pubSerial = 0, 0, false, 0
	f.h.mds.mu.Unlock()
	after := serial()
	if after <= before {
		t.Errorf("after a restart serial = %d, want > %d", after, before)
	}
	if again := serial(); again != after {
		t.Errorf("unchanged: %d, want %d", again, after)
	}
	// A new BLOB raises it even though no + gen is below it.
	f.h.setMDS(mdsWith(t, 88, next, mdsKeyAAGUID, root), &fidomds.Status{Serial: 88, NextUpdate: next})
	if s := serial(); s <= after {
		t.Errorf("new BLOB: serial = %d, want > %d", s, after)
	}
}

// RunMDS with a failing fetch and a clock past nextUpdate + 30 days
// republishes signin-keycloak.json with "authenticators": {}.
func TestRunMDSPublishesStaleEmpty(t *testing.T) {
	f := newFixture(t)
	root := fidomdstest.NewCert(t, "MDS test root", nil, true)
	leaf := fidomdstest.NewCert(t, "MDS test signer", root, false)
	srv := &fidomdstest.Server{}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	start := time.Now().UTC()
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	next := start.AddDate(0, 0, 20)
	entry := fidomdstest.Entry(mdsKeyAAGUID, []string{"external"}, []string{"secure_element"}, fidomdstest.B64(root.Cert), fidomdstest.Reports("FIDO_CERTIFIED"))
	srv.Serve(fidomdstest.SignBlob(t, leaf, []*x509.Certificate{leaf.Cert, root.Cert}, fidomdstest.Payload(42, next, entry)))
	f.h.mds.fetcher = &fidomds.Fetcher{URL: ts.URL, CacheFile: filepath.Join(f.data, filepath.FromSlash(MDSCacheFile)), Roots: pool, HTTP: ts.Client(), Now: now}
	f.h.mds.now = now
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.h.RunMDS(ctx, 20*time.Millisecond); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	published := func() (KeycloakSignIn, string) {
		b, err := os.ReadFile(filepath.Join(f.data, SignInKeycloakFile))
		if err != nil {
			return KeycloakSignIn{}, ""
		}
		var doc KeycloakSignIn
		json.Unmarshal(b, &doc)
		return doc, string(b)
	}
	waitUntil(t, "the FIDO list published", func() bool {
		doc, _ := published()
		return doc.MDS.Serial == 42 && len(doc.Authenticators) == 1
	})
	srv.Fail(500)
	clock.Store(next.Add(31 * 24 * time.Hour).UnixNano())
	waitUntil(t, "the stale list published empty", func() bool {
		doc, raw := published()
		return doc.MDS.Serial == 42 && strings.Contains(raw, `"authenticators": {}`)
	})
	v, _ := f.h.SignInView(context.Background())
	if !v.MDS.Stale || v.MDSWarning == "" || v.MDS.Err == "" {
		t.Errorf("view = %+v %q", v.MDS, v.MDSWarning)
	}
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCapStale(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	st := fidomds.Status{NextUpdate: now.Add(-fidomds.StaleAfter + time.Hour)}
	if got := capStale(24*time.Hour, st, now); got != time.Hour+time.Second {
		t.Errorf("capStale = %v, want 1h1s", got)
	}
	if got := capStale(time.Minute, st, now); got != time.Minute {
		t.Errorf("shorter wait kept: %v", got)
	}
	if got := capStale(time.Minute, fidomds.Status{NextUpdate: now.Add(-40 * 24 * time.Hour)}, now); got != time.Minute {
		t.Errorf("already stale: %v", got)
	}
}

// mdsRig is a fake MDS server and a Fetcher on f's data directory.
type mdsRig struct {
	root, leaf *fidomdstest.CA
	srv        *fidomdstest.Server
}

func startMDS(t *testing.T, f *fixture) *mdsRig {
	t.Helper()
	r := &mdsRig{root: fidomdstest.NewCert(t, "MDS test root", nil, true), srv: &fidomdstest.Server{}}
	r.leaf = fidomdstest.NewCert(t, "MDS test signer", r.root, false)
	ts := httptest.NewServer(r.srv)
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(r.root.Cert)
	f.h.mds.fetcher = &fidomds.Fetcher{URL: ts.URL, CacheFile: filepath.Join(f.data, filepath.FromSlash(MDSCacheFile)), Roots: pool, HTTP: ts.Client()}
	return r
}

func (r *mdsRig) blob(t *testing.T, no int) []byte {
	entry := fidomdstest.Entry(mdsKeyAAGUID, []string{"external"}, []string{"secure_element"}, fidomdstest.B64(r.root.Cert), fidomdstest.Reports("FIDO_CERTIFIED"))
	return fidomdstest.SignBlob(t, r.leaf, []*x509.Certificate{r.leaf.Cert, r.root.Cert}, fidomdstest.Payload(no, time.Now().AddDate(0, 0, 20), entry))
}

func runMDS(t *testing.T, f *fixture) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.h.RunMDS(ctx, 20*time.Millisecond); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func fidoFinding(t *testing.T, f *fixture) *doctor.Finding {
	t.Helper()
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range r.Findings {
		if x.Kind == doctor.KindSignInFIDOUnavailable {
			return &x
		}
	}
	return nil
}

func signInWarning(t *testing.T, f *fixture) string {
	t.Helper()
	v, err := f.h.SignInView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v.MDSWarning
}

// Every fetch failing since the first start: Settings warns and the
// doctor reports signin_fido_list_unavailable; a good fetch clears both.
func TestMDSUnavailableWarnsAndDoctor(t *testing.T) {
	f, _, _ := doctorFixture(t)
	if fidoFinding(t, f) != nil {
		t.Fatal("finding before any failure")
	}
	r := startMDS(t, f)
	r.srv.Fail(500)
	runMDS(t, f)
	waitUntil(t, "the unavailable warning", func() bool { return strings.Contains(signInWarning(t, f), "isn't available") })
	if w := signInWarning(t, f); !strings.Contains(w, "status 500") || strings.Contains(w, "mds.serial") {
		t.Errorf("warning = %q", w)
	}
	x := fidoFinding(t, f)
	if x == nil || x.Severity != doctor.Warning || !strings.Contains(x.Why, "status 500") {
		t.Fatalf("finding = %+v", x)
	}
	r.srv.Serve(r.blob(t, 3))
	r.srv.Fail(0)
	waitUntil(t, "the warning cleared", func() bool { return signInWarning(t, f) == "" })
	if x := fidoFinding(t, f); x != nil {
		t.Errorf("finding after a good fetch: %+v", x)
	}
}

// An unreadable high-water serial: the warning and the finding name
// <data>/signin/mds.serial.
func TestMDSHighWaterUnreadableNamed(t *testing.T) {
	f, _, _ := doctorFixture(t)
	r := startMDS(t, f)
	hw := f.h.mds.fetcher.HighWaterFile()
	if want := filepath.Join(f.data, "signin", "mds.serial"); hw != want {
		t.Fatalf("high-water file = %s, want %s", hw, want)
	}
	os.MkdirAll(filepath.Dir(hw), 0700)
	os.WriteFile(hw, []byte("junk"), 0600)
	r.srv.Serve(r.blob(t, 3))
	runMDS(t, f)
	waitUntil(t, "the high-water warning", func() bool { return strings.Contains(signInWarning(t, f), hw) })
	x := fidoFinding(t, f)
	if x == nil || !strings.Contains(strings.Join(x.Steps, " "), hw) {
		t.Fatalf("finding = %+v", x)
	}
	doc := readKeycloakSignIn(t, f)
	if len(doc.Authenticators) != 0 {
		t.Errorf("published %v with an unreadable high-water serial", doc.Authenticators)
	}
}

// Production (no HUB_DEV): a BLOB below the serial signin-keycloak.json
// last published is refused even with no high-water file.
func TestMDSPublishedSerialFloor(t *testing.T) {
	f := newFixture(t)
	next := time.Now().AddDate(0, 0, 10).UTC().Truncate(24 * time.Hour)
	f.h.setMDS(mdsWith(t, 50, next, mdsKeyAAGUID, testRootDER(t, "mds")), &fidomds.Status{Serial: 50, NextUpdate: next})
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	// A new process: nothing in memory, no cache, no high-water file.
	f.h.mds.mu.Lock()
	f.h.mds.meta, f.h.mds.status = nil, fidomds.Status{}
	f.h.mds.mu.Unlock()
	r := startMDS(t, f)
	r.srv.Serve(r.blob(t, 49))
	runMDS(t, f)
	waitUntil(t, "the refusal", func() bool { return strings.Contains(f.h.mdsStatus().Err, "below the serial already seen (50)") })
	if s := lastPublishedSerial(f.h.signInKeycloakPath()); s != 50 {
		t.Errorf("published serial = %d, want 50 kept", s)
	}
	if _, err := os.Stat(f.h.mds.fetcher.CacheFile); !os.IsNotExist(err) {
		t.Errorf("BLOB 49 cached: %v", err)
	}
}
