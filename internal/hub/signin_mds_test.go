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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/portcullis/hub/internal/fidomds"
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
