package invite

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {
	secret := strings.Repeat("k", 40)
	reply := `{"url":"https://enroll.example.org/invite/abc","expires_at":"2026-11-03T10:00:00Z"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		if strings.Contains(reply, "error") {
			w.WriteHeader(409)
		} else {
			w.WriteHeader(201)
		}
		w.Write([]byte(reply))
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(file, []byte(secret+"\n"), 0600)
	c := New(srv.URL, file)
	inv, err := c.Create(context.Background(), "alice")
	if err != nil || inv.URL != "https://enroll.example.org/invite/abc" || inv.ExpiresAt.IsZero() {
		t.Fatalf("Create = %+v, %v", inv, err)
	}
	for _, bad := range []string{
		`{"url":"javascript:alert(1)","expires_at":"2026-11-03T10:00:00Z"}`,
		`{"url":"http://enroll.example.org/x","expires_at":"2026-11-03T10:00:00Z"}`,
		`{"url":"https://enroll.example.org/x"}`,
		`{"error":"user is protected"}`,
	} {
		reply = bad
		if _, err := c.Create(context.Background(), "alice"); err == nil {
			t.Errorf("accepted %s", bad)
		} else if strings.Contains(err.Error(), secret) {
			t.Error("secret in error")
		}
	}
	if !strings.Contains(func() string { _, err := c.Create(context.Background(), "a"); return err.Error() }(), "user is protected") {
		t.Error("core's error message not surfaced")
	}
	os.WriteFile(file, []byte("short"), 0600)
	if err := c.Available(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("short secret: %v", err)
	}
	if err := New(srv.URL, filepath.Join(t.TempDir(), "x")).Available(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing secret: %v", err)
	}
}

func TestCertificates(t *testing.T) {
	secret := strings.Repeat("k", 40)
	status, reply := 200, `{"certificates":[{"user":"Alice","serial":"0a","kind":"yubikey","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","revoked":false},{"user":"bob","serial":"0b","kind":"browser","not_after":"2025-01-01T00:00:00Z","revoked":true},{"user":"","serial":"0c","kind":"yubikey","not_after":"2027-01-01T00:00:00Z"}]}`
	path := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(status)
		w.Write([]byte(reply))
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(file, []byte(secret), 0600)
	c := New(srv.URL+"/internal/invites", file)
	ctx := context.Background()
	certs, err := c.Certificates(ctx)
	if err != nil || path != "/internal/certificates" {
		t.Fatalf("Certificates = %+v, %v (path %s)", certs, err, path)
	}
	if len(certs) != 2 || certs[0].User != "alice" || certs[0].Serial != "0a" || certs[0].NotAfter.Year() != 2027 || !certs[1].Revoked {
		t.Errorf("certs = %+v", certs)
	}
	status = 404
	if _, err := c.Certificates(ctx); !errors.Is(err, ErrNoCertAPI) {
		t.Errorf("404 = %v", err)
	}
	for _, bad := range []struct {
		status int
		body   string
	}{{500, `{}`}, {200, `{}`}, {200, `not json`}, {401, ``}} {
		status, reply = bad.status, bad.body
		if _, err := c.Certificates(ctx); err == nil || errors.Is(err, ErrNoCertAPI) || strings.Contains(err.Error(), secret) {
			t.Errorf("%d %q = %v", bad.status, bad.body, err)
		}
	}
	if _, err := New(srv.URL, filepath.Join(t.TempDir(), "x")).Certificates(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no secret = %v", err)
	}
}

// TestCertificatesKinds (sign-in part 2): yubikey and browser records are
// kept with their kind and not_before; any other kind, or none, is
// dropped (it never counts).
func TestCertificatesKinds(t *testing.T) {
	secret := strings.Repeat("k", 40)
	reply := `{"certificates":[` +
		`{"user":"ann","serial":"01","kind":"yubikey","not_before":"2026-11-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","revoked":false},` +
		`{"user":"ann","serial":"02","kind":"browser","not_before":"2026-11-02T00:00:00Z","not_after":"2026-12-01T00:00:00Z","revoked":true},` +
		`{"user":"bob","serial":"03","kind":"other","not_after":"2027-01-01T00:00:00Z"},` +
		`{"user":"bob","serial":"04","not_after":"2027-01-01T00:00:00Z"},` +
		`{"user":"bob","serial":"05","kind":"Browser","not_after":"2027-01-01T00:00:00Z"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(reply))
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(file, []byte(secret), 0600)
	certs, err := New(srv.URL+"/internal/invites", file).Certificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("certs = %+v", certs)
	}
	a, b := certs[0], certs[1]
	if a.Kind != KindYubiKey || a.Serial != "01" || !a.NotBefore.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) || a.Revoked {
		t.Errorf("yubikey = %+v", a)
	}
	if b.Kind != KindBrowser || b.Serial != "02" || b.NotBefore.Day() != 2 || !b.Revoked {
		t.Errorf("browser = %+v", b)
	}
}
