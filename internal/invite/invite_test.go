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
	status, reply := 200, `{"certificates":[{"user":"Alice","serial":"0a","not_after":"2027-01-01T00:00:00Z","revoked":false},{"user":"bob","serial":"0b","not_after":"2025-01-01T00:00:00Z","revoked":true},{"user":"","serial":"0c","not_after":"2027-01-01T00:00:00Z"}]}`
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
