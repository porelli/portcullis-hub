package domains

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClient(t *testing.T) {
	secret := strings.Repeat("k", 40)
	tok := "tok-SECRET/value+0123456789"
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		got = r.Method + " " + r.URL.EscapedPath()
		switch r.Method {
		case "PUT":
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"bad token tok-SECRET%2Fvalue%2B0123456789 / ` + tok + `"}`))
		case "GET":
			w.Write([]byte(`[{"name":"a.example.org","provider":"cloudflare","records_ok":true,"cert_not_after":"2099-01-01T00:00:00Z","last_error":"","state":"ready"}]`))
		case "DELETE":
			w.Write([]byte(`{"warning":"left a record"}`))
		}
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "s")
	os.WriteFile(f, []byte(secret+"\n"), 0600)
	c := New(srv.URL, f)
	list, err := c.List(context.Background())
	if err != nil || len(list) != 1 || !list[0].Assignable(list[0].CertNotAfter.AddDate(-1, 0, 0)) {
		t.Fatalf("List = %+v, %v", list, err)
	}
	_, err = c.Enroll(context.Background(), "a.example.org", "cloudflare", map[string]string{"api_token": tok})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("Enroll error %v", err)
	}
	if got != "PUT /domains/a.example.org" {
		t.Fatalf("request %s", got)
	}
	if w, err := c.Delete(context.Background(), "a.example.org"); err != nil || w != "left a record" {
		t.Fatalf("Delete = %q, %v", w, err)
	}
	srv.Close()
	if _, err := c.List(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("closed server: %v", err)
	}
	os.WriteFile(f, []byte("short"), 0600)
	if err := c.Available(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("short secret: %v", err)
	}
	if err := New(srv.URL, filepath.Join(t.TempDir(), "x")).Available(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing secret: %v", err)
	}
}

// TestRedactBeforeClip: a credential straddling the 500-byte clip of the
// service's message is redacted before clipping.
func TestRedactBeforeClip(t *testing.T) {
	secret := strings.Repeat("k", 40)
	tok := "tokSECRETvalue0123456789"
	for _, pad := range []int{480, 490, 495, 499} {
		msg := strings.Repeat("é", pad/2) + tok + " end"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"` + msg + `"}`))
		}))
		f := filepath.Join(t.TempDir(), "s")
		os.WriteFile(f, []byte(secret), 0600)
		_, err := New(srv.URL, f).Enroll(context.Background(), "a.example.org", "cloudflare", map[string]string{"api_token": tok})
		srv.Close()
		if err == nil || strings.Contains(err.Error(), tok[:4]) {
			t.Errorf("pad %d: %v", pad, err)
		}
		if !utf8.ValidString(err.Error()) {
			t.Errorf("pad %d: clipped inside a rune", pad)
		}
	}
}
