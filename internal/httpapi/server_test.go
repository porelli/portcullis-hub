package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/web"
)

type nopRunner struct{}

func (nopRunner) Up(context.Context, compose.Project) error           { return nil }
func (nopRunner) Down(context.Context, compose.Project) error         { return nil }
func (nopRunner) DownByName(ctx context.Context, name string) error   { return nil }
func (nopRunner) Create(ctx context.Context, p compose.Project) error { return nil }

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "src", "demo")
	os.MkdirAll(src, 0755)
	os.WriteFile(filepath.Join(src, "manifest.yaml"), []byte("name: Demo <b>\ncategory: test\nauth:\n  method: forward-auth\n"), 0644)
	os.WriteFile(filepath.Join(src, "compose.yml"), []byte("services:\n  web:\n    image: x\n"), 0644)
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0755)
	st := state.New()
	st.Sources = []state.Source{{Name: "local", Path: filepath.Dir(src)}}
	st.Save(filepath.Join(data, "state.yaml"))
	h, err := hub.New(hub.Config{ProjectDir: filepath.Join(root, "project"), DataDir: data, Domain: "example.org"}, nopRunner{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Init()
	t.Cleanup(h.Wait)
	s := &Server{Hub: h, Secret: testSecret, Web: web.FS}
	handler, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, body string, secret bool) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret {
		req.Header.Set(ProxySecretHeader, testSecret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestServerAuth(t *testing.T) {
	srv := newServer(t)
	if r, b := do(t, srv, "GET", "/healthz", "", false); r.StatusCode != 200 || b != "ok\n" {
		t.Errorf("healthz = %d %q", r.StatusCode, b)
	}
	for _, p := range []string{"/", "/api/templates", "/api/drift", "/api/settings", "/static/index.html"} {
		if r, _ := do(t, srv, "GET", p, "", false); r.StatusCode != 401 {
			t.Errorf("GET %s without secret = %d", p, r.StatusCode)
		}
	}
	if r, _ := do(t, srv, "POST", "/api/templates/enable", `{"id":"demo"}`, false); r.StatusCode != 401 {
		t.Errorf("enable without secret = %d", r.StatusCode)
	}

	r, b := do(t, srv, "GET", "/api/templates", "", true)
	if r.StatusCode != 200 {
		t.Fatalf("templates = %d %s", r.StatusCode, b)
	}
	var ts []map[string]interface{}
	if err := json.Unmarshal([]byte(b), &ts); err != nil || len(ts) != 1 || ts[0]["id"] != "demo" {
		t.Errorf("templates body = %s", b)
	}

	r, b = do(t, srv, "GET", "/", "", true)
	if r.StatusCode != 200 || !strings.Contains(b, "Demo &lt;b&gt;") || strings.Contains(b, "Demo <b>") {
		t.Errorf("index = %d, escaped name missing", r.StatusCode)
	}

	// The badge shows X-Forwarded-User (the LLDAP username) as-is, escaped.
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "alice<x>")
	req.Header.Set("X-Forwarded-Email", "alice@example.org")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "Authenticated as <strong>alice&lt;x&gt;</strong>") {
		t.Error("username badge missing or unescaped")
	}
}

func TestServerRoutes(t *testing.T) {
	srv := newServer(t)
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/api/templates/enable", `{"id":"demo"}`, 200},
		{"POST", "/api/templates/enable", `{"id":"../etc"}`, 400},
		{"POST", "/api/templates/enable", `{"id":"missing"}`, 400},
		{"POST", "/api/templates/enable", `not json`, 400},
		{"GET", "/api/templates/enable", "", 405},
		{"GET", "/api/templates/status/demo", "", 502}, // no docker engine in this test
		{"POST", "/api/drift/resolve", `{"id":"demo","action":"bogus"}`, 400},
		{"GET", "/api/drift", "", 200},
		{"PUT", "/api/settings", `{}`, 400},
		{"PUT", "/api/settings", `{"default_auth_policy":{"factors":["webauthn"]}}`, 200},
		{"PUT", "/api/settings", `{"default_auth_policy":{"factors":["password","mtls"]}}`, 400},
		{"GET", "/api/directory", "", 503}, // no directory service in this test
		{"POST", "/api/directory/users", `{}`, 503},
		{"GET", "/api/directory/users", "", 404}, // wrong method falls through to "/"
		{"GET", "/api/portal/apps", "", 200},
		{"POST", "/api/templates/disable", `{"id":"demo"}`, 200},
		{"POST", "/api/templates/disable", `{"id":"demo"}`, 400},
		{"GET", "/nope", "", 404},
	}
	for _, c := range cases {
		if r, b := do(t, srv, c.method, c.path, c.body, true); r.StatusCode != c.want {
			t.Errorf("%s %s = %d (%s), want %d", c.method, c.path, r.StatusCode, strings.TrimSpace(b), c.want)
		}
	}
	// Oversized body is refused.
	big := `{"id":"` + strings.Repeat("a", maxBodyBytes+10) + `"}`
	if r, _ := do(t, srv, "POST", "/api/templates/enable", big, true); r.StatusCode != 400 {
		t.Errorf("oversized body = %d", r.StatusCode)
	}
}
