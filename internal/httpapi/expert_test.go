package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/web"
)

// failRunner fails compose up like the AdGuard incident did.
type failRunner struct{ nopRunner }

func (failRunner) Up(context.Context, compose.Project) error {
	return &compose.Error{Command: "up", Err: errors.New("exit status 1"),
		Output: " Container portcullis-demo-web-1  Created\nError response from daemon: failed to bind host port 0.0.0.0:53/tcp: address already in use\n"}
}

func newExpertServer(t *testing.T, runner compose.Runner) (http.Handler, *directory.AuditLog) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "src", "demo")
	os.MkdirAll(src, 0755)
	os.WriteFile(filepath.Join(src, "manifest.yaml"), []byte("name: Demo\ncategory: test\nauth:\n  method: forward-auth\n"), 0644)
	os.WriteFile(filepath.Join(src, "compose.yml"), []byte("services:\n  web:\n    image: x\n    labels:\n      traefik.http.routers.demo.rule: Host(`demo.${PORTCULLIS_DOMAIN}`)\n"), 0644)
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0755)
	st := state.New()
	st.Sources = []state.Source{{Name: "local", Path: filepath.Dir(src)}}
	st.Save(filepath.Join(data, "state.yaml"))
	h, err := hub.New(hub.Config{ProjectDir: filepath.Join(root, "project"), DataDir: data, Domain: "example.org"}, runner, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Init()
	t.Cleanup(h.Wait)
	audit := &directory.AuditLog{Path: filepath.Join(data, "audit.jsonl")}
	s := &Server{Hub: h, Audit: audit, Secret: testSecret, Web: web.FS}
	handler, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return handler, audit
}

func call(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "alice")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A failed enable answers with compose's output and a hint (JSON), and
// the record stays readable afterwards — the app is not enabled.
func TestEnableErrorCarriesOutput(t *testing.T) {
	h, _ := newExpertServer(t, failRunner{})
	if r := call(h, "GET", "/api/templates/lastop/demo", ""); r.Code != 200 || strings.TrimSpace(r.Body.String()) != "null" {
		t.Errorf("lastop before = %d %s", r.Code, r.Body)
	}
	r := call(h, "POST", "/api/templates/enable", `{"id":"demo"}`)
	if r.Code != 500 || !strings.HasPrefix(r.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("enable = %d %q %s", r.Code, r.Header().Get("Content-Type"), r.Body)
	}
	var body struct {
		Error, Op, Output, Hint string
		RolledBack              bool `json:"rolled_back"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Op != "enable" || !body.RolledBack || !strings.Contains(body.Error, "address already in use") ||
		!strings.Contains(body.Output, "Container portcullis-demo-web-1  Created") || !strings.Contains(body.Hint, "0.0.0.0:53/tcp") {
		t.Errorf("body = %+v", body)
	}
	r = call(h, "GET", "/api/templates/lastop/demo", "")
	var rec hub.OpRecord
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &rec) != nil || rec.OK || rec.Output != body.Output {
		t.Errorf("lastop = %d %s", r.Code, r.Body)
	}
	if r := call(h, "GET", "/api/templates/lastop/missing", ""); r.Code != 404 {
		t.Errorf("lastop unknown = %d", r.Code)
	}
	// The catalog shows the failure and offers its Logs tab.
	page := call(h, "GET", "/", "").Body.String()
	if !strings.Contains(page, `data-dtab="logs" data-app="demo"`) || !strings.Contains(page, "last enable failed") {
		t.Error("index lacks the failed-op badge / Logs tab")
	}
	// Restart of a not-enabled app: plain 400.
	if r := call(h, "POST", "/api/templates/restart/demo", "{}"); r.Code != 400 {
		t.Errorf("restart = %d %s", r.Code, r.Body)
	}
}

func TestExpertComposeAPI(t *testing.T) {
	h, audit := newExpertServer(t, nopRunner{})
	r := call(h, "GET", "/api/templates/compose/demo", "")
	var v hub.ComposeView
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || !strings.Contains(v.Compose, "traefik.http.routers.demo.rule") ||
		!strings.Contains(v.HubOverride, "tls.options") || v.UserOverride != "" || len(v.Rules) == 0 {
		t.Fatalf("GET = %d %s", r.Code, r.Body)
	}
	// The template's compose.yml and the Hub override are read-only.
	if r := call(h, "PUT", "/api/templates/compose/demo", `{"compose":"services: {}"}`); r.Code != 400 {
		t.Errorf("compose edit = %d", r.Code)
	}
	if r := call(h, "PUT", "/api/templates/compose/demo", `{"user_override":"services:\n  web:\n    privileged: true\n"}`); r.Code != 400 || !strings.Contains(r.Body.String(), "privileged") {
		t.Errorf("privileged = %d %s", r.Code, r.Body)
	}
	r = call(h, "PUT", "/api/templates/compose/demo", `{"user_override":"services:\n  web:\n    environment:\n      PASSWORD: hunter2hunter2\n"}`)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"restart_required":false`) || !strings.Contains(r.Body.String(), `"saved"`) {
		t.Errorf("save = %d %s", r.Code, r.Body)
	}
	if r := call(h, "POST", "/api/templates/enable", `{"id":"demo"}`); r.Code != 200 {
		t.Fatalf("enable = %d %s", r.Code, r.Body)
	}
	r = call(h, "PUT", "/api/templates/compose/demo", `{"user_override":""}`)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"removed"`) || !strings.Contains(r.Body.String(), `"restart_required":true`) {
		t.Errorf("remove = %d %s", r.Code, r.Body)
	}
	if r := call(h, "POST", "/api/templates/restart/demo", "{}"); r.Code != 200 || !strings.Contains(r.Body.String(), "restarted") {
		t.Errorf("restart = %d %s", r.Code, r.Body)
	}
	es, _ := audit.Recent(10)
	if len(es) != 3 || es[2].Result != "refused" || es[1].Result != "ok" || !strings.HasPrefix(es[1].Detail, "saved (") ||
		es[0].Detail != "removed" || es[0].Action != "app.compose_override" || es[0].Actor != "alice" || es[0].Target != "demo" {
		t.Errorf("audit = %+v", es)
	}
	raw, _ := os.ReadFile(audit.Path)
	if strings.Contains(string(raw), "hunter2") {
		t.Error("override content in the audit log")
	}
}
