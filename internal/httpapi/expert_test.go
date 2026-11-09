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
	"time"

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
	h, audit, _ := newExpertServerHub(t, runner)
	return h, audit
}

// newExpertServerHub is newExpertServer with the Hub it serves.
func newExpertServerHub(t *testing.T, runner compose.Runner) (http.Handler, *directory.AuditLog, *hub.Hub) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "src", "demo")
	os.MkdirAll(src, 0755)
	os.WriteFile(filepath.Join(src, "manifest.yaml"), []byte("name: Demo\ncategory: test\nai: {unsupported: test fixture}\nauth:\n  method: forward-auth\n"), 0644)
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
	h.SetAudit(audit) // the Hub audits instance.enable / restart (as main wires it)
	s := &Server{Hub: h, Audit: audit, Secret: testSecret, Web: web.FS}
	handler, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return handler, audit, h
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
	h, _, hb := newExpertServerHub(t, failRunner{})
	if r := call(h, "GET", "/api/templates/lastop/demo", ""); r.Code != 200 || strings.TrimSpace(r.Body.String()) != "null" {
		t.Errorf("lastop before = %d %s", r.Code, r.Body)
	}
	// In the background (202, §11.7): the failure is the op record's.
	r := call(h, "POST", "/api/templates/enable", `{"id":"demo"}`)
	if r.Code != 202 {
		t.Fatalf("enable = %d %q %s", r.Code, r.Header().Get("Content-Type"), r.Body)
	}
	rec := waitHandlerOp(t, h, "demo")
	if rec.Op != "enable" || rec.OK || rec.Running || !rec.RolledBack || rec.Status != 500 || !strings.Contains(rec.Error, "address already in use") ||
		!strings.Contains(rec.Output, "Container portcullis-demo-web-1  Created") || !strings.Contains(rec.Hint, "0.0.0.0:53/tcp") {
		t.Errorf("lastop = %+v", rec)
	}
	if r := call(h, "GET", "/api/templates/lastop/missing", ""); r.Code != 404 {
		t.Errorf("lastop unknown = %d", r.Code)
	}
	// Apps shows the failure ("last enable failed": the instance's state
	// error — the record above — and its op summary's op) and the
	// instance page offers its Logs tab.
	// The data the rows read: /api/instances/ops (OpSummaries) has demo's
	// failed enable, /api/instances (Instances) its state error.
	if o, ok := hb.OpSummaries()["demo"]; !ok || o.Op != "enable" || o.OK || o.Running {
		t.Errorf("op summary = %+v", o)
	}
	failed := false
	for _, v := range hb.Instances() {
		failed = failed || (v.ID == "demo" && v.State == hub.StateError)
	}
	if !failed {
		t.Errorf("instances = %+v, want demo in state error", hb.Instances())
	}
	page := call(h, "GET", "/", "").Body.String()
	if !strings.Contains(page, `text: 'last ' + ((op && op.op) || 'operation') + ' failed'`) || !strings.Contains(page, `['logs', 'Logs']`) {
		t.Error("Apps lacks the failed-op badge, or the instance page its Logs tab")
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
	if r := call(h, "POST", "/api/templates/enable", `{"id":"demo"}`); r.Code != 202 {
		t.Fatalf("enable = %d %s", r.Code, r.Body)
	}
	waitHandlerOp(t, h, "demo")
	r = call(h, "PUT", "/api/templates/compose/demo", `{"user_override":""}`)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"removed"`) || !strings.Contains(r.Body.String(), `"restart_required":true`) {
		t.Errorf("remove = %d %s", r.Code, r.Body)
	}
	if r := call(h, "POST", "/api/templates/restart/demo", "{}"); r.Code != 202 || !strings.Contains(r.Body.String(), `"op":"restart"`) {
		t.Errorf("restart = %d %s", r.Code, r.Body)
	}
	waitHandlerOp(t, h, "demo")
	all, _ := audit.Recent(10)
	var es []directory.AuditEntry // the enable and restart are audited too (instance.*)
	for _, e := range all {
		if e.Action == "app.compose_override" {
			es = append(es, e)
		}
	}
	if len(all) != 5 || len(es) != 3 || es[2].Result != "refused" || es[1].Result != "ok" || !strings.HasPrefix(es[1].Detail, "saved (") ||
		es[0].Detail != "removed" || es[0].Action != "app.compose_override" || es[0].Actor != "alice" || es[0].Target != "demo" {
		t.Errorf("audit = %+v", es)
	}
	raw, _ := os.ReadFile(audit.Path)
	if strings.Contains(string(raw), "hunter2") {
		t.Error("override content in the audit log")
	}
}

// waitHandlerOp polls h's /api/templates/lastop/<id> until its record no
// longer runs.
func waitHandlerOp(t *testing.T, h http.Handler, id string) hub.OpRecord {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		r := call(h, "GET", "/api/templates/lastop/"+id, "")
		var rec hub.OpRecord
		if r.Code == 200 && json.Unmarshal(r.Body.Bytes(), &rec) == nil && rec.Op != "" && !rec.Running {
			return rec
		}
	}
	t.Fatalf("%s: op still running", id)
	return hub.OpRecord{}
}
