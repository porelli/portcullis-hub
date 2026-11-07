package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// Operation progress, Task 7 (contract §11.7, §15.10): enable, disable,
// restart and create answer 202 {op_id, op, instance, poll} and the op
// record (with its steps) polls to done; a busy instance is a 409 whose
// body is the running record; POST /api/instances/{id}/op/stop stops it.

// blockingPull is the fake engine whose image pulls wait until release
// is closed (or the pull's context ends: a Stop): an enable stays running
// on its images step.
type blockingPull struct {
	hub.Engine
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (e *blockingPull) PullWithProgress(ctx context.Context, ref string, fn func(int64, int64, bool)) error {
	e.once.Do(func() { close(e.started) })
	select {
	case <-e.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func newBlockingPull(e hub.Engine) *blockingPull {
	return &blockingPull{Engine: e, started: make(chan struct{}), release: make(chan struct{})}
}

func newBlockingEnv(t *testing.T) (*instEnv, *blockingPull) {
	t.Helper()
	var bp *blockingPull
	e := newInstEnvWith(t, t.TempDir(), nil, func(f *fakeEngine) hub.Engine {
		bp = newBlockingPull(f)
		return bp
	})
	t.Cleanup(func() {
		select {
		case <-bp.release:
		default:
			close(bp.release)
		}
	})
	return e, bp
}

// stepKeys lists a record's step keys.
func stepKeys(r hub.OpRecord) []string {
	var out []string
	for _, s := range r.Steps {
		out = append(out, s.Key)
	}
	return out
}

func TestLifecycleRoutesAnswer202(t *testing.T) {
	e := newInstEnv(t)
	// Create: 202 (op create, the new id's record), result instance.
	rec := e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-a"}`)
	if !rec.OK || rec.Op != "create" || rec.Result["instance"] != "grafana-a" || len(rec.Steps) == 0 || rec.Created == nil {
		t.Fatalf("create record = %+v", rec)
	}
	// Enable: 202, its steps planned (groups … settings), all done.
	rec = e.runOp(t, "POST", "/api/templates/enable", `{"id":"grafana-a"}`)
	if !rec.OK || rec.Op != "enable" || rec.Actor != "root" {
		t.Fatalf("enable record = %+v", rec)
	}
	if got := strings.Join(stepKeys(rec), ","); !strings.Contains(got, "images") || !strings.Contains(got, "healthy") {
		t.Errorf("enable steps = %s", got)
	}
	for _, s := range rec.Steps {
		if s.State != hub.StepDone {
			t.Errorf("enable step %s = %s", s.Key, s.State)
		}
	}
	if !e.s.Hub.IsEnabled("grafana-a") {
		t.Fatal("grafana-a not enabled")
	}
	// Restart and disable: 202 too.
	if rec = e.runOp(t, "POST", "/api/templates/restart/grafana-a", ``); !rec.OK || rec.Op != "restart" || len(rec.Steps) == 0 {
		t.Fatalf("restart record = %+v", rec)
	}
	if rec = e.runOp(t, "POST", "/api/templates/disable", `{"id":"grafana-a"}`); !rec.OK || rec.Op != "disable" || len(rec.Steps) == 0 {
		t.Fatalf("disable record = %+v", rec)
	}
	if e.s.Hub.IsEnabled("grafana-a") {
		t.Fatal("grafana-a still enabled")
	}
	// Synchronous refusals keep their codes; nothing is recorded.
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{"POST", "/api/templates/enable", `{"id":"Bad_ID"}`, 400},
		{"POST", "/api/templates/enable", `{"id":"nosuch"}`, 404},
		{"POST", "/api/templates/disable", `{"id":"grafana-a"}`, 400}, // not enabled
		{"POST", "/api/templates/restart/grafana-a", ``, 400},         // not enabled
		{"POST", "/api/templates/restart/nosuch", ``, 404},
		{"POST", "/api/instances", `{"template":"grafana","id":"grafana-a"}`, 409},
	} {
		if code, b := e.do(t, "root", c.method, c.path, c.body); code != c.code {
			t.Errorf("%s %s %s = %d %s, want %d", c.method, c.path, c.body, code, b, c.code)
		}
	}
	// Audited once each, with the outcome, by the request's actor.
	got := strings.Join(e.auditActions(t, "instance.enable"), ",")
	if !strings.HasPrefix(got, "instance.enable:ok:root:grafana-a") {
		t.Errorf("enable audit = %s", got)
	}
	for _, a := range []string{"instance.restart", "instance.disable"} {
		if got := e.auditActions(t, a); len(got) == 0 || got[0] != a+":ok:root:grafana-a" {
			t.Errorf("%s audit = %v", a, got)
		}
	}
}

// A request on an instance whose operation runs: 409 with the running
// record as JSON; the Stop route stops it (202 with the record), the
// record polls to stopped, a second Stop is 409 with the record.
func TestBusyAndStopRoutes(t *testing.T) {
	e, bp := newBlockingEnv(t)
	mustDo(t, e.hub, "root", "POST", "/api/instances", `{"template":"grafana","id":"grafana-a"}`, 202)
	waitIdle(t, e.s.Hub, "grafana-a")
	code, b := e.do(t, "root", "POST", "/api/templates/enable", `{"id":"grafana-a"}`)
	if code != 202 {
		t.Fatalf("enable = %d %s", code, b)
	}
	var acc OpStarted
	json.Unmarshal([]byte(b), &acc)
	select {
	case <-bp.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the enable never pulled")
	}
	// Busy: every lifecycle route answers the running record.
	for _, c := range [][3]string{
		{"POST", "/api/templates/enable", `{"id":"grafana-a"}`},
		{"POST", "/api/templates/disable", `{"id":"grafana-a"}`},
		{"POST", "/api/instances/grafana-a/backups", ``},
		{"DELETE", "/api/instances/grafana-a", `{"confirm":"grafana-a"}`},
	} {
		r, body := doAs(t, e.hub, "root", c[0], c[1], c[2])
		var rec hub.OpRecord
		if r.StatusCode != 409 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") ||
			json.Unmarshal([]byte(body), &rec) != nil || !rec.Running || rec.OpID != acc.OpID || rec.Op != "enable" || len(rec.Steps) == 0 {
			t.Errorf("busy %s %s = %d %q %s", c[0], c[1], r.StatusCode, r.Header.Get("Content-Type"), body)
		}
	}
	// The Stop route: strict body, admins only, Hub listener only.
	for _, body := range []string{``, `{"x":1}`, `{} {}`} {
		if code, b := e.do(t, "root", "POST", "/api/instances/grafana-a/op/stop", body); code != 400 {
			t.Errorf("stop body %q = %d %s, want 400", body, code, b)
		}
	}
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"helpers"}`, 200)
	for _, u := range []string{"dana", "nobody", ""} {
		if code, b := e.do(t, u, "POST", "/api/instances/grafana-a/op/stop", `{}`); code != 403 {
			t.Errorf("stop as %q = %d %s, want 403", u, code, b)
		}
	}
	if r, _ := doAs(t, e.ppl, "root", "POST", "/api/instances/grafana-a/op/stop", `{}`); r.StatusCode != 404 && r.StatusCode != 405 {
		t.Errorf("people listener stop = %d, want 404", r.StatusCode)
	}
	// CSRF: a form post is refused before the handler.
	req, _ := http.NewRequest("POST", e.hub.URL+"/api/instances/grafana-a/op/stop", strings.NewReader(`x=1`))
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form post stop = %v %v", resp, err)
	}
	// Without the proxy secret: refused.
	req, _ = http.NewRequest("POST", e.hub.URL+"/api/instances/grafana-a/op/stop", strings.NewReader(`{}`))
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode < 400 {
		t.Errorf("stop without the proxy secret = %v %v", resp, err)
	}
	if !e.s.Hub.LastOp("grafana-a").Running || e.s.Hub.LastOp("grafana-a").Stopping {
		t.Fatal("a refused Stop stopped the enable")
	}
	// Stop: 202 with the stopping record.
	r, body := doAs(t, e.hub, "root", "POST", "/api/instances/grafana-a/op/stop", `{}`)
	var rec hub.OpRecord
	if r.StatusCode != 202 || json.Unmarshal([]byte(body), &rec) != nil || !rec.Stopping || rec.StoppedBy != "root" || rec.OpID != acc.OpID {
		t.Fatalf("stop = %d %s", r.StatusCode, body)
	}
	waitIdle(t, e.s.Hub, "grafana-a")
	final := e.s.Hub.LastOp("grafana-a")
	if final.OK || final.Running || final.Stopping || final.Error != "" || final.OpID != acc.OpID {
		t.Fatalf("stopped record = %+v", final)
	}
	if e.s.Hub.IsEnabled("grafana-a") {
		t.Error("a stopped enable left the instance enabled")
	}
	// Nothing runs now: 409 with the record.
	r, body = doAs(t, e.hub, "root", "POST", "/api/instances/grafana-a/op/stop", `{}`)
	rec = hub.OpRecord{}
	if r.StatusCode != 409 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || json.Unmarshal([]byte(body), &rec) != nil || rec.OpID != acc.OpID {
		t.Errorf("stop again = %d %s", r.StatusCode, body)
	}
	// Unknown instance, no record: 404.
	if code, b := e.do(t, "root", "POST", "/api/instances/nosuch/op/stop", `{}`); code != 404 {
		t.Errorf("stop unknown = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "POST", "/api/instances/home/op/stop", `{}`); code != 404 {
		t.Errorf("stop without a record = %d %s", code, b)
	}
	// Audited enable.stop (ok, then refused) by root.
	got := strings.Join(e.auditActions(t, "enable.stop"), ",")
	if got != "enable.stop:ok:root:grafana-a,enable.stop:refused:root:grafana-a" {
		t.Errorf("stop audit = %s", got)
	}
}

// MCP: the enable tool answers the twin's 202 body, a busy call is an
// isError "409: " with the running record, get_op / wait_for_op show the
// steps and created, stop_op stops it (W: no confirmation) and answers
// the stopping record, audited enable.stop via ai.
func TestStopOpTool(t *testing.T) {
	var bp *blockingPull
	e := newToolEnvWith(t, mcpEnvOpts{wrap: func(f hub.Engine) hub.Engine {
		bp = newBlockingPull(f)
		return bp
	}})
	defer func() {
		select {
		case <-bp.release:
		default:
			close(bp.release)
		}
	}()
	if _, err := e.s.Hub.CreateInstanceAs("notes", "x", nil, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	txt, isErr, conf := e.tool(t, "enable_instance", map[string]any{"id": "x"})
	var op OpStarted
	if isErr || conf != "" || json.Unmarshal([]byte(txt), &op) != nil || op.Op != "enable" || op.Instance != "x" || op.Poll != "/api/instances/x/op" || op.OpID == "" {
		t.Fatalf("enable_instance = %s %v %q", txt, isErr, conf)
	}
	select {
	case <-bp.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the enable never pulled")
	}
	txt, isErr, _ = e.tool(t, "restart_instance", map[string]any{"id": "x"})
	var busy hub.OpRecord
	if !isErr || !strings.HasPrefix(txt, "409: ") || json.Unmarshal([]byte(strings.TrimPrefix(txt, "409: ")), &busy) != nil || !busy.Running || busy.OpID != op.OpID {
		t.Errorf("busy restart_instance = %s %v", txt, isErr)
	}
	txt, isErr, _ = e.tool(t, "get_op", map[string]any{"id": "x"})
	var rec hub.OpRecord
	if isErr || json.Unmarshal([]byte(txt), &rec) != nil || !rec.Running || len(rec.Steps) == 0 || rec.Created == nil ||
		!strings.Contains(txt, `"steps":`) || !strings.Contains(txt, `"created":`) || !rec.Stoppable {
		t.Fatalf("get_op = %s %v", txt, isErr)
	}
	txt, isErr, conf = e.tool(t, "stop_op", map[string]any{"id": "x"})
	rec = hub.OpRecord{}
	if isErr || conf != "" || json.Unmarshal([]byte(txt), &rec) != nil || !rec.Stopping || rec.StoppedBy != "root" {
		t.Fatalf("stop_op = %s %v %q", txt, isErr, conf)
	}
	txt, isErr, _ = e.tool(t, "wait_for_op", map[string]any{"id": "x", "op_id": op.OpID})
	var w struct {
		Done   bool         `json:"done"`
		Record hub.OpRecord `json:"record"`
	}
	if isErr || json.Unmarshal([]byte(txt), &w) != nil || !w.Done || w.Record.OK || w.Record.StoppedBy != "root" || len(w.Record.Steps) == 0 || !strings.Contains(txt, `"created":`) {
		t.Fatalf("wait_for_op = %s %v", txt, isErr)
	}
	// Nothing runs: isError 409 with the record.
	txt, isErr, _ = e.tool(t, "stop_op", map[string]any{"id": "x"})
	if !isErr || !strings.HasPrefix(txt, "409: {") {
		t.Errorf("stop_op again = %s %v", txt, isErr)
	}
	if txt, isErr, _ = e.tool(t, "stop_op", map[string]any{"id": "nosuch"}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("stop_op unknown = %s %v", txt, isErr)
	}
	var stops []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "enable.stop" {
			stops = append(stops, a)
		}
	}
	if len(stops) != 2 || stops[0].Result != "ok" || stops[1].Result != "refused" || stops[0].Via != "ai" || stops[0].Client != mcpClient {
		t.Errorf("enable.stop audit = %+v", stops)
	}
}

// opDone sends a long-operation request through srv as user, wants 202
// {op_id, …} and polls the instance's op record (as root, an admin) until
// that operation ended: its final record.
func opDone(t *testing.T, srv *httptest.Server, user, method, path, body string) hub.OpRecord {
	t.Helper()
	r, b := doAs(t, srv, user, method, path, body)
	var acc OpStarted
	if r.StatusCode != http.StatusAccepted || json.Unmarshal([]byte(b), &acc) != nil || acc.OpID == "" || acc.Poll != "/api/instances/"+acc.Instance+"/op" {
		t.Fatalf("%s %s = %d %s, want 202 + op id", method, path, r.StatusCode, b)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r, b := doAs(t, srv, "root", "GET", acc.Poll, "")
		var rec hub.OpRecord
		if r.StatusCode == 200 && json.Unmarshal([]byte(b), &rec) == nil && rec.OpID == acc.OpID && !rec.Running {
			return rec
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s %s: op %s did not finish", method, path, acc.OpID)
	return hub.OpRecord{}
}

// opOK is opDone wanting the operation to succeed.
func opOK(t *testing.T, srv *httptest.Server, method, path, body string) hub.OpRecord {
	t.Helper()
	rec := opDone(t, srv, "root", method, path, body)
	if !rec.OK {
		t.Fatalf("%s %s %s failed: %+v", method, path, body, rec)
	}
	return rec
}

// PUT /api/instances/{id}/ai (§15.11): on an enabled instance a companion
// switch runs in the background (202, op ai, its steps); on a disabled
// one it answers the tab (200, TestInstanceAIAPI).
func TestAISwitchRouteAnswers202(t *testing.T) {
	e := aiAppEnv(t)
	opOK(t, e.hub, "POST", "/api/templates/enable", `{"id":"aiapp"}`)
	rec := opDone(t, e.hub, "root", "PUT", "/api/instances/aiapp/ai", `{"companions":{"tok":{"enabled":true,"mode":"read_only"}}}`)
	if rec.Op != "ai" || rec.Actor != "root" || len(rec.Steps) == 0 {
		t.Fatalf("ai record = %+v", rec)
	}
	if got := strings.Join(stepKeys(rec), ","); !strings.Contains(got, "restart") {
		t.Errorf("ai steps = %s", got)
	}
	// The fake engine runs no container for the revoke hook: the switch
	// fails in the background — the record's outcome, never the answer.
	if rec.OK || !strings.Contains(rec.Error, "revoke_all failed") {
		t.Errorf("ai record = %+v", rec)
	}
	// On a disabled instance: the tab at once (200), no operation.
	opDone(t, e.hub, "root", "POST", "/api/templates/disable", `{"id":"aiapp"}`)
	if code, b := e.do(t, "root", "PUT", "/api/instances/aiapp/ai", `{"companions":{"tok":{"enabled":false}}}`); code != 200 || !strings.Contains(b, `"companions"`) {
		t.Errorf("disabled instance = %d %s", code, b)
	}
}
