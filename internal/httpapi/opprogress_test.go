package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
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

// blockingDown is the compose runner whose Down waits while armed (a
// disable held on its stop step).
type blockingDown struct {
	nopRunner
	mu      sync.Mutex
	gate    chan struct{}
	reached chan struct{}
}

func (b *blockingDown) arm() {
	b.mu.Lock()
	b.gate, b.reached = make(chan struct{}), make(chan struct{}, 1)
	b.mu.Unlock()
}

func (b *blockingDown) release() {
	b.mu.Lock()
	if b.gate != nil {
		close(b.gate)
		b.gate = nil
	}
	b.mu.Unlock()
}

func (b *blockingDown) Down(ctx context.Context, p compose.Project) error {
	b.mu.Lock()
	gate, reached := b.gate, b.reached
	b.mu.Unlock()
	if gate != nil {
		select {
		case reached <- struct{}{}:
		default:
		}
		<-gate
	}
	return nil
}

// stopAsked calls stop_op as root (text form) with id and opID and wants
// a confirmation: it is declined (which blocks those arguments until it
// expires), and the operation keeps running, not stopping.
func stopAsked(t *testing.T, e *toolEnv, id, opID string) {
	t.Helper()
	txt, isErr := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "stop_op", map[string]any{"id": id, "op_id": opID}, nil))
	m := confirmTextRe.FindStringSubmatch(txt)
	if m == nil {
		t.Fatalf("stop_op without a confirmation = %s %v", txt, isErr)
	}
	e.decide(t, m[1], "", false)
	if r := e.s.Hub.LastOp(id); r == nil || !r.Running || r.Stopping {
		t.Fatalf("a declined stop_op stopped it: %+v", r)
	}
}

// stop_op's class follows what the undo turns back on (Task 7 security
// review): stopping a disable (the app back on) or an AI switch-off (the
// companion back on) needs op_id and the confirmation enable_instance /
// set_ai_support would; declined, nothing stops; confirmed, it stops. A
// confirmation for one operation never stops another. An admin's HTTP
// Stop is unaffected.
func TestStopOpClassFollowsTheUndo(t *testing.T) {
	br := &blockingDown{}
	e := newToolEnvWith(t, mcpEnvOpts{runner: br})
	defer br.release()
	waitDown := func() {
		t.Helper()
		select {
		case <-br.reached:
		case <-time.After(10 * time.Second):
			t.Fatal("the disable never reached compose down")
		}
	}
	startDisable := func() OpStarted {
		t.Helper()
		br.arm()
		txt, isErr, conf := e.tool(t, "disable_instance", map[string]any{"id": "aiapp"})
		var op OpStarted
		if isErr || conf != "" || json.Unmarshal([]byte(txt), &op) != nil || op.Op != "disable" {
			t.Fatalf("disable_instance = %s %v %q", txt, isErr, conf)
		}
		waitDown()
		return op
	}
	// A disable: its undo enables aiapp again, whose access group has
	// members (enable_instance would be D).
	op := startDisable()
	if txt, isErr, _ := e.tool(t, "stop_op", map[string]any{"id": "aiapp"}); !isErr || !strings.HasPrefix(txt, "400: ") || !strings.Contains(txt, "op_id") {
		t.Errorf("D stop_op without op_id = %s %v", txt, isErr)
	}
	stopAsked(t, e, "aiapp", op.OpID)
	// An op_id that isn't the running one: refused (409 with the current
	// record), nothing stopped.
	if txt, isErr, _ := e.tool(t, "stop_op", map[string]any{"id": "aiapp", "op_id": "0123456789abcdef"}); !isErr || !strings.HasPrefix(txt, "409: {") || !strings.Contains(txt, op.OpID) {
		t.Errorf("stop_op of another op = %s %v", txt, isErr)
	}
	if r := e.s.Hub.LastOp("aiapp"); !r.Running || r.Stopping {
		t.Fatalf("a refused stop_op stopped it: %+v", r)
	}
	br.release()
	waitIdle(t, e.s.Hub, "aiapp")
	opOK(t, e.hub, "POST", "/api/templates/enable", `{"id":"aiapp"}`)

	// Confirmed: it stops, aiapp is enabled again.
	op = startDisable()
	txt, isErr, conf := e.tool(t, "stop_op", map[string]any{"id": "aiapp", "op_id": op.OpID})
	var rec hub.OpRecord
	if isErr || conf == "" || json.Unmarshal([]byte(txt), &rec) != nil || !rec.Stopping || rec.OpID != op.OpID {
		t.Fatalf("confirmed stop_op = %s %v %q", txt, isErr, conf)
	}
	br.release()
	waitIdle(t, e.s.Hub, "aiapp")
	if r := e.s.Hub.LastOp("aiapp"); r.OK || r.Running || r.StoppedBy != "root" || !e.s.Hub.IsEnabled("aiapp") {
		t.Fatalf("stopped disable = %+v enabled %v", r, e.s.Hub.IsEnabled("aiapp"))
	}
	var stop directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "disable.stop" && a.Result == "ok" {
			stop = a
		}
	}
	if stop.Via != "ai" || !strings.HasSuffix(stop.Detail, "confirmation "+conf) {
		t.Errorf("disable.stop audit = %+v, want via ai with confirmation %s", stop, conf)
	}

	// An AI switch-off (W): held on its revoke_all hook; its undo
	// switches tok back on in read_write (set_ai_support on: D).
	holdHooks := func() func() {
		gate := make(chan struct{})
		e.eng.mu.Lock()
		e.eng.gate, e.eng.calls = gate, nil
		e.eng.mu.Unlock()
		return sync.OnceFunc(func() {
			e.eng.mu.Lock()
			e.eng.gate = nil
			e.eng.mu.Unlock()
			close(gate)
		})
	}
	switchOff := func() OpStarted {
		t.Helper()
		txt, isErr, conf := e.tool(t, "set_ai_support", map[string]any{"id": "aiapp", "companion": "tok", "enabled": false})
		var op OpStarted
		if isErr || conf != "" || json.Unmarshal([]byte(txt), &op) != nil || op.Op != "ai" {
			t.Fatalf("set_ai_support off = %s %v %q", txt, isErr, conf)
		}
		// Its Before is in the very first record (written before ready).
		if r := e.s.Hub.LastOp("aiapp"); r == nil || r.OpID != op.OpID || r.Before[hub.BeforeCompanion+"tok"] != "on read_write" {
			t.Fatalf("first AI record = %+v", r)
		}
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			e.eng.mu.Lock()
			n := len(e.eng.calls)
			e.eng.mu.Unlock()
			if n > 0 {
				return op
			}
			if time.Now().After(deadline) {
				t.Fatal("the switch-off never ran its revoke hook")
			}
		}
	}
	release := holdHooks()
	defer release()
	op = switchOff()
	stopAsked(t, e, "aiapp", op.OpID)
	release()
	waitIdle(t, e.s.Hub, "aiapp")

	// A confirmation for operation A, used once A ended and B runs:
	// refused, B untouched.
	opOK(t, e.hub, "PUT", "/api/instances/aiapp/ai", `{"companions":{"tok":{"enabled":true}}}`)
	release = holdHooks()
	defer release()
	a := switchOff()
	args := map[string]any{"id": "aiapp", "op_id": a.OpID}
	txt, _ = resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "stop_op", args, nil))
	m := confirmTextRe.FindStringSubmatch(txt)
	if m == nil {
		t.Fatalf("stop_op of the switch-off = %s", txt)
	}
	e.decide(t, m[1], "aiapp", true)
	release()
	waitIdle(t, e.s.Hub, "aiapp")
	b := startDisable()
	txt, isErr = resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "stop_op", args, nil))
	if !isErr || !strings.HasPrefix(txt, "409: {") || !strings.Contains(txt, b.OpID) {
		t.Errorf("A's confirmation used on B = %s %v", txt, isErr)
	}
	if r := e.s.Hub.LastOp("aiapp"); !r.Running || r.Stopping || r.OpID != b.OpID {
		t.Fatalf("B stopped by A's confirmation: %+v", r)
	}

	// The admin's HTTP Stop of a disable: no confirmation, 202.
	if code, b := e.do(t, "root", "POST", "/api/instances/aiapp/op/stop", `{}`); code != 202 || !strings.Contains(b, `"stopping":true`) {
		t.Errorf("HTTP stop = %d %s", code, b)
	}
	br.release()
	waitIdle(t, e.s.Hub, "aiapp")
	if !e.s.Hub.IsEnabled("aiapp") {
		t.Error("the stopped disable left aiapp disabled")
	}
}

// undoClass per operation (Task 7 security review): what the undo turns
// back on decides; cloud is public by default (its enable is D), secretapp
// isn't (W).
func TestStopUndoClass(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	ctx := withCallMemo(context.Background(), &directory.Caller{User: "root", Admin: true})
	before := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, c := range []struct {
		name, id string
		rec      *hub.OpRecord
		want     ToolClass
	}{
		{"no record", "cloud", nil, ClassWrite},
		{"enable", "cloud", &hub.OpRecord{Op: hub.OpEnable}, ClassWrite},
		{"restart", "cloud", &hub.OpRecord{Op: hub.OpRestart, Before: before("running", "true")}, ClassWrite},
		{"backup", "cloud", &hub.OpRecord{Op: hub.OpBackup, Before: before("running", "true")}, ClassWrite},
		{"create", "cloud", &hub.OpRecord{Op: hub.OpCreate}, ClassWrite},
		{"disable, public app", "cloud", &hub.OpRecord{Op: hub.OpDisable}, ClassDestructive},
		{"disable, plain app", "secretapp", &hub.OpRecord{Op: hub.OpDisable}, ClassWrite},
		{"delete of an enabled public app", "cloud", &hub.OpRecord{Op: hub.OpDelete, Before: before(hub.BeforeEnabled, "true")}, ClassDestructive},
		{"delete, Before not written yet", "cloud", &hub.OpRecord{Op: hub.OpDelete}, ClassDestructive},
		{"delete of a disabled app", "cloud", &hub.OpRecord{Op: hub.OpDelete, Before: before(hub.BeforeEnabled, "false")}, ClassWrite},
		{"restore of an enabled app", "secretapp", &hub.OpRecord{Op: hub.OpRestore, Before: before(hub.BeforeEnabled, "true")}, ClassDestructive},
		{"restore, rollback armed", "secretapp", &hub.OpRecord{Op: hub.OpRestore, Before: before(hub.BeforeEnabled, "false", hub.BeforeRestoring, "true")}, ClassDestructive},
		{"restore, Before not written yet", "secretapp", &hub.OpRecord{Op: hub.OpRestore}, ClassDestructive},
		{"restore of a disabled app", "secretapp", &hub.OpRecord{Op: hub.OpRestore, Before: before(hub.BeforeEnabled, "false")}, ClassWrite},
		{"restore into a new id", "secretapp", &hub.OpRecord{Op: hub.OpRestore, Before: before(hub.BeforeNewID, "true", hub.BeforeEnabled, "true")}, ClassWrite},
		{"AI switch-off", "aiapp", &hub.OpRecord{Op: hub.OpAI, Before: before(hub.BeforeCompanion+"tok", "on read_only")}, ClassDestructive},
		{"AI switch-on", "aiapp", &hub.OpRecord{Op: hub.OpAI, Before: before(hub.BeforeCompanion+"tok", "off read_write")}, ClassWrite},
		{"AI, unreadable entry", "aiapp", &hub.OpRecord{Op: hub.OpAI, Before: before(hub.BeforeCompanion+"tok", "?")}, ClassDestructive},
		{"AI, Before not written yet", "aiapp", &hub.OpRecord{Op: hub.OpAI}, ClassDestructive},
	} {
		if got := e.s.undoClass(ctx, c.id, c.rec); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}

	// Run's own refusals go through the Hub (fix round 1): audited
	// <op>.stop refused, a 409 answered with the current record.
	rec := e.s.Hub.LastOp("aiapp")
	if rec == nil {
		t.Fatal("aiapp has no record")
	}
	err := e.s.refuseStop(directory.Human("root"), "aiapp", hub.ErrOpChanged)
	if got := opRecordOf(err); got == nil || got.OpID != rec.OpID || errStatus(err, 500) != 409 {
		t.Errorf("refuseStop = %v (record %+v)", err, got)
	}
	audits := readAudit(t, e.audit)
	if a := audits[len(audits)-1]; a.Action != rec.Op+".stop" || a.Result != "refused" || a.Target != "aiapp" {
		t.Errorf("refuseStop audit = %+v", a)
	}
	err = e.s.refuseStop(directory.Human("root"), "Bad_ID", badArg("invalid instance id"))
	audits = readAudit(t, e.audit)
	if a := audits[len(audits)-1]; errStatus(err, 500) != 400 || a.Action != "op.stop" || a.Result != "refused" {
		t.Errorf("refuseStop of an invalid id = %v, audit %+v", err, a)
	}
}

// A record without an op id (finishOp's: hook, hosts, reload,
// credentials, drift) is judged as "no operation" (opNone), never as
// "any": stop_op then stops nothing that starts meanwhile.
func TestStopClassRecordWithoutOpID(t *testing.T) {
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{data: func(dir string) {
		os.MkdirAll(filepath.Join(dir, "ops"), 0700)
		os.WriteFile(filepath.Join(dir, "ops", "grafana.json"), []byte(`{"op":"hook","at":"2026-11-07T10:00:00Z","ok":false,"error":"hook failed"}`), 0600)
	}})
	rec := e.s.Hub.LastOp("grafana")
	if rec == nil || rec.OpID != "" || rec.Op != "hook" {
		t.Fatalf("seeded record = %+v", rec)
	}
	ctx := withCallMemo(context.Background(), &directory.Caller{User: "root", Admin: true})
	e.s.stopClass(ctx, json.RawMessage(`{"id":"grafana"}`))
	if got := memoOf(ctx).stopOpID; got != opNone {
		t.Errorf("classified op id = %q, want opNone", got)
	}
	exp, err := e.s.stopExpected(ctx, stopArgs{ID: "grafana"})
	if err != nil || exp != opNone {
		t.Fatalf("expected = %q %v, want opNone", exp, err)
	}
	// The Hub refuses it (the record isn't operation opNone's).
	if _, err := e.s.Hub.StopOpExpect("grafana", directory.Human("root"), exp); errStatus(err, 500) != 409 {
		t.Errorf("StopOpExpect(opNone) = %v, want 409", err)
	}
}
