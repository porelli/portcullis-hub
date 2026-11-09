package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// TestOpHistoryRoutes (contract §11.7 "Op history"): ?op_id= answers that
// operation's record after newer ones replaced the instance's (404
// unknown, 400 malformed); without it the current record as before;
// GET /api/instances/ops summarises every instance's current record
// (admins only, Hub listener only).
func TestOpHistoryRoutes(t *testing.T) {
	e := newInstEnv(t)
	create := e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-a","label":"Test"}`)
	enable := e.runOp(t, "POST", "/api/templates/enable", `{"id":"grafana-a"}`)
	// The restart takes the instance's record after the ok enable.
	restart := e.runOp(t, "POST", "/api/templates/restart/grafana-a", ``)
	if !enable.OK || !restart.OK || enable.OpID == restart.OpID {
		t.Fatalf("enable %+v restart %+v", enable, restart)
	}
	var cur hub.OpRecord
	if code, b := e.do(t, "root", "GET", "/api/instances/grafana-a/op", ""); code != 200 || json.Unmarshal([]byte(b), &cur) != nil || cur.OpID != restart.OpID {
		t.Fatalf("current = %d %s", code, b)
	}
	for _, want := range []hub.OpRecord{create, enable, restart} {
		var rec hub.OpRecord
		code, b := e.do(t, "root", "GET", "/api/instances/grafana-a/op?op_id="+want.OpID, "")
		if code != 200 || json.Unmarshal([]byte(b), &rec) != nil || rec.OpID != want.OpID || rec.Op != want.Op || !rec.OK || rec.Running || len(rec.Steps) == 0 {
			t.Fatalf("%s by op id = %d %s", want.Op, code, b)
		}
	}
	for q, code := range map[string]int{
		"?op_id=0123456789abcdef":                404,
		"?op_id=XYZ":                             400,
		"?op_id=":                                400,
		"?op_id=" + strings.ToUpper(enable.OpID): 400,
		"?op_id=" + enable.OpID + "&op_id=" + enable.OpID: 400,
	} {
		if got, b := e.do(t, "root", "GET", "/api/instances/grafana-a/op"+q, ""); got != code {
			t.Errorf("GET op%s = %d %s, want %d", q, got, b, code)
		}
	}
	if got, b := e.do(t, "root", "GET", "/api/instances/nosuch/op?op_id="+enable.OpID, ""); got != 404 {
		t.Errorf("an unknown instance with grafana-a's op id = %d %s", got, b)
	}
	// Another real instance's op id is never answered for grafana-a.
	other := e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-b","label":"Test"}`)
	if got, b := e.do(t, "root", "GET", "/api/instances/grafana-a/op?op_id="+other.OpID, ""); got != 404 {
		t.Errorf("grafana-b's op id on grafana-a = %d %s", got, b)
	}
	if got, b := e.do(t, "root", "GET", "/api/instances/grafana-b/op?op_id="+enable.OpID, ""); got != 404 {
		t.Errorf("grafana-a's op id on grafana-b = %d %s", got, b)
	}
	if got, _ := e.do(t, "root", "GET", "/api/instances/grafana-b/op?op_id="+other.OpID, ""); got != 200 {
		t.Errorf("grafana-b's own op id = %d", got)
	}
	// The summary route.
	var sum map[string]hub.OpSummary
	code, b := e.do(t, "root", "GET", "/api/instances/ops", "")
	if code != 200 || json.Unmarshal([]byte(b), &sum) != nil {
		t.Fatalf("ops = %d %s", code, b)
	}
	if s := sum["grafana-b"]; s.Op != "create" || s.OpID != other.OpID {
		t.Fatalf("ops[grafana-b] = %+v", s)
	}
	if s := sum["grafana-a"]; s.Op != "restart" || s.OpID != restart.OpID || s.Running || !s.OK || s.At.IsZero() {
		t.Fatalf("ops[grafana-a] = %+v (%s)", s, b)
	}
	if strings.Contains(b, `"steps"`) || strings.Contains(b, `"_`) {
		t.Errorf("ops isn't a summary: %s", b)
	}
	for _, k := range []string{`"op":`, `"op_id":`, `"running":`, `"stopping":`, `"stoppable":`, `"ok":`, `"at":`} {
		if !strings.Contains(b, k) {
			t.Errorf("ops lacks %s: %s", k, b)
		}
	}
	if code, _ := e.do(t, "nobody", "GET", "/api/instances/ops", ""); code != 403 {
		t.Errorf("ops as a non-admin = %d", code)
	}
	if r, _ := doAs(t, e.ppl, "root", "GET", "/api/instances/ops", ""); r.StatusCode != 404 && r.StatusCode != 405 {
		t.Errorf("ops on the people listener = %d", r.StatusCode)
	}
}

// TestOpHistoryMCP: get_op / wait_for_op with op_id answer that
// operation's record — wait_for_op ends on its own outcome after a newer
// operation became the instance's —; a malformed op_id is 400, an
// unknown one 404; list_ops is the summary route's answer.
func TestOpHistoryMCP(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	if _, err := e.s.Hub.CreateInstanceAs(hub.CreateRequest{Template: "notes", ID: "x", Label: "Test"}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	start := func(tool string) OpStarted {
		t.Helper()
		txt, isErr, conf := e.tool(t, tool, map[string]any{"id": "x"})
		var op OpStarted
		if isErr || conf != "" || json.Unmarshal([]byte(txt), &op) != nil || op.OpID == "" || op.Poll != "/api/instances/x/op?op_id="+op.OpID {
			t.Fatalf("%s = %s %v %q", tool, txt, isErr, conf)
		}
		return op
	}
	type waited struct {
		Done   bool         `json:"done"`
		Record hub.OpRecord `json:"record"`
	}
	wait := func(opID string) waited {
		t.Helper()
		txt, isErr, _ := e.tool(t, "wait_for_op", map[string]any{"id": "x", "op_id": opID})
		var w waited
		if isErr || json.Unmarshal([]byte(txt), &w) != nil {
			t.Fatalf("wait_for_op %s = %s %v", opID, txt, isErr)
		}
		return w
	}
	enable := start("enable_instance")
	if w := wait(enable.OpID); !w.Done || !w.Record.OK || w.Record.OpID != enable.OpID {
		t.Fatalf("wait for the enable = %+v", w)
	}
	restart := start("restart_instance")
	if w := wait(restart.OpID); !w.Done || w.Record.Op != "restart" {
		t.Fatalf("wait for the restart = %+v", w)
	}
	// The restart is the instance's record now; the enable's own answers.
	if lo := e.s.Hub.LastOp("x"); lo == nil || lo.OpID != restart.OpID {
		t.Fatalf("last op = %+v", lo)
	}
	if w := wait(enable.OpID); !w.Done || w.Record.Op != "enable" || w.Record.OpID != enable.OpID || !w.Record.OK || len(w.Record.Steps) == 0 {
		t.Fatalf("wait for the enable after the restart = %+v", w)
	}
	txt, isErr, _ := e.tool(t, "get_op", map[string]any{"id": "x", "op_id": enable.OpID})
	var rec hub.OpRecord
	if isErr || json.Unmarshal([]byte(txt), &rec) != nil || rec.OpID != enable.OpID || rec.Op != "enable" {
		t.Fatalf("get_op by op id = %s %v", txt, isErr)
	}
	if txt, isErr, _ = e.tool(t, "get_op", map[string]any{"id": "x"}); isErr || !strings.Contains(txt, restart.OpID) {
		t.Fatalf("get_op = %s %v", txt, isErr)
	}
	for _, tool := range []string{"get_op", "wait_for_op"} {
		if txt, isErr, _ := e.tool(t, tool, map[string]any{"id": "x", "op_id": "XYZ"}); !isErr || !strings.HasPrefix(txt, "400: ") {
			t.Errorf("%s malformed = %s %v", tool, txt, isErr)
		}
		if txt, isErr, _ := e.tool(t, tool, map[string]any{"id": "x", "op_id": "0123456789abcdef"}); !isErr || !strings.HasPrefix(txt, "404: ") {
			t.Errorf("%s unknown = %s %v", tool, txt, isErr)
		}
	}
	txt, isErr, _ = e.tool(t, "list_ops", nil)
	var sum map[string]hub.OpSummary
	if isErr || json.Unmarshal([]byte(txt), &sum) != nil || sum["x"].OpID != restart.OpID || sum["x"].Op != "restart" {
		t.Fatalf("list_ops = %s %v", txt, isErr)
	}
}
