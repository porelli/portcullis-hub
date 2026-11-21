package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/state"
)

func usageU64(v uint64) *uint64 { return &v }

// usageEnv is an instEnv on a fake runtime with instance grafana-a
// (label lbl) running web.1 and db.1, plus core's hub, sampled once.
func usageEnv(t *testing.T, lbl string) (*instEnv, *runtimetest.Fake) {
	t.Helper()
	rt := &runtimetest.Fake{InfoVal: runtime.Info{Verified: true, CPUs: 4, MemoryBytes: 8 << 30}}
	unit := func(id, project, svc string) runtime.Unit {
		return runtime.Unit{ID: id, Project: project, Service: svc, State: "running",
			Labels: map[string]string{docker.LabelProject: project, docker.LabelService: svc, docker.LabelNumber: "1"}}
	}
	rt.Units = []runtime.Unit{unit("web1", "portcullis-grafana-a", "web"), unit("db1", "portcullis-grafana-a", "db"), unit("hub1", "portcullis", "hub"),
		{ID: "other1", State: "running"}}
	now := time.Now()
	for _, id := range []string{"web1", "db1", "hub1"} {
		rt.SetStats(id, runtime.UnitStats{Read: now, CPUUsageNS: usageU64(1e9), MemUsage: usageU64(64 << 20), Pids: usageU64(5)})
	}
	rt.Infos = map[string]runtime.UnitInfo{"web1": {ID: "web1", Memory: 0}, "db1": {ID: "db1", Memory: 256 << 20}}
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		rt: rt,
		seed: func(st *state.AppState) {
			if st.Instances == nil {
				st.Instances = map[string]state.Instance{}
			}
			st.Instances["grafana-a"] = state.Instance{ID: "grafana-a", Template: "grafana", State: state.InstanceCreated,
				Hosts: map[string]string{"grafana": "grafana-a.example.org"}, Label: lbl}
		},
	})
	e.s.Hub.SweepUsage(context.Background())
	return e, rt
}

var usageRoutes = []route{
	{"GET", "/api/usage", ""},
	{"GET", "/api/usage/instances/grafana-a", ""},
	{"GET", "/api/usage/export.csv?view=apps", ""},
}

func TestUsageRoutesHubListenerOnly(t *testing.T) {
	e, _ := usageEnv(t, "Team A")
	checkAdminOnly(t, e, usageRoutes)
	for _, p := range e.s.peopleMux().patterns {
		if strings.Contains(p, "/api/usage") {
			t.Errorf("people listener registers %q", p)
		}
	}
}

func TestUsageOverviewJSON(t *testing.T) {
	e, _ := usageEnv(t, "Team A")
	resp, body := doAs(t, e.hub, "root", "GET", "/api/usage", "")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /api/usage = %d %q %s", resp.StatusCode, resp.Header.Get("Cache-Control"), body)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"sampled_at", "interval_s", "stale", "engine", "hosts", "apps", "core", "unknown_projects", "not_shown", "over_limit"} {
		if _, ok := v[k]; !ok {
			t.Errorf("no %q", k)
		}
	}
	if v["interval_s"] != 15.0 || v["not_shown"] != 1.0 || v["over_limit"] != 0.0 {
		t.Errorf("header = %v %v %v", v["interval_s"], v["not_shown"], v["over_limit"])
	}
	if eng := v["engine"].(map[string]any); eng["runtime"] != "docker" || eng["verified"] != true {
		t.Errorf("engine = %v", eng)
	}
	if host := v["hosts"].(map[string]any)["primary"].(map[string]any); host["cpus"] != 4.0 || host["name"] != "Primary" {
		t.Errorf("hosts.primary = %v", host)
	}
	if _, ok := v["host"]; ok {
		t.Error("the old host field is still there")
	}
	apps := v["apps"].([]any)
	if len(apps) != 1 {
		t.Fatalf("apps = %v", apps)
	}
	a := apps[0].(map[string]any)
	tot := a["totals"].(map[string]any)
	if tot["mem_bytes"] != float64(128<<20) || a["instance"] != "grafana-a" || a["name"] != "Grafana · Team A" || a["server"] != "primary" {
		t.Errorf("app = %v", a)
	}
	// Null stays null (first sample: no CPU rate); the key is there.
	if c, ok := tot["cpu_cores"]; !ok || c != nil {
		t.Errorf("cpu_cores = %v (present %v)", c, ok)
	}
	// Partly unlimited: web has no memory limit.
	if l, ok := tot["mem_limit_bytes"]; !ok || l != nil {
		t.Errorf("mem_limit_bytes = %v", l)
	}
}

func TestUsageInstance404(t *testing.T) {
	e, _ := usageEnv(t, "Team A")
	for _, p := range []string{"/api/usage/instances/nope", "/api/usage/instances/..%2Fx", "/api/usage/instances/x%00"} {
		code, body := e.do(t, "root", "GET", p, "")
		if code != 404 || (code == 404 && !strings.Contains(body, "app instance not found") && !strings.Contains(body, "404")) {
			t.Errorf("GET %s = %d %s", p, code, body)
		}
	}
	code, body := e.do(t, "root", "GET", "/api/usage/instances/grafana-a", "")
	if code != 200 || !strings.Contains(body, `"history"`) || !strings.Contains(body, `"web.1"`) {
		t.Errorf("instance = %d %s", code, body)
	}
}

var usageCSVNameRe = regexp.MustCompile(`^attachment; filename="portcullis-usage-apps-\d{8}T\d{6}Z\.csv"$`)

func TestUsageCSV(t *testing.T) {
	e, _ := usageEnv(t, "=HYPERLINK(x)")
	resp, body := doAs(t, e.hub, "root", "GET", "/api/usage/export.csv?view=apps", "")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/csv; charset=utf-8" || resp.Header.Get("Cache-Control") != "no-store" ||
		!usageCSVNameRe.MatchString(resp.Header.Get("Content-Disposition")) {
		t.Fatalf("csv = %d %v", resp.StatusCode, resp.Header)
	}
	recs, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(recs[0], ","); got != "instance,template,name,status,cpu_cores,mem_bytes,mem_limit_bytes,cpu_limit_cores,pids,pids_limit,net_rx_bps,net_tx_bps,blk_read_bps,blk_write_bps,partial,measured_at" {
		t.Errorf("header = %s", got)
	}
	var app, core []string
	for _, r := range recs[1:] {
		switch r[0] {
		case "grafana-a":
			app = r
		case "core":
			core = r
		}
	}
	if app == nil || core == nil {
		t.Fatalf("rows = %q", recs)
	}
	if app[2] != "'Grafana · =HYPERLINK(x)" && !strings.HasPrefix(app[2], "Grafana · ") {
		t.Errorf("name = %q", app[2])
	}
	if app[4] != "" || app[5] != fmt.Sprint(128<<20) {
		t.Errorf("cpu %q (want empty), mem %q", app[4], app[5])
	}
	resp, body = doAs(t, e.hub, "root", "GET", "/api/usage/export.csv?view=containers", "")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "instance,service,number,id12,state,cpu_cores,mem_bytes,mem_limit_bytes,cpu_limit_cores,pids,pids_limit,net_rx_bps,net_tx_bps,blk_read_bps,blk_write_bps,oom_killed,restarts,measured_at\n") {
		t.Errorf("containers = %d %s", resp.StatusCode, body)
	}
	if code, _ := e.do(t, "root", "GET", "/api/usage/export.csv?view=bogus", ""); code != 400 {
		t.Errorf("bogus view = %d", code)
	}
}

// A label starting with = becomes a formula-safe cell.
func TestUsageCSVFormulaCell(t *testing.T) {
	e, rt := usageEnv(t, "Team A")
	_ = rt
	u := e.s.Hub.UsageOverview("last")
	if len(u.UnknownProjects) != 0 {
		t.Fatalf("unknown = %+v", u.UnknownProjects)
	}
	rt.Lock()
	rt.Units = append(rt.Units, runtime.Unit{ID: "x1", Project: "portcullis-=cmd", Service: "=svc", State: "running",
		Labels: map[string]string{docker.LabelProject: "portcullis-=cmd", docker.LabelService: "=svc"}})
	rt.Unlock()
	rt.SetStats("x1", runtime.UnitStats{Read: time.Now()})
	e.s.Hub.SweepUsage(context.Background())
	_, body := doAs(t, e.hub, "root", "GET", "/api/usage/export.csv?view=containers", "")
	recs, _ := csv.NewReader(strings.NewReader(body)).ReadAll()
	found := false
	for _, r := range recs {
		if r[0] == "portcullis-=cmd" && r[1] == "'=svc" {
			found = true
		}
	}
	if !found {
		t.Errorf("no escaped row: %q", recs)
	}
}

// Review Focus 2: reads come from the cache only.
func TestUsageReadsNeverReachEngine(t *testing.T) {
	e, rt := usageEnv(t, "Team A")
	before := len(rt.Calls())
	e.s.registerMCPTools()
	tools := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		tools[tl.Name] = tl
	}
	caller := &directory.Caller{User: "root"}
	for range 100 {
		mustDo(t, e.hub, "root", "GET", "/api/usage", "", 200)
	}
	for range 50 {
		mustDo(t, e.hub, "root", "GET", "/api/usage/instances/grafana-a", "", 200)
	}
	for range 20 {
		mustDo(t, e.hub, "root", "GET", "/api/usage/export.csv?view=containers", "", 200)
	}
	for i := range 20 {
		name, args := "usage_overview", `{}`
		if i%2 == 1 {
			name, args = "usage_instance", `{"id":"grafana-a"}`
		}
		if _, err := tools[name].Run(context.Background(), caller, json.RawMessage(args)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if after := rt.Calls()[before:]; len(after) != 0 {
		t.Errorf("reads reached the engine: %q", after)
	}
}

var _ = http.StatusOK

func waitUsageIdle(t *testing.T, e *instEnv) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r := e.s.Hub.LastOp("_usage"); r == nil || !r.Running {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the measurement didn't end")
}

func TestUsageStorageRoutes(t *testing.T) {
	e, _ := usageEnv(t, "Team A")
	checkAdminOnly(t, e, []route{
		{"GET", "/api/usage/storage", ""}, {"POST", "/api/usage/storage/measure", "{}"},
		{"GET", "/api/usage/storage/op", ""}, {"POST", "/api/usage/storage/op/stop", "{}"},
	})
	if code, body := e.do(t, "root", "GET", "/api/usage/storage/op", ""); code != 404 {
		t.Errorf("op before any = %d %s", code, body)
	}
	if code, body := e.do(t, "root", "POST", "/api/usage/storage/op/stop", "{}"); code != 404 {
		t.Errorf("stop before any = %d %s", code, body)
	}
	if code, _ := e.do(t, "root", "POST", "/api/usage/storage/measure", `{"instance":"nope"}`); code != 404 {
		t.Errorf("unknown instance = %d", code)
	}
	if code, _ := e.do(t, "root", "POST", "/api/usage/storage/measure", `{"bogus":1}`); code != 400 {
		t.Errorf("unknown field = %d", code)
	}
	if code, _ := e.do(t, "root", "POST", "/api/usage/storage/measure", `{"instance":"`+strings.Repeat("x", 2000)+`"}`); code != 413 {
		t.Errorf("big body = %d", code)
	}
	code, body := e.do(t, "root", "POST", "/api/usage/storage/measure", "{}")
	var op map[string]string
	json.Unmarshal([]byte(body), &op)
	if code != 202 || op["op"] != "usage_measure" || op["instance"] != "_usage" || op["poll"] != "/api/usage/storage/op" || len(op["op_id"]) != 16 {
		t.Fatalf("measure = %d %s", code, body)
	}
	if code, _ := e.do(t, "root", "POST", "/api/usage/storage/op/stop", `{"op_id":"`+op["op_id"]+`"}`); code != 202 && code != 409 {
		t.Errorf("stop = %d", code)
	}
	waitUsageIdle(t, e)
	resp, body := doAs(t, e.hub, "root", "GET", "/api/usage/storage/op", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"op":"usage_measure"`) {
		t.Errorf("op = %d %s", resp.StatusCode, body)
	}
	resp, body = doAs(t, e.hub, "root", "GET", "/api/usage/storage", "")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("storage = %d", resp.StatusCode)
	}
	var v map[string]any
	json.Unmarshal([]byte(body), &v)
	for _, k := range []string{"measured_at", "running_op", "disks", "apps", "folders", "core", "metrics_scraped"} {
		if _, ok := v[k]; !ok {
			t.Errorf("storage lacks %q", k)
		}
	}
}

func TestUsageCSVStorage(t *testing.T) {
	e, _ := usageEnv(t, "Team A")
	mustDo(t, e.hub, "root", "POST", "/api/usage/storage/measure", "{}", 202)
	waitUsageIdle(t, e)
	resp, body := doAs(t, e.hub, "root", "GET", "/api/usage/export.csv?view=storage", "")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "owner,kind,target,alloc_bytes,apparent_bytes,partial,in_total,shared_with,measured_at\n") {
		t.Fatalf("storage csv = %d %s", resp.StatusCode, body)
	}
	recs, _ := csv.NewReader(strings.NewReader(body)).ReadAll()
	found := false
	for _, r := range recs[1:] {
		if r[1] == "hub_files" {
			found = true
			if r[3] != "" || r[4] != "" {
				t.Errorf("null sizes = %q", r)
			}
		}
	}
	if !found {
		t.Errorf("no hub_files row: %q", recs)
	}
}

func TestUsageWindowParam(t *testing.T) {
	e, _ := usageEnv(t, "Team A")
	for q, want := range map[string]string{"": "last", "?window=last": "last", "?window=1h": "1h"} {
		resp, body := doAs(t, e.hub, "root", "GET", "/api/usage"+q, "")
		var v map[string]any
		if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &v) != nil || v["window"] != want {
			t.Errorf("GET /api/usage%s = %d %s", q, resp.StatusCode, body)
		}
	}
	for _, q := range []string{"?window=5m", "?window=", "?window=1h&window=last", "?window=1h&window=1h", "?window=1H"} {
		resp, body := doAs(t, e.hub, "root", "GET", "/api/usage"+q, "")
		if resp.StatusCode != 400 || !strings.Contains(body, "window must be last or 1h") || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("GET /api/usage%s = %d %s", q, resp.StatusCode, body)
		}
	}
}
