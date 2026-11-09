package httpapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Apps & instances Task 6: Apps, the Marketplace and one page per
// instance. The browser behaviour is checked against the harness
// (task-6-report.md); these tests pin the routing of the old deep links,
// the status counts (contract §11.9 "Fine") and the page's rules.

// hubFunc answers the served Hub index's top-level function name.
func hubFunc(t *testing.T, page, name string) string {
	t.Helper()
	i := strings.Index(page, "    function "+name+"(")
	if i < 0 {
		i = strings.Index(page, "    async function "+name+"(")
	}
	j := strings.Index(page[max(i, 0):], "\n    }\n")
	if i < 0 || j < 0 {
		t.Fatalf("the hub index lacks function %s", name)
	}
	return page[i : i+j+len("\n    }\n")]
}

func hubIndex(t *testing.T) string {
	t.Helper()
	e := newPeopleEnv(t)
	_, b := doAs(t, e.hub, "root", "GET", "/", "")
	return b
}

// TestHubOldAppLinks: #app/<id>/settings[/<option>] and #app/<id>/ai
// route to the instance page; anything else isn't an old app link.
func TestHubOldAppLinks(t *testing.T) {
	fn := hubFunc(t, hubIndex(t), "oldAppLink")
	cases := map[string]any{
		"app/grafana/settings":             "#apps/grafana/settings",
		"app/grafana-team-a/settings/smtp": "#apps/grafana-team-a/settings/smtp",
		"app/secretapp/settings/api_key":   "#apps/secretapp/settings/api_key",
		"app/aiapp/ai":                     "#apps/aiapp/ai",
		"app/aiapp/logs":                   nil,
		"app/Bad/settings":                 nil,
		"apps/grafana":                     nil,
		"app/x/settings/a<b":               nil,
		"settings":                         nil,
	}
	keys := make([]string, 0, len(cases))
	for k := range cases {
		keys = append(keys, k)
	}
	b, _ := json.Marshal(keys)
	var got []any
	if err := json.Unmarshal([]byte(runNode(t, fn+"process.stdout.write(JSON.stringify("+string(b)+".map(oldAppLink)));\n")), &got); err != nil || len(got) != len(keys) {
		t.Fatalf("oldAppLink = %v (%v)", got, err)
	}
	for i, k := range keys {
		if got[i] != cases[k] {
			t.Errorf("#%s → %v, want %v", k, got[i], cases[k])
		}
	}
}

// TestHubStatusSummary: "n of m" by service (contract §11.9 "Fine"): a
// done job counts, a failed / running / pending / missing one doesn't; a
// service with no container (a "missing" row) is in m; two replicas of a
// service count once, fine only when both are; the jobs' word.
func TestHubStatusSummary(t *testing.T) {
	fn := hubFunc(t, hubIndex(t), "statusSummary")
	rows := `[
	  [{"service":"web","state":"running"},{"service":"db","state":"running"},{"service":"init","state":"exited","job":true,"job_state":"done"}],
	  [{"service":"web","state":"running"},{"service":"db","state":"running"},{"service":"init","state":"exited","job":true,"job_state":"failed"}],
	  [{"service":"web","state":"running"},{"service":"db","state":"exited"}],
	  [{"service":"web","state":"running"},{"service":"init","state":"created","job":true,"job_state":"pending"}],
	  [{"service":"init","state":"running","job":true,"job_state":"running"},{"service":"seed","state":"exited","job":true,"job_state":"done"}],
	  [],
	  [{"service":"web","state":"running"},{"service":"db","name":"","state":"missing","status":"no container"}],
	  [{"service":"web","state":"running"},{"service":"init","name":"","state":"missing","status":"no container","job":true,"job_state":"missing"}],
	  [{"service":"web","state":"running"},{"service":"web","state":"running"},{"service":"db","state":"running"}],
	  [{"service":"web","state":"running"},{"service":"web","state":"exited"},{"service":"db","state":"running"}]
	]`
	var got []map[string]any
	if err := json.Unmarshal([]byte(runNode(t, fn+"process.stdout.write(JSON.stringify("+rows+".map(statusSummary)));\n")), &got); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		n, m float64
		job  string
	}{{3, 3, "done"}, {2, 3, "failed"}, {1, 2, ""}, {1, 2, "pending"}, {1, 2, "running"}, {0, 0, ""},
		{1, 2, ""}, {1, 2, "missing"}, {2, 2, ""}, {1, 2, ""}}
	if len(got) != len(want) {
		t.Fatalf("summaries = %v", got)
	}
	for i, w := range want {
		if got[i]["n"] != w.n || got[i]["m"] != w.m || got[i]["job"] != w.job {
			t.Errorf("rows %d: %v, want %+v", i, got[i], w)
		}
	}
}

// appsJS runs the Apps rows' helpers (instStatus, instLineHtml,
// namesLine and what they call) from the served page with stub state,
// and answers expr (JSON).
func appsJS(t *testing.T, setup, expr string) any {
	t.Helper()
	page := hubIndex(t)
	var src strings.Builder
	src.WriteString(`let instancesCache = [], catalogCache = {grafana: {manifest: {name: "Grafana", instances: "multi"}}}, statusCache = {}, opSummaries = {}, opRunning = {}, dirCache = null, dirErr = null;
const PortcullisPeople = { groupLink: g => '<a class="group-link">' + escapeHtml(g) + '</a>' };
`)
	i := strings.Index(page, "    const JOB_WORDS = ")
	if i < 0 {
		t.Fatal("the hub index lacks JOB_WORDS")
	}
	src.WriteString(page[i : i+strings.Index(page[i:], "\n")+1])
	for _, fn := range []string{"escapeHtml", "statusSummary", "instStatus", "instActionsHtml", "opShowButton", "opCardText", "opWords", "memberCountHtml",
		"dirGroup", "instLineHtml", "instName", "appName", "namesLine"} {
		src.WriteString(hubFunc(t, page, fn))
	}
	i = strings.Index(page, "    const OP_WORDS = {")
	src.WriteString(page[i : i+strings.Index(page[i:], "\n    };\n")+len("\n    };\n")])
	var v any
	if err := json.Unmarshal([]byte(runNode(t, src.String()+setup+"\nprocess.stdout.write(JSON.stringify("+expr+"));\n")), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestHubNamesLine: first names (the display name's first word, else
// the username), sorted, "… +N" beyond the limit; markup stays text here
// (the caller escapes the line).
func TestHubNamesLine(t *testing.T) {
	got := appsJS(t, `dirCache = { users: [{username: "alice", display_name: "Alice Smith"}, {username: "bob", display_name: "  Bob  "}, {username: "carol", display_name: ""}, {username: "dave", display_name: "Dave"}] };`,
		`[namesLine(["bob", "alice", "carol"], 5), namesLine(["dave", "carol", "bob", "alice", "erin", "frank", "gus"], 3), namesLine([], 3)]`)
	want := []any{"Alice, Bob, carol", "Alice, Bob, carol, … +4", ""}
	if l, ok := got.([]any); !ok || len(l) != 3 || l[0] != want[0] || l[1] != want[1] || l[2] != want[2] {
		t.Errorf("namesLine = %v, want %v", got, want)
	}
}

// TestHubInstStatus: each state's dot and pill; a failed or missing
// setup job is red (dot stopped, pill bad) like its pill.
func TestHubInstStatus(t *testing.T) {
	got := appsJS(t, `statusCache = {
	  done: [{service: "web", state: "running"}, {service: "init", state: "exited", job: true, job_state: "done"}],
	  failed: [{service: "web", state: "running"}, {service: "init", state: "exited", job: true, job_state: "failed"}],
	  missing: [{service: "web", state: "running"}, {service: "init", name: "", state: "missing", status: "no container", job: true, job_state: "missing"}],
	  partial: [{service: "web", state: "running"}, {service: "db", name: "", state: "missing", status: "no container"}],
	  none: [] };
	opSummaries = { broken: {op: "enable", ok: false} };`,
		`["done", "failed", "missing", "partial", "none", "unpolled"].map(id => instStatus({id: id === "unpolled" ? "x" : id, state: "enabled"}))
		  .concat([{id: "c", state: "created"}, {id: "d", state: "disabled"}, {id: "broken", state: "error"}, {id: "e", state: "error", error: "template x is missing"},
		    {id: "f", state: "deleting"}, {id: "g", state: "restoring"}].map(instStatus))`)
	want := [][3]string{
		{"running", "running · 2 of 2 · setup job done", "ok"},
		{"stopped", "running · 1 of 2 · setup job failed", "bad"},
		{"stopped", "running · 1 of 2 · setup job never ran", "bad"},
		{"partial", "running · 1 of 2", "warn"},
		{"stopped", "not running · no containers", "bad"},
		{"", "enabled · checking…", "info"},
		{"", "not started yet", "info"},
		{"", "stopped", ""},
		{"stopped", "last enable failed", "bad"},
		{"stopped", "can't run: template x is missing", "bad"},
		{"partial", "delete not finished", "warn"},
		{"partial", "restore not finished", "warn"},
	}
	l, ok := got.([]any)
	if !ok || len(l) != len(want) {
		t.Fatalf("instStatus = %v", got)
	}
	for i, w := range want {
		m, _ := l[i].(map[string]any)
		if m["dot"] != w[0] || m["text"] != w[1] || m["cls"] != w[2] {
			t.Errorf("%d: %v, want dot %q text %q cls %q", i, m, w[0], w[1], w[2])
		}
	}
}

// TestHubInstLineEscapes: a hostile label, id, host or group name is
// text in an Apps row, never markup; two instances with one name show
// their ids.
func TestHubInstLineEscapes(t *testing.T) {
	got := appsJS(t, `const evil = {id: "x-1", template: "grafana", state: "disabled", name: "Grafana · <img src=x onerror=alert(1)>", hosts: {web: "<b>h</b>.example.org"}, access_group: "g\"><script>"};
	instancesCache = [evil];`,
		`[instLineHtml(evil, false), instLineHtml(evil, true)]`)
	l, ok := got.([]any)
	if !ok || len(l) != 2 {
		t.Fatalf("rows = %v", got)
	}
	row := l[0].(string)
	for _, bad := range []string{"<img", "<script", "<b>h</b>", `g"`} {
		if strings.Contains(row, bad) {
			t.Errorf("row carries %q: %s", bad, row)
		}
	}
	for _, want := range []string{"Grafana · &lt;img src=x onerror=alert(1)&gt;", "&lt;b&gt;h&lt;/b&gt;.example.org", "g&quot;&gt;&lt;script&gt;", `href="#apps/x-1"`, `data-inst-toggle="x-1"`} {
		if !strings.Contains(row, want) {
			t.Errorf("row lacks %q: %s", want, row)
		}
	}
	if strings.Contains(row, `<code class="muted">x-1</code>`) || !strings.Contains(l[1].(string), `<code class="muted">x-1</code>`) {
		t.Error("the id shows only for instances sharing a name")
	}
}

// TestHubAppsPageStatic: the top tabs (Apps · Marketplace · Audit log ·
// Doctor · Settings · People ↗); the card's detail panel, the instance
// dialog and the Template Sources tab are gone; the Marketplace carries
// the sources; the Apps / Marketplace / instance page code and markup
// use data-* attributes and delegated listeners, never inline handlers.
func TestHubAppsPageStatic(t *testing.T) {
	b := hubIndex(t)
	tabs := regexp.MustCompile(`<div class="tab[^"]*" data-tab="([a-z]+)"`).FindAllStringSubmatch(b, -1)
	var names []string
	for _, m := range tabs {
		names = append(names, m[1])
	}
	if strings.Join(names, ",") != "apps,marketplace,audit,doctor,settings" || !strings.Contains(b, `<a class="tab" data-people-link href="#">People &#8599;</a>`) ||
		!strings.Contains(b, "document.querySelector('[data-people-link]').href = PortcullisPeople.base;") {
		t.Errorf("top tabs = %v", names)
	}
	for _, gone := range []string{`class="app-detail"`, "toggleDetail(", "openInstance(", "showInstTab(", `data-tab="catalog"`, `data-tab="sources"`, `id="tab-sources"`,
		"data-dtab=", "instances-overview", "data-instances-of"} {
		if strings.Contains(b, gone) {
			t.Errorf("the hub index still has %q", gone)
		}
	}
	for _, want := range []string{`id="tab-apps"`, `id="tab-instance"`, `id="tab-marketplace"`, `id="mkt-sources"`, `data-src-remove="`, `data-src-sync`,
		`data-mkt-use="`, "'in use · ' + n + (n === 1 ? ' instance' : ' instances')", `data-apps-filter="' + escapeHtml(tid) + '">Show in Apps</button>`,
		`data-install="' + escapeHtml(tid) + '">Install…</button>`, "Manage on People &#8599;", "existing group", "'+ Add your own variable'",
		`const page = /^apps\/([a-z0-9-]+)(?:\/([a-z]+)(?:\/([A-Za-z0-9_.-]+))?)?$/.exec(t);`, "function openSettingAt(id, key) { navInstance(id, 'settings', key || ''); }",
		`<div class="drift" id="drift"></div>`, `<div class="drift" id="missing-groups"></div>`, `<script src="/static/settings.js"></script>`} {
		if !strings.Contains(b, strings.Trim(want, "'")) {
			t.Errorf("the hub index lacks %q", want)
		}
	}
	// The source (html/template drops the script's comments when serving).
	src := webAsset(t, "index.html")
	start := strings.Index(src, "    // ── Apps, Marketplace and the instance page (contract §11, §11.9) ──")
	end := strings.Index(src, "    // ── Sources ───")
	if start < 0 || end < start {
		t.Fatal("the Apps block isn't in the hub index")
	}
	inline := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	if inline.MatchString(src[start:end]) {
		t.Error("the Apps / instance page code generates inline event handlers")
	}
	// None anywhere in index.html (markup or generated).
	if m := inline.FindAllString(src, -1); len(m) > 0 {
		t.Errorf("index.html has inline event handlers: %q", m)
	}
	ms, me := strings.Index(src, `<div class="tab-content active" id="tab-apps">`), strings.Index(src, "<!-- Doctor Tab (web/doctor.js) -->")
	if ms < 0 || me < ms || inline.MatchString(src[ms:me]) {
		t.Error("the Apps / Marketplace markup has inline event handlers")
	}
	for _, fn := range []string{"loadExpert", "renderEnvRows", "loadLogs"} {
		if inline.MatchString(hubFunc(t, b, fn)) {
			t.Errorf("%s generates inline event handlers", fn)
		}
	}
}
