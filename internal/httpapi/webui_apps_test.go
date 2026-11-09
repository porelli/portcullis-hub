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

// TestHubStatusSummary: "n of m" counts a done job as fine, never a
// failed / running / pending one; the jobs' word.
func TestHubStatusSummary(t *testing.T) {
	fn := hubFunc(t, hubIndex(t), "statusSummary")
	rows := `[
	  [{"state":"running"},{"state":"running"},{"state":"exited","job":true,"job_state":"done"}],
	  [{"state":"running"},{"state":"running"},{"state":"exited","job":true,"job_state":"failed"}],
	  [{"state":"running"},{"state":"exited"}],
	  [{"state":"running"},{"state":"created","job":true,"job_state":"pending"}],
	  [{"state":"running","job":true,"job_state":"running"},{"state":"exited","job":true,"job_state":"done"}],
	  []
	]`
	var got []map[string]any
	if err := json.Unmarshal([]byte(runNode(t, fn+"process.stdout.write(JSON.stringify("+rows+".map(statusSummary)));\n")), &got); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		n, m float64
		job  string
	}{{3, 3, "done"}, {2, 3, "failed"}, {1, 2, ""}, {1, 2, "pending"}, {1, 2, "running"}, {0, 0, ""}}
	for i, w := range want {
		if got[i]["n"] != w.n || got[i]["m"] != w.m || got[i]["job"] != w.job {
			t.Errorf("rows %d: %v, want %+v", i, got[i], w)
		}
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
