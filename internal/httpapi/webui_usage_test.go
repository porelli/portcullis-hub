package httpapi

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/web"
)

func usageJS(t *testing.T) string {
	t.Helper()
	b, err := fs.ReadFile(web.FS, "usage.js")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// usageAllowedRe: what a string concatenation in usage.js may add — an
// escaper, a number formatter or an *Html helper (which escapes).
var usageAllowedRe = regexp.MustCompile(`^(esc|enc|fmtBytes|fmtCores|fmtRate|fmtPct|fmtNum|fmtAge|Number|[a-zA-Z]*Html)\b`)

// TestUsageJSEscapesAndDelegates: every concatenated value goes through
// esc() or a formatter; no inline handlers, no storage, no logging, no
// template-literal interpolation.
func TestUsageJSEscapesAndDelegates(t *testing.T) {
	js := usageJS(t)
	for i, line := range strings.Split(js, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, m := range regexp.MustCompile(`\+ ([a-z][\w$]*)`).FindAllStringSubmatch(line, -1) {
			if !usageAllowedRe.MatchString(m[1]) {
				t.Errorf("usage.js:%d concatenates %q without esc(): %s", i+1, m[1], strings.TrimSpace(line))
			}
		}
	}
	for _, banned := range []string{"onclick=", "localStorage", "sessionStorage", "console.log", "${"} {
		if strings.Contains(js, banned) {
			t.Errorf("usage.js contains %q", banned)
		}
	}
	if regexp.MustCompile(`\son[a-z]+="`).MatchString(js) {
		t.Error("usage.js has an inline handler attribute")
	}
	if !strings.Contains(js, "addEventListener('click'") {
		t.Error("usage.js has no delegated click listener")
	}
}

func TestUsageJSPollsOnlyWhenVisible(t *testing.T) {
	js := usageJS(t)
	for _, want := range []string{"document.visibilityState", "visibilitychange", "15000"} {
		if !strings.Contains(js, want) {
			t.Errorf("usage.js lacks %q", want)
		}
	}
	stop := regexp.MustCompile(`(?s)function stop\(\) \{.*?\n  \}`).FindString(js)
	if !strings.Contains(stop, "clearTimeout") && !strings.Contains(stop, "clearInterval") {
		t.Errorf("stop() doesn't clear the timer: %q", stop)
	}
}

func TestUsageJSBinaryUnits(t *testing.T) {
	js := usageJS(t)
	for _, u := range []string{"'KiB'", "'MiB'", "'GiB'", "'TiB'"} {
		if !strings.Contains(js, u) {
			t.Errorf("no %s", u)
		}
	}
	if strings.Contains(js, "'MB'") || strings.Contains(js, "'GB'") {
		t.Error("decimal units")
	}
	if !strings.Contains(js, "not measured") {
		t.Error("no \"not measured\"")
	}
	// Each formatter answers "not measured" for a missing value first.
	for _, fn := range []string{"fmtBytes", "fmtRate", "fmtCores", "fmtNum"} {
		body := regexp.MustCompile(`(?s)function ` + fn + `\([^)]*\) \{(.*?)\n  \}`).FindStringSubmatch(js)
		if body == nil || !strings.Contains(body[1], "isNum(") || !strings.Contains(body[1], "NOT_MEASURED") {
			t.Errorf("%s doesn't turn a null into not measured", fn)
		}
	}
}

func TestUsageSparklineNumbersOnly(t *testing.T) {
	js := usageJS(t)
	body := regexp.MustCompile(`(?s)function sparkHtml\([^)]*\) \{(.*?)\n  \}`).FindStringSubmatch(js)
	if body == nil {
		t.Fatal("no sparkHtml")
	}
	for _, m := range regexp.MustCompile(`\+ ([A-Za-z][\w$.]*)`).FindAllStringSubmatch(body[1], -1) {
		if !strings.HasPrefix(m[1], "Number") && !strings.HasPrefix(m[1], "ptsHtml.join") && !strings.HasPrefix(m[1], "lines.map") {
			t.Errorf("the sparkline interpolates %q", m[1])
		}
	}
	if !strings.Contains(body[1], ".toFixed(") || !strings.Contains(body[1], "<polyline") {
		t.Error("the sparkline isn't a polyline of fixed numbers")
	}
}

func TestUsageTabPlacement(t *testing.T) {
	b, _ := fs.ReadFile(web.FS, "index.html")
	h := string(b)
	d, u, s := strings.Index(h, `data-tab="doctor"`), strings.Index(h, `data-tab="usage"`), strings.Index(h, `data-tab="settings"`)
	if d < 0 || u < 0 || s < 0 || !(d < u && u < s) {
		t.Errorf("tab order: doctor %d, usage %d, settings %d", d, u, s)
	}
	if !strings.Contains(h, `['logs', 'Logs'], ['usage', 'Usage']`) {
		t.Error("PAGE_TABS lacks usage after logs")
	}
	for _, want := range []string{`<script src="/static/usage.js"></script>`, `id="tab-usage"`, `id="usage-root"`, `^usage(?:\/(apps|containers|storage))?$`, "PortcullisUsage.stop()"} {
		if !strings.Contains(h, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	g, _ := fs.ReadFile(web.FS, "usage.js")
	if len(g) == 0 {
		t.Error("usage.js isn't embedded")
	}
}

func TestUsageCSVLinks(t *testing.T) {
	js := usageJS(t)
	for _, want := range []string{"/api/usage/export.csv?view=apps", "/api/usage/export.csv?view=containers"} {
		if !strings.Contains(js, want) {
			t.Errorf("usage.js lacks %q", want)
		}
	}
}

func TestUsageStorageView(t *testing.T) {
	js := usageJS(t)
	for _, want := range []string{
		"DISK_WARN = 90", "DISK_BAD = 97", "Measure now", "data-usage-measure", `{ instance: instance }`,
		"shared, not in total", "Hub-managed files", "measured ' + fmtAge(", "172800", "usage-dim",
		"'≥ ' + figHtml", "stopped after 2 min", "if (v.metrics_scraped)", "History in Grafana ↗",
		"/api/usage/storage/measure", "'/api/usage/storage'", "openOpPanel('_usage'",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("usage.js lacks %q", want)
		}
	}
}

func TestOppStopUsageKey(t *testing.T) {
	b, _ := fs.ReadFile(web.FS, "index.html")
	h := string(b)
	for _, want := range []string{
		"id === OP_KEY_USAGE ? '/api/usage/storage/op/stop'", "if (id === OP_KEY_USAGE) return '/api/usage/storage/op';",
		"fetch(opStopURL(id),", "const url = opRecordURL(tr.id, tr.opId);",
		"usage_measure: { ing: 'Measuring storage', ed: 'measured', short: 'Measuring', stopped: 'stopped: the figures measured so far are kept' }",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	if strings.Contains(h, "fetch('/api/instances/' + encodeURIComponent(id) + '/op/stop'") {
		t.Error("the panel's Stop still posts the instance route for every key")
	}
}
