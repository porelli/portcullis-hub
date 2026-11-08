package httpapi

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// People & groups Task 7: people and groups live on people.<domain>. The
// Hub page's PortcullisPeople (the people base URL and group links) and
// its peopleRedirect (the old #users… deep links) run under node against
// the served index (skipped when node isn't installed; CI has it). The
// harness checks the same in a browser.

// hubIndexScripts answers the served Hub index's PortcullisPeople block
// and peopleRedirect function.
func hubIndexScripts(t *testing.T, peopleURL string) (people, redirect string) {
	t.Helper()
	e := newPeopleEnv(t)
	e.s.PeopleURL = peopleURL
	_, b := doAs(t, e.hub, "root", "GET", "/", "")
	i := strings.Index(b, "      (function () {\n        const injected")
	j := strings.Index(b[max(i, 0):], "      })();\n")
	k := strings.Index(b, "    function peopleRedirect(t) {")
	l := strings.Index(b[max(k, 0):], "\n    }\n")
	if i < 0 || j < 0 || k < 0 || l < 0 {
		t.Fatal("the hub index lacks PortcullisPeople or peopleRedirect")
	}
	return b[i : i+j+len("      })();\n")], b[k : k+l+len("\n    }\n")]
}

func runNode(t *testing.T, script string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI for the people link tests")
		}
		t.Skip("node not installed")
	}
	cmd := exec.Command(node, "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	return string(out)
}

// peopleJS runs the block with location.host = host and answers what
// expr (JSON) gives.
func peopleJS(t *testing.T, peopleURL, host, expr string) any {
	t.Helper()
	ppl, redir := hubIndexScripts(t, peopleURL)
	script := "global.window = {};\nglobal.location = { host: " + jsonString(host) + " };\n" +
		"const tab = {};\nglobal.document = { getElementById: () => tab };\n" + ppl + redir +
		"const PortcullisPeople = window.PortcullisPeople;\nprocess.stdout.write(JSON.stringify(" + expr + "));\n"
	var v any
	if err := json.Unmarshal([]byte(runNode(t, script)), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestHubPeopleBase: https://people.<main domain>/ from the configured
// domain whatever the browser's host (never its port or another domain),
// the injected URL (the harness) when set; the Users & Groups tab links
// there.
func TestHubPeopleBase(t *testing.T) {
	for _, c := range []struct{ inject, host, want string }{
		{"", "hub.example.org", "https://people.example.org/"},
		{"", "hub.example.org:8443", "https://people.example.org/"},
		{"", "HUB.example.org", "https://people.example.org/"},
		{"", "hub.evil.example", "https://people.example.org/"},
		{"", "10.0.0.5:8080", "https://people.example.org/"},
		{"http://127.0.0.1:18889/", "127.0.0.1:18888", "http://127.0.0.1:18889/"},
	} {
		got := peopleJS(t, c.inject, c.host, "[PortcullisPeople.base, tab.href]")
		if l, ok := got.([]any); !ok || len(l) != 2 || l[0] != c.want || l[1] != c.want {
			t.Errorf("host %q inject %q: base, tab = %v, want %s", c.host, c.inject, got, c.want)
		}
	}
}

// TestHubPeopleRedirects: each old Hub deep link → its people page.
func TestHubPeopleRedirects(t *testing.T) {
	cases := map[string]any{
		"users":                "",
		"users/carol":          "#people/carol",
		"users/Carol":          "#people/Carol", // the people page resolves the case
		"users/carol?password": "#users/carol?password",
		"users/carol?invite":   "#users/carol?invite",
		"users/a%20b":          "#people/a%20b",
		"users/%E0":            "",
		"users?create":         "#invite",
		"users?create&username=erin&email=erin%40example.org&groups=a,b": "#invite?username=erin&email=erin%40example.org&groups=a,b",
		"groups":               "#groups",
		"groups/office_milan":  "#groups/office_milan",
		"people/carol":         "#people/carol",
		"settings":             nil,
		"app/grafana/settings": nil,
		"usersx":               nil,
		"audit":                nil,
	}
	keys := make([]string, 0, len(cases))
	for k := range cases {
		keys = append(keys, k)
	}
	b, _ := json.Marshal(keys)
	got := peopleJS(t, "", "hub.example.org", string(b)+".map(peopleRedirect)")
	l, ok := got.([]any)
	if !ok || len(l) != len(keys) {
		t.Fatalf("redirects = %v", got)
	}
	for i, k := range keys {
		if l[i] != cases[k] {
			t.Errorf("#%s → %v, want %v", k, l[i], cases[k])
		}
	}
}

// TestHubGroupLink: a group name links to its page, escaped, same tab —
// a new tab when asked (the settings panel's links always ask: an unsaved
// draft must survive following one).
func TestHubGroupLink(t *testing.T) {
	got := peopleJS(t, "", "hub.example.org", `[PortcullisPeople.groupLink("a<b>&\"c'"), PortcullisPeople.groupLink("office_milan", true), PortcullisPeople.groupLink("ops", false, true)]`)
	l, ok := got.([]any)
	if !ok || len(l) != 3 {
		t.Fatalf("links = %v", got)
	}
	if l[0] != `<a class="group-link" href="https://people.example.org/#groups/a%3Cb%3E%26%22c&#39;" title="Open a&lt;b&gt;&amp;&quot;c&#39;&#39;s page">a&lt;b&gt;&amp;&quot;c&#39;</a>` {
		t.Errorf("escaped link = %s", l[0])
	}
	if l[1] != `<a class="group-link" href="https://people.example.org/#groups/office_milan" title="Open office_milan&#39;s page"><code>office_milan</code></a>` {
		t.Errorf("code link = %s", l[1])
	}
	if strings.Contains(l[0].(string), "target=") {
		t.Error("group links open in the same tab")
	}
	if l[2] != `<a class="group-link" href="https://people.example.org/#groups/ops" target="_blank" rel="noopener" title="Open ops&#39;s page (new tab)">ops</a>` {
		t.Errorf("new-tab link = %s", l[2])
	}
	if js := webAsset(t, "settings.js"); !strings.Contains(js, "window.PortcullisPeople.groupLink(name, false, true)") {
		t.Error("settings.js: the settings panel's group links must open in a new tab")
	}
}

// TestPeoplePageDomain: people.html is served with the configured main
// domain injected (directory.js's links into the Hub:
// https://hub.<domain>/), whatever host the browser used; directory.js
// never derives it from location.host.
func TestPeoplePageDomain(t *testing.T) {
	e := newPeopleEnv(t)
	_, b := doAs(t, e.people, "root", "GET", "/", "")
	if !strings.Contains(b, `domain: "`+e.s.Hub.Domain()+`",`) || e.s.Hub.Domain() == "" {
		t.Errorf("people page lacks the injected domain %q", e.s.Hub.Domain())
	}
	if strings.Contains(b, "{{") {
		t.Error("people page left a template action unrendered")
	}
	js := webAsset(t, "directory.js")
	if strings.Contains(js, "location.host") || !strings.Contains(js, "'https://hub.' + String(options.domain || '') + '/'") {
		t.Error("directory.js: hubLink must build the Hub URL from options.domain, never location.host")
	}
	if strings.Contains(webAsset(t, "index.html"), "location.host") {
		t.Error("index.html: the people URL must come from the configured domain, never location.host")
	}
}
