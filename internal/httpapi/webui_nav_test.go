package httpapi

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/web"
)

// Hub UX reorganisation Task 11: the top tabs (Apps · Doctor · Usage ·
// Access · Settings · Audit), the table-driven routes (ROUTES in
// index.html) and every hash the Hub itself emits landing on a route.

// TestTopTabsOrder: the top tabs, in order; no People ↗ tab (the site bar
// has People), no Marketplace or SSH access tab.
func TestTopTabsOrder(t *testing.T) {
	src := webAsset(t, "index.html")
	var names []string
	for _, m := range regexp.MustCompile(`class="tab[^"]*" data-tab="([a-z]+)"`).FindAllStringSubmatch(src, -1) {
		names = append(names, m[1])
	}
	if got := strings.Join(names, " "); got != "apps doctor usage access settings audit" {
		t.Errorf("top tabs = %q", got)
	}
	for _, gone := range []string{"data-people-link", `data-tab="marketplace"`, `data-tab="ssh"`, `id="tab-ssh"`} {
		if strings.Contains(src, gone) {
			t.Errorf("index.html still has %q", gone)
		}
	}
	for _, want := range []string{`id="tab-access"`, `id="access-root"`, `<script src="/static/access.js"></script>`, "PortcullisAccess.render("} {
		if !strings.Contains(src, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	if b, err := fs.ReadFile(web.FS, "access.js"); err != nil || len(b) < 1000 {
		t.Errorf("access.js not embedded: %v", err)
	}
}

// hubRoutes answers index.html's ROUTES block (source) and its regexes,
// compiled with Go's regexp (the table's regexes stay in the common
// subset: no lookarounds, no backreferences).
func hubRoutes(t *testing.T) (block string, res []*regexp.Regexp) {
	t.Helper()
	src := webAsset(t, "index.html")
	i := strings.Index(src, "    const ROUTES = [\n")
	j := strings.Index(src[max(i, 0):], "\n    ];\n")
	if i < 0 || j < 0 {
		t.Fatal("index.html lacks the ROUTES table")
	}
	block = src[i : i+j+len("\n    ];\n")]
	for _, m := range regexp.MustCompile(`(?m)^      \[/(.+?)/, `).FindAllStringSubmatch(block, -1) {
		re, err := regexp.Compile(strings.ReplaceAll(m[1], `\/`, `/`))
		if err != nil {
			t.Fatalf("route /%s/: %v", m[1], err)
		}
		res = append(res, re)
	}
	if len(res) < 10 {
		t.Fatalf("ROUTES has %d regexes", len(res))
	}
	return block, res
}

// hashChars: what a hash can hold; the first other character ends it
// (a closing quote, a parenthesis, markup).
var hashChars = regexp.MustCompile(`^[A-Za-z0-9_/?=&.%:-]*`)

// expandHash follows a string literal starting at s[0] (its quote) with
// its concatenations: each literal's text kept, each other operand
// becomes "x" ('#apps/' + id + '/mail' → #apps/x/mail).
func expandHash(s string) string {
	var out strings.Builder
	for len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		q := s[0]
		end := strings.IndexByte(s[1:], q)
		if end < 0 {
			break
		}
		out.WriteString(s[1 : 1+end])
		s = strings.TrimLeft(s[2+end:], " ")
		if !strings.HasPrefix(s, "+") {
			break
		}
		s = strings.TrimLeft(s[1:], " ")
		if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
			continue
		}
		// An operand: up to the next "+ '" / "+ \"" (or the end).
		out.WriteString("x")
		k := regexp.MustCompile(`\s\+\s*['"]`).FindStringIndex(s)
		if k == nil {
			break
		}
		s = strings.TrimLeft(s[k[0]:], " ")[1:]
		s = strings.TrimLeft(s, " ")
	}
	h := strings.TrimPrefix(out.String(), "#")
	return hashChars.FindString(h)
}

// emittedHashes: every hash the Hub page links to or sets, and every
// Hub-page hash the Hub's Go code builds (s.mcpScope(…).home + "#…"),
// by where it was found. The people page's own hashes (peopleHome(),
// PortcullisPeople.href, scripts served on the people listener) route
// there, not here.
func emittedHashes(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	goRe := regexp.MustCompile(`\.home \+ ("#)`)
	root := filepath.Join("..", "..", "internal")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(string(b), "\n") {
			for _, m := range goRe.FindAllStringSubmatchIndex(line, -1) {
				out[expandHash(line[m[2]:])] = p + ":" + itoa(n+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The Hub page's scripts: index.html and the scripts only it loads.
	files := []string{"index.html"}
	for _, m := range regexp.MustCompile(`<script src="/static/([a-z]+\.js)"></script>`).FindAllStringSubmatch(webAsset(t, "index.html"), -1) {
		if !peopleStatic[m[1]] {
			files = append(files, m[1])
		}
	}
	jsRe := regexp.MustCompile(`(?:href=\\?"|href = |href: |location\.hash = |replaceState\([^,]*, *[^,]*, *|pushState\([^,]*, *[^,]*, *|location\.replace\()(['"]?)#[a-z]`)
	for _, f := range files {
		for n, line := range strings.Split(webAsset(t, f), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") || strings.Contains(line, "PortcullisPeople.href(") {
				continue
			}
			for _, m := range jsRe.FindAllStringSubmatchIndex(line, -1) {
				var h string
				if m[3] > m[2] { // a quoted literal: '#…' (+ concatenations)
					h = expandHash(line[m[2]:])
				} else { // href="#…" inside a literal of markup
					h = hashChars.FindString(line[m[3]+1:])
					rest := line[m[3]+1+len(h):]
					if k := regexp.MustCompile(`^['"] \+ `).FindString(rest); k != "" {
						h += "x"
						tail := rest[len(k):]
						if l := regexp.MustCompile(`\s\+\s*['"]`).FindStringIndex(tail); l != nil {
							h += hashChars.FindString(tail[l[1]:])
						}
					}
				}
				out[h] = f + ":" + itoa(n+1)
			}
		}
	}
	return out
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestEmittedHashesRoute: each hash the Hub emits matches one of
// routeHash's ROUTES (the MCP hints, mail.js's #marketplace?filter=mail,
// the Usage links, #usage/<view>, the Access and Settings links), so no
// link the Hub hands out falls back to Apps.
func TestEmittedHashesRoute(t *testing.T) {
	_, routes := hubRoutes(t)
	hashes := emittedHashes(t)
	for _, want := range []string{"settings/ai?x", "settings/network?x", "settings/sources", "marketplace?filter=mail", "apps/x/mail", "usage/x", "doctor", "audit", "settings/ssh", "access/vpn"} {
		if _, ok := hashes[want]; !ok {
			t.Errorf("no emitted #%s found (the scan missed it, or the link moved): %v", want, hashes)
		}
	}
	for _, gone := range []string{"sources", "settings/domains?x", "ssh"} {
		if at, ok := hashes[gone]; ok {
			t.Errorf("#%s is still emitted (%s)", gone, at)
		}
	}
	for h, at := range hashes {
		// "usage/x", "access/x": the view or section is a variable (one of
		// the route's).
		probe := strings.NewReplacer("usage/x", "usage/storage", "access/x", "access/vpn").Replace(h)
		ok := false
		for _, re := range routes {
			if re.MatchString(probe) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("#%s (%s) matches no route", h, at)
		}
	}
}

// TestRouteHashNode: routeHash over ROUTES with showTab and the pages
// stubbed: #access/vpn opens Access at VPN devices; #ssh is no longer a
// route (no redirect before a release): Apps; #marketplace?filter=mail
// opens the Marketplace in Apps, mail servers only.
func TestRouteHashNode(t *testing.T) {
	block, _ := hubRoutes(t)
	src := webAsset(t, "index.html")
	script := `
const calls = [];
let usageView = 'apps', accessView = null, settingsView = null;
global.window = {};
global.location = { hash: '', pathname: '/', replace: h => calls.push(['replace', h]) };
global.history = { replaceState: (a, b, h) => calls.push(['replaceState', h]) };
global.document = { getElementById: () => null, querySelector: () => null };
const PortcullisPeople = { href: f => 'https://people.example.org/' + (f || '') };
function showTab(n) { calls.push(['showTab', n, n === 'access' ? accessView : n === 'settings' ? settingsView : null]); return true; }
function openInstancePage(id, tab, opt) { calls.push(['instance', id, tab, opt]); }
function openSettingsForm(kind, q) { calls.push(['form', kind, q.toString()]); }
function filterMarketplace(k) { calls.push(['filter', k]); }
function flash() {}
` + hubFunc(t, src, "peopleRedirect") + hubFunc(t, src, "oldAppLink") + hubFunc(t, src, "showMarketplace") + hubFunc(t, src, "showSettings") + block + hubFunc(t, src, "routeTo") + hubFunc(t, src, "routeHash") + `
const out = {};
function route(h) { calls.length = 0; location.hash = h; routeHash(); return JSON.parse(JSON.stringify(calls)); }
for (const h of ['#access/vpn', '#access', '#access/ssh/grants', '#access/signins?user=alice', '#ssh', '#sources', '#marketplace?filter=mail', '#usage/storage', '#settings/network?add=example.org', '#settings/ssh', '#bogus', '']) out[h] = route(h);
window.PortcullisMarketplace = { render: (root, o) => calls.push(['mkt', o]) };
out['mkt+'] = route('#marketplace?filter=mail');
out['mkt/'] = route('#marketplace/stalwart');
process.stdout.write(JSON.stringify(out));
`
	var got map[string]any
	if err := json.Unmarshal([]byte(nodeEval(t, script)), &got); err != nil {
		t.Fatal(err)
	}
	str := func(k string) string { b, _ := json.Marshal(got[k]); return string(b) }
	cases := map[string]string{
		"#access/vpn":                       `[["showTab","access",{"section":"vpn","sub":"","user":""}]]`,
		"#access":                           `[["showTab","access",{"section":"ssh","sub":"","user":""}]]`,
		"#access/ssh/grants":                `[["showTab","access",{"section":"ssh","sub":"grants","user":""}]]`,
		"#access/signins?user=alice":        `[["showTab","access",{"section":"signins","sub":"","user":"alice"}]]`,
		"#ssh":                              `[["showTab","apps",null]]`,
		"#sources":                          `[["showTab","apps",null]]`,
		"#marketplace?filter=mail":          `[["showTab","marketplace",null],["filter","mail"]]`,
		"#usage/storage":                    `[["showTab","usage",null]]`,
		"#settings/network?add=example.org": `[["form","network","add=example.org"]]`,
		"#settings/ssh":                     `[["showTab","settings",{"section":"ssh"}]]`,
		"#bogus":                            `[["showTab","apps",null]]`,
		"":                                  `[["showTab","apps",null]]`,
		"mkt+":                              `[["showTab","apps",null],["mkt",{"filter":"mail","open":""}]]`,
		"mkt/":                              `[["showTab","apps",null],["mkt",{"filter":"","open":"stalwart"}]]`,
	}
	for k, want := range cases {
		if g := str(k); g != want {
			t.Errorf("%q → %s, want %s", k, g, want)
		}
	}
	// The Marketplace (until it moves into Apps) and an instance page
	// keep the Apps tab highlighted.
	if !strings.Contains(src, "const top = name === 'instance' || name === 'marketplace' ? 'apps' : name;") {
		t.Error("showTab doesn't highlight Apps for the Marketplace")
	}
}
