package httpapi

import (
	"strings"
	"testing"
)

// Bypass badges (contract §11.7 "bypass"): each instance that skips part
// of Portcullis's protection shows a badge per entry of inst.bypass on
// its Apps card and its page head; a click opens the details (hosts,
// paths, TLS tier, why). The data is the Hub's (TestBypass* in
// internal/hub); these pin the words, the escaping and click-to-open.

const bypassFixtureJS = `const sync = {id: "firefox-sync", template: "grafana", state: "enabled", name: "Firefox Sync", hosts: {sync: "sync.example.org"},
  bypass: [{kind: "open_host", hosts: ["sync.example.org"], paths: [], tier: "public@file",
    reason: "No Portcullis sign-in: the app's auth method is custom, so nothing in front checks who is asking.",
    note: "Firefox cannot pass a sign-in <b>here</b>."}]};
const cloud = {id: "cloud", template: "grafana", state: "enabled", name: "Cloud", hosts: {cloud: "cloud.example.org"},
  bypass: [{kind: "public_paths", hosts: ["cloud.example.org"], paths: [{path: "/s", match: "prefix"}, {path: "/dist", match: "static"}], tier: "default", reason: "The public exception is on.", note: "Public share links"},
    {kind: "open_router", router: "cloud-login", hosts: ["cloud.example.org"], paths: [{path: "/login", match: "prefix"}], tier: "default", reason: "No sign-in on cloud-login."},
    {kind: "weak_tls", hosts: ["cloud.example.org"], paths: [], tier: "public@file", reason: "Its sign-in template asks for no certificate."},
    {kind: "open_host", hosts: ["vpn.example.org"], paths: [], tier: "public@file", vpn_only: true, reason: "x"},
    {kind: "public_paths", hosts: ["cloud.example.org"], paths: [{path: "/.well-known/", match: "prefix"}], tier: "default", reason: "y"}]};
const plain = {id: "grafana", template: "grafana", state: "enabled", name: "Grafana", hosts: {web: "grafana.example.org"}, bypass: []};
instancesCache = [sync, cloud, plain];`

// TestHubBypassBadgeWords: plain words per kind; no badge without bypass.
func TestHubBypassBadgeWords(t *testing.T) {
	got := appsJS(t, bypassFixtureJS, `[sync.bypass.map(bypassLabel), cloud.bypass.map(bypassLabel), bypassBadgesHtml(plain, "line"), bypassDetailsHtml(plain, "line"), instLineHtml(plain, false).includes("bypass")]`)
	l := got.([]any)
	if s := l[0].([]any); s[0] != "Open to the internet: whole host" {
		t.Errorf("sync label = %v", s)
	}
	want := []string{"Public paths: /s/… +1", "Open to the internet: /login/…", "No certificate asked: public TLS", "Open on the VPN: whole host", "Public path: /.well-known/…"}
	for i, w := range want {
		if c := l[1].([]any); c[i] != w {
			t.Errorf("cloud label %d = %v, want %q", i, c[i], w)
		}
	}
	if l[2] != "" || l[3] != "" || l[4] != false {
		t.Errorf("an instance without bypass shows badges: %v", l[2:])
	}
}

// TestHubBypassCardAndDetails: the Apps card carries one badge button per
// entry, all controlling one closed details panel with each host, path,
// tier and reason (escaped); a click opens it (aria-expanded, hidden off)
// and the next render keeps it open; a second click closes it.
func TestHubBypassCardAndDetails(t *testing.T) {
	setup := bypassFixtureJS + `
const els = {};
global.CSS = { escape: s => s };
global.document = {
  querySelectorAll: sel => { const k = sel.match(/"(.*)"/)[1]; return (els.btn[k] || []); },
  querySelector: sel => { const k = sel.match(/"(.*)"/)[1]; return els.box[k] || null; } };
function fakeEl() { return { hidden: true, attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } }; }
els.btn = { "line:firefox-sync": [fakeEl()] };
els.box = { "line:firefox-sync": fakeEl() };
const before = instLineHtml(sync, false), cloudRow = instLineHtml(cloud, false);
toggleBypass({ dataset: { bypassToggle: "line:firefox-sync" } });
const afterClick = [els.box["line:firefox-sync"].hidden, els.btn["line:firefox-sync"][0].attrs["aria-expanded"]];
const reopened = instLineHtml(sync, false), pageHead = bypassBadgesHtml(sync, "page") + bypassDetailsHtml(sync, "page");
toggleBypass({ dataset: { bypassToggle: "line:firefox-sync" } });
const closed = [els.box["line:firefox-sync"].hidden, instLineHtml(sync, false)];`
	got := appsJS(t, setup, `[before, cloudRow, afterClick, reopened, pageHead, closed]`)
	l := got.([]any)
	before, cloudRow, reopened, pageHead := l[0].(string), l[1].(string), l[3].(string), l[4].(string)
	for _, w := range []string{`data-bypass-toggle="line:firefox-sync"`, `aria-expanded="false"`, `aria-controls="bypass-line-firefox-sync"`,
		`id="bypass-line-firefox-sync" data-bypass-details="line:firefox-sync" hidden`, "Open to the internet: whole host",
		"<code>sync.example.org</code>", "the whole host", "public — no certificate asked", "auth method is custom",
		"Firefox cannot pass a sign-in &lt;b&gt;here&lt;/b&gt;.", `data-inst-toggle="firefox-sync"`} {
		if !strings.Contains(before, w) {
			t.Errorf("sync row lacks %q:\n%s", w, before)
		}
	}
	if strings.Contains(before, "<b>here") {
		t.Error("the note isn't escaped")
	}
	if n := strings.Count(cloudRow, `data-bypass-toggle="line:cloud"`); n != 5 {
		t.Errorf("cloud badges = %d, want 5", n)
	}
	for _, w := range []string{"<code>/s/…</code>, <code>/dist/… (static files)</code>", "<dt>Router</dt><dd><code>cloud-login</code>", "default — a certificate if the browser has one", "Public share links"} {
		if !strings.Contains(cloudRow, w) {
			t.Errorf("cloud details lack %q", w)
		}
	}
	if a := l[2].([]any); a[0] != false || a[1] != "true" {
		t.Errorf("after the click: hidden=%v aria-expanded=%v", a[0], a[1])
	}
	if !strings.Contains(reopened, `aria-expanded="true"`) || strings.Contains(reopened, `data-bypass-details="line:firefox-sync" hidden`) {
		t.Errorf("a re-render closed the details:\n%s", reopened)
	}
	// The page head's own panel is separate (closed).
	if !strings.Contains(pageHead, `data-bypass-toggle="page:firefox-sync"`) || !strings.Contains(pageHead, `data-bypass-details="page:firefox-sync" hidden`) {
		t.Errorf("page head = %s", pageHead)
	}
	if c := l[5].([]any); c[0] != true || !strings.Contains(c[1].(string), `data-bypass-details="line:firefox-sync" hidden`) {
		t.Errorf("second click didn't close: %v", c[0])
	}
}

// TestHubBypassWired: the delegated click listener opens the details
// before the instance page's own handler, and both the Apps card and
// the page head render the badges.
func TestHubBypassWired(t *testing.T) {
	page := hubIndex(t)
	i := strings.Index(page, "if ((el = t.closest('[data-bypass-toggle]'))) { toggleBypass(el); return; }")
	j := strings.Index(page, "if (t.closest('#instance-page')) { pageClick(t); return; }")
	if i < 0 || j < 0 || i > j {
		t.Errorf("the bypass click isn't wired before the page handler (%d, %d)", i, j)
	}
	if !strings.Contains(hubFunc(t, page, "instLineHtml"), "bypassBadgesHtml(i, 'line')") || !strings.Contains(hubFunc(t, page, "renderPageHead"), "bypassBadgesHtml(inst, 'page')") {
		t.Error("the badges aren't on the card and the page head")
	}
}
