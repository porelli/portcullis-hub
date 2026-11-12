package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Sign-in part 3 Task 8: the impersonation banner and the Stop page
// (web/impersonation.js), "Sign in as…" on a person's Sign-in tab
// (mysignin.js in person mode) and the Settings → Sign-in switch
// (signin.js). The browser behaviour is checked against the harness
// (task-8-report.md); these tests run the scripts under node over the
// fake DOM (skipped without node, required in CI).

// impDOM extends fakeDOM with what the banner, the Stop page and the
// dialog use: insertBefore / firstChild / removeChild, closest([attr]),
// getElementById, a dispatch that bubbles, a stub fetch (routes: url →
// {status, body}; calls: [method, url, body]), session storage, a
// location that records assign / reload, a clock (NOW) and timers of a
// second or more recorded instead of run.
const impDOM = fakeDOM + `
El.prototype.insertBefore = function (c, ref) { c.parent = this; const i = this.children.indexOf(ref); if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; };
Object.defineProperty(El.prototype, 'firstChild', { get() { return this.children[0] || null; } });
El.prototype.removeChild = function (c) { this.children = this.children.filter(x => x !== c); c.parent = null; return c; };
El.prototype.closest = function (sel) { const m = /^\[([a-z-]+)\]$/.exec(sel); for (let n = this; n instanceof El; n = n.parent) if (m && m[1] in n.attrs) return n; return null; };
El.prototype.contains = function () { return true; };
El.prototype.focus = function () {};
function dispatch(target, ev, extra) { for (let n = target; n; n = n.parent) for (const f of (n.ls && n.ls[ev]) || []) f(Object.assign({ target, key: '', preventDefault() {} }, extra || {})); }
function byAttr(a) { return document.body.all().find(e => a in e.attrs) || null; }
document.getElementById = id => document.body.all().find(e => e.attrs.id === id) || null;
document.readyState = 'complete';
document.addEventListener = () => {};
const routes = {}, calls = [];
global.fetch = async (url, opts) => {
  const method = (opts && opts.method) || 'GET';
  calls.push([method, url, opts && opts.body ? JSON.parse(opts.body) : null, opts && opts.headers ? opts.headers['Content-Type'] || '' : '']);
  const r = routes[method + ' ' + url] || { status: 404, body: { error: 'not found' } };
  return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body, text: async () => r.body == null ? '' : JSON.stringify(r.body) };
};
const store = {};
global.sessionStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; } };
const assigned = [];
let reloads = 0;
global.location = { protocol: 'https:', assign: u => assigned.push(u), reload: () => { reloads++; } };
let NOW = Date.parse('2026-11-12T14:06:30Z');
Date.now = () => NOW;
const realTimeout = setTimeout, timers = [];
global.setTimeout = (f, ms) => { if (ms >= 1000) { timers.push({ f, ms }); return timers.length; } return realTimeout(f, ms); };
const tick = () => new Promise(r => realTimeout(r, 5));
`

// impJS runs setup, then the web assets, then expr (JSON) over impDOM.
func impJS(t *testing.T, setup string, assets []string, expr string) any {
	t.Helper()
	script := impDOM + setup + "\n"
	for _, a := range assets {
		script += webAsset(t, a) + "\n"
	}
	script += `Promise.resolve((async () => (` + expr + `))()).then(v => process.stdout.write(JSON.stringify(v)), e => process.stdout.write(JSON.stringify({ thrown: String(e && e.stack || e) })));`
	var v any
	nodeJSON(t, script, &v)
	if m, ok := v.(map[string]any); ok && m["thrown"] != nil {
		t.Fatalf("node: %v", m["thrown"])
	}
	return v
}

// activeJSON is GET /api/me/impersonation's answer for alice signed in
// by root until 14:32 UTC (NOW is 14:06:30: 25 min 30 s left).
func activeJSON(reason string) string {
	return `{"active": {"person": "alice", "admin": "root", "reason": ` + jsonString(reason) + `, "until": "2026-11-12T14:32:00Z", "stop_url": "https://people.example.org/impersonation/stop"}}`
}

const bannerOut = `(async () => {
  await tick();
  const b = document.getElementById('pc-imp-banner');
  if (!b) return { none: true, calls };
  const btn = b.querySelector('[data-imp-act]');
  return { first: document.body.firstChild === b, role: b.getAttribute('role'), text: b.querySelector('[data-imp-text]').textContent,
    btn: btn && btn.textContent, elements: b.all().map(e => e.tagName), timers: timers.map(x => x.ms), calls };
})()`

// TestBannerText (D43): the fixed line, "26 min left" for 25 min 30 s,
// a Stop button, role alert, the body's first child; the countdown runs
// on the minute of what's left and reloads at 0.
func TestBannerText(t *testing.T) {
	out := impJS(t, `routes['GET /api/me/impersonation'] = { status: 200, body: `+activeJSON("checking quota")+` };
document.body.appendChild(document.createElement('main'));`, []string{"impersonation.js"}, `(async () => {
  const r = await `+bannerOut+`;
  // 30 s later (14:07:00): 25 min left; then past 14:32: reload.
  NOW += 30000;
  timers.shift().f();
  r.after = document.getElementById('pc-imp-banner').querySelector('[data-imp-text]').textContent;
  r.next = timers.map(x => x.ms);
  NOW = Date.parse('2026-11-12T14:32:00Z');
  timers.shift().f();
  r.reloads = reloads;
  return r;
})()`).(map[string]any)
	if out["text"] != "You are signed in as alice (by root) · reason “checking quota” · 26 min left" {
		t.Errorf("banner text = %q", out["text"])
	}
	if out["btn"] != "Stop" || out["role"] != "alert" || out["first"] != true {
		t.Errorf("banner: Stop %v, role %v, first child %v", out["btn"], out["role"], out["first"])
	}
	if ts, _ := json.Marshal(out["timers"]); string(ts) != "[30000]" {
		t.Errorf("first tick in %s ms, want 30000 (on the minute of what's left)", ts)
	}
	if out["after"] != "You are signed in as alice (by root) · reason “checking quota” · 25 min left" {
		t.Errorf("after a tick = %q", out["after"])
	}
	if ts, _ := json.Marshal(out["next"]); string(ts) != "[60000]" {
		t.Errorf("next tick in %s ms, want 60000", ts)
	}
	if out["reloads"] != float64(1) {
		t.Errorf("at 0: %v reloads, want 1", out["reloads"])
	}
	// One request, a GET with no-store semantics handled by the Hub.
	if c, _ := json.Marshal(out["calls"]); !strings.HasPrefix(string(c), `[["GET","/api/me/impersonation"`) {
		t.Errorf("calls = %s", c)
	}
}

// TestBannerEscapes: a hostile reason or name is text: no element is
// made from it.
func TestBannerEscapes(t *testing.T) {
	hostile := `<img src=x onerror=alert(1)>`
	out := impJS(t, `routes['GET /api/me/impersonation'] = { status: 200, body: {"active": {"person": "alice", "admin": "<b>root</b>", "reason": `+jsonString(hostile)+`, "until": "2026-11-12T14:32:00Z"}} };`,
		[]string{"impersonation.js"}, bannerOut).(map[string]any)
	if !strings.Contains(out["text"].(string), "reason “"+hostile+"”") || !strings.Contains(out["text"].(string), "(by <b>root</b>)") {
		t.Errorf("text = %q", out["text"])
	}
	for _, e := range out["elements"].([]any) {
		if e != "SPAN" && e != "BUTTON" {
			t.Errorf("an element %v was made inside the banner", e)
		}
	}
	// No innerHTML anywhere in the script.
	if strings.Contains(webAsset(t, "impersonation.js"), "innerHTML") {
		t.Error("impersonation.js uses innerHTML")
	}
}

// TestBannerStop: Stop POSTs /api/me/impersonation/stop (JSON, so CSRF
// passes) and then goes to the answer's sign_out; a 404 (already ended)
// reloads; a sign_out that isn't https isn't followed.
func TestBannerStop(t *testing.T) {
	signOut := "https://auth.example.org/oauth2/sign_out?rd=https%3A%2F%2Fexample.org%2F"
	run := func(status int, body string) map[string]any {
		return impJS(t, `routes['GET /api/me/impersonation'] = { status: 200, body: `+activeJSON("checking quota")+` };
routes['POST /api/me/impersonation/stop'] = { status: `+jsonNum(status)+`, body: `+body+` };`, []string{"impersonation.js"}, `(async () => {
  await tick();
  const b = document.getElementById('pc-imp-banner');
  const btn = b.querySelector('[data-imp-act]');
  dispatch(btn, 'click');
  dispatch(btn, 'click'); // a double click stops once
  await tick();
  return { calls, assigned, reloads, msg: b.querySelector('[data-imp-msg]').textContent };
})()`).(map[string]any)
	}
	ok := run(200, `{"sign_out": `+jsonString(signOut)+`}`)
	if c, _ := json.Marshal(ok["calls"]); string(c) != `[["GET","/api/me/impersonation",null,""],["POST","/api/me/impersonation/stop",{},"application/json"]]` {
		t.Errorf("calls = %s", c)
	}
	if a, _ := json.Marshal(ok["assigned"]); string(a) != `["`+signOut+`"]` {
		t.Errorf("went to %s, want sign_out", a)
	}
	if gone := run(404, `{"error":"not found"}`); gone["reloads"] != float64(1) || len(gone["assigned"].([]any)) != 0 {
		t.Errorf("404: reloads %v, assigned %v", gone["reloads"], gone["assigned"])
	}
	if bad := run(200, `{"sign_out": "javascript:alert(1)"}`); len(bad["assigned"].([]any)) != 0 || bad["reloads"] != float64(1) {
		t.Errorf("a non-https sign_out: assigned %v", bad["assigned"])
	}
	if refused := run(503, `{"error":"the Hub can't do that right now"}`); len(refused["assigned"].([]any)) != 0 || !strings.Contains(refused["msg"].(string), "the Hub can't do that right now") {
		t.Errorf("503: %v", refused)
	}
}

func jsonNum(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestNoBannerWhenNull: {"active": null}, or a failed question, shows
// nothing.
func TestNoBannerWhenNull(t *testing.T) {
	for _, r := range []string{`{ status: 200, body: {"active": null} }`, `{ status: 503, body: {"error": "x"} }`} {
		out := impJS(t, `routes['GET /api/me/impersonation'] = `+r+`;`, []string{"impersonation.js"}, bannerOut).(map[string]any)
		if out["none"] != true {
			t.Errorf("%s: a banner: %v", r, out)
		}
	}
}

// TestStopPage: /impersonation/stop shows "Stop signing in as alice"
// (which POSTs and goes to sign_out), or "Nothing to stop"; it is served
// unframeable with its CSP, and impersonation.js is first in <body> of
// every people-listener page.
func TestStopPage(t *testing.T) {
	page := `const main = document.createElement('main'); main.setAttribute('id', 'imp-stop'); main.setAttribute('data-domain', 'example.org');
const box = document.createElement('div'); box.setAttribute('data-imp-stop-body', ''); main.appendChild(box); document.body.appendChild(main);`
	stopOut := `(async () => {
  await tick();
  const box = byAttr('data-imp-stop-body');
  const btn = box.querySelector('button');
  const r = { text: box.textContent, btn: btn ? btn.textContent : '', links: box.querySelectorAll('a').map(a => a.getAttribute('href')) };
  if (btn && btn.getAttribute('data-imp-act') === 'stop-page') { dispatch(btn, 'click'); await tick(); }
  r.calls = calls.map(c => c[0] + ' ' + c[1]);
  r.assigned = assigned;
  return r;
})()`
	on := impJS(t, page+`routes['GET /api/me/impersonation'] = { status: 200, body: `+activeJSON("checking quota")+` };
routes['POST /api/me/impersonation/stop'] = { status: 200, body: {"sign_out": "https://auth.example.org/oauth2/sign_out?rd=https%3A%2F%2Fexample.org%2F"} };`, []string{"impersonation.js"}, stopOut).(map[string]any)
	if on["btn"] != "Stop signing in as alice" || !strings.Contains(on["text"].(string), "You are signed in as alice (by root)") {
		t.Errorf("impersonating: %v", on)
	}
	if c, _ := json.Marshal(on["calls"]); string(c) != `["GET /api/me/impersonation","POST /api/me/impersonation/stop"]` {
		t.Errorf("calls = %s (one question for the page and the banner)", c)
	}
	if a, _ := json.Marshal(on["assigned"]); !strings.Contains(string(a), "oauth2/sign_out") {
		t.Errorf("assigned = %s", a)
	}
	off := impJS(t, page+`routes['GET /api/me/impersonation'] = { status: 200, body: {"active": null} };`, []string{"impersonation.js"}, stopOut).(map[string]any)
	if !strings.HasPrefix(off["text"].(string), "Nothing to stop") || off["btn"] != "" {
		t.Errorf("not impersonating: %v", off)
	}
	if l, _ := json.Marshal(off["links"]); string(l) != `["https://example.org/"]` {
		t.Errorf("links = %s", l)
	}
	failed := impJS(t, page+`routes['GET /api/me/impersonation'] = { status: 503, body: {"error": "x"} };`, []string{"impersonation.js"}, stopOut).(map[string]any)
	if !strings.Contains(failed["text"].(string), "Couldn't check") || failed["btn"] != "Try again" {
		t.Errorf("failed: %v", failed)
	}

	// The page itself (Task 6 review M1).
	e := newImpEnv(t)
	r, b := doAs(t, e.people, "alice", "GET", "/impersonation/stop", "")
	csp := r.Header.Get("Content-Security-Policy")
	if r.StatusCode != http.StatusOK || r.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(csp, "frame-ancestors 'none'") ||
		!strings.Contains(csp, "form-action 'self'") || !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("stop page headers: %d XFO %q CSP %q", r.StatusCode, r.Header.Get("X-Frame-Options"), csp)
	}
	if !strings.Contains(b, `<script src="/static/impersonation.js"></script>`) || strings.Contains(b, "<script>") {
		t.Errorf("stop page: no impersonation.js, or an inline script (the CSP forbids it):\n%s", b)
	}
	if r, js := doAs(t, e.people, "alice", "GET", "/static/impersonation.js", ""); r.StatusCode != 200 || !strings.Contains(js, "pc-imp-banner") {
		t.Errorf("people /static/impersonation.js = %d", r.StatusCode)
	}
	// First in <body> of people.html and mysignin.html.
	for _, p := range []string{"people.html", "mysignin.html", "impersonation-stop.html"} {
		h := webAsset(t, p)
		i := strings.Index(h, "<body")
		j := strings.Index(h, `<script src="/static/impersonation.js"></script>`)
		if i < 0 || j < i || strings.Contains(h[i:j], "<script") || strings.Contains(h[i:j], "<div") || strings.Contains(h[i:j], "<main") {
			t.Errorf("%s: impersonation.js isn't first in <body>", p)
		}
	}
}

// personView is a PersonSignIn for alice seen by an administrator:
// can.impersonate, impersonate_refusal and impersonation (JSON).
func personView(can bool, refusal, running string) string {
	v := mySignInView("YubiKey 5C")
	c, _ := json.Marshal(can)
	return strings.TrimSuffix(v, "}") + `,"can":{"setup_link":true,"remove_passkeys":true,"revoke":true,"issue":true,"password":true,"impersonate":` + string(c) +
		`},"impersonate_refusal":` + jsonString(refusal) + `,"impersonation":` + running + `}`
}

const personSetup = `
let started = null;
window.PortcullisFreshAuth = { start: (fa, h) => { started = { fa, h }; h.busy(true); }, cancel: () => { started = null; } };
`

// personMount mounts mysignin.js in person mode for alice over view.
func personMount(view string) string {
	return `routes['GET /api/directory/users/alice/signin'] = { status: 200, body: ` + view + ` };
routes['GET /api/directory/users/alice/signin/history?limit=20'] = { status: 200, body: {entries: [], next: '', unknown: []} };`
}

// TestSignInAsDialog (D38, contract §9.7): an administrator with
// can.impersonate gets "Sign in as alice…"; the dialog's Continue is
// disabled for a reason under 3 characters (or two lines); Continue runs
// the fresh sign-in, POSTs {reason, code, code_verifier, nonce} and opens
// next in the top window. can false shows impersonate_refusal, no button.
func TestSignInAsDialog(t *testing.T) {
	next := "https://auth.example.org/realms/portcullis/portcullis-impersonate/start?id=0123456789abcdef0123456789abcdef"
	out := impJS(t, personSetup+personMount(personView(true, "", "null"))+`
routes['POST /api/directory/users/alice/impersonation'] = { status: 200, body: {"id": "0123456789abcdef0123456789abcdef", "next": `+jsonString(next)+`, "until": "2026-11-12T14:36:30Z"} };`,
		[]string{"mysignin.js"}, `(async () => {
  const S = window.PortcullisMySignIn;
  const root = document.createElement('div');
  await S.mount(root, { mode: 'person', user: 'alice' });
  await tick();
  const r = { html: root.innerHTML };
  const btn = { dataset: { msiAct: 'imp-open' }, disabled: false };
  btn.closest = () => btn;
  root.ls.click[0]({ target: btn });
  const dlg = document.body.querySelector('dialog');
  const input = dlg.querySelector('[data-msi-imp-reason]'), go = dlg.querySelector('[data-msi-imp="go"]');
  r.title = dlg.getAttribute('aria-label');
  r.disabledEmpty = go.disabled;
  input.value = 'ab'; dispatch(input, 'input');
  r.disabledShort = go.disabled;
  input.value = 'two\nlines'; dispatch(input, 'input');
  r.disabledTwoLines = go.disabled;
  input.value = '  checking quota  '; dispatch(input, 'input');
  r.disabledOK = go.disabled;
  dispatch(go, 'click');
  r.fa = started && started.fa;
  r.ctx = started && started.h.ctx;
  await started.h.proof({ code: 'CODE', code_verifier: 'VERIFIER', nonce: 'NONCE' });
  r.post = calls.filter(c => c[0] === 'POST');
  r.assigned = assigned;
  r.stored = JSON.parse(store['portcullis-imp-start'] || 'null');
  return r;
})()`).(map[string]any)
	html := out["html"].(string)
	if !strings.Contains(html, `data-msi-act="imp-open">Sign in as alice…</button>`) || !strings.Contains(html, "asks for your YubiKey now") {
		t.Errorf("no Sign in as alice… row:\n%s", html)
	}
	if out["title"] != "Sign in as alice" || out["disabledEmpty"] != true || out["disabledShort"] != true || out["disabledTwoLines"] != true || out["disabledOK"] != false {
		t.Errorf("dialog: %v", out)
	}
	if fa, _ := json.Marshal(out["fa"]); !strings.Contains(string(fa), `"client_id":"portcullis-fresh-auth"`) {
		t.Errorf("fresh sign-in with %s, want the view's fresh_auth", fa)
	}
	if p, _ := json.Marshal(out["post"]); string(p) != `[["POST","/api/directory/users/alice/impersonation",{"code":"CODE","code_verifier":"VERIFIER","nonce":"NONCE","reason":"checking quota"},"application/json"]]` {
		t.Errorf("POST = %s", p)
	}
	if a, _ := json.Marshal(out["assigned"]); string(a) != `["`+next+`"]` {
		t.Errorf("location.assign(%s), want next", a)
	}
	if s, _ := json.Marshal(out["stored"]); string(s) != `{"id":"0123456789abcdef0123456789abcdef","user":"alice"}` {
		t.Errorf("stored start = %s (only the user and the id)", s)
	}

	// can false: the refusal, escaped; no button. A holder's view (all
	// false / "" / null): nothing at all.
	refused := mySignInJS(t, `{admin: S.impersonationHtml(`+personView(false, "administrators <b>can't</b> be signed in as", "null")+`, {mode: 'person', user: 'alice', can: {impersonate: false}}),
  holder: S.impersonationHtml(`+personView(false, "", "null")+`, {mode: 'person', user: 'alice', can: {impersonate: false}}),
  self: S.impersonationHtml({impersonate_refusal: "x"}, {mode: 'self'})}`).(map[string]any)
	if a := refused["admin"].(string); !strings.Contains(a, "Signing in as alice isn't possible: administrators &lt;b&gt;can&#39;t&lt;/b&gt; be signed in as") || strings.Contains(a, "imp-open") {
		t.Errorf("refusal:\n%s", a)
	}
	if refused["holder"] != "" || refused["self"] != "" {
		t.Errorf("holder %q, self %q: want nothing", refused["holder"], refused["self"])
	}

	// A refused start: the Hub's text in the dialog, nothing opened.
	bad := impJS(t, personSetup+personMount(personView(true, "", "null"))+`
routes['POST /api/directory/users/alice/impersonation'] = { status: 403, body: {"error": "your sign-in can't be read: sign in again"} };`,
		[]string{"mysignin.js"}, `(async () => {
  const S = window.PortcullisMySignIn;
  const root = document.createElement('div');
  await S.mount(root, { mode: 'person', user: 'alice' });
  const btn = { dataset: { msiAct: 'imp-open' }, disabled: false };
  btn.closest = () => btn;
  root.ls.click[0]({ target: btn });
  const dlg = document.body.querySelector('dialog');
  const input = dlg.querySelector('[data-msi-imp-reason]');
  input.value = 'checking quota'; dispatch(input, 'input');
  dispatch(dlg.querySelector('[data-msi-imp="go"]'), 'click');
  await started.h.proof({ code: 'C', code_verifier: 'V', nonce: 'N' });
  return { status: dlg.querySelector('[data-msi-imp-status]').textContent, assigned, stored: store['portcullis-imp-start'] || '', goDisabled: dlg.querySelector('[data-msi-imp="go"]').disabled };
})()`).(map[string]any)
	if bad["status"] != "your sign-in can't be read: sign in again" || len(bad["assigned"].([]any)) != 0 || bad["stored"] != "" || bad["goDisabled"] != false {
		t.Errorf("refused start: %v", bad)
	}
}

// TestSignInAsRunningAndStartAgain: the running line (UTC times, the
// reason, the minutes left, Stop → POST …/impersonation/stop), and the
// tab's own start that is still listed as running when the admin comes
// back: "That start link was already used…" with Start again, which
// stops it and opens the dialog again (Task 2 review M5).
func TestSignInAsRunningAndStartAgain(t *testing.T) {
	running := `{"id": "0123456789abcdef0123456789abcdef", "admin": "root", "person": "alice", "reason": "checking <i>quota</i>", "started": "2026-11-12T14:02:00Z", "until": "2026-11-12T14:32:00Z", "ended": null, "how": ""}`
	line := mySignInJS(t, `S.impersonationHtml(`+personView(false, "root is signed in as alice right now", running)+`, {mode: 'person', user: 'alice', can: {}})`).(string)
	// The clock is real here: only the fixed parts.
	for _, w := range []string{"root is signed in as alice since 14:02 UTC · reason “checking &lt;i&gt;quota&lt;/i&gt;” · ", " min left (until 14:32 UTC)", `data-msi-act="imp-stop">Stop</button>`} {
		if !strings.Contains(line, w) {
			t.Errorf("running line lacks %q:\n%s", w, line)
		}
	}
	if strings.Contains(line, "imp-open") || strings.Contains(line, "isn't possible") {
		t.Errorf("running: also offers a start or the refusal:\n%s", line)
	}

	out := impJS(t, personSetup+`store['portcullis-imp-start'] = JSON.stringify({user: 'alice', id: '0123456789abcdef0123456789abcdef'});
let views = [`+personView(false, "root is signed in as alice right now", running)+`, `+personView(true, "", "null")+`];
routes['GET /api/directory/users/alice/signin/history?limit=20'] = { status: 200, body: {entries: [], next: '', unknown: []} };
routes['POST /api/directory/users/alice/impersonation/stop'] = { status: 204, body: null };
const realFetch = global.fetch;
global.fetch = (url, opts) => { if (url === '/api/directory/users/alice/signin') routes['GET ' + url] = { status: 200, body: views.length > 1 ? views.shift() : views[0] }; return realFetch(url, opts); };`,
		[]string{"mysignin.js"}, `(async () => {
  const S = window.PortcullisMySignIn;
  const root = document.createElement('div');
  await S.mount(root, { mode: 'person', user: 'alice' });
  const r = { html: root.innerHTML };
  const btn = { dataset: { msiAct: 'imp-again' }, disabled: false };
  btn.closest = () => btn;
  root.ls.click[0]({ target: btn });
  await tick(); await tick();
  r.calls = calls.map(c => c[0] + ' ' + c[1]);
  r.dialog = !!document.body.querySelector('dialog');
  r.after = root.innerHTML;
  r.stored = store['portcullis-imp-start'] || '';
  return r;
})()`).(map[string]any)
	html := out["html"].(string)
	if !strings.Contains(html, "That start link was already used or didn't work") || !strings.Contains(html, `data-msi-act="imp-again">Start again</button>`) {
		t.Errorf("no start-again notice:\n%s", html)
	}
	if c, _ := json.Marshal(out["calls"]); !strings.Contains(string(c), `"POST /api/directory/users/alice/impersonation/stop"`) {
		t.Errorf("Start again: calls %s", c)
	}
	if out["dialog"] != true || out["stored"] != "" || strings.Contains(out["after"].(string), "already used") {
		t.Errorf("after Start again: dialog %v, stored %q\n%s", out["dialog"], out["stored"], out["after"])
	}
}

// TestSettingsSwitch: Settings → Sign-in's "Signing in as someone else":
// the switch (on), the running list with Stop; switching off asks first,
// naming the running ones, then PUTs {allowed: false}; a No puts it back
// and sends nothing; switching on asks nothing.
func TestSettingsSwitch(t *testing.T) {
	iv := `{"allowed": true, "max_minutes": 30, "running": [{"id": "0123456789abcdef0123456789abcdef", "admin": "root", "person": "alice", "reason": "checking <i>quota</i>", "started": "2026-11-12T14:02:00Z", "until": "2026-11-12T14:32:00Z", "ended": null, "how": ""}], "recent": []}`
	out := signInJS(t, `(async () => {
  const IV = `+iv+`;
  const calls = [], asked = [];
  let answer = true;
  global.confirm = q => { asked.push(q); return answer; };
  window.apiPut = async (url, body) => { calls.push(['PUT', url, body]); return Object.assign({}, IV, { allowed: body.allowed, running: body.allowed ? IV.running : [] }); };
  window.apiCall = async (url, method, body) => { calls.push([method, url, body]); return {}; };
  window.apiGet = async url => { calls.push(['GET', url]); return IV; };
  const slots = {};
  const el = { innerHTML: '', querySelector: sel => slots[sel] || (slots[sel] = { textContent: '', innerHTML: '', outerHTML: '' }) };
  const T = S._test, st = Object.assign(T.state(el, {}), { imp: IV });
  const res = { html: S.impersonationHtml(IV), off: S.impersonationHtml(Object.assign({}, IV, { allowed: false, running: [] })) };
  const t = { checked: false, disabled: false, dataset: {} };
  answer = false;
  await T.toggleImpersonation(st, t, false);
  res.no = { calls: calls.length, checked: t.checked, asked: asked.slice() };
  answer = true;
  t.checked = false;
  await T.toggleImpersonation(st, t, false);
  res.yes = { calls: calls.slice(), imp: st.imp };
  calls.length = 0; asked.length = 0;
  await T.toggleImpersonation(st, { checked: true, disabled: false, dataset: {} }, true);
  res.on = { calls: calls.slice(), asked: asked.length };
  calls.length = 0; asked.length = 0;
  await T.stopImpersonation(st, { disabled: false, dataset: { user: 'alice', admin: 'root' } });
  res.stop = { calls: calls.map(c => c[0] + ' ' + c[1]), asked: asked.slice() };
  return res;
})()`).(map[string]any)
	html := out["html"].(string)
	for _, w := range []string{"Signing in as someone else", `data-signin-action="impersonation" checked`, "root is signed in as alice since 14:02 UTC · reason “checking &lt;i&gt;quota&lt;/i&gt;”",
		"(until 14:32 UTC)", `data-signin-action="imp-stop" data-user="alice" data-admin="root">Stop</button>`, "at most 30 minutes"} {
		if !strings.Contains(html, w) {
			t.Errorf("block lacks %q:\n%s", w, html)
		}
	}
	if off := out["off"].(string); strings.Contains(off, " checked") || !strings.Contains(off, "Nobody is signed in as someone else right now.") {
		t.Errorf("off:\n%s", off)
	}
	no := out["no"].(map[string]any)
	if no["calls"] != float64(0) || no["checked"] != true || !strings.Contains(no["asked"].([]any)[0].(string), "This ends the one running now: root as alice.") {
		t.Errorf("No: %v", no)
	}
	if c, _ := json.Marshal(out["yes"].(map[string]any)["calls"]); string(c) != `[["PUT","/api/signin/impersonation",{"allowed":false}]]` {
		t.Errorf("Yes: calls %s", c)
	}
	if c, _ := json.Marshal(out["on"]); string(c) != `{"asked":0,"calls":[["PUT","/api/signin/impersonation",{"allowed":true}]]}` {
		t.Errorf("on: %s", c)
	}
	if c, _ := json.Marshal(out["stop"]); string(c) != `{"asked":["Stop root signing in as alice? Their session as alice ends at once."],"calls":["POST /api/directory/users/alice/impersonation/stop","GET /api/impersonations"]}` {
		t.Errorf("stop: %s", c)
	}
	// Mounting reads the block on its own.
	if js := webAsset(t, "signin.js"); !strings.Contains(js, "window.apiGet('/api/impersonations')") {
		t.Error("signin.js doesn't read GET /api/impersonations")
	}
}

// TestImpersonationTimesUTC: the "hh:mm UTC" texts are UTC whatever the
// browser's zone (Task 5 ruling).
func TestImpersonationTimesUTC(t *testing.T) {
	for _, f := range []string{"mysignin.js", "signin.js"} {
		js := webAsset(t, f)
		if !strings.Contains(js, "d.getUTCHours()") || !strings.Contains(js, "' UTC'") {
			t.Errorf("%s: hh:mm isn't UTC", f)
		}
	}
}
