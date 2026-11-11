package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// Sign-in part 2 Task 8: the Sign-in page (web/mysignin.html +
// mysignin.js), the person's Sign-in tab, the Settings limits, the
// sign_in_help permission and the clear names. The browser behaviour is
// checked against the harness (task-8-report.md); these tests run the
// pages' helpers under node (skipped without node, required in CI) and pin
// what a browser check can't prove for every path.

// fakeDOM is the little DOM mysignin.js's download dialog needs under
// node: elements with attributes, children, text, listeners, a dialog's
// showModal / close, and querySelector by [attr] / [attr="v"].
const fakeDOM = `
const revoked = [], created = [];
class Node_ { constructor(t) { this.nodeType = 3; this._t = t; } get textContent() { return this._t; } set textContent(v) { this._t = String(v); } }
class El {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.attrs = {}; this.children = []; this.parent = null; this.ls = {}; this.open = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  hasAttribute(k) { return k in this.attrs; }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  remove() { if (this.parent) { this.parent.children = this.parent.children.filter(x => x !== this); this.parent = null; } }
  get textContent() { return this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this.children = v === '' ? [] : [new Node_(v)]; }
  addEventListener(ev, f) { (this.ls[ev] = this.ls[ev] || []).push(f); }
  fire(ev) { for (const f of this.ls[ev] || []) f({ target: this, preventDefault() {} }); }
  showModal() { this.open = true; }
  close() { if (!this.open) return; this.open = false; this.fire('close'); }
  all() { const out = []; const walk = n => { for (const c of n.children || []) if (c instanceof El) { out.push(c); walk(c); } }; walk(this); return out; }
  querySelectorAll(sel) {
    const m = /^\[([a-z-]+)(?:="([^"]*)")?\]$/.exec(sel);
    return this.all().filter(e => m ? (m[1] in e.attrs && (m[2] === undefined || e.attrs[m[1]] === m[2])) : e.tagName === sel.toUpperCase());
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
global.window = { addEventListener() {} };
global.location = { protocol: 'https:' };
global.document = { createElement: t => new El(t), createTextNode: t => new Node_(t), body: new El('body') };
global.navigator = {};
global.confirm = () => true;
URL.createObjectURL = b => { const u = 'blob:https://people.example.org/' + created.length; created.push({ u, b }); return u; };
URL.revokeObjectURL = u => { revoked.push(u); };
`

// mySignInJS runs mysignin.js over the fake DOM and answers expr (JSON).
func mySignInJS(t *testing.T, expr string) any {
	t.Helper()
	var v any
	nodeJSON(t, fakeDOM+webAsset(t, "mysignin.js")+`
const S = window.PortcullisMySignIn;
Promise.resolve((async () => (`+expr+`))()).then(v => process.stdout.write(JSON.stringify(v)), e => process.stdout.write(JSON.stringify({ thrown: String(e && e.stack || e) })));
`, &v)
	if m, ok := v.(map[string]any); ok && m["thrown"] != nil {
		t.Fatalf("node: %v", m["thrown"])
	}
	return v
}

// mySignInView is a MySignIn (JSON names) for alice: password off,
// a synced passkey, browser_cert on with one valid certificate, no
// device-bound passkey, two security keys (one label hostile), an
// expiring YubiKey certificate; three apps (met, not met, unknown).
func mySignInView(label string) string {
	return `{"user":"alice","methods":[
{"id":"password","label":"Password","on":false,"state":"off"},
{"id":"passkey_synced","label":"Passkey (phone / laptop, synced)","on":true,"state":"set","passkeys":[{"label":"iPhone","kind":"passkey_synced","created_at":"2026-11-02T09:12:00Z"}]},
{"id":"browser_cert","label":"Browser certificate","on":true,"state":"set"},
{"id":"passkey_device","label":"Device-bound passkey","on":true,"state":"none"},
{"id":"security_key","label":"Security key passkey (YubiKey touch)","on":true,"state":"set","passkeys":[{"label":` + jsonString(label) + `,"kind":"security_key","created_at":"2026-10-20T14:03:00Z"},{"label":"YubiKey 5 Nano","kind":"security_key","created_at":"2026-10-21T14:03:00Z"}]},
{"id":"yubikey_cert","label":"YubiKey certificate","on":true,"state":"set"}],
"certificates":[{"serial":"1a:2b:3c","kind":"browser","status":"valid","not_before":"2026-11-10T08:00:00Z","not_after":"2026-12-10T08:00:00Z"},
{"serial":"4f:2a","kind":"yubikey","status":"expiring","not_before":"2025-12-01T08:00:00Z","not_after":"` + "2099-12-01T08:00:00Z" + `"},
{"serial":"0b:0b","kind":"browser","status":"revoked","not_before":"2026-10-01T08:00:00Z","not_after":"2026-11-01T08:00:00Z"}],
"apps":[{"kind":"instance","id":"gitea","name":"Gitea","template":"standard","template_name":"Standard","score":{"tenths":25},"ok":true},
{"kind":"instance","id":"nc","name":"Nextcloud <i>family</i>","template":"family","template_name":"Family","score":{"tenths":25},"ok":false},
{"kind":"core","id":"people","name":"People","template":"strong","template_name":"Strong","score":{"tenths":35},"ok":null}],
"limits":{"limits":{"browser_cert_days":30,"browser_cert_max_active":3,"history_days":365},"ceiling_days":30,"effective":{"browser_cert_days":30,"browser_cert_max_active":3,"history_days":365}},
"active_browser_certs":1,"add_stronger":false,"account_url":"https://auth.example.org/realms/portcullis/account/account-security/signing-in",
"cert_fresh":["passkey_device","security_key","yubikey_cert"],"cert_fresh_refusal":"creating a certificate needs a passkey or YubiKey sign-in that people.example.org accepts",
"fresh_auth":{"authorize_url":"https://auth.example.org/realms/portcullis/protocol/openid-connect/auth","client_id":"portcullis-fresh-auth","redirect_uri":"https://people.example.org/signin"}}`
}

// TestMySignInPageRendersMockupRows: the rows in the view's (canonical)
// order, a switched-off method "off on this server" without actions, the
// actions the page offers, and the apps' ✓ / ✗ / ?.
func TestMySignInPageRendersMockupRows(t *testing.T) {
	v := mySignInView("YubiKey 5C")
	out := mySignInJS(t, `{rows: S.methodsHtml(`+v+`, {mode: 'self'}), apps: S.appsHtml(`+v+`),
  admin: S.methodsHtml(Object.assign(`+v+`, {user: 'portcullis-hub'}), {mode: 'self'})}`).(map[string]any)
	rows := out["rows"].(string)
	order := regexp.MustCompile(`data-msi-method="([a-z_]+)"`).FindAllStringSubmatch(rows, -1)
	var got []string
	for _, m := range order {
		got = append(got, m[1])
	}
	if strings.Join(got, ",") != "password,passkey_synced,browser_cert,passkey_device,security_key,yubikey_cert" {
		t.Errorf("rows = %v", got)
	}
	pw := rowOf(rows, "password")
	if !strings.Contains(pw, "off on this server") || strings.Contains(pw, "<button") {
		t.Errorf("the switched-off password row:\n%s", pw)
	}
	for id, want := range map[string][]string{
		"passkey_synced": {"iPhone · added", "+ Add", `href="https://auth.example.org/realms/portcullis/account/account-security/signing-in"`},
		"browser_cert":   {"a file you install in this browser / computer", "1 of 3 allowed", `data-msi-act="bc-create"`, `data-msi-act="revoke" data-serial="1a:2b:3c"`},
		"security_key":   {"YubiKey 5 Nano · added", `<span class="pd-pill ok">2</span>`},
		"yubikey_cert":   {"valid until", "expires in", `data-msi-act="yk-renew"`},
		"passkey_device": {"none yet"},
	} {
		r := rowOf(rows, id)
		for _, w := range want {
			if !strings.Contains(r, w) {
				t.Errorf("%s row lacks %q:\n%s", id, w, r)
			}
		}
	}
	// A revoked certificate shows revoked, without Revoke; the YubiKey
	// certificate can't be revoked from one's own page.
	if strings.Contains(rows, `data-serial="0b:0b"`) || !strings.Contains(rowOf(rows, "browser_cert"), "revoked") || strings.Contains(rowOf(rows, "yubikey_cert"), `data-msi-act="revoke"`) {
		t.Errorf("revoked / YubiKey revoke wrong:\n%s", rows)
	}
	// A server-managed account gets no certificate actions.
	if a := out["admin"].(string); strings.Contains(a, "bc-create") || strings.Contains(a, "yk-renew") || strings.Contains(a, `data-msi-act="revoke"`) || !strings.Contains(a, "managed from the server") {
		t.Errorf("portcullis-hub's page offers certificate actions:\n%s", a)
	}
	apps := out["apps"].(string)
	for _, w := range []string{"Apps and what they need", "<b>Gitea</b> Standard <span class=\"msi-ok\"", "✓", "✗", "?", "Nextcloud &lt;i&gt;family&lt;/i&gt;"} {
		if !strings.Contains(apps, w) {
			t.Errorf("apps lack %q:\n%s", w, apps)
		}
	}
}

// rowOf is the row of method id with its certificate list (up to the
// next row's panel).
func rowOf(h, id string) string {
	i := strings.Index(h, `data-msi-method="`+id+`"`)
	if i < 0 {
		return ""
	}
	j := strings.Index(h[i:], `data-msi-panel="`+id+`"`)
	if j < 0 {
		return h[i:]
	}
	return h[i : i+j]
}

// TestMySignInDownloadDialog: after a create, one download link (a blob:
// URL from the .p12 bytes), the password shown once next to it; a click
// revokes that URL right after; closing drops the node, the password and
// every URL. Nothing is put in localStorage / sessionStorage.
func TestMySignInDownloadDialog(t *testing.T) {
	out := mySignInJS(t, `(async () => {
  const d = S.openDownload({p12: btoa('PKCS12-BYTES'), password: 'ABCDE-FGHJK-MNPQR-STVWX', filename: 'alice-browser-certificate-20261111.p12',
    certificate: {serial: '1a', kind: 'browser', status: 'valid', not_after: '2026-12-10T08:00:00Z'}});
  const dlg = document.body.querySelector('dialog');
  const links = dlg.querySelectorAll('[data-msi-dl]');
  const first = links[0].getAttribute('href');
  const res = {open: dlg.open, links: links.length, href: first, download: links[0].getAttribute('download'),
    pw: dlg.querySelector('[data-msi-pw]').textContent, text: dlg.textContent, bytes: await created[0].b.text()};
  links[0].fire('click');
  await new Promise(r => setTimeout(r, 5));
  res.revokedAfterClick = revoked.includes(first);
  res.rearmed = links[0].getAttribute('href');
  dlg.querySelector('[data-msi-dlg="done"]').fire('click');
  res.closed = !dlg.open && document.body.children.length === 0;
  res.pwAfter = dlg.querySelector('[data-msi-pw]').textContent;
  res.hrefAfter = links[0].getAttribute('href');
  res.allRevoked = created.every(c => revoked.includes(c.u));
  return res;
})()`).(map[string]any)
	if out["open"] != true || out["links"] != float64(1) || !strings.HasPrefix(out["href"].(string), "blob:") || out["download"] != "alice-browser-certificate-20261111.p12" || out["bytes"] != "PKCS12-BYTES" {
		t.Errorf("dialog = %v", out)
	}
	if out["pw"] != "ABCDE-FGHJK-MNPQR-STVWX" || strings.Count(out["text"].(string), "ABCDE-FGHJK-MNPQR-STVWX") != 1 || !strings.Contains(out["text"].(string), "This password is shown only now.") || !strings.Contains(out["text"].(string), "Copy") {
		t.Errorf("password shown wrong: %v", out)
	}
	if out["revokedAfterClick"] != true || out["rearmed"] == out["href"] {
		t.Errorf("the URL wasn't revoked after the click: %v", out)
	}
	if out["closed"] != true || out["pwAfter"] != "" || out["hrefAfter"] != nil || out["allRevoked"] != true {
		t.Errorf("closing left something: %v", out)
	}
	js := webAsset(t, "mysignin.js")
	for _, bad := range []string{"localStorage", "sessionStorage.setItem", "location.hash =", "history.pushState"} {
		if strings.Contains(js, bad) {
			t.Errorf("mysignin.js uses %s", bad)
		}
	}
	if regexp.MustCompile(`\son[a-z]+=`).MatchString(js) {
		t.Error("mysignin.js generates inline event handlers")
	}
}

// TestMySignInEscapes: a passkey label, an app name, certificate fields
// and every history field are text, never markup; the history's detail
// ("Setup link used") and the unknown sources are shown.
func TestMySignInEscapes(t *testing.T) {
	out := mySignInJS(t, `{rows: S.methodsHtml(`+mySignInView(hostile)+`, {mode: 'self'}),
  person: S.methodsHtml(`+mySignInView(hostile)+`, {mode: 'person', user: '<b>x</b>', can: {revoke: true, setup_link: true}}),
  hist: S.historyHtml([
    {time: '2026-11-10T08:14:02Z', kind: 'sign_in', methods: ['security_key'], app: '', ip: '203.0.113.7', browser: `+jsonString(hostile)+`, by: '', reason: '', detail: ''},
    {time: '2026-11-10T08:10:00Z', kind: 'sign_in', methods: [], app: '', ip: '', browser: '', by: '', reason: '', detail: 'Setup link used'},
    {time: '2026-11-09T08:10:00Z', kind: 'failed', methods: ['password'], app: '', ip: '<i>ip</i>', browser: '', by: '', reason: `+jsonString(hostile)+`, detail: ''},
    {time: '2026-11-09T07:10:00Z', kind: 'opened', methods: [], app: `+jsonString(hostile)+`, ip: '', browser: '', by: '', reason: '', detail: ''},
    {time: '2026-11-08T07:10:00Z', kind: 'help', methods: [], app: '', ip: '', browser: '', by: '<b>root</b>', reason: '', detail: `+jsonString(hostile)+`}]),
  unknown: S.unknownHtml(['keycloak', '<x>'])}`).(map[string]any)
	for k, h := range out {
		s := h.(string)
		if strings.Contains(s, "<img") || strings.Contains(s, "<i>") || strings.Contains(s, "<b>root") || strings.Contains(s, "<b>x") || strings.Contains(s, "<x>") {
			t.Errorf("%s renders markup:\n%s", k, s)
		}
	}
	if !strings.Contains(out["rows"].(string), "&lt;img src=x onerror=alert(1)&gt; · added") {
		t.Errorf("the passkey label isn't shown as text:\n%s", out["rows"])
	}
	hist := out["hist"].(string)
	for _, w := range []string{"Signed in · security key", "&lt;img src=x onerror=alert(1)&gt; · 203.0.113.7", "Signed in · Setup link used", "Sign-in failed · password: &lt;img",
		"Opened &lt;img", "Help from &lt;b&gt;root&lt;/b&gt; · &lt;img"} {
		if !strings.Contains(hist, w) {
			t.Errorf("history lacks %q:\n%s", w, hist)
		}
	}
	if u := out["unknown"].(string); !strings.Contains(u, "sign-ins and failed sign-ins") || !strings.Contains(u, "&lt;x&gt;") {
		t.Errorf("unknown line = %s", u)
	}
}

// TestMySignInLoadsCallbackFirst: GET /signin answers mysignin.html with
// freshauth-callback.js as the first script in <head>, then the page's
// scripts and the shared navigation from the configured domain.
func TestMySignInLoadsCallbackFirst(t *testing.T) {
	e := newPeopleEnv(t)
	r, b := doAs(t, e.people, "bob", "GET", "/signin", "")
	if r.StatusCode != 200 || r.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("/signin = %d", r.StatusCode)
	}
	head := b[:max(strings.Index(b, "</head>"), 0)]
	scripts := regexp.MustCompile(`<script[^>]*>`).FindAllString(head, -1)
	if len(scripts) == 0 || scripts[0] != `<script src="/static/freshauth-callback.js">` {
		t.Errorf("head scripts = %v", scripts)
	}
	for _, w := range []string{`src="/static/freshauth.js"`, `src="/static/mysignin.js"`, `PortcullisMySignIn.mount(`, `domain: "example.org"`, "current: 'signin'"} {
		if !strings.Contains(b, w) {
			t.Errorf("/signin lacks %q", w)
		}
	}
	if r, _ := doAs(t, e.hub, "root", "GET", "/signin", ""); r.StatusCode != 404 {
		t.Errorf("hub /signin = %d, want 404", r.StatusCode)
	}
}

// TestPersonSignInTabActions: a person's tab offers exactly what `can`
// allows: a holder (revoke, setup link, remove passkeys) gets Revoke on
// every certificate that isn't revoked, never Reset password or Issue;
// can {revoke} alone gives Revoke buttons only; an administrator's can
// gives every action, with directory.js's own data-act buttons.
func TestPersonSignInTabActions(t *testing.T) {
	v := mySignInView("YubiKey 5C")
	out := mySignInJS(t, `{revoke: S.methodsHtml(`+v+`, {mode: 'person', user: 'alice', can: {revoke: true}}),
  holder: S.methodsHtml(`+v+`, {mode: 'person', user: 'alice', can: {setup_link: true, remove_passkeys: true, revoke: true, issue: false, password: false}}),
  admin: S.methodsHtml(`+v+`, {mode: 'person', user: 'alice', passwordHint: 'Password… sets their LLDAP password.', can: {setup_link: true, remove_passkeys: true, revoke: true, issue: true, password: true}}),
  none: S.methodsHtml(`+v+`, {mode: 'person', user: 'alice', can: {}})}`).(map[string]any)
	buttons := func(h string) []string {
		var l []string
		for _, m := range regexp.MustCompile(`<(?:button|a)[^>]*>([^<]*)</(?:button|a)>`).FindAllStringSubmatch(h, -1) {
			l = append(l, m[1])
		}
		return l
	}
	if b := buttons(out["revoke"].(string)); strings.Join(b, ",") != "Revoke,Revoke" {
		t.Errorf("can {revoke}: buttons %v, want Revoke on the two live certificates", b)
	}
	holder := out["holder"].(string)
	if b := buttons(holder); strings.Join(b, ",") != "Revoke,Revoke,Send setup link,Remove all passkeys" {
		t.Errorf("holder buttons = %v", b)
	}
	if strings.Contains(holder, "Reset password") || strings.Contains(holder, `data-act="password"`) || strings.Contains(holder, "Issue") || strings.Contains(holder, "+ Add") || strings.Contains(holder, "bc-create") {
		t.Errorf("a holder is offered more:\n%s", holder)
	}
	admin := out["admin"].(string)
	for _, w := range []string{`data-act="password" data-user="alice">Reset password`, `data-msi-act="yk-issue"`, `data-act="invite" data-user="alice">Send setup link`,
		`data-act="reset-passkeys" data-user="alice">Remove all passkeys`, `data-pw-hint>Password… sets their LLDAP password.`} {
		if !strings.Contains(admin, w) {
			t.Errorf("admin tab lacks %q:\n%s", w, admin)
		}
	}
	if b := buttons(out["none"].(string)); len(b) != 0 {
		t.Errorf("can {} offers %v", b)
	}
	// directory.js mounts the tab for administrators and holders only.
	js := webAsset(t, "directory.js")
	for _, w := range []string{"window.PortcullisMySignIn.mount(sb, {\n        mode: 'person', user: who,", "perms().includes('sign_in_help') && !u.self && !u.admin && !u.protected"} {
		if !strings.Contains(js, w) {
			t.Errorf("directory.js lacks %q", w)
		}
	}
}

// TestPermissionsTableListsSignInHelp: Setup → Permissions lists
// sign_in_help with its words, after edit_details, invite and remove.
func TestPermissionsTableListsSignInHelp(t *testing.T) {
	js := webAsset(t, "directory.js")
	i := strings.Index(js, "  const PERMS = [")
	j := strings.Index(js[max(i, 0):], "\n  ];\n")
	if i < 0 || j < 0 {
		t.Fatal("directory.js lacks PERMS")
	}
	var perms [][]string
	nodeJSON(t, js[i:i+j+len("\n  ];\n")]+"process.stdout.write(JSON.stringify(PERMS));", &perms)
	var ids []string
	for _, p := range perms {
		ids = append(ids, p[0])
	}
	if strings.Join(ids, ",") != "edit_details,invite,remove,sign_in_help" {
		t.Errorf("permissions = %v", ids)
	}
	last := perms[len(perms)-1]
	if last[1]+" ("+last[2]+")" != "Help with sign-in (setup link, remove passkeys, revoke certificates)" {
		t.Errorf("sign_in_help = %v", last)
	}
}

// TestSettingsLimitsForm: Settings → Sign-in shows the three limits with
// the ceiling, the stored-above-the-ceiling warning, and refuses
// out-of-range values client-side with the server's bounds.
func TestSettingsLimitsForm(t *testing.T) {
	v := `{methods: [], templates: [], core: {}, people_total: 0, limits: {browser_cert_days: 45, browser_cert_max_active: 3, history_days: 365}, ceiling_days: 30,
  effective: {browser_cert_days: 30, browser_cert_max_active: 3, history_days: 365}, warning: "The lifetime is <b>45</b> days"}`
	out := signInJS(t, `{html: S.render(`+v+`), ok: S.limitsProblem({browser_cert_days: '30', browser_cert_max_active: '20', history_days: '30'}, `+v+`),
  over: S.limitsProblem({browser_cert_days: '31', browser_cert_max_active: '3', history_days: '365'}, `+v+`),
  zero: S.limitsProblem({browser_cert_days: '0', browser_cert_max_active: '3', history_days: '365'}, `+v+`),
  active: S.limitsProblem({browser_cert_days: '30', browser_cert_max_active: '21', history_days: '365'}, `+v+`),
  hist: S.limitsProblem({browser_cert_days: '30', browser_cert_max_active: '3', history_days: '29'}, `+v+`),
  frac: S.limitsProblem({browser_cert_days: '2.5', browser_cert_max_active: '3', history_days: '365'}, `+v+`)}`).(map[string]any)
	h := out["html"].(string)
	for _, w := range []string{"ceiling: 30 days (the core", `min="1" max="30" value="45" data-signin-limit="browser_cert_days"`,
		`min="1" max="20" value="3" data-signin-limit="browser_cert_max_active"`, `min="30" max="3650" value="365" data-signin-limit="history_days"`,
		"The lifetime is &lt;b&gt;45&lt;/b&gt; days", `data-signin-action="limits-save"`} {
		if !strings.Contains(h, w) {
			t.Errorf("Settings lacks %q:\n%s", w, h)
		}
	}
	if out["ok"] != "" {
		t.Errorf("in-range values refused: %v", out["ok"])
	}
	for k, want := range map[string]string{"over": "from 1 to 30", "zero": "from 1 to 30", "active": "from 1 to 20", "hist": "from 30 to 3650", "frac": "from 1 to 30"} {
		if s, _ := out[k].(string); !strings.Contains(s, want) {
			t.Errorf("%s: %q, want %q", k, s, want)
		}
	}
	if !strings.Contains(webAsset(t, "signin.js"), "window.apiPut('/api/signin/limits', { browser_cert_days:") {
		t.Error("signin.js doesn't save the limits through PUT /api/signin/limits")
	}
}

// TestNoEnrollWording: the served Hub and people pages and their scripts
// never say "Enroll domain", "enroll.", "/self" or "client certificate"
// (D34); the Domains form is "Add domain".
func TestNoEnrollWording(t *testing.T) {
	e := newPeopleEnv(t)
	_, hubPage := doAs(t, e.hub, "root", "GET", "/", "")
	_, peoplePage := doAs(t, e.people, "bob", "GET", "/", "")
	_, signInPage := doAs(t, e.people, "bob", "GET", "/signin", "")
	pages := map[string]string{"hub index": hubPage, "people page": peoplePage, "sign-in page": signInPage}
	for _, a := range []string{"directory.js", "settings.js", "signin.js", "myapps.js", "myai.js", "mysignin.js", "folders.js", "doctor.js", "confirm.js", "freshauth.js", "freshauth-callback.js", "confirm.html"} {
		pages[a] = webAsset(t, a)
	}
	for name, b := range pages {
		low := strings.ToLower(b)
		for _, bad := range []string{"enroll domain", "enroll.", "/self", "client certificate", "enrolled domain"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s says %q", name, bad)
			}
		}
	}
	if !strings.Contains(hubPage, ">Add domain</button>") || !strings.Contains(hubPage, "showToast('Adding ' + name") || !strings.Contains(hubPage, "q.get('add')") {
		t.Error("the Domains form isn't Add domain")
	}
	if !strings.Contains(hubPage, "Website certificate (HTTPS) valid until") {
		t.Error("Settings → Domains doesn't name the website certificate")
	}
}

// TestMySignInFixRound1: "+ Add" only from the view's https account_url;
// D26 is checked before the popup (cert_fresh against the person's set-up
// methods); Show older fetches each cursor once (disabled while it runs);
// Escape asks before closing the shown-once dialog; directory.js shows
// its own buttons when the person's tab can't be read.
func TestMySignInFixRound1(t *testing.T) {
	v := mySignInView("YubiKey 5C")
	out := mySignInJS(t, `(async () => {
  const v = `+v+`;
  const noURL = Object.assign({}, v, {account_url: 'javascript:alert(1)'});
  const res = {
    add: S.methodsHtml(v, {mode: 'self'}).includes('href="https://auth.example.org/realms/portcullis/account/account-security/signing-in"'),
    noAdd: S.methodsHtml(noURL, {mode: 'self'}).includes('+ Add'),
    okSelf: S.certFreshProblem(v, true),
    // alice has only a synced passkey: none of the allowed methods.
    noneSelf: S.certFreshProblem(Object.assign({}, v, {methods: v.methods.map(m => m.id === 'security_key' || m.id === 'yubikey_cert' ? Object.assign({}, m, {state: 'none'}) : m)}), true),
    emptyTemplate: S.certFreshProblem(Object.assign({}, v, {cert_fresh: []}), false),
    okPerson: S.certFreshProblem(v, false),
  };
  // Show older: two clicks while the first request runs fetch once.
  const calls = [];
  let release;
  global.fetch = url => { calls.push(url); return new Promise(r => { release = () => r({ ok: true, text: async () => JSON.stringify({entries: [], next: '', unknown: []}) }); }); };
  const box = new El('div');
  const el = new El('div');
  el.querySelector = sel => sel === '[data-msi-hist]' ? box : null;
  const st = S._test.state(el, {mode: 'self'});
  st.hist = {entries: [], next: '2026-11-01T00:00:00.123456789Z', unknown: []};
  const btn = new El('button');
  const p1 = S._test.loadHistory(st, true, btn);
  res.disabledWhileLoading = btn.disabled === true;
  await S._test.loadHistory(st, true, btn);
  release();
  await p1;
  res.calls = calls;
  // The dialog's cancel (Escape): asked first; "no" keeps it open.
  let asked = '';
  global.confirm = q => { asked = q; return false; };
  S.openDownload({p12: btoa('x'), password: 'ABCDE-FGHJK-MNPQR-STVWX', filename: 'a.p12'});
  const dlg = document.body.querySelector('dialog');
  let prevented = false;
  for (const f of dlg.ls.cancel || []) f({ preventDefault() { prevented = true; } });
  res.cancelAsked = asked; res.cancelPrevented = prevented; res.stillOpen = dlg.open && dlg.querySelector('[data-msi-pw]').textContent === 'ABCDE-FGHJK-MNPQR-STVWX';
  global.confirm = () => true;
  for (const f of dlg.ls.cancel || []) f({ preventDefault() {} });
  res.closedAfterYes = !dlg.open && document.body.children.length === 0;
  return res;
})()`).(map[string]any)
	refusal := "creating a certificate needs a passkey or YubiKey sign-in that people.example.org accepts"
	if out["add"] != true || out["noAdd"] != false {
		t.Errorf("+ Add: %v / %v", out["add"], out["noAdd"])
	}
	if out["okSelf"] != "" || out["noneSelf"] != refusal || out["emptyTemplate"] != refusal || out["okPerson"] != "" {
		t.Errorf("D26 precheck = %v", out)
	}
	if calls, _ := out["calls"].([]any); len(calls) != 1 || calls[0] != "/api/me/signin/history?limit=20&before=2026-11-01T00%3A00%3A00.123456789Z" || out["disabledWhileLoading"] != true {
		t.Errorf("Show older fetched %v (disabled %v)", out["calls"], out["disabledWhileLoading"])
	}
	if out["cancelAsked"] != "The password won't be shown again — close?" || out["cancelPrevented"] != true || out["stillOpen"] != true || out["closedAfterYes"] != true {
		t.Errorf("Escape: %v", out)
	}
	if js := webAsset(t, "mysignin.js"); !strings.Contains(js, "const bad = certFreshProblem(st.view, true);\n    if (bad) { panelStatus(p, bad, true); return; }\n    fresh(st, p, 'browser_cert'") {
		t.Error("mysignin.js: the D26 check isn't before the popup")
	}
	if d := webAsset(t, "directory.js"); !strings.Contains(d, "onError: () => {") || !strings.Contains(d, "personKeyActions(u).filter(([a]) => SIGNIN_TAB_ACTS.includes(a))") {
		t.Error("directory.js doesn't fall back to its own buttons when the tab can't be read")
	}
}
