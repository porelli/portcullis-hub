package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// Authenticator codes Task 10: the Sign-in page's authenticator apps,
// the fresh-auth popup's kc_action and pc_method, the callback's
// kc_action_status, the editor's code-only mark and the core warning.

// totpView is mySignInView with the totp row: two apps, one of them with
// markup in its name.
func totpView(extra string) string {
	return `{"user":"alice","add_stronger":false,"max_authenticators":3,` + extra + `"methods":[
{"id":"password","label":"Password","on":true,"state":"set"},
{"id":"totp","label":"Authenticator app","on":true,"state":"set","authenticators":[
 {"id":"11111111-1111-4111-8111-111111111111","label":"Phone <img src=x onerror=alert(1)>","created_at":"2026-10-01T09:00:00Z"},
 {"id":"22222222-2222-4222-8222-222222222222","label":"Tablet","created_at":"2026-11-01T09:00:00Z"}],
 "remove_impact":["Nextcloud"]},
{"id":"security_key","label":"Security key","on":true,"state":"set","passkeys":[{"id":"k1","label":"YubiKey","kind":"security_key","model":"","created_at":"2026-11-02T09:12:00Z"}]}
],"certificates":[],"apps":[],"fresh_auth":{"authorize_url":"https://auth.example.org/a","client_id":"portcullis-fresh-auth","redirect_uri":"https://people.example.org/signin"}}`
}

// TestWebUIMySignInTOTPActions: the totp row's list and its four actions,
// escaped; + Add hidden at the limit, off, read-only and on a person's
// tab; the cap's "ask your admin"; the person tab's Remove authenticator
// apps from can; the rename's own text.
func TestWebUIMySignInTOTPActions(t *testing.T) {
	out := mySignInJS(t, `(() => {
  const v = `+totpView("")+`;
  const one = JSON.parse(JSON.stringify(v)); one.methods[1].authenticators.pop();
  const full = JSON.parse(JSON.stringify(v)); full.methods[1].authenticators.push({id: '33333333-3333-4333-8333-333333333333', label: 'Spare', created_at: ''});
  const capped = JSON.parse(JSON.stringify(one)); capped.methods[1].authenticators = []; capped.methods[1].state = 'none'; capped.methods[2].state = 'none'; capped.methods[2].passkeys = [];
  const off = JSON.parse(JSON.stringify(v)); off.methods[1] = {id: 'totp', label: 'Authenticator app', on: false, state: 'off'};
  const open = JSON.parse(JSON.stringify(capped)); open.add_stronger = true;
  return {
    self: S.methodsHtml(v, {mode: 'self'}),
    full: S.methodsHtml(full, {mode: 'self'}),
    capped: S.methodsHtml(capped, {mode: 'self'}),
    open: S.methodsHtml(open, {mode: 'self'}),
    off: S.methodsHtml(off, {mode: 'self'}),
    ro: S.methodsHtml(v, {mode: 'self', readOnly: 'root'}),
    person: S.methodsHtml(v, {mode: 'person', user: 'alice', can: {remove_passkeys: true, remove_authenticators: true}}),
    personNo: S.methodsHtml(v, {mode: 'person', user: 'alice', can: {remove_passkeys: true}}),
    managed: S.methodsHtml(Object.assign(JSON.parse(JSON.stringify(v)), {user: 'portcullis-hub'}), {mode: 'self'}),
    authProblem: S.labelProblem('x'.repeat(65), 'authenticator'), pkProblem: S.labelProblem('', 'passkey'), okLabel: S.labelProblem('Work phone', 'authenticator'),
    history: S.whatText({kind: 'method', methods: ['totp'], detail: 'authenticator app added: Phone'}),
    failed: S.whatText({kind: 'failed', methods: ['totp'], reason: 'wrong authenticator code'}),
  };
})()`).(map[string]any)
	self := rowOf(out["self"].(string), "totp")
	for _, w := range []string{
		`data-msi-act="totp-add"`, "+ Add authenticator app",
		`data-msi-act="totp-rename" data-cred="11111111-1111-4111-8111-111111111111"`,
		`data-msi-act="totp-replace" data-cred="22222222-2222-4222-8222-222222222222"`,
		`data-msi-act="totp-remove" data-cred="11111111-1111-4111-8111-111111111111"`,
		"Phone &lt;img src=x onerror=alert(1)&gt; · added", "Tablet · added", `<span class="pd-pill ok">2</span>`,
	} {
		if !strings.Contains(self, w) {
			t.Errorf("totp row lacks %q:\n%s", w, self)
		}
	}
	if strings.Contains(self, "<img") {
		t.Errorf("unescaped label:\n%s", self)
	}
	if i, j := strings.Index(self, "Phone"), strings.Index(self, "Tablet"); i < 0 || j < 0 || i > j {
		t.Errorf("not oldest first:\n%s", self)
	}
	if r := rowOf(out["full"].(string), "totp"); strings.Contains(r, "totp-add") || !strings.Contains(r, "the most allowed") {
		t.Errorf("at the limit:\n%s", r)
	}
	if r := rowOf(out["capped"].(string), "totp"); strings.Contains(r, "totp-add") || !strings.Contains(r, "ask your admin for a setup link") {
		t.Errorf("under the cap:\n%s", r)
	}
	if r := rowOf(out["open"].(string), "totp"); !strings.Contains(r, "totp-add") {
		t.Errorf("add_stronger on:\n%s", r)
	}
	if r := rowOf(out["off"].(string), "totp"); !strings.Contains(r, "off on this server") || strings.Contains(r, "<button") {
		t.Errorf("off:\n%s", r)
	}
	for _, k := range []string{"ro", "personNo", "managed"} {
		if r := rowOf(out[k].(string), "totp"); strings.Contains(r, "data-msi-act=\"totp-") {
			t.Errorf("%s offers totp actions:\n%s", k, r)
		}
	}
	person := out["person"].(string)
	if !strings.Contains(person, `data-act="reset-authenticators" data-user="alice"`) || strings.Contains(out["personNo"].(string), "reset-authenticators") {
		t.Errorf("person tab:\n%s", person)
	}
	if out["authProblem"] != "An authenticator name is 1–64 characters on one line." || out["pkProblem"] != "A passkey name is 1–64 characters on one line." || out["okLabel"] != "" {
		t.Errorf("labelProblem: %v %v %v", out["authProblem"], out["pkProblem"], out["okLabel"])
	}
	if out["history"] != "Sign-in method · authenticator app added: Phone" || out["failed"] != "Sign-in failed · authenticator code: wrong authenticator code" {
		t.Errorf("history: %v / %v", out["history"], out["failed"])
	}
	js := webAsset(t, "mysignin.js")
	// Every authenticator action goes through Keycloak's own actions
	// (kcAction); the only Hub write is the rename.
	for _, w := range []string{"kcAction(st, 'add', 'CONFIGURE_TOTP')", "kcAction(st, 'replace', 'CONFIGURE_TOTP:' + b.dataset.cred)",
		"kcAction(st, 'remove', 'delete_credential:' + id)", "'/api/me/signin/authenticators/' + enc(id) + '/label'"} {
		if !strings.Contains(js, w) {
			t.Errorf("mysignin.js lacks %q", w)
		}
	}
}

// TestMySignInTOTPFlows: the rename's PUT and reload; a removal shows the
// last app's impact first; an action's answer reloads with ?refresh=1
// once, says how it went and recommends a second app after the first.
func TestMySignInTOTPFlows(t *testing.T) {
	out := mySignInJS(t, `(async () => {
  const v = `+totpView("")+`;
  const calls = [], started = [], asked = [];
  let view = v;
  global.fetch = (url, opts) => { calls.push({url, method: (opts && opts.method) || 'GET', body: (opts && opts.body) || ''});
    return Promise.resolve({ ok: true, text: async () => url.includes('/authenticators/') ? '' : (url.includes('/history') ? JSON.stringify({entries: [], next: '', unknown: []}) : url.includes('impersonation') ? '{}' : JSON.stringify(view)) }); };
  global.confirm = q => { asked.push(q); return true; };
  window.PortcullisFreshAuth = { start: (fa, h) => { started.push({fa, kcAction: h.kcAction, ctx: h.ctx}); window._h = h; }, cancel() {} };
  const input = new El('input');
  const p = new El('div');
  p.querySelector = sel => sel === '[data-msi-authlabel]' ? input : null;
  p.querySelectorAll = () => [];
  const el = new El('div');
  el.querySelector = () => null;
  el.querySelectorAll = () => [];
  const st = S._test.state(el, {mode: 'self'});
  st.view = v;
  input.value = ' Work phone ';
  await S._test.authRenameGo(st, p, '11111111-1111-4111-8111-111111111111');
  const renameCalls = calls.slice();
  calls.length = 0;
  S._test.removeAuthenticator(st, '11111111-1111-4111-8111-111111111111');
  const removeStart = started.pop();
  // First add: none before, one after.
  const none = JSON.parse(JSON.stringify(v)); none.methods[1].authenticators = []; none.methods[1].state = 'none';
  st.view = none;
  S._test.kcAction(st, 'add', 'CONFIGURE_TOTP');
  const addStart = started.pop();
  const one = JSON.parse(JSON.stringify(v)); one.methods[1].authenticators.pop();
  view = one;
  let status = '';
  const setStatusSpy = () => {};
  await window._h.action('success');
  const afterAdd = calls.map(c => c.url);
  calls.length = 0;
  const firstRead = S._test.readURL(st);
  return {renameCalls, asked, removeStart, addStart, afterAdd, firstRead};
})()`).(map[string]any)
	rc, _ := out["renameCalls"].([]any)
	if len(rc) < 2 {
		t.Fatalf("rename calls = %v", rc)
	}
	put := rc[0].(map[string]any)
	if put["url"] != "/api/me/signin/authenticators/11111111-1111-4111-8111-111111111111/label" || put["method"] != "PUT" || put["body"] != `{"label":"Work phone"}` {
		t.Errorf("PUT = %v", put)
	}
	if get := rc[1].(map[string]any); get["url"] != "/api/me/signin" {
		t.Errorf("no reload after the rename: %v", rc)
	}
	asked, _ := out["asked"].([]any)
	if len(asked) != 1 || !strings.Contains(asked[0].(string), "you could no longer open Nextcloud") {
		t.Errorf("removal question = %v", asked)
	}
	rs := out["removeStart"].(map[string]any)
	if rs["kcAction"] != "delete_credential:11111111-1111-4111-8111-111111111111" {
		t.Errorf("remove start = %v", rs)
	}
	if as := out["addStart"].(map[string]any); as["kcAction"] != "CONFIGURE_TOTP" {
		t.Errorf("add start = %v", as)
	}
	after, _ := out["afterAdd"].([]any)
	if len(after) == 0 || after[0] != "/api/me/signin?refresh=1" {
		t.Errorf("after the action = %v, want a ?refresh=1 read first", after)
	}
	if out["firstRead"] != "/api/me/signin" {
		t.Errorf("refresh not dropped after one read: %v", out["firstRead"])
	}
	js := webAsset(t, "mysignin.js")
	if !strings.Contains(js, "Add a second one (another phone, or a password manager)") {
		t.Error("no second-app hint after the first add")
	}
}

// freshDOM is what freshauth.js needs under node: a popup, sessionStorage,
// a message listener and crypto.
const freshDOM = `
const store = {};
global.sessionStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; } };
const listeners = {};
const popups = [];
global.window = { addEventListener: (ev, f) => { (listeners[ev] = listeners[ev] || []).push(f); },
  open: () => { const p = { closed: false, location: { href: '' }, close() { this.closed = true; } }; popups.push(p); return p; } };
global.location = { protocol: 'https:', origin: 'https://people.example.org' };
global.setInterval = () => 1; global.clearInterval = () => {};
`

// freshJS runs freshauth.js and answers expr (JSON).
func freshJS(t *testing.T, expr string) any {
	t.Helper()
	var v any
	nodeJSON(t, freshDOM+webAsset(t, "freshauth.js")+`
const F = window.PortcullisFreshAuth;
const fire = d => { for (const f of listeners.message || []) f({ origin: 'https://people.example.org', source: popups[popups.length - 1], data: d }); };
Promise.resolve((async () => (`+expr+`))()).then(v => process.stdout.write(JSON.stringify(v)), e => process.stdout.write(JSON.stringify({ thrown: String(e && e.stack || e) })));
`, &v)
	if m, ok := v.(map[string]any); ok && m["thrown"] != nil {
		t.Fatalf("node: %v", m["thrown"])
	}
	return v
}

// TestFreshAuthKcActionAllowlist (P1, P10): kc_action only from the
// allowlist (nothing opened otherwise); pc_method=totp only on a proof
// flow, never with a kc_action; an action's answer goes to h.action,
// never h.proof — also when its callback carries only kc_action_status.
func TestFreshAuthKcActionAllowlist(t *testing.T) {
	fa := webAsset(t, "freshauth.js")
	if !strings.Contains(fa, `const KC_ACTION = /^(CONFIGURE_TOTP(:[0-9a-f-]{36})?|delete_credential:[0-9a-f-]{36})$/;`) {
		t.Error("freshauth.js lacks the kc_action allowlist literal")
	}
	if n := len(regexp.MustCompile(`'kc_action'`).FindAllString(fa, -1)); n != 1 {
		t.Errorf("'kc_action' set %d times, want once", n)
	}
	if n := len(regexp.MustCompile(`'pc_method', 'totp'`).FindAllString(fa, -1)); n != 1 {
		t.Errorf("pc_method set %d times, want once (the literal totp only)", n)
	}
	out := freshJS(t, `(async () => {
  const fa = {authorize_url: 'https://auth.example.org/a', client_id: 'c', redirect_uri: 'https://people.example.org/signin', pc_method: 'totp'};
  const res = {};
  const h = (name) => ({ ctx: {x: name}, status: (t, w) => { res[name + 'Status'] = t; }, busy() {}, end() {},
    proof: p => { res[name + 'Proof'] = p; }, action: s => { res[name + 'Action'] = s; } });
  for (const bad of ['CONFIGURE_TOTP:replace:11111111-1111-4111-8111-111111111111', 'UPDATE_PASSWORD', 'delete_credential', 'CONFIGURE_TOTP ', '']) {
    const before = popups.length;
    await F.start(fa, Object.assign(h('bad'), {kcAction: bad}));
    if (popups.length !== before) res.badOpened = bad;
  }
  await F.start(fa, h('proof'));
  res.proofURL = popups[popups.length - 1].location.href;
  fire({type: 'portcullis-fresh-auth', state: 'nope', code: 'c', error: ''});
  res.proofEarly = res.proofProof || null;
  const st = JSON.parse(sessionStorage.getItem('portcullis-fresh-auth')).state;
  fire({type: 'portcullis-fresh-auth', state: st, code: 'the-code', error: '', kc_action_status: ''});
  await F.start(fa, Object.assign(h('add'), {kcAction: 'CONFIGURE_TOTP'}));
  res.addURL = popups[popups.length - 1].location.href;
  fire({type: 'portcullis-fresh-auth', state: '', code: '', error: '', kc_action_status: 'success'});
  await F.start(fa, Object.assign(h('rm'), {kcAction: 'delete_credential:11111111-1111-4111-8111-111111111111'}));
  res.rmURL = popups[popups.length - 1].location.href;
  const st2 = JSON.parse(sessionStorage.getItem('portcullis-fresh-auth')).state;
  fire({type: 'portcullis-fresh-auth', state: st2, code: 'x', error: '', kc_action_status: 'cancelled'});
  // A stateless message with a code is never an action's answer.
  await F.start(fa, Object.assign(h('sneak'), {kcAction: 'CONFIGURE_TOTP'}));
  fire({type: 'portcullis-fresh-auth', state: '', code: 'stolen', error: '', kc_action_status: 'success'});
  // My apps' per-app pc_method: '' overrides the view's.
  await F.start(fa, Object.assign(h('app'), {pcMethod: ''}));
  res.appURL = popups[popups.length - 1].location.href;
  return res;
})()`).(map[string]any)
	if out["badOpened"] != nil || out["badStatus"] != "That action isn't available here." {
		t.Errorf("a bad kc_action: opened %v, status %v", out["badOpened"], out["badStatus"])
	}
	pu := out["proofURL"].(string)
	if !strings.Contains(pu, "pc_method=totp") || strings.Contains(pu, "kc_action") || !strings.Contains(out["proofStatus"].(string), "your password (or key), then a code from your authenticator app") {
		t.Errorf("proof flow: %s / %v", pu, out["proofStatus"])
	}
	if out["proofEarly"] != nil {
		t.Error("a message with another state was accepted")
	}
	if p, _ := out["proofProof"].(map[string]any); p == nil || p["code"] != "the-code" {
		t.Errorf("proof = %v", out["proofProof"])
	}
	au := out["addURL"].(string)
	if !strings.Contains(au, "kc_action=CONFIGURE_TOTP") || strings.Contains(au, "pc_method") || out["addAction"] != "success" || out["addProof"] != nil {
		t.Errorf("add: %s action %v proof %v", au, out["addAction"], out["addProof"])
	}
	if !strings.Contains(out["rmURL"].(string), "kc_action=delete_credential%3A11111111-1111-4111-8111-111111111111") || out["rmAction"] != "cancelled" || out["rmProof"] != nil {
		t.Errorf("remove: %v %v %v", out["rmURL"], out["rmAction"], out["rmProof"])
	}
	if out["sneakAction"] != nil || out["sneakProof"] != nil {
		t.Errorf("a stateless message with a code was accepted: %v %v", out["sneakAction"], out["sneakProof"])
	}
	if strings.Contains(out["appURL"].(string), "pc_method") {
		t.Errorf("an app without fresh_pc_method sent pc_method: %v", out["appURL"])
	}
}

// TestCallbackForwardsKcActionStatus: the callback forwards
// kc_action_status ("" when absent) and handles a callback with only it.
func TestCallbackForwardsKcActionStatus(t *testing.T) {
	run := func(search string) map[string]any {
		var v map[string]any
		nodeJSON(t, `
const posted = [];
const opener = { location: { origin: 'https://people.example.org' }, postMessage: (m, o) => posted.push({m, o}) };
global.window = { opener, close() {} };
global.location = { search: '`+search+`', pathname: '/signin', hash: '', origin: 'https://people.example.org' };
global.history = { replaceState() {} };
global.document = { documentElement: { style: {} }, addEventListener() {} };
global.URLSearchParams = URLSearchParams;
`+webAsset(t, "freshauth-callback.js")+`
process.stdout.write(JSON.stringify({handled: window.portcullisFreshAuthCallback, posted}));
`, &v)
		return v
	}
	only := run("?kc_action_status=success")
	posted, _ := only["posted"].([]any)
	if only["handled"] != true || len(posted) != 1 {
		t.Fatalf("only kc_action_status: %v", only)
	}
	m := posted[0].(map[string]any)["m"].(map[string]any)
	if m["kc_action_status"] != "success" || m["code"] != "" || m["type"] != "portcullis-fresh-auth" {
		t.Errorf("message = %v", m)
	}
	plain := run("?code=c&state=s")
	m = plain["posted"].([]any)[0].(map[string]any)["m"].(map[string]any)
	if m["kc_action_status"] != "" || m["code"] != "c" {
		t.Errorf("plain message = %v", m)
	}
	if none := run(""); none["handled"] != false {
		t.Errorf("no parameters: %v", none)
	}
}

// TestSignInEditorMarksCodeOnly (T2): the preview's code_only group is
// marked si-codeonly with the problem text; the editor offers the
// Authenticator app; Settings shows core_warnings next to the pick.
func TestSignInEditorMarksCodeOnly(t *testing.T) {
	out := signInJS(t, `(() => {
  const rule = {op: 'any', items: ['security_key', {op: 'any', items: ['totp', 'passkey_synced']}]};
  const problem = "an authenticator code can't be the only way in: combine it with another method (all of)";
  const p = {unusable: [], groups: [], code_only: [[1]], problem, score: {tenths: 15, reason: ''}, sentence: '', affected: []};
  const v = Object.assign(`+signInView("Strong")+`, {core_warnings: {people: 'The Hub can be opened with a password and a code: both can be phished'}});
  return {marks: S.marksFor(rule, p), editor: S.editorHtml({id: 'x', name: 'x', rule}, p), table: S.render(v, [])};
})()`).(map[string]any)
	marks, _ := out["marks"].([]any)
	var codeOnly []map[string]any
	for _, m := range marks {
		if mm, ok := m.(map[string]any); ok && mm["codeOnly"] == true {
			codeOnly = append(codeOnly, mm)
		}
	}
	if len(codeOnly) != 1 || !strings.Contains(codeOnly[0]["why"].(string), "can't be the only way in") {
		t.Errorf("marks = %v", marks)
	}
	ed := out["editor"].(string)
	if !strings.Contains(ed, `si-codeonly" data-signin-node data-depth="2" data-path="1"`) || strings.Count(ed, "si-codeonly") != 1 ||
		!strings.Contains(ed, "can&#39;t be the only way in") {
		t.Errorf("editor:\n%s", ed)
	}
	if !strings.Contains(ed, `<option value="totp">Authenticator app</option>`) {
		t.Errorf("the editor doesn't offer the authenticator app:\n%s", ed)
	}
	tb := out["table"].(string)
	if !strings.Contains(tb, `data-signin-corewarn="people" role="note">The Hub can be opened with a password and a code: both can be phished</div>`) || strings.Contains(tb, `data-signin-corewarn="hub"`) {
		t.Errorf("Settings doesn't show the warning by its pick:\n%s", tb)
	}
	js := webAsset(t, "signin.js")
	if !strings.Contains(js, "classList.toggle('si-codeonly'") {
		t.Error("the live preview doesn't toggle si-codeonly")
	}
	if !strings.Contains(webAsset(t, "index.html"), ".si-codeonly") {
		t.Error("index.html has no si-codeonly style")
	}
}

// TestDirectoryTOTPActions (P12): the person tab's Remove authenticator
// apps (typed name) and the setup-link dialog's checkbox → authenticator.
func TestDirectoryTOTPActions(t *testing.T) {
	js := webAsset(t, "directory.js")
	for _, w := range []string{
		"const SIGNIN_TAB_ACTS = ['invite', 'reset-passkeys', 'reset-authenticators', 'password'];",
		"case 'reset-authenticators': {",
		"api('POST', path + '/remove-authenticators', { confirm: user })",
		"authenticatorOn() ? '<div class=\"pd-checks\"><label><input type=\"checkbox\" data-pp-invite-auth>",
		"const body = box && box.checked ? { authenticator: true } : {};",
		"function authenticatorOn() { return !!(dir && dir.authenticator_on); }",
	} {
		if !strings.Contains(js, w) {
			t.Errorf("directory.js lacks %q", w)
		}
	}
	if strings.Contains(js, "confirm('Create a new one-time invite link") {
		t.Error("the setup link still uses confirm(): the dialog has the checkbox")
	}
}
