package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/signin"
)

// Sign-in Task 9: Settings → Sign-in, the template editor and the
// instance pick (web/signin.js). The browser behaviour is checked against
// the harness (task-9-report.md); these tests run signin.js's helpers
// under node (skipped without node, required in CI) and pin escaping,
// the editor's tree ↔ rule round trip, the depth limit, the greyed-out
// parts, the instance body and the People page's password wording.

// signInJS runs signin.js with a stub window and answers expr (JSON).
// fakeRoot(html) is a stand-in for an element holding html: its
// querySelectorAll answers the [data-signin-node] elements in document
// order, each with its data-* attributes as dataset (what
// ruleFromEditor reads).
func signInJS(t *testing.T, expr string) any {
	t.Helper()
	page := hubIndex(t)
	script := "global.window = {};\nglobal.CSS = { escape: s => String(s).replace(/[\"\\\\]/g, '\\\\$&') };\n" + hubFunc(t, page, "escapeHtml") + "window.escapeHtml = escapeHtml;\n" + webAsset(t, "signin.js") + `
const S = window.PortcullisSignIn;
function unesc(s) { return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'); }
function fakeRoot(html) {
  const els = [];
  const tag = /<[a-z]+\s([^>]*)>/g;
  let m;
  while ((m = tag.exec(html))) {
    if (!/(^|\s)data-signin-node(\s|=|$)/.test(m[1])) continue;
    const ds = {};
    const at = /data-([a-z-]+)(?:="([^"]*)")?/g;
    let a;
    while ((a = at.exec(m[1]))) ds[a[1].replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = unesc(a[2] || '');
    els.push({ dataset: ds });
  }
  return { querySelectorAll: () => els };
}
Promise.resolve(` + expr + `).then(v => process.stdout.write(JSON.stringify(v)), e => process.stdout.write(JSON.stringify({ thrown: String(e && e.stack || e) })));
`
	var v any
	out := runNode(t, script)
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return v
}

// nestedRule is the spec's example: ((password AND YubiKey touch) OR
// (YubiKey AND passkey)) AND certificate.
const nestedRule = `{"op":"all","items":[{"op":"any","items":[{"op":"all","items":["password","security_key"]},{"op":"all","items":["family:yubikey","family:passkey"]}]},"family:certificate"]}`

const hostile = `<img src=x onerror=alert(1)>`

func signInView(name string) string {
	n, _ := json.Marshal(name)
	return `{"methods":[{"id":"password","label":"Password","tenths":10,"on":true,"available":true,"people":2},
{"id":"browser_cert","label":"Browser certificate","tenths":25,"on":false,"available":false,"people":-1},
{"id":"security_key","label":"Security key passkey (YubiKey touch)","tenths":35,"on":true,"available":true,"people":5}],
"people_total":12,"default":"standard","core":{"hub":"strong"},"add_stronger":false,"mds_warning":"FIDO <b>stale</b>",
"templates":[{"id":"standard","name":"Standard","rule":{"op":"any","items":["family:passkey"]},"sentence":"a passkey","score":{"tenths":25,"reason":"r"},"enabled":true,"built_in":true,"used_by":[{"kind":"default","id":"default","name":"the default"}]},
{"id":"strong","name":"Strong","rule":{"op":"any","items":["security_key"]},"sentence":"a YubiKey touch","score":{"tenths":35,"reason":"r"},"enabled":true,"built_in":true,"used_by":[]},
{"id":"evil","name":` + string(n) + `,"rule":{"op":"any","items":["password"]},"sentence":` + string(n) + `,"score":{"tenths":10,"reason":` + string(n) + `},"problem":` + string(n) + `,"enabled":true,"built_in":false,"used_by":[{"kind":"instance","id":"x","name":` + string(n) + `}]}]}`
}

// TestSignInRenderEscapes: a hostile template name, sentence, reason,
// use, warning and blocked person are rendered escaped in the tables,
// the editor, "who it affects" and the instance block.
func TestSignInRenderEscapes(t *testing.T) {
	v := signInView(hostile)
	out := signInJS(t, `{
  table: S.render(`+v+`, ["note <i>x</i>"]),
  editor: S.editorHtml(`+v+`.templates[2], {sentence: `+jsonString(hostile)+`, score: {tenths: 10, reason: `+jsonString(hostile)+`}, problem: `+jsonString(hostile)+`,
    affected: [{kind: "instance", instance: "x", name: `+jsonString(hostile)+`, blocked: [{user: `+jsonString(hostile)+`, why: `+jsonString(hostile)+`}]}], unusable: [], groups: []}),
  inst: S.instanceHtml({method: "forward-auth", sign_in_template: ""}, {instance: "x", name: `+jsonString(hostile)+`, takes_template: true, default: "standard",
    choices: [{id: "standard", name: `+jsonString(hostile)+`, sentence: `+jsonString(hostile)+`, score: {tenths: 25}}], blocked: [{user: `+jsonString(hostile)+`, why: "password only"}]}),
  blocked: S.blockedHtml([{user: "<b>bob</b>", why: "<i>why</i>"}])
}`).(map[string]any)
	for k, h := range out {
		s := h.(string)
		if strings.Contains(s, "<img") || strings.Contains(s, "<b>stale") || strings.Contains(s, "<i>") || strings.Contains(s, "<b>bob") {
			t.Errorf("%s renders markup unescaped:\n%s", k, s)
		}
		if k != "blocked" && !strings.Contains(s, "&lt;img src=x onerror=alert(1)&gt;") {
			t.Errorf("%s lacks the escaped name:\n%s", k, s)
		}
	}
	if !strings.Contains(out["table"].(string), "FIDO &lt;b&gt;stale&lt;/b&gt;") || !strings.Contains(out["table"].(string), "5 of 12") {
		t.Errorf("the MDS warning or the people counts are missing:\n%s", out["table"])
	}
	if !strings.Contains(out["table"].(string), "not available yet") {
		t.Error("browser_cert isn't shown as not available yet")
	}
}

// TestSignInEditorRoundTrip: editorHtml(nested example) → ruleFromEditor
// gives the same JSON; so does every built-in shape.
func TestSignInEditorRoundTrip(t *testing.T) {
	rules := []string{nestedRule, `{"op":"any","items":["family:passkey","family:certificate","password"]}`,
		`{"op":"all","items":["yubikey_cert","security_key"]}`, `{"op":"any","items":[{"op":"all","items":["password",{"op":"any","items":["passkey_synced","passkey_device"]}]},"security_key"]}`}
	for _, r := range rules {
		got := signInJS(t, `S.ruleFromEditor(fakeRoot(S.editorHtml({id: "eng", name: "Engineering", rule: `+r+`})))`)
		b, _ := json.Marshal(got)
		var want any
		_ = json.Unmarshal([]byte(r), &want)
		w, _ := json.Marshal(want)
		if !bytes.Equal(b, w) {
			t.Errorf("round trip of %s = %s", w, b)
		}
	}
}

// TestSignInEditorDepthLimit: "+ group" is offered at levels 1 and 2,
// never on a level-3 group.
func TestSignInEditorDepthLimit(t *testing.T) {
	h := signInJS(t, `S.editorHtml({id: "eng", name: "Engineering", rule: `+nestedRule+`})`).(string)
	groups := regexp.MustCompile(`data-signin-node data-depth="(\d)" data-path="[^"]*" data-op=`).FindAllStringSubmatch(h, -1)
	if len(groups) != 4 {
		t.Fatalf("%d groups rendered, want 4", len(groups))
	}
	// Each group's "+ group" follows its items; split at the groups.
	parts := regexp.MustCompile(`data-signin-node data-depth="\d" data-path="[^"]*" data-op=`).Split(h, -1)[1:]
	depth3 := 0
	for i, g := range groups {
		if g[1] == "3" {
			depth3++
			// The level-3 group's own controls end at its note slot (its
			// items are methods only); nothing up to it offers "+ group".
			own := parts[i][:strings.Index(parts[i], "data-signin-gnote")]
			if strings.Contains(own, `data-signin-action="add-group"`) {
				t.Error("a level-3 group offers + group")
			}
		}
	}
	if depth3 != 2 || strings.Count(h, `data-signin-action="add-group"`) != 2 {
		t.Errorf("level-3 groups %d, + group buttons %d; want 2 and 2", depth3, strings.Count(h, `data-signin-action="add-group"`))
	}
}

// TestSignInGreyedOut: the preview's unusable parts are greyed out with
// their reason, parts inside them greyed out with them, and every group
// shows its score.
func TestSignInGreyedOut(t *testing.T) {
	h := signInJS(t, `S.editorHtml({id: "eng", name: "Engineering", rule: `+nestedRule+`},
  {sentence: "s", score: {tenths: 44, reason: "its strongest part"}, affected: [],
   unusable: [[0, 0]], groups: [{path: [], tenths: 44}, {path: [0], tenths: 39}, {path: [0, 0], tenths: 0}, {path: [0, 1], tenths: 39}]})`).(string)
	g := regexp.MustCompile(`<div class="si-g si-all si-unusable" data-signin-node data-depth="3" data-path="0.0" data-op="all"><div class="si-hd">.*?<span class="si-why" data-signin-why> — a part of it can&#39;t be met</span><span class="si-gs" data-signin-gscore>0.0</span>`)
	if !g.MatchString(h) {
		t.Errorf("the password group isn't greyed out with its reason:\n%s", h)
	}
	if !strings.Contains(h, `<span class="si-chip si-unusable" data-signin-node data-depth="4" data-path="0.0.0" data-leaf="password">`) {
		t.Error("a part inside a greyed-out group isn't greyed out")
	}
	if strings.Contains(h, `data-leaf="family:yubikey">YubiKey (touch or certificate) <button type="button" class="si-x" data-signin-action="remove" aria-label="Remove YubiKey (touch or certificate)">×</button><span class="si-why" data-signin-why> —`) ||
		strings.Contains(h, `si-chip si-unusable" data-signin-node data-depth="4" data-leaf="family:yubikey"`) {
		t.Error("a usable part is greyed out")
	}
	for _, s := range []string{`data-signin-gscore>4.4</span>`, `data-signin-gscore>3.9</span>`, `4.4 <small>/ 5</small>`, "its strongest part", "Certificate (YubiKey or browser)", "Passkey (any kind)"} {
		if !strings.Contains(h, s) {
			t.Errorf("the editor lacks %q", s)
		}
	}
	// A switched-off method and the browser certificate say why.
	marks := signInJS(t, `S.marksFor({op: "any", items: ["password", "browser_cert", "family:certificate", "security_key"]}, {unusable: [[0], [1], [2]], groups: []})`)
	b, _ := json.Marshal(marks)
	if string(b) != `[{},{"why":"off on this server"},{"why":"not available yet"},{"why":"none of its methods is on"},{}]` {
		t.Errorf("marks = %s", b)
	}
}

// TestSignInNoInlineHandlers: nothing signin.js generates (or holds) has
// an inline handler or a javascript: URL.
func TestSignInNoInlineHandlers(t *testing.T) {
	inline := regexp.MustCompile(`(?i)\son[a-z]+\s*=|javascript:`)
	out := signInJS(t, `[S.render(`+signInView("Family")+`, ["n"]), S.editorHtml({id: "eng", name: "Engineering", rule: `+nestedRule+`}),
  S.editorHtml({isNew: true, name: "", rule: {op: "any", items: []}}),
  S.instanceHtml({method: "forward-auth", sign_in_template: "strong"}, {name: "Gitea", takes_template: true, default: "standard", choices: [], blocked: []}),
  S.instanceHtml({method: "mtls"}, null)]`).([]any)
	for i, h := range out {
		if m := inline.FindString(h.(string)); m != "" {
			t.Errorf("output %d has %q", i, m)
		}
	}
	if m := inline.FindAllString(webAsset(t, "signin.js"), -1); len(m) > 0 {
		t.Errorf("signin.js has %q", m)
	}
}

// TestInstanceSignInBody: the drop-down's first entry is "Default
// (Standard · 2.5 / 5)" with value "": picking it sends sign_in_template
// ""; the saved pick sends nothing; an mtls app shows "client certificate
// required" and no drop-down.
func TestInstanceSignInBody(t *testing.T) {
	isv := `{instance: "gitea", name: "Gitea", takes_template: true, template: "strong", inherits: false, default: "standard",
  choices: [{id: "standard", name: "Standard", sentence: "a passkey or a certificate", score: {tenths: 25}, default: true},
            {id: "strong", name: "Strong", sentence: "a YubiKey touch or a YubiKey certificate", score: {tenths: 35}}],
  blocked: [{user: "carol", why: "password only"}]}`
	out := signInJS(t, `{html: S.instanceHtml({method: "forward-auth", sign_in_template: "strong"}, `+isv+`),
  toDefault: S.pickBody("", "strong"), same: S.pickBody("strong", "strong"), toStrong: S.pickBody("strong", ""),
  mtls: S.instanceHtml({method: "mtls", sign_in_template: ""}, `+isv+`)}`).(map[string]any)
	h := out["html"].(string)
	if !strings.Contains(h, `<option value="" data-sentence="a passkey or a certificate">Default (Standard · 2.5 / 5)</option>`) ||
		!strings.Contains(h, `<option value="strong" selected data-sentence="a YubiKey touch or a YubiKey certificate">Strong · 3.5 / 5</option>`) {
		t.Errorf("drop-down:\n%s", h)
	}
	if !strings.Contains(h, "1 person who can use Gitea can&#39;t meet it: <b>carol</b> (password only)") {
		t.Errorf("blocked warning:\n%s", h)
	}
	b, _ := json.Marshal([]any{out["toDefault"], out["same"], out["toStrong"]})
	if string(b) != `[{"sign_in_template":""},{},{"sign_in_template":"strong"}]` {
		t.Errorf("bodies = %s", b)
	}
	if m := out["mtls"].(string); !strings.Contains(m, "Client certificate required") || strings.Contains(m, "<select") {
		t.Errorf("mtls block:\n%s", m)
	}
	// settings.js sends the pick through pickBody, under sign_in_template.
	js := webAsset(t, "settings.js")
	for _, want := range []string{"window.PortcullisSignIn.pickBody(now.sign_in_template, base.sign_in_template)", "b.sign_in_template = a.sign_in_template",
		"window.PortcullisSignIn.instanceHtml(p, st.signin)", "'/signin'"} {
		if !strings.Contains(js, want) {
			t.Errorf("settings.js lacks %q", want)
		}
	}
	for _, gone := range []string{"collectPolicy", "renderAppPolicy", "auth_policy"} {
		if strings.Contains(js, gone) || strings.Contains(webAsset(t, "index.html"), gone) {
			t.Errorf("the old policy UI is left: %q", gone)
		}
	}
}

// TestPasswordActionCopy: the person page's password hint and the invite
// dialog, rendered by directory.js under node over an overview with
// password_on true and false: the hint says whether Password is off now,
// and password onboarding is offered only while it is on.
func TestPasswordActionCopy(t *testing.T) {
	script := `const noop = () => {};
global.window = { addEventListener: noop, location: { hash: '', host: 'people.example.org' } };
global.location = window.location;
global.document = { addEventListener: noop, getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] };
global.history = { replaceState: noop };
` + webAsset(t, "directory.js") + `
const D = window.PortcullisDirectory._test;
const out = {};
for (const on of [true, false]) {
  D.setOverview({ admin: true, password_on: on, users: [{ username: 'bob', email: 'bob@example.org', groups: [] }], groups: [], fields: [] }, { user: 'admin', admin: true });
  out[on] = { page: D.personPageHtml('bob'), invite: D.inviteFormHtml() };
}
process.stdout.write(JSON.stringify(out));
`
	var got map[string]struct{ Page, Invite string }
	nodeJSON(t, script, &got)
	hint := regexp.MustCompile(`<p class="pd-muted pd-small" data-pw-hint>([^<]*)</p>`)
	for on, want := range map[string]string{
		"true":  "Password… sets their LLDAP password. Signs in to Portcullis only while Password is on; apps that check LDAP passwords use it either way.",
		"false": "Password… sets their LLDAP password. Signs in to Portcullis only while Password is on (it is off now: Hub → Settings → Sign-in); apps that check LDAP passwords use it either way.",
	} {
		g := got[on]
		if m := hint.FindStringSubmatch(g.Page); m == nil || m[1] != want {
			t.Errorf("password_on %s: the hint = %v, want %q", on, m, want)
		}
		if !strings.Contains(g.Page, `data-act="password"`) {
			t.Errorf("password_on %s: no Password… action", on)
		}
		offered, offNote := strings.Contains(g.Invite, `id="nu-use-password"`), strings.Contains(g.Invite, "data-pw-onboard-off")
		if offered != (on == "true") || offNote == (on == "true") {
			t.Errorf("password_on %s: password onboarding offered %v, the off note %v", on, offered, offNote)
		}
		if strings.Contains(g.Page+g.Invite, "Fallback: set a password") {
			t.Error("the old password wording is left")
		}
	}
	if !strings.Contains(got["false"].Invite, "Onboarding with a password isn't offered: the Password sign-in method is off (Hub → Settings → Sign-in).") {
		t.Errorf("the invite dialog lacks the off note:\n%s", got["false"].Invite)
	}
	// The prompt says the same as the hint (it is passwordCopy()).
	if !strings.Contains(webAsset(t, "directory.js"), "'Set a password for ' + user + ' (signs them out). ' + passwordCopy()") {
		t.Error("the password prompt doesn't use passwordCopy()")
	}
}

// TestSignInPreviewParts: the preview carries each group's score and the
// parts the switches make unmeetable (the editor's greyed-out parts);
// the overview says whether password onboarding is offered.
func TestSignInPreviewParts(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	e.s.Directory.PasswordMethodOn = e.s.Hub.PasswordMethodOn // as cmd/hub wires it
	call := func(method, path, body string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Forwarded-User", "admin")
		rec := httptest.NewRecorder()
		e.s.hubMux().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s = %d %s", method, path, rec.Code, rec.Body)
		}
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return v
	}
	parts := func(v map[string]any) string {
		b, _ := json.Marshal([]any{v["score"].(map[string]any)["tenths"], v["unusable"], v["groups"]})
		return string(b)
	}
	// Password off (the start): its group can't be met.
	if got := parts(call("POST", "/api/signin/templates/preview", `{"name":"Engineering","rule":`+nestedRule+`}`)); got !=
		`[44,[[0,0]],[{"path":[],"tenths":44},{"path":[0],"tenths":39},{"path":[0,0],"tenths":0},{"path":[0,1],"tenths":39}]]` {
		t.Errorf("password off: %s", got)
	}
	if v := call("GET", "/api/directory", ""); v["password_on"] != false {
		t.Errorf("password_on = %v with password off", v["password_on"])
	}
	call("PUT", "/api/signin/methods/password", `{"on":true}`)
	if got := parts(call("POST", "/api/signin/templates/preview", `{"name":"Engineering","rule":`+nestedRule+`}`)); got !=
		`[44,[],[{"path":[],"tenths":44},{"path":[0],"tenths":39},{"path":[0,0],"tenths":39},{"path":[0,1],"tenths":39}]]` {
		t.Errorf("password on: %s", got)
	}
	if v := call("GET", "/api/directory", ""); v["password_on"] != true {
		t.Errorf("password_on = %v with password on", v["password_on"])
	}
	if v := call("GET", "/api/signin", ""); v["people_total"] == nil {
		t.Error("the view lacks people_total")
	}
}

// TestSignInEditorItemLimit: a group holding 8 items offers no "+ method"
// or "+ group"; editRule refuses a ninth item and a leaf already in the
// group (the note the editor shows next to the controls), but takes the
// same leaf in another group.
func TestSignInEditorItemLimit(t *testing.T) {
	eight := `{"op":"any","items":["password","passkey_synced","passkey_device","security_key","yubikey_cert","family:yubikey","family:passkey",{"op":"all","items":["password"]}]}`
	out := signInJS(t, `(() => {
  const html = S.editorHtml({id: "big", name: "Big", rule: `+eight+`});
  const top = html.slice(html.indexOf('data-path=""'));
  return {
    html,
    topAdd: top.slice(top.lastIndexOf('<div class="si-add">')),
    ninth: S.editRule(`+eight+`, {kind: "add-leaf", path: [], leaf: "browser_cert"}),
    ninthGroup: S.editRule(`+eight+`, {kind: "add-group", path: []}),
    twice: S.editRule({op: "any", items: ["password"]}, {kind: "add-leaf", path: [], leaf: "password"}),
    elsewhere: S.editRule({op: "any", items: ["password", {op: "all", items: ["security_key"]}]}, {kind: "add-leaf", path: [1], leaf: "password"}),
    deep: S.editRule({op: "any", items: [{op: "all", items: [{op: "any", items: ["password"]}]}]}, {kind: "add-group", path: [0, 0]}),
    unknown: S.editRule({op: "any", items: ["password"]}, {kind: "add-leaf", path: [], leaf: "nope"})
  };
})()`).(map[string]any)
	html := out["html"].(string)
	// The top group is full: one "+ method" (the nested group's) and one "+ group".
	if n := strings.Count(html, `data-signin-action="add-method"`); n != 1 {
		t.Errorf("%d \"+ method\" selects, want 1 (the nested group's)", n)
	}
	if n := strings.Count(html, `data-signin-full`); n != 1 || !strings.Contains(html, "8 items: the most a group holds") {
		t.Errorf("%d full notes, want 1:\n%s", n, html)
	}
	if strings.Contains(out["topAdd"].(string), "add-method") || strings.Contains(out["topAdd"].(string), "add-group") {
		t.Errorf("the full top group still offers adding: %s", out["topAdd"])
	}
	refused := func(k, want string) {
		t.Helper()
		r := out[k].(map[string]any)
		got, _ := r["refused"].(string)
		if !strings.Contains(got, want) {
			t.Errorf("%s: refused %q, want %q", k, got, want)
		}
	}
	refused("ninth", "A group holds at most 8 items")
	refused("ninthGroup", "A group holds at most 8 items")
	refused("twice", "Password is already in this group.")
	refused("deep", "Groups nest up to 3 levels.")
	refused("unknown", "unknown method")
	var eightV any
	_ = json.Unmarshal([]byte(eight), &eightV)
	w, _ := json.Marshal(eightV)
	if b, _ := json.Marshal(out["ninth"].(map[string]any)["rule"]); string(b) != string(w) {
		t.Errorf("a refused edit changed the rule: %s", b)
	}
	if b, _ := json.Marshal(out["elsewhere"]); string(b) != `{"rule":{"items":["password",{"items":["security_key","password"],"op":"all"}],"op":"any"}}` {
		t.Errorf("the same leaf in another group: %s", b)
	}
}

// TestSignInTreeEditing: add a method, add a group and fill it, remove a
// part and toggle all/any, each through editRule and drawn again: the
// editor's tree reads back as the edited rule and every group's data-op
// is the option its select shows.
func TestSignInTreeEditing(t *testing.T) {
	out := signInJS(t, `(() => {
  const steps = [];
  let rule = {op: "any", items: ["family:passkey"]};
  for (const e of [
    {kind: "add-leaf", path: [], leaf: "security_key"},
    {kind: "add-group", path: []},
    {kind: "add-leaf", path: [2], leaf: "password"},
    {kind: "add-leaf", path: [2], leaf: "yubikey_cert"},
    {kind: "op", path: [2], op: "any"},
    {kind: "op", path: [], op: "all"},
    {kind: "remove", path: [0]},
    {kind: "remove", path: [1, 0]},
    {kind: "remove", path: []}
  ]) {
    const r = S.editRule(rule, e);
    rule = r.rule;
    const html = S.editorHtml({id: "t", name: "T", rule});
    const ops = [...html.matchAll(/data-op="(all|any)"><div class="si-hd">Require <select data-signin-action="op"[^>]*><option value="all"( selected)?>all of<\/option><option value="any"( selected)?>/g)]
      .map(m => [m[1], m[2] ? "all" : m[3] ? "any" : ""]);
    steps.push({rule, refused: r.refused || "", back: S.ruleFromEditor(fakeRoot(html)), ops, groups: (html.match(/data-op=/g) || []).length});
  }
  return steps;
})()`).([]any)
	want := []string{
		`{"items":["family:passkey","security_key"],"op":"any"}`,
		`{"items":["family:passkey","security_key",{"items":[],"op":"all"}],"op":"any"}`,
		`{"items":["family:passkey","security_key",{"items":["password"],"op":"all"}],"op":"any"}`,
		`{"items":["family:passkey","security_key",{"items":["password","yubikey_cert"],"op":"all"}],"op":"any"}`,
		`{"items":["family:passkey","security_key",{"items":["password","yubikey_cert"],"op":"any"}],"op":"any"}`,
		`{"items":["family:passkey","security_key",{"items":["password","yubikey_cert"],"op":"any"}],"op":"all"}`,
		`{"items":["security_key",{"items":["password","yubikey_cert"],"op":"any"}],"op":"all"}`,
		`{"items":["security_key",{"items":["yubikey_cert"],"op":"any"}],"op":"all"}`,
		`{"items":["security_key",{"items":["yubikey_cert"],"op":"any"}],"op":"all"}`, // the top group stays
	}
	for i, st := range out {
		m := st.(map[string]any)
		rule, _ := json.Marshal(m["rule"])
		back, _ := json.Marshal(m["back"])
		if string(rule) != want[i] {
			t.Errorf("step %d: rule %s, want %s", i, rule, want[i])
		}
		if string(back) != string(rule) {
			t.Errorf("step %d: the editor reads back %s, not %s", i, back, rule)
		}
		ops := m["ops"].([]any)
		if len(ops) != int(m["groups"].(float64)) {
			t.Errorf("step %d: %d groups with a select, %v groups", i, len(ops), m["groups"])
		}
		for _, o := range ops {
			p := o.([]any)
			if p[0] != p[1] {
				t.Errorf("step %d: a group's data-op %v but its select shows %v", i, p[0], p[1])
			}
		}
	}
	if r := out[len(out)-1].(map[string]any)["refused"]; r != "the top group stays" {
		t.Errorf("removing the top group: refused %q", r)
	}
}

// signInStub is a stand-in for the mounted container and the API: el's
// error and confirm slots are objects (by selector), calls lists every
// request, impact is what POST /api/signin/impact answers (or throws).
const signInStub = `
function stubEl() {
  const slots = {};
  return { slots, innerHTML: '', querySelector(sel) {
    if (!/^\[data-signin-(err|confirm)=/.test(sel)) return null;
    return slots[sel] || (slots[sel] = { textContent: '', innerHTML: '' });
  } };
}
const calls = [];
let impact = { affected: [], unknown: '' };
window.apiPost = async (url, body) => { calls.push(['POST', url, body]); if (impact instanceof Error) throw impact; return impact; };
window.apiPut = async (url, body) => { calls.push(['PUT', url, body]); return { view: VIEW, warnings: [], restarts: [] }; };
window.apiGet = async url => { calls.push(['GET', url]); return VIEW; };
`

// TestSignInConfirmThenApply: a default, core page or method switch-off
// asks /api/signin/impact first; nobody newly blocked = the change at
// once; someone blocked or people unknown = the list next to the control
// with Apply / Cancel and nothing changed until Apply; Cancel puts the
// control back; a refused draft is shown like the change's refusal.
func TestSignInConfirmThenApply(t *testing.T) {
	out := signInJS(t, `(async () => {
  const VIEW = `+signInView("x")+`;
  global.VIEW = VIEW;
  `+signInStub+`
  const T = S._test, res = {};
  const run = async (name, draft, errKey) => {
    calls.length = 0;
    const el = stubEl(), st = T.state(el, VIEW), ctl = { disabled: false, value: 'strong' };
    let restored = 0;
    const call = () => window.apiPut('/api/signin/x', draft);
    await T.guarded(st, ctl, errKey, draft, call, () => { restored++; ctl.value = 'standard'; });
    const confirm = el.slots['[data-signin-confirm="' + errKey + '"]'] || {};
    const err = el.slots['[data-signin-err="' + errKey + '"]'] || {};
    res[name] = { calls: calls.map(c => c[0] + ' ' + c[1]), draft: calls[0] && calls[0][2], confirm: confirm.innerHTML, err: err.textContent, disabled: ctl.disabled, restored, pending: Object.keys(st.pending) };
    return { st, el, ctl, confirm, get restored() { return restored; } };
  };
  impact = { affected: [], unknown: '' };
  await run('nobody', { default: 'strong' }, 'default');
  impact = { affected: [{ kind: 'core', instance: 'portal', name: 'Portal', blocked: [{ user: 'bob', why: 'synced passkey only' }] }], unknown: '' };
  const a = await run('blocked', { default: 'strong' }, 'default');
  calls.length = 0;
  await T.resolvePending(a.st, 'default', true);
  res.applied = { calls: calls.map(c => c[0] + ' ' + c[1]), confirm: a.confirm.innerHTML, pending: Object.keys(a.st.pending) };
  const c = await run('blocked2', { core_page: 'hub', core: '' }, 'core:hub');
  calls.length = 0;
  await T.resolvePending(c.st, 'core:hub', false);
  res.cancelled = { calls: calls.length, restored: c.restored, disabled: c.ctl.disabled, value: c.ctl.value, confirm: c.confirm.innerHTML };
  impact = { affected: [], unknown: 'the sign-in methods of bob aren\'t known' };
  await run('unknown', { method: 'passkey_synced', on: false }, 'method:passkey_synced');
  impact = Object.assign(new Error('no sign-in template nope'), { status: 404 });
  await run('refused', { default: 'nope' }, 'default');
  return res;
})()`).(map[string]any)
	get := func(k string) map[string]any { return out[k].(map[string]any) }
	if th, ok := out["thrown"]; ok {
		t.Fatal(th)
	}
	calls := func(m map[string]any) string { b, _ := json.Marshal(m["calls"]); return string(b) }
	if got := calls(get("nobody")); got != `["POST /api/signin/impact","PUT /api/signin/x"]` || get("nobody")["confirm"] != "" {
		t.Errorf("nobody blocked: calls %s, confirm %q", got, get("nobody")["confirm"])
	}
	if d, _ := json.Marshal(get("nobody")["draft"]); string(d) != `{"default":"strong"}` {
		t.Errorf("the draft sent: %s", d)
	}
	b := get("blocked")
	if calls(b) != `["POST /api/signin/impact"]` || b["disabled"] != true || b["restored"] != float64(0) {
		t.Errorf("blocked: calls %s, disabled %v, restored %v (want only the impact asked, the control held)", calls(b), b["disabled"], b["restored"])
	}
	for _, want := range []string{"1 person would no longer be able to sign in to Portal", "<b>bob</b> (synced passkey only)",
		`data-signin-action="impact-apply" data-key="default"`, `data-signin-action="impact-cancel" data-key="default"`} {
		if !strings.Contains(b["confirm"].(string), want) {
			t.Errorf("the confirm lacks %q:\n%s", want, b["confirm"])
		}
	}
	if ap := get("applied"); calls(ap) != `["PUT /api/signin/x"]` || ap["confirm"] != "" || len(ap["pending"].([]any)) != 0 {
		t.Errorf("Apply: calls %s, confirm %q, pending %v", calls(ap), ap["confirm"], ap["pending"])
	}
	if c := get("cancelled"); c["calls"] != float64(0) || c["restored"] != float64(1) || c["disabled"] != false || c["value"] != "standard" || c["confirm"] != "" {
		t.Errorf("Cancel: %v", c)
	}
	if u := get("unknown"); calls(u) != `["POST /api/signin/impact"]` || !strings.Contains(u["confirm"].(string), "Who this change blocks isn't known: the sign-in methods of bob aren&#39;t known") {
		t.Errorf("people unknown: calls %s, confirm %q", calls(u), u["confirm"])
	}
	if r := get("refused"); calls(r) != `["POST /api/signin/impact"]` || r["err"] != "no sign-in template nope" || r["restored"] != float64(1) || r["disabled"] != false {
		t.Errorf("refused draft: %v", r)
	}
	// The handlers go through guarded for exactly these changes.
	js := webAsset(t, "signin.js")
	for _, want := range []string{"guarded(st, t, 'default', { default: want }", "guarded(st, t, 'core:' + key, { core_page: key, core: want }",
		"if (want) act(st, t, 'method:' + m, call, restore);\n        else guarded(st, t, 'method:' + m, { method: m, on: false }, call, restore);"} {
		if !strings.Contains(js, want) {
			t.Errorf("signin.js lacks %q", want)
		}
	}
}

// TestInstancePickImpact: changing the instance's drop-down asks who the
// new pick newly blocks (debounced, the latest change wins) and shows it
// in place of the saved choice's list; back to the saved choice shows
// that list again.
func TestInstancePickImpact(t *testing.T) {
	out := signInJS(t, `(async () => {
  global.VIEW = {};
  `+signInStub+`
  const html = S.instanceHtml({method: "forward-auth", sign_in_template: ""}, {instance: "hookapp", name: "Hook App", takes_template: true, default: "standard",
    choices: [{id: "standard", name: "Standard", sentence: "a passkey", score: {tenths: 25}}, {id: "strong", name: "Strong", sentence: "a YubiKey touch", score: {tenths: 35}}],
    blocked: [{user: "dave", why: "no method yet"}]});
  const slot = () => ({ textContent: '', innerHTML: '', hidden: false });
  const box = { s: {}, querySelector(sel) { return this.s[sel] || (this.s[sel] = slot()); } };
  box.s['[data-signin-pick-impact]'] = Object.assign(slot(), { hidden: true });
  const sel = { value: 'strong', dataset: { saved: '', instance: 'hookapp', name: 'Hook App' }, selectedOptions: [{ dataset: { sentence: 'a YubiKey touch' } }], closest: () => box };
  impact = { affected: [{ kind: 'instance', instance: 'other', name: 'Other', blocked: [{ user: 'zed', why: 'x' }] },
    { kind: 'instance', instance: 'hookapp', name: 'Hook App', blocked: [{ user: 'bob', why: 'password only' }, { user: 'carol', why: 'password only' }] }], unknown: '' };
  const first = S.pickChanged(sel);          // superseded before it fires
  const second = S.pickChanged(sel);
  const checking = box.s['[data-signin-pick-impact]'].innerHTML;
  await Promise.all([first, second]);
  const res = { html, checking, posts: calls.filter(c => c[0] === 'POST').map(c => c[2]), impact: box.s['[data-signin-pick-impact]'].innerHTML,
    savedHidden: box.s['[data-signin-pick-saved]'].hidden, impactHidden: box.s['[data-signin-pick-impact]'].hidden, sentence: box.s['[data-signin-pick-sentence]'].textContent };
  impact = { affected: [], unknown: '' };
  await S.pickChanged(sel);
  res.nobody = box.s['[data-signin-pick-impact]'].innerHTML;
  impact = { affected: [], unknown: 'Users & Groups can\'t be read' };
  await S.pickChanged(sel);
  res.unknown = box.s['[data-signin-pick-impact]'].innerHTML;
  impact = Object.assign(new Error('"Strong" is disabled: enable it first'), { status: 409 });
  await S.pickChanged(sel);
  res.refused = box.s['[data-signin-pick-impact]'].innerHTML;
  sel.value = '';
  await S.pickChanged(sel);
  res.back = { savedHidden: box.s['[data-signin-pick-saved]'].hidden, impactHidden: box.s['[data-signin-pick-impact]'].hidden, impact: box.s['[data-signin-pick-impact]'].innerHTML };
  return res;
})()`).(map[string]any)
	if th, ok := out["thrown"]; ok {
		t.Fatal(th)
	}
	html := out["html"].(string)
	for _, want := range []string{`data-instance="hookapp"`, `data-name="Hook App"`, `<div data-signin-pick-saved><div class="public-warn" data-signin-blocked>1 person who can use Hook App can&#39;t meet it`, `<div data-signin-pick-impact role="status" hidden></div>`} {
		if !strings.Contains(html, want) {
			t.Errorf("the block lacks %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, "save to see") {
		t.Error("the \"save first\" note is left")
	}
	if p, _ := json.Marshal(out["posts"]); string(p) != `[{"instance":"hookapp","pick":"strong"}]` {
		t.Errorf("impact asked %s, want once for the latest change", p)
	}
	if !strings.Contains(out["checking"].(string), "Checking who this choice blocks") {
		t.Errorf("while waiting: %q", out["checking"])
	}
	imp := out["impact"].(string)
	if !strings.Contains(imp, "2 people who can use Hook App would no longer be able to sign in to it: <b>bob</b> (password only) · <b>carol</b> (password only)") || strings.Contains(imp, "zed") {
		t.Errorf("the impact: %s", imp)
	}
	if out["savedHidden"] != true || out["impactHidden"] != false || out["sentence"] != "a YubiKey touch" {
		t.Errorf("saved hidden %v, impact hidden %v, sentence %v", out["savedHidden"], out["impactHidden"], out["sentence"])
	}
	if !strings.Contains(out["nobody"].(string), "Nobody who can use Hook App is newly blocked by this choice.") {
		t.Errorf("nobody blocked: %s", out["nobody"])
	}
	if !strings.Contains(out["unknown"].(string), "Who this choice blocks isn't known: Users &amp; Groups can&#39;t be read") {
		t.Errorf("unknown: %s", out["unknown"])
	}
	if !strings.Contains(out["refused"].(string), "Refused: &quot;Strong&quot; is disabled: enable it first") {
		t.Errorf("refused: %s", out["refused"])
	}
	if b := out["back"].(map[string]any); b["savedHidden"] != false || b["impactHidden"] != true || b["impact"] != "" {
		t.Errorf("back to the saved choice: %v", b)
	}
}

// TestPickRefusalMatchesHub: the texts the Hub refuses an instance's
// template pick with (an id that isn't one, an unknown template, a
// disabled one) are what settings.js shows at the drop-down
// (PortcullisSignIn.PICK_REFUSAL); other refusals aren't.
func TestPickRefusalMatchesHub(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	ctx := context.Background()
	root := directory.Human("root")
	rule := signin.Node{Op: "any", Items: []signin.Node{{Leaf: string(signin.SecurityKey)}}}
	if _, err := e.s.Hub.SaveTemplate(ctx, "parked", hub.TemplateInput{Name: "Parked", Rule: rule}, true, root); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Hub.SetTemplateEnabled(ctx, "parked", false, root); err != nil {
		t.Fatal(err)
	}
	var msgs []string
	for _, pick := range []string{"Bad Id!", "nope", "parked"} {
		_, err := e.s.Hub.SaveSettings("notes", hub.SettingsUpdate{SignInTemplate: &pick}, root)
		if err == nil {
			t.Fatalf("pick %q saved", pick)
		}
		msgs = append(msgs, err.Error())
	}
	other := []string{"setting retention: must be a number", "Users & Groups is not available", "the template changed while creating: try again"}
	b, _ := json.Marshal(append(append([]string{}, msgs...), other...))
	got := signInJS(t, `(`+string(b)+`).map(m => S.PICK_REFUSAL.test(m))`).([]any)
	for i, m := range append(msgs, other...) {
		if want := i < len(msgs); got[i] != want {
			t.Errorf("PICK_REFUSAL.test(%q) = %v, want %v", m, got[i], want)
		}
	}
	if !strings.Contains(webAsset(t, "settings.js"), "window.PortcullisSignIn.PICK_REFUSAL.test(err.message || '')") {
		t.Error("settings.js doesn't place pick refusals with PICK_REFUSAL")
	}
}
