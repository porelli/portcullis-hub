package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
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
	script := "global.window = {};\n" + hubFunc(t, page, "escapeHtml") + "window.escapeHtml = escapeHtml;\n" + webAsset(t, "signin.js") + `
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
process.stdout.write(JSON.stringify(` + expr + `));
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
	groups := regexp.MustCompile(`data-signin-node data-depth="(\d)" data-op=`).FindAllStringSubmatch(h, -1)
	if len(groups) != 4 {
		t.Fatalf("%d groups rendered, want 4", len(groups))
	}
	// Each group's "+ group" follows its items; split at the groups.
	parts := regexp.MustCompile(`data-signin-node data-depth="\d" data-op=`).Split(h, -1)[1:]
	depth3 := 0
	for i, g := range groups {
		if g[1] == "3" {
			depth3++
			// The level-3 group's own controls end at its "+ method" select's
			// closing tag; nothing up to the next group offers "+ group".
			own := parts[i][:strings.Index(parts[i], "</select></div></div>")]
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
	g := regexp.MustCompile(`<div class="si-g si-all si-unusable" data-signin-node data-depth="3" data-op="all"><div class="si-hd">.*?<span class="si-why" data-signin-why> — a part of it can&#39;t be met</span><span class="si-gs" data-signin-gscore>0.0</span>`)
	if !g.MatchString(h) {
		t.Errorf("the password group isn't greyed out with its reason:\n%s", h)
	}
	if !strings.Contains(h, `<span class="si-chip si-unusable" data-signin-node data-depth="4" data-leaf="password">`) {
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

// TestPasswordActionCopy: the People page's password action says what
// the password is; password onboarding is offered only while the method
// is on (the overview's password_on).
func TestPasswordActionCopy(t *testing.T) {
	js := webAsset(t, "directory.js")
	for _, want := range []string{"Signs in to Portcullis only while Password is on", "(it is off now: Hub → Settings → Sign-in)",
		"'Set a password for ' + user + ' (signs them out). ' + passwordCopy()", "if (passwordOn()) {", "data-pw-onboard-off", "function passwordOn() { return !!(dir && dir.password_on); }"} {
		if !strings.Contains(js, want) {
			t.Errorf("directory.js lacks %q", want)
		}
	}
	if strings.Contains(js, "Fallback: set a password") {
		t.Error("the old password wording is left")
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
