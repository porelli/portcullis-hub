package httpapi

import (
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/web"
)

// Plan 3 Task 14: the file-sharing UI. The browser behaviour is checked
// against the harness (task-14-report.md); these tests pin the rules a
// browser check can't prove for every path.

func webAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(web.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestMyAppsFreshAuthOpener: the opener side of the fresh-auth popup
// (contract §5.1, F20), shared by My apps and the confirmation page
// (freshauth.js, fix round 1 of plan 4 Task 14). The authorize request
// carries every required parameter, the verifier comes from
// crypto.getRandomValues and its S256 challenge from crypto.subtle; a
// message is accepted only from this origin, from the popup the page
// opened, of type portcullis-fresh-auth, with the stored state and the
// flow's own ctx; the sessionStorage entry is deleted before the proof is
// handed on. myapps.js uses it and posts {code, code_verifier, nonce}.
func TestMyAppsFreshAuthOpener(t *testing.T) {
	fa := webAsset(t, "freshauth.js")
	for _, want := range []string{
		"crypto.getRandomValues(",
		"crypto.subtle.digest('SHA-256'",
		"['response_type', 'code']",
		"['scope', 'openid']",
		"['prompt', 'login']",
		"['max_age', '0']",
		"['code_challenge_method', 'S256']",
		"['code_challenge', challenge]",
		"['client_id', fa.client_id]",
		"['redirect_uri', fa.redirect_uri]",
		"['state', state]",
		"['nonce', nonce]",
		"ev.origin !== location.origin",
		"ev.source !== flow.popup",
		"flow.ctx !== pending.ctx",
		"/^https:\\/\\//i.test(",
		"location.protocol === 'http:'",
		"FLOW_DEADLINE_MS = 10 * 60 * 1000",
		"d.type !== 'portcullis-fresh-auth'",
		"d.state !== pending.state",
		"sessionStorage.removeItem(FA_KEY)",
		"f.h.proof({ code: d.code, code_verifier: pending.verifier, nonce: pending.nonce })",
		"window.addEventListener('pagehide', cancel)",
		"window.PortcullisFreshAuth = { start, cancel }",
	} {
		if !strings.Contains(fa, want) {
			t.Errorf("freshauth.js lacks %q", want)
		}
	}
	// The verifier: 64 random bytes base64url = 86 characters (43–128).
	if !strings.Contains(fa, "randomB64(64)") {
		t.Error("the PKCE verifier must be randomB64(64) (86 characters)")
	}
	// The stored entry is removed before the proof is handed on.
	if i, j := strings.LastIndex(fa, "sessionStorage.removeItem(FA_KEY)"), strings.Index(fa, "f.h.proof("); i < 0 || j < 0 || i > j {
		t.Error("sessionStorage must be cleared before the proof is handed on")
	}
	if n := strings.Count(fa, "sessionStorage.setItem("); n != 1 {
		t.Errorf("freshauth.js: sessionStorage.setItem used %d times, want exactly once (the PKCE state)", n)
	}
	// Sign-in methods (contract §5.1): no acr_values — which methods count
	// as fresh is the proof's rule (pc_fresh, §8).
	for _, bad := range []string{"localStorage", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "acr_values"} {
		if strings.Contains(fa, bad) {
			t.Errorf("freshauth.js uses %s", bad)
		}
	}

	js := webAsset(t, "myapps.js")
	for _, want := range []string{
		"PortcullisFreshAuth.start(el.maFreshAuth, {",
		"ctx: { instance: f.instance, key: f.key },",
		"proof: p => submitProof(f, p),",
		"JSON.stringify({ code: p.code, code_verifier: p.code_verifier, nonce: p.nonce })",
		"PortcullisFreshAuth.cancel()",
		"This is the only time it is shown.",
		"method: 'DELETE'",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("myapps.js lacks %q", want)
		}
	}
	// myapps.js no longer runs a flow of its own.
	for _, bad := range []string{"window.open(", "sessionStorage", "addEventListener('message'", "localStorage"} {
		if strings.Contains(js, bad) {
			t.Errorf("myapps.js uses %s: the flow is freshauth.js's", bad)
		}
	}
	// The password never reaches storage or a URL.
	if regexp.MustCompile(`sessionStorage\.setItem\([^)]*(password|pw)`).MatchString(js + fa) {
		t.Error("the password must never reach sessionStorage")
	}
	// No inline handlers in generated markup.
	if regexp.MustCompile(`\son[a-z]+=`).MatchString(js) {
		t.Error("myapps.js generates inline event handlers")
	}
	// people.html loads the opener before myapps.js.
	pg := webAsset(t, "people.html")
	if i, j := strings.Index(pg, `src="/static/freshauth.js"`), strings.Index(pg, `src="/static/myapps.js"`); i < 0 || j < 0 || i > j {
		t.Error("people.html must load freshauth.js before myapps.js")
	}
}

// TestDoctorFindingsFor (F50): doctor.js exports findingsFor next to the
// unchanged lineFor, and finding links (data-doctor-fp) open the Doctor tab
// at that finding.
func TestDoctorFindingsFor(t *testing.T) {
	js := webAsset(t, "doctor.js")
	for _, want := range []string{
		"async function findingsFor(instance, kinds)",
		"window.PortcullisDoctor = { render, badge, refreshBadge, lineFor, findingsFor }",
		"data-doctor-fp",
		"'<a href=\"#doctor\" class=\"doctor-line ' + cls + '\" data-doctor-goto=\"' + esc(instance) + '\">Doctor: ' + esc(parts.join(', ')) + '</a>'",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("doctor.js lacks %q", want)
		}
	}
}

// TestIndexFileSharingTab: an instance whose template has a person_secret
// option gets the File sharing tab on its page and its Marketplace card
// "No web page" (router-less); others don't. The tab's script reads the
// admin credentials API, revokes with DELETE, and the enable path asks
// to confirm lan_only ports on 0.0.0.0.
func TestIndexFileSharingTab(t *testing.T) {
	e := newCredEnv(t)
	_, b := doAs(t, e.hub, "root", "GET", "/", "")
	// The page's tabs: File sharing only for a person_secret template
	// (the catalog's settings options, as the tab's own loader reads).
	if !strings.Contains(b, `return PAGE_TABS.filter(([k]) => (k !== 'filesharing' || templateHasPersonSecret(inst.template)) && (k !== 'vpn' || templateHasVPN(inst.template)));`) ||
		!strings.Contains(b, `['filesharing', 'File sharing']`) || !strings.Contains(b, `return opts.some(o => o.type === 'person_secret');`) ||
		!strings.Contains(b, `case 'filesharing': loadFileSharing(id, pane); break;`) {
		t.Error("the instance page has no File sharing tab for person_secret templates")
	}
	var cat []map[string]any
	if r, body := doAs(t, e.hub, "root", "GET", "/api/templates", ""); r.StatusCode != 200 || json.Unmarshal([]byte(body), &cat) != nil {
		t.Fatalf("templates = %d", r.StatusCode)
	}
	secret := map[string]bool{}
	for _, c := range cat {
		m, _ := c["manifest"].(map[string]any)
		st, _ := m["settings"].(map[string]any)
		opts, _ := st["options"].([]any)
		for _, o := range opts {
			if om, _ := o.(map[string]any); om["type"] == "person_secret" {
				secret[c["id"].(string)] = true
			}
		}
	}
	if !secret["smbfixture"] {
		t.Error("smbfixture (person_secret) gets no File sharing tab")
	}
	if secret["grafana"] {
		t.Error("grafana (no person_secret) gets a File sharing tab")
	}
	if !strings.Contains(b, `data-no-web-page="smbfixture"`) {
		t.Error("router-less smbfixture lacks the No web page badge")
	}
	if strings.Contains(b, `data-no-web-page="grafana"`) {
		t.Error("grafana shows No web page")
	}
	for _, want := range []string{
		"'/api/instances/' + encodeURIComponent(id) + '/credentials'",
		"PortcullisDoctor.findingsFor(id, ['lan_only_exposed'])",
		"Docker-published ports bypass ufw.",
		"will listen on every interface of this server. Make sure your firewall or router blocks port ",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	if !regexp.MustCompile(`apiCall\([^;]*'/credentials/' \+ encodeURIComponent\(key\) \+ '/' \+ encodeURIComponent\(user\), 'DELETE'\)`).MatchString(b) {
		t.Error("the admin revoke must DELETE /api/instances/{id}/credentials/{key}/{user}")
	}
}
