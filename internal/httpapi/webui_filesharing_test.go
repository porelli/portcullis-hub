package httpapi

import (
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
// (contract §5.1, F20). The authorize request carries every required
// parameter, the verifier comes from crypto.getRandomValues and its S256
// challenge from crypto.subtle; a message is accepted only from this
// origin, of type portcullis-fresh-auth and with the stored state; the
// sessionStorage entry is deleted before the POST of {code, code_verifier,
// nonce}.
func TestMyAppsFreshAuthOpener(t *testing.T) {
	js := webAsset(t, "myapps.js")
	for _, want := range []string{
		"crypto.getRandomValues(",
		"crypto.subtle.digest('SHA-256'",
		"['response_type', 'code']",
		"['scope', 'openid']",
		"['prompt', 'login']",
		"['max_age', '0']",
		"['acr_values', 'hwk']",
		"['code_challenge_method', 'S256']",
		"['code_challenge', challenge]",
		"['client_id', fa.client_id]",
		"['redirect_uri', fa.redirect_uri]",
		"['state', state]",
		"['nonce', nonce]",
		"ev.origin !== location.origin",
		"d.type !== 'portcullis-fresh-auth'",
		"d.state !== pending.state",
		"sessionStorage.removeItem(FA_KEY)",
		"JSON.stringify({ code: d.code, code_verifier: pending.verifier, nonce: pending.nonce })",
		"method: 'DELETE'",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("myapps.js lacks %q", want)
		}
	}
	// The verifier: 64 random bytes base64url = 86 characters (43–128).
	if !strings.Contains(js, "randomB64(64)") {
		t.Error("the PKCE verifier must be randomB64(64) (86 characters)")
	}
	// The stored entry is removed before the code is posted.
	if i, j := strings.Index(js, "sessionStorage.removeItem(FA_KEY)"), strings.Index(js, "code_verifier: pending.verifier"); i < 0 || j < 0 || i > j {
		t.Error("sessionStorage must be cleared before the POST")
	}
	// The password is never stored anywhere but one closure, and never in
	// a URL.
	if strings.Contains(js, "localStorage") {
		t.Error("myapps.js must not use localStorage")
	}
	if n := strings.Count(js, "sessionStorage.setItem("); n != 1 {
		t.Errorf("sessionStorage.setItem used %d times, want exactly once (the PKCE state)", n)
	}
	if regexp.MustCompile(`sessionStorage\.setItem\([^)]*(password|pw)`).MatchString(js) {
		t.Error("the password must never reach sessionStorage")
	}
	// No inline handlers in generated markup.
	if regexp.MustCompile(`\son[a-z]+=`).MatchString(js) {
		t.Error("myapps.js generates inline event handlers")
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

// TestIndexFileSharingTab: an app whose template has a person_secret
// option gets the File sharing detail tab and "No web page" (router-less);
// others don't. The tab's script reads the admin credentials API, revokes
// with DELETE, and the enable path asks to confirm lan_only ports on
// 0.0.0.0.
func TestIndexFileSharingTab(t *testing.T) {
	e := newCredEnv(t)
	_, b := doAs(t, e.hub, "root", "GET", "/", "")
	if !strings.Contains(b, `data-dtab="filesharing" data-app="smbfixture"`) || !strings.Contains(b, `id="detail-filesharing-smbfixture"`) {
		t.Error("smbfixture has no File sharing tab")
	}
	if strings.Contains(b, `data-dtab="filesharing" data-app="grafana"`) {
		t.Error("grafana (no person_secret) has a File sharing tab")
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
