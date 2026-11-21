package httpapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/doctor"
)

// Doctor finding links (contract §14.5 "Links"): the page shows a link
// only when its hash matches doctor.LinkHashPattern, and every hash the
// doctor can build is a route of routeHash's ROUTES.

// TestDoctorLinkPattern: doctor.js's LINK_RE is doctor.LinkHashPattern,
// as a JS literal; every page and tab link routes; the card renders the
// link as an escaped <a href> and nothing else.
func TestDoctorLinkPattern(t *testing.T) {
	js := webAsset(t, "doctor.js")
	want := "const LINK_RE = /" + strings.ReplaceAll(doctor.LinkHashPattern, "/", `\/`) + "/;"
	if !strings.Contains(js, want) {
		t.Errorf("doctor.js lacks %s", want)
	}
	for _, gone := range []string{"data-dr-open", "openSettingAt", "openAppTab"} {
		if strings.Contains(js, gone) || strings.Contains(webAsset(t, "index.html"), gone) {
			t.Errorf("%q is still in the page", gone)
		}
	}
	if !strings.Contains(js, `'<a class="btn btn-secondary btn-sm" data-dr-link href="' + esc(lk.hash) + '">' + esc(lk.label) + '</a>'`) {
		t.Error("the link isn't an escaped <a href>")
	}
	_, routes := hubRoutes(t)
	var hashes []string
	for _, p := range []string{doctor.PageSettingsSignIn, doctor.PageSettingsNetwork, doctor.PageSettingsStorage, doctor.PageSettingsMail,
		doctor.PageSettingsAI, doctor.PageSettingsServers, doctor.PageSettingsSSH, doctor.PageSettingsSources, doctor.PageAccessSSH,
		doctor.PageAccessSSHHosts, doctor.PageAccessSSHGroups, doctor.PageAccessSSHGrants, doctor.PageAccessSSHCerts, doctor.PageAccessVPN,
		doctor.PageUsage, doctor.PageUsageStorage} {
		hashes = append(hashes, doctor.Link{Page: p}.Route())
	}
	for _, tab := range []string{"overview", "settings", "groups", "filesharing", "logs", "usage", "backups", "ai", "vpn", "mail", "expert"} {
		hashes = append(hashes, doctor.Link{Instance: "stalwart", Tab: tab}.Route())
	}
	hashes = append(hashes, doctor.Link{Instance: "grafana", Option: "smtp_host"}.Route())
	re := regexp.MustCompile(doctor.LinkHashPattern)
	for _, h := range hashes {
		if h == "" || !re.MatchString(h) {
			t.Errorf("hash %q doesn't match the pattern", h)
			continue
		}
		ok := false
		for _, r := range routes {
			if r.MatchString(h[1:]) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("#%s matches no route", h[1:])
		}
	}
}

// TestDoctorLinkOfNode: linkOf in node: a valid hash and its label; a
// hostile or malformed one (javascript:, an attribute break, another
// origin, a route outside the allowlist, a non-string) shows no link.
func TestDoctorLinkOfNode(t *testing.T) {
	js := webAsset(t, "doctor.js")
	i, j := strings.Index(js, "  const LINK_RE = "), strings.Index(js, "\n  function card(f) {")
	if i < 0 || j < i {
		t.Fatal("linkOf isn't in doctor.js")
	}
	cases := map[string]any{
		"#apps/stalwart/mail":                          map[string]any{"hash": "#apps/stalwart/mail", "label": "Open Mail tab"},
		"#apps/grafana/settings/smtp_host":             map[string]any{"hash": "#apps/grafana/settings/smtp_host", "label": "Open setting"},
		"#apps/grafana":                                map[string]any{"hash": "#apps/grafana", "label": "Open app"},
		"#apps/grafana/overview":                       map[string]any{"hash": "#apps/grafana/overview", "label": "Open app"},
		"#settings/mail":                               map[string]any{"hash": "#settings/mail", "label": "Open Settings → Mail"},
		"#access/ssh/hosts":                            map[string]any{"hash": "#access/ssh/hosts", "label": "Open Access → SSH hosts"},
		"#usage/storage":                               map[string]any{"hash": "#usage/storage", "label": "Open Usage → Storage"},
		"javascript:alert(1)":                          nil,
		`#apps/a" onmouseover="alert(1)`:               nil,
		"https://evil.example/#apps/a":                 nil,
		"//evil.example/":                              nil,
		"#settings/domains":                            nil,
		"#apps/Grafana":                                nil,
		"#apps/a/settings/<img src=x>":                 nil,
		"#apps/a/bogus":                                nil,
		"#apps/a/b/c/d":                                nil,
		"#app/grafana/settings":                        nil,
		"":                                             nil,
		"#settings/mail\n":                             nil,
		"#marketplace?filter=mail":                     nil,
		"#access/signins?user=alice":                   nil,
		"#apps/a/settings/" + strings.Repeat("x", 129): nil,
	}
	keys := make([]string, 0, len(cases))
	for k := range cases {
		keys = append(keys, k)
	}
	b, _ := json.Marshal(keys)
	script := js[i:j] + "\nconst out = " + string(b) + ".map(h => linkOf({ link: { hash: h } }));\n" +
		"out.push(linkOf({ link: { hash: 42 } }), linkOf({ link: null }), linkOf({}));\nprocess.stdout.write(JSON.stringify(out));\n"
	var got []any
	if err := json.Unmarshal([]byte(nodeEval(t, script)), &got); err != nil || len(got) != len(keys)+3 {
		t.Fatalf("linkOf = %v (%v)", got, err)
	}
	for n, k := range keys {
		g, _ := json.Marshal(got[n])
		w, _ := json.Marshal(cases[k])
		if string(g) != string(w) {
			t.Errorf("linkOf(%q) = %s, want %s", k, g, w)
		}
	}
	for _, g := range got[len(keys):] {
		if g != nil {
			t.Errorf("a non-string or missing link gave %v", g)
		}
	}
}
