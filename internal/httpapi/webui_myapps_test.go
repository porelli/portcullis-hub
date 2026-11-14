package httpapi

import (
	"strings"
	"testing"
)

// TestMyAppsCardJS: an app without settings is a bare card (no settings
// section); vpn_only shows a "VPN only" badge; no_access a "No access"
// one and no link.
func TestMyAppsCardJS(t *testing.T) {
	js := webAsset(t, "myapps.js")
	script := nodeEsc + jsBlock(t, js, "  function safeURL(u) {", "}\n") + jsBlock(t, js, "  function card(app) {", "\n  }\n") + `
const credHtml = () => '', entryHtml = () => '<div class="entry"></div>', reasonText = () => '', APPLIES = {};
console.log(JSON.stringify({
  bare: card({ id: 'plain', name: 'Plain', url: 'https://plain.example.org', values: [], entries: [], credentials: [] }),
  vpn: card({ id: 'plain', name: 'Plain', url: 'https://plain.example.org', vpn_only: true, values: [], entries: [], credentials: [] }),
  none: card({ id: 'e', name: 'E', url: '', no_access: true, values: [], entries: [{ key: 'k' }], credentials: [] }),
}));
`
	var got struct{ Bare, VPN, None string }
	nodeJSON(t, script, &got)
	if strings.Contains(got.Bare, "ma-values") || !strings.Contains(got.Bare, `href="https://plain.example.org"`) || strings.Contains(got.Bare, "VPN only") {
		t.Errorf("bare card: %s", got.Bare)
	}
	if !strings.Contains(got.VPN, "VPN only") {
		t.Errorf("vpn card: %s", got.VPN)
	}
	if !strings.Contains(got.None, "No access") || strings.Contains(got.None, "href=") || strings.Contains(got.None, "No web page") {
		t.Errorf("no-access card: %s", got.None)
	}
}
