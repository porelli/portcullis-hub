package httpapi

import (
	"os"
	"strings"
	"testing"
)

// DNS hardening Task 11: the DNS panel per added domain and the main
// domain's read-only panel (contract §12.3). The browser behaviour is
// checked against the harness; these tests pin the rules a browser check
// can't prove for every path.

// TestDNSPanelAsset: dns.js reads the plan routes, offers Fix only for
// fix: auto, signs only behind the exact confirmation, copies DS values,
// escapes every value, never turns signing off, and the main domain's fix
// is the server command.
func TestDNSPanelAsset(t *testing.T) {
	js := webAsset(t, "dns.js")
	for _, want := range []string{
		"'/api/domains/' + encodeURIComponent(name) + '/dns'",
		"/api/dns/main",
		"fix === 'auto'",
		"'Turns on signing for the whole zone '",
		"navigator.clipboard.writeText(",
		"escapeHtml(",
		"./portcullis dns setup",
		"'/dns/apply'",
		"'/dnssec'",
		"{ enable: true }",
		"refresh=1",
		"data-dns-item",
		"data-dns-fix",
		"data-dnssec-sign",
		"would issue: ",
		"CA-only",
		"window.PortcullisDNS",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("dns.js lacks %q", want)
		}
	}
	for _, bad := range []string{`enable": false`, "enable: false", "disable", "innerText =", ".outerHTML ="} {
		if strings.Contains(js, bad) {
			t.Errorf("dns.js contains %q", bad)
		}
	}
}

// TestDNSPanelEmbedded: index.html loads dns.js (next to folders.js), the
// Hub embeds it, and the people listener never serves it.
func TestDNSPanelEmbedded(t *testing.T) {
	html := webAsset(t, "index.html")
	if !strings.Contains(html, `<script src="/static/dns.js"></script>`) {
		t.Error("index.html doesn't load /static/dns.js")
	}
	src, err := os.ReadFile("../../web/web.go")
	if err != nil {
		t.Fatal(err)
	}
	embed := ""
	for _, l := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(l, "//go:embed index.html") {
			embed = l
		}
	}
	if !strings.Contains(embed+" ", " dns.js ") {
		t.Errorf("web.go's embed line lacks dns.js: %q", embed)
	}
	if peopleStatic["dns.js"] {
		t.Error("dns.js is served on the people listener")
	}
	// The Domains table gets a DNS button per row and a hidden panel row.
	for _, want := range []string{"data-domain-dns=", "data-dns-row=", "PortcullisDNS.mount("} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
}

// TestMainDomainRowReadOnly: the main domain's block mounts the panel with
// main: true (no Fix and no signing buttons, dns.js).
func TestMainDomainRowReadOnly(t *testing.T) {
	html := webAsset(t, "index.html")
	if !strings.Contains(html, "main: true") {
		t.Error("index.html doesn't mount the main domain's panel with main: true")
	}
	js := webAsset(t, "dns.js")
	// Fix and signing are both gated on !main.
	if !strings.Contains(js, "!opts.main && it.fix === 'auto'") || !strings.Contains(js, "!opts.main && d.provider_can_sign && d.state === 'unsigned'") {
		t.Error("dns.js doesn't gate Fix / signing on !main")
	}
}
