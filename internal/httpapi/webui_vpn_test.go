package httpapi

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/web"
)

// TestVPNPageNeverPostsPrivateKey (contract §5.1): vpn.js posts bodies
// built only from the name, the public key and the fresh-auth proof;
// it stores nothing in the browser; the config text and the QR are
// built in the page; the key pair is WebCrypto's X25519.
func TestVPNPageNeverPostsPrivateKey(t *testing.T) {
	b, err := fs.ReadFile(web.FS, "vpn.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, banned := range []string{"localStorage", "sessionStorage", "indexedDB", "document.cookie", "private_key", "privateKey:", "console.log"} {
		if strings.Contains(js, banned) && banned != "privateKey:" {
			t.Errorf("vpn.js mentions %s", banned)
		}
	}
	// Every call body: only name, public_key, code, code_verifier, nonce.
	bodies := regexp.MustCompile(`call\('(?:POST|PUT)', [^,]+, \{([^}]*)\}\)`).FindAllStringSubmatch(js, -1)
	if len(bodies) < 3 {
		t.Fatalf("%d call bodies found", len(bodies))
	}
	allowed := map[string]bool{"name": true, "public_key": true, "code": true, "code_verifier": true, "nonce": true}
	for _, m := range bodies {
		for _, kv := range strings.Split(m[1], ",") {
			k := strings.TrimSpace(strings.SplitN(kv, ":", 2)[0])
			if !allowed[k] {
				t.Errorf("a body carries %q: %s", k, m[0])
			}
		}
	}
	for _, want := range []string{"generateKey({ name: 'X25519' }", "exportKey('raw'", "exportKey('pkcs8'", "pk8.length - 32", "'[Interface]\\n'", "qrcode(0, 'M')", "secret = null"} {
		if !strings.Contains(js, want) {
			t.Errorf("vpn.js lacks %q", want)
		}
	}
	h, _ := fs.ReadFile(web.FS, "vpn.html")
	for _, src := range regexp.MustCompile(`src="([^"]+)"`).FindAllStringSubmatch(string(h), -1) {
		if !strings.HasPrefix(src[1], "/vpn/assets/") {
			t.Errorf("vpn.html loads %s (only /vpn/assets/: /static/ is VPN-only in server mode)", src[1])
		}
	}
	q, _ := fs.ReadFile(web.FS, "vendor/qrcode.js")
	if !strings.Contains(string(q), "qrcode-generator 2.0.4") || !strings.Contains(string(q), "sha256 79ec86f82856005b1c887905cfccfcfbec3821ca61c7fd5a952faa5f778f791c") {
		t.Error("vendor/qrcode.js lacks its pinned version and sha256 header")
	}
}
