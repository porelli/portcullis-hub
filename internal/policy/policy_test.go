package policy

import (
	"testing"

	"github.com/portcullis/hub/internal/signin"
)

// TestTierFourOptions: the four TLS options of contract §5 "TLS tier per
// host", from compiled rules (sign-in part 2). protected@file trusts only
// the YubiKey CA, so it is kept for rules every alternative of which needs
// a YubiKey certificate; protected-any@file for rules every alternative of
// which needs some certificate; public exceptions turn both into
// authaware@file. (An auth.method: mtls app is protected@file before any
// rule: the Hub's access.tier, TestMTLSAppAlwaysProtected.)
func TestTierFourOptions(t *testing.T) {
	on := defaultOn()
	on[signin.BrowserCert] = true
	l := func(m string) signin.Node { return signin.Node{Leaf: m} }
	g := func(op string, items ...signin.Node) signin.Node { return signin.Node{Op: op, Items: items} }
	standard := signin.Node{}
	for _, b := range signin.Builtins() {
		if b.ID == "standard" {
			standard = b.Rule
		}
	}
	for _, c := range []struct {
		name string
		rule signin.Node
		want string
	}{
		{"any[yubikey_cert]", g("any", l("yubikey_cert")), TierProtected},
		{"all[yubikey_cert, security_key]", g("all", l("yubikey_cert"), l("security_key")), TierProtected},
		{"any[all[yubikey_cert, password], yubikey_cert]", g("any", g("all", l("yubikey_cert"), l("security_key")), l("yubikey_cert")), TierProtected},
		{"any[browser_cert]", g("any", l("browser_cert")), TierProtectedAny},
		{"any[yubikey_cert, browser_cert]", g("any", l("yubikey_cert"), l("browser_cert")), TierProtectedAny},
		{"any[family:certificate]", g("any", l("family:certificate")), TierProtectedAny},
		{"all[browser_cert, security_key]", g("all", l("browser_cert"), l("security_key")), TierProtectedAny},
		{"standard", standard, TierAuthAware},
		{"any[security_key, browser_cert]", g("any", l("security_key"), l("browser_cert")), TierAuthAware},
		{"any[family:passkey]", g("any", l("family:passkey")), TierPublic},
	} {
		comp, err := signin.Compile(c.rule, on)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := Tier(&comp, on, false); got != c.want {
			t.Errorf("%s: Tier = %s, want %s", c.name, got, c.want)
		}
		want := c.want
		if want == TierProtected || want == TierProtectedAny {
			want = TierAuthAware
		}
		if got := Tier(&comp, on, true); got != want {
			t.Errorf("%s with public exceptions: Tier = %s, want %s", c.name, got, want)
		}
	}
	// With browser_cert off the certificate family is YubiKey-only again.
	off := defaultOn()
	comp, err := signin.Compile(g("any", l("family:certificate")), off)
	if err != nil {
		t.Fatal(err)
	}
	if got := Tier(&comp, off, false); got != TierProtected {
		t.Errorf("family:certificate, browser_cert off: %s", got)
	}
	for in, want := range map[string]string{TierProtected: TierAuthAware, TierProtectedAny: TierAuthAware, TierAuthAware: TierAuthAware, TierPublic: TierPublic} {
		if got := HostTier(in, true); got != want {
			t.Errorf("HostTier(%s, true) = %s, want %s", in, got, want)
		}
		if got := HostTier(in, false); got != in {
			t.Errorf("HostTier(%s, false) = %s", in, got)
		}
	}
}
