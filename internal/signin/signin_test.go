package signin

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// onSet builds a switched-on map from method ids.
func onSet(ms ...Method) map[Method]bool {
	on := map[Method]bool{}
	for _, m := range ms {
		on[m] = true
	}
	return on
}

// defaultOn is the starting state: every method but password and browser_cert.
func defaultOn() map[Method]bool {
	return onSet(PasskeySynced, PasskeyDevice, SecurityKey, YubiKeyCert)
}

func leaf(s string) Node       { return Node{Leaf: s} }
func all(items ...Node) Node   { return Node{Op: OpAll, Items: items} }
func anyOf(items ...Node) Node { return Node{Op: OpAny, Items: items} }
func leaves(ss ...string) (n []Node) {
	for _, s := range ss {
		n = append(n, leaf(s))
	}
	return n
}

func builtin(t *testing.T, id string) Node {
	t.Helper()
	for _, b := range Builtins() {
		if b.ID == id {
			return b.Rule
		}
	}
	t.Fatalf("no built-in %q", id)
	return Node{}
}

func mustCompile(t *testing.T, n Node, on map[Method]bool) Node {
	t.Helper()
	c, err := Compile(n, on)
	if err != nil {
		t.Fatalf("Compile(%s): %v", js(n), err)
	}
	return c
}

func js(n Node) string {
	b, err := json.Marshal(n)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

// nestedRule is the contract's score example.
func nestedRule() Node {
	return all(
		anyOf(
			all(leaves("password", "security_key")...),
			all(leaves("family:yubikey", "family:passkey")...),
		),
		leaf("family:certificate"),
	)
}

func TestScoreSpecExamples(t *testing.T) {
	withPassword := defaultOn()
	withPassword[Password] = true
	withCert := defaultOn()
	withCert[BrowserCert] = true

	cases := []struct {
		name string
		rule Node
		on   map[Method]bool
		want string
	}{
		{"basic", builtin(t, "basic"), withPassword, "1.0 / 5"},
		{"standard", builtin(t, "standard"), defaultOn(), "2.5 / 5"},
		{"strong", builtin(t, "strong"), defaultOn(), "3.5 / 5"},
		{"yubikey-and-certificate", builtin(t, "yubikey-and-certificate"), defaultOn(), "4.4 / 5"},
		{"family example", anyOf(all(leaves("password", "family:passkey")...), leaf("security_key")), withPassword, "2.9 / 5"},
		{"nested", nestedRule(), defaultOn(), "4.4 / 5"},
		// browser_cert isn't available yet: switched on, it still counts as off.
		{"nested, browser cert on but not available", nestedRule(), withCert, "4.4 / 5"},
		{"family scores its weakest member", all(leaves("security_key", "family:passkey")...), defaultOn(), "3.9 / 5"},
		{"basic, password off: its alternative doesn't count", builtin(t, "basic"), defaultOn(), "2.5 / 5"},
		{"no way in", all(leaf("password")), defaultOn(), "0.0 / 5"},
	}
	for _, c := range cases {
		if got := ScoreOf(c.rule, c.on).String(); got != c.want {
			t.Errorf("%s: score %q, want %q", c.name, got, c.want)
		}
	}

	fam := ScoreOf(anyOf(all(leaves("password", "family:passkey")...), leaf("security_key")), withPassword)
	if want := "its weakest way in: a password and a passkey"; fam.Reason != want {
		t.Errorf("family example reason %q, want %q", fam.Reason, want)
	}

	eight := all(leaves("yubikey_cert", "security_key", "passkey_device", "passkey_synced",
		"password", "family:passkey", "family:yubikey", "family:certificate")...)
	s := ScoreOf(eight, withPassword)
	if s.Tenths != 50 {
		t.Errorf("8 leaves: tenths %d, want 50 (4.0 + 0.4×7 capped)", s.Tenths)
	}
	if !strings.HasSuffix(s.Reason, ", capped at 5") || !strings.HasPrefix(s.Reason, "its strongest part (a YubiKey certificate) + 0.4 for each of 7 more") {
		t.Errorf("8 leaves reason %q", s.Reason)
	}
	if s.String() != "5.0 / 5" {
		t.Errorf("8 leaves string %q", s.String())
	}

	reasons := []struct {
		name string
		rule Node
		want string
	}{
		{"two-item all", builtin(t, "yubikey-and-certificate"), "its strongest part (a YubiKey certificate) + 0.4 for 1 more part"},
		{"three-item all", all(leaves("yubikey_cert", "security_key", "passkey_device")...), "its strongest part (a YubiKey certificate) + 0.4 for each of 2 more"},
		{"one-item all of a group", all(anyOf(leaves("security_key", "yubikey_cert")...)), "its weakest way in: a YubiKey touch"},
		{"one-item all of a leaf", all(leaf("security_key")), "its only way in: a YubiKey touch"},
		{"one-item any of an all", anyOf(all(leaves("security_key", "yubikey_cert")...)), "its strongest part (a YubiKey certificate) + 0.4 for 1 more part"},
	}
	for _, c := range reasons {
		if got := ScoreOf(c.rule, defaultOn()).Reason; got != c.want {
			t.Errorf("%s: reason %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBrowserCertUnavailable(t *testing.T) {
	on := defaultOn()
	on[BrowserCert] = true
	if _, err := Compile(anyOf(leaf("browser_cert")), on); !errors.Is(err, ErrUnmeetable) {
		t.Errorf("browser_cert switched on but unavailable compiled: %v", err)
	}
	c := mustCompile(t, anyOf(leaf("family:certificate")), on)
	if js(c) != `{"op":"any","items":[{"op":"any","items":["yubikey_cert"]}]}` {
		t.Errorf("certificate family with browser_cert unavailable: %s", js(c))
	}
	if got := Needs(builtin(t, "standard"), on); len(got) != 0 {
		t.Errorf("Needs(standard) = %v", got)
	}
}

func TestSentenceNested(t *testing.T) {
	want := "(a password and a YubiKey touch, or a YubiKey and a passkey) and a certificate"
	if got := Sentence(nestedRule()); got != want {
		t.Errorf("Sentence = %q, want %q", got, want)
	}
	if got := Sentence(builtin(t, "strong")); got != "a YubiKey touch or a YubiKey certificate" {
		t.Errorf("strong sentence %q", got)
	}
	// Single-item groups are looked through: the brackets still show that
	// the passkeys are alternatives of each other, not of the certificate.
	u, err := Usable(all(leaf("family:certificate"), anyOf(anyOf(leaves("passkey_synced", "passkey_device")...), leaf("password"))), defaultOn())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Sentence(u), "a certificate and (a synced passkey or a device-bound passkey)"; got != want {
		t.Errorf("password off: %q, want %q", got, want)
	}
	if got, want := Sentence(all(leaf("security_key"), all(anyOf(leaves("passkey_synced", "passkey_device")...)))), "a YubiKey touch and (a synced passkey or a device-bound passkey)"; got != want {
		t.Errorf("all[sk, all[any[spk,dpk]]]: %q, want %q", got, want)
	}
	if got, want := Sentence(anyOf(all(leaves("password", "security_key")...), anyOf(all(leaves("yubikey_cert", "passkey_device")...)))), "a password and a YubiKey touch, or a YubiKey certificate and a device-bound passkey"; got != want {
		t.Errorf("any with a wrapped all: %q, want %q", got, want)
	}
	if got := Sentence(anyOf(leaf("webauthn"), leaf("security_key"))); got != "an unknown method or a YubiKey touch" {
		t.Errorf("unknown leaf: %q", got)
	}
}

func TestValidateLimits(t *testing.T) {
	nine := []string{"password", "passkey_synced", "browser_cert", "passkey_device", "security_key",
		"yubikey_cert", "family:passkey", "family:yubikey", "family:certificate"}
	ok := anyOf(all(anyOf(leaves("password")...)))
	if err := Validate(ok); err != nil {
		t.Errorf("depth 3: %v", err)
	}
	cases := map[string]Node{
		"depth 4":    anyOf(all(anyOf(all(leaves("password")...)))),
		"9 items":    anyOf(leaves(nine...)...),
		"17 leaves":  anyOf(all(leaves(nine[:8]...)...), all(leaves(nine[1:]...)...), leaf("yubikey_cert")),
		"unknown":    anyOf(leaf("webauthn")),
		"leaf top":   leaf("security_key"),
		"no items":   anyOf(),
		"bad op":     {Op: "xor", Items: leaves("password")},
		"family:any": anyOf(leaf("family:password")),
	}
	for name, n := range cases {
		if err := Validate(n); err == nil {
			t.Errorf("%s: Validate accepted %s", name, js(n))
		}
	}
	// 16 leaves is the limit, not an error.
	sixteen := anyOf(all(leaves(nine[:8]...)...), all(leaves(nine[1:]...)...))
	if err := Validate(sixteen); err != nil {
		t.Errorf("16 leaves: %v", err)
	}
}

func TestValidateDuplicateSiblings(t *testing.T) {
	err := Validate(all(leaves("security_key", "yubikey_cert", "security_key")...))
	if err == nil || err.Error() != "security_key is listed twice in one group" {
		t.Errorf("duplicate leaf: %v", err)
	}
	g := anyOf(leaves("passkey_synced", "passkey_device")...)
	if err := Validate(all(g, leaf("security_key"), g)); err == nil || !strings.HasSuffix(err.Error(), " is listed twice in one group") {
		t.Errorf("duplicate group: %v", err)
	}
	// Not duplicates: the same leaf in two groups, a reordered group, and
	// overlap through a family (a known limit of the score formula).
	for _, n := range []Node{
		anyOf(all(leaves("security_key", "yubikey_cert")...), all(leaves("security_key", "passkey_device")...)),
		anyOf(all(leaves("security_key", "yubikey_cert")...), all(leaves("yubikey_cert", "security_key")...)),
		all(leaves("family:passkey", "passkey_synced")...),
	} {
		if err := Validate(n); err != nil {
			t.Errorf("%s: %v", js(n), err)
		}
	}
}

func TestValidateCompiled(t *testing.T) {
	for _, b := range Builtins() {
		if c, err := Compile(b.Rule, onSet(Methods...)); err == nil {
			if err := ValidateCompiled(c); err != nil {
				t.Errorf("%s: %v", b.ID, err)
			}
		}
	}
	if err := ValidateCompiled(mustCompile(t, nestedRule(), defaultOn())); err != nil {
		t.Errorf("nested (depth 4): %v", err)
	}
	for name, n := range map[string]Node{
		"family":   anyOf(leaf("family:passkey")),
		"unknown":  anyOf(leaf("webauthn")),
		"depth 5":  anyOf(all(anyOf(all(anyOf(leaf("security_key")))))),
		"empty":    anyOf(leaf("security_key"), all()),
		"leaf top": leaf("security_key"),
	} {
		if ValidateCompiled(n) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestNodeJSONStrict(t *testing.T) {
	var n Node
	good := `{"op":"any","items":["security_key",{"items":["yubikey_cert"],"op":"all"}]}`
	if err := json.Unmarshal([]byte(good), &n); err != nil {
		t.Fatalf("good: %v", err)
	}
	if got := js(n); got != `{"op":"any","items":["security_key",{"op":"all","items":["yubikey_cert"]}]}` {
		t.Errorf("round trip %s", got)
	}
	for _, bad := range []string{
		`{"op":"any","items":["a"],"x":1}`,
		`{"op":"any"}`,
		`{"items":["a"]}`,
		`{"op":"one","items":["a"]}`,
		`{"op":"any","op":"all","items":["a"]}`,
		`{"op":"any","items":null}`,
		`{"op":"any","items":[""]}`,
		`{"op":"any","items":[1]}`,
		`["a"]`,
		`{"op":"any","items":["a"]} {}`,
		`null`,
	} {
		var m Node
		if err := json.Unmarshal([]byte(bad), &m); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestCompileRefusesSwitchedOffLeaf(t *testing.T) {
	_, err := Compile(all(leaf("password")), defaultOn())
	if !errors.Is(err, ErrUnmeetable) {
		t.Errorf("all[password] with password off: %v, want ErrUnmeetable", err)
	}
	// An "any" group drops the switched-off alternative and stays meetable.
	c := mustCompile(t, anyOf(leaf("password"), leaf("security_key")), defaultOn())
	if js(c) != `{"op":"any","items":["security_key"]}` {
		t.Errorf("any[password, security_key] with password off compiled to %s", js(c))
	}
	if Satisfied(c, onSet(Password)) {
		t.Error("a dropped password alternative still met")
	}
	// An "all" group with a part that can't be met can't be met, and inside
	// an "any" it is dropped as a whole.
	if _, err := Compile(all(leaf("security_key"), leaf("password")), defaultOn()); !errors.Is(err, ErrUnmeetable) {
		t.Errorf("all[security_key, password] with password off: %v, want ErrUnmeetable", err)
	}
	c = mustCompile(t, anyOf(all(leaves("password", "security_key")...), leaf("yubikey_cert")), defaultOn())
	if js(c) != `{"op":"any","items":["yubikey_cert"]}` {
		t.Errorf("unmeetable all inside any compiled to %s", js(c))
	}
	if Satisfied(c, onSet(SecurityKey)) {
		t.Error("the dropped all group's other part met the rule alone")
	}
	_, err = Compile(anyOf(leaf("password"), leaf("family:certificate")), onSet(PasskeySynced))
	if !errors.Is(err, ErrUnmeetable) {
		t.Errorf("any with no alternative left: %v, want ErrUnmeetable", err)
	}
	_, err = Compile(anyOf(leaf("family:passkey")), onSet(YubiKeyCert))
	if !errors.Is(err, ErrUnmeetable) {
		t.Errorf("family with no member on: %v, want ErrUnmeetable", err)
	}
	if _, err := Compile(anyOf(leaf("webauthn")), defaultOn()); err == nil || errors.Is(err, ErrUnmeetable) {
		t.Errorf("unknown leaf: %v, want a validation error", err)
	}
	// Whatever the switches, a compiled rule names only switched-on methods.
	for _, rule := range []Node{builtin(t, "basic"), builtin(t, "standard"), builtin(t, "strong"),
		builtin(t, "yubikey-and-certificate"), nestedRule()} {
		for mask := 0; mask < 1<<len(Methods); mask++ {
			on := maskOn(mask)
			c, err := Compile(rule, on)
			if err != nil {
				if !errors.Is(err, ErrUnmeetable) {
					t.Fatalf("%s: %v", js(rule), err)
				}
				continue
			}
			for _, l := range compiledLeaves(c) {
				if !on[Method(l)] {
					t.Fatalf("%s with %v compiled to %s", js(rule), on, js(c))
				}
			}
		}
	}
}

func maskOn(mask int) map[Method]bool {
	on := map[Method]bool{}
	for i, m := range Methods {
		if mask&(1<<i) != 0 {
			on[m] = true
		}
	}
	return on
}

func TestUnusable(t *testing.T) {
	on := defaultOn()
	if got := Unusable(builtin(t, "standard"), on); got != nil {
		t.Errorf("standard: %v, want nil", got)
	}
	if got := Unusable(builtin(t, "basic"), on); len(got) != 1 || !slices.Equal(got[0], Path{2}) {
		t.Errorf("basic, password off: %v, want [[2]]", got)
	}
	// The nested rule with password off: the all[password, security_key]
	// alternative, listed once (its items are not).
	if got := Unusable(nestedRule(), on); len(got) != 1 || !slices.Equal(got[0], Path{0, 0}) {
		t.Errorf("nested, password off: %v, want [[0 0]]", got)
	}
	// A rule with no way in lists the top group's parts that block it.
	got := Unusable(all(leaf("security_key"), leaf("family:certificate")), onSet(SecurityKey))
	if len(got) != 1 || !slices.Equal(got[0], Path{1}) {
		t.Errorf("all with an unmeetable part: %v, want [[1]]", got)
	}
	u, err := Usable(builtin(t, "basic"), on)
	if err != nil || Sentence(u) != "a passkey or a certificate" {
		t.Errorf("Usable(basic) sentence %q, %v", Sentence(u), err)
	}
}

func TestCompileFamilySkipsOffMembers(t *testing.T) {
	got := mustCompile(t, anyOf(leaf("family:certificate")), defaultOn())
	if want := `{"op":"any","items":[{"op":"any","items":["yubikey_cert"]}]}`; js(got) != want {
		t.Errorf("compiled %s, want %s", js(got), want)
	}
	std := mustCompile(t, builtin(t, "standard"), defaultOn())
	if want := `{"op":"any","items":[{"op":"any","items":["passkey_synced","passkey_device","security_key"]},{"op":"any","items":["yubikey_cert"]}]}`; js(std) != want {
		t.Errorf("standard compiled %s, want the contract's %s", js(std), want)
	}
}

func TestFamiliesNeverContainPassword(t *testing.T) {
	for _, fam := range []string{"family:passkey", "family:yubikey", "family:certificate"} {
		for mask := 0; mask < 1<<len(Methods); mask++ {
			on := map[Method]bool{}
			for i, m := range Methods {
				if mask&(1<<i) != 0 {
					on[m] = true
				}
			}
			for _, rule := range []Node{anyOf(leaf(fam)), all(leaf(fam))} {
				c, err := Compile(rule, on)
				if err != nil {
					continue
				}
				if slices.Contains(compiledLeaves(c), string(Password)) {
					t.Fatalf("%s with %v compiled to %s", fam, on, js(c))
				}
				if Satisfied(c, onSet(Password)) {
					t.Fatalf("%s with %v met by a password", fam, on)
				}
			}
		}
	}
}

func compiledLeaves(n Node) []string {
	if n.Op == "" {
		return []string{n.Leaf}
	}
	var out []string
	for _, it := range n.Items {
		out = append(out, compiledLeaves(it)...)
	}
	return out
}

func TestSecurityKeyRuleRefusesDeviceBound(t *testing.T) {
	strong := mustCompile(t, builtin(t, "strong"), defaultOn())
	if Satisfied(strong, onSet(PasskeyDevice, PasskeySynced)) {
		t.Error("strong met by a device-bound and a synced passkey")
	}
	if !Satisfied(strong, onSet(SecurityKey)) {
		t.Error("strong not met by a security key")
	}
}

func TestImpliesAndNeeds(t *testing.T) {
	on := defaultOn()
	strong := mustCompile(t, builtin(t, "strong"), on)
	standard := mustCompile(t, builtin(t, "standard"), on)
	if !Implies(strong, standard) {
		t.Error("Implies(strong, standard) false")
	}
	if Implies(standard, strong) {
		t.Error("Implies(standard, strong) true")
	}
	// Needs = the methods whose switch-off would leave the rule with no way
	// in. Standard with browser_cert off: passkeys still let people in.
	if got := Needs(builtin(t, "standard"), on); len(got) != 0 {
		t.Errorf("Needs(standard, browser_cert off) = %v, want []", got)
	}
	withCert := defaultOn()
	withCert[BrowserCert] = true
	if got := Needs(builtin(t, "standard"), withCert); len(got) != 0 {
		t.Errorf("Needs(standard, browser_cert on) = %v, want []", got)
	}
	// Strong keeps a way in when either of its two methods goes.
	if got := Needs(builtin(t, "strong"), on); len(got) != 0 {
		t.Errorf("Needs(strong) = %v, want []", got)
	}
	if got := Needs(builtin(t, "yubikey-and-certificate"), on); !slices.Equal(got, []Method{SecurityKey, YubiKeyCert}) {
		t.Errorf("Needs(yubikey-and-certificate) = %v", got)
	}
	if got := Needs(anyOf(leaf("family:certificate")), on); !slices.Equal(got, []Method{YubiKeyCert}) {
		t.Errorf("Needs(any[family:certificate]) = %v, want [yubikey_cert]", got)
	}
	if got := Needs(nestedRule(), on); !slices.Equal(got, []Method{YubiKeyCert}) {
		t.Errorf("Needs(nested, password off) = %v, want [yubikey_cert]", got)
	}
	if got := Needs(all(leaf("password")), on); len(got) != 0 {
		t.Errorf("Needs of a rule that can't be met now = %v, want []", got)
	}
}

func TestNeedsCertificate(t *testing.T) {
	on := defaultOn()
	if !NeedsCertificate(mustCompile(t, all(leaves("yubikey_cert", "security_key")...), on)) {
		t.Error("all[yubikey_cert, security_key] doesn't need a certificate")
	}
	if NeedsCertificate(mustCompile(t, builtin(t, "strong"), on)) {
		t.Error("strong needs a certificate")
	}
}

func TestCheckPassword(t *testing.T) {
	if err := CheckPassword("alice", "short"); err == nil {
		t.Error("short accepted")
	}
	if err := CheckPassword("alice-wonderland", "Alice-Wonderland"); err == nil {
		t.Error("username accepted")
	}
	if err := CheckPassword("alice", "password1234"); err == nil {
		t.Error("listed password accepted")
	}
	if err := CheckPassword("alice", "PASSWORD1234"); err == nil {
		t.Error("listed password in capitals accepted")
	}
	if err := CheckPassword("alice", strings.Repeat("x", 129)); err == nil {
		t.Error("129 characters accepted")
	}
	if err := CheckPassword("alice", "k3#Tq9vLz!wR"); err != nil {
		t.Errorf("12 random: %v", err)
	}
	if err := CheckPassword("alice", strings.Repeat("é", 12)); err != nil {
		t.Errorf("12 runes: %v", err)
	}
}

func TestMethodTable(t *testing.T) {
	want := map[Method]struct {
		amr    string
		tenths int
	}{
		Password: {"pwd", 10}, PasskeySynced: {"spk", 25}, BrowserCert: {"file", 25},
		PasskeyDevice: {"dpk", 30}, SecurityKey: {"hwk", 35}, YubiKeyCert: {"mtls", 40},
	}
	if len(Methods) != 6 {
		t.Fatalf("Methods %v", Methods)
	}
	for _, m := range Methods {
		info, ok := InfoOf(m)
		if !ok || info.AMR != want[m].amr || info.Tenths != want[m].tenths {
			t.Errorf("%s: %+v", m, info)
		}
		if got, ok := MethodForAMR(info.AMR); !ok || got != m {
			t.Errorf("MethodForAMR(%s) = %s, %v", info.AMR, got, ok)
		}
		if info.Available != (m != BrowserCert) {
			t.Errorf("%s available %v", m, info.Available)
		}
	}
	for _, a := range []string{"inv", "", "webauthn", "PWD"} {
		if _, ok := MethodForAMR(a); ok {
			t.Errorf("MethodForAMR(%q) ok", a)
		}
	}
	if _, ok := InfoOf("family:passkey"); ok {
		t.Error("InfoOf(family) ok")
	}
}

func TestBuiltins(t *testing.T) {
	b := Builtins()
	ids := []string{}
	for _, tpl := range b {
		ids = append(ids, tpl.ID)
		if !tpl.BuiltIn {
			t.Errorf("%s not BuiltIn", tpl.ID)
		}
		if err := Validate(tpl.Rule); err != nil {
			t.Errorf("%s: %v", tpl.ID, err)
		}
		wantOn := tpl.ID == "standard" || tpl.ID == "strong"
		if tpl.Enabled != wantOn {
			t.Errorf("%s enabled %v", tpl.ID, tpl.Enabled)
		}
	}
	if !slices.Equal(ids, []string{"basic", "standard", "strong", "yubikey-and-certificate"}) {
		t.Errorf("ids %v", ids)
	}
	// Basic with password off drops its password alternative.
	if c := mustCompile(t, builtin(t, "basic"), defaultOn()); js(c) != js(mustCompile(t, builtin(t, "standard"), defaultOn())) {
		t.Errorf("basic with password off compiled to %s", js(c))
	}
	// Builtins hands out copies.
	b[1].Rule.Items[0].Leaf = "password"
	if js(builtin(t, "standard")) != `{"op":"any","items":["family:passkey","family:certificate"]}` {
		t.Error("Builtins shares its rules")
	}
}

func TestAlternativesMinimal(t *testing.T) {
	c := mustCompile(t, anyOf(leaf("security_key"), all(leaves("yubikey_cert", "security_key")...), all(leaves("security_key", "passkey_synced")...)), defaultOn())
	alts, err := Alternatives(c)
	if err != nil || len(alts) != 1 || !slices.Equal(alts[0], []Method{SecurityKey}) {
		t.Errorf("alternatives %v, %v", alts, err)
	}
	c = mustCompile(t, all(leaves("yubikey_cert", "passkey_synced")...), defaultOn())
	alts, _ = Alternatives(c)
	if len(alts) != 1 || !slices.Equal(alts[0], []Method{PasskeySynced, YubiKeyCert}) {
		t.Errorf("not sorted canonically: %v", alts)
	}
	if _, err := Alternatives(anyOf(leaf("family:passkey"))); err == nil {
		t.Error("uncompiled rule accepted")
	}
	if Satisfied(anyOf(leaf("family:passkey")), onSet(PasskeySynced)) {
		t.Error("Satisfied accepted a family leaf")
	}
}

// FreshAccepted (contract §8 "Governing template", the controller
// ruling): the strongest switched-on method of each alternative of a
// compiled rule — the built-ins at the starting switches, a password-only
// rule, all[security_key, password] (the key only), a tie, and refusals of
// anything that isn't compiled.
func TestFreshAccepted(t *testing.T) {
	names := func(m map[Method]bool) string {
		var out []string
		for _, x := range Methods {
			if m[x] {
				out = append(out, string(x))
			}
		}
		return strings.Join(out, ",")
	}
	withPw := onSet(Password, PasskeySynced, PasskeyDevice, SecurityKey, YubiKeyCert)
	for _, c := range []struct {
		name, want string
		rule       Node
		on         map[Method]bool
	}{
		{"strong", "security_key,yubikey_cert", builtin(t, "strong"), defaultOn()},
		{"standard", "passkey_synced,passkey_device,security_key,yubikey_cert", builtin(t, "standard"), defaultOn()},
		{"basic, password on", "password,passkey_synced,passkey_device,security_key,yubikey_cert", builtin(t, "basic"), withPw},
		{"standard, two on", "passkey_synced,security_key", builtin(t, "standard"), onSet(PasskeySynced, SecurityKey)},
		{"yubikey + certificate", "yubikey_cert", builtin(t, "yubikey-and-certificate"), defaultOn()},
		{"password only", "password", anyOf(leaf("password")), withPw},
		{"all[security_key, password]", "security_key", all(leaves("security_key", "password")...), withPw},
		{"any[all[key, pw], passkey_synced]", "passkey_synced,security_key", anyOf(all(leaves("security_key", "password")...), leaf("passkey_synced")), withPw},
	} {
		got, err := FreshAccepted(mustCompile(t, c.rule, c.on), c.on)
		if err != nil || names(got) != c.want {
			t.Errorf("%s: FreshAccepted = %s, %v; want %s", c.name, names(got), err, c.want)
		}
	}
	// A tie (passkey_synced and browser_cert are both 2.5): both qualify.
	// Compile never switches browser_cert on, so the compiled rule is built
	// here; FreshAccepted reads the switches it is given.
	tie := Node{Op: OpAny, Items: []Node{all(leaves("passkey_synced", "browser_cert")...)}}
	if got, err := FreshAccepted(tie, onSet(PasskeySynced, BrowserCert)); err != nil || names(got) != "passkey_synced,browser_cert" {
		t.Errorf("tie: %s, %v", names(got), err)
	}
	if got, err := FreshAccepted(tie, onSet(PasskeySynced)); err != nil || names(got) != "passkey_synced" {
		t.Errorf("tie, browser_cert off: %s, %v", names(got), err)
	}
	for _, bad := range []Node{leaf("password"), anyOf(leaf("family:passkey")), anyOf(leaf("inv")), {Op: OpAny}} {
		if _, err := FreshAccepted(bad, withPw); err == nil {
			t.Errorf("FreshAccepted(%s): no error", js(bad))
		}
	}
}
