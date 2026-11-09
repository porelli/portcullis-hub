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
		{"nested, browser cert on", nestedRule(), withCert, "4.3 / 5"},
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
		"family:passkey", "family:yubikey", "family:certificate", "yubikey_cert")...)
	s := ScoreOf(eight, defaultOn())
	if s.Tenths != 50 {
		t.Errorf("8 leaves: tenths %d, want 50 (4.0 + 0.4×7 capped)", s.Tenths)
	}
	if !strings.HasSuffix(s.Reason, ", capped at 5") || !strings.HasPrefix(s.Reason, "its strongest part (a YubiKey certificate) + 0.4 for each of 7 more") {
		t.Errorf("8 leaves reason %q", s.Reason)
	}
	if s.String() != "5.0 / 5" {
		t.Errorf("8 leaves string %q", s.String())
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
}

func TestValidateLimits(t *testing.T) {
	ok := anyOf(all(anyOf(leaves("password")...)))
	if err := Validate(ok); err != nil {
		t.Errorf("depth 3: %v", err)
	}
	cases := map[string]Node{
		"depth 4":    anyOf(all(anyOf(all(leaves("password")...)))),
		"9 items":    anyOf(leaves("password", "password", "password", "password", "password", "password", "password", "password", "password")...),
		"17 leaves":  anyOf(all(leaves(strings.Split(strings.Repeat("security_key,", 8), ",")[:8]...)...), all(leaves(strings.Split(strings.Repeat("security_key,", 8), ",")[:8]...)...), leaf("yubikey_cert")),
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
	sixteen := anyOf(all(leaves(strings.Split(strings.Repeat("security_key,", 8), ",")[:8]...)...), all(leaves(strings.Split(strings.Repeat("security_key,", 8), ",")[:8]...)...))
	if err := Validate(sixteen); err != nil {
		t.Errorf("16 leaves: %v", err)
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
	_, err = Compile(anyOf(leaf("password"), leaf("security_key")), defaultOn())
	if !errors.Is(err, ErrUnmeetable) {
		t.Errorf("any[password, security_key] with password off: %v, want ErrUnmeetable", err)
	}
	_, err = Compile(anyOf(leaf("family:passkey")), onSet(YubiKeyCert))
	if !errors.Is(err, ErrUnmeetable) {
		t.Errorf("family with no member on: %v, want ErrUnmeetable", err)
	}
	if _, err := Compile(anyOf(leaf("webauthn")), defaultOn()); err == nil || errors.Is(err, ErrUnmeetable) {
		t.Errorf("unknown leaf: %v, want a validation error", err)
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
	// Contract §8.1 "Needs": the only switched-on member of a family it names
	// is needed. With browser_cert off, yubikey_cert is family:certificate's
	// only member: switching it off would leave Standard unmeetable (D2).
	if got := Needs(builtin(t, "standard"), on); !slices.Equal(got, []Method{YubiKeyCert}) {
		t.Errorf("Needs(standard, browser_cert off) = %v, want [yubikey_cert]", got)
	}
	withCert := defaultOn()
	withCert[BrowserCert] = true
	if got := Needs(builtin(t, "standard"), withCert); len(got) != 0 {
		t.Errorf("Needs(standard, browser_cert on) = %v, want []", got)
	}
	if got := Needs(builtin(t, "strong"), on); !slices.Equal(got, []Method{SecurityKey, YubiKeyCert}) {
		t.Errorf("Needs(strong) = %v", got)
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
	if _, err := Compile(builtin(t, "basic"), defaultOn()); !errors.Is(err, ErrUnmeetable) {
		t.Errorf("basic with password off: %v", err)
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
