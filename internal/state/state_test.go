package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/signin"
)

func TestLoadMissing(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Settings == nil || s.AuthPolicies == nil || len(s.Enabled) != 0 {
		t.Errorf("bad empty state: %+v", s)
	}
}

func TestLoadCorrupt(t *testing.T) {
	for name, content := range map[string]string{
		"empty":      "",
		"whitespace": "  \n\t\n",
		"garbage":    "enabled: [unclosed\n",
		"wrong type": "enabled: {a: b}\n",
	} {
		p := filepath.Join(t.TempDir(), "state.yaml")
		os.WriteFile(p, []byte(content), 0600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: corrupt state accepted", name)
		}
		// The file must be left untouched for the operator.
		if b, _ := os.ReadFile(p); string(b) != content {
			t.Errorf("%s: state file modified", name)
		}
	}
}

func TestLoadUnreadable(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be: read fails with something other
	// than ErrNotExist.
	p := filepath.Join(dir, "state.yaml")
	os.Mkdir(p, 0700)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("err = %v", err)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.yaml")
	s := New()
	s.SetEnabled("a", true)
	s.SetEnabled("b", true)
	s.SetEnabled("a", true)
	s.SetEnabled("b", false)
	s.Sources = []Source{{Name: "portcullis", URL: "https://x", Path: "/data/repos/portcullis"}}
	s.Settings["a"] = InstanceSettings{Ports: map[string]string{"K": "v"}, Values: map[string]any{"n": 30}, Person: map[string]PersonSetting{"q": {Default: "x", Rows: []GroupValue{{Group: "g", GroupID: 3, Value: "y"}}}}}
	s.AuthPolicies["a"] = policy.AuthPolicy{Factors: []string{"mtls"}}
	s.SetDefault(policy.AuthPolicy{Factors: []string{"webauthn"}})
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Enabled) != 1 || got.Enabled[0] != "a" || !got.IsEnabled("a") || got.IsEnabled("b") {
		t.Errorf("enabled = %v", got.Enabled)
	}
	if got.Settings["a"].Ports["K"] != "v" || got.Settings["a"].Values["n"] != 30 || got.Settings["a"].Person["q"].Rows[0].GroupID != 3 || got.Sources[0].Path != "/data/repos/portcullis" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if p := got.ResolvePolicy("a"); p.Factors[0] != "mtls" {
		t.Errorf("per-app policy = %+v", p)
	}
	if p := got.ResolvePolicy("other"); p.Factors[0] != "webauthn" {
		t.Errorf("default policy = %+v", p)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left: %d", len(entries))
	}
}

func TestDefaultPolicyUnsetVsPublic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.yaml")

	// Fresh install: a YubiKey by either method (client cert or passkey).
	s, _ := Load(p)
	if d := s.Default(); strings.Join(d.Factors, ",") != "mtls,webauthn" || d.Op != "any" {
		t.Errorf("fresh default = %+v", d)
	}
	// A file that never set a default behaves the same.
	os.WriteFile(p, []byte("enabled: []\n"), 0600)
	s, _ = Load(p)
	if d := s.Default(); strings.Join(d.Factors, ",") != "mtls,webauthn" || d.Op != "any" {
		t.Errorf("unset default = %+v", d)
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); strings.Contains(string(b), "default_auth_policy") {
		t.Errorf("unset default persisted:\n%s", b)
	}

	// An explicitly saved public default survives a round trip.
	s.SetDefault(policy.AuthPolicy{})
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.DefaultPolicy == nil {
		t.Fatal("explicit public default lost")
	}
	if d := s.Default(); d.Factors == nil || len(d.Factors) != 0 || s.ResolvePolicy("x").Factors == nil {
		t.Errorf("explicit public default = %+v", d)
	}
}

// Stored policies naming the removed "password" factor are normalised on
// load (never into something weaker) and flagged for the UI.
func TestLoadLegacyPassword(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.yaml")
	os.WriteFile(p, []byte(`default_auth_policy: {factors: [password], op: ""}
auth_policies:
  a: {factors: [password, webauthn], op: all}
  b: {factors: [mtls], op: ""}
published:
  a: {subdomains: [a], group_access: false, policy: {factors: [password, mtls], op: any}}
sign_in_mode: {plex: native}
`), 0600)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if d := s.Default(); strings.Join(d.Factors, ",") != "mtls,webauthn" || d.Op != "any" {
		t.Errorf("default = %+v", d)
	}
	if a := s.AuthPolicies["a"]; strings.Join(a.Factors, ",") != "webauthn" {
		t.Errorf("a = %+v", a)
	}
	if pp := s.Published["a"].Policy; pp == nil || strings.Join(pp.Factors, ",") != "mtls,webauthn" || pp.Op != "any" {
		t.Errorf("published a = %+v", pp)
	}
	if !s.LegacyPassword[""] || !s.LegacyPassword["a"] || s.LegacyPassword["b"] {
		t.Errorf("flags = %v", s.LegacyPassword)
	}
	if s.SignInMode["plex"] != SignInNative {
		t.Errorf("sign_in = %v", s.SignInMode)
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	// The saved policies no longer name the factor (the sign_in section
	// names the password method and is not a legacy policy).
	if l, err := Load(p); err != nil || len(l.LegacyPassword) != 0 {
		b, _ := os.ReadFile(p)
		t.Errorf("saved state still names password (%v):\n%s", err, b)
	}
}

// Settings in the old flat form are never read silently: Load refuses,
// naming the instances (no migration).
func TestLoadRefusesLegacyFlatSettings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.yaml")
	os.WriteFile(p, []byte("enabled: [grafana]\nsettings:\n  grafana:\n    GRAFANA_PORT: \"3301\"\n    GRAFANA_PORT_BIND: 127.0.0.1\n  other:\n    ports: {OTHER_PORT: \"1\"}\n  zeta:\n    K: v\n"), 0600)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "grafana, zeta") || strings.Contains(err.Error(), "other") || !strings.Contains(err.Error(), "old flat form") {
		t.Fatalf("Load = %v", err)
	}
	os.WriteFile(p, []byte("settings:\n  other:\n    ports: {OTHER_PORT: \"1\"}\n"), 0600)
	if s, err := Load(p); err != nil || s.Settings["other"].Ports["OTHER_PORT"] != "1" {
		t.Fatalf("typed form: %v %+v", err, s)
	}
}

func TestLocalNetworksLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.yaml")
	empty := []string{}
	s := New()
	s.LocalNetworks = &empty
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.LocalNetworks == nil || len(*got.LocalNetworks) != 0 {
		t.Fatalf("[] round-trip = %v", got.LocalNetworks)
	}
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.1/8", "x"} {
		os.WriteFile(p, []byte("local_networks: [\""+bad+"\"]\n"), 0600)
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}

func TestEnsureSignInDefaults(t *testing.T) {
	s := New()
	si := s.SignIn
	want := map[string]bool{"password": false, "passkey_synced": true, "browser_cert": false, "passkey_device": true, "security_key": true, "yubikey_cert": true}
	if len(si.Methods) != len(want) {
		t.Errorf("methods = %v", si.Methods)
	}
	for m, on := range want {
		if v, ok := si.Methods[m]; !ok || v != on {
			t.Errorf("method %s = %v (set %v), want %v", m, v, ok, on)
		}
	}
	if len(si.Templates) != 4 {
		t.Fatalf("templates = %v", si.Templates)
	}
	for _, b := range signin.Builtins() {
		got, ok := si.Templates[b.ID]
		if !ok || !got.BuiltIn || got.Name != b.Name || signin.Sentence(got.Rule) != signin.Sentence(b.Rule) {
			t.Errorf("built-in %s = %+v", b.ID, got)
		}
	}
	for id, on := range map[string]bool{"basic": false, "standard": true, "strong": true, "yubikey-and-certificate": false} {
		if si.Templates[id].Enabled != on {
			t.Errorf("%s enabled = %v, want %v", id, si.Templates[id].Enabled, on)
		}
	}
	if si.Default != "standard" {
		t.Errorf("default = %q", si.Default)
	}
	for _, k := range CoreSignInKeys {
		w := ""
		if k == "hub" || k == "people" {
			w = "strong"
		}
		if v, ok := si.Core[k]; !ok || v != w {
			t.Errorf("core %s = %q (set %v), want %q", k, v, ok, w)
		}
	}
	if si.AddStronger || si.Passwords == nil {
		t.Errorf("add_stronger %v passwords %v", si.AddStronger, si.Passwords)
	}

	// A stored state keeps its choices; the rule survives a round trip in
	// its JSON shape; a missing built-in comes back; a method without an
	// entry is off; browser_cert is forced off.
	s.SignIn.Default = "strong"
	s.SignIn.Methods["password"] = true
	s.SignIn.Methods["browser_cert"] = true
	delete(s.SignIn.Methods, "passkey_device")
	delete(s.SignIn.Templates, "basic")
	s.SignIn.Templates["mine"] = SignInTemplate{Name: "Mine", Rule: signin.Node{Op: "all", Items: []signin.Node{{Leaf: "password"}, {Op: "any", Items: []signin.Node{{Leaf: "family:yubikey"}, {Leaf: "passkey_synced"}}}}}, Enabled: true, BuiltIn: true}
	s.Instances["grafana"] = Instance{ID: "grafana", Template: "grafana", SignInTemplate: "mine"}
	p := filepath.Join(t.TempDir(), "state.yaml")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "- password") || !strings.Contains(string(data), "op: any") {
		t.Errorf("rule not in its JSON shape:\n%s", data)
	}
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if l.SignIn.Default != "strong" || !l.SignIn.Methods["password"] || l.SignIn.Methods["browser_cert"] || l.SignIn.Methods["passkey_device"] {
		t.Errorf("loaded = %+v", l.SignIn)
	}
	if _, ok := l.SignIn.Templates["basic"]; !ok {
		t.Error("missing built-in not restored")
	}
	m := l.SignIn.Templates["mine"]
	if m.BuiltIn || !m.Enabled || signin.Sentence(m.Rule) != signin.Sentence(s.SignIn.Templates["mine"].Rule) {
		t.Errorf("mine = %+v", m)
	}
	if l.Instances["grafana"].SignInTemplate != "mine" || !l.Instances["grafana"].HoldsIdentity() {
		t.Errorf("instance pick = %+v", l.Instances["grafana"])
	}

	// A section that doesn't hold together never loads.
	for name, bad := range map[string]string{
		"unknown method":  "sign_in: {methods: {sms: true}}\n",
		"bad rule":        "sign_in: {templates: {x: {name: X, rule: {op: some, items: [password]}}}}\n",
		"bad id":          "sign_in: {templates: {Bad: {name: X, rule: {op: any, items: [password]}}}}\n",
		"unknown default": "sign_in: {default: nope}\n",
		"unknown core":    "sign_in: {core: {auth: standard}}\n",
		"core template":   "sign_in: {core: {hub: nope}}\n",
		"instance pick":   "instances: {a: {id: a, template: a, sign_in_template: nope}}\n",
	} {
		os.WriteFile(p, []byte(bad), 0600)
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
