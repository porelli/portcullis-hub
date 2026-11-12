package state

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/signin"
)

func TestLoadMissing(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Settings == nil || len(s.Enabled) != 0 {
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
	s.Published["a"] = PublishedApp{Hosts: []string{"a.example.com"}, SignInTemplate: "strong"}
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
	if got.Published["a"].SignInTemplate != "strong" {
		t.Errorf("published pick = %+v", got.Published["a"])
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left: %d", len(entries))
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
	// entry is off; a switched-on browser_cert stays on.
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
	if l.SignIn.Default != "strong" || !l.SignIn.Methods["password"] || !l.SignIn.Methods["browser_cert"] || l.SignIn.Methods["passkey_device"] {
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

	// A section that doesn't hold together never loads, each for its own
	// reason (the D1 switches stored, so only the case's flaw is wrong).
	const on = "methods: {password: false, passkey_synced: true, browser_cert: false, passkey_device: true, security_key: true, yubikey_cert: true}, "
	for name, c := range map[string][2]string{
		"unknown method":     {"sign_in: {methods: {sms: true}}\n", `unknown method "sms"`},
		"bad rule":           {"sign_in: {" + on + "templates: {x: {name: X, rule: {op: some, items: [password]}}}}\n", `"op" must be`},
		"bad id":             {"sign_in: {" + on + "templates: {Bad: {name: X, rule: {op: any, items: [password]}}}}\n", `template id "Bad"`},
		"unknown default":    {"sign_in: {" + on + "default: nope}\n", `default: "nope" is not a template`},
		"unknown core":       {"sign_in: {" + on + "core: {auth: standard}}\n", `unknown core page "auth"`},
		"core template":      {"sign_in: {" + on + "core: {hub: nope}}\n", `core page hub: "nope" is not a template`},
		"instance pick":      {"sign_in: {" + on + "default: standard}\ninstances: {a: {id: a, template: a, sign_in_template: nope}}\n", `instance a: "nope" is not a template`},
		"default disabled":   {"sign_in: {" + on + "default: basic}\n", `default: template "basic" is disabled`},
		"core disabled":      {"sign_in: {" + on + "core: {portal: yubikey-and-certificate}}\n", `core page portal: template "yubikey-and-certificate" is disabled`},
		"instance disabled":  {"sign_in: {" + on + "default: standard}\ninstances: {a: {id: a, template: a, sign_in_template: basic}}\n", `instance a: template "basic" is disabled`},
		"enabled unmeetable": {"sign_in: {" + on + "templates: {pw: {name: PW, rule: {op: all, items: [password]}, enabled: true}}}\n", "template pw is enabled but"},
		"no methods":         {"sign_in: {default: standard}\n", "template standard is enabled but"},
		"hidden name":        {"sign_in: {" + on + "templates: {x: {name: \"a\\u200bb\", rule: {op: any, items: [password]}}}}\n", "template x: the name must be one line of visible text"},
		"padded name":        {"sign_in: {" + on + "templates: {x: {name: \" X\", rule: {op: any, items: [password]}}}}\n", "template x: the name may not start or end"},
		"enroll core page":   {"sign_in: {" + on + "core: {enroll: \"\"}}\n", `unknown core page "enroll"`},
		"cert days":          {"sign_in: {" + on + "limits: {browser_cert_days: -1}}\n", "limits: browser_cert_days -1"},
		"max active":         {"sign_in: {" + on + "limits: {browser_cert_max_active: 21}}\n", "limits: browser_cert_max_active 21"},
		"history short":      {"sign_in: {" + on + "limits: {history_days: 29}}\n", "limits: history_days 29"},
		"history long":       {"sign_in: {" + on + "limits: {history_days: 3651}}\n", "limits: history_days 3651"},
	} {
		os.WriteFile(p, []byte(c[0]), 0600)
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "corrupt") || !strings.Contains(err.Error(), c[1]) {
			t.Errorf("%s: err = %v, want %q", name, err, c[1])
		}
	}
}

// The limits' D27 defaults (30 days, 3 certificates, 365 days) fill a
// fresh state and every missing limit of a stored one; the core pages no
// longer include enroll (sign-in part 2, D31).
func TestEnsureSignInLimitsDefaults(t *testing.T) {
	want := SignInLimits{BrowserCertDays: 30, BrowserCertMaxActive: 3, HistoryDays: 365}
	if got := New().SignIn.Limits; got != want {
		t.Errorf("fresh limits = %+v, want %+v", got, want)
	}
	if slices.Contains(CoreSignInKeys, "enroll") {
		t.Errorf("CoreSignInKeys = %v", CoreSignInKeys)
	}
	if _, ok := New().SignIn.Core["enroll"]; ok {
		t.Error("a fresh state has an enroll core pick")
	}
	p := filepath.Join(t.TempDir(), "state.yaml")
	const on = "methods: {password: false, passkey_synced: true, browser_cert: true, passkey_device: true, security_key: true, yubikey_cert: true}"
	os.WriteFile(p, []byte("sign_in: {"+on+", limits: {browser_cert_days: 10}}\n"), 0600)
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.SignIn.Limits; got != (SignInLimits{BrowserCertDays: 10, BrowserCertMaxActive: 3, HistoryDays: 365}) {
		t.Errorf("stored limits = %+v", got)
	}
	if !l.SignIn.Methods["browser_cert"] || !l.SignIn.MethodsOn()[signin.BrowserCert] {
		t.Errorf("browser_cert stored on: %v", l.SignIn.Methods)
	}
	// Stored values survive a round trip; one above any ceiling loads
	// (the Hub applies it as the ceiling).
	l.SignIn.Limits = SignInLimits{BrowserCertDays: 400, BrowserCertMaxActive: 20, HistoryDays: 30}
	if err := l.Save(p); err != nil {
		t.Fatal(err)
	}
	if l2, err := Load(p); err != nil || l2.SignIn.Limits != l.SignIn.Limits {
		t.Errorf("reloaded: %v %+v", err, l2)
	}
}

// A stored section is fresh only when it is wholly empty: without methods
// every method is off (fail closed). A file without sign_in is reported,
// until the next save, so the Hub persists the seeded defaults.
func TestEnsureSignInStoredWithoutMethods(t *testing.T) {
	s := &AppState{SignIn: SignIn{Default: "strong"}}
	s.init()
	s.EnsureSignIn()
	for m, on := range s.SignIn.Methods {
		if on {
			t.Errorf("%s on in a stored section without methods", m)
		}
	}
	if s.SignIn.Default != "strong" || len(s.SignIn.Templates) != 4 {
		t.Errorf("section = %+v", s.SignIn)
	}

	p := filepath.Join(t.TempDir(), "state.yaml")
	os.WriteFile(p, []byte("enabled: []\n"), 0600)
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !l.SignInMissing() || !l.SignIn.Methods["security_key"] {
		t.Errorf("missing %v, methods %v", l.SignInMissing(), l.SignIn.Methods)
	}
	if err := l.Save(p); err != nil {
		t.Fatal(err)
	}
	if l.SignInMissing() {
		t.Error("still missing after save")
	}
	if l2, err := Load(p); err != nil || l2.SignInMissing() {
		t.Errorf("reloaded: %v, missing %v", err, l2 != nil && l2.SignInMissing())
	}
}

// TestImpersonationsRoundTrip (F1, F3): the records are top level
// (impersonations, outside sign_in) and keep their apps; the switch is
// sign_in.impersonation_off, whose zero value means on.
func TestImpersonationsRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.yaml")
	s := New()
	if s.SignIn.ImpersonationOff {
		t.Fatal("a new state has impersonation off")
	}
	at := time.Date(2026, 11, 12, 14, 2, 58, 0, time.UTC)
	rec := Impersonation{ID: "0f3c0f3c0f3c0f3c0f3c0f3c0f3c0f3c", Admin: "root", Target: "alice", AdminSID: "s1", Reason: "checking quota",
		Fresh: "security_key", FreshAt: at.Add(-7 * time.Second), Started: at, Until: at.Add(30 * time.Minute),
		Ended: at.Add(12 * time.Minute), How: "stopped", EndedBy: "sam", Used: true,
		Apps: []ImpersonationApp{{Name: "Gitea"}, {Name: "Nextcloud", OwnSession: true}}}
	s.Impersonations = []Impersonation{rec}
	s.SignIn.ImpersonationOff = true
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "\nimpersonations:\n") || !strings.Contains(string(raw), "    impersonation_off: true\n") {
		t.Errorf("state.yaml:\n%s", raw)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SignIn.ImpersonationOff || len(got.Impersonations) != 1 || !reflect.DeepEqual(got.Impersonations[0], rec) {
		t.Errorf("round trip: off %v, %+v", got.SignIn.ImpersonationOff, got.Impersonations)
	}
	if c := rec.Clone(); &c.Apps[0] == &rec.Apps[0] {
		t.Error("Clone shares Apps")
	}
}
