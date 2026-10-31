package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/policy"
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
	s.Settings["a"] = map[string]string{"K": "v"}
	s.AuthPolicies["a"] = policy.AuthPolicy{Factors: []string{"mtls"}}
	s.SetDefault(policy.AuthPolicy{Factors: []string{"password"}})
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
	if got.Settings["a"]["K"] != "v" || got.Sources[0].Path != "/data/repos/portcullis" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if p := got.ResolvePolicy("a"); p.Factors[0] != "mtls" {
		t.Errorf("per-app policy = %+v", p)
	}
	if p := got.ResolvePolicy("other"); p.Factors[0] != "password" {
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

	// Fresh install: hardware keys by default.
	s, _ := Load(p)
	if d := s.Default(); strings.Join(d.Factors, ",") != "webauthn" {
		t.Errorf("fresh default = %+v", d)
	}
	// A file that never set a default behaves the same.
	os.WriteFile(p, []byte("enabled: []\n"), 0600)
	s, _ = Load(p)
	if d := s.Default(); strings.Join(d.Factors, ",") != "webauthn" {
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
