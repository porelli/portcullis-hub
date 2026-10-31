package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuild(t *testing.T) {
	webauthn := AuthPolicy{Factors: []string{"webauthn"}}
	mtls := AuthPolicy{Factors: []string{"mtls"}}
	apps := []App{
		{ID: "gitlab", Enabled: true, Subdomains: []string{"git", "registry"}, GroupAccess: true, AccessGroup: "users_gitlab",
			AdminGroup: "admin_gitlab", AdminPaths: []string{"/admin", "/-/admin"}},
		{ID: "grafana", Enabled: true, Subdomains: []string{"grafana"}, GroupAccess: false, AccessGroup: "users_grafana"},
		// Disabled: publishes nothing at all.
		{ID: "jellyfin", Enabled: false, Subdomains: []string{"media"}, GroupAccess: true, AccessGroup: "users_jellyfin",
			AdminGroup: "admin_jellyfin", AdminPaths: []string{"/admin"}},
		// Tries to claim core subdomains.
		{ID: "evil", Enabled: true, Subdomains: []string{"auth", "hub", "evil"}, GroupAccess: true, AccessGroup: "users_evil",
			AdminGroup: "admin_evil", AdminPaths: []string{"/"}},
		// Admin paths without admin group publish nothing.
		{ID: "nogroup", Enabled: true, Subdomains: []string{"nogroup"}, AdminPaths: []string{"/admin"}},
	}
	perApp := map[string]AuthPolicy{
		"gitlab":   mtls,
		"jellyfin": webauthn,
		"evil":     {},
		"hub":      {},
	}
	doc := Build(apps, perApp, webauthn)

	if doc.Version != 2 {
		t.Errorf("version = %d", doc.Version)
	}
	if !reflect.DeepEqual(doc.Default, webauthn) {
		t.Errorf("default = %+v", doc.Default)
	}
	// Subdomain keys of enabled apps with an override only — no template-ID
	// keys, nothing for disabled apps, nothing for core subdomains.
	wantPolicies := map[string]AuthPolicy{"git": mtls, "registry": mtls, "evil": {}}
	if !reflect.DeepEqual(doc.Policies, wantPolicies) {
		t.Errorf("policies = %+v\nwant %+v", doc.Policies, wantPolicies)
	}
	wantGroups := map[string]string{"git": "users_gitlab", "registry": "users_gitlab", "evil": "users_evil"}
	if !reflect.DeepEqual(doc.Groups, wantGroups) {
		t.Errorf("groups = %v, want %v", doc.Groups, wantGroups)
	}
	gl := []PathGroup{{"/-/admin", "admin_gitlab"}, {"/admin", "admin_gitlab"}}
	wantPG := map[string][]PathGroup{"git": gl, "registry": gl, "evil": {{"/", "admin_evil"}}}
	if !reflect.DeepEqual(doc.PathGroups, wantPG) {
		t.Errorf("path_groups = %+v, want %+v", doc.PathGroups, wantPG)
	}
	for core := range CoreSubdomains {
		if _, ok := doc.Policies[core]; ok {
			t.Errorf("core subdomain %s in policies", core)
		}
		if _, ok := doc.Groups[core]; ok {
			t.Errorf("core subdomain %s in groups", core)
		}
		if _, ok := doc.PathGroups[core]; ok {
			t.Errorf("core subdomain %s in path_groups", core)
		}
	}
}

// A template whose ID equals another app's subdomain must not be able to
// publish its (weaker) policy for that subdomain.
func TestBuildIDIsNotAKey(t *testing.T) {
	apps := []App{
		{ID: "vaultwarden", Enabled: true, Subdomains: []string{"passwords"}},
		{ID: "passwords", Enabled: true, Subdomains: []string{"pw-other"}},
	}
	doc := Build(apps, map[string]AuthPolicy{
		"vaultwarden": {Factors: []string{"mtls"}},
		"passwords":   {}, // public
	}, AuthPolicy{Factors: []string{"webauthn"}})
	if p := doc.Policies["passwords"]; strings.Join(p.Factors, ",") != "mtls" {
		t.Errorf("passwords = %+v, want vaultwarden's mtls policy", p)
	}
	if p, ok := doc.Policies["pw-other"]; !ok || len(p.Factors) != 0 {
		t.Errorf("pw-other = %+v, %v", p, ok)
	}
	if _, ok := doc.Policies["vaultwarden"]; ok {
		t.Error("template ID published as a key")
	}
}

func TestBuildCollisions(t *testing.T) {
	webauthn := AuthPolicy{Factors: []string{"webauthn"}}
	a := App{ID: "a", Enabled: true, Subdomains: []string{"shared"}, GroupAccess: true, AccessGroup: "ga", AdminGroup: "aa", AdminPaths: []string{"/admin", "/x"}}
	b := App{ID: "b", Enabled: true, Subdomains: []string{"shared"}, GroupAccess: true, AccessGroup: "gb", AdminGroup: "ab", AdminPaths: []string{"/admin", "/y"}}
	for _, order := range [][]App{{a, b}, {b, a}} {
		// a is public by override, b inherits the webauthn default: the
		// stricter (inherited) policy is published.
		doc := Build(order, map[string]AuthPolicy{"a": {}}, webauthn)
		if p := doc.Policies["shared"]; strings.Join(p.Factors, ",") != "webauthn" {
			t.Errorf("policy = %+v", p)
		}
		if doc.Groups["shared"] != "ga" {
			t.Errorf("group = %q (lowest ID must win)", doc.Groups["shared"])
		}
		want := []PathGroup{{"/admin", "aa"}, {"/x", "aa"}, {"/y", "ab"}}
		if !reflect.DeepEqual(doc.PathGroups["shared"], want) {
			t.Errorf("path groups = %+v", doc.PathGroups["shared"])
		}
	}
	// Two overrides: all-of beats any-of at the same LoA, higher LoA wins.
	anyOf := AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}
	allOf := AuthPolicy{Factors: []string{"password", "webauthn"}, Op: "all"}
	doc := Build([]App{a, b}, map[string]AuthPolicy{"a": anyOf, "b": allOf}, AuthPolicy{})
	if p := doc.Policies["shared"]; p.Op != "all" {
		t.Errorf("policy = %+v, want all-of", p)
	}
	doc = Build([]App{a, b}, map[string]AuthPolicy{"a": {Factors: []string{"mtls"}}, "b": allOf}, AuthPolicy{})
	if p := doc.Policies["shared"]; strings.Join(p.Factors, ",") != "mtls" {
		t.Errorf("policy = %+v, want mtls", p)
	}
}

func TestStricter(t *testing.T) {
	pub := AuthPolicy{}
	pwd := AuthPolicy{Factors: []string{"password"}}
	hwk := AuthPolicy{Factors: []string{"webauthn"}}
	any2 := AuthPolicy{Factors: []string{"password", "webauthn"}, Op: "any"}
	all2 := AuthPolicy{Factors: []string{"password", "webauthn"}, Op: "all"}
	for _, c := range []struct {
		a, b AuthPolicy
		want bool
	}{
		{pwd, pub, true}, {pub, pwd, false}, {hwk, pwd, true}, {all2, hwk, true}, {hwk, all2, false},
		{all2, any2, true}, {any2, pwd, false}, {pwd, any2, true}, {hwk, hwk, false}, {pub, pub, false},
	} {
		if got := Stricter(c.a, c.b); got != c.want {
			t.Errorf("Stricter(%+v, %+v) = %v", c.a, c.b, got)
		}
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "group-gate-policy.json")
	doc := Build(nil, nil, AuthPolicy{})
	if err := Write(path, doc); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
	var raw map[string]interface{}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["version"] != float64(2) {
		t.Errorf("version = %v", raw["version"])
	}
	for _, k := range []string{"policies", "groups", "path_groups"} {
		if _, ok := raw[k].(map[string]interface{}); !ok {
			t.Errorf("%s must be an object, got %T", k, raw[k])
		}
	}
	// An unset default keeps "factors": null — group-gate treats that as
	// "no default policy", which differs from [] (public).
	def := raw["default"].(map[string]interface{})
	if f, ok := def["factors"]; !ok || f != nil {
		t.Errorf("default factors = %v, want null", f)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %d entries", len(entries))
	}
}

func TestBuildDeny(t *testing.T) {
	apps := []App{
		{ID: "live", Enabled: true, Subdomains: []string{"shared"}},
		{ID: "ghost", Enabled: true, Deny: true, Subdomains: []string{"shared", "ghost", "hub"}},
	}
	doc := Build(apps, nil, AuthPolicy{})
	if doc.Groups["ghost"] != DenyGroup {
		t.Errorf("ghost = %q", doc.Groups["ghost"])
	}
	if _, ok := doc.Groups["shared"]; ok {
		t.Error("deny overrode a subdomain claimed by a live app")
	}
	if _, ok := doc.Groups["hub"]; ok {
		t.Error("core subdomain published")
	}
}
