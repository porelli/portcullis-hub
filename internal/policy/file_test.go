package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuild(t *testing.T) {
	webauthn := AuthPolicy{Factors: []string{"webauthn"}}
	mtls := AuthPolicy{Factors: []string{"mtls"}}
	apps := []App{
		{ID: "gitlab", Enabled: true, Subdomains: []string{"git", "registry"}, GroupAccess: true, AccessGroup: "users_gitlab",
			AdminGroup: "admin_gitlab", AdminPaths: []string{"/admin", "/-/admin"}},
		{ID: "grafana", Enabled: true, Subdomains: []string{"grafana"}, GroupAccess: false, AccessGroup: "users_grafana"},
		// Disabled: publishes neither subdomain policies nor groups.
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
		"evil":     AuthPolicy{},
		"hub":      AuthPolicy{}, // core key must be dropped
		// Explicit subdomain-keyed policy wins over the template alias.
		"registry": webauthn,
	}
	doc := Build(apps, perApp, webauthn)

	if doc.Version != 2 {
		t.Errorf("version = %d", doc.Version)
	}
	if !reflect.DeepEqual(doc.Default, webauthn) {
		t.Errorf("default = %+v", doc.Default)
	}
	wantPolicies := map[string]AuthPolicy{
		"gitlab": mtls, "git": mtls, "registry": webauthn,
		"jellyfin": webauthn, // ID key stays even when disabled
		"evil":     {},
	}
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

func TestBuildDeterministicCollision(t *testing.T) {
	a := App{ID: "a", Enabled: true, Subdomains: []string{"shared"}, GroupAccess: true, AccessGroup: "ga"}
	b := App{ID: "b", Enabled: true, Subdomains: []string{"shared"}, GroupAccess: true, AccessGroup: "gb"}
	d1 := Build([]App{a, b}, nil, AuthPolicy{})
	d2 := Build([]App{b, a}, nil, AuthPolicy{})
	if d1.Groups["shared"] != d2.Groups["shared"] {
		t.Errorf("collision depends on input order: %v vs %v", d1.Groups, d2.Groups)
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
