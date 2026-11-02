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
	domain := "portcullis.local"
	webauthn := AuthPolicy{Factors: []string{"webauthn"}}
	mtls := AuthPolicy{Factors: []string{"mtls"}}
	apps := []App{
		{ID: "gitlab", Enabled: true,
			Hosts:       map[string]string{"git." + domain: "git." + domain, "registry." + domain: "registry." + domain},
			GroupAccess: true, AccessGroup: "users_gitlab",
			AdminGroup: "admin_gitlab", AdminPaths: []string{"/admin", "/-/admin"}},
		{ID: "grafana", Enabled: true,
			Hosts:       map[string]string{"grafana." + domain: "grafana." + domain},
			GroupAccess: false, AccessGroup: "users_grafana"},
		// Disabled: publishes nothing at all.
		{ID: "jellyfin", Enabled: false,
			Hosts:       map[string]string{"media." + domain: "media." + domain},
			GroupAccess: true, AccessGroup: "users_jellyfin",
			AdminGroup: "admin_jellyfin", AdminPaths: []string{"/admin"}},
		// Tries to claim core hostnames (Build doesn't filter; Hub does).
		{ID: "evil", Enabled: true,
			Hosts:       map[string]string{"auth." + domain: "auth." + domain, "hub." + domain: "hub." + domain, "evil." + domain: "evil." + domain},
			GroupAccess: true, AccessGroup: "users_evil",
			AdminGroup: "admin_evil", AdminPaths: []string{"/"}},
		// Admin paths without admin group publish nothing.
		{ID: "nogroup", Enabled: true,
			Hosts:      map[string]string{"nogroup." + domain: "nogroup." + domain},
			AdminPaths: []string{"/admin"}},
	}
	perApp := map[string]AuthPolicy{
		"gitlab":   mtls,
		"jellyfin": webauthn,
		"evil":     {},
		"hub":      {},
	}
	doc := Build(apps, perApp, webauthn, []string{})

	if doc.Version != 5 {
		t.Errorf("version = %d, want 5", doc.Version)
	}
	if !reflect.DeepEqual(doc.Default, webauthn) {
		t.Errorf("default = %+v", doc.Default)
	}
	// Hostname keys of enabled apps with an override only — no instance-ID
	// keys, nothing for disabled apps.
	wantPolicies := map[string]AuthPolicy{
		"git." + domain:      mtls,
		"registry." + domain: mtls,
		"auth." + domain:     {},
		"hub." + domain:      {},
		"evil." + domain:     {},
	}
	if !reflect.DeepEqual(doc.Policies, wantPolicies) {
		t.Errorf("policies = %+v\nwant %+v", doc.Policies, wantPolicies)
	}
	wantGroups := map[string]string{
		"git." + domain:      "users_gitlab",
		"registry." + domain: "users_gitlab",
		"auth." + domain:     "users_evil",
		"hub." + domain:      "users_evil",
		"evil." + domain:     "users_evil",
	}
	if !reflect.DeepEqual(doc.Groups, wantGroups) {
		t.Errorf("groups = %v, want %v", doc.Groups, wantGroups)
	}
	gl := []PathGroup{{"/-/admin", "admin_gitlab"}, {"/admin", "admin_gitlab"}}
	wantPG := map[string][]PathGroup{
		"git." + domain:      gl,
		"registry." + domain: gl,
		"auth." + domain:     {{"/", "admin_evil"}},
		"hub." + domain:      {{"/", "admin_evil"}},
		"evil." + domain:     {{"/", "admin_evil"}},
	}
	if !reflect.DeepEqual(doc.PathGroups, wantPG) {
		t.Errorf("path_groups = %+v, want %+v", doc.PathGroups, wantPG)
	}
}

// An instance whose ID equals another app's hostname must not be able to
// publish its (weaker) policy for that hostname (v5: policy keys are
// hostnames, never instance IDs).
func TestBuildIDIsNotAKey(t *testing.T) {
	domain := "portcullis.local"
	apps := []App{
		{ID: "vaultwarden", Enabled: true,
			Hosts: map[string]string{"passwords." + domain: "passwords." + domain}},
		{ID: "passwords", Enabled: true,
			Hosts: map[string]string{"pw-other." + domain: "pw-other." + domain}},
	}
	doc := Build(apps, map[string]AuthPolicy{
		"vaultwarden": {Factors: []string{"mtls"}},
		"passwords":   {}, // public
	}, AuthPolicy{Factors: []string{"webauthn"}}, []string{})
	if p := doc.Policies["passwords."+domain]; strings.Join(p.Factors, ",") != "mtls" {
		t.Errorf("passwords.%s = %+v, want vaultwarden's mtls policy", domain, p)
	}
	if p, ok := doc.Policies["pw-other."+domain]; !ok || len(p.Factors) != 0 {
		t.Errorf("pw-other.%s = %+v, %v", domain, p, ok)
	}
	if _, ok := doc.Policies["vaultwarden"]; ok {
		t.Error("instance ID published as a key")
	}
}

func TestBuildCollisions(t *testing.T) {
	domain := "portcullis.local"
	shared := "shared." + domain
	webauthn := AuthPolicy{Factors: []string{"webauthn"}}
	a := App{ID: "a", Enabled: true,
		Hosts:       map[string]string{shared: shared},
		GroupAccess: true, AccessGroup: "ga", AdminGroup: "aa", AdminPaths: []string{"/admin", "/x"}}
	b := App{ID: "b", Enabled: true,
		Hosts:       map[string]string{shared: shared},
		GroupAccess: true, AccessGroup: "gb", AdminGroup: "ab", AdminPaths: []string{"/admin", "/y"}}
	for _, order := range [][]App{{a, b}, {b, a}} {
		// a is public by override, b inherits the webauthn default: the
		// stricter (inherited) policy is published.
		doc := Build(order, map[string]AuthPolicy{"a": {}}, webauthn, []string{})
		if p := doc.Policies[shared]; strings.Join(p.Factors, ",") != "webauthn" {
			t.Errorf("policy = %+v", p)
		}
		if doc.Groups[shared] != "ga" {
			t.Errorf("group = %q (lowest ID must win)", doc.Groups[shared])
		}
		want := []PathGroup{{"/admin", "aa"}, {"/x", "aa"}, {"/y", "ab"}}
		if !reflect.DeepEqual(doc.PathGroups[shared], want) {
			t.Errorf("path groups = %+v", doc.PathGroups[shared])
		}
	}
	// Two overrides: all-of beats any-of at the same LoA, higher LoA wins.
	anyOf := AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}
	allOf := AuthPolicy{Factors: []string{"password", "webauthn"}, Op: "all"}
	doc := Build([]App{a, b}, map[string]AuthPolicy{"a": anyOf, "b": allOf}, AuthPolicy{}, []string{})
	if p := doc.Policies[shared]; p.Op != "all" {
		t.Errorf("policy = %+v, want all-of", p)
	}
	doc = Build([]App{a, b}, map[string]AuthPolicy{"a": {Factors: []string{"mtls"}}, "b": allOf}, AuthPolicy{}, []string{})
	if p := doc.Policies[shared]; strings.Join(p.Factors, ",") != "mtls" {
		t.Errorf("policy = %+v, want mtls", p)
	}
}

func TestStricter(t *testing.T) {
	pub := AuthPolicy{}
	hwk := AuthPolicy{Factors: []string{"webauthn"}}
	cert := AuthPolicy{Factors: []string{"mtls"}}
	any2 := AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}
	all2 := AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "all"}
	for _, c := range []struct {
		a, b AuthPolicy
		want bool
	}{
		{hwk, pub, true}, {pub, hwk, false}, {cert, hwk, true}, {all2, cert, true}, {cert, all2, false},
		{all2, any2, true}, {any2, hwk, false}, {hwk, any2, true}, {hwk, hwk, false}, {pub, pub, false},
	} {
		if got := Stricter(c.a, c.b); got != c.want {
			t.Errorf("Stricter(%+v, %+v) = %v", c.a, c.b, got)
		}
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "group-gate-policy.json")
	doc := Build(nil, nil, AuthPolicy{}, []string{})
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
	if raw["version"] != float64(5) {
		t.Errorf("version = %v, want 5", raw["version"])
	}
	for _, k := range []string{"policies", "groups", "path_groups", "public_paths"} {
		if _, ok := raw[k].(map[string]interface{}); !ok {
			t.Errorf("%s must be an object, got %T", k, raw[k])
		}
	}
	if _, ok := raw["extra_domains"].([]interface{}); !ok {
		t.Errorf("extra_domains must be an array, got %T", raw["extra_domains"])
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
	domain := "portcullis.local"
	shared := "shared." + domain
	ghostHost := "ghost." + domain
	hubHost := "hub." + domain
	apps := []App{
		{ID: "live", Enabled: true,
			Hosts: map[string]string{shared: shared}},
		{ID: "ghost", Enabled: true, Deny: true,
			Hosts: map[string]string{shared: shared, ghostHost: ghostHost, hubHost: hubHost}},
	}
	doc := Build(apps, nil, AuthPolicy{}, []string{})
	if doc.Groups[ghostHost] != DenyGroup {
		t.Errorf("ghost host = %q, want %q", doc.Groups[ghostHost], DenyGroup)
	}
	if _, ok := doc.Groups[shared]; ok {
		t.Error("deny overrode a hostname claimed by a live app")
	}
	// Note: Build doesn't filter core hosts; the Hub does that before calling.
	// The hub host will have DenyGroup if it reaches Build.
}

func TestBuildPublicPaths(t *testing.T) {
	domain := "portcullis.local"
	cloudHost := "cloud." + domain
	offHost := "off." + domain
	hubHost := "hub." + domain
	goneHost := "gone." + domain
	cloud := &PublicEntry{Paths: []PublicPath{{"/s/{token}", "prefix"}, {"/dist", "static"}}, TokenPattern: "^[a-z]+$",
		StaticExtensions: []string{"css"}, CredentialHeaders: []string{"Authorization"}, CredentialCookies: []string{"nc_token"}, CredentialQuery: []string{}}
	apps := []App{
		{ID: "cloud", Enabled: true,
			Hosts:       map[string]string{cloudHost: cloudHost},
			PublicHosts: map[string]string{cloudHost: cloudHost}, Public: cloud},
		{ID: "dup", Enabled: true,
			Hosts:       map[string]string{cloudHost: cloudHost},
			PublicHosts: map[string]string{cloudHost: cloudHost}, Public: &PublicEntry{Paths: []PublicPath{{"/x", "prefix"}}}},
		{ID: "off", Enabled: true,
			Hosts: map[string]string{offHost: offHost}},
		{ID: "core", Enabled: true,
			Hosts:       map[string]string{hubHost: hubHost},
			PublicHosts: map[string]string{hubHost: hubHost}, Public: cloud},
		{ID: "gone", Enabled: true, Deny: true,
			Hosts:       map[string]string{goneHost: goneHost},
			PublicHosts: map[string]string{goneHost: goneHost}, Public: cloud},
	}
	doc := Build(apps, nil, InitialDefault(), []string{})
	if doc.Version != 5 || len(doc.PublicPaths) != 2 {
		t.Errorf("public_paths length = %d (version %d), want 2", len(doc.PublicPaths), doc.Version)
	}
	if !reflect.DeepEqual(doc.PublicPaths[cloudHost], *cloud) {
		t.Errorf("public_paths[%s] = %+v", cloudHost, doc.PublicPaths[cloudHost])
	}
	if doc.Groups[goneHost] != DenyGroup {
		t.Errorf("deny app lost its deny group: %v", doc.Groups)
	}
	raw, _ := json.Marshal(doc)
	for _, want := range []string{`"version":5`, `"paths":[{"path":"/s/{token}","match":"prefix"},{"path":"/dist","match":"static"}]`,
		`"credential_cookies":["nc_token"]`, `"credential_query":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("policy file lacks %s: %s", want, raw)
		}
	}
	raw, _ = json.Marshal(Build(nil, nil, InitialDefault(), []string{}))
	if !strings.Contains(string(raw), `"public_paths":{}`) {
		t.Errorf("empty public_paths not published as {}: %s", raw)
	}
}

func TestPolicyFileV5Expiring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	exp1 := Expiring{User: "jsmith", Group: "contractors", At: "2027-03-31T23:59:59Z"}
	exp2 := Expiring{User: "alee", Group: "temporary", At: "2027-06-30T23:59:59Z"}

	doc := Document{
		Version:      FileVersion,
		Default:      AuthPolicy{Factors: []string{"webauthn"}},
		ExtraDomains: []string{},
		Policies:     map[string]AuthPolicy{},
		Groups:       map[string]string{"app.portcullis.local": "users"},
		PathGroups:   map[string][]PathGroup{},
		PublicPaths:  map[string]PublicEntry{},
		Expiring:     []Expiring{exp1, exp2},
	}

	if err := Write(path, doc); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed["version"] != float64(5) {
		t.Errorf("version = %v, want 5", parsed["version"])
	}

	expiring, ok := parsed["expiring"].([]interface{})
	if !ok {
		t.Fatalf("expiring missing or not an array: %T", parsed["expiring"])
	}
	if len(expiring) != 2 {
		t.Fatalf("expiring length = %d, want 2", len(expiring))
	}

	e1 := expiring[0].(map[string]interface{})
	if e1["user"] != "jsmith" || e1["group"] != "contractors" || e1["at"] != "2027-03-31T23:59:59Z" {
		t.Errorf("expiring[0] = %+v", e1)
	}

	// Empty expiring array should still be present
	doc.Expiring = []Expiring{}
	if err := Write(path, doc); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if !strings.Contains(string(data), `"expiring": []`) {
		t.Errorf("empty expiring array not serialized: %s", string(data))
	}
}
