package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/signin"
)

// defaultOn are the methods switched on at the start (D1).
func defaultOn() map[signin.Method]bool {
	return map[signin.Method]bool{signin.PasskeySynced: true, signin.PasskeyDevice: true, signin.SecurityKey: true, signin.YubiKeyCert: true}
}

func onList(on map[signin.Method]bool) []signin.Method {
	var out []signin.Method
	for _, m := range signin.Methods {
		if on[m] {
			out = append(out, m)
		}
	}
	return out
}

// compiledBuiltins are the built-ins that compile with on, by id.
func compiledBuiltins(t *testing.T, on map[signin.Method]bool) map[string]signin.Node {
	t.Helper()
	out := map[string]signin.Node{}
	for _, b := range signin.Builtins() {
		if c, err := signin.Compile(b.Rule, on); err == nil {
			out[b.ID] = c
		}
	}
	return out
}

func input(t *testing.T, apps []App) BuildInput {
	on := defaultOn()
	return BuildInput{Apps: apps, Default: "standard", Core: map[string]string{"hub": "strong", "people": "strong"},
		Templates: compiledBuiltins(t, on), Methods: onList(on), MainDomain: "portcullis.local", ExtraDomains: []string{}}
}

func host(h string) map[string]string { return map[string]string{h: h} }

func TestBuildV6(t *testing.T) {
	domain := "portcullis.local"
	apps := []App{
		{ID: "gitlab", Enabled: true,
			Hosts:       map[string]string{"git." + domain: "git." + domain, "registry." + domain: "registry." + domain},
			GroupAccess: true, AccessGroup: "users_gitlab",
			AdminGroup: "admin_gitlab", AdminPaths: []string{"/admin", "/-/admin"}, Template: "strong"},
		// Inherits: no hosts entry.
		{ID: "grafana", Enabled: true, Hosts: host("grafana." + domain), AccessGroup: "users_grafana"},
		// Disabled: publishes nothing at all.
		{ID: "jellyfin", Enabled: false, Hosts: host("media." + domain), GroupAccess: true, AccessGroup: "users_jellyfin", Template: "strong"},
		// Tries to claim core hostnames: skipped.
		{ID: "evil", Enabled: true,
			Hosts:       map[string]string{"auth." + domain: "auth." + domain, "hub." + domain: "hub." + domain, "evil." + domain: "evil." + domain},
			GroupAccess: true, AccessGroup: "users_evil", AdminGroup: "admin_evil", AdminPaths: []string{"/"}, Template: "strong"},
		// Admin paths without admin group publish nothing.
		{ID: "nogroup", Enabled: true, Hosts: host("nogroup." + domain), AdminPaths: []string{"/admin"}},
	}
	in := input(t, apps)
	in.People = map[string][]signin.Method{"Alice": {signin.SecurityKey, signin.PasskeySynced, signin.Password}, "bob": {}}
	doc := Build(in)
	if doc.Version != 6 || doc.Default != "standard" || doc.AddStronger {
		t.Errorf("version %d default %q add_stronger %v", doc.Version, doc.Default, doc.AddStronger)
	}
	if want := []string{"passkey_device", "passkey_synced", "security_key", "yubikey_cert"}; !reflect.DeepEqual(doc.Methods, want) {
		t.Errorf("methods = %v", doc.Methods)
	}
	if _, ok := doc.Templates["basic"]; !ok {
		t.Error("compiled basic (password off: like standard) not published")
	}
	if _, ok := doc.Templates["yubikey-and-certificate"]; !ok {
		t.Error("input templates not all published")
	}
	wantHosts := map[string]string{"git." + domain: "strong", "registry." + domain: "strong", "evil." + domain: "strong"}
	if !reflect.DeepEqual(doc.Hosts, wantHosts) {
		t.Errorf("hosts = %v\nwant %v", doc.Hosts, wantHosts)
	}
	wantCore := map[string]string{
		domain: "standard", "hub." + domain: "strong", "people." + domain: "strong", "directory." + domain: "standard",
		"metrics." + domain: "standard", "traefik." + domain: "standard",
	}
	if !reflect.DeepEqual(doc.Core, wantCore) {
		t.Errorf("core = %v\nwant %v", doc.Core, wantCore)
	}
	for _, k := range []string{"auth." + domain, "mcp." + domain} {
		if _, ok := doc.Core[k]; ok {
			t.Errorf("core lists %s", k)
		}
	}
	if want := map[string][]string{"alice": {"passkey_synced", "security_key"}, "bob": {}}; !reflect.DeepEqual(doc.People, want) {
		t.Errorf("people = %v (switched-off password must not be listed)", doc.People)
	}
	wantGroups := map[string]string{"git." + domain: "users_gitlab", "registry." + domain: "users_gitlab", "evil." + domain: "users_evil"}
	if !reflect.DeepEqual(doc.Groups, wantGroups) {
		t.Errorf("groups = %v, want %v", doc.Groups, wantGroups)
	}
	gl := []PathGroup{{"/-/admin", "admin_gitlab"}, {"/admin", "admin_gitlab"}}
	wantPG := map[string][]PathGroup{"git." + domain: gl, "registry." + domain: gl, "evil." + domain: {{"/", "admin_evil"}}}
	if !reflect.DeepEqual(doc.PathGroups, wantPG) {
		t.Errorf("path_groups = %+v, want %+v", doc.PathGroups, wantPG)
	}
	for core := range CoreHosts(domain) {
		if _, ok := doc.Hosts[core]; ok {
			t.Errorf("core host %s in hosts", core)
		}
		if _, ok := doc.Groups[core]; ok {
			t.Errorf("core host %s in groups", core)
		}
	}
	raw, _ := json.Marshal(doc)
	for _, k := range []string{`"policies"`, `"factors"`} {
		if strings.Contains(string(raw), k) {
			t.Errorf("v6 document carries %s: %s", k, raw)
		}
	}
}

// A picked template that isn't published (disabled meanwhile, can't be
// met) denies the host instead of naming an unknown template.
func TestBuildUnknownTemplateDenies(t *testing.T) {
	in := input(t, []App{{ID: "a", Enabled: true, Hosts: host("a.portcullis.local"), Template: "gone"}})
	in.Core["traefik"] = "gone"
	doc := Build(in)
	if doc.Groups["a.portcullis.local"] != DenyGroup || doc.Hosts["a.portcullis.local"] != "" {
		t.Errorf("groups %v hosts %v", doc.Groups, doc.Hosts)
	}
	if _, ok := doc.Core["traefik.portcullis.local"]; ok {
		t.Error("a core page on an unpublished template must be left out (group-gate denies it)")
	}
}

func TestBuildCollisionNeverWeaker(t *testing.T) {
	shared := "shared.portcullis.local"
	a := App{ID: "a", Enabled: true, Hosts: host(shared), GroupAccess: true, AccessGroup: "ga", AdminGroup: "aa", AdminPaths: []string{"/admin", "/x"}}
	b := App{ID: "b", Enabled: true, Hosts: host(shared), GroupAccess: true, AccessGroup: "gb", AdminGroup: "ab", AdminPaths: []string{"/admin", "/y"}}
	for _, order := range [][2]string{{"basic", "strong"}, {"strong", "basic"}} {
		a.Template, b.Template = order[0], order[1]
		doc := Build(input(t, []App{a, b}))
		if doc.Hosts[shared] != "strong" {
			t.Errorf("%v: hosts = %v, want strong", order, doc.Hosts)
		}
		if doc.Groups[shared] != "ga" {
			t.Errorf("group = %q (lowest ID must win)", doc.Groups[shared])
		}
		want := []PathGroup{{"/admin", "aa"}, {"/x", "aa"}, {"/y", "ab"}}
		if !reflect.DeepEqual(doc.PathGroups[shared], want) {
			t.Errorf("path groups = %+v", doc.PathGroups[shared])
		}
	}
	// One inherits the (weaker) default: the stricter pick wins.
	a.Template, b.Template = "", "strong"
	if doc := Build(input(t, []App{a, b})); doc.Hosts[shared] != "strong" {
		t.Errorf("default + strong: hosts = %v", doc.Hosts)
	}
	// Incomparable: all of both.
	in := input(t, nil)
	in.Templates["passkeys"] = signin.Node{Op: signin.OpAny, Items: []signin.Node{{Leaf: "passkey_synced"}, {Leaf: "passkey_device"}}}
	in.Templates["certs"] = signin.Node{Op: signin.OpAny, Items: []signin.Node{{Leaf: "yubikey_cert"}}}
	a.Template, b.Template = "passkeys", "certs"
	in.Apps = []App{a, b}
	doc := Build(in)
	if doc.Hosts[shared] != "collision.1" {
		t.Fatalf("hosts = %v, want collision.1", doc.Hosts)
	}
	want := signin.Node{Op: signin.OpAll, Items: []signin.Node{in.Templates["passkeys"], in.Templates["certs"]}}
	if !reflect.DeepEqual(doc.Templates["collision.1"], want) {
		t.Errorf("collision.1 = %+v", doc.Templates["collision.1"])
	}
	if err := signin.ValidateCompiled(doc.Templates["collision.1"]); err != nil {
		t.Error(err)
	}
	for _, r := range []string{"passkeys", "certs"} {
		if !signin.Implies(doc.Templates["collision.1"], doc.Templates[r]) {
			t.Errorf("collision.1 is weaker than %s", r)
		}
	}
}

func TestTier(t *testing.T) {
	on := defaultOn()
	g := func(op string, items ...signin.Node) *signin.Node { return &signin.Node{Op: op, Items: items} }
	l := func(m string) signin.Node { return signin.Node{Leaf: m} }
	for _, c := range []struct {
		name   string
		rule   *signin.Node
		on     map[signin.Method]bool
		public bool
		want   string
	}{
		{"all cert+key", g("all", l("yubikey_cert"), l("security_key")), on, false, TierProtected},
		{"strong", g("any", l("security_key"), l("yubikey_cert")), on, false, TierAuthAware},
		{"protected + public", g("all", l("yubikey_cert"), l("security_key")), on, true, TierAuthAware},
		{"nil", nil, on, false, TierPublic},
		{"passkeys only", g("any", *g("any", l("passkey_synced"), l("passkey_device"), l("security_key"))), on, false, TierPublic},
		{"cert switched off", g("any", l("yubikey_cert")), map[signin.Method]bool{}, false, TierPublic},
		{"not compiled", g("any", l("family:passkey")), on, false, TierProtected},
		{"empty group", g("any"), on, false, TierProtected},
	} {
		if got := Tier(c.rule, c.on, c.public); got != c.want {
			t.Errorf("%s: Tier = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "group-gate-policy.json")
	doc := Build(input(t, nil))
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
	if raw["version"] != float64(6) {
		t.Errorf("version = %v, want 6", raw["version"])
	}
	for _, k := range []string{"templates", "hosts", "core", "people", "groups", "path_groups", "public_paths"} {
		if _, ok := raw[k].(map[string]interface{}); !ok {
			t.Errorf("%s must be an object, got %T", k, raw[k])
		}
	}
	if _, ok := raw["extra_domains"].([]interface{}); !ok {
		t.Errorf("extra_domains must be an array, got %T", raw["extra_domains"])
	}
	if _, ok := raw["methods"].([]interface{}); !ok || raw["default"] != "standard" || raw["add_stronger"] != false {
		t.Errorf("methods %T default %v add_stronger %v", raw["methods"], raw["default"], raw["add_stronger"])
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
	doc := Build(input(t, apps))
	if doc.Groups[ghostHost] != DenyGroup {
		t.Errorf("ghost host = %q, want %q", doc.Groups[ghostHost], DenyGroup)
	}
	if _, ok := doc.Groups[shared]; ok {
		t.Error("deny overrode a hostname claimed by a live app")
	}
	if _, ok := doc.Groups[hubHost]; ok {
		t.Error("core host published")
	}
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
		// A public host the app doesn't route: never opened.
		{ID: "wide", Enabled: true,
			Hosts:       map[string]string{"wide." + domain: "wide." + domain},
			PublicHosts: map[string]string{"wide-admin." + domain: "wide-admin." + domain}, Public: cloud},
	}
	doc := Build(input(t, apps))
	if doc.Version != 6 || len(doc.PublicPaths) != 1 || !reflect.DeepEqual(doc.PublicPaths[cloudHost], *cloud) {
		t.Errorf("public_paths = %+v (version %d)", doc.PublicPaths, doc.Version)
	}
	if doc.Groups[goneHost] != DenyGroup {
		t.Errorf("deny app lost its deny group: %v", doc.Groups)
	}
	raw, _ := json.Marshal(doc)
	for _, want := range []string{`"version":6`, `"paths":[{"path":"/s/{token}","match":"prefix"},{"path":"/dist","match":"static"}]`,
		`"credential_cookies":["nc_token"]`, `"credential_query":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("policy file lacks %s: %s", want, raw)
		}
	}
	raw, _ = json.Marshal(Build(input(t, nil)))
	if !strings.Contains(string(raw), `"public_paths":{}`) {
		t.Errorf("empty public_paths not published as {}: %s", raw)
	}
}

func TestPolicyFileExpiring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	exp1 := Expiring{User: "jsmith", Group: "contractors", At: "2027-03-31T23:59:59Z"}
	exp2 := Expiring{User: "alee", Group: "temporary", At: "2027-06-30T23:59:59Z"}

	doc := Document{
		Version:      FileVersion,
		Default:      "standard",
		ExtraDomains: []string{},
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

	if parsed["version"] != float64(6) {
		t.Errorf("version = %v, want 6", parsed["version"])
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

// The contract §4 example: two Grafana instances, one on the main domain
// on the default, one on an enrolled domain picked onto Strong, and the
// default Vaultwarden instance.
func TestBuildContractExample(t *testing.T) {
	main := "portcullis.example.com"
	on := defaultOn()
	in := BuildInput{
		Apps: []App{
			{ID: "grafana-team-a", Enabled: true, Hosts: host("grafana-team-a." + main), GroupAccess: true, AccessGroup: "users_grafana-team-a"},
			{ID: "grafana-team-b", Enabled: true, Hosts: host("grafana.team-b.example.org"), GroupAccess: true, AccessGroup: "users_grafana-team-b", Template: "strong"},
			{ID: "vaultwarden", Enabled: true, Hosts: host("passwords." + main), GroupAccess: true, AccessGroup: "users_vaultwarden",
				AdminGroup: "admin_vaultwarden", AdminPaths: []string{"/admin"}},
		},
		Default: "standard", Core: map[string]string{"portal": "", "hub": "strong", "people": "strong", "directory": "", "metrics": "", "traefik": ""},
		Templates: compiledBuiltins(t, on), Methods: onList(on),
		People:     map[string][]signin.Method{"alice": {signin.PasskeySynced, signin.SecurityKey}, "bob": {signin.PasskeySynced}},
		MainDomain: main, ExtraDomains: []string{"team-b.example.org"},
	}
	delete(in.Templates, "basic") // starts disabled (D12)
	delete(in.Templates, "yubikey-and-certificate")
	doc := Build(in)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal(raw, &got)
	want := map[string]any{}
	if err := json.Unmarshal([]byte(`{
  "version": 6,
  "methods": ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"],
  "templates": {
    "standard": {"op": "any", "items": [
      {"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
      {"op": "any", "items": ["yubikey_cert"]}
    ]},
    "strong": {"op": "any", "items": ["security_key", "yubikey_cert"]}
  },
  "default": "standard",
  "hosts": {"grafana.team-b.example.org": "strong"},
  "core": {
    "directory.portcullis.example.com": "standard",
    "hub.portcullis.example.com": "strong",
    "metrics.portcullis.example.com": "standard",
    "people.portcullis.example.com": "strong",
    "portcullis.example.com": "standard",
    "traefik.portcullis.example.com": "standard"
  },
  "people": {"alice": ["passkey_synced", "security_key"], "bob": ["passkey_synced"]},
  "add_stronger": false,
  "extra_domains": ["team-b.example.org"],
  "groups": {
    "grafana-team-a.portcullis.example.com": "users_grafana-team-a",
    "grafana.team-b.example.org": "users_grafana-team-b",
    "passwords.portcullis.example.com": "users_vaultwarden"
  },
  "path_groups": {"passwords.portcullis.example.com": [{"prefix": "/admin", "group": "admin_vaultwarden"}]},
  "public_paths": {},
  "expiring": []
}`), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("document =\n%s", raw)
	}
}

// CoreHosts is the main domain plus the eight core subdomains (auth and
// mcp included); none of them is ever published for an app, as a public
// host or a denied one.
func TestCoreHostsNeverPublished(t *testing.T) {
	main := "portcullis.local"
	core := CoreHosts(main)
	want := []string{main}
	for _, sub := range []string{"auth", "traefik", "hub", "directory", "enroll", "metrics", "people", "mcp"} {
		want = append(want, sub+"."+main)
	}
	if len(core) != len(want) {
		t.Errorf("CoreHosts = %v", core)
	}
	for _, h := range want {
		if !core[h] {
			t.Errorf("CoreHosts lacks %s", h)
		}
	}
	all := map[string]string{}
	for h := range core {
		all[h] = h
	}
	pub := &PublicEntry{Paths: []PublicPath{{"/s", "prefix"}}}
	doc := Build(input(t, []App{
		{ID: "pub", Enabled: true, Hosts: all, PublicHosts: all, Public: pub, GroupAccess: true, AccessGroup: "g", Template: "strong"},
		{ID: "ghost", Enabled: true, Deny: true, Hosts: all},
	}))
	for h := range core {
		if _, ok := doc.Hosts[h]; ok {
			t.Errorf("%s in hosts", h)
		}
		if _, ok := doc.Groups[h]; ok {
			t.Errorf("%s in groups (deny or app)", h)
		}
		if _, ok := doc.PublicPaths[h]; ok {
			t.Errorf("%s in public_paths", h)
		}
	}
}
