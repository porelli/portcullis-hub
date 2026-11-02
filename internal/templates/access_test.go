package templates

import (
	"os"
	"path/filepath"
	"testing"
)

const accessCompose = "services:\n  s:\n    labels:\n      traefik.http.routers.app.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`)\n"

func discoverOne(t *testing.T, manifest, compose string) []Template {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "x"), 0755)
	os.WriteFile(filepath.Join(dir, "x", "manifest.yaml"), []byte(manifest), 0644)
	os.WriteFile(filepath.Join(dir, "x", "compose.yml"), []byte(compose), 0644)
	return Discover(dir, "s", "example.org", nil)
}

func TestAccessRoleEnforced(t *testing.T) {
	for _, c := range []struct {
		auth Auth
		want bool
	}{
		{Auth{Method: "native-oidc", AccessGroup: "users_x"}, true},
		{Auth{Method: "native-oidc", AccessGroup: "users_x", GroupAccess: true}, false},
		{Auth{Method: "native-oidc", AccessGroup: "users_x", GroupAccess: true, KeycloakAccessRole: true}, true},
		{Auth{Method: "native-oidc"}, false}, // no group to grant it to
		{Auth{Method: "forward-auth", AccessGroup: "users_x"}, false},
	} {
		m := Manifest{Auth: c.auth}
		if got := m.AccessRoleEnforced(); got != c.want {
			t.Errorf("%+v: %v, want %v", c.auth, got, c.want)
		}
	}
}

func TestAccessManifestFields(t *testing.T) {
	good := `name: X
instances: multi
auth:
  method: native-oidc
  group_access: true
  keycloak_access_role: true
  access_group: users_x
hosts:
  immutable: [app]
keycloak_clients:
  - client_id: x
    redirect_uri: https://{{HOST_APP}}/cb
    backchannel_logout_url: https://{{HOST_APP}}/index.php/apps/user_oidc/backchannel-logout/Portcullis
`
	ts := discoverOne(t, good, accessCompose)
	if len(ts) != 1 {
		t.Fatal("valid manifest not loaded")
	}
	cat := ts[0]
	if !cat.Manifest.AccessRoleEnforced() || !cat.Manifest.ImmutableHost("app") || cat.Manifest.ImmutableHost("other") {
		t.Errorf("manifest = %+v", cat.Manifest)
	}
	if got := cat.Manifest.Clients[0].BackchannelLogoutURL; got != "https://app.example.org/index.php/apps/user_oidc/backchannel-logout/Portcullis" {
		t.Errorf("catalog backchannel = %s", got)
	}
	v, err := cat.Instance("x-b", map[string]string{"app": "app-b.example.org"}, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Manifest.Clients[0].BackchannelLogoutURL; got != "https://app-b.example.org/index.php/apps/user_oidc/backchannel-logout/Portcullis" {
		t.Errorf("instance backchannel = %s", got)
	}

	bad := map[string]string{
		"access role on forward-auth": "name: X\nauth:\n  method: forward-auth\n  keycloak_access_role: true\n  access_group: users_x\n",
		"access role without group":   "name: X\nauth:\n  method: native-oidc\n  group_access: true\n  keycloak_access_role: true\nkeycloak_clients:\n  - client_id: x\n",
		"backchannel http":            "name: X\nauth:\n  method: native-oidc\n  group_access: true\nkeycloak_clients:\n  - {client_id: x, backchannel_logout_url: \"http://{{HOST_APP}}/bc\"}\n",
		"backchannel foreign host":    "name: X\nauth:\n  method: native-oidc\n  group_access: true\nkeycloak_clients:\n  - {client_id: x, backchannel_logout_url: \"https://evil.example.com/bc\"}\n",
		"backchannel query":           "name: X\nauth:\n  method: native-oidc\n  group_access: true\nkeycloak_clients:\n  - {client_id: x, backchannel_logout_url: \"https://{{HOST_APP}}/bc?x=1\"}\n",
		"backchannel unknown router":  "name: X\nauth:\n  method: native-oidc\n  group_access: true\nkeycloak_clients:\n  - {client_id: x, backchannel_logout_url: \"https://{{HOST_NOPE}}/bc\"}\n",
		"multi backchannel on DOMAIN": "name: X\ninstances: multi\nauth:\n  method: native-oidc\n  group_access: true\nkeycloak_clients:\n  - {client_id: x, backchannel_logout_url: \"https://app.{{DOMAIN}}/bc\"}\n",
		"native-oidc open, no group":  "name: X\nauth:\n  method: native-oidc\nkeycloak_clients:\n  - client_id: x\n",
		"immutable unknown router":    "name: X\nauth:\n  method: forward-auth\nhosts:\n  immutable: [nope]\n",
		"immutable empty":             "name: X\nauth:\n  method: forward-auth\nhosts:\n  immutable: []\n",
	}
	for name, m := range bad {
		if got := discoverOne(t, m, accessCompose); len(got) != 0 {
			t.Errorf("%s: loaded", name)
		}
	}
}
