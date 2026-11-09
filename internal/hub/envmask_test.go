package hub

import (
	"maps"
	"os"
	"testing"
)

// maskAppManifest has every kind of variable that always holds a secret
// (SecretEnvNames): a Keycloak client's secret_env the Hub doesn't
// generate, a generated env entry and a secret option's env delivery.
const maskAppManifest = `name: Mask App
category: misc
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_maskapp
keycloak_clients:
  - client_id: maskapp
    secret_env: CLIENT_VALUE
    redirect_uri: https://maskapp.{{DOMAIN}}/cb
env:
  - key: GEN_VALUE
    generate: random
settings:
  options:
    - key: api_key
      label: API key
      type: secret
      applies: restart
      delivery: [{env: OPT_VALUE}]
`

const maskAppCompose = "services:\n  web:\n    image: x\n    environment:\n      C: ${CLIENT_VALUE}\n      G: ${GEN_VALUE}\n      O: ${OPT_VALUE}\n" +
	"    labels:\n      traefik.http.routers.maskapp.rule: Host(`maskapp.${PORTCULLIS_DOMAIN}`)\n"

// TestEnvOverrideNeverWritesMask (Task 17b concern, §11.9): an env
// override never writes a mask — "[set]" (the env rows') or "[secret]"
// (the MCP's) — nor any value into a client secret_env, a generated
// variable or a secret option's variable: each is refused (400) and the
// .env stays byte for byte; the rows never show the secrets.
func TestEnvOverrideNeverWritesMask(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"maskapp": {maskAppManifest, maskAppCompose}})
	if f.h.Template("maskapp") == nil {
		t.Fatal("maskapp fixture not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 0)
	saveSecret(t, f, "maskapp", "api_key", setSecret("opt-VALUE-0123456789"))
	if err := f.h.Enable("maskapp"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	path := f.h.envPath("maskapp")
	before := readEnvFile(path)
	for _, k := range []string{"GEN_VALUE", "OPT_VALUE"} {
		if v := before[k]; v == "" || isEnvMask(v) {
			t.Fatalf("%s = %q before the test", k, v)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"CLIENT_VALUE", "GEN_VALUE", "OPT_VALUE", "FREE_VAR"} {
		for _, v := range []string{"[set]", "[secret]", "client-VALUE-new"} {
			if k == "FREE_VAR" && !isEnvMask(v) {
				continue
			}
			if err := envOverrideErr(f.h, "maskapp", k, v); statusOf(err) != 400 {
				t.Errorf("override %s=%s = %v, want 400", k, v, err)
			}
			if got, _ := os.ReadFile(path); string(got) != string(raw) {
				t.Fatalf("override %s=%s changed the env:\n%s", k, v, got)
			}
		}
	}
	vars, err := envView(f.h, "maskapp")
	if err != nil {
		t.Fatal(err)
	}
	if vars["OPT_VALUE"] != "[set]" || vars["GEN_VALUE"] != "[set]" {
		t.Errorf("rows show OPT_VALUE %q GEN_VALUE %q", vars["OPT_VALUE"], vars["GEN_VALUE"])
	}
	if after := readEnvFile(path); !maps.Equal(after, before) {
		t.Errorf("the env changed: %v, was %v", after, before)
	}
}
