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

// TestSaveEnvNeverWritesMask (Task 17b concern): the HTTP Expert Env save
// never writes the literal mask "[set]" (Env's) or "[secret]" (get_env's)
// into a client secret_env, a generated variable or a secret option's
// variable: a posted mask is "unchanged", as a secret option's [set]
// always was. Real values are still written (client secret) or refused
// (secret option), and a mask for an unset variable writes nothing.
func TestSaveEnvNeverWritesMask(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"maskapp": {maskAppManifest, maskAppCompose}})
	if f.h.Template("maskapp") == nil {
		t.Fatal("maskapp fixture not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 0)
	saveSecret(t, f, "maskapp", "api_key", setSecret("opt-VALUE-0123456789"))
	const client = "client-VALUE-0123456789"
	if err := f.h.SaveEnv("maskapp", map[string]string{"CLIENT_VALUE": client}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("maskapp"); err != nil {
		t.Fatal(err)
	}
	path := f.h.envPath("maskapp")
	before := readEnvFile(path)
	for _, k := range []string{"CLIENT_VALUE", "GEN_VALUE", "OPT_VALUE"} {
		if v := before[k]; v == "" || isEnvMask(v) {
			t.Fatalf("%s = %q before the test", k, v)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Each mask on each secret variable, alone.
	for _, k := range []string{"CLIENT_VALUE", "GEN_VALUE", "OPT_VALUE"} {
		for _, mask := range []string{"[set]", "[secret]"} {
			if err := f.h.SaveEnv("maskapp", map[string]string{k: mask}); err != nil {
				t.Errorf("SaveEnv %s=%s = %v, want unchanged", k, mask, err)
			}
			if got, _ := os.ReadFile(path); string(got) != string(raw) {
				t.Fatalf("SaveEnv %s=%s changed the env:\n%s", k, mask, got)
			}
		}
	}
	// The Expert UI's round trip: everything Env showed, with the masks
	// the AI path shows on top.
	vars, _, err := f.h.Env("maskapp")
	if err != nil {
		t.Fatal(err)
	}
	if vars["OPT_VALUE"] != "[set]" {
		t.Errorf("Env shows OPT_VALUE %q", vars["OPT_VALUE"])
	}
	vars["CLIENT_VALUE"], vars["GEN_VALUE"] = "[set]", "[secret]"
	if err := f.h.SaveEnv("maskapp", vars); err != nil {
		t.Fatalf("SaveEnv of the masked view = %v", err)
	}
	if after := readEnvFile(path); !maps.Equal(after, before) {
		t.Errorf("the env changed: %v, was %v", after, before)
	}
	// A real value still goes through the existing rules.
	if err := f.h.SaveEnv("maskapp", map[string]string{"CLIENT_VALUE": "client-VALUE-new"}); err != nil {
		t.Errorf("SaveEnv of a new client secret = %v", err)
	}
	if got := readEnvFile(path)["CLIENT_VALUE"]; got != "client-VALUE-new" {
		t.Errorf("CLIENT_VALUE = %q", got)
	}
	if err := f.h.SaveEnv("maskapp", map[string]string{"OPT_VALUE": "other"}); statusOf(err) != 400 {
		t.Errorf("SaveEnv changing a secret option = %v, want 400", err)
	}
	// An unset client secret: a mask writes nothing.
	if err := setEnvVars(path, map[string]string{"CLIENT_VALUE": ""}, false); err != nil {
		t.Fatal(err)
	}
	for _, mask := range []string{"[set]", "[secret]"} {
		if err := f.h.SaveEnv("maskapp", map[string]string{"CLIENT_VALUE": mask}); err != nil {
			t.Errorf("SaveEnv of %s for an unset client secret = %v", mask, err)
		}
		if got := readEnvFile(path)["CLIENT_VALUE"]; got != "" {
			t.Errorf("an unset client secret got %q", got)
		}
	}
	if readEnvFile(path)["OPT_VALUE"] != before["OPT_VALUE"] || readEnvFile(path)["GEN_VALUE"] != before["GEN_VALUE"] {
		t.Error("another secret changed")
	}
}
