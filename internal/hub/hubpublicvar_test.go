package hub

import (
	"slices"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

// TestEnvSecretsSkipsHubPublicVars (Task 17b fix round 1): the Hub-set
// instance variables of contract §3.1 are never redacted for their name;
// generated values, secret-looking template variables and provider
// secrets still are.
func TestEnvSecretsSkipsHubPublicVars(t *testing.T) {
	tm := &templates.Template{Manifest: templates.Manifest{Env: []templates.EnvVar{{Key: "PLAIN_GEN", Generate: "random"}}}}
	vars := map[string]string{
		"PORTCULLIS_HOST_SECRETAPP":          "secretapp.example.org",
		"PORTCULLIS_INSTANCE":                "token-box",
		"PORTCULLIS_ACCESS_GROUP":            "users_token-box",
		"PORTCULLIS_ADMIN_GROUP":             "admin_token-box",
		"PORTCULLIS_OIDC_CLIENT_ID":          "token-box-client",
		"PORTCULLIS_OIDC_CLIENT_ID_KEYCLOAK": "keycloak-client",
		"PORTCULLIS_AI_READONLY_TOKENS":      "truthy",
		"API_TOKEN":                          "tok-value-123",
		"OIDC_CLIENT_SECRET":                 "client-secret-123",
		"PLAIN_GEN":                          "generated-123",
		"PORTCULLIS_AI_PROVIDER_OLLAMA_KEY":  "provider-key-123",
		"PORTCULLIS_SECRET_THING":            "bare-prefix-secret",
	}
	got := envSecrets(tm, vars)
	for _, v := range []string{"secretapp.example.org", "token-box", "users_token-box", "admin_token-box", "token-box-client", "keycloak-client", "truthy"} {
		if slices.Contains(got, v) {
			t.Errorf("%q is redacted", v)
		}
	}
	for _, v := range []string{"tok-value-123", "client-secret-123", "generated-123", "provider-key-123", "bare-prefix-secret"} {
		if !slices.Contains(got, v) {
			t.Errorf("%q is not redacted", v)
		}
	}
}
