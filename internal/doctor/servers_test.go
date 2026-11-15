package doctor

import (
	"strings"
	"testing"
)

func TestServerSecretsNotRotated(t *testing.T) {
	if f := (serverSecretsCheck{}).Run(&Inputs{}); f != nil {
		t.Errorf("no input: %v", f)
	}
	f := (serverSecretsCheck{}).Run(&Inputs{Servers: &ServersIn{NotRotated: map[string]string{"nas": "keycloak down", "pi": "x"}}})
	if len(f) != 2 || f[0].Kind != KindServerSecretsNotRotated || f[0].Severity != Problem || !strings.Contains(f[0].Title, "nas") || !strings.Contains(f[0].Why, "keycloak down") {
		t.Errorf("%+v", f)
	}
}
