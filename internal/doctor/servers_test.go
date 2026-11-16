package doctor

import (
	"strings"
	"testing"
)

func TestServerSecretsNotRotated(t *testing.T) {
	if f := (serversCheck{kind: KindServerSecretsNotRotated}).Run(&Inputs{}); f != nil {
		t.Errorf("no input: %v", f)
	}
	f := (serversCheck{kind: KindServerSecretsNotRotated}).Run(&Inputs{Servers: &ServersIn{NotRotated: map[string]string{"nas": "keycloak down", "pi": "x"}}})
	if len(f) != 2 || f[0].Kind != KindServerSecretsNotRotated || f[0].Severity != Problem || !strings.Contains(f[0].Title, "nas") || !strings.Contains(f[0].Why, "keycloak down") {
		t.Errorf("%+v", f)
	}
}

func TestServersKinds(t *testing.T) {
	in := &Inputs{Servers: &ServersIn{Quarantined: map[string]string{"app": "nas: a symlink"}, PlacementInvalid: map[string]string{"chat": "ai.chat"}, Stuck: map[string]string{"cloud": "server nas"}}}
	for kind, id := range map[string]string{KindInstanceQuarantined: "app", KindPlacementInvalid: "chat", KindMoveStuck: "cloud"} {
		f := (serversCheck{kind: kind}).Run(in)
		if len(f) != 1 || f[0].Kind != kind || f[0].Severity != Problem || !strings.Contains(f[0].Title, id) {
			t.Errorf("%s: %+v", kind, f)
		}
	}
}
