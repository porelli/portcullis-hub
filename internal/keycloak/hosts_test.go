package keycloak_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

func TestUpdateClientHosts(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	id := kc.AddClient("chat-b", map[string]string{keycloak.OwnerAttr: "chat-b"})
	kc.SetClientURIs(id, []string{"https://a.example.org/cb", "https://keep.example.org/x"}, []string{"https://a.example.org", "+", "https://b.example.org"})
	spec := keycloak.ClientSpec{ClientID: "chat-b", TemplateID: "chat-b", RedirectURIs: []string{"https://n.example.org/cb"}}
	if err := c.UpdateClientHosts(ctx, spec, []string{"https://a.example.org/cb"}, map[string]string{"a.example.org": "n.example.org"}); err != nil {
		t.Fatal(err)
	}
	got := kc.ClientByClientID("chat-b")
	if strings.Join(got.RedirectURIs, ",") != "https://keep.example.org/x,https://n.example.org/cb" || strings.Join(got.WebOrigins, ",") != "https://n.example.org,+,https://b.example.org" {
		t.Errorf("client = %v %v", got.RedirectURIs, got.WebOrigins)
	}
	// Another instance's client, a core client, a missing one.
	var ce *keycloak.ConflictError
	spec.TemplateID = "chat-c"
	if err := c.UpdateClientHosts(ctx, spec, nil, nil); !errors.As(err, &ce) {
		t.Errorf("foreign client: %v", err)
	}
	if err := c.UpdateClientHosts(ctx, keycloak.ClientSpec{ClientID: keycloak.ForwardAuthClient}, nil, nil); !errors.As(err, &ce) {
		t.Errorf("core client: %v", err)
	}
	if err := c.UpdateClientHosts(ctx, keycloak.ClientSpec{ClientID: "nope", TemplateID: "nope"}, nil, nil); !errors.Is(err, keycloak.ErrClientNotFound) {
		t.Errorf("missing client: %v", err)
	}
}

func TestUpdateForwardAuthCallbacks(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	id := kc.AddClient(keycloak.ForwardAuthClient, nil)
	kc.SetClientURIs(id, []string{"https://auth.example.org/oauth2/callback", "https://x.team.org/oauth2/callback"}, nil)
	if err := c.UpdateForwardAuthCallbacks(ctx, nil, nil); err != nil || kc.CountCalls("PUT") != 0 {
		t.Errorf("nothing to do: %v, %d PUTs", err, kc.CountCalls("PUT"))
	}
	for _, bad := range []string{"https://x.team.org/other", "http://x.team.org/oauth2/callback", "https://*.team.org/oauth2/callback"} {
		if err := c.UpdateForwardAuthCallbacks(ctx, []string{bad}, nil); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := c.UpdateForwardAuthCallbacks(ctx, []string{keycloak.CallbackURI("g.team.org")}, []string{keycloak.CallbackURI("x.team.org")}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(kc.ClientByClientID(keycloak.ForwardAuthClient).RedirectURIs, ","); got != "https://auth.example.org/oauth2/callback,https://g.team.org/oauth2/callback" {
		t.Errorf("callbacks = %s", got)
	}
}
