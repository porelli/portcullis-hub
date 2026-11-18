package keycloak_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

var cliRedirects = []string{"http://127.0.0.1:38917/callback", "http://127.0.0.1:38918/callback", "http://127.0.0.1:38919/callback"}

// checkCLIClient asserts every contract §18.2 setting of portcullis-cli.
func checkCLIClient(t *testing.T, kc *kctest.Server) {
	t.Helper()
	got := kc.ClientByClientID(keycloak.CLIClientID)
	if got == nil {
		t.Fatal("no portcullis-cli client")
	}
	isTrue := func(p *bool) bool { return p != nil && *p }
	isFalse := func(p *bool) bool { return p != nil && !*p }
	if !isTrue(got.PublicClient) || !isTrue(got.StandardFlowEnabled) {
		t.Errorf("public %v standard %v", got.PublicClient, got.StandardFlowEnabled)
	}
	if !isFalse(got.DirectAccessGrantsEnabled) || !isFalse(got.ImplicitFlowEnabled) || !isFalse(got.ServiceAccountsEnabled) {
		t.Errorf("direct %v implicit %v service accounts %v: want all false", got.DirectAccessGrantsEnabled, got.ImplicitFlowEnabled, got.ServiceAccountsEnabled)
	}
	if !isFalse(got.ConsentRequired) {
		t.Errorf("consent required %v", got.ConsentRequired)
	}
	for k, want := range map[string]string{
		"pkce.code.challenge.method":                "S256",
		"use.refresh.tokens":                        "false",
		"oauth2.device.authorization.grant.enabled": "false",
		"oidc.ciba.grant.enabled":                   "false",
		"standard.token.exchange.enabled":           "false",
		keycloak.OwnerAttr:                          "portcullis-cli",
	} {
		if got.Attributes[k] != want {
			t.Errorf("attribute %s = %q, want %q", k, got.Attributes[k], want)
		}
	}
	if !slices.Equal(got.RedirectURIs, cliRedirects) {
		t.Errorf("redirect URIs %v", got.RedirectURIs)
	}
	if len(got.WebOrigins) != 0 {
		t.Errorf("web origins %v, want none", got.WebOrigins)
	}
	if s := kc.ClientScopes(got.ID); strings.Join(s, ",") != "acr,basic" {
		t.Errorf("default scopes %v, want exactly acr, basic", s)
	}
	if s := kc.OptionalScopes(got.ID); len(s) != 0 {
		t.Errorf("optional scopes %v, want none (no offline_access)", s)
	}
	if len(got.AuthenticationFlowBindingOverrides) != 0 {
		t.Errorf("flow overrides %v", got.AuthenticationFlowBindingOverrides)
	}
	ms := kc.ClientMappers(got.ID)
	u, okU := ms[keycloak.CLIUsernameMapper]
	pf, okF := ms["portcullis-fresh"]
	if len(ms) != 2 || !okU || !okF {
		t.Fatalf("client mappers %v, want only %s and portcullis-fresh", ms, keycloak.CLIUsernameMapper)
	}
	if u.Config["claim.name"] != "preferred_username" || u.Config["id.token.claim"] != "true" || u.Config["access.token.claim"] != "false" {
		t.Errorf("username mapper %+v", u)
	}
	if pf.ProtocolMapper != "portcullis-fresh" || pf.Config["id.token.claim"] != "true" || pf.Config["access.token.claim"] != "false" {
		t.Errorf("portcullis-fresh mapper %+v", pf)
	}
}

func TestEnsureCLIClientCreatesExact(t *testing.T) {
	ctx := context.Background()
	kc := freshRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	for i := 0; i < 2; i++ {
		if err := c.EnsureCLIClient(ctx); err != nil {
			t.Fatal(err)
		}
		checkCLIClient(t, kc)
	}
	id := kc.ClientByClientID(keycloak.CLIClientID).ID
	// Drift is put back: grants on, refresh tokens, a web origin, an extra
	// redirect URI, the device grant, extra scopes.
	kc.UpdateClient(id, func(cl *kctest.Client) {
		yes, no := true, false
		cl.DirectAccessGrantsEnabled, cl.ImplicitFlowEnabled, cl.ServiceAccountsEnabled, cl.ConsentRequired = &yes, &yes, &yes, &yes
		cl.PublicClient = &no
		cl.Attributes["use.refresh.tokens"] = "true"
		cl.Attributes["oauth2.device.authorization.grant.enabled"] = "true"
		cl.RedirectURIs = append(cl.RedirectURIs, "http://127.0.0.1:40000/callback", "http://localhost:38917/callback")
		cl.WebOrigins = []string{"+"}
	})
	kc.SetOptionalScopes(id, "offline_access")
	if err := c.EnsureCLIClient(ctx); err != nil {
		t.Fatal(err)
	}
	checkCLIClient(t, kc)
	if kc.ClientByClientID(keycloak.CLIClientID).ID != id {
		t.Error("client re-created")
	}
}

func TestEnsureCLIClientConflict(t *testing.T) {
	ctx := context.Background()
	for _, attrs := range []map[string]string{nil, {keycloak.OwnerAttr: "someapp"}, {keycloak.OwnerAttr: "portcullis-fresh-auth"}} {
		kc := freshRealm(t)
		id := kc.AddClient(keycloak.CLIClientID, attrs, "profile", "groups")
		c := keycloak.New(kc.HTTP.URL, "admin", "admin")
		var ce *keycloak.ConflictError
		if err := c.EnsureCLIClient(ctx); !errors.As(err, &ce) {
			t.Fatalf("existing client %v: %v, want *ConflictError", attrs, err)
		}
		if kc.CountCalls("PUT") != 0 || kc.CountCalls("DELETE") != 0 || kc.CountCalls("POST /admin") != 0 {
			t.Errorf("a foreign client was changed: %v", kc.Calls)
		}
		if s := kc.ClientScopes(id); strings.Join(s, ",") != "groups,profile" {
			t.Errorf("scopes changed: %v", s)
		}
	}
}

func TestEnsureCLIClientDeletesExtraMapper(t *testing.T) {
	ctx := context.Background()
	kc := freshRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	if err := c.EnsureCLIClient(ctx); err != nil {
		t.Fatal(err)
	}
	id := kc.ClientByClientID(keycloak.CLIClientID).ID
	kc.AddClientMapper(id, "fresh-forged", "oidc-hardcoded-claim-mapper", map[string]string{"claim.name": "pc_fresh", "claim.value": "security_key"})
	kc.AddClientMapper(id, "user-forged", "oidc-hardcoded-claim-mapper", map[string]string{"claim.name": "preferred_username", "claim.value": "root"})
	if err := c.EnsureCLIClient(ctx); err != nil {
		t.Fatal(err)
	}
	checkCLIClient(t, kc)
}

func TestProtectedCLIClient(t *testing.T) {
	ctx := context.Background()
	kc := freshRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	var ce *keycloak.ConflictError
	_, err := c.RegisterClient(ctx, keycloak.ClientSpec{ClientID: keycloak.CLIClientID, TemplateID: keycloak.CLIClientID, RedirectURIs: []string{"https://x.example.org/"}})
	if !errors.As(err, &ce) {
		t.Errorf("RegisterClient(portcullis-cli) = %v, want *ConflictError", err)
	}
	if kc.ClientByClientID(keycloak.CLIClientID) != nil {
		t.Error("a template created portcullis-cli")
	}
}
