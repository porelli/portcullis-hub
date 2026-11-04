package keycloak_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

const (
	faRedirect = "https://people.example.org/"
	faOrigin   = "https://people.example.org"
)

// freshRealm is a fake realm with the scopes core keeps (basic, acr with
// its amr mapper, groups, profile, email, portcullis-invite-client) plus
// the Hub's attributes scope and offline_access.
func freshRealm(t *testing.T) *kctest.Server {
	kc := kctest.New(t)
	for _, n := range []string{"basic", "acr", "groups", "profile", "email", keycloak.AttributesScope, "portcullis-invite-client", "offline_access"} {
		kc.AddScope(n)
	}
	return kc
}

// checkFreshClient asserts every F17 setting of the fresh-auth client.
func checkFreshClient(t *testing.T, kc *kctest.Server) {
	t.Helper()
	got := kc.ClientByClientID(freshauth.ClientID)
	if got == nil {
		t.Fatal("no fresh-auth client")
	}
	isTrue := func(p *bool) bool { return p != nil && *p }
	isFalse := func(p *bool) bool { return p != nil && !*p }
	if !isTrue(got.PublicClient) {
		t.Error("not a public client")
	}
	if !isTrue(got.StandardFlowEnabled) {
		t.Error("standard flow off")
	}
	if !isFalse(got.DirectAccessGrantsEnabled) || !isFalse(got.ImplicitFlowEnabled) || !isFalse(got.ServiceAccountsEnabled) {
		t.Errorf("direct %v implicit %v service accounts %v: want all false", got.DirectAccessGrantsEnabled, got.ImplicitFlowEnabled, got.ServiceAccountsEnabled)
	}
	for k, want := range map[string]string{
		"pkce.code.challenge.method":                "S256",
		"use.refresh.tokens":                        "false",
		"oauth2.device.authorization.grant.enabled": "false",
		"oidc.ciba.grant.enabled":                   "false",
		"standard.token.exchange.enabled":           "false",
		keycloak.OwnerAttr:                          freshauth.ClientID,
	} {
		if got.Attributes[k] != want {
			t.Errorf("attribute %s = %q, want %q", k, got.Attributes[k], want)
		}
	}
	if !slices.Equal(got.RedirectURIs, []string{faRedirect}) || !slices.Equal(got.WebOrigins, []string{faOrigin}) {
		t.Errorf("redirect URIs %v web origins %v", got.RedirectURIs, got.WebOrigins)
	}
	if s := kc.ClientScopes(got.ID); strings.Join(s, ",") != "acr,basic" {
		t.Errorf("default scopes %v, want exactly acr, basic", s)
	}
	if s := kc.OptionalScopes(got.ID); len(s) != 0 {
		t.Errorf("optional scopes %v, want none", s)
	}
	if len(got.AuthenticationFlowBindingOverrides) != 0 {
		t.Errorf("flow overrides %v, want none", got.AuthenticationFlowBindingOverrides)
	}
	// Exactly one client mapper: preferred_username in the ID token (the
	// profile scope, which normally carries it, is not attached).
	ms := kc.ClientMappers(got.ID)
	m, ok := ms[keycloak.FreshAuthUsernameMapper]
	if len(ms) != 1 || !ok {
		t.Fatalf("client mappers %v, want only %s", ms, keycloak.FreshAuthUsernameMapper)
	}
	if m.ProtocolMapper != "oidc-usermodel-attribute-mapper" || m.Config["user.attribute"] != "username" ||
		m.Config["claim.name"] != "preferred_username" || m.Config["id.token.claim"] != "true" {
		t.Errorf("username mapper %+v", m)
	}
}

func TestEnsureFreshAuthClient(t *testing.T) {
	ctx := context.Background()
	kc := freshRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	if err := c.EnsureFreshAuthClient(ctx, faRedirect, faOrigin); err != nil {
		t.Fatal(err)
	}
	checkFreshClient(t, kc)
	id := kc.ClientByClientID(freshauth.ClientID).ID

	// Idempotent: the same client, still exactly so.
	if err := c.EnsureFreshAuthClient(ctx, faRedirect, faOrigin); err != nil {
		t.Fatal(err)
	}
	checkFreshClient(t, kc)
	if kc.ClientByClientID(freshauth.ClientID).ID != id {
		t.Error("client re-created")
	}

	// Drift is put back: grants switched on, extra scopes, a hardcoded amr
	// mapper (would forge a proof), a flow override, extra URIs.
	kc.UpdateClient(id, func(cl *kctest.Client) {
		yes, no := true, false
		cl.DirectAccessGrantsEnabled, cl.ImplicitFlowEnabled, cl.ServiceAccountsEnabled = &yes, &yes, &yes
		cl.PublicClient, cl.StandardFlowEnabled = &no, &no
		cl.Attributes["use.refresh.tokens"] = "true"
		cl.Attributes["pkce.code.challenge.method"] = "plain"
		cl.Attributes["oauth2.device.authorization.grant.enabled"] = "true"
		cl.RedirectURIs = append(cl.RedirectURIs, "https://evil.example.com/*")
		cl.WebOrigins = []string{"*"}
		cl.DefaultClientScopes = append(cl.DefaultClientScopes, "groups", keycloak.AttributesScope, "portcullis-invite-client")
		cl.OptionalClientScopes = []string{"offline_access", "profile"}
		cl.AuthenticationFlowBindingOverrides = map[string]string{"browser": "weak-flow"}
	})
	kc.AddClientMapper(id, "amr-forged", "oidc-hardcoded-claim-mapper", map[string]string{"claim.name": "amr", "claim.value": "hwk"})
	if err := c.EnsureFreshAuthClient(ctx, faRedirect, faOrigin); err != nil {
		t.Fatal(err)
	}
	checkFreshClient(t, kc)

	// A realm without the acr scope (no amr: every proof refused): an error.
	kc2 := kctest.New(t)
	kc2.AddScope("basic")
	if err := keycloak.New(kc2.HTTP.URL, "admin", "admin").EnsureFreshAuthClient(ctx, faRedirect, faOrigin); err == nil || !strings.Contains(err.Error(), "acr") {
		t.Errorf("realm without acr: %v", err)
	}

	// Bad arguments never reach Keycloak.
	for _, bad := range [][2]string{
		{"http://people.example.org/", faOrigin},
		{"https://people.example.org/*", faOrigin},
		{"https://people.example.org/x", faOrigin},
		{faRedirect, "https://people.example.org/"},
		{faRedirect, "https://other.example.org"},
		{faRedirect, "*"},
		{"", ""},
	} {
		if err := c.EnsureFreshAuthClient(ctx, bad[0], bad[1]); err == nil {
			t.Errorf("EnsureFreshAuthClient(%q, %q) accepted", bad[0], bad[1])
		}
	}
}

func TestEnsureFreshAuthClientConflict(t *testing.T) {
	ctx := context.Background()
	for _, attrs := range []map[string]string{nil, {keycloak.OwnerAttr: "someapp"}} {
		kc := freshRealm(t)
		id := kc.AddClient(freshauth.ClientID, attrs, "profile", "groups")
		c := keycloak.New(kc.HTTP.URL, "admin", "admin")
		var ce *keycloak.ConflictError
		if err := c.EnsureFreshAuthClient(ctx, faRedirect, faOrigin); !errors.As(err, &ce) {
			t.Fatalf("existing client %v: %v, want *ConflictError", attrs, err)
		}
		// Left alone.
		if kc.CountCalls("PUT") != 0 || kc.CountCalls("DELETE") != 0 || kc.CountCalls("POST /admin") != 0 {
			t.Errorf("a foreign client was changed: %v", kc.Calls)
		}
		if s := kc.ClientScopes(id); strings.Join(s, ",") != "groups,profile" {
			t.Errorf("scopes changed: %v", s)
		}
	}
}

// The Hub's other Keycloak syncs never touch the fresh-auth client: no
// template may register a client of that id, and the attributes scope
// (attached to every Hub-tagged client) is not attached to it.
func TestFreshAuthClientLeftAloneByOtherSyncs(t *testing.T) {
	ctx := context.Background()
	kc := freshRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	if err := c.EnsureFreshAuthClient(ctx, faRedirect, faOrigin); err != nil {
		t.Fatal(err)
	}
	app := kc.AddClient("someapp", map[string]string{keycloak.OwnerAttr: "someapp"})
	_ = c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "office"}}) // no LDAP provider in the fake: its error is not the point
	if s := kc.ClientScopes(app); !slices.Contains(s, keycloak.AttributesScope) {
		t.Fatalf("attributes scope not attached to a Hub client: %v", s)
	}
	checkFreshClient(t, kc)
	var ce *keycloak.ConflictError
	err := c.RegisterClient(ctx, keycloak.ClientSpec{ClientID: freshauth.ClientID, TemplateID: freshauth.ClientID, RedirectURIs: []string{faRedirect}})
	if !errors.As(err, &ce) {
		t.Errorf("RegisterClient(%s) = %v, want *ConflictError", freshauth.ClientID, err)
	}
	checkFreshClient(t, kc)
}
