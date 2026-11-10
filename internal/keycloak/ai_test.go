package keycloak_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

const (
	week  = 7 * 24 * time.Hour
	month = 30 * 24 * time.Hour
)

// aiRealm is a fake realm with Keycloak's built-in scopes as realm
// defaults (a new client gets them), core's acr and groups and the Hub's
// attributes scope.
func aiRealm(t *testing.T) *kctest.Server {
	kc := kctest.New(t)
	for _, n := range []string{"basic", "acr", "offline_access", "profile", "email", "roles", "web-origins", "groups", "address", keycloak.AttributesScope} {
		kc.AddScope(n)
	}
	kc.SetRealmDefaultScopes([]string{"basic", "acr", "profile", "email", "roles", "web-origins"}, []string{"offline_access", "address"})
	return kc
}

func hubAISpec(id string, scopes ...string) keycloak.AIClientSpec {
	return keycloak.AIClientSpec{ClientID: id, Public: true, RedirectURIs: keycloak.AIRedirectURIs(id), OptionalScopes: scopes,
		OfflineIdle: week, OfflineMax: month, Owner: keycloak.AIOwner}
}

func ensureScope(t *testing.T, c *keycloak.Client, name, aud, text string) {
	t.Helper()
	if err := c.EnsureMCPScope(context.Background(), keycloak.MCPScope{Name: name, Audience: aud, ConsentText: text}); err != nil {
		t.Fatal(err)
	}
}

// checkAIClient asserts every contract §8 / G9 setting of an AI client.
func checkAIClient(t *testing.T, kc *kctest.Server, id string, public bool, owner string, redirects, optional []string) string {
	t.Helper()
	got := kc.ClientByClientID(id)
	if got == nil {
		t.Fatalf("no client %s", id)
	}
	isTrue := func(p *bool) bool { return p != nil && *p }
	isFalse := func(p *bool) bool { return p != nil && !*p }
	if isTrue(got.PublicClient) != public || got.PublicClient == nil {
		t.Errorf("%s: public %v, want %v", id, got.PublicClient, public)
	}
	if !public && got.Secret == "" {
		t.Errorf("%s: confidential without a secret", id)
	}
	if !isTrue(got.StandardFlowEnabled) || !isTrue(got.ConsentRequired) || !isFalse(got.FullScopeAllowed) || !isFalse(got.BearerOnly) {
		t.Errorf("%s: standard %v consent %v fullScope %v bearerOnly %v", id, got.StandardFlowEnabled, got.ConsentRequired, got.FullScopeAllowed, got.BearerOnly)
	}
	if !isFalse(got.DirectAccessGrantsEnabled) || !isFalse(got.ImplicitFlowEnabled) || !isFalse(got.ServiceAccountsEnabled) {
		t.Errorf("%s: direct %v implicit %v service accounts %v: want all false", id, got.DirectAccessGrantsEnabled, got.ImplicitFlowEnabled, got.ServiceAccountsEnabled)
	}
	for k, want := range map[string]string{
		"pkce.code.challenge.method":                "S256",
		"client.offline.session.idle.timeout":       "604800",
		"client.offline.session.max.lifespan":       "2592000",
		"oauth2.device.authorization.grant.enabled": "false",
		"oidc.ciba.grant.enabled":                   "false",
		"standard.token.exchange.enabled":           "false",
		keycloak.OwnerAttr:                          owner,
		keycloak.AIClientAttr:                       "true",
	} {
		if got.Attributes[k] != want {
			t.Errorf("%s: attribute %s = %q, want %q", id, k, got.Attributes[k], want)
		}
	}
	if acr, ok := got.Attributes["default.acr.values"]; ok {
		t.Errorf("%s: default.acr.values = %q, want none (contract §8.1)", id, acr)
	}
	if !slices.Equal(got.RedirectURIs, redirects) || len(got.WebOrigins) != 0 {
		t.Errorf("%s: redirect URIs %v web origins %v, want %v and none", id, got.RedirectURIs, got.WebOrigins, redirects)
	}
	if s := kc.ClientScopes(got.ID); strings.Join(s, ",") != "acr,basic" {
		t.Errorf("%s: default scopes %v, want exactly acr, basic", id, s)
	}
	want := append([]string{"offline_access"}, optional...)
	slices.Sort(want)
	if s := kc.OptionalScopes(got.ID); !slices.Equal(s, want) {
		t.Errorf("%s: optional scopes %v, want %v", id, s, want)
	}
	if public && len(got.AuthenticationFlowBindingOverrides) != 0 {
		t.Errorf("%s: flow overrides %v, want none", id, got.AuthenticationFlowBindingOverrides)
	}
	ms := kc.ClientMappers(got.ID)
	m, ok := ms[keycloak.AIUsernameMapper]
	if len(ms) != 1 || !ok {
		t.Fatalf("%s: client mappers %v, want only %s", id, names(ms), keycloak.AIUsernameMapper)
	}
	if m.ProtocolMapper != "oidc-usermodel-attribute-mapper" || m.Config["user.attribute"] != "username" || m.Config["claim.name"] != "preferred_username" ||
		m.Config["id.token.claim"] != "true" || m.Config["access.token.claim"] != "true" {
		t.Errorf("%s: username mapper %+v", id, m)
	}
	return got.ID
}

func TestEnsureAIClient(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	ensureScope(t, c, "mcp:all", "https://mcp.example.org/mcp", "Use all your Portcullis apps as you")
	claude := []string{"https://claude.ai/api/mcp/auth_callback"}
	loop := []string{"http://localhost:33418/callback", "http://127.0.0.1:33418/callback"}
	want := map[string][]string{keycloak.AIClientIDs.Claude: claude, keycloak.AIClientIDs.ClaudeCode: loop, keycloak.AIClientIDs.Generic: loop}
	ids := map[string]string{}
	for _, round := range []string{"create", "idempotent"} {
		for id, redirects := range want {
			if _, err := c.EnsureAIClient(ctx, hubAISpec(id, "mcp:all")); err != nil {
				t.Fatalf("%s %s: %v", round, id, err)
			}
			uuid := checkAIClient(t, kc, id, true, keycloak.AIOwner, redirects, []string{"mcp:all"})
			if round == "create" {
				ids[id] = uuid
			} else if ids[id] != uuid {
				t.Errorf("%s re-created", id)
			}
		}
	}

	// Drift is put back: grants, consent off, realm-default scopes, the
	// attributes scope, a group mapper, a flow override, extra URIs.
	id := ids[keycloak.AIClientIDs.ClaudeCode]
	kc.UpdateClient(id, func(cl *kctest.Client) {
		yes, no := true, false
		cl.DirectAccessGrantsEnabled, cl.ImplicitFlowEnabled, cl.ServiceAccountsEnabled, cl.FullScopeAllowed = &yes, &yes, &yes, &yes
		cl.ConsentRequired, cl.StandardFlowEnabled, cl.PublicClient = &no, &no, &no
		cl.Attributes["pkce.code.challenge.method"] = "plain"
		cl.Attributes["oidc.ciba.grant.enabled"] = "true"
		cl.RedirectURIs = append(cl.RedirectURIs, "http://localhost:*")
		cl.WebOrigins = []string{"*"}
		cl.DefaultClientScopes = append(cl.DefaultClientScopes, "profile", "email", "groups", keycloak.AttributesScope)
		cl.OptionalClientScopes = append(cl.OptionalClientScopes, "address", "roles")
		cl.AuthenticationFlowBindingOverrides = map[string]string{"browser": "weak-flow"}
	})
	kc.AddClientMapper(id, "groups", "oidc-group-membership-mapper", nil)
	if _, err := c.EnsureAIClient(ctx, hubAISpec(keycloak.AIClientIDs.ClaudeCode, "mcp:all")); err != nil {
		t.Fatal(err)
	}
	checkAIClient(t, kc, keycloak.AIClientIDs.ClaudeCode, true, keycloak.AIOwner, loop, []string{"mcp:all"})

	// Spec checks never reach Keycloak.
	calls := kc.CountCalls("")
	bad := []keycloak.AIClientSpec{
		{ClientID: keycloak.AIClientIDs.Claude, Public: true, RedirectURIs: loop, OfflineIdle: week, OfflineMax: month, Owner: keycloak.AIOwner},
		{ClientID: keycloak.AIClientIDs.Claude, Public: false, Secret: "s", RedirectURIs: claude, OfflineIdle: week, OfflineMax: month, Owner: keycloak.AIOwner},
		{ClientID: keycloak.AIClientIDs.Claude, Public: true, RedirectURIs: claude, OfflineIdle: week, OfflineMax: month, Owner: "app"},
		{ClientID: keycloak.AIClientIDs.Claude, Public: true, RedirectURIs: claude, OfflineIdle: time.Hour, OfflineMax: month, Owner: keycloak.AIOwner},
		{ClientID: keycloak.AIClientIDs.Claude, Public: true, RedirectURIs: claude, OfflineIdle: week, OfflineMax: 91 * 24 * time.Hour, Owner: keycloak.AIOwner},
		{ClientID: keycloak.AIClientIDs.Claude, Public: true, RedirectURIs: claude, OfflineIdle: week, OfflineMax: month, Owner: keycloak.AIOwner, OptionalScopes: []string{"profile"}},
		{ClientID: keycloak.AIClientIDs.Claude, Public: true, RedirectURIs: claude, OfflineIdle: 20 * 24 * time.Hour, OfflineMax: 10 * 24 * time.Hour, Owner: keycloak.AIOwner},
		{ClientID: "portcullis-ai-other", Secret: "s", RedirectURIs: []string{"https://chat.example.org/cb"}, OfflineIdle: week, OfflineMax: month, Owner: "chat"},
		{ClientID: keycloak.ForwardAuthClient, Secret: "s", RedirectURIs: []string{"https://chat.example.org/cb"}, OfflineIdle: week, OfflineMax: month, Owner: "chat"},
		{ClientID: "chat", Public: true, RedirectURIs: []string{"https://chat.example.org/cb"}, OfflineIdle: week, OfflineMax: month, Owner: "chat"},
		{ClientID: "chat", Secret: "s", RedirectURIs: []string{"https://chat.example.org/*"}, OfflineIdle: week, OfflineMax: month, Owner: "chat"},
		{ClientID: "chat", Secret: "s", RedirectURIs: []string{"https://chat.example.org/cb"}, OfflineIdle: week, OfflineMax: month, Owner: "chat", OptionalScopes: []string{"mcp:portcullis.admin"}},
	}
	for i, s := range bad {
		if _, err := c.EnsureAIClient(ctx, s); err == nil {
			t.Errorf("bad spec %d accepted: %+v", i, s)
		}
	}
	if n := kc.CountCalls(""); n != calls {
		t.Errorf("a refused spec reached Keycloak (%d calls)", n-calls)
	}

	// A realm without the scope asked for: an error.
	if _, err := c.EnsureAIClient(ctx, hubAISpec(keycloak.AIClientIDs.Generic, "mcp:nothere")); err == nil || !strings.Contains(err.Error(), "mcp:nothere") {
		t.Errorf("missing scope: %v", err)
	}
}

func TestEnsureAIClientConflict(t *testing.T) {
	ctx := context.Background()
	for _, attrs := range []map[string]string{nil, {keycloak.OwnerAttr: "someapp"}} {
		kc := aiRealm(t)
		id := kc.AddClient(keycloak.AIClientIDs.Claude, attrs, "profile", "groups")
		c := keycloak.New(kc.HTTP.URL, "admin", "admin")
		var ce *keycloak.ConflictError
		if _, err := c.EnsureAIClient(ctx, hubAISpec(keycloak.AIClientIDs.Claude)); !errors.As(err, &ce) {
			t.Fatalf("existing client %v: %v, want *ConflictError", attrs, err)
		}
		if kc.CountCalls("PUT") != 0 || kc.CountCalls("DELETE") != 0 || kc.CountCalls("POST /admin") != 0 {
			t.Errorf("a foreign client was changed: %v", kc.Calls)
		}
		if s := kc.ClientScopes(id); strings.Join(s, ",") != "groups,profile" {
			t.Errorf("scopes changed: %v", s)
		}
		// Neither SetOptionalScopes nor DeleteAIClient touch it.
		if err := c.SetOptionalScopes(ctx, keycloak.AIClientIDs.Claude, nil); !errors.Is(err, keycloak.ErrNotAIClient) {
			t.Errorf("SetOptionalScopes on a foreign client: %v", err)
		}
		if err := c.DeleteAIClient(ctx, keycloak.AIClientIDs.Claude, keycloak.AIOwner); !errors.As(err, &ce) {
			t.Errorf("DeleteAIClient on a foreign client: %v", err)
		}
		if kc.ClientByClientID(keycloak.AIClientIDs.Claude) == nil {
			t.Error("foreign client deleted")
		}
	}
}

// An ai_client: confidential, the instance's tag, only mcp:all, its
// access flow kept; the other syncs leave it alone.
func TestEnsureAIClientAppClient(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	ensureScope(t, c, "mcp:all", "https://mcp.example.org/mcp", "Use all your Portcullis apps as you")
	ensureScope(t, c, "mcp:portcullis.admin", "https://hub.example.org/mcp", "Manage Portcullis as you — administrator")
	spec := keycloak.AIClientSpec{ClientID: "librechat-mcp", Name: "LibreChat", Secret: "s3cret", RedirectURIs: []string{"https://chat.example.org/api/mcp/cb"},
		OptionalScopes: []string{"mcp:all"}, OfflineIdle: week, OfflineMax: month, Owner: "librechat"}
	if _, err := c.EnsureAIClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	id := checkAIClient(t, kc, "librechat-mcp", false, "librechat", spec.RedirectURIs, []string{"mcp:all"})
	// The access role's flow binding survives a re-assert.
	flow := kc.AddFlow("portcullis-client-access-librechat-mcp-x", "")
	kc.UpdateClient(id, func(cl *kctest.Client) { cl.AuthenticationFlowBindingOverrides = map[string]string{"browser": flow} })
	if _, err := c.EnsureAIClient(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if got := kc.ClientByClientID("librechat-mcp").AuthenticationFlowBindingOverrides["browser"]; got != flow {
		t.Errorf("access flow binding = %q, want kept", got)
	}

	if err := c.SetOptionalScopes(ctx, "librechat-mcp", []string{"mcp:portcullis.admin"}); err == nil {
		t.Error("admin scope on an ai_client accepted")
	}
	// RegisterClient never takes it over (it would
	// attach profile, email, groups and the attributes scope).
	var ce *keycloak.ConflictError
	app := keycloak.ClientSpec{ClientID: "librechat-mcp", TemplateID: "librechat", Secret: "s3cret", RedirectURIs: spec.RedirectURIs}
	if _, err := c.RegisterClient(ctx, app); !errors.As(err, &ce) {
		t.Errorf("RegisterClient(ai_client) = %v, want *ConflictError", err)
	}
	// Nor do the setting claims (G9: no claim but the username; a
	// claim mapper would be deleted again by every ensure).
	if err := c.EnsureSettingClaims(ctx, "librechat-mcp", "librechat", []keycloak.SettingClaim{{Attr: "ps-0123456789ab", Claim: "quota", JSONType: "int"}}); !errors.As(err, &ce) {
		t.Errorf("EnsureSettingClaims(ai_client) = %v, want *ConflictError", err)
	}
	if err := c.RemoveSettingClaims(ctx, "librechat-mcp", "librechat", []string{"ps-0123456789ab"}); !errors.As(err, &ce) {
		t.Errorf("RemoveSettingClaims(ai_client) = %v, want *ConflictError", err)
	}
	_ = c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "office"}})
	checkAIClient(t, kc, "librechat-mcp", false, "librechat", spec.RedirectURIs, []string{"mcp:all"})

	// Deleted only as the instance's AI client.
	if err := c.DeleteAIClient(ctx, "librechat-mcp", "other"); !errors.As(err, &ce) {
		t.Errorf("delete as another owner: %v", err)
	}
	if err := c.DeleteAIClient(ctx, "librechat-mcp", "librechat"); err != nil {
		t.Fatal(err)
	}
	if kc.ClientByClientID("librechat-mcp") != nil {
		t.Error("not deleted")
	}
	if err := c.DeleteAIClient(ctx, "librechat-mcp", "librechat"); err != nil {
		t.Errorf("missing: %v", err)
	}
}

// G8: client registration never adopts a portcullis-ai-* client, and the
// attributes scope is never attached to an AI client (G9).
func TestAIClientsProtected(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	if _, err := c.EnsureAIClient(ctx, hubAISpec(keycloak.AIClientIDs.Generic)); err != nil {
		t.Fatal(err)
	}
	var ce *keycloak.ConflictError
	for _, id := range []string{keycloak.AIClientIDs.Generic, "portcullis-ai-mine", "Portcullis-AI-x"} {
		// An existing untagged one pointing only at the app's host would
		// otherwise be adopted.
		if kc.ClientByClientID(id) == nil {
			cid := kc.AddClient(id, nil)
			kc.SetClientURIs(cid, []string{"https://app.example.org/cb"}, nil)
		}
		s := keycloak.ClientSpec{ClientID: id, TemplateID: "app", Secret: "x", RedirectURIs: []string{"https://app.example.org/cb"}, AllowedHosts: []string{"app.example.org"}}
		if _, err := c.RegisterClient(ctx, s); !errors.As(err, &ce) {
			t.Errorf("RegisterClient(%s) = %v, want *ConflictError", id, err)
		}
		if err := c.UpdateClientHosts(ctx, s, nil, nil); !errors.As(err, &ce) {
			t.Errorf("UpdateClientHosts(%s) = %v, want *ConflictError", id, err)
		}
		if err := c.DeleteClient(ctx, id, "app"); !errors.As(err, &ce) {
			t.Errorf("DeleteClient(%s) = %v, want *ConflictError", id, err)
		}
		if err := c.EnsureClientAccess(ctx, keycloak.AccessSpec{ClientID: id, TemplateID: "app", Group: "g"}); !errors.As(err, &ce) {
			t.Errorf("EnsureClientAccess(%s) = %v, want *ConflictError", id, err)
		}
		if err := c.EnsureSettingClaims(ctx, id, "app", nil); !errors.As(err, &ce) {
			t.Errorf("EnsureSettingClaims(%s) = %v, want *ConflictError", id, err)
		}
		if keycloak.MayReconcile(map[string]interface{}{"clientId": id, "redirectUris": []string{"https://app.example.org/cb"}}, "app", []string{"app.example.org"}) {
			t.Errorf("MayReconcile(%s) = true", id)
		}
	}
	app := kc.AddClient("someapp", map[string]string{keycloak.OwnerAttr: "someapp"})
	_ = c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "office"}})
	if s := kc.ClientScopes(app); !slices.Contains(s, keycloak.AttributesScope) {
		t.Fatalf("attributes scope not attached to a Hub client: %v", s)
	}
	checkAIClient(t, kc, keycloak.AIClientIDs.Generic, true, keycloak.AIOwner, keycloak.LoopbackRedirectURIs, nil)
}

func TestEnsureMCPScope(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	name := "mcp:gitea.gitea"
	check := func(aud, text string) {
		t.Helper()
		sc := kc.Scope(name)
		if sc == nil || sc.Protocol != "openid-connect" {
			t.Fatalf("scope %+v", sc)
		}
		for k, want := range map[string]string{"include.in.token.scope": "true", "display.on.consent.screen": "true", "consent.screen.text": text} {
			if sc.Attributes[k] != want {
				t.Errorf("attribute %s = %q, want %q", k, sc.Attributes[k], want)
			}
		}
		ms := kc.ScopeMappers(name)
		m, ok := ms[keycloak.MCPAudienceMapper]
		if len(ms) != 1 || !ok {
			t.Fatalf("mappers %v, want only %s", names(ms), keycloak.MCPAudienceMapper)
		}
		if m.ProtocolMapper != "oidc-audience-mapper" || m.Config["included.custom.audience"] != aud || m.Config["access.token.claim"] != "true" ||
			m.Config["id.token.claim"] != "false" || m.Config["included.client.audience"] != "" {
			t.Errorf("audience mapper %+v", m)
		}
		if def, opt := kc.RealmScopes(); slices.Contains(def, name) || slices.Contains(opt, name) {
			t.Errorf("realm defaults %v / %v hold %s", def, opt, name)
		}
	}
	ensureScope(t, c, name, "https://git.example.org/mcp", "Use Gitea (git.example.org) as you")
	check("https://git.example.org/mcp", "Use Gitea (git.example.org) as you")
	n := kc.ScopeCount()
	ensureScope(t, c, name, "https://git.example.org/mcp", "Use Gitea (git.example.org) as you")
	check("https://git.example.org/mcp", "Use Gitea (git.example.org) as you")
	if kc.ScopeCount() != n {
		t.Error("scope re-created")
	}
	// A hostname change rewrites the audience and the consent text; a
	// group mapper someone added and a realm-default attachment go.
	kc.AddScopeMapper(name, "groups", "oidc-group-membership-mapper", nil)
	kc.SetRealmDefaultScopes([]string{"basic", "acr", name}, []string{"offline_access", name})
	ensureScope(t, c, name, "https://code.example.org/mcp", "Use Gitea (code.example.org) as you")
	check("https://code.example.org/mcp", "Use Gitea (code.example.org) as you")

	// Delete detaches it from every client first (Keycloak refuses to
	// delete a linked scope).
	ensureScope(t, c, "mcp:all", "https://mcp.example.org/mcp", "Use all your Portcullis apps as you")
	for _, id := range []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.Generic} {
		if _, err := c.EnsureAIClient(ctx, hubAISpec(id, "mcp:all", name)); err != nil {
			t.Fatal(err)
		}
	}
	kc.SetRealmDefaultScopes([]string{"basic", "acr"}, []string{"offline_access", name})
	if err := c.DeleteMCPScope(ctx, name); err != nil {
		t.Fatal(err)
	}
	if kc.Scope(name) != nil {
		t.Fatal("scope left")
	}
	for _, id := range []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.Generic} {
		checkAIClient(t, kc, id, true, keycloak.AIOwner, keycloak.AIRedirectURIs(id), []string{"mcp:all"})
	}
	if err := c.DeleteMCPScope(ctx, name); err != nil {
		t.Errorf("missing scope: %v", err)
	}
	// Only mcp:* scopes, and only well-formed arguments.
	if err := c.DeleteMCPScope(ctx, "profile"); err == nil || kc.Scope("profile") == nil {
		t.Errorf("DeleteMCPScope(profile) = %v", err)
	}
	for _, s := range []keycloak.MCPScope{
		{Name: "profile", Audience: "https://x.example.org/mcp", ConsentText: "x"},
		{Name: "mcp:", Audience: "https://x.example.org/mcp", ConsentText: "x"},
		{Name: "mcp:a.b", Audience: "http://x.example.org/mcp", ConsentText: "x"},
		{Name: "mcp:a.b", Audience: "https://x.example.org/mcp#f", ConsentText: "x"},
		{Name: "mcp:a.b", Audience: "https://x.example.org/mcp", ConsentText: ""},
		{Name: "mcp:a.b", Audience: "https://x.example.org/mcp", ConsentText: "two\nlines"},
	} {
		if err := c.EnsureMCPScope(ctx, s); err == nil {
			t.Errorf("EnsureMCPScope(%+v) accepted", s)
		}
	}
}

func TestOptionalScopesExact(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	ensureScope(t, c, "mcp:all", "https://mcp.example.org/mcp", "Use all your Portcullis apps as you")
	ensureScope(t, c, "mcp:gitea.gitea", "https://git.example.org/mcp", "Use Gitea (git.example.org) as you")
	id := keycloak.AIClientIDs.Claude
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetOptionalScopes(ctx, id, []string{"mcp:all", "mcp:gitea.gitea"}); err != nil {
		t.Fatal(err)
	}
	uuid := kc.ClientByClientID(id).ID
	if s := kc.OptionalScopes(uuid); strings.Join(s, ",") != "mcp:all,mcp:gitea.gitea,offline_access" {
		t.Fatalf("optional %v", s)
	}
	// A non-mcp optional scope added by hand is not SetOptionalScopes'
	// business (EnsureAIClient removes it).
	kc.UpdateClient(uuid, func(cl *kctest.Client) { cl.OptionalClientScopes = append(cl.OptionalClientScopes, "address") })
	if err := c.SetOptionalScopes(ctx, id, []string{"mcp:all"}); err != nil {
		t.Fatal(err)
	}
	if s := kc.OptionalScopes(uuid); strings.Join(s, ",") != "address,mcp:all,offline_access" {
		t.Errorf("optional %v, want only the gitea scope removed", s)
	}
	if s := kc.ClientScopes(uuid); strings.Join(s, ",") != "acr,basic" {
		t.Errorf("default scopes touched: %v", s)
	}
	// An mcp scope as a default scope moves out.
	kc.UpdateClient(uuid, func(cl *kctest.Client) { cl.DefaultClientScopes = append(cl.DefaultClientScopes, "mcp:gitea.gitea") })
	if err := c.SetOptionalScopes(ctx, id, []string{"mcp:all", "mcp:gitea.gitea"}); err != nil {
		t.Fatal(err)
	}
	if s := kc.ClientScopes(uuid); strings.Join(s, ",") != "acr,basic" {
		t.Errorf("default scopes %v", s)
	}
	if s := kc.OptionalScopes(uuid); strings.Join(s, ",") != "address,mcp:all,mcp:gitea.gitea,offline_access" {
		t.Errorf("optional %v", s)
	}
	if err := c.SetOptionalScopes(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
	if s := kc.OptionalScopes(uuid); strings.Join(s, ",") != "address,offline_access" {
		t.Errorf("optional %v", s)
	}

	// Refused: core's clients, the fresh-auth client, app clients, an
	// untagged client, a non-mcp scope, a scope the realm lacks.
	fa := kc.AddClient(keycloak.ForwardAuthClient, map[string]string{keycloak.OwnerAttr: keycloak.AIOwner})
	kc.AddClient(freshauth.ClientID, map[string]string{keycloak.OwnerAttr: freshauth.ClientID})
	app := kc.AddClient("gitea", map[string]string{keycloak.OwnerAttr: "gitea"})
	kc.AddClient("loose", map[string]string{keycloak.AIClientAttr: "true"})
	for _, cid := range []string{keycloak.ForwardAuthClient, freshauth.ClientID, "gitea", "loose", "account", "nothere"} {
		if err := c.SetOptionalScopes(ctx, cid, []string{"mcp:all"}); err == nil {
			t.Errorf("SetOptionalScopes(%s) accepted", cid)
		}
	}
	if s := kc.OptionalScopes(fa); len(s) != 0 {
		t.Errorf("forward-auth got %v", s)
	}
	if s := kc.OptionalScopes(app); len(s) != 0 {
		t.Errorf("app client got %v", s)
	}
	for _, bad := range [][]string{{"profile"}, {"mcp:all", "mcp:all"}, {"mcp:nothere"}} {
		if err := c.SetOptionalScopes(ctx, id, bad); err == nil {
			t.Errorf("SetOptionalScopes(%v) accepted", bad)
		}
	}
	if s := kc.OptionalScopes(uuid); strings.Join(s, ",") != "address,offline_access" {
		t.Errorf("a refused call changed the client: %v", s)
	}
}

func TestAIConnectionsAndRevoke(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	ensureScope(t, c, "mcp:all", "https://mcp.example.org/mcp", "Use all your Portcullis apps as you")
	for _, id := range []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode} {
		if _, err := c.EnsureAIClient(ctx, hubAISpec(id, "mcp:all")); err != nil {
			t.Fatal(err)
		}
	}
	claude, code := kc.ClientByClientID(keycloak.AIClientIDs.Claude).ID, kc.ClientByClientID(keycloak.AIClientIDs.ClaudeCode).ID
	app := kc.AddClient("gitea", map[string]string{keycloak.OwnerAttr: "gitea"})
	kc.Import("alice")
	kc.Import("bob")
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	last := t0.Add(48 * time.Hour)
	kc.AddConsent("alice", keycloak.AIClientIDs.Claude, t0, "mcp:all", "offline_access")
	kc.AddOfflineSession("alice", t0, last, claude)
	kc.AddOfflineSession("alice", t0, t0.Add(time.Hour), code, app) // one session, two clients
	kc.AddConsent("alice", "gitea", t0)
	kc.AddConsent("bob", keycloak.AIClientIDs.Claude, t0)
	kc.AddOfflineSession("bob", t0, last, claude)

	all := []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode, keycloak.AIClientIDs.Generic, "gitea"}
	conns, err := c.AIConnections(ctx, "alice", all)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 2 {
		t.Fatalf("connections %+v, want claude and claude-code (generic missing, gitea no AI client)", conns)
	}
	cl := conns[0]
	if cl.Client != keycloak.AIClientIDs.Claude || cl.Consented == nil || !cl.Consented.Equal(t0) || cl.LastUsed == nil || !cl.LastUsed.Equal(last) ||
		cl.Expires == nil || !cl.Expires.Equal(last.Add(week)) {
		t.Errorf("claude connection %+v", cl)
	}
	if cc := conns[1]; cc.Client != keycloak.AIClientIDs.ClaudeCode || cc.Consented != nil || cc.LastUsed == nil {
		t.Errorf("claude-code connection %+v", cc)
	}
	// The max lifespan caps the idle time: carol's only session started
	// 29 days ago, so it ends at start + 30 days, before last use + 7.
	kc.Import("carol")
	start := t0.Add(-29 * 24 * time.Hour)
	kc.AddOfflineSession("carol", start, last, claude)
	conns, err = c.AIConnections(ctx, "carol", all[:1])
	if err != nil || len(conns) != 1 || conns[0].Expires == nil || !conns[0].Expires.Equal(start.Add(month)) {
		t.Errorf("capped session: %s, want expires %v", fmtConns(conns), start.Add(month))
	}
	if conns, err := c.AIConnections(ctx, "nobody", all); err != nil || len(conns) != 0 {
		t.Errorf("unknown user: %v %v", conns, err)
	}

	if err := c.RevokeAIConnection(ctx, "alice", keycloak.AIClientIDs.Claude); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(kc.UserConsents("alice"), ","); got != "gitea" {
		t.Errorf("alice's consents %s, want gitea only", got)
	}
	if got := strings.Join(kc.OfflineClients("alice"), ","); got != "gitea+"+keycloak.AIClientIDs.ClaudeCode {
		t.Errorf("alice's offline sessions %s", got)
	}
	if got := strings.Join(kc.UserConsents("bob"), ","); got != keycloak.AIClientIDs.Claude {
		t.Errorf("bob's consents changed: %s", got)
	}
	// Offline sessions without a consent are revoked too; nothing left
	// is nil.
	if err := c.RevokeAIConnection(ctx, "alice", keycloak.AIClientIDs.ClaudeCode); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(kc.OfflineClients("alice"), ","); got != "gitea" {
		t.Errorf("alice's offline sessions %s", got)
	}
	if err := c.RevokeAIConnection(ctx, "alice", keycloak.AIClientIDs.ClaudeCode); err != nil {
		t.Errorf("nothing to revoke: %v", err)
	}
	if err := c.RevokeAIConnection(ctx, "nobody", keycloak.AIClientIDs.Claude); err != nil {
		t.Errorf("unknown user: %v", err)
	}
	// Only AI clients.
	for _, id := range []string{"gitea", keycloak.ForwardAuthClient} {
		if err := c.RevokeAIConnection(ctx, "alice", id); err == nil {
			t.Errorf("RevokeAIConnection(%s) accepted", id)
		}
	}
	if got := strings.Join(kc.UserConsents("alice"), ","); got != "gitea" {
		t.Errorf("gitea consent touched: %s", got)
	}
}

// A scope or mapper step that fails on a client still holding a scope it
// must not have leaves it disabled; the next good ensure re-enables it.
func TestEnsureAIClientFailsClosed(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	id := keycloak.AIClientIDs.Claude
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil {
		t.Fatal(err)
	}
	uuid := kc.ClientByClientID(id).ID
	enabled := func() bool { e := kc.ClientByClientID(id).Enabled; return e != nil && *e }
	if !enabled() {
		t.Fatal("not enabled")
	}
	kc.UpdateClient(uuid, func(cl *kctest.Client) { cl.DefaultClientScopes = append(cl.DefaultClientScopes, "profile", "groups") })
	kc.SetFailPrefix("DELETE /admin/realms/portcullis/clients/" + uuid + "/default-client-scopes")
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err == nil {
		t.Fatal("failing detach: no error")
	}
	if enabled() {
		t.Error("client with profile/groups left enabled after a failed detach")
	}
	// A failing mapper step with an extra mapper: disabled too.
	kc.SetFailPrefix("")
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil {
		t.Fatal(err)
	}
	if !enabled() {
		t.Error("not re-enabled by a good ensure")
	}
	checkAIClient(t, kc, id, true, keycloak.AIOwner, keycloak.ClaudeRedirectURIs, nil)
	kc.AddClientMapper(uuid, "groups", "oidc-group-membership-mapper", nil)
	kc.SetFailPrefix("DELETE /admin/realms/portcullis/clients/" + uuid + "/protocol-mappers")
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err == nil || enabled() {
		t.Errorf("failing mapper delete: %v, enabled %v", err, enabled())
	}
	// A failure on a clean client (a missing mcp scope) keeps it enabled.
	kc.SetFailPrefix("")
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil || !enabled() {
		t.Fatalf("re-enable: %v", err)
	}
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id, "mcp:nothere")); err == nil || !enabled() {
		t.Errorf("clean client, missing scope: %v, enabled %v", err, enabled())
	}
}

// The disable check is the reconciler's: a username mapper with the
// right name but another config counts as disallowed.
func TestEnsureAIClientFailsClosedOnAlteredMapper(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	id := keycloak.AIClientIDs.Generic
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil {
		t.Fatal(err)
	}
	uuid := kc.ClientByClientID(id).ID
	kc.UpdateClient(uuid, func(cl *kctest.Client) {
		for i := range cl.ProtocolMappers {
			cl.ProtocolMappers[i].Config["user.attribute"] = "email" // same name, leaks the email
		}
	})
	kc.SetFailPrefix("DELETE /admin/realms/portcullis/clients/" + uuid + "/protocol-mappers")
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err == nil {
		t.Fatal("failing mapper delete: no error")
	}
	if e := kc.ClientByClientID(id).Enabled; e == nil || *e {
		t.Error("client with an altered username mapper left enabled")
	}
	kc.SetFailPrefix("")
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil {
		t.Fatal(err)
	}
	if e := kc.ClientByClientID(id).Enabled; e == nil || !*e {
		t.Error("not re-enabled")
	}
	checkAIClient(t, kc, id, true, keycloak.AIOwner, keycloak.LoopbackRedirectURIs, nil)
}

// A failed read-back disables the client through the representation
// EnsureAIClient already holds; a failing disable PUT joins every error.
func TestEnsureAIClientFailsClosedOnFailedReadback(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	id := keycloak.AIClientIDs.ClaudeCode
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil {
		t.Fatal(err)
	}
	uuid := kc.ClientByClientID(id).ID
	kc.UpdateClient(uuid, func(cl *kctest.Client) { cl.DefaultClientScopes = append(cl.DefaultClientScopes, "profile") })
	failing := func(failPut bool) func(method, path string) bool {
		lists := 0
		return func(method, path string) bool {
			switch {
			case method == "DELETE" && strings.HasPrefix(path, "/admin/realms/portcullis/clients/"+uuid+"/default-client-scopes"):
				return true
			case method == "GET" && path == "/admin/realms/portcullis/clients":
				lists++
				return lists > 1 // the first lookup works, the read-back fails
			case method == "PUT" && path == "/admin/realms/portcullis/clients/"+uuid:
				return failPut
			}
			return false
		}
	}
	kc.SetFailFunc(failing(false))
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err == nil {
		t.Fatal("no error")
	}
	if e := kc.ClientByClientID(id).Enabled; e == nil || *e {
		t.Error("client left enabled after a failed read-back")
	}
	// The disable PUT failing too: every error comes back.
	kc.SetFailFunc(nil)
	if _, err := c.EnsureAIClient(ctx, hubAISpec(id)); err != nil {
		t.Fatal(err)
	}
	kc.UpdateClient(uuid, func(cl *kctest.Client) { cl.DefaultClientScopes = append(cl.DefaultClientScopes, "profile") })
	kc.SetFailFunc(failing(true))
	_, err := c.EnsureAIClient(ctx, hubAISpec(id))
	if err == nil || !strings.Contains(err.Error(), "detach default scope profile") || !strings.Contains(err.Error(), "client lookup") ||
		!strings.Contains(err.Error(), "update client") {
		t.Errorf("joined errors: %v", err)
	}
	kc.SetFailFunc(nil)
}

// TestMCPScopeNames lists only mcp:* scopes, sorted (plan 4 Task 15).
func TestMCPScopeNames(t *testing.T) {
	ctx := context.Background()
	kc := aiRealm(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	for _, n := range []string{"mcp:b.x", "mcp:a.y"} {
		if err := c.EnsureMCPScope(ctx, keycloak.MCPScope{Name: n, Audience: "https://a.example.com/mcp", ConsentText: "Use A (a.example.com) as you"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c.MCPScopeNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "mcp:a.y,mcp:b.x" {
		t.Errorf("names = %v", got)
	}
}
