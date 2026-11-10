package keycloak_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v14"

	"github.com/portcullis/hub/internal/keycloak"
)

// Opt-in test of the access role against a real Keycloak (the version core
// pins), e.g.
//
//	bin/kc.sh start-dev --http-port=18080   # or the core image
//	PORTCULLIS_KEYCLOAK_LIVE_URL=http://127.0.0.1:18080 go test ./internal/keycloak -run Live
//
// Admin credentials: PORTCULLIS_KEYCLOAK_LIVE_ADMIN / _PASSWORD (default
// admin / admin, a throwaway dev server). It DELETES and recreates the
// realm "portcullis": never point it at a real deployment. Sign-ins are
// real browser logins (authorization endpoint, login form, SSO cookie) of
// local users with passwords through the realm's built-in browser flow.

const liveRedirect = "http://127.0.0.1:1/cb"

type liveEnv struct {
	base string
	g    *gocloak.GoCloak
	tok  string
}

func liveSetup(t *testing.T) (*liveEnv, *keycloak.Client) {
	t.Helper()
	base := os.Getenv("PORTCULLIS_KEYCLOAK_LIVE_URL")
	if base == "" {
		t.Skip("PORTCULLIS_KEYCLOAK_LIVE_URL not set")
	}
	if os.Getenv("PORTCULLIS_KEYCLOAK_LIVE_WIPE") != keycloak.Realm {
		t.Skip("this test deletes realm " + keycloak.Realm + ": set PORTCULLIS_KEYCLOAK_LIVE_WIPE=" + keycloak.Realm + " to confirm")
	}
	user, pass := os.Getenv("PORTCULLIS_KEYCLOAK_LIVE_ADMIN"), os.Getenv("PORTCULLIS_KEYCLOAK_LIVE_PASSWORD")
	if user == "" {
		user, pass = "admin", "admin"
	}
	ctx := context.Background()
	g := gocloak.NewClient(base)
	jwt, err := g.LoginAdmin(ctx, user, pass, "master")
	if err != nil {
		t.Fatal(err)
	}
	e := &liveEnv{base: base, g: g, tok: jwt.AccessToken}
	_ = g.DeleteRealm(ctx, e.tok, keycloak.Realm)
	if _, err := g.CreateRealm(ctx, e.tok, gocloak.RealmRepresentation{Realm: gocloak.StringP(keycloak.Realm), Enabled: gocloak.BoolP(true)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.DeleteRealm(context.Background(), e.tok, keycloak.Realm) })
	gid, err := g.CreateGroup(ctx, e.tok, keycloak.Realm, gocloak.Group{Name: gocloak.StringP("users_app")})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		id, err := g.CreateUser(ctx, e.tok, keycloak.Realm, gocloak.User{
			Username: gocloak.StringP(u), Enabled: gocloak.BoolP(true), Email: gocloak.StringP(u + "@example.org"),
			EmailVerified: gocloak.BoolP(true), FirstName: gocloak.StringP(u), LastName: gocloak.StringP("Test"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := g.SetPassword(ctx, e.tok, id, keycloak.Realm, u+"-pw", false); err != nil {
			t.Fatal(err)
		}
		if u == "alice" {
			if err := g.AddUserToGroup(ctx, e.tok, keycloak.Realm, id, gid); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := keycloak.New(base, user, pass)
	for _, id := range []string{"app", "other"} {
		if _, err := c.RegisterClient(ctx, keycloak.ClientSpec{ClientID: id, TemplateID: id, Secret: "s-" + id, RedirectURIs: []string{liveRedirect}}); err != nil {
			t.Fatal(err)
		}
	}
	return e, c
}

var formAction = regexp.MustCompile(`<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"`)

// login signs user in to clientID in a browser with jar (nil: a fresh
// one): "allowed" (redirected back with a code), "denied" (Keycloak's
// access-denied page with the Hub's message) or the page text.
func (e *liveEnv) login(t *testing.T, clientID, user string, jar http.CookieJar) string {
	t.Helper()
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	hc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), liveRedirect) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	q := url.Values{"client_id": {clientID}, "redirect_uri": {liveRedirect}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s"}, "nonce": {"n"}}
	resp, err := hc.Get(e.base + "/realms/" + keycloak.Realm + "/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		page := string(body)
		if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, liveRedirect) {
			if u, _ := url.Parse(loc); u != nil && u.Query().Get("code") != "" {
				return "allowed"
			}
			return "redirect without code: " + loc
		}
		if strings.Contains(html.UnescapeString(page), keycloak.AccessDeniedMessage) {
			return "denied"
		}
		m := formAction.FindStringSubmatch(page)
		if m == nil || i > 0 {
			if len(page) > 400 {
				page = page[:400]
			}
			return "unexpected page: " + page
		}
		resp, err = hc.PostForm(html.UnescapeString(m[1]), url.Values{"username": {user}, "password": {user + "-pw"}, "credentialId": {""}})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (e *liveEnv) expect(t *testing.T, step, clientID, user string, jar http.CookieJar, want string) {
	t.Helper()
	if got := e.login(t, clientID, user, jar); got != want {
		t.Errorf("%s: %s on %s = %s, want %s", step, user, clientID, got, want)
	}
}

func (e *liveEnv) clientUUID(t *testing.T, clientID string) string {
	t.Helper()
	cls, err := e.g.GetClients(context.Background(), e.tok, keycloak.Realm, gocloak.GetClientsParams{ClientID: gocloak.StringP(clientID)})
	if err != nil || len(cls) != 1 {
		t.Fatalf("client %s: %v", clientID, err)
	}
	return *cls[0].ID
}

func (e *liveEnv) bound(t *testing.T, clientID string) string {
	t.Helper()
	cl, err := e.g.GetClient(context.Background(), e.tok, keycloak.Realm, e.clientUUID(t, clientID))
	if err != nil {
		t.Fatal(err)
	}
	return cl.AuthenticationFlowBindingOverrides["browser"]
}

func TestLiveClientAccess(t *testing.T) {
	ctx := context.Background()
	e, c := liveSetup(t)
	spec := keycloak.AccessSpec{ClientID: "app", TemplateID: "app", Group: "users_app"}
	e.expect(t, "before", "app", "bob", nil, "allowed")

	if err := c.EnsureClientAccess(ctx, spec); err != nil {
		t.Fatal(err)
	}
	flow := e.bound(t, "app")
	if flow == "" {
		t.Fatal("no browser flow override")
	}
	e.expect(t, "enforced", "app", "alice", nil, "allowed")
	e.expect(t, "enforced", "app", "bob", nil, "denied")
	e.expect(t, "enforced", "other", "bob", nil, "allowed")
	// SSO: bob signed in elsewhere is still denied here.
	jar, _ := cookiejar.New(nil)
	e.expect(t, "sso", "other", "bob", jar, "allowed")
	e.expect(t, "sso", "app", "bob", jar, "denied")
	ajar, _ := cookiejar.New(nil)
	e.expect(t, "sso", "other", "alice", ajar, "allowed")
	e.expect(t, "sso", "app", "alice", ajar, "allowed")

	// Idempotent: Keycloak's read-back of the copy matches what the Hub
	// built, so the next ensure keeps it.
	if err := c.EnsureClientAccess(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if got := e.bound(t, "app"); got != flow {
		t.Fatalf("second ensure rebuilt the flow (%s → %s): the read-back differs", flow, got)
	}

	// Review finding 1: the role deleted in the console → nobody gets in.
	uuid := e.clientUUID(t, "app")
	if err := e.g.DeleteClientRole(ctx, e.tok, keycloak.Realm, uuid, keycloak.AccessRole); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "role deleted", "app", "alice", nil, "denied")
	e.expect(t, "role deleted", "app", "bob", nil, "denied")
	if err := c.EnsureClientAccess(ctx, spec); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "role restored", "app", "alice", nil, "allowed")
	e.expect(t, "role restored", "app", "bob", nil, "denied")

	// Finding 4: the role as a composite of default-roles-portcullis lets
	// everybody in until the next ensure removes it.
	role, err := e.g.GetClientRole(ctx, e.tok, keycloak.Realm, uuid, keycloak.AccessRole)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.g.AddRealmRoleComposite(ctx, e.tok, keycloak.Realm, "default-roles-portcullis", []gocloak.Role{*role}); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "composite", "app", "bob", nil, "allowed")
	if err := c.EnsureClientAccess(ctx, spec); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "composite removed", "app", "bob", nil, "denied")

	// Finding 3: the deny sub-flow disabled in the console → the next
	// ensure binds a fresh copy and deletes the edited one.
	flow = e.bound(t, "app")
	f, err := e.g.GetAuthenticationFlow(ctx, e.tok, keycloak.Realm, flow)
	if err != nil {
		t.Fatal(err)
	}
	execs, err := e.g.GetAuthenticationExecutions(ctx, e.tok, keycloak.Realm, *f.Alias)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range execs {
		if x.DisplayName != nil && *x.DisplayName == *f.Alias+".deny" {
			x.Requirement = gocloak.StringP("DISABLED")
			if err := e.g.UpdateAuthenticationExecution(ctx, e.tok, keycloak.Realm, *f.Alias, *x); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.expect(t, "deny disabled", "app", "bob", nil, "allowed")
	if err := c.EnsureClientAccess(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if got := e.bound(t, "app"); got == flow {
		t.Error("edited copy kept")
	}
	if _, err := e.g.GetAuthenticationFlow(ctx, e.tok, keycloak.Realm, flow); err == nil {
		t.Error("edited copy not deleted")
	}
	e.expect(t, "repaired", "app", "bob", nil, "denied")
	e.expect(t, "repaired", "app", "alice", nil, "allowed")

	// Cleanup opens the client again and leaves no access flow behind.
	if err := c.RemoveClientAccess(ctx, "app", "app", nil); err != nil {
		t.Fatal(err)
	}
	if got := e.bound(t, "app"); got != "" {
		t.Errorf("override left: %q", got)
	}
	e.expect(t, "removed", "app", "bob", nil, "allowed")
	flows, err := e.g.GetAuthenticationFlows(ctx, e.tok, keycloak.Realm)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range flows {
		if strings.HasPrefix(*f.Alias, keycloak.AccessFlowPrefix) {
			t.Errorf("flow %s left", *f.Alias)
		}
	}
	var apiErr *gocloak.APIError
	if _, err := e.g.GetClientRole(ctx, e.tok, keycloak.Realm, uuid, keycloak.AccessRole); !errors.As(err, &apiErr) || apiErr.Code != 404 {
		t.Errorf("role left: %v", err)
	}
}

// ── AI clients (contract §8, plan 4 Task 10) ─────────────

// TestLiveAIObjects builds the AI clients and mcp:* scopes on a real
// Keycloak (26.8.1, the version core pins) and signs alice in through
// them with PKCE and the consent screen. Recorded on Keycloak 26.8.1
// (kc.sh start-dev, Homebrew OpenJDK 27, 2026-11-05), each one asserted:
//
//   - loopback redirect URIs match exactly, port included: with
//     http://localhost:33418/callback and http://127.0.0.1:33418/callback
//     registered, 127.0.0.1:40123, localhost:40123 and [::1]:33418 get
//     "Invalid parameter: redirect_uri" (no redirect). The fixed port
//     33418 is required, not just kept for the People card;
//   - a scope the client lacks (mcp:portcullis.admin, not attached):
//     error redirect invalid_scope "Invalid scopes: openid
//     mcp:portcullis.admin", no code;
//   - PKCE: no code_challenge, or method plain: error redirect
//     invalid_request;
//   - consent: the screen shows each requested mcp:* scope's
//     consent.screen.text and nothing for scopes not requested; asking
//     for a new scope later shows the screen again; after a disconnect
//     the next sign-in asks again;
//   - tokens: the access token carries exactly acr amr aud auth_time azp
//     exp iat iss jti preferred_username scope sid sub typ (ID token: the
//     same plus at_hash and nonce, minus scope); aud = the requested
//     resources' URLs only; no email / name / groups / roles /
//     attribute claims. Access tokens live 300 s (realm default);
//   - amr: a password sign-in on Keycloak's built-in browser flow gets
//     acr / amr "pwd" (the client has no default ACR, contract §8.1: the
//     gate checks the resource's sign-in rule);
//   - offline: the offline refresh token (typ Offline) lives exactly the
//     client's idle attribute (7 days = 168 h); refreshing twice with the
//     same refresh token works (no rotation: realm revokeRefreshToken
//     false, G51);
//   - disconnect (G52): after RevokeAIConnection the client's offline
//     AND online refresh tokens are refused (invalid_grant): Keycloak's
//     consent delete also logs the client's sessions out. Only issued
//     access tokens stay valid, up to 5 min. Another AI client's offline
//     token keeps working;
//   - Keycloak 26.8.1 lists a consent's grantedClientScopes as names; a
//     deleted mcp:* scope disappears from the consents that named it.
//
// The hwk amr after a passkey sign-in needs a WebAuthn authenticator and
// is skipped here (T32's manual checklist); the client is asserted to
// carry no default.acr.values.
func TestLiveAIObjects(t *testing.T) {
	ctx := context.Background()
	e, c := liveSetup(t)
	realmSettings(t, e)
	scopes := []keycloak.MCPScope{
		{Name: "mcp:all", Audience: "https://mcp.example.org/mcp", ConsentText: "Use all your Portcullis apps as you"},
		{Name: "mcp:gitea.gitea", Audience: "https://git.example.org/mcp", ConsentText: "Use Gitea (git.example.org) as you"},
		{Name: "mcp:portcullis.admin", Audience: "https://hub.example.org/mcp", ConsentText: "Manage Portcullis as you — administrator"},
	}
	for _, s := range scopes {
		if err := c.EnsureMCPScope(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode, keycloak.AIClientIDs.Generic}
	for round := 0; round < 2; round++ { // the second round: idempotent on a real Keycloak
		for _, id := range ids {
			spec := keycloak.AIClientSpec{ClientID: id, Public: true, RedirectURIs: keycloak.AIRedirectURIs(id), OptionalScopes: []string{"mcp:all", "mcp:gitea.gitea"},
				OfflineIdle: 7 * 24 * time.Hour, OfflineMax: 30 * 24 * time.Hour, Owner: keycloak.AIOwner}
			if _, err := c.EnsureAIClient(ctx, spec); err != nil {
				t.Fatal(err)
			}
			e.checkLiveAIClient(t, id, []string{"mcp:all", "mcp:gitea.gitea", "offline_access"})
		}
	}
	// SetOptionalScopes: exact mcp set, app clients refused.
	if err := c.SetOptionalScopes(ctx, keycloak.AIClientIDs.Claude, []string{"mcp:all"}); err != nil {
		t.Fatal(err)
	}
	e.checkLiveAIClient(t, keycloak.AIClientIDs.Claude, []string{"mcp:all", "offline_access"})
	for _, id := range []string{"app", keycloak.ForwardAuthClient} {
		if err := c.SetOptionalScopes(ctx, id, []string{"mcp:all"}); err == nil {
			t.Errorf("SetOptionalScopes(%s) accepted", id)
		}
	}
	// G9 on a real realm: attributes sync skips AI clients.
	_ = c.EnsureAttributeMappers(ctx, []keycloak.AttrField{{Name: "office"}})
	e.checkLiveAIClient(t, keycloak.AIClientIDs.ClaudeCode, []string{"mcp:all", "mcp:gitea.gitea", "offline_access"})

	code := keycloak.AIClientIDs.ClaudeCode
	cb := "http://127.0.0.1:33418/callback"
	jar, _ := cookiejar.New(nil)

	// PKCE is required, S256 only.
	for _, method := range []string{"", "plain"} {
		r := e.aiAuthorize(t, jar, code, cb, "openid mcp:all", method)
		if r.code != "" || r.errCode == "" {
			t.Errorf("PKCE method %q: %+v, want an error", method, r)
		}
		t.Logf("PKCE method %q refused: %s", method, r.errCode)
	}

	// The full sign-in: login, consent, code, tokens.
	r := e.aiAuthorize(t, jar, code, cb, "openid offline_access mcp:all", "S256")
	if r.code == "" {
		t.Fatalf("sign-in: %+v", r)
	}
	if !strings.Contains(r.consent, "Use all your Portcullis apps as you") {
		t.Errorf("consent screen without the scope's text: %.600s", r.consent)
	}
	if strings.Contains(r.consent, "Gitea") {
		t.Errorf("consent screen lists a scope not requested")
	}
	tok := e.aiToken(t, code, cb, r)
	at, id := jwtClaims(t, tok["access_token"]), jwtClaims(t, tok["id_token"])
	t.Logf("access token claims: %v", keys(at))
	t.Logf("ID token claims: %v", keys(id))
	t.Logf("acr after a password sign-in: %v (amr %v)", at["acr"], at["amr"])
	if at["preferred_username"] != "alice" || id["preferred_username"] != "alice" {
		t.Errorf("preferred_username access %v id %v", at["preferred_username"], id["preferred_username"])
	}
	if aud := fmt.Sprint(at["aud"]); !strings.Contains(aud, "https://mcp.example.org/mcp") || strings.Contains(aud, "git.example.org") {
		t.Errorf("aud %v", at["aud"])
	}
	if sc := fmt.Sprint(at["scope"]); !strings.Contains(sc, "mcp:all") || strings.Contains(sc, "gitea") || strings.Contains(sc, "profile") {
		t.Errorf("scope %v", at["scope"])
	}
	if at["azp"] != code || at["typ"] != "Bearer" {
		t.Errorf("azp %v typ %v", at["azp"], at["typ"])
	}
	for _, k := range []string{"email", "name", "given_name", "family_name", "groups", "realm_access", "resource_access", "attr_office", "email_verified"} {
		if _, ok := at[k]; ok {
			t.Errorf("access token carries %s", k)
		}
		if _, ok := id[k]; ok {
			t.Errorf("ID token carries %s", k)
		}
	}
	rt := jwtClaims(t, tok["refresh_token"])
	life := time.Duration(num(rt["exp"])-num(rt["iat"])) * time.Second
	t.Logf("offline refresh token: typ %v, lifetime %v (client idle 7 days)", rt["typ"], life)
	if rt["typ"] != "Offline" || life > 7*24*time.Hour+time.Minute || life < 7*24*time.Hour-time.Hour {
		t.Errorf("offline refresh token typ %v lifetime %v, want Offline / 7 days", rt["typ"], life)
	}
	// No rotation: the same refresh token works twice.
	for i := 0; i < 2; i++ {
		if res := e.refresh(t, code, tok["refresh_token"]); res["access_token"] == "" {
			t.Errorf("refresh %d with the same offline token: %v", i+1, res["error"])
		}
	}

	// Loopback port matching: exact.
	for _, other := range []string{"http://127.0.0.1:40123/callback", "http://localhost:40123/callback", "http://[::1]:33418/callback"} {
		r := e.aiAuthorize(t, jar, code, other, "openid mcp:all", "S256")
		msg := r.page
		if m := feedback.FindStringSubmatch(r.page); m != nil {
			msg = strings.TrimSpace(m[1])
		}
		t.Logf("loopback: registered %v, asked %s → code %v, error %q, page %.120q", keycloak.LoopbackRedirectURIs, other, r.code != "", r.errCode, msg)
		if r.code != "" || msg != "Invalid parameter: redirect_uri" {
			t.Errorf("redirect %s: %+v, want Invalid parameter: redirect_uri", other, msg)
		}
	}
	// A redirect URI of another client: refused.
	if r := e.aiAuthorize(t, jar, code, "https://claude.ai/api/mcp/auth_callback", "openid mcp:all", "S256"); r.code != "" {
		t.Errorf("claude.ai callback accepted for %s", code)
	}

	// A scope the client lacks: invalid_scope.
	r = e.aiAuthorize(t, jar, code, cb, "openid mcp:portcullis.admin", "S256")
	t.Logf("missing scope: code %v, error %q %q", r.code != "", r.errCode, r.errDesc)
	if r.code != "" || r.errCode != "invalid_scope" {
		t.Errorf("a scope the client lacks: %+v, want invalid_scope", r)
	}

	// A new scope asks for consent again.
	r = e.aiAuthorize(t, jar, code, cb, "openid mcp:all mcp:gitea.gitea", "S256")
	t.Logf("second request with mcp:gitea.gitea: consent asked %v", r.consent != "")
	if r.code == "" || !strings.Contains(r.consent, "Use Gitea (git.example.org) as you") {
		t.Errorf("new scope: %+v", r)
	}
	online := e.aiToken(t, code, cb, r) // online refresh token (no offline_access)
	if rt := jwtClaims(t, online["refresh_token"]); rt["typ"] != "Refresh" {
		t.Errorf("online refresh token typ %v", rt["typ"])
	}
	// Another AI client, offline too: survives the disconnect of the first.
	gen := keycloak.AIClientIDs.Generic
	r = e.aiAuthorize(t, jar, gen, cb, "openid offline_access mcp:all mcp:gitea.gitea", "S256")
	if r.code == "" {
		t.Fatalf("generic sign-in: %+v", r)
	}
	genTok := e.aiToken(t, gen, cb, r)

	conns, err := c.AIConnections(ctx, "alice", ids)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("connections: %s", fmtConns(conns))
	if len(conns) != 2 || conns[0].Client != code || conns[0].Consented == nil || conns[0].LastUsed == nil || conns[0].Expires == nil {
		t.Errorf("connections %s", fmtConns(conns))
	}

	// Disconnect (G52).
	if err := c.RevokeAIConnection(ctx, "alice", code); err != nil {
		t.Fatal(err)
	}
	off := e.refresh(t, code, tok["refresh_token"])
	on := e.refresh(t, code, online["refresh_token"])
	t.Logf("disconnect: offline refresh → %q, online refresh → %q (access tokens are self-contained JWTs: valid until exp, %v s)",
		off["error"], on["error"], num(at["exp"])-num(at["iat"]))
	if off["access_token"] != "" || on["access_token"] != "" {
		t.Errorf("refresh after the disconnect: offline %v online %v, want both refused", off["error"], on["error"])
	}
	if res := e.refresh(t, gen, genTok["refresh_token"]); res["access_token"] == "" {
		t.Errorf("another client's offline token died with the disconnect: %v", res["error"])
	}
	// Signing in again asks for consent again.
	if r := e.aiAuthorize(t, jar, code, cb, "openid mcp:all", "S256"); r.consent == "" {
		t.Errorf("no consent screen after the disconnect: %+v", r)
	}
	conns, _ = c.AIConnections(ctx, "alice", ids)
	t.Logf("connections after the disconnect: %s", fmtConns(conns))

	// A deleted scope is detached first and leaves the consents.
	if err := c.DeleteMCPScope(ctx, "mcp:gitea.gitea"); err != nil {
		t.Fatal(err)
	}
	e.checkLiveAIClient(t, gen, []string{"mcp:all", "offline_access"})
	t.Logf("generic consent after the scope delete: %v", e.consentScopes(t, "alice", gen))
	if s := e.consentScopes(t, "alice", gen); slices.Contains(s, "mcp:gitea.gitea") {
		t.Errorf("consent still names the deleted scope: %v", s)
	}

	// Delete: only tagged ones.
	if err := c.DeleteAIClient(ctx, keycloak.AIClientIDs.Claude, keycloak.AIOwner); err != nil {
		t.Fatal(err)
	}

	t.Run("passkey sign-in gives acr/amr hwk", func(t *testing.T) {
		t.Skip("needs a WebAuthn authenticator (no headless virtual authenticator here): T32 manual checklist; the client is asserted to carry no default.acr.values")
	})
}

// realmSettings: core's realm values the AI clients depend on (offline
// bounds, rotation off, the LoA map) and core's amr mapper on acr.
func realmSettings(t *testing.T, e *liveEnv) {
	t.Helper()
	ctx := context.Background()
	err := e.g.UpdateRealm(ctx, e.tok, gocloak.RealmRepresentation{Realm: gocloak.StringP(keycloak.Realm),
		OfflineSessionIdleTimeout: gocloak.IntP(30 * 86400), OfflineSessionMaxLifespanEnabled: gocloak.BoolP(true),
		OfflineSessionMaxLifespan: gocloak.IntP(90 * 86400), RevokeRefreshToken: gocloak.BoolP(false),
		Attributes: map[string]string{"acr.loa.map": `{"public":0,"pwd":1,"hwk":2,"mtls":3}`}})
	if err != nil {
		t.Fatal(err)
	}
	scs, err := e.g.GetClientScopes(ctx, e.tok, keycloak.Realm)
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range scs {
		if *sc.Name == "acr" {
			resp, err := e.g.GetRequestWithBearerAuth(ctx, e.tok).SetBody(map[string]interface{}{"name": "amr", "protocol": "openid-connect", "protocolMapper": "oidc-amr-mapper",
				"config": map[string]string{"id.token.claim": "true", "access.token.claim": "true", "introspection.token.claim": "true"}}).
				Post(e.base + "/admin/realms/" + keycloak.Realm + "/client-scopes/" + *sc.ID + "/protocol-mappers/models")
			if err != nil || resp.IsError() {
				t.Fatalf("amr mapper: %v %v", err, resp)
			}
		}
	}
}

func (e *liveEnv) checkLiveAIClient(t *testing.T, clientID string, optional []string) {
	t.Helper()
	ctx := context.Background()
	uuid := e.clientUUID(t, clientID)
	cl, err := e.g.GetClient(ctx, e.tok, keycloak.Realm, uuid)
	if err != nil {
		t.Fatal(err)
	}
	if !*cl.PublicClient || !*cl.ConsentRequired || !*cl.StandardFlowEnabled || *cl.DirectAccessGrantsEnabled || *cl.ImplicitFlowEnabled ||
		*cl.ServiceAccountsEnabled || *cl.FullScopeAllowed {
		t.Errorf("%s: flags public %v consent %v standard %v direct %v implicit %v sa %v fullScope %v", clientID, *cl.PublicClient, *cl.ConsentRequired,
			*cl.StandardFlowEnabled, *cl.DirectAccessGrantsEnabled, *cl.ImplicitFlowEnabled, *cl.ServiceAccountsEnabled, *cl.FullScopeAllowed)
	}
	for k, want := range map[string]string{"pkce.code.challenge.method": "S256", "client.offline.session.idle.timeout": "604800",
		"client.offline.session.max.lifespan": "2592000", "oauth2.device.authorization.grant.enabled": "false", "oidc.ciba.grant.enabled": "false",
		"standard.token.exchange.enabled": "false", keycloak.OwnerAttr: keycloak.AIOwner} {
		if cl.Attributes[k] != want {
			t.Errorf("%s: %s = %q, want %q", clientID, k, cl.Attributes[k], want)
		}
	}
	if acr, ok := cl.Attributes["default.acr.values"]; ok {
		t.Errorf("%s: default.acr.values = %q, want none", clientID, acr)
	}
	if !slices.Equal(sorted(cl.RedirectURIs), sorted(keycloak.AIRedirectURIs(clientID))) || len(cl.WebOrigins) != 0 {
		t.Errorf("%s: redirects %v origins %v", clientID, cl.RedirectURIs, cl.WebOrigins)
	}
	scopeNames := func(f func(context.Context, string, string, string) ([]*gocloak.ClientScope, error)) []string {
		scs, err := f(ctx, e.tok, keycloak.Realm, uuid)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range scs {
			out = append(out, *s.Name)
		}
		return sorted(out)
	}
	if d := scopeNames(e.g.GetClientsDefaultScopes); !slices.Equal(d, []string{"acr", "basic"}) {
		t.Errorf("%s: default scopes %v", clientID, d)
	}
	if o := scopeNames(e.g.GetClientsOptionalScopes); !slices.Equal(o, sorted(optional)) {
		t.Errorf("%s: optional scopes %v, want %v", clientID, o, optional)
	}
	if n := len(cl.ProtocolMappers); n != 1 || *cl.ProtocolMappers[0].Name != keycloak.AIUsernameMapper {
		t.Errorf("%s: %d protocol mappers", clientID, n)
	}
}

func sorted(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }

type authResult struct {
	code, errCode, errDesc, consent, page, verifier string
}

var (
	consentForm = regexp.MustCompile(`<form[^>]+action="([^"]*login-actions/consent[^"]*)"`)
	feedback    = regexp.MustCompile(`(?s)class="[^"]*(?:kc-feedback-text|instruction)[^"]*">([^<]+)<`)
	hiddenCode  = regexp.MustCompile(`name="code"\s+value="([^"]+)"`)
)

// aiAuthorize runs an authorization request for clientID (PKCE method
// "" = none) through the login form and the consent screen.
func (e *liveEnv) aiAuthorize(t *testing.T, jar http.CookieJar, clientID, redirect, scope, method string) authResult {
	t.Helper()
	base, _ := url.Parse(e.base)
	hc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host != base.Host {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	var res authResult
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	res.verifier = base64.RawURLEncoding.EncodeToString(b)
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {scope}, "state": {"s"}, "nonce": {"n"}}
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(res.verifier))
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		q.Set("code_challenge_method", "S256")
	case "plain":
		q.Set("code_challenge", res.verifier)
		q.Set("code_challenge_method", "plain")
	}
	resp, err := hc.Get(e.base + "/realms/" + keycloak.Realm + "/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		page := string(body)
		if loc := resp.Header.Get("Location"); loc != "" {
			u, _ := url.Parse(loc)
			if u != nil && u.Host != base.Host {
				res.code, res.errCode, res.errDesc = u.Query().Get("code"), u.Query().Get("error"), u.Query().Get("error_description")
				return res
			}
		}
		if m := formAction.FindStringSubmatch(page); m != nil {
			resp, err = hc.PostForm(html.UnescapeString(m[1]), url.Values{"username": {"alice"}, "password": {"alice-pw"}, "credentialId": {""}})
		} else if m := consentForm.FindStringSubmatch(page); m != nil {
			res.consent = html.UnescapeString(page)
			form := url.Values{"accept": {"Yes"}}
			if c := hiddenCode.FindStringSubmatch(page); c != nil {
				form.Set("code", html.UnescapeString(c[1]))
			}
			action, _ := base.Parse(html.UnescapeString(m[1]))
			resp, err = hc.PostForm(action.String(), form)
		} else {
			res.page = html.UnescapeString(page)
			return res
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	res.page = "too many steps"
	return res
}

func (e *liveEnv) tokenCall(t *testing.T, form url.Values) map[string]string {
	t.Helper()
	resp, err := http.PostForm(e.base+"/realms/"+keycloak.Realm+"/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	out := map[string]string{}
	for k, v := range raw {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func (e *liveEnv) aiToken(t *testing.T, clientID, redirect string, r authResult) map[string]string {
	t.Helper()
	tok := e.tokenCall(t, url.Values{"grant_type": {"authorization_code"}, "code": {r.code}, "redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {r.verifier}})
	if tok["access_token"] == "" {
		t.Fatalf("code exchange for %s: %s %s", clientID, tok["error"], tok["error_description"])
	}
	return tok
}

func (e *liveEnv) refresh(t *testing.T, clientID, rt string) map[string]string {
	t.Helper()
	return e.tokenCall(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}})
}

// consentScopes: the scopes of user's consent to clientID.
func (e *liveEnv) consentScopes(t *testing.T, user, clientID string) []string {
	t.Helper()
	ctx := context.Background()
	us, err := e.g.GetUsers(ctx, e.tok, keycloak.Realm, gocloak.GetUsersParams{Username: gocloak.StringP(user), Exact: gocloak.BoolP(true)})
	if err != nil || len(us) != 1 {
		t.Fatalf("user %s: %v", user, err)
	}
	var cs []struct {
		ClientID string   `json:"clientId"`
		Scopes   []string `json:"grantedClientScopes"` // names, on 26.8.1
	}
	if _, err := e.g.GetRequestWithBearerAuth(ctx, e.tok).SetResult(&cs).Get(e.base + "/admin/realms/" + keycloak.Realm + "/users/" + *us[0].ID + "/consents"); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, c := range cs {
		if c.ClientID == clientID {
			out = append(out, c.Scopes...)
		}
	}
	return sorted(out)
}

func jwtClaims(t *testing.T, tok string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func num(v interface{}) int64 {
	f, _ := v.(float64)
	return int64(f)
}

func keys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return sorted(out)
}

func fmtConns(cs []keycloak.AIConnection) string {
	var b strings.Builder
	for _, c := range cs {
		f := func(p *time.Time) string {
			if p == nil {
				return "-"
			}
			return p.Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "[%s consented %s last %s expires %s] ", c.Client, f(c.Consented), f(c.LastUsed), f(c.Expires))
	}
	return b.String()
}
