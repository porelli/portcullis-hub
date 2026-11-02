package keycloak_test

import (
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

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
		if err := c.RegisterClient(ctx, keycloak.ClientSpec{ClientID: id, TemplateID: id, Secret: "s-" + id, RedirectURIs: []string{liveRedirect}}); err != nil {
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
