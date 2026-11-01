// Package keycloak is the Hub's Keycloak admin-API client, built on
// github.com/Nerzal/gocloak (HTTP via resty over a net/http client).
//
// Talking HTTP instead of shelling out to kcadm/curl keeps the admin
// password and bearer tokens out of process arguments, gives every call a
// timeout, and verifies TLS if the URL is ever https.
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v14"
	"github.com/go-resty/resty/v2"
)

// Realm is the Portcullis realm the Hub manages.
const Realm = "portcullis"

// OwnerAttr marks Keycloak clients created by the Hub with the template that
// owns them, so a template can only ever reconcile its own client.
const OwnerAttr = "portcullis.hub.template"

const maxBody = 16 << 20

// protectedClients are core/built-in clients no template may touch.
var protectedClients = map[string]bool{
	"portcullis-forward-auth": true, "admin-cli": true, "account": true, "account-console": true,
	"broker": true, "realm-management": true, "security-admin-console": true,
}

// DefaultScopes are attached to every client the Hub manages: "acr" puts
// acr/amr in tokens (step-up), "groups" (created by `portcullis init`, claim
// "groups", group names without path) lets apps map users_<app>/admin_<app>
// to roles.
var DefaultScopes = []string{"acr", "groups"}

// EmailUnverifiedScope is the realm client scope (maintained by core's
// `portcullis keycloak configure`) that carries the email claim but no
// email_verified. Clients with ClientSpec.OmitEmailVerified get it instead
// of the built-in "email" scope; the two are mutually exclusive.
const EmailUnverifiedScope = "email-unverified"

// emailScopes returns the email scope a client must have and the one it
// must not have.
func (s ClientSpec) emailScopes() (want, drop string) {
	if s.OmitEmailVerified {
		return EmailUnverifiedScope, "email"
	}
	return "email", EmailUnverifiedScope
}

// uuidRe: Keycloak user IDs are UUIDs (they are spliced into UI handlers).
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)

// ValidUserID reports whether id looks like a Keycloak user ID.
func ValidUserID(id string) bool { return uuidRe.MatchString(id) }

// Client is a Keycloak admin client. The fields are read on first use.
type Client struct {
	BaseURL   string
	AdminUser string
	AdminPass string
	HTTP      *http.Client

	once sync.Once
	gc   *gocloak.GoCloak
}

// New returns a client with a 20s per-request timeout.
func New(baseURL, user, pass string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		AdminUser: user,
		AdminPass: pass,
		HTTP:      &http.Client{Timeout: 20 * time.Second},
	}
}

// api returns the gocloak client over c.HTTP (bodies capped at maxBody).
func (c *Client) api() *gocloak.GoCloak {
	c.once.Do(func() {
		hc := c.HTTP
		if hc == nil {
			hc = &http.Client{Timeout: 20 * time.Second}
		}
		rc := resty.NewWithClient(hc).SetResponseBodyLimit(maxBody).SetDisableWarn(true).SetLogger(quietLogger{})
		// The admin API only speaks JSON; parse it as such even when a
		// proxy (or a test fake) leaves out the Content-Type.
		rc.OnBeforeRequest(func(_ *resty.Client, r *resty.Request) error {
			r.ForceContentType("application/json")
			return nil
		})
		c.gc = gocloak.NewClient(c.BaseURL)
		c.gc.SetRestyClient(rc)
	})
	return c.gc
}

// quietLogger drops resty's own log lines (unparsable error bodies during
// an outage, ...): failures are returned as errors, and nothing about a
// request may reach the log on its own.
type quietLogger struct{}

func (quietLogger) Errorf(string, ...interface{}) {}
func (quietLogger) Warnf(string, ...interface{})  {}
func (quietLogger) Debugf(string, ...interface{}) {}

// HTTPError is an unexpected admin API status.
type HTTPError struct {
	Op     string
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.Op, e.Status) }

// statusCode is the HTTP status of a gocloak error (0: not an HTTP error).
func statusCode(err error) int {
	var ae *gocloak.APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return 0
}

// opErr turns a gocloak error into "op: HTTP n" (*HTTPError, response body
// dropped) or "op: <transport error>".
func opErr(op string, err error) error {
	if code := statusCode(err); code != 0 {
		return &HTTPError{Op: op, Status: code}
	}
	return fmt.Errorf("%s: %w", op, err)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// token fetches a short-lived admin access token (password grant, master realm).
func (c *Client) token(ctx context.Context) (string, error) {
	jwt, err := c.api().LoginAdmin(ctx, c.AdminUser, c.AdminPass, "master")
	if err != nil {
		return "", opErr("keycloak auth failed", err)
	}
	if jwt.AccessToken == "" {
		return "", fmt.Errorf("no access token from keycloak")
	}
	return jwt.AccessToken, nil
}

// User is the subset of a Keycloak user representation the UI shows.
type User struct {
	ID              string   `json:"id"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	Enabled         bool     `json:"enabled"`
	RequiredActions []string `json:"requiredActions"`
	// FederationLink is the id of the user storage provider (the LDAP
	// federation) the user was imported from; "" for local users.
	FederationLink string `json:"federationLink"`
}

func userOf(u *gocloak.User) User {
	return User{ID: str(u.ID), Username: str(u.Username), Email: str(u.Email), Enabled: u.Enabled != nil && *u.Enabled,
		RequiredActions: u.RequiredActions, FederationLink: str(u.FederationLink)}
}

func (c *Client) findClient(ctx context.Context, token, clientID string) (*gocloak.Client, error) {
	clients, err := c.api().GetClients(ctx, token, Realm, gocloak.GetClientsParams{ClientID: &clientID})
	if err != nil {
		return nil, opErr("client lookup", err)
	}
	for _, cl := range clients {
		if cl != nil && str(cl.ClientID) == clientID && str(cl.ID) != "" {
			return cl, nil
		}
	}
	return nil, fmt.Errorf("client %s not found in keycloak", clientID)
}

// withACR sets default.acr.values on a client representation.
func withACR(client *gocloak.Client, acrValue string) {
	if client.Attributes == nil {
		client.Attributes = map[string]string{}
	}
	client.Attributes["default.acr.values"] = acrValue
}

// ensureDefaultScopes attaches DefaultScopes and the spec's email scope to
// an existing client and detaches the other email scope (default or
// optional). Keycloak ignores defaultClientScopes in a client PUT, so scopes
// go through the dedicated sub-resources. A missing acr/groups/email scope
// is logged, not fatal (the client still works, just without that claim);
// a missing email-unverified scope is an error and leaves "email" attached,
// since the app asked not to see email_verified.
func (c *Client) ensureDefaultScopes(ctx context.Context, token string, client *gocloak.Client, s ClientSpec) error {
	set := func(names []string) map[string]bool {
		out := map[string]bool{}
		for _, n := range names {
			out[n] = true
		}
		return out
	}
	haveDefault, haveOptional := set(client.DefaultClientScopes), set(client.OptionalClientScopes)
	wantEmail, dropEmail := s.emailScopes()
	var missing []string
	for _, name := range append(append([]string{}, DefaultScopes...), wantEmail) {
		if !haveDefault[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 && !haveDefault[dropEmail] && !haveOptional[dropEmail] {
		return nil
	}
	g := c.api()
	realmScopes, err := g.GetClientScopes(ctx, token, Realm)
	if err != nil {
		return opErr("list client scopes", err)
	}
	ids := map[string]string{}
	for _, sc := range realmScopes {
		if sc != nil {
			ids[str(sc.Name)] = str(sc.ID)
		}
	}
	clientUUID, clientID := url.PathEscape(str(client.ID)), str(client.ClientID)
	for _, name := range missing {
		id := ids[name]
		if id == "" {
			if name == EmailUnverifiedScope {
				return fmt.Errorf("client %v: the Keycloak realm has no %q client scope (run `portcullis keycloak configure`); keeping its current email scope", clientID, name)
			}
			log.Printf("Keycloak realm has no %q client scope — client %v will not get that claim (run `portcullis keycloak configure`)", name, clientID)
			continue
		}
		if err := g.AddDefaultScopeToClient(ctx, token, Realm, clientUUID, url.PathEscape(id)); err != nil {
			return opErr("attach scope "+name, err)
		}
	}
	// Detach only after the replacement is attached.
	id := url.PathEscape(ids[dropEmail])
	if id == "" {
		return nil
	}
	if haveDefault[dropEmail] {
		if err := g.RemoveDefaultScopeFromClient(ctx, token, Realm, clientUUID, id); err != nil {
			return opErr("detach default scope "+dropEmail, err)
		}
	}
	if haveOptional[dropEmail] {
		if err := g.RemoveOptionalScopeFromClient(ctx, token, Realm, clientUUID, id); err != nil {
			return opErr("detach optional scope "+dropEmail, err)
		}
	}
	return nil
}

func (c *Client) putClient(ctx context.Context, token string, client *gocloak.Client) error {
	if err := c.api().UpdateClient(ctx, token, Realm, *client); err != nil {
		if code := statusCode(err); code != 0 {
			return fmt.Errorf("client %v update: unexpected HTTP %d", str(client.ClientID), code)
		}
		return fmt.Errorf("client update failed: %w", err)
	}
	return nil
}

// UpdateClientACR pushes a new default.acr.values to a client so its own
// authorize requests trigger step-up when the session's LoA is too low.
// Only clients the template may reconcile (see MayReconcile) are touched;
// s.Secret and s.Name are ignored.
func (c *Client) UpdateClientACR(ctx context.Context, s ClientSpec) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	existing, err := c.findClient(ctx, tok, s.ClientID)
	if err != nil {
		return err
	}
	if !mayReconcile(existing, s.TemplateID, s.AllowedHosts) {
		return &ConflictError{ClientID: s.ClientID, TemplateID: s.TemplateID, Owner: existing.Attributes[OwnerAttr]}
	}
	withACR(existing, s.ACR)
	if err := c.putClient(ctx, tok, existing); err != nil {
		return err
	}
	return c.ensureDefaultScopes(ctx, tok, existing, s)
}

// MayReconcile decides whether an existing client may be updated for
// template id. Tagged clients must carry this template's tag. Untagged
// clients are adopted only if they demonstrably belong to the template:
// they have at least one redirect URI, and every redirect URI and web
// origin is a plain https/http URL (no wildcards) whose host is one of
// allowedHosts (the template's own <sub>.<domain> hosts). Anything else —
// including an untagged client with no redirect URIs at all, or a
// representation that doesn't parse — fails closed.
func MayReconcile(existing map[string]interface{}, id string, allowedHosts []string) bool {
	b, err := json.Marshal(existing)
	if err != nil {
		return false
	}
	var cl gocloak.Client
	if err := json.Unmarshal(b, &cl); err != nil {
		return false
	}
	return mayReconcile(&cl, id, allowedHosts)
}

func mayReconcile(existing *gocloak.Client, id string, allowedHosts []string) bool {
	if protectedClients[str(existing.ClientID)] {
		return false
	}
	if owner := existing.Attributes[OwnerAttr]; owner != "" {
		return owner == id
	}
	allowed := map[string]bool{}
	for _, h := range allowedHosts {
		if h != "" {
			allowed[strings.ToLower(h)] = true
		}
	}
	if len(allowed) == 0 {
		return false
	}
	ownURL := func(s string) bool {
		if s == "" || strings.Contains(s, "*") {
			return false
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
			return false
		}
		return allowed[strings.ToLower(u.Hostname())]
	}
	if len(existing.RedirectURIs) == 0 {
		return false
	}
	for _, raw := range existing.RedirectURIs {
		if !ownURL(raw) {
			return false
		}
	}
	for _, raw := range existing.WebOrigins {
		if raw == "+" { // "same as the redirect URIs"
			continue
		}
		if !ownURL(raw) {
			return false
		}
	}
	return true
}

// ConflictError means a client with the requested clientId already exists
// and the template may not take it over (see MayReconcile).
type ConflictError struct {
	ClientID   string
	TemplateID string
	Owner      string // owning template tag, "" if untagged
}

func (e *ConflictError) Error() string {
	owner := "it is not tagged as Hub-managed and does not point only at this app's hosts"
	if e.Owner != "" {
		owner = "it belongs to template " + e.Owner
	}
	return fmt.Sprintf("Keycloak client %q already exists and %s — refusing to let template %s take it over; delete or rename that client in Keycloak, or change client_id in the template", e.ClientID, owner, e.TemplateID)
}

// ClientSpec is what the Hub wants a template's OIDC client to look like.
type ClientSpec struct {
	ClientID     string
	Name         string
	Secret       string
	RedirectURIs []string
	TemplateID   string
	ACR          string
	// AllowedHosts are the template's own hosts (<sub>.<domain>); an
	// untagged existing client is only adopted if it points solely there.
	AllowedHosts []string
	// OmitEmailVerified attaches EmailUnverifiedScope instead of "email"
	// (manifest keycloak_clients[].email_verified_claim: false).
	OmitEmailVerified bool
}

// RegisterClient creates (or, if it already exists and the template owns
// it, reconciles) an OIDC client.
func (c *Client) RegisterClient(ctx context.Context, s ClientSpec) error {
	if protectedClients[s.ClientID] {
		return &ConflictError{ClientID: s.ClientID, TemplateID: s.TemplateID, Owner: "core"}
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	wantEmail, _ := s.emailScopes()
	rep := gocloak.Client{
		ClientID:                  gocloak.StringP(s.ClientID),
		Name:                      gocloak.StringP(s.Name),
		Enabled:                   gocloak.BoolP(true),
		Protocol:                  gocloak.StringP("openid-connect"),
		PublicClient:              gocloak.BoolP(false),
		Secret:                    gocloak.StringP(s.Secret),
		RedirectURIs:              s.RedirectURIs,
		StandardFlowEnabled:       gocloak.BoolP(true),
		DirectAccessGrantsEnabled: gocloak.BoolP(false),
		Attributes: map[string]string{
			"default.acr.values": s.ACR,
			OwnerAttr:            s.TemplateID,
		},
		DefaultClientScopes: append([]string{"openid", "profile", wantEmail}, DefaultScopes...),
	}
	_, err = c.api().CreateClient(ctx, tok, Realm, rep)
	switch code := statusCode(err); {
	case err == nil:
		log.Printf("Registered Keycloak client %s", s.ClientID)
		// Keycloak silently drops unknown scope names on create; verify.
		created, err := c.findClient(ctx, tok, s.ClientID)
		if err != nil {
			return err
		}
		return c.ensureDefaultScopes(ctx, tok, created, s)
	case code == http.StatusConflict:
		// Already exists: reconcile secret, redirect URIs and ACR so the
		// app's .env and Keycloak agree.
		existing, err := c.findClient(ctx, tok, s.ClientID)
		if err != nil {
			return err
		}
		if !mayReconcile(existing, s.TemplateID, s.AllowedHosts) {
			return &ConflictError{ClientID: s.ClientID, TemplateID: s.TemplateID, Owner: existing.Attributes[OwnerAttr]}
		}
		if existing.Attributes == nil {
			existing.Attributes = map[string]string{}
		}
		existing.Attributes[OwnerAttr] = s.TemplateID
		if s.Secret != "" {
			existing.Secret = gocloak.StringP(s.Secret)
		}
		if len(s.RedirectURIs) > 0 {
			existing.RedirectURIs = s.RedirectURIs
		}
		withACR(existing, s.ACR)
		if err := c.putClient(ctx, tok, existing); err != nil {
			return err
		}
		log.Printf("Updated existing Keycloak client %s", s.ClientID)
		return c.ensureDefaultScopes(ctx, tok, existing, s)
	case code != 0:
		return fmt.Errorf("client %s registration: unexpected HTTP %d", s.ClientID, code)
	default:
		return fmt.Errorf("client registration failed: %w", err)
	}
}

// ── user management (contract §9) ────────────────────────

// PasskeyAction is the required action that makes a user register a passkey.
const PasskeyAction = "webauthn-register-passwordless"

// passkeyTypes are the WebAuthn credential types (2FA and passwordless).
var passkeyTypes = map[string]bool{"webauthn": true, "webauthn-passwordless": true}

// UserStatus is a user's Keycloak-side state.
type UserStatus struct {
	ID              string   `json:"id"`
	Username        string   `json:"username"`
	Enabled         bool     `json:"enabled"`
	RequiredActions []string `json:"required_actions"`
	Passkeys        int      `json:"passkeys"`
	// LDAPFederated: imported from the realm's LDAP federation (LLDAP).
	LDAPFederated bool `json:"ldap_federated"`
	// Error is set when this user's credentials couldn't be read (Passkeys
	// is then unknown). Keycloak answers 404 or 500 for a federated user
	// whose LDAP entry is gone; ErrorStatus is that HTTP status (0: not an
	// HTTP error, e.g. a timeout).
	Error       string `json:"error,omitempty"`
	ErrorStatus int    `json:"error_status,omitempty"`
}

type credential struct {
	ID   string
	Type string
}

func (c *Client) credentials(ctx context.Context, tok, userID string) ([]credential, error) {
	creds, err := c.api().GetCredentials(ctx, tok, Realm, url.PathEscape(userID))
	if err != nil {
		return nil, opErr("list credentials", err)
	}
	out := make([]credential, 0, len(creds))
	for _, cr := range creds {
		if cr != nil {
			out = append(out, credential{ID: str(cr.ID), Type: str(cr.Type)})
		}
	}
	return out, nil
}

// StatusConcurrency bounds the parallel credential lookups of UserStatuses.
const StatusConcurrency = 8

func (c *Client) listUsers(ctx context.Context, tok string) ([]User, error) {
	users, err := c.api().GetUsers(ctx, tok, Realm, gocloak.GetUsersParams{Max: gocloak.IntP(1000), BriefRepresentation: gocloak.BoolP(false)})
	if err != nil {
		return nil, opErr("list users", err)
	}
	out := make([]User, 0, len(users))
	for _, u := range users {
		if u != nil {
			out = append(out, userOf(u))
		}
	}
	return out, nil
}

// ldapProviders returns the ids of the realm's LDAP user storage providers.
func (c *Client) ldapProviders(ctx context.Context, tok string) (map[string]bool, error) {
	comps, err := c.api().GetComponentsWithParams(ctx, tok, Realm, gocloak.GetComponentsParams{ProviderType: gocloak.StringP("org.keycloak.storage.UserStorageProvider")})
	if err != nil {
		return nil, opErr("list user federation", err)
	}
	out := map[string]bool{}
	for _, cp := range comps {
		if cp != nil && str(cp.ProviderID) == "ldap" && str(cp.ID) != "" {
			out[str(cp.ID)] = true
		}
	}
	return out, nil
}

func statusOf(u User, ldap map[string]bool) UserStatus {
	acts := u.RequiredActions
	if acts == nil {
		acts = []string{}
	}
	return UserStatus{ID: u.ID, Username: u.Username, Enabled: u.Enabled, RequiredActions: acts,
		LDAPFederated: u.FederationLink != "" && ldap[u.FederationLink]}
}

// UserStatuses returns every user already in Keycloak (LDAP users are
// imported lazily, on first login or lookup), keyed by lowercase username,
// with their passkey count. One token, at most StatusConcurrency
// credential lookups at once. The error is realm-level only (auth, user
// list, federation list: Keycloak is down); a failed credential lookup
// marks just that user (UserStatus.Error), so one broken record never
// hides everybody's status.
func (c *Client) UserStatuses(ctx context.Context) (map[string]UserStatus, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	users, err := c.listUsers(ctx, tok)
	if err != nil {
		return nil, err
	}
	ldap, err := c.ldapProviders(ctx, tok)
	if err != nil {
		return nil, err
	}
	out := make(map[string]UserStatus, len(users))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, StatusConcurrency)
	for _, u := range users {
		if !ValidUserID(u.ID) {
			continue
		}
		wg.Add(1)
		go func(u User) {
			defer wg.Done()
			st := statusOf(u, ldap)
			var creds []credential
			var err error
			select {
			case sem <- struct{}{}:
				creds, err = c.credentials(ctx, tok, u.ID)
				<-sem
			case <-ctx.Done():
				err = fmt.Errorf("list credentials: %w", ctx.Err())
			}
			if err != nil {
				st.Error = err.Error()
				var he *HTTPError
				if errors.As(err, &he) {
					st.ErrorStatus = he.Status
				}
			}
			for _, cr := range creds {
				if passkeyTypes[cr.Type] {
					st.Passkeys++
				}
			}
			mu.Lock()
			out[strings.ToLower(u.Username)] = st
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return out, nil
}

// ListedUser returns username's record as Keycloak's user list has it
// (no LDAP lookup or import, no credentials), or nil if Keycloak has no
// such user. It works for federated users whose LDAP entry is gone.
func (c *Client) ListedUser(ctx context.Context, username string) (*UserStatus, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	users, err := c.listUsers(ctx, tok)
	if err != nil {
		return nil, err
	}
	ldap, err := c.ldapProviders(ctx, tok)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, username) && ValidUserID(u.ID) {
			st := statusOf(u, ldap)
			return &st, nil
		}
	}
	return nil, nil
}

// findUser looks a user up by exact username. For an LDAP-federated realm
// this also imports the user from LDAP if Keycloak hasn't seen them yet.
// Returns nil, nil if there is no such user.
func (c *Client) findUser(ctx context.Context, tok, username string) (*gocloak.User, error) {
	users, err := c.api().GetUsers(ctx, tok, Realm, gocloak.GetUsersParams{
		Username: gocloak.StringP(username), Exact: gocloak.BoolP(true), BriefRepresentation: gocloak.BoolP(false)})
	if err != nil {
		return nil, opErr("find user", err)
	}
	for _, u := range users {
		if u != nil && strings.EqualFold(str(u.Username), username) && ValidUserID(str(u.ID)) {
			return u, nil
		}
	}
	return nil, nil
}

// ErrUserNotFound means Keycloak doesn't know (and couldn't import) the user.
var ErrUserNotFound = fmt.Errorf("user not found in Keycloak")

// importUser returns the user's representation, importing it from LDAP.
func (c *Client) importUser(ctx context.Context, tok, username string) (*gocloak.User, error) {
	u, err := c.findUser(ctx, tok, username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUserNotFound
	}
	return u, nil
}

// userUpdate is a user PUT body that always carries requiredActions:
// gocloak.User tags it omitempty, so an empty list (clearing every action)
// would be dropped and Keycloak would keep the old ones.
type userUpdate struct {
	gocloak.User
	RequiredActions []string `json:"requiredActions"`
}

// putUser updates a user. Raw request (on gocloak's resty request builder)
// instead of gocloak.UpdateUser because of the omitempty above.
func (c *Client) putUser(ctx context.Context, tok string, user *gocloak.User) error {
	body := userUpdate{User: *user, RequiredActions: user.RequiredActions}
	if body.RequiredActions == nil {
		body.RequiredActions = []string{}
	}
	resp, err := c.api().GetRequestWithBearerAuth(ctx, tok).SetBody(body).
		Put(c.BaseURL + "/admin/realms/" + Realm + "/users/" + url.PathEscape(str(user.ID)))
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if resp.IsError() {
		return &HTTPError{Op: "update user", Status: resp.StatusCode()}
	}
	return nil
}

// ImportUser makes sure Keycloak has imported username from LDAP and
// returns its Keycloak id.
func (c *Client) ImportUser(ctx context.Context, username string) (string, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return "", err
	}
	u, err := c.importUser(ctx, tok, username)
	if err != nil {
		return "", err
	}
	return str(u.ID), nil
}

// SetUserRequiredActions imports username if needed and replaces its
// required actions.
func (c *Client) SetUserRequiredActions(ctx context.Context, username string, actions []string) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	u, err := c.importUser(ctx, tok, username)
	if err != nil {
		return err
	}
	if actions == nil {
		actions = []string{}
	}
	u.RequiredActions = actions
	return c.putUser(ctx, tok, u)
}

// RequirePasskey imports username if needed and adds PasskeyAction to its
// required actions.
func (c *Client) RequirePasskey(ctx context.Context, username string) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	u, err := c.importUser(ctx, tok, username)
	if err != nil {
		return err
	}
	return c.addAction(ctx, tok, u, PasskeyAction)
}

func (c *Client) addAction(ctx context.Context, tok string, u *gocloak.User, action string) error {
	for _, a := range u.RequiredActions {
		if a == action {
			return nil
		}
	}
	u.RequiredActions = append(append([]string{}, u.RequiredActions...), action)
	return c.putUser(ctx, tok, u)
}

// CredentialCount returns how many credentials of any type (password,
// OTP, WebAuthn, ...) username has; 0 for a user Keycloak doesn't know (an
// LDAP user may be imported by the lookup). A failed lookup is an error,
// never 0.
func (c *Client) CredentialCount(ctx context.Context, username string) (int, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return 0, err
	}
	u, err := c.findUser(ctx, tok, username)
	if err != nil || u == nil {
		return 0, err
	}
	creds, err := c.credentials(ctx, tok, str(u.ID))
	if err != nil {
		return 0, err
	}
	return len(creds), nil
}

// RemovePasskeys deletes every WebAuthn credential of username, adds
// PasskeyAction if requireNew, and signs the user out. It returns how many
// credentials were deleted.
func (c *Client) RemovePasskeys(ctx context.Context, username string, requireNew bool) (int, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return 0, err
	}
	u, err := c.importUser(ctx, tok, username)
	if err != nil {
		return 0, err
	}
	id := str(u.ID)
	creds, err := c.credentials(ctx, tok, id)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, cr := range creds {
		if !passkeyTypes[cr.Type] {
			continue
		}
		err := c.api().DeleteCredentials(ctx, tok, Realm, url.PathEscape(id), url.PathEscape(cr.ID))
		if err != nil && statusCode(err) != http.StatusNotFound {
			return n, opErr("delete credential", err)
		}
		n++
	}
	if requireNew {
		if err := c.addAction(ctx, tok, u, PasskeyAction); err != nil {
			return n, err
		}
	}
	return n, c.logout(ctx, tok, id)
}

func (c *Client) logout(ctx context.Context, tok, id string) error {
	if err := c.api().LogoutAllSessions(ctx, tok, Realm, url.PathEscape(id)); err != nil {
		return opErr("sign out user", err)
	}
	return nil
}

// LogoutUser ends every Keycloak session of username. A user Keycloak has
// never imported has no sessions: that's not an error.
func (c *Client) LogoutUser(ctx context.Context, username string) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	u, err := c.findUser(ctx, tok, username)
	if err != nil || u == nil {
		return err
	}
	return c.logout(ctx, tok, str(u.ID))
}

// DeleteUserByID removes a user from Keycloak's database (and its
// sessions). With the READ_ONLY LDAP federation this never touches LLDAP.
// A missing user is not an error.
func (c *Client) DeleteUserByID(ctx context.Context, id string) error {
	if !ValidUserID(id) {
		return fmt.Errorf("invalid user id")
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	if err := c.api().DeleteUser(ctx, tok, Realm, url.PathEscape(id)); err != nil && statusCode(err) != http.StatusNotFound {
		return opErr("delete user", err)
	}
	return nil
}
