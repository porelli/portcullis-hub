// Package keycloak is a small Keycloak admin-API client (net/http only).
//
// Using net/http instead of shelling out to curl keeps the admin password
// and bearer tokens out of process arguments, gives every call a timeout,
// and verifies TLS if the URL is ever https.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
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

// Client is a Keycloak admin client.
type Client struct {
	BaseURL   string
	AdminUser string
	AdminPass string
	HTTP      *http.Client
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

// token fetches a short-lived admin access token (password grant, master realm).
func (c *Client) token(ctx context.Context) (string, error) {
	form := url.Values{
		"client_id":  {"admin-cli"},
		"username":   {c.AdminUser},
		"password":   {c.AdminPass},
		"grant_type": {"password"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak auth failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("keycloak auth failed: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", fmt.Errorf("keycloak auth response parse: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("no access token from keycloak")
	}
	return tr.AccessToken, nil
}

// do performs an authenticated admin API call. body (if non-nil) is sent as
// JSON; out (if non-nil) receives the decoded 2xx response.
func (c *Client) do(ctx context.Context, method, path, token string, body, out interface{}) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("parse response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func realmPath(rest string) string { return "/admin/realms/" + Realm + rest }

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

func (c *Client) findClient(ctx context.Context, token, clientID string) (map[string]interface{}, error) {
	var clients []map[string]interface{}
	code, err := c.do(ctx, "GET", realmPath("/clients?clientId="+url.QueryEscape(clientID)), token, nil, &clients)
	if err != nil {
		return nil, fmt.Errorf("client lookup failed: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("client lookup: HTTP %d", code)
	}
	for _, cl := range clients {
		if cl["clientId"] == clientID {
			if id, _ := cl["id"].(string); id != "" {
				return cl, nil
			}
		}
	}
	return nil, fmt.Errorf("client %s not found in keycloak", clientID)
}

// withACR sets default.acr.values on a client representation.
func withACR(client map[string]interface{}, acrValue string) {
	attrs, _ := client["attributes"].(map[string]interface{})
	if attrs == nil {
		attrs = map[string]interface{}{}
	}
	attrs["default.acr.values"] = acrValue
	client["attributes"] = attrs
}

// ensureDefaultScopes attaches DefaultScopes and the spec's email scope to
// an existing client and detaches the other email scope (default or
// optional). Keycloak ignores defaultClientScopes in a client PUT, so scopes
// go through the dedicated sub-resources. A missing acr/groups/email scope
// is logged, not fatal (the client still works, just without that claim);
// a missing email-unverified scope is an error and leaves "email" attached,
// since the app asked not to see email_verified.
func (c *Client) ensureDefaultScopes(ctx context.Context, token string, client map[string]interface{}, s ClientSpec) error {
	names := func(key string) map[string]bool {
		out := map[string]bool{}
		if scopes, ok := client[key].([]interface{}); ok {
			for _, sc := range scopes {
				if n, ok := sc.(string); ok {
					out[n] = true
				}
			}
		}
		return out
	}
	haveDefault, haveOptional := names("defaultClientScopes"), names("optionalClientScopes")
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
	var realmScopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	code, err := c.do(ctx, "GET", realmPath("/client-scopes"), token, nil, &realmScopes)
	if err != nil {
		return fmt.Errorf("list client scopes: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("list client scopes: HTTP %d", code)
	}
	ids := map[string]string{}
	for _, sc := range realmScopes {
		ids[sc.Name] = sc.ID
	}
	clientUUID, _ := client["id"].(string)
	scopePath := func(kind, id string) string {
		return realmPath("/clients/" + url.PathEscape(clientUUID) + "/" + kind + "-client-scopes/" + url.PathEscape(id))
	}
	for _, name := range missing {
		id := ids[name]
		if id == "" {
			if name == EmailUnverifiedScope {
				return fmt.Errorf("client %v: the Keycloak realm has no %q client scope (run `portcullis keycloak configure`); keeping its current email scope", client["clientId"], name)
			}
			log.Printf("Keycloak realm has no %q client scope — client %v will not get that claim (run `portcullis keycloak configure`)", name, client["clientId"])
			continue
		}
		code, err := c.do(ctx, "PUT", scopePath("default", id), token, nil, nil)
		if err != nil {
			return fmt.Errorf("attach scope %s: %w", name, err)
		}
		if code != 204 {
			return fmt.Errorf("attach scope %s: HTTP %d", name, code)
		}
	}
	// Detach only after the replacement is attached.
	for kind, have := range map[string]bool{"default": haveDefault[dropEmail], "optional": haveOptional[dropEmail]} {
		id := ids[dropEmail]
		if !have || id == "" {
			continue
		}
		code, err := c.do(ctx, "DELETE", scopePath(kind, id), token, nil, nil)
		if err != nil {
			return fmt.Errorf("detach %s scope %s: %w", kind, dropEmail, err)
		}
		if code != 204 {
			return fmt.Errorf("detach %s scope %s: HTTP %d", kind, dropEmail, code)
		}
	}
	return nil
}

func (c *Client) putClient(ctx context.Context, token string, client map[string]interface{}) error {
	id, _ := client["id"].(string)
	code, err := c.do(ctx, "PUT", realmPath("/clients/"+url.PathEscape(id)), token, client, nil)
	if err != nil {
		return fmt.Errorf("client update failed: %w", err)
	}
	if code != 204 {
		return fmt.Errorf("client %v update: unexpected HTTP %d", client["clientId"], code)
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
	if !MayReconcile(existing, s.TemplateID, s.AllowedHosts) {
		return &ConflictError{ClientID: s.ClientID, TemplateID: s.TemplateID, Owner: ownerOf(existing)}
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
// including an untagged client with no redirect URIs at all — fails closed.
func MayReconcile(existing map[string]interface{}, id string, allowedHosts []string) bool {
	cid, _ := existing["clientId"].(string)
	if protectedClients[cid] {
		return false
	}
	if attrs, ok := existing["attributes"].(map[string]interface{}); ok {
		if owner, ok := attrs[OwnerAttr].(string); ok && owner != "" {
			return owner == id
		}
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
	ownURL := func(raw interface{}) bool {
		s, ok := raw.(string)
		if !ok || s == "" || strings.Contains(s, "*") {
			return false
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
			return false
		}
		return allowed[strings.ToLower(u.Hostname())]
	}
	redirects, _ := existing["redirectUris"].([]interface{})
	if len(redirects) == 0 {
		return false
	}
	for _, raw := range redirects {
		if !ownURL(raw) {
			return false
		}
	}
	if origins, ok := existing["webOrigins"].([]interface{}); ok {
		for _, raw := range origins {
			if raw == "+" { // "same as the redirect URIs"
				continue
			}
			if !ownURL(raw) {
				return false
			}
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

func ownerOf(client map[string]interface{}) string {
	if attrs, ok := client["attributes"].(map[string]interface{}); ok {
		o, _ := attrs[OwnerAttr].(string)
		return o
	}
	return ""
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
	rep := map[string]interface{}{
		"clientId":                  s.ClientID,
		"name":                      s.Name,
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"secret":                    s.Secret,
		"redirectUris":              s.RedirectURIs,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		"attributes": map[string]string{
			"default.acr.values": s.ACR,
			OwnerAttr:            s.TemplateID,
		},
		"defaultClientScopes": append([]string{"openid", "profile", wantEmail}, DefaultScopes...),
	}
	code, err := c.do(ctx, "POST", realmPath("/clients"), tok, rep, nil)
	if err != nil {
		return fmt.Errorf("client registration failed: %w", err)
	}
	switch code {
	case 201:
		log.Printf("Registered Keycloak client %s", s.ClientID)
		// Keycloak silently drops unknown scope names on create; verify.
		created, err := c.findClient(ctx, tok, s.ClientID)
		if err != nil {
			return err
		}
		return c.ensureDefaultScopes(ctx, tok, created, s)
	case 409:
		// Already exists: reconcile secret, redirect URIs and ACR so the
		// app's .env and Keycloak agree.
		existing, err := c.findClient(ctx, tok, s.ClientID)
		if err != nil {
			return err
		}
		if !MayReconcile(existing, s.TemplateID, s.AllowedHosts) {
			return &ConflictError{ClientID: s.ClientID, TemplateID: s.TemplateID, Owner: ownerOf(existing)}
		}
		attrs, _ := existing["attributes"].(map[string]interface{})
		if attrs == nil {
			attrs = map[string]interface{}{}
		}
		attrs[OwnerAttr] = s.TemplateID
		existing["attributes"] = attrs
		if s.Secret != "" {
			existing["secret"] = s.Secret
		}
		if len(s.RedirectURIs) > 0 {
			existing["redirectUris"] = s.RedirectURIs
		}
		withACR(existing, s.ACR)
		if err := c.putClient(ctx, tok, existing); err != nil {
			return err
		}
		log.Printf("Updated existing Keycloak client %s", s.ClientID)
		return c.ensureDefaultScopes(ctx, tok, existing, s)
	default:
		return fmt.Errorf("client %s registration: unexpected HTTP %d", s.ClientID, code)
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
	ID   string `json:"id"`
	Type string `json:"type"`
}

// HTTPError is an unexpected admin API status.
type HTTPError struct {
	Op     string
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.Op, e.Status) }

func (c *Client) credentials(ctx context.Context, tok, userID string) ([]credential, error) {
	var creds []credential
	code, err := c.do(ctx, "GET", realmPath("/users/"+url.PathEscape(userID)+"/credentials"), tok, nil, &creds)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	if code != 200 {
		return nil, &HTTPError{Op: "list credentials", Status: code}
	}
	return creds, nil
}

// StatusConcurrency bounds the parallel credential lookups of UserStatuses.
const StatusConcurrency = 8

func (c *Client) listUsers(ctx context.Context, tok string) ([]User, error) {
	var users []User
	code, err := c.do(ctx, "GET", realmPath("/users?max=1000&briefRepresentation=false"), tok, nil, &users)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	if code != 200 {
		return nil, &HTTPError{Op: "list users", Status: code}
	}
	return users, nil
}

// ldapProviders returns the ids of the realm's LDAP user storage providers.
func (c *Client) ldapProviders(ctx context.Context, tok string) (map[string]bool, error) {
	var comps []struct {
		ID         string `json:"id"`
		ProviderID string `json:"providerId"`
	}
	code, err := c.do(ctx, "GET", realmPath("/components?type=org.keycloak.storage.UserStorageProvider"), tok, nil, &comps)
	if err != nil {
		return nil, fmt.Errorf("list user federation: %w", err)
	}
	if code != 200 {
		return nil, &HTTPError{Op: "list user federation", Status: code}
	}
	out := map[string]bool{}
	for _, cp := range comps {
		if cp.ProviderID == "ldap" && cp.ID != "" {
			out[cp.ID] = true
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
func (c *Client) findUser(ctx context.Context, tok, username string) (map[string]interface{}, error) {
	var users []map[string]interface{}
	code, err := c.do(ctx, "GET", realmPath("/users?exact=true&briefRepresentation=false&username="+url.QueryEscape(username)), tok, nil, &users)
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("find user: HTTP %d", code)
	}
	for _, u := range users {
		name, _ := u["username"].(string)
		id, _ := u["id"].(string)
		if strings.EqualFold(name, username) && ValidUserID(id) {
			return u, nil
		}
	}
	return nil, nil
}

// ErrUserNotFound means Keycloak doesn't know (and couldn't import) the user.
var ErrUserNotFound = fmt.Errorf("user not found in Keycloak")

// importUser returns the user's representation, importing it from LDAP.
func (c *Client) importUser(ctx context.Context, tok, username string) (map[string]interface{}, error) {
	u, err := c.findUser(ctx, tok, username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (c *Client) putUser(ctx context.Context, tok string, user map[string]interface{}) error {
	id, _ := user["id"].(string)
	code, err := c.do(ctx, "PUT", realmPath("/users/"+url.PathEscape(id)), tok, user, nil)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if code != 204 {
		return fmt.Errorf("update user: HTTP %d", code)
	}
	return nil
}

func actionsOf(user map[string]interface{}) []string {
	out := []string{}
	if list, ok := user["requiredActions"].([]interface{}); ok {
		for _, a := range list {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
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
	id, _ := u["id"].(string)
	return id, nil
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
	u["requiredActions"] = actions
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
	return c.addActionLocked(ctx, tok, u, PasskeyAction)
}

func (c *Client) addActionLocked(ctx context.Context, tok string, u map[string]interface{}, action string) error {
	acts := actionsOf(u)
	for _, a := range acts {
		if a == action {
			return nil
		}
	}
	u["requiredActions"] = append(acts, action)
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
	id, _ := u["id"].(string)
	creds, err := c.credentials(ctx, tok, id)
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
	id, _ := u["id"].(string)
	creds, err := c.credentials(ctx, tok, id)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, cr := range creds {
		if !passkeyTypes[cr.Type] {
			continue
		}
		code, err := c.do(ctx, "DELETE", realmPath("/users/"+url.PathEscape(id)+"/credentials/"+url.PathEscape(cr.ID)), tok, nil, nil)
		if err != nil {
			return n, fmt.Errorf("delete credential: %w", err)
		}
		if code != 204 && code != 404 {
			return n, fmt.Errorf("delete credential: HTTP %d", code)
		}
		n++
	}
	if requireNew {
		if err := c.addActionLocked(ctx, tok, u, PasskeyAction); err != nil {
			return n, err
		}
	}
	return n, c.logout(ctx, tok, id)
}

func (c *Client) logout(ctx context.Context, tok, id string) error {
	code, err := c.do(ctx, "POST", realmPath("/users/"+url.PathEscape(id)+"/logout"), tok, nil, nil)
	if err != nil {
		return fmt.Errorf("sign out user: %w", err)
	}
	if code != 204 && code != 200 {
		return fmt.Errorf("sign out user: HTTP %d", code)
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
	id, _ := u["id"].(string)
	return c.logout(ctx, tok, id)
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
	code, err := c.do(ctx, "DELETE", realmPath("/users/"+url.PathEscape(id)), tok, nil, nil)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if code != 204 && code != 404 {
		return fmt.Errorf("delete user: HTTP %d", code)
	}
	return nil
}
