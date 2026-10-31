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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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
}

// ListUsers returns realm users (up to 1000) with valid IDs.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	var users []User
	code, err := c.do(ctx, "GET", realmPath("/users?max=1000&briefRepresentation=false"), tok, nil, &users)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("list users: HTTP %d", code)
	}
	out := users[:0]
	for _, u := range users {
		if ValidUserID(u.ID) {
			out = append(out, u)
		}
	}
	return out, nil
}

// SetRequiredActions replaces the user's requiredActions array.
func (c *Client) SetRequiredActions(ctx context.Context, userID string, actions []string) error {
	if !ValidUserID(userID) {
		return fmt.Errorf("invalid user id")
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	userPath := realmPath("/users/" + url.PathEscape(userID))
	var user map[string]interface{}
	code, err := c.do(ctx, "GET", userPath, tok, nil, &user)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("get user: HTTP %d", code)
	}
	if actions == nil {
		actions = []string{} // Keycloak insists on a JSON array
	}
	user["requiredActions"] = actions
	code, err = c.do(ctx, "PUT", userPath, tok, user, nil)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if code != 204 {
		return fmt.Errorf("user %s required-actions update: HTTP %d", userID, code)
	}
	return nil
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

// withACR sets default.acr.values and makes sure the "acr" default client
// scope is present on a client representation.
func withACR(client map[string]interface{}, acrValue string) {
	attrs, _ := client["attributes"].(map[string]interface{})
	if attrs == nil {
		attrs = map[string]interface{}{}
	}
	attrs["default.acr.values"] = acrValue
	client["attributes"] = attrs
	scopes, _ := client["defaultClientScopes"].([]interface{})
	for _, sc := range scopes {
		if sc == "acr" {
			return
		}
	}
	client["defaultClientScopes"] = append(scopes, "acr")
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
	if !MayReconcile(existing, s.TemplateID, s.RedirectURIs) {
		return fmt.Errorf("client %s is not owned by template %s", s.ClientID, s.TemplateID)
	}
	withACR(existing, s.ACR)
	return c.putClient(ctx, tok, existing)
}

// MayReconcile decides whether an existing client may be updated for
// template id. Tagged clients must carry this template's tag. Untagged
// clients are adopted only if every existing redirect URI points at a host
// the template itself declares (wantURIs).
func MayReconcile(existing map[string]interface{}, id string, wantURIs []string) bool {
	cid, _ := existing["clientId"].(string)
	if protectedClients[cid] {
		return false
	}
	if attrs, ok := existing["attributes"].(map[string]interface{}); ok {
		if owner, ok := attrs[OwnerAttr].(string); ok && owner != "" {
			return owner == id
		}
	}
	hosts := map[string]bool{}
	for _, u := range wantURIs {
		if pu, err := url.Parse(u); err == nil && pu.Host != "" {
			hosts[strings.ToLower(pu.Host)] = true
		}
	}
	if len(hosts) == 0 {
		return false
	}
	existingURIs, _ := existing["redirectUris"].([]interface{})
	for _, raw := range existingURIs {
		s, _ := raw.(string)
		pu, err := url.Parse(s)
		if err != nil || !hosts[strings.ToLower(pu.Host)] {
			return false
		}
	}
	return true
}

// ClientSpec is what the Hub wants a template's OIDC client to look like.
type ClientSpec struct {
	ClientID     string
	Name         string
	Secret       string
	RedirectURIs []string
	TemplateID   string
	ACR          string
}

// RegisterClient creates (or, if it already exists and the template owns
// it, reconciles) an OIDC client.
func (c *Client) RegisterClient(ctx context.Context, s ClientSpec) error {
	if protectedClients[s.ClientID] {
		return fmt.Errorf("client %s is reserved", s.ClientID)
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
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
		"defaultClientScopes": []string{"openid", "profile", "email", "acr"},
	}
	code, err := c.do(ctx, "POST", realmPath("/clients"), tok, rep, nil)
	if err != nil {
		return fmt.Errorf("client registration failed: %w", err)
	}
	switch code {
	case 201:
		log.Printf("Registered Keycloak client %s", s.ClientID)
		return nil
	case 409:
		// Already exists: reconcile secret, redirect URIs and ACR so the
		// app's .env and Keycloak agree.
		existing, err := c.findClient(ctx, tok, s.ClientID)
		if err != nil {
			return err
		}
		if !MayReconcile(existing, s.TemplateID, s.RedirectURIs) {
			log.Printf("Keycloak client %s already exists and is not owned by template %s — left untouched", s.ClientID, s.TemplateID)
			return nil
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
		return nil
	default:
		return fmt.Errorf("client %s registration: unexpected HTTP %d", s.ClientID, code)
	}
}
