// Package lldap is a small LLDAP client (net/http + a minimal LDAP codec,
// stdlib only) for user and group management (integration contract §9).
//
// Users and groups go through LLDAP's GraphQL API (/api/graphql) with a JWT
// from /auth/simple/login; passwords through the LDAP Password Modify
// extended operation (see ldap.go). The client logs in as the dedicated
// service account whose username and password core mounts as files, re-read
// on every login so a rotated password needs no restart. Secrets are never
// logged and never appear in errors.
package lldap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultCredentialsDir is where core mounts the service account (§9).
const DefaultCredentialsDir = "/run/portcullis/lldap"

// AdminGroup is LLDAP's built-in admin group (group id 1).
const AdminGroup = "lldap_admin"

const maxResponse = 16 << 20

// ErrNotConfigured means the credential files are missing or empty.
var ErrNotConfigured = errors.New("LLDAP credentials not configured")

// Client talks to one LLDAP instance.
type Client struct {
	HTTPURL        string // e.g. http://lldap:17170
	LDAPURL        string // e.g. ldap://lldap:3890
	BaseDN         string // e.g. dc=portcullis,dc=local
	CredentialsDir string // contains username and password
	HTTP           *http.Client
	Timeout        time.Duration // LDAP timeout

	mu      sync.Mutex
	token   string
	refresh string
	expires time.Time
}

// New returns a client with 20s timeouts.
func New(httpURL, ldapURL, baseDN, credDir string) *Client {
	return &Client{
		HTTPURL:        strings.TrimRight(httpURL, "/"),
		LDAPURL:        ldapURL,
		BaseDN:         baseDN,
		CredentialsDir: credDir,
		HTTP:           &http.Client{Timeout: 20 * time.Second},
		Timeout:        20 * time.Second,
	}
}

// readSecretFile reads a small credential file, trimming one trailing newline.
func readSecretFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// Credentials returns the service account's username and password.
func (c *Client) Credentials() (user, pass string, err error) {
	if c.CredentialsDir == "" {
		return "", "", ErrNotConfigured
	}
	user, err = readSecretFile(filepath.Join(c.CredentialsDir, "username"))
	if err != nil {
		return "", "", fmt.Errorf("%w: %s/username unreadable", ErrNotConfigured, c.CredentialsDir)
	}
	pass, err = readSecretFile(filepath.Join(c.CredentialsDir, "password"))
	if err != nil {
		return "", "", fmt.Errorf("%w: %s/password unreadable", ErrNotConfigured, c.CredentialsDir)
	}
	user = strings.TrimSpace(user)
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("%w: empty username or password file in %s", ErrNotConfigured, c.CredentialsDir)
	}
	if !ValidUsername(user) {
		return "", "", fmt.Errorf("%w: invalid service account username", ErrNotConfigured)
	}
	return user, pass, nil
}

// ServiceUser returns the service account's username ("" if unconfigured).
func (c *Client) ServiceUser() string {
	u, _, err := c.Credentials()
	if err != nil {
		return ""
	}
	return strings.ToLower(u)
}

// Available reports whether the credentials are present (no network call).
func (c *Client) Available() error {
	_, _, err := c.Credentials()
	return err
}

// jwtExpiry reads the exp claim of a JWT without verifying it (the token
// came straight from LLDAP; this only schedules a refresh).
func jwtExpiry(tok string) time.Time {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

type loginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

func (c *Client) postJSON(ctx context.Context, path string, hdr http.Header, body interface{}) (*http.Response, []byte, error) {
	var rdr io.Reader
	method := http.MethodGet
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rdr, method = bytes.NewReader(b), http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, c.HTTPURL+path, rdr)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	return resp, data, err
}

// login gets a fresh token (refresh token first, then username/password).
// Caller holds c.mu.
func (c *Client) loginLocked(ctx context.Context) error {
	if c.refresh != "" {
		resp, data, err := c.postJSON(ctx, "/auth/refresh", http.Header{"Refresh-Token": {c.refresh}}, nil)
		if err == nil && resp.StatusCode == 200 {
			var lr loginResponse
			if json.Unmarshal(data, &lr) == nil && lr.Token != "" {
				c.token, c.expires = lr.Token, jwtExpiry(lr.Token)
				return nil
			}
		}
		c.refresh = ""
	}
	user, pass, err := c.Credentials()
	if err != nil {
		return err
	}
	resp, data, err := c.postJSON(ctx, "/auth/simple/login", nil, map[string]string{"username": user, "password": pass})
	if err != nil {
		return fmt.Errorf("lldap login: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("lldap login as %s failed: HTTP %d", user, resp.StatusCode)
	}
	var lr loginResponse
	if err := json.Unmarshal(data, &lr); err != nil || lr.Token == "" {
		return fmt.Errorf("lldap login: no token in response")
	}
	c.token, c.refresh, c.expires = lr.Token, lr.RefreshToken, jwtExpiry(lr.Token)
	return nil
}

func (c *Client) currentToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if force || c.token == "" || (!c.expires.IsZero() && time.Until(c.expires) < time.Minute) {
		if err := c.loginLocked(ctx); err != nil {
			c.token = ""
			return "", err
		}
	}
	return c.token, nil
}

// GraphQLError is an error returned in a GraphQL response.
type GraphQLError struct{ Messages []string }

func (e *GraphQLError) Error() string { return "lldap: " + strings.Join(e.Messages, "; ") }

// graphql runs one query; a 401 triggers a single re-login and retry.
func (c *Client) graphql(ctx context.Context, query string, vars map[string]interface{}, out interface{}) error {
	body := map[string]interface{}{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.currentToken(ctx, attempt > 0)
		if err != nil {
			return err
		}
		resp, data, err := c.postJSON(ctx, "/api/graphql", http.Header{"Authorization": {"Bearer " + tok}}, body)
		if err != nil {
			return fmt.Errorf("lldap graphql: %w", err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("lldap graphql: HTTP %d", resp.StatusCode)
		}
		var gr struct {
			Data   json.RawMessage `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(data, &gr); err != nil {
			return fmt.Errorf("lldap graphql: parse response: %w", err)
		}
		if len(gr.Errors) > 0 {
			ge := &GraphQLError{}
			for _, e := range gr.Errors {
				ge.Messages = append(ge.Messages, e.Message)
			}
			return ge
		}
		if out != nil {
			if err := json.Unmarshal(gr.Data, out); err != nil {
				return fmt.Errorf("lldap graphql: parse data: %w", err)
			}
		}
		return nil
	}
	return fmt.Errorf("lldap graphql: unauthorized")
}

// Attribute is a custom user attribute from the schema.
type Attribute struct {
	Name   string
	IsList bool
}

// GroupRef is a group as listed on a user.
type GroupRef struct {
	ID          int    `json:"id"`
	DisplayName string `json:"displayName"`
}

// User is an LLDAP user.
type User struct {
	ID           string              `json:"id"`
	Email        string              `json:"email"`
	DisplayName  string              `json:"displayName"`
	CreationDate string              `json:"creationDate"`
	Groups       []GroupRef          `json:"groups"`
	Attributes   map[string][]string `json:"-"` // custom attributes only
}

// Group is an LLDAP group with its members' ids.
type Group struct {
	ID           int    `json:"id"`
	DisplayName  string `json:"displayName"`
	CreationDate string `json:"creationDate"`
	Users        []struct {
		ID string `json:"id"`
	} `json:"users"`
}

// Members returns the member user ids.
func (g Group) Members() []string {
	out := make([]string, 0, len(g.Users))
	for _, u := range g.Users {
		out = append(out, u.ID)
	}
	return out
}

// ListUsers returns every user with their groups and custom attributes.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var resp struct {
		Users []struct {
			ID           string     `json:"id"`
			Email        string     `json:"email"`
			DisplayName  string     `json:"displayName"`
			CreationDate string     `json:"creationDate"`
			Groups       []GroupRef `json:"groups"`
			Attributes   []struct {
				Name   string   `json:"name"`
				Value  []string `json:"value"`
				Schema struct {
					IsHardcoded bool `json:"isHardcoded"`
				} `json:"schema"`
			} `json:"attributes"`
		} `json:"users"`
	}
	err := c.graphql(ctx, `query { users { id email displayName creationDate groups { id displayName } attributes { name value schema { isHardcoded } } } }`, nil, &resp)
	if err != nil {
		return nil, err
	}
	users := make([]User, 0, len(resp.Users))
	for _, u := range resp.Users {
		user := User{
			ID:           u.ID,
			Email:        u.Email,
			DisplayName:  u.DisplayName,
			CreationDate: u.CreationDate,
			Groups:       u.Groups,
			Attributes:   map[string][]string{},
		}
		for _, a := range u.Attributes {
			if !a.Schema.IsHardcoded {
				user.Attributes[a.Name] = a.Value
			}
		}
		users = append(users, user)
	}
	return users, nil
}

// ListGroups returns every group with its members.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var out struct {
		Groups []Group `json:"groups"`
	}
	err := c.graphql(ctx, `query { groups { id displayName creationDate users { id } } }`, nil, &out)
	return out.Groups, err
}

// CreateUser creates a user (no password yet).
func (c *Client) CreateUser(ctx context.Context, id, email, displayName string) error {
	in := map[string]interface{}{"id": id, "email": email}
	if displayName != "" {
		in["displayName"] = displayName
	}
	return c.graphql(ctx, `mutation($user: CreateUserInput!) { createUser(user: $user) { id } }`, map[string]interface{}{"user": in}, nil)
}

// UpdateUser changes email and/or display name (nil = unchanged).
func (c *Client) UpdateUser(ctx context.Context, id string, email, displayName *string) error {
	in := map[string]interface{}{"id": id}
	if email != nil {
		in["email"] = *email
	}
	if displayName != nil {
		in["displayName"] = *displayName
	}
	return c.graphql(ctx, `mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }`, map[string]interface{}{"user": in}, nil)
}

// DeleteUser deletes a user.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.graphql(ctx, `mutation($id: String!) { deleteUser(userId: $id) { ok } }`, map[string]interface{}{"id": id}, nil)
}

// CreateGroup creates a group and returns its id.
func (c *Client) CreateGroup(ctx context.Context, name string) (int, error) {
	var out struct {
		CreateGroup struct {
			ID int `json:"id"`
		} `json:"createGroup"`
	}
	err := c.graphql(ctx, `mutation($name: String!) { createGroup(name: $name) { id } }`, map[string]interface{}{"name": name}, &out)
	return out.CreateGroup.ID, err
}

// DeleteGroup deletes a group by id.
func (c *Client) DeleteGroup(ctx context.Context, id int) error {
	return c.graphql(ctx, `mutation($id: Int!) { deleteGroup(groupId: $id) { ok } }`, map[string]interface{}{"id": id}, nil)
}

// AddUserToGroup adds a member.
func (c *Client) AddUserToGroup(ctx context.Context, user string, group int) error {
	return c.graphql(ctx, `mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }`, map[string]interface{}{"u": user, "g": group}, nil)
}

// RemoveUserFromGroup removes a member.
func (c *Client) RemoveUserFromGroup(ctx context.Context, user string, group int) error {
	return c.graphql(ctx, `mutation($u: String!, $g: Int!) { removeUserFromGroup(userId: $u, groupId: $g) { ok } }`, map[string]interface{}{"u": user, "g": group}, nil)
}

// UserDN is the LDAP DN of a (validated) user id.
func (c *Client) UserDN(user string) string {
	return "uid=" + user + ",ou=people," + c.BaseDN
}

// SetPassword sets a user's password through the LDAP Password Modify
// extended operation, bound as the service account.
func (c *Client) SetPassword(ctx context.Context, user, password string) error {
	if !ValidUsername(user) {
		return fmt.Errorf("invalid username")
	}
	if c.LDAPURL == "" || c.BaseDN == "" {
		return fmt.Errorf("LLDAP LDAP URL or base DN not configured")
	}
	svc, svcPass, err := c.Credentials()
	if err != nil {
		return err
	}
	return ldapPasswordModify(ctx, c.LDAPURL, c.Timeout, c.UserDN(strings.ToLower(svc)), svcPass, c.UserDN(user), password)
}

// UserAttributes returns the non-hardcoded user attributes from the schema.
func (c *Client) UserAttributes(ctx context.Context) ([]Attribute, error) {
	var out struct {
		Schema struct {
			UserSchema struct {
				Attributes []struct {
					Name        string `json:"name"`
					IsList      bool   `json:"isList"`
					IsHardcoded bool   `json:"isHardcoded"`
				} `json:"attributes"`
			} `json:"userSchema"`
		} `json:"schema"`
	}
	err := c.graphql(ctx, `query { schema { userSchema { attributes { name isList isHardcoded } } } }`, nil, &out)
	if err != nil {
		return nil, err
	}
	var attrs []Attribute
	for _, a := range out.Schema.UserSchema.Attributes {
		if !a.IsHardcoded {
			attrs = append(attrs, Attribute{Name: a.Name, IsList: a.IsList})
		}
	}
	return attrs, nil
}

// AddUserAttribute adds a custom user attribute to the schema (STRING type, visible, not editable).
func (c *Client) AddUserAttribute(ctx context.Context, name string, isList bool) error {
	vars := map[string]interface{}{
		"name":          name,
		"attributeType": "STRING",
		"isList":        isList,
		"isVisible":     true,
		"isEditable":    false,
	}
	return c.graphql(ctx, `mutation($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) { addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) { ok } }`, vars, nil)
}

// DeleteUserAttribute deletes a custom user attribute from the schema.
func (c *Client) DeleteUserAttribute(ctx context.Context, name string) error {
	return c.graphql(ctx, `mutation($name: String!) { deleteUserAttribute(name: $name) { ok } }`, map[string]interface{}{"name": name}, nil)
}

// SetUserAttributes sets or removes custom attributes on a user.
// set maps attribute names to their values (as string slices, even for single-valued attributes).
// remove lists attribute names to delete.
func (c *Client) SetUserAttributes(ctx context.Context, user string, set map[string][]string, remove []string) error {
	in := map[string]interface{}{"id": user}
	if len(set) > 0 {
		var insert []map[string]interface{}
		for name, values := range set {
			insert = append(insert, map[string]interface{}{"name": name, "value": values})
		}
		in["insertAttributes"] = insert
	}
	if len(remove) > 0 {
		in["removeAttributes"] = remove
	}
	return c.graphql(ctx, `mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }`, map[string]interface{}{"user": in}, nil)
}
