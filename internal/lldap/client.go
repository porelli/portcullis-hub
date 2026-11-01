// Package lldap is a small LLDAP client (hasura/go-graphql-client +
// go-ldap/ldap) for user and group management (integration contract §9).
//
// Users and groups go through LLDAP's GraphQL API (/api/graphql) with a JWT
// from /auth/simple/login; passwords through the LDAP Password Modify
// extended operation (RFC 3062) using go-ldap/ldap. The client logs in as the
// dedicated service account whose username and password core mounts as files,
// re-read on every login so a rotated password needs no restart. Secrets are
// never logged and never appear in errors.
package lldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hasura/go-graphql-client"
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

// errResponseTooLarge is returned when a GraphQL response exceeds maxResponse.
var errResponseTooLarge = errors.New("response too large")

// limitDoer bounds every GraphQL response body to maxResponse (the library
// reads bodies whole); reading past it fails with errResponseTooLarge.
type limitDoer struct{ c *http.Client }

func (d limitDoer) Do(req *http.Request) (*http.Response, error) {
	resp, err := d.c.Do(req)
	if err == nil && resp.Body != nil {
		resp.Body = &limitBody{rc: resp.Body, left: maxResponse}
	}
	return resp, err
}

type limitBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *limitBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		// One byte more tells "exactly at the limit" from "over it".
		var one [1]byte
		if n, _ := b.rc.Read(one[:]); n > 0 {
			return 0, errResponseTooLarge
		}
		return b.rc.Read(p)
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *limitBody) Close() error { return b.rc.Close() }

// graphql runs one query; a 401 triggers a single re-login and retry.
func (c *Client) graphql(ctx context.Context, query string, vars map[string]interface{}, out interface{}) error {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.currentToken(ctx, attempt > 0)
		if err != nil {
			return err
		}
		gc := graphql.NewClient(c.HTTPURL+"/api/graphql", limitDoer{c.HTTP}).
			WithRequestModifier(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) })
		data, err := gc.ExecRaw(ctx, query, vars)
		if err != nil {
			var ne graphql.NetworkError
			if errors.As(err, &ne) {
				if ne.StatusCode() == http.StatusUnauthorized && attempt == 0 {
					continue
				}
				return fmt.Errorf("lldap graphql: HTTP %d", ne.StatusCode())
			}
			var ges graphql.Errors
			if !errors.As(err, &ges) || len(ges) == 0 {
				return fmt.Errorf("lldap graphql: %w", err)
			}
			ge := &GraphQLError{}
			for _, e := range ges {
				if inner := e.Unwrap(); errors.Is(inner, errResponseTooLarge) {
					return fmt.Errorf("lldap graphql: %w", errResponseTooLarge)
				} else if inner != nil {
					// Transport / decode failure, not a server-reported error.
					return fmt.Errorf("lldap graphql: %w", inner)
				}
				ge.Messages = append(ge.Messages, e.Message)
			}
			return ge
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
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
// extended operation (RFC 3062), bound as the service account.
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

// Password changes go over LDAP, not HTTP: LLDAP stores passwords with
// OPAQUE, and its HTTP endpoints (/auth/opaque/register/*) expect the client
// half of the OPAQUE registration, which the Hub can't do. LLDAP's LDAP
// server implements the RFC 3062 Password Modify extended operation and runs
// the OPAQUE registration server-side (lldap v0.6.3
// crates/ldap/src/password.rs); members of lldap_admin may change any user's
// password that way.
//
// ldapPasswordModify binds as bindDN and sets userDN's password. The whole
// exchange (dial, bind, extended op) is bounded by timeout and by ctx, so a
// silent server can't hang the caller.
func ldapPasswordModify(ctx context.Context, rawURL string, timeout time.Duration, bindDN, bindPassword, userDN, newPassword string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid LLDAP LDAP URL: %w", err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return fmt.Errorf("LLDAP LDAP URL must be ldap:// or ldaps://, got %q", u.Scheme)
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ldap: connect: %w", err)
	}
	conn, err := ldap.DialURL(rawURL,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout, Deadline: deadline}),
		ldap.DialWithTLSConfig(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}))
	if err != nil {
		return fmt.Errorf("ldap: connect: %w", err)
	}
	defer func() {
		_ = conn.Unbind() // best effort; Close tears the connection down anyway
		conn.Close()
	}()
	// Per-request timeout (go-ldap's default is none; <= 0 also means none,
	// hence the check), and close the connection (failing the pending
	// request) when ctx is cancelled.
	setTimeout := func() error {
		left := time.Until(deadline)
		if left <= 0 {
			return fmt.Errorf("ldap: %w", context.DeadlineExceeded)
		}
		conn.SetTimeout(left)
		return nil
	}
	if err := setTimeout(); err != nil {
		return err
	}
	defer context.AfterFunc(ctx, func() { conn.Close() })()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		// Never echo the server message for binds: keep it short.
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode != ldap.ErrorNetwork {
			return &ldap.Error{ResultCode: le.ResultCode, Err: fmt.Errorf("ldap bind: result %d", le.ResultCode)}
		}
		return fmt.Errorf("ldap bind: %w", err)
	}
	// Same overall deadline for the extended op (SetTimeout is per request).
	if err := setTimeout(); err != nil {
		return err
	}
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(userDN, "", newPassword)); err != nil {
		return fmt.Errorf("ldap password modify: %w", err)
	}
	return nil
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
