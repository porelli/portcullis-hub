// Package lldap resolves a forward-auth email to an LLDAP username for the
// Hub's header badge.
package lldap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to LLDAP's HTTP API.
type Client struct {
	URL      string
	User     string
	Password string
	HTTP     *http.Client
}

// New returns a client with a 20s per-request timeout.
func New(url, user, pass string) *Client {
	return &Client{URL: strings.TrimRight(url, "/"), User: user, Password: pass, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// ResolveUsername converts an email to an LLDAP user id, returning the input
// unchanged on any failure (or when no admin password is configured).
func (c *Client) ResolveUsername(ctx context.Context, email string) string {
	if c == nil || c.Password == "" || !strings.Contains(email, "@") {
		return email
	}
	loginBody, _ := json.Marshal(map[string]string{"username": c.User, "password": c.Password})
	var tok struct {
		Token string `json:"token"`
	}
	if !c.post(ctx, "/auth/simple/login", "", loginBody, &tok) || tok.Token == "" {
		return email
	}
	// The email is a GraphQL variable — never spliced into the query.
	query, _ := json.Marshal(map[string]interface{}{
		"query":     `query($email: String!) { users(filters: {eq: {field: "email", value: $email}}) { id } }`,
		"variables": map[string]string{"email": email},
	})
	var gql struct {
		Data struct {
			Users []struct {
				ID string `json:"id"`
			} `json:"users"`
		} `json:"data"`
	}
	if !c.post(ctx, "/api/graphql", tok.Token, query, &gql) || len(gql.Data.Users) == 0 {
		return email
	}
	return gql.Data.Users[0].ID
}

func (c *Client) post(ctx context.Context, path, bearer string, body []byte, out interface{}) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out) == nil
}
