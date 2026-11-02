// Package domains calls core's domains service (integration contract
// §12.2): enroll extra domains with their DNS provider credentials, list
// their status, replace the credentials, remove them. The Hub forwards
// credentials once and forgets them: this package never keeps, logs or
// returns them, and redacts them from every error it builds.
package domains

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Defaults (contract §12.1).
const (
	DefaultAPIURL     = "http://domains:8080"
	DefaultSecretFile = "/run/portcullis/domains/api-secret"
)

// ErrNotConfigured means the API secret file is missing, unreadable or too
// short: the Hub's Domains section is disabled and says why.
var ErrNotConfigured = errors.New("domains service not configured")

// ErrUnreachable wraps a failed connection (the service is down).
var ErrUnreachable = errors.New("domains service unreachable")

// APIError is a non-2xx answer.
type APIError struct {
	Status  int
	Message string // the service's {"error"}, truncated; never a credential
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("domains service: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("domains service: HTTP %d", e.Status)
}

// Domain is the service's domain object (§12.2).
type Domain struct {
	Name         string     `json:"name"`
	Provider     string     `json:"provider"`
	RecordsOK    bool       `json:"records_ok"`
	CertNotAfter *time.Time `json:"cert_not_after"`
	LastError    string     `json:"last_error"`
	State        string     `json:"state"`
}

// Assignable: records OK and a certificate valid at now (§12.3).
func (d Domain) Assignable(now time.Time) bool {
	return d.RecordsOK && d.CertNotAfter != nil && d.CertNotAfter.After(now)
}

// Client calls the domains API.
type Client struct {
	APIURL     string
	SecretFile string
	HTTP       *http.Client
}

// New returns a client. DELETE may wait for a running records step on the
// service, so the timeout is generous.
func New(apiURL, secretFile string) *Client {
	return &Client{APIURL: strings.TrimSuffix(apiURL, "/"), SecretFile: secretFile, HTTP: &http.Client{Timeout: 4 * time.Minute}}
}

func (c *Client) secret() (string, error) {
	if c.SecretFile == "" {
		return "", ErrNotConfigured
	}
	f, err := os.Open(c.SecretFile)
	if err != nil {
		return "", fmt.Errorf("%w: %s unreadable", ErrNotConfigured, c.SecretFile)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", fmt.Errorf("%w: %s unreadable", ErrNotConfigured, c.SecretFile)
	}
	s := strings.TrimSpace(string(b))
	if len(s) < 32 {
		return "", fmt.Errorf("%w: %s must hold at least 32 characters", ErrNotConfigured, c.SecretFile)
	}
	return s, nil
}

// Available reports whether the secret is present (no network call).
func (c *Client) Available() error {
	_, err := c.secret()
	return err
}

// redact removes every credential value from msg.
func redact(msg string, creds map[string]string) string {
	for _, v := range creds {
		if len(v) < 4 {
			continue
		}
		for _, form := range []string{v, fmt.Sprintf("%q", v), url.QueryEscape(v), url.PathEscape(v)} {
			msg = strings.ReplaceAll(msg, form, "[redacted]")
		}
	}
	return msg
}

// do sends one request; creds (if any) are redacted from every error.
func (c *Client) do(ctx context.Context, method, path string, body any, creds map[string]string, out any) (int, error) {
	sec, err := c.secret()
	if err != nil {
		return 0, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, errors.New("encoding the request failed")
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.APIURL+path, rd)
	if err != nil {
		return 0, errors.New(redact(err.Error(), creds))
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// The URL holds no secret; still never echo transport details that
		// could quote the request.
		return 0, fmt.Errorf("%w (%s)", ErrUnreachable, redact(strings.ReplaceAll(err.Error(), sec, "[redacted]"), creds))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if len(msg) > 500 {
			msg = msg[:500] + "…"
		}
		return resp.StatusCode, &APIError{Status: resp.StatusCode, Message: redact(msg, creds)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("domains service: unexpected answer (HTTP %d)", resp.StatusCode)
		}
	}
	return resp.StatusCode, nil
}

func path(name string) string { return "/domains/" + url.PathEscape(name) }

// List returns every enrolled domain, sorted by name.
func (c *Client) List(ctx context.Context) ([]Domain, error) {
	var out []Domain
	if _, err := c.do(ctx, http.MethodGet, "/domains", nil, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Domain{}
	}
	return out, nil
}

type credsBody struct {
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
}

// Enroll enrolls name with its provider credentials (sent once).
func (c *Client) Enroll(ctx context.Context, name, provider string, creds map[string]string) (Domain, error) {
	var d Domain
	_, err := c.do(ctx, http.MethodPut, path(name), credsBody{provider, creds}, creds, &d)
	return d, err
}

// SetToken replaces name's credentials (the provider may change).
func (c *Client) SetToken(ctx context.Context, name, provider string, creds map[string]string) (Domain, error) {
	var d Domain
	_, err := c.do(ctx, http.MethodPost, path(name)+"/token", credsBody{provider, creds}, creds, &d)
	return d, err
}

// Delete removes name; warning is set if some DNS records couldn't be
// removed.
func (c *Client) Delete(ctx context.Context, name string) (warning string, err error) {
	var w struct {
		Warning string `json:"warning"`
	}
	if _, err := c.do(ctx, http.MethodDelete, path(name), nil, nil, &w); err != nil {
		return "", err
	}
	return w.Warning, nil
}
