// Package mailctl calls core's mailctl API (integration contract §19.5):
// the Hub sends the desired mail state, reads the wanted DNS sets, the
// checks and the status, and manages people's mail passwords. mailctl is
// the only holder of Stalwart's API key; the Hub holds only the bearer
// secret, which this package never logs, returns or puts in an error.
package mailctl

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
	"unicode/utf8"
)

// Defaults (contract §19.1).
const (
	DefaultAPIURL     = "http://mailctl:8080"
	DefaultSecretFile = "/run/portcullis/mail/hub-secret"
)

// maxAnswer is the largest answer read (the API's body limit).
const maxAnswer = 4 << 20

// ErrNotConfigured: the bearer secret file is missing, unreadable or too
// short. The Hub then treats mail as off (contract §19.1).
var ErrNotConfigured = errors.New("mailctl not configured")

// ErrUnreachable wraps a failed connection.
var ErrUnreachable = errors.New("mailctl unreachable")

// APIError is a non-2xx answer. Msg is mailctl's {"error"}, redacted and
// clipped.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("mailctl: HTTP %d: %s", e.Status, e.Msg)
	}
	return fmt.Sprintf("mailctl: HTTP %d", e.Status)
}

// StatusOf is err's HTTP status (0 when it isn't an APIError).
func StatusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// Client calls the mailctl API.
type Client struct {
	APIURL     string
	SecretFile string
	HTTP       *http.Client
}

// New returns a client. Every mailctl call is short (Stalwart calls are
// local), so the timeout is too.
func New(apiURL, secretFile string) *Client {
	return &Client{APIURL: strings.TrimSuffix(apiURL, "/"), SecretFile: secretFile, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// secret reads the bearer secret at each call (core may rotate it).
func (c *Client) secret() (string, error) {
	if c == nil || c.SecretFile == "" {
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

// redact removes every secret from msg, in its plain and escaped forms.
func redact(msg string, secrets ...string) string {
	for _, v := range secrets {
		if len(v) < 4 {
			continue
		}
		for _, form := range []string{v, fmt.Sprintf("%q", v), url.QueryEscape(v), url.PathEscape(v)} {
			msg = strings.ReplaceAll(msg, form, "[redacted]")
		}
	}
	return msg
}

// clip shortens s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// do sends one request. The answer is decoded strictly into out (the
// contract's exact shape: an unknown key is a contract mismatch, refused).
// Errors never carry the bearer secret.
func (c *Client) do(ctx context.Context, method, path string, body, out any) (int, error) {
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
		return 0, errors.New(redact(err.Error(), sec))
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w (%s)", ErrUnreachable, clip(redact(err.Error(), sec), 300))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	// The answer may hold a created password: wipe the buffer once decoded.
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if len(raw) > maxAnswer {
		return resp.StatusCode, fmt.Errorf("mailctl: answer larger than %d bytes (HTTP %d)", maxAnswer, resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		// Redact first, then clip: clipping first could cut a secret so
		// that its prefix escapes redaction.
		return resp.StatusCode, &APIError{Status: resp.StatusCode, Msg: clip(redact(e.Error, sec), 500)}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("mailctl: unexpected answer (HTTP %d)", resp.StatusCode)
		}
		if dec.More() {
			return resp.StatusCode, fmt.Errorf("mailctl: unexpected answer (HTTP %d): trailing data", resp.StatusCode)
		}
	}
	return resp.StatusCode, nil
}

// PutState sends a document; the answer is the generation mailctl took.
func (c *Client) PutState(ctx context.Context, st *MailState) (int, error) {
	if st == nil {
		return 0, errors.New("mailctl: no state")
	}
	var out struct {
		Generation int `json:"generation"`
	}
	if _, err := c.do(ctx, http.MethodPut, "/v1/state", st, &out); err != nil {
		return 0, err
	}
	return out.Generation, nil
}

// State is the applied generation and whether the base plan is in place.
func (c *Client) State(ctx context.Context) (StateStatus, error) {
	var out StateStatus
	_, err := c.do(ctx, http.MethodGet, "/v1/state", nil, &out)
	return out, err
}

// DNS is domain's wanted mail set.
func (c *Client) DNS(ctx context.Context, domain string) (DNSSet, error) {
	var out DNSSet
	_, err := c.do(ctx, http.MethodGet, "/v1/dns/"+url.PathEscape(domain), nil, &out)
	return out, err
}

// Checks are the last check results (refresh: run them again).
func (c *Client) Checks(ctx context.Context, refresh bool) (Checks, error) {
	p := "/v1/checks"
	if refresh {
		p += "?refresh=1"
	}
	var out Checks
	_, err := c.do(ctx, http.MethodGet, p, nil, &out)
	return out, err
}

// Status is MailStatus.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	_, err := c.do(ctx, http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

// Credentials are user's live mail passwords (never a secret).
func (c *Client) Credentials(ctx context.Context, user string) ([]Credential, error) {
	var out []Credential
	if _, err := c.do(ctx, http.MethodGet, "/v1/credentials?user="+url.QueryEscape(user), nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Credential{}
	}
	return out, nil
}

// CreateCredential creates one mail password for user. The answer's
// Secret is the only copy of the password: the caller zeroes it.
func (c *Client) CreateCredential(ctx context.Context, user, label string, expires *time.Time) (Created, error) {
	body := struct {
		Username  string     `json:"username"`
		Label     string     `json:"label"`
		ExpiresAt *time.Time `json:"expires_at"`
	}{user, label, expires}
	var out Created
	if _, err := c.do(ctx, http.MethodPost, "/v1/credentials", body, &out); err != nil {
		out.Secret.Zero()
		return Created{}, err
	}
	if out.ID == "" || len(out.Secret) == 0 {
		out.Secret.Zero()
		return Created{}, errors.New("mailctl: unexpected answer (no id or no password)")
	}
	return out, nil
}

// RevokeCredential destroys one of user's mail passwords (also when it
// was already gone).
func (c *Client) RevokeCredential(ctx context.Context, user, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/credentials/"+url.PathEscape(id)+"?user="+url.QueryEscape(user), nil, nil)
	return err
}

// Action runs one of mailctl's actions on domain.
func (c *Client) Action(ctx context.Context, name, domain string) error {
	switch name {
	case ActionDKIMRotate, ActionDMARCPromote, ActionMTASTSEnforce:
	default:
		return fmt.Errorf("mailctl: unknown action %q", name)
	}
	_, err := c.do(ctx, http.MethodPost, "/v1/actions/"+name, struct {
		Domain string `json:"domain"`
	}{domain}, nil)
	return err
}
