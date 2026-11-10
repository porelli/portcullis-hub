// Package invite asks core for one-time onboarding links (integration
// contract §9.4): a user opens the link, registers a passkey and is signed
// in — no password, no other manual step.
package invite

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

// Defaults (§9.4).
const (
	DefaultAPIURL     = "http://enroll:8444/internal/invites"
	DefaultSecretFile = "/run/portcullis/invite/secret"
)

// ErrNotConfigured means the shared secret file is missing or empty.
var ErrNotConfigured = errors.New("invite API not configured")

// APIError is a non-2xx answer from core's invite API.
type APIError struct {
	Status  int
	Message string // core's {"error"}, truncated; may be empty
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("invite API: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("invite API: HTTP %d", e.Status)
}

// Invite is a one-time link.
type Invite struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Client calls core's invite API.
type Client struct {
	APIURL     string
	SecretFile string
	HTTP       *http.Client
}

// New returns a client with a 20s timeout.
func New(apiURL, secretFile string) *Client {
	return &Client{APIURL: apiURL, SecretFile: secretFile, HTTP: &http.Client{Timeout: 20 * time.Second}}
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

// Create requests a new invite for username. Core revokes the user's
// earlier unredeemed invites.
func (c *Client) Create(ctx context.Context, username string) (*Invite, error) {
	sec, err := c.secret()
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"username": username})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.APIURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("invite API: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		msg := ""
		if json.Unmarshal(data, &e) == nil {
			msg = e.Error
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, &APIError{Status: resp.StatusCode, Message: msg}
	}
	var inv Invite
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("invite API: parse response: %w", err)
	}
	// The link is shown and copied in the UI: only plain https URLs.
	u, err := url.Parse(inv.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("invite API returned an invalid link")
	}
	if inv.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("invite API returned no expiry")
	}
	return &inv, nil
}

// ErrNoCertAPI means enroll has no certificates route (404): an enroll
// older than the sign-in methods. Certificates are then unknown, which
// never counts (contract §9.4).
var ErrNoCertAPI = errors.New("enroll has no certificates API")

// CertRecord is one YubiKey (pki_int) client certificate enroll issued.
type CertRecord struct {
	User     string    `json:"user"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
	Revoked  bool      `json:"revoked"`
}

// maxCertBody bounds the certificates answer.
const maxCertBody = 8 << 20

// certificatesURL is the certificates route next to the invites route:
// <APIURL's directory>/certificates (contract §9.4).
func (c *Client) certificatesURL() (string, error) {
	u, err := url.Parse(c.APIURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invite API URL %q isn't valid", c.APIURL)
	}
	return u.ResolveReference(&url.URL{Path: "certificates"}).String(), nil
}

// Certificates lists the YubiKey client certificates enroll issued (GET
// /internal/certificates, same bearer as invites). 404 = ErrNoCertAPI;
// any other failure is an error too: the caller treats every certificate
// as unknown. Users are lowercased; an entry without a user or with a
// zero expiry is dropped (it can never count).
func (c *Client) Certificates(ctx context.Context) ([]CertRecord, error) {
	sec, err := c.secret()
	if err != nil {
		return nil, err
	}
	target, err := c.certificatesURL()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certificates API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoCertAPI
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode}
	}
	var doc struct {
		Certificates *[]CertRecord `json:"certificates"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCertBody+1))
	if err != nil {
		return nil, fmt.Errorf("certificates API: %w", err)
	}
	if len(data) > maxCertBody {
		return nil, errors.New("certificates API: answer too large")
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Certificates == nil {
		return nil, errors.New("certificates API: unexpected answer")
	}
	out := make([]CertRecord, 0, len(*doc.Certificates))
	for _, r := range *doc.Certificates {
		r.User = strings.ToLower(strings.TrimSpace(r.User))
		if r.User == "" || r.NotAfter.IsZero() {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
