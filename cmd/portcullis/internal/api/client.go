// Package api is the CLI's HTTPS client to its Portcullis (contract
// §18.3–18.4): the system trust store plus an optional CA file, the
// version header, strict answers, the exit codes, and a --debug log that
// never prints a secret.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

// Exit codes (contract §18.15).
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitNoCert      = 3
	ExitRefused     = 4
	ExitUnreachable = 5
)

// Error is an error with its exit code. Its text is safe to print.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Errorf is an *Error.
func Errorf(code int, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// ExitCode is err's exit code (1 for a plain error).
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ExitError
}

// Client talks to one Portcullis.
type Client struct {
	Base    string // https://people.<d>
	Version string
	HTTP    *http.Client
	Debug   io.Writer // nil = no debug log
}

// TLSConfig is the system pool plus caFile's certificates ("" = none).
// There is no way to skip verification.
func TLSConfig(caFile string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("--ca-file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("--ca-file holds no PEM certificate")
		}
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// New is a client for base with caFile.
func New(base, version, caFile string) (*Client, error) {
	tc, err := TLSConfig(caFile)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext, TLSHandshakeTimeout: 15 * time.Second}
	return &Client{Base: strings.TrimRight(base, "/"), Version: version,
		HTTP: &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// MaxAnswer bounds every answer.
const MaxAnswer = 4 << 20

// Do sends method path with body (nil = none) and decodes the answer into
// out strictly; extra decorates the request (host signatures).
func (c *Client) Do(ctx context.Context, method, path string, body any, out any, extra func(*http.Request, []byte) error) (int, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set(cliapi.HeaderCLI, cliapi.CLIHeaderValue(c.Version))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if extra != nil {
		if err := extra(req, raw); err != nil {
			return 0, err
		}
	}
	c.debugf("> %s %s %s", method, redactURL(req.URL.String()), Redact(raw))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue interface{ Timeout() bool }
		if errors.As(err, &ue) || isDial(err) {
			return 0, Errorf(ExitUnreachable, "can't reach %s: %v", c.Base, cleanNetErr(err))
		}
		return 0, Errorf(ExitUnreachable, "can't reach %s: %v", c.Base, cleanNetErr(err))
	}
	defer resp.Body.Close()
	ans, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswer+1))
	if err != nil {
		return resp.StatusCode, Errorf(ExitUnreachable, "%s: the answer was cut off", c.Base)
	}
	c.debugf("< %d %s", resp.StatusCode, Redact(ans))
	if len(ans) > MaxAnswer {
		return resp.StatusCode, Errorf(ExitError, "%s: the answer is too large", c.Base)
	}
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, statusError(resp.StatusCode, ans)
	}
	if out != nil {
		if err := cliapi.UnmarshalStrict(ans, out); err != nil {
			return resp.StatusCode, Errorf(ExitError, "%s answered something this CLI doesn't understand: update the Portcullis CLI", c.Base)
		}
	}
	return resp.StatusCode, nil
}

func statusError(code int, ans []byte) error {
	var e cliapi.ErrorAnswer
	text := ""
	if json.Unmarshal(ans, &e) == nil {
		text = printable(e.Error)
	}
	if text == "" {
		text = http.StatusText(code)
	}
	switch {
	case code == http.StatusUpgradeRequired:
		return Errorf(ExitError, "%s", text)
	case code == http.StatusForbidden || code == http.StatusConflict:
		return Errorf(ExitRefused, "%s", text)
	case code == http.StatusUnauthorized:
		return Errorf(ExitRefused, "refused by the server (%s)", text)
	case code >= 500:
		return Errorf(ExitError, "the server can't do this right now: %s", text)
	}
	return Errorf(ExitError, "%s", text)
}

// printable keeps a server text to one printable line of ≤ 300 runes
// (a server can't move the terminal's cursor or fake a prompt).
func printable(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e || r == 0x2066 || r == 0x2067 || r == 0x2068 || r == 0x2069 {
			r = ' '
		}
		b.WriteRune(r)
		if n++; n >= 300 {
			break
		}
	}
	return b.String()
}

// Printable is printable for other packages.
func Printable(s string) string { return printable(s) }

func isDial(err error) bool {
	var op *net.OpError
	return errors.As(err, &op)
}

func cleanNetErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) {
		return op.Err.Error()
	}
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return "its TLS certificate isn't trusted (a test server on staging certificates needs --ca-file)"
	}
	return err.Error()
}

func (c *Client) debugf(format string, a ...any) {
	if c.Debug != nil {
		fmt.Fprintf(c.Debug, format+"\n", a...)
	}
}

// Get fetches path's raw answer (public text routes).
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(cliapi.HeaderCLI, cliapi.CLIHeaderValue(c.Version))
	c.debugf("> GET %s", redactURL(req.URL.String()))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, Errorf(ExitUnreachable, "can't reach %s: %v", c.Base, cleanNetErr(err))
	}
	defer resp.Body.Close()
	ans, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswer+1))
	if err != nil || len(ans) > MaxAnswer {
		return nil, Errorf(ExitError, "%s: the answer is cut off or too large", c.Base)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, ans)
	}
	return ans, nil
}
