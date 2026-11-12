package invite

// enroll's certificate actions (contract §9.4 "Certificate actions",
// sign-in part 2): browser certificates, YubiKey certificates issued from
// a CSR or renewed, and revocation. Same listener and bearer as the
// invites; the URLs derive from the invites URL's directory, like
// certificatesURL. The .p12 and its password cross this client exactly
// once: they never reach a log, an error or a String().

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// maxMessage bounds an APIError's Message (characters).
	maxMessage = 200
	// maxActionBody bounds an action's answer.
	maxActionBody = 1 << 20
	// maxActionRequest is enroll's request limit (64 KiB, else 413):
	// refused here before anything is sent.
	maxActionRequest = 64 << 10
)

// BrowserCertRequest asks enroll for a browser certificate for User,
// valid Days (1 ≤ Days ≤ MaxDays), while User has fewer than MaxActive
// unrevoked, unexpired browser certificates.
type BrowserCertRequest struct {
	User      string
	Days      int
	MaxDays   int
	MaxActive int
}

// BrowserCert is a new browser certificate: the .p12 (P12, its key
// included) and its Password are shown once and never kept. Clear zeroes
// P12 after use. String, GoString and Format never print P12 or Password.
type BrowserCert struct {
	P12      []byte
	Password string
	Serial   string
	Filename string
	NotAfter time.Time
}

// String names the certificate without its secrets. String, GoString
// and Format have value receivers, so a BrowserCert value and a pointer
// to one print the same (fmt prints a nil pointer as <nil>).
func (b BrowserCert) String() string {
	return fmt.Sprintf("browser certificate %s (%s, until %s)", b.Serial, b.Filename, b.NotAfter.UTC().Format(time.RFC3339))
}

// GoString is String (%#v never prints the secrets either).
func (b BrowserCert) GoString() string { return b.String() }

// Format prints String for every verb.
func (b BrowserCert) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, b.String()) }

// Clear zeroes the .p12 and drops it and the password.
func (b *BrowserCert) Clear() {
	if b == nil {
		return
	}
	clear(b.P12)
	b.P12 = nil
	b.Password = ""
}

// IssuedCert is a YubiKey certificate enroll signed: PEM is the
// certificate (no key: the key stays on the YubiKey).
type IssuedCert struct {
	PEM      string
	Serial   string
	NotAfter time.Time
}

// errProtected is enroll's own refusal, answered here before anything is
// sent (the protected names never reach enroll).
func errProtected() error {
	return &APIError{Status: http.StatusConflict, Message: "protected account"}
}

// ProtectedName reports whether user is one enroll's certificate actions
// refuse: admin, portcullis-hub or any portcullis-* name (lowercased).
func ProtectedName(user string) bool {
	u := strings.ToLower(strings.TrimSpace(user))
	return u == "admin" || u == "portcullis-hub" || strings.HasPrefix(u, "portcullis-")
}

// actionURL is <APIURL's directory>/<path> (contract §9.4).
func (c *Client) actionURL(path string) (string, error) {
	u, err := url.Parse(c.APIURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invite API URL %q isn't valid", c.APIURL)
	}
	return u.ResolveReference(&url.URL{Path: path}).String(), nil
}

// post sends body (JSON) to path with the bearer and returns the answer
// when its status is want. Any other status is an *APIError: enroll's
// {"error"} text (≤ maxMessage characters) only for 400, 403, 404 and
// 409, never the request body. The answer is bounded to maxActionBody;
// the caller zeroes it after use. The request buffer is zeroed here.
func (c *Client) post(ctx context.Context, path string, body any, want int) ([]byte, error) {
	if c.HTTP == nil {
		return nil, errors.New("certificates API: no HTTP client")
	}
	sec, err := c.secret()
	if err != nil {
		return nil, err
	}
	target, err := c.actionURL(path)
	if err != nil {
		return nil, err
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("certificates API: request can't be encoded")
	}
	defer clear(buf)
	if len(buf) > maxActionRequest {
		return nil, &APIError{Status: http.StatusRequestEntityTooLarge, Message: "request too large"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.noRedirect().Do(req)
	if err != nil {
		return nil, fmt.Errorf("certificates API: %w", redactURLError(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxActionBody+1))
	if err != nil {
		clear(data)
		return nil, errors.New("certificates API: answer unreadable")
	}
	if len(data) > maxActionBody {
		clear(data)
		return nil, errors.New("certificates API: answer too large")
	}
	if resp.StatusCode != want {
		e := &APIError{Status: resp.StatusCode}
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict:
			var doc struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(data, &doc) == nil {
				e.Message = clip(doc.Error, maxMessage)
			}
		}
		clear(data)
		return nil, e
	}
	return data, nil
}

// noRedirect is c.HTTP that never follows a redirect: a 3xx is answered
// as it is (an *APIError), so the bearer and request body never go
// anywhere but the configured URL.
func (c *Client) noRedirect() *http.Client {
	hc := *c.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &hc
}

// decodeOne decodes exactly one JSON value from data into v, strictly
// (no unknown fields), with nothing after it: a second Decode must
// return io.EOF.
func decodeOne(data []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		return false
	}
	var extra json.RawMessage
	err := dec.Decode(&extra)
	clear(extra)
	return err == io.EOF
}

// redactURLError drops the URL from a transport error (it holds no
// secret, but keeps the message short and stable).
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// safeFilename is the .p12 download name enroll gives
// (<user>-browser-certificate-<YYYYMMDD>.p12): a plain file name.
var safeFilename = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,200}\.p12$`)

// p12Password is enroll's password form (D22): 20 Crockford base32
// characters in 4 groups of 5 joined by "-".
var p12Password = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$`)

// CreateBrowserCertificate asks enroll for a browser certificate
// (POST /internal/browser-certificates → 201). The answer is decoded
// once; its buffer is zeroed. A malformed answer is an error that never
// quotes it. The caller shows P12 and Password once, then calls Clear.
func (c *Client) CreateBrowserCertificate(ctx context.Context, r BrowserCertRequest) (*BrowserCert, error) {
	if strings.TrimSpace(r.User) == "" {
		return nil, errors.New("certificates API: no user")
	}
	if ProtectedName(r.User) {
		return nil, errProtected()
	}
	body := struct {
		User      string `json:"user"`
		Days      int    `json:"days"`
		MaxDays   int    `json:"max_days"`
		MaxActive int    `json:"max_active"`
	}{r.User, r.Days, r.MaxDays, r.MaxActive}
	data, err := c.post(ctx, "browser-certificates", body, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var doc struct {
		P12      []byte    `json:"p12"` // std base64, decoded by encoding/json
		Password string    `json:"password"`
		Serial   string    `json:"serial"`
		NotAfter time.Time `json:"not_after"`
		Filename string    `json:"filename"`
	}
	bad := errors.New("certificates API: unexpected browser certificate answer")
	if !decodeOne(data, &doc) {
		clear(doc.P12)
		return nil, bad
	}
	if len(doc.P12) == 0 || !p12Password.MatchString(doc.Password) || doc.Serial == "" || doc.NotAfter.IsZero() || !safeFilename.MatchString(doc.Filename) {
		clear(doc.P12)
		return nil, bad
	}
	return &BrowserCert{P12: doc.P12, Password: doc.Password, Serial: doc.Serial, Filename: doc.Filename, NotAfter: doc.NotAfter}, nil
}

// IssueYubiKeyCertificate asks enroll to sign csrPEM for user on pki_int
// (POST /internal/yubikey-certificates → 201; the admin CSR path). The CN
// is always user, never the CSR's subject.
func (c *Client) IssueYubiKeyCertificate(ctx context.Context, user, csrPEM string) (*IssuedCert, error) {
	if strings.TrimSpace(user) == "" {
		return nil, errors.New("certificates API: no user")
	}
	if ProtectedName(user) {
		return nil, errProtected()
	}
	body := struct {
		User string `json:"user"`
		CSR  string `json:"csr"`
	}{user, csrPEM}
	return c.issued(ctx, "yubikey-certificates", body)
}

// RenewYubiKeyCertificate asks enroll to renew user's YubiKey certificate
// (POST /internal/yubikey-certificates/renew → 201): presentedPEM is the
// certificate the browser presented (real PEM), csrPEM the new request.
func (c *Client) RenewYubiKeyCertificate(ctx context.Context, user, presentedPEM, csrPEM string) (*IssuedCert, error) {
	if strings.TrimSpace(user) == "" {
		return nil, errors.New("certificates API: no user")
	}
	if ProtectedName(user) {
		return nil, errProtected()
	}
	body := struct {
		User      string `json:"user"`
		Presented string `json:"presented"`
		CSR       string `json:"csr"`
	}{user, presentedPEM, csrPEM}
	return c.issued(ctx, "yubikey-certificates/renew", body)
}

// issued posts body to path and decodes a {certificate, serial,
// not_after} answer: the certificate must be one PEM CERTIFICATE block
// that parses as X.509.
func (c *Client) issued(ctx context.Context, path string, body any) (*IssuedCert, error) {
	data, err := c.post(ctx, path, body, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var doc struct {
		Certificate string    `json:"certificate"`
		Serial      string    `json:"serial"`
		NotAfter    time.Time `json:"not_after"`
	}
	bad := errors.New("certificates API: unexpected certificate answer")
	if !decodeOne(data, &doc) {
		return nil, bad
	}
	if doc.Serial == "" || doc.NotAfter.IsZero() {
		return nil, bad
	}
	blk, rest := pem.Decode([]byte(doc.Certificate))
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, bad
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		return nil, bad
	}
	return &IssuedCert{PEM: doc.Certificate, Serial: doc.Serial, NotAfter: doc.NotAfter}, nil
}

// RevokeCertificate asks enroll to revoke user's certificate serial on
// whichever mount holds it (POST /internal/certificates/revoke → 204;
// already revoked is 204 too; another user's serial is 404).
func (c *Client) RevokeCertificate(ctx context.Context, user, serial string) error {
	if strings.TrimSpace(user) == "" || strings.TrimSpace(serial) == "" {
		return errors.New("certificates API: no user or serial")
	}
	if ProtectedName(user) {
		return errProtected()
	}
	body := struct {
		User   string `json:"user"`
		Serial string `json:"serial"`
	}{user, serial}
	data, err := c.post(ctx, "certificates/revoke", body, http.StatusNoContent)
	clear(data)
	return err
}

// clip is s without control characters, cut to at most n characters
// (never inside a UTF-8 sequence).
func clip(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if count == n {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
