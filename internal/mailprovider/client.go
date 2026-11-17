package mailprovider

// The client of the wired mail provider's API v1 (contract §19.5): the
// Hub sends the desired mail state, reads the wanted DNS sets, the checks
// and the status, manages people's mail passwords, voids, reloads the
// certificate and sends test mail. The Hub holds only the bearer secret,
// which this package never logs, returns or puts in an error. Every
// answer is decoded strictly (unknown keys and trailing data refused,
// 4 MiB at most), every id shaped and every text clipped: a hostile
// provider can't feed the Hub anything else.

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
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// DefaultAPIURL is HUB_MAIL_API_URL's default for the stalwart block
// (contract §19.1: the alias mail-api on the block's api.port).
const DefaultAPIURL = "http://mail-api:8080"

// maxAnswer is the largest answer read (the API's body limit).
const maxAnswer = 4 << 20

// ErrNoSecret: the bearer secret file is missing, unreadable, empty or
// too short. The client then sends nothing (contract §19.5).
var ErrNoSecret = errors.New("mail provider: no API secret")

// ErrUnreachable wraps a failed connection.
var ErrUnreachable = errors.New("mail provider unreachable")

// ErrAPIVersion: GET /v1/provider names an api_version the Hub doesn't
// speak (contract §19.5: refused at wiring, doctor mail_provider_refused).
var ErrAPIVersion = errors.New("mail provider: the Hub speaks provider API version 1 only")

// APIError is a non-2xx answer. Msg is the provider's {"error"},
// redacted and clipped.
type APIError struct {
	Status int
	// Kind is the provider's error_kind ("mass_removal" for the
	// mass-removal 409; "" when absent): callers branch on it, never on
	// Msg.
	Kind string
	// Removed (the mass-removal 409): the live accounts the refused
	// document would remove.
	Removed []Removed
	Msg     string
}

// Removed is one account a refused mass removal would remove.
type Removed struct {
	Username string `json:"username"`
	UUID     string `json:"uuid"`
}

// Error kinds (APIError.Kind).
const (
	ErrorKindMassRemoval     = "mass_removal"
	ErrorKindAccountMismatch = "account_mismatch"
	ErrorKindGeneration      = "generation"
	ErrorKindLimit           = "limit"
)

func (e *APIError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("mail provider: HTTP %d: %s", e.Status, e.Msg)
	}
	return fmt.Sprintf("mail provider: HTTP %d", e.Status)
}

// StatusOf is err's HTTP status (0 when it isn't an APIError).
func StatusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// Client calls the provider API.
type Client struct {
	APIURL     string
	SecretFile string
	HTTP       *http.Client
}

// New returns a client for baseURL; secretFile holds the bearer (the
// wired instance's _mail/api-secret). Every call is bounded at 30 s.
func New(baseURL, secretFile string) *Client {
	return &Client{APIURL: strings.TrimSuffix(baseURL, "/"), SecretFile: secretFile, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// minSecret is the shortest bearer accepted (the Hub writes 48).
const minSecret = 32

// secret reads the bearer secret at each call (the Hub rewrites it on
// every wiring and deletes it on unwire).
func (c *Client) secret() (string, error) {
	if c == nil || c.SecretFile == "" {
		return "", ErrNoSecret
	}
	f, err := os.Open(c.SecretFile)
	if err != nil {
		return "", fmt.Errorf("%w: the secret file is unreadable", ErrNoSecret)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", fmt.Errorf("%w: the secret file is unreadable", ErrNoSecret)
	}
	s := strings.TrimSpace(string(b))
	if len(s) < minSecret {
		wipe(b)
		return "", fmt.Errorf("%w: the secret file holds fewer than %d characters", ErrNoSecret, minSecret)
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
	status, raw, err := c.fetch(ctx, method, path, body)
	defer wipe(raw)
	if err != nil || out == nil {
		return status, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return status, fmt.Errorf("mail provider: unexpected answer (HTTP %d)", status)
	}
	if dec.More() {
		return status, fmt.Errorf("mail provider: unexpected answer (HTTP %d): trailing data", status)
	}
	return status, nil
}

// wipe zeroes b's whole backing array.
func wipe(b []byte) {
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0
	}
}

// readOwned reads r (at most max bytes) into one buffer the caller owns:
// every buffer it outgrows is zeroed before it is dropped (an answer may
// hold a created password). Over max: an error, nothing kept.
func readOwned(r io.Reader, hint int64, max int) ([]byte, error) {
	size := 4096
	if hint > 0 && hint <= int64(max) {
		size = int(hint) + 1
	}
	buf := make([]byte, 0, size)
	for {
		if len(buf) == cap(buf) {
			if len(buf) > max {
				wipe(buf)
				return nil, fmt.Errorf("mail provider: answer larger than %d bytes", max)
			}
			n := make([]byte, len(buf), 2*cap(buf))
			copy(n, buf)
			wipe(buf)
			buf = n
		}
		k, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+k]
		if len(buf) > max {
			wipe(buf)
			return nil, fmt.Errorf("mail provider: answer larger than %d bytes", max)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			wipe(buf)
			return nil, err
		}
	}
}

// rawHook, if set, sees every answer buffer (tests: it is zeroed once
// the call returns).
var rawHook func([]byte)

// fetch sends one request and answers the status and the raw answer (a
// buffer the caller wipes); a non-2xx is an *APIError. The bearer
// secret never reaches an error.
func (c *Client) fetch(ctx context.Context, method, path string, body any) (int, []byte, error) {
	sec, err := c.secret()
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, errors.New("encoding the request failed")
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.APIURL+path, rd)
	if err != nil {
		return 0, nil, errors.New(redact(err.Error(), sec))
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w (%s)", ErrUnreachable, clip(redact(err.Error(), sec), 300))
	}
	defer resp.Body.Close()
	// net/http's transport keeps its own read buffer (an accepted
	// residual); the answer itself lives only in raw.
	raw, err := readOwned(resp.Body, resp.ContentLength, maxAnswer)
	if rawHook != nil && raw != nil {
		rawHook(raw)
	}
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%v (HTTP %d)", err, resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error   string    `json:"error"`
			Kind    string    `json:"error_kind"`
			Removed []Removed `json:"removed"`
		}
		_ = json.Unmarshal(raw, &e)
		if len(e.Removed) > 10000 || !removedShaped(e.Removed) {
			e.Removed = nil
		}
		if !kindRe.MatchString(e.Kind) {
			e.Kind = ""
		}
		// Redact first, then clip: clipping first could cut a secret so
		// that its prefix escapes redaction.
		return resp.StatusCode, raw, &APIError{Status: resp.StatusCode, Msg: clip(redact(e.Error, sec), 500), Kind: clip(e.Kind, 64), Removed: e.Removed}
	}
	return resp.StatusCode, raw, nil
}

// PutState sends a document; the answer is the generation the provider
// took.
func (c *Client) PutState(ctx context.Context, st *MailState) (int, error) {
	if st == nil {
		return 0, errors.New("mail provider: no state")
	}
	var out struct {
		Generation int `json:"generation"`
	}
	if _, err := c.do(ctx, http.MethodPut, "/v1/state", st, &out); err != nil {
		return 0, err
	}
	return out.Generation, nil
}

// State is the applied generation and whether the provider bootstrapped.
func (c *Client) State(ctx context.Context) (StateStatus, error) {
	var out StateStatus
	if _, err := c.do(ctx, http.MethodGet, "/v1/state", nil, &out); err != nil {
		return StateStatus{}, err
	}
	if len(out.Errors) > maxList {
		out.Errors = out.Errors[:maxList]
	}
	for i := range out.Errors {
		out.Errors[i] = clipText(out.Errors[i], 500)
	}
	return out, nil
}

// Provider is GET /v1/provider. An api_version other than 1 answers the
// decoded info with ErrAPIVersion.
func (c *Client) Provider(ctx context.Context) (ProviderInfo, error) {
	var out ProviderInfo
	if _, err := c.do(ctx, http.MethodGet, "/v1/provider", nil, &out); err != nil {
		return ProviderInfo{}, err
	}
	if !oneLine(out.Name, 64) || !oneLine(out.Version, 64) || out.Checks == nil || out.Actions == nil || len(out.Checks) > maxList {
		return ProviderInfo{}, errors.New("mail provider: unexpected answer: provider name, version, checks or actions")
	}
	for _, id := range out.Checks {
		if !validCheckListID(id) {
			return ProviderInfo{}, errors.New("mail provider: unexpected answer: an unknown check id")
		}
	}
	for _, a := range out.Actions {
		switch a {
		case ActionDKIMRotate, ActionDMARCPromote, ActionMTASTSEnforce, ActionTest:
		default:
			return ProviderInfo{}, errors.New("mail provider: unexpected answer: an unknown action")
		}
	}
	if out.APIVersion != APIVersion {
		return out, ErrAPIVersion
	}
	return out, nil
}

// DNS is domain's wanted mail set. wildcard: the domain's plan has a
// *.<domain> address record (false: the provider adds the CNAMEs for
// mta-sts, autoconfig and autodiscover). The set is not validated here
// (dnsrules, Task 11): only its shape.
func (c *Client) DNS(ctx context.Context, domain string, wildcard bool) (DNSSet, error) {
	var out DNSSet
	if _, err := c.do(ctx, http.MethodGet, "/v1/dns/"+url.PathEscape(domain)+"?wildcard="+strconv.FormatBool(wildcard), nil, &out); err != nil {
		return DNSSet{}, err
	}
	if !strings.EqualFold(out.Domain, domain) || (out.DKIM != "auto" && out.DKIM != "manual") || out.Records == nil || len(out.Records) > maxRecords {
		return DNSSet{}, errors.New("mail provider: unexpected answer: the dns set's domain, dkim or records")
	}
	return out, nil
}

// maxList caps the lists of an answer (checks, errors, steps' parent).
const maxList = 1000

// maxRecords caps a domain's set (the domains service's limit).
const maxRecords = 200

// Checks are the last check results (refresh: run them again). An id
// outside the catalog refuses the whole answer; texts are clipped
// (contract §19.8).
func (c *Client) Checks(ctx context.Context, refresh bool) (Checks, error) {
	p := "/v1/checks"
	if refresh {
		p += "?refresh=1"
	}
	var out Checks
	if _, err := c.do(ctx, http.MethodGet, p, nil, &out); err != nil {
		return Checks{}, err
	}
	if out.Checks == nil || len(out.Checks) > maxList {
		return Checks{}, errors.New("mail provider: unexpected answer: checks")
	}
	for i := range out.Checks {
		if err := shapeCheck(&out.Checks[i]); err != nil {
			return Checks{}, err
		}
	}
	return out, nil
}

// shapeCheck refuses an unknown id or severity and clips the texts.
func shapeCheck(k *Check) error {
	if !ValidCheckID(k.ID) {
		return errors.New("mail provider: unexpected answer: an unknown check id")
	}
	switch k.Severity {
	case SeverityOK, SeverityInfo, SeverityWarning, SeverityProblem:
	default:
		return errors.New("mail provider: unexpected answer: an unknown check severity")
	}
	if strings.HasPrefix(k.ID, "x-") {
		k.Title = clipText(k.Title, 80)
	} else {
		k.Title = ""
	}
	k.Detail = clipText(k.Detail, 500)
	if len(k.Steps) > 10 {
		k.Steps = k.Steps[:10]
	}
	for i := range k.Steps {
		k.Steps[i] = clipText(k.Steps[i], 200)
	}
	if k.Steps == nil {
		k.Steps = []string{}
	}
	if k.ID != "fcrdns_v4" && k.ID != "fcrdns_v6" || (k.Reason != ReasonPTRMissing && k.Reason != ReasonPTRMismatch) {
		k.Reason = ""
	}
	return nil
}

// catalogChecks are the neutral check ids (contract §19.8); catalogScoped
// take ":<domain>" or ":<username>".
var (
	catalogChecks = map[string]bool{"port25": true, "fcrdns_v4": true, "fcrdns_v6": true, "blocklist": true, "cert": true,
		"dane": true, "client_ip": true, "dmarc_reports": true, "tlsrpt_reports": true}
	catalogScoped = map[string]bool{"records": true, "dkim_selftest": true, "dkim_stuck": true, "dkim_manual": true, "rate_held": true}
	xCheckRe      = regexp.MustCompile(`^x-[a-z0-9_]{1,40}$`)
	scopeRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.@-]{0,252}$`)
	kindRe        = regexp.MustCompile(`^[a-z_]{0,64}$`)
	credIDRe      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	uuidRe        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	spkiRe        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	usernameRe    = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
)

// ValidCheckID: a catalog id (records:<d> and the other scoped ones with
// their domain or username) or x-[a-z0-9_]{1,40} (contract §19.8).
func ValidCheckID(id string) bool {
	if catalogChecks[id] || xCheckRe.MatchString(id) {
		return true
	}
	p, scope, ok := strings.Cut(id, ":")
	return ok && catalogScoped[p] && scopeRe.MatchString(strings.ToLower(scope))
}

// validCheckListID is ValidCheckID or a scoped id's bare prefix
// ("dkim_stuck:"), as GET /v1/provider lists them.
func validCheckListID(id string) bool {
	if p, ok := strings.CutSuffix(id, ":"); ok && catalogScoped[p] {
		return true
	}
	return ValidCheckID(id)
}

// oneLine: 1–n runes, no control character.
func oneLine(s string, n int) bool {
	if s == "" || utf8.RuneCountInString(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// clipText is s with control characters (newlines included) made spaces,
// invalid UTF-8 dropped and at most n runes (plain text only, §19.8).
func clipText(s string, n int) string {
	var b strings.Builder
	k := 0
	for _, r := range strings.ToValidUTF8(s, "") {
		if k == n {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
		k++
	}
	return b.String()
}

// removedShaped: every removed account has a username and a uuid.
func removedShaped(rs []Removed) bool {
	for _, r := range rs {
		if !usernameRe.MatchString(r.Username) || !uuidRe.MatchString(r.UUID) {
			return false
		}
	}
	return true
}

// Status is MailStatus.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	if _, err := c.do(ctx, http.MethodGet, "/v1/status", nil, &out); err != nil {
		return Status{}, err
	}
	out.Provider.Name = clipText(out.Provider.Name, 64)
	out.Provider.Version = clipText(out.Provider.Version, 64)
	if out.DNS != nil {
		// Domain names compare lowercase (the Hub's are).
		dns := make(map[string]string, len(out.DNS))
		for d, h := range out.DNS {
			dns[strings.ToLower(d)] = h
		}
		out.DNS = dns
	}
	return out, nil
}

// Credentials are the live mail passwords of the account with uuid
// (never a secret). Every row must echo that uuid, carry a shaped id and
// a valid allowed_ips list, else the whole answer is refused.
func (c *Client) Credentials(ctx context.Context, uuid string) ([]Credential, error) {
	if !uuidRe.MatchString(uuid) {
		return nil, errors.New("mail provider: not a uuid")
	}
	var out []Credential
	if _, err := c.do(ctx, http.MethodGet, "/v1/credentials?uuid="+url.QueryEscape(uuid), nil, &out); err != nil {
		return nil, err
	}
	if len(out) > maxList {
		return nil, errors.New("mail provider: unexpected answer: too many credentials")
	}
	for i := range out {
		r := &out[i]
		if r.UUID != uuid {
			return nil, errors.New("mail provider: unexpected answer: a credential of another account")
		}
		if !credIDRe.MatchString(r.ID) || r.CreatedAt.IsZero() {
			return nil, errors.New("mail provider: unexpected answer: a credential id or created_at")
		}
		if r.AllowedIPs == nil || len(r.AllowedIPs) > 256 {
			return nil, errors.New("mail provider: unexpected answer: allowed_ips")
		}
		for _, p := range r.AllowedIPs {
			if !p.IsValid() || p != p.Masked() {
				return nil, errors.New("mail provider: unexpected answer: allowed_ips")
			}
		}
		r.Label = clipText(r.Label, 64)
	}
	if out == nil {
		out = []Credential{}
	}
	return out, nil
}

// CreateCredential creates one mail password for user. The answer's
// Secret is the only copy of the password: the caller zeroes it.
// uuid is the person's LLDAP uuid: the provider refuses (409, error_kind
// account_mismatch) when the account under username has another one.
func (c *Client) CreateCredential(ctx context.Context, user, uuid, label string, expires *time.Time) (Created, error) {
	body := struct {
		Username  string     `json:"username"`
		UUID      string     `json:"uuid"`
		Label     string     `json:"label"`
		ExpiresAt *time.Time `json:"expires_at"`
	}{user, uuid, label, expires}
	status, raw, err := c.fetch(ctx, http.MethodPost, "/v1/credentials", body)
	defer wipe(raw)
	if err != nil {
		return Created{}, err
	}
	out, err := decodeCreated(raw)
	if err != nil {
		return Created{}, fmt.Errorf("mail provider: unexpected answer (HTTP %d): %v", status, err)
	}
	return out, nil
}

// anyValue skips a JSON value without copying it (the key check).
type anyValue struct{}

func (*anyValue) UnmarshalJSON([]byte) error { return nil }

// decodeCreated decodes POST /v1/credentials' answer strictly with
// json.Unmarshal (no decoder buffer: Secret.UnmarshalJSON reads a
// subslice of raw, so wiping raw wipes every encoded copy) and exactly
// the contract's keys. The password is bytes only.
func decodeCreated(raw []byte) (Created, error) {
	var keys map[string]*anyValue
	if err := json.Unmarshal(raw, &keys); err != nil {
		return Created{}, errors.New("not an object")
	}
	want := map[string]bool{"id": true, "secret": true, "created_at": true, "expires_at": true}
	if len(keys) != len(want) {
		return Created{}, errors.New("unexpected keys")
	}
	for k := range keys {
		if !want[k] {
			return Created{}, errors.New("unexpected keys")
		}
	}
	var out Created
	if err := json.Unmarshal(raw, &out); err != nil {
		out.Secret.Zero()
		return Created{}, errors.New("bad fields")
	}
	if !credIDRe.MatchString(out.ID) || len(out.Secret) == 0 {
		out.Secret.Zero()
		return Created{}, errors.New("no id or no password")
	}
	return out, nil
}

// RevokeCredential destroys mail password id of the account with uuid
// (parked accounts too; never resolved through a username). An unknown
// uuid or id is 204 too.
func (c *Client) RevokeCredential(ctx context.Context, uuid, id string) error {
	status, err := c.do(ctx, http.MethodDelete, "/v1/credentials/"+url.PathEscape(id)+"?uuid="+url.QueryEscape(uuid), nil, nil)
	if err == nil && status != http.StatusNoContent {
		// Only 204 is the provider's confirmation that the password is gone.
		return fmt.Errorf("mail provider: revoke answered HTTP %d, not 204", status)
	}
	return err
}

// Void destroys every credential of every account (POST /v1/void;
// reason wire or restore). The Hub verifies it afterwards (§19.11).
func (c *Client) Void(ctx context.Context, reason string) (VoidResult, error) {
	if reason != VoidWire && reason != VoidRestore {
		return VoidResult{}, fmt.Errorf("mail provider: void reason %q", reason)
	}
	var out VoidResult
	if _, err := c.do(ctx, http.MethodPost, "/v1/void", struct {
		Reason string `json:"reason"`
	}{reason}, &out); err != nil {
		return VoidResult{}, err
	}
	if out.Voided < 0 || out.RestoredAt.IsZero() {
		return VoidResult{}, errors.New("mail provider: unexpected answer: voided or restored_at")
	}
	return out, nil
}

// TLSReload asks the provider to read the certificate again; the answer
// is the SPKI it then serves (64 lowercase hex).
func (c *Client) TLSReload(ctx context.Context, spki []string) (string, error) {
	if len(spki) < 1 || len(spki) > 2 {
		return "", errors.New("mail provider: tls reload takes 1–2 SPKIs")
	}
	for _, k := range spki {
		if !spkiRe.MatchString(k) {
			return "", errors.New("mail provider: an SPKI isn't 64 lowercase hex")
		}
	}
	var out struct {
		Serving string `json:"serving_spki_sha256"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/v1/tls/reload", struct {
		SPKI []string `json:"spki_sha256"`
	}{spki}, &out); err != nil {
		return "", err
	}
	if !spkiRe.MatchString(out.Serving) {
		return "", errors.New("mail provider: unexpected answer: serving_spki_sha256")
	}
	return out.Serving, nil
}

// Test sends a test message to to (POST /v1/actions/test); the answer
// is the queue id.
func (c *Client) Test(ctx context.Context, to string) (string, error) {
	var out struct {
		QueueID string `json:"queue_id"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/v1/actions/test", struct {
		To string `json:"to"`
	}{to}, &out); err != nil {
		return "", err
	}
	if !oneLine(out.QueueID, 128) {
		return "", errors.New("mail provider: unexpected answer: queue_id")
	}
	return out.QueueID, nil
}

// Action runs one of the provider's domain actions.
func (c *Client) Action(ctx context.Context, name, domain string) error {
	switch name {
	case ActionDKIMRotate, ActionDMARCPromote, ActionMTASTSEnforce:
	default:
		return fmt.Errorf("mail provider: unknown action %q", name)
	}
	_, err := c.do(ctx, http.MethodPost, "/v1/actions/"+name, struct {
		Domain string `json:"domain"`
	}{domain}, nil)
	return err
}
