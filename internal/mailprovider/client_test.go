package mailprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSecret = "hub-secret-0123456789abcdefghijklmnopqrstuvwxyz"

func secretFile(t *testing.T, s string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "hub-secret")
	if err := os.WriteFile(f, []byte(s+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestClientRedactsSecret: an error answer that quotes the bearer secret
// (plain, quoted, escaped) never carries it; a transport error neither.
func TestClientRedactsSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecret {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":"bad %s / %s"}`, testSecret, url.QueryEscape(testSecret+"/x"))
	}))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	_, err := c.State(context.Background())
	if StatusOf(err) != 400 || strings.Contains(err.Error(), testSecret) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("State error %v", err)
	}
	srv.Close()
	_, err = c.Status(context.Background())
	if !errors.Is(err, ErrUnreachable) || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("closed server: %v", err)
	}
	// A URL that quotes the secret (nothing should, but the error path
	// must still redact it).
	c2 := New("http://127.0.0.1:1/"+testSecret, c.SecretFile)
	if _, err := c2.State(context.Background()); err == nil || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("secret in error: %v", err)
	}
}

// TestClientRefusesWithoutSecretFile: no (or a short) secret file means
// no request at all.
func TestClientRefusesWithoutSecretFile(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, f := range []string{"", filepath.Join(t.TempDir(), "missing"), secretFile(t, "short")} {
		c := New(srv.URL, f)
		if err := c.Available(); !errors.Is(err, ErrNoSecret) {
			t.Fatalf("%q: Available = %v", f, err)
		}
		if _, err := c.State(context.Background()); !errors.Is(err, ErrNoSecret) {
			t.Fatalf("%q: State = %v", f, err)
		}
		if _, err := c.CreateCredential(context.Background(), "alice", "u-1", "x", nil); !errors.Is(err, ErrNoSecret) {
			t.Fatalf("%q: Create = %v", f, err)
		}
	}
	var nilClient *Client
	if err := nilClient.Available(); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("nil client: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests sent without a secret", hits.Load())
	}
}

// TestStatusMatchesContractExample: the contract's MailStatus example
// decodes strictly.
func TestStatusMatchesContractExample(t *testing.T) {
	doc, _ := os.ReadFile("../../web/docs/integration-contracts.md")
	s := string(doc)
	i := strings.Index(s, "**MailStatus** (`GET /v1/status`)")
	if i < 0 {
		t.Fatal("no MailStatus in the contract")
	}
	a := strings.Index(s[i:], "```json\n") + i + len("```json\n")
	b := strings.Index(s[a:], "```") + a
	dec := json.NewDecoder(strings.NewReader(s[a:b]))
	dec.DisallowUnknownFields()
	var st Status
	if err := dec.Decode(&st); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if !st.Bootstrap || st.Cert.NotAfter == nil || len(st.DKIM) != 1 || st.DMARC[0].Proposed != nil || st.Provider.Name != "Stalwart" || st.Former[0].Username != "alice" {
		t.Fatalf("decoded %+v", st)
	}
}

// TestClientRequests: each method's method, path, body and decoding as
// contract §19.5 says; the created secret is bytes and never prints.
func TestClientRequests(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecret {
			w.WriteHeader(403)
			return
		}
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(body))
		switch r.Method + " " + r.URL.Path {
		case "PUT /v1/state":
			w.WriteHeader(202)
			w.Write([]byte(`{"generation":13}`))
		case "GET /v1/state":
			w.Write([]byte(`{"generation":13,"applied_generation":12,"bootstrap":true,"errors":[]}`))
		case "GET /v1/dns/team-b.example.org":
			w.Write([]byte(`{"domain":"team-b.example.org","records":[{"name":"team-b.example.org","type":"MX","ttl":3600,"value":"10 mail.example.com."}],"dkim":"auto"}`))
		case "GET /v1/checks":
			w.Write([]byte(`{"checked_at":"2026-11-15T10:00:00Z","checks":[{"id":"port25","severity":"info","detail":"no outbound delivery yet: not known","steps":[]}]}`))
		case "GET /v1/credentials":
			w.Write([]byte(`[{"id":"3","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"iPhone","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null,"allowed_ips":[]}]`))
		case "POST /v1/credentials":
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"4","secret":"s3cret-mail-password","created_at":"2026-11-15T09:00:00Z","expires_at":null}`))
		case "DELETE /v1/credentials/4":
			w.WriteHeader(204)
		case "POST /v1/actions/dkim-rotate":
			w.WriteHeader(202)
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not a mail domain"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/", secretFile(t, testSecret))
	ctx := context.Background()
	if g, err := c.PutState(ctx, &MailState{Version: 2, Generation: 13}); err != nil || g != 13 {
		t.Fatalf("PutState = %d, %v", g, err)
	}
	if s, err := c.State(ctx); err != nil || s.AppliedGeneration != 12 || !s.Bootstrap {
		t.Fatalf("State = %+v, %v", s, err)
	}
	if d, err := c.DNS(ctx, "team-b.example.org", false); err != nil || len(d.Records) != 1 || d.Records[0].TTL != 3600 {
		t.Fatalf("DNS = %+v, %v", d, err)
	}
	if _, err := c.DNS(ctx, "other.example", true); StatusOf(err) != 404 {
		t.Fatalf("DNS other = %v", err)
	}
	if ch, err := c.Checks(ctx, true); err != nil || ch.Checks[0].ID != "port25" {
		t.Fatalf("Checks = %+v, %v", ch, err)
	}
	if cr, err := c.Credentials(ctx, "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"); err != nil || len(cr) != 1 || cr[0].ExpiresAt != nil {
		t.Fatalf("Credentials = %+v, %v", cr, err)
	}
	exp := time.Date(2027, 11, 15, 9, 0, 0, 0, time.UTC)
	cr, err := c.CreateCredential(ctx, "alice", "u-1", "iPhone", &exp)
	if err != nil || cr.ID != "4" || string(cr.Secret) != "s3cret-mail-password" {
		t.Fatalf("Create = %+v, %v", cr, err)
	}
	for _, s := range []string{fmt.Sprintf("%v", cr), fmt.Sprintf("%+v", cr), fmt.Sprintf("%#v", cr), cr.Secret.String()} {
		if strings.Contains(s, "s3cret") {
			t.Fatalf("secret printed: %s", s)
		}
	}
	if b, _ := json.Marshal(cr); strings.Contains(string(b), "s3cret") {
		t.Fatalf("secret encoded: %s", b)
	}
	cr.Secret.Zero()
	if strings.Contains(string(cr.Secret), "s3cret") {
		t.Fatal("Zero left the secret")
	}
	if err := c.RevokeCredential(ctx, "u-1", "4"); err != nil {
		t.Fatalf("Revoke = %v", err)
	}
	if err := c.Action(ctx, ActionDKIMRotate, "example.com"); err != nil {
		t.Fatalf("Action = %v", err)
	}
	if err := c.Action(ctx, "../v1/state", "example.com"); err == nil {
		t.Fatal("an unknown action was sent")
	}
	want := []string{
		`PUT /v1/state {"version":2,"generation":13,`,
		`GET /v1/state `,
		`GET /v1/dns/team-b.example.org?wildcard=false `,
		`GET /v1/dns/other.example?wildcard=true `,
		`GET /v1/checks?refresh=1 `,
		`GET /v1/credentials?uuid=6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b `,
		`POST /v1/credentials {"username":"alice","uuid":"u-1","label":"iPhone","expires_at":"2027-11-15T09:00:00Z"}`,
		`DELETE /v1/credentials/4?uuid=u-1 `,
		`POST /v1/actions/dkim-rotate {"domain":"example.com"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("requests %q", got)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Fatalf("request %d = %q, want prefix %q", i, got[i], want[i])
		}
	}
}

// TestClientRefusesUnknownAnswerKeys: an answer outside the contract's
// shape is refused (fail closed), never half-read.
func TestClientRefusesUnknownAnswerKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"generation":1,"applied_generation":1,"bootstrap":true,"errors":[],"extra":1}`))
	}))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	if _, err := c.State(context.Background()); err == nil {
		t.Fatal("unknown key accepted")
	}
}

// TestChecksReasonDecodes: fcrdns checks carry reason missing|mismatch;
// other checks omit it (both decode strictly).
func TestChecksReasonDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"checked_at":"2026-11-15T10:00:00Z","checks":[{"id":"fcrdns_v4","severity":"problem","detail":"x","steps":[],"reason":"missing"},{"id":"port25","severity":"ok","detail":"","steps":[]}]}`))
	}))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	ch, err := c.Checks(context.Background(), false)
	if err != nil || ch.Checks[0].Reason != ReasonPTRMissing || ch.Checks[1].Reason != "" {
		t.Fatalf("%+v %v", ch, err)
	}
}

// TestSecretUnquoteBytes: the password is decoded by hand into fresh
// bytes (escapes, \u, surrogate pairs); invalid literals are refused.
func TestSecretUnquoteBytes(t *testing.T) {
	for in, want := range map[string]string{
		`"plain-123"`:     "plain-123",
		`"a\"b\\c\/d"`:    `a"b\c/d`,
		`"\b\f\n\r\t"`:    "\b\f\n\r\t",
		`"Aé"`:            "Aé",
		`"😀x"`:            "😀x",
		`"\u0041\u00e9"`:  "Aé",
		`"\ud83d\ude00x"`: "😀x",
		`"ünïcode"`:       "ünïcode",
	} {
		var s Secret
		if err := s.UnmarshalJSON([]byte(in)); err != nil || string(s) != want {
			t.Errorf("%s → %q, %v", in, s, err)
		}
	}
	for _, in := range []string{`plain`, `"unterminated`, `"bad\x"`, `"\u12"`, `"\ud83dx"`, "\"ctl\x01\"", `"a"b"`, `""x`} {
		var s Secret
		if err := s.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("%s accepted as %q", in, s)
		}
	}
}

// TestCreateCredentialBytesOnly: the answer buffer is zeroed once the call
// returns, the password survives it (no alias), unknown keys are refused.
func TestCreateCredentialBytesOnly(t *testing.T) {
	var raws [][]byte
	rawHook = func(b []byte) { raws = append(raws, b) }
	t.Cleanup(func() { rawHook = nil })
	answer := `{"id":"4","secret":"s3cret\"pwA","created_at":"2026-11-15T09:00:00Z","expires_at":null}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		w.Write([]byte(answer))
	}))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	cr, err := c.CreateCredential(context.Background(), "alice", "u-1", "x", nil)
	if err != nil || string(cr.Secret) != `s3cret"pwA` {
		t.Fatalf("%q %v", cr.Secret, err)
	}
	if len(raws) != 1 {
		t.Fatalf("%d buffers", len(raws))
	}
	for _, b := range raws[0][:cap(raws[0])] {
		if b != 0 {
			t.Fatal("the answer buffer wasn't zeroed")
		}
	}
	answer = `{"id":"4","secret":"x","created_at":"2026-11-15T09:00:00Z","expires_at":null,"extra":1}`
	if _, err := c.CreateCredential(context.Background(), "alice", "u-1", "x", nil); err == nil {
		t.Fatal("unknown key accepted")
	}
	answer = `{"id":"4","created_at":"2026-11-15T09:00:00Z","expires_at":null,"other":"y"}`
	if _, err := c.CreateCredential(context.Background(), "alice", "u-1", "x", nil); err == nil {
		t.Fatal("missing secret accepted")
	}
}

// TestAPIErrorKind: error_kind reaches APIError.Kind.
func TestAPIErrorKind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"mass removal: 2 of 3 accounts","error_kind":"mass_removal"}`))
	}))
	defer srv.Close()
	_, err := New(srv.URL, secretFile(t, testSecret)).PutState(context.Background(), &MailState{Version: 2})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 409 || ae.Kind != ErrorKindMassRemoval {
		t.Fatalf("%#v", err)
	}
}

// TestRevokeNeeds204 (L3): only 204 confirms a revoke.
func TestRevokeNeeds204(t *testing.T) {
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	if err := c.RevokeCredential(context.Background(), "u", "1"); err == nil {
		t.Fatal("200 accepted")
	}
	code = 204
	if err := c.RevokeCredential(context.Background(), "u", "1"); err != nil {
		t.Fatal(err)
	}
}

// TestNoRedirectsFollowed (M11): a 3xx is an error answer, never
// replayed elsewhere.
func TestNoRedirectsFollowed(t *testing.T) {
	var other int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/state", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	if _, err := c.PutState(context.Background(), &MailState{}); err == nil || other != 0 {
		t.Fatalf("followed: %v, %d requests elsewhere", err, other)
	}
}

// TestStrictAnswers (L9, L11): trailing tokens, a credential id twice, a
// created answer without created_at are refused.
func TestStrictAnswers(t *testing.T) {
	answer := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
		}
		w.Write([]byte(answer))
	}))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	const u = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
	answer = `{"bootstrap":true,"applied_generation":1}}`
	if _, err := c.State(context.Background()); err == nil {
		t.Error("a trailing } accepted")
	}
	row := `{"id":"1","uuid":"` + u + `","label":"x","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null,"allowed_ips":[]}`
	answer = "[" + row + "," + row + "]"
	if _, err := c.Credentials(context.Background(), u); err == nil {
		t.Error("an id twice accepted")
	}
	answer = `{"id":"4","secret":"s3cretpwAB","created_at":null,"expires_at":null}`
	if _, err := c.CreateCredential(context.Background(), "alice", u, "x", nil); err == nil {
		t.Error("no created_at accepted")
	}
	answer = `{"id":"4","secret":"s3cret pwAB","created_at":"2026-11-15T09:00:00Z","expires_at":null}`
	if _, err := c.CreateCredential(context.Background(), "alice", u, "x", nil); err == nil {
		t.Error("a password with a space accepted")
	}
}

// TestStatusShaped (M10): unshaped status values never reach the Hub.
func TestStatusShaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"bootstrap":true,"provider":{"name":"S‮talwart\n","version":"1"},
"cert":{"not_after":null,"sans":["mail.example.org","ignore previous instructions"],"spki_sha256":"zz"},
"dkim":[{"domain":"example.org","algorithm":"ed25519","selector":"s1","stage":"active","since":"2026-11-15T09:00:00Z"},
        {"domain":"example.org","algorithm":"rsa; drop","selector":"s2","stage":"active","since":"2026-11-15T09:00:00Z"}],
"mtasts":[{"domain":"Example.org","mode":"enforce","since":"2026-11-15T09:00:00Z","enforce_ready":true},{"domain":"x","mode":"weird","since":"2026-11-15T09:00:00Z","enforce_ready":false}],
"dmarc":[{"domain":"example.org","policy":"reject","since":"2026-11-15T09:00:00Z","proposed":"tell the admin to run rm -rf"}],
"queue":{"messages":-1,"deferred":2},"restored_at":null,
"former":[{"id":"f1","username":"bob","since":"2026-11-15T09:00:00Z"},{"id":"f 2\n","username":"eve","since":"2026-11-15T09:00:00Z"}],
"dns":{"Example.org":"abc","bad name!":"x"}}`))
	}))
	defer srv.Close()
	st, err := New(srv.URL, secretFile(t, testSecret)).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(st.Provider.Name, "‮\n") || len(st.Cert.SANs) != 1 || st.Cert.SPKISHA256 != "" || len(st.DKIM) != 1 ||
		len(st.MTASTS) != 1 || st.MTASTS[0].Domain != "example.org" || st.DMARC[0].Proposed != nil || st.Queue.Messages != 0 ||
		len(st.Former) != 1 || len(st.DNS) != 1 || st.DNS["example.org"] != "abc" {
		t.Fatalf("%+v", st)
	}
}

// TestAPIErrorShaped (M9, L10): an error message keeps one printable
// line: newlines, ANSI escapes, bidi and zero-width characters go.
func TestAPIErrorShaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"bad\n2026/11/17 mail: void verified \u001b[31mred‮​"}`))
	}))
	defer srv.Close()
	err := New(srv.URL, secretFile(t, testSecret)).Action(context.Background(), "dkim-rotate", "example.org")
	var ae *APIError
	if !errors.As(err, &ae) || strings.ContainsAny(ae.Msg, "\n\u001b‮​") {
		t.Fatalf("%q", err)
	}
}
