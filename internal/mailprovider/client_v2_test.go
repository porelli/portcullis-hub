package mailprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

const uuidA = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"

// answering is a provider that answers body (status 200) to every
// request with the bearer, and counts them.
func answering(t *testing.T, body *string, hits *atomic.Int32) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecret {
			w.WriteHeader(403)
			return
		}
		if hits != nil {
			hits.Add(1)
		}
		io.WriteString(w, *body)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, secretFile(t, testSecret))
}

// TestMailStateV2Vector: the shared vector decodes strictly into
// MailState and encodes back to the vector's bytes (compacted): no key
// missing, none extra, the same order.
func TestMailStateV2Vector(t *testing.T) {
	raw, err := os.ReadFile("testdata/mailstate_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var st MailState
	if err := strictDecode(raw, &st); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if st.Version != StateVersion || st.Relay == nil || st.Relay.Port != 465 || len(st.TLS.SPKISHA256) != 1 || st.Domains[1].DMARCFloor != "none" || st.ClientIP != ClientIPPreserved {
		t.Fatalf("decoded %+v", st)
	}
	if st.Senders == nil || len(*st.Senders) != 2 || (*st.Senders)[0].Username != "portcullis-hub-mail" || (*st.Senders)[1].Address != "portcullis-app-firefox-sync-fxa@example.com" {
		t.Fatalf("senders %+v", st.Senders)
	}
	back, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, want.Bytes()) {
		t.Fatalf("round trip differs:\n%s\n%s", want.Bytes(), back)
	}
}

// TestMailStateSendersShape (§19.5, §19.14): senders absent (nil), present
// and empty ([]), or a list; never null.
func TestMailStateSendersShape(t *testing.T) {
	enc := func(st MailState) string {
		b, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if s := enc(MailState{}); strings.Contains(s, `"senders"`) {
		t.Errorf("absent senders encoded: %s", s)
	}
	empty := []Sender{}
	if s := enc(MailState{Senders: &empty}); !strings.Contains(s, `"senders":[]`) || strings.Contains(s, "null,\"aliases") {
		t.Errorf("empty senders encoded: %s", s)
	}
	var st MailState
	if err := json.Unmarshal([]byte(`{"senders":[]}`), &st); err != nil || st.Senders == nil || len(*st.Senders) != 0 {
		t.Errorf("present and empty read as %+v (%v)", st.Senders, err)
	}
}

// TestCredentialRowsMustEchoUUID: a row of another account (or none)
// refuses the whole answer; nothing is returned.
func TestCredentialRowsMustEchoUUID(t *testing.T) {
	body := ""
	c := answering(t, &body, nil)
	for _, b := range []string{
		`[{"id":"1","uuid":"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d","label":"x","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null,"allowed_ips":[]}]`,
		`[{"id":"1","label":"x","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null,"allowed_ips":[]}]`,
		`[{"id":"1","uuid":"` + uuidA + `","label":"x","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null,"allowed_ips":[]},` +
			`{"id":"2","uuid":"3e5a7c9b-1d2f-4a6b-8c0e-2f4a6b8c0d1e","label":"y","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null,"allowed_ips":[]}]`,
	} {
		body = b
		if rows, err := c.Credentials(context.Background(), uuidA); err == nil || rows != nil {
			t.Errorf("%s: %+v %v", b, rows, err)
		}
	}
	if _, err := c.Credentials(context.Background(), "alice"); err == nil {
		t.Error("a username accepted as the uuid")
	}
	body = `[{"id":"a.b-1_2","uuid":"` + uuidA + `","label":"x","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null,"allowed_ips":["10.0.0.0/8","fd00::/8"]}]`
	rows, err := c.Credentials(context.Background(), uuidA)
	if err != nil || len(rows) != 1 || rows[0].UUID != uuidA || len(rows[0].AllowedIPs) != 2 || rows[0].AllowedIPs[1].String() != "fd00::/8" {
		t.Fatalf("%+v %v", rows, err)
	}
}

// TestCredentialAllowedIPsStrict: allowed_ips is a list of canonical
// prefixes: missing, null, a bare address, host bits, junk or an id out
// of shape refuse the answer; [] is anywhere.
func TestCredentialAllowedIPsStrict(t *testing.T) {
	body := ""
	c := answering(t, &body, nil)
	row := func(id, ips string) string {
		r := `{"id":"` + id + `","uuid":"` + uuidA + `","label":"x","created_at":"2026-11-15T09:00:00Z","expires_at":null,"last_used":null`
		if ips != "-" {
			r += `,"allowed_ips":` + ips
		}
		return "[" + r + "}]"
	}
	for _, b := range []string{row("1", "-"), row("1", "null"), row("1", `["10.0.0.1"]`), row("1", `["10.0.0.1/8"]`),
		row("1", `["x"]`), row("1", `[1]`), row("1", `"10.0.0.0/8"`), row("../1", `[]`), row("", `[]`), row(strings.Repeat("a", 65), `[]`)} {
		body = b
		if rows, err := c.Credentials(context.Background(), uuidA); err == nil {
			t.Errorf("%s accepted: %+v", b, rows)
		}
	}
	body = row("1", `[]`)
	if rows, err := c.Credentials(context.Background(), uuidA); err != nil || len(rows) != 1 || rows[0].AllowedIPs == nil || len(rows[0].AllowedIPs) != 0 {
		t.Fatalf("[]: %+v %v", rows, err)
	}
}

// TestUnknownCheckIDRefused: an id outside the catalog (and not x-…)
// refuses the whole answer; the catalog's scoped ids and x- ids pass.
func TestUnknownCheckIDRefused(t *testing.T) {
	body := ""
	c := answering(t, &body, nil)
	check := func(id string) string {
		return `{"checked_at":"2026-11-15T10:00:00Z","checks":[{"id":"cert","severity":"ok","detail":"","steps":[]},{"id":"` + id + `","severity":"warning","detail":"d","steps":[]}]}`
	}
	for _, id := range []string{"spam_rules", "external_lookups", "x-", "x-Upper", "x-" + strings.Repeat("a", 41), "records", "records:", "dkim_stuck:a b", "auth_failures:alice", "<script>"} {
		body = check(id)
		if ch, err := c.Checks(context.Background(), false); err == nil {
			t.Errorf("%q accepted: %+v", id, ch)
		}
	}
	for _, id := range []string{"port25", "fcrdns_v6", "tlsrpt_reports", "records:example.com", "dkim_selftest:team-b.example.org", "rate_held:alice", "x-spam_rules", "x-" + strings.Repeat("a", 40)} {
		body = check(id)
		if _, err := c.Checks(context.Background(), false); err != nil {
			t.Errorf("%q refused: %v", id, err)
		}
		if !ValidCheckID(id) {
			t.Errorf("ValidCheckID(%q) false", id)
		}
	}
	body = `{"checked_at":"2026-11-15T10:00:00Z","checks":[{"id":"cert","severity":"fatal","detail":"","steps":[]}]}`
	if _, err := c.Checks(context.Background(), false); err == nil {
		t.Error("an unknown severity accepted")
	}
	// GET /v1/provider lists the scoped ids by their prefix.
	body = `{"name":"P","version":"1","api_version":1,"checks":["dkim_stuck:","cert","x-a"],"actions":["test"],"export":false}`
	if p, err := c.Provider(context.Background()); err != nil || len(p.Checks) != 3 {
		t.Fatalf("provider: %+v %v", p, err)
	}
	body = `{"name":"P","version":"1","api_version":1,"checks":["spam_rules"],"actions":[],"export":false}`
	if _, err := c.Provider(context.Background()); err == nil {
		t.Error("provider with an unknown check id accepted")
	}
	body = `{"name":"P","version":"1","api_version":1,"checks":[],"actions":["reboot"],"export":false}`
	if _, err := c.Provider(context.Background()); err == nil {
		t.Error("provider with an unknown action accepted")
	}
	body = `{"name":"P","version":"1","api_version":2,"checks":[],"actions":[],"export":true}`
	if p, err := c.Provider(context.Background()); !errors.Is(err, ErrAPIVersion) || p.APIVersion != 2 {
		t.Errorf("api_version 2: %+v %v", p, err)
	}
	body = `{"name":"two\nlines","version":"1","api_version":1,"checks":[],"actions":[],"export":false}`
	if _, err := c.Provider(context.Background()); err == nil {
		t.Error("a two-line name accepted")
	}
}

// TestXCheckTextClipped: title (x- only, 80), detail (500), steps (10 ×
// 200) are clipped to plain one-line text; a catalog check loses any
// title, a non-fcrdns check any reason.
func TestXCheckTextClipped(t *testing.T) {
	steps := make([]string, 15)
	for i := range steps {
		steps[i] = strings.Repeat("s", 300)
	}
	sb, _ := json.Marshal(steps)
	body := `{"checked_at":"2026-11-15T10:00:00Z","checks":[` +
		`{"id":"x-spam_rules","severity":"problem","title":"` + strings.Repeat("t", 100) + `","detail":"<a href=x>` + strings.Repeat("d", 600) + `\n\u0007","steps":` + string(sb) + `},` +
		`{"id":"cert","severity":"ok","title":"sneaky","detail":"","steps":[],"reason":"missing"}]}`
	c := answering(t, &body, nil)
	ch, err := c.Checks(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	x := ch.Checks[0]
	if n := utf8.RuneCountInString(x.Title); n != 81 || !strings.HasSuffix(x.Title, "…") {
		t.Errorf("title %d runes", n)
	}
	if n := utf8.RuneCountInString(x.Detail); n != 501 || strings.ContainsAny(x.Detail, "\n\a") {
		t.Errorf("detail %d runes %q", n, x.Detail[len(x.Detail)-8:])
	}
	if len(x.Steps) != 10 || utf8.RuneCountInString(x.Steps[0]) != 201 {
		t.Errorf("steps %d × %d", len(x.Steps), utf8.RuneCountInString(x.Steps[0]))
	}
	if k := ch.Checks[1]; k.Title != "" || k.Reason != "" {
		t.Errorf("catalog check kept title %q reason %q", k.Title, k.Reason)
	}
}

// TestResponseSizeCapped: an answer over 4 MiB is refused.
func TestResponseSizeCapped(t *testing.T) {
	body := `{"generation":1,"applied_generation":1,"bootstrap":true,"errors":["` + strings.Repeat("e", 4<<20) + `"]}`
	c := answering(t, &body, nil)
	if _, err := c.State(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("%v", err)
	}
}

// TestTrailingBytesRefused: a second JSON value after the answer refuses
// it (and a duplicate-free, well-formed answer passes).
func TestTrailingBytesRefused(t *testing.T) {
	body := `{"generation":1,"applied_generation":1,"bootstrap":true,"errors":[]} {}`
	c := answering(t, &body, nil)
	if _, err := c.State(context.Background()); err == nil {
		t.Fatal("trailing data accepted")
	}
	body = `{"generation":1,"applied_generation":1,"bootstrap":true,"errors":[]}`
	if _, err := c.State(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestSecretReReadPerCall: the bearer is read at every call, so a new
// secret (a re-wiring) is used at once and a deleted one (an unwire)
// stops every request.
func TestSecretReReadPerCall(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		io.WriteString(w, `{"generation":1,"applied_generation":1,"bootstrap":true,"errors":[]}`)
	}))
	defer srv.Close()
	f := secretFile(t, testSecret)
	c := New(srv.URL, f)
	if _, err := c.State(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := strings.Repeat("Z", 48)
	if err := os.WriteFile(f, []byte(second), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.State(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if _, err := c.State(context.Background()); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("deleted secret: %v", err)
	}
	if len(seen) != 2 || seen[0] != "Bearer "+testSecret || seen[1] != "Bearer "+second {
		t.Fatalf("%q", seen)
	}
}

// TestNoSecretNoRequest: a missing, empty or short secret file sends
// nothing on any route, the new ones included.
func TestNoSecretNoRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	ctx := context.Background()
	for _, f := range []string{"", t.TempDir() + "/missing", secretFile(t, ""), secretFile(t, "short")} {
		c := New(srv.URL, f)
		for name, call := range map[string]func() error{
			"provider": func() error { _, err := c.Provider(ctx); return err },
			"void":     func() error { _, err := c.Void(ctx, VoidWire); return err },
			"reload":   func() error { _, err := c.TLSReload(ctx, []string{strings.Repeat("a", 64)}); return err },
			"test":     func() error { _, err := c.Test(ctx, "a@example.com"); return err },
			"creds":    func() error { _, err := c.Credentials(ctx, uuidA); return err },
			"revoke":   func() error { return c.RevokeCredential(ctx, uuidA, "1") },
		} {
			if err := call(); !errors.Is(err, ErrNoSecret) {
				t.Errorf("%q %s: %v", f, name, err)
			}
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests without a secret", hits.Load())
	}
}

// TestVoidAndTLSReloadShapes: the void, reload and test requests and
// answers as §19.5 says; wrong arguments are never sent, wrong answers
// refused.
func TestVoidAndTLSReloadShapes(t *testing.T) {
	var got []string
	answer := map[string]string{
		"/v1/void":         `{"voided":3,"restored_at":"2026-11-17T10:00:00Z"}`,
		"/v1/tls/reload":   `{"serving_spki_sha256":"99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"}`,
		"/v1/actions/test": `{"queue_id":"q-1"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b))
		io.WriteString(w, answer[r.URL.Path])
	}))
	defer srv.Close()
	c := New(srv.URL, secretFile(t, testSecret))
	ctx := context.Background()
	v, err := c.Void(ctx, VoidRestore)
	if err != nil || v.Voided != 3 || v.RestoredAt.IsZero() {
		t.Fatalf("void %+v %v", v, err)
	}
	spki := "99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"
	if s, err := c.TLSReload(ctx, []string{spki}); err != nil || s != spki {
		t.Fatalf("reload %q %v", s, err)
	}
	if q, err := c.Test(ctx, "a@example.org"); err != nil || q != "q-1" {
		t.Fatalf("test %q %v", q, err)
	}
	n := len(got)
	if _, err := c.Void(ctx, "because"); err == nil {
		t.Error("void reason accepted")
	}
	for _, bad := range [][]string{nil, {}, {"A" + spki[1:]}, {spki, spki, spki}, {"abc"}} {
		if _, err := c.TLSReload(ctx, bad); err == nil {
			t.Errorf("reload %q accepted", bad)
		}
	}
	if len(got) != n {
		t.Fatalf("bad arguments were sent: %q", got[n:])
	}
	want := []string{
		`POST /v1/void {"reason":"restore"}`,
		`POST /v1/tls/reload {"spki_sha256":["` + spki + `"]}`,
		`POST /v1/actions/test {"to":"a@example.org"}`,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d = %q, want %q", i, got[i], want[i])
		}
	}
	answer["/v1/void"] = `{"voided":-1,"restored_at":"2026-11-17T10:00:00Z"}`
	if _, err := c.Void(ctx, VoidWire); err == nil {
		t.Error("negative voided accepted")
	}
	answer["/v1/void"] = `{"voided":1}`
	if _, err := c.Void(ctx, VoidWire); err == nil {
		t.Error("void without restored_at accepted")
	}
	answer["/v1/tls/reload"] = `{"serving_spki_sha256":"nope"}`
	if _, err := c.TLSReload(ctx, []string{spki}); err == nil {
		t.Error("a malformed serving SPKI accepted")
	}
	answer["/v1/actions/test"] = `{"queue_id":""}`
	if _, err := c.Test(ctx, "a@example.org"); err == nil {
		t.Error("an empty queue id accepted")
	}
}
