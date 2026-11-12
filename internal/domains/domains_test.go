package domains

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestClient(t *testing.T) {
	secret := strings.Repeat("k", 40)
	tok := "tok-SECRET/value+0123456789"
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		got = r.Method + " " + r.URL.EscapedPath()
		switch r.Method {
		case "PUT":
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"bad token tok-SECRET%2Fvalue%2B0123456789 / ` + tok + `"}`))
		case "GET":
			w.Write([]byte(`[{"name":"a.example.org","provider":"cloudflare","records_ok":true,"cert_not_after":"2099-01-01T00:00:00Z","last_error":"","state":"ready"}]`))
		case "DELETE":
			w.Write([]byte(`{"warning":"left a record"}`))
		}
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "s")
	os.WriteFile(f, []byte(secret+"\n"), 0600)
	c := New(srv.URL, f)
	list, err := c.List(context.Background())
	if err != nil || len(list) != 1 || !list[0].Assignable(list[0].CertNotAfter.AddDate(-1, 0, 0)) {
		t.Fatalf("List = %+v, %v", list, err)
	}
	_, err = c.Enroll(context.Background(), "a.example.org", "cloudflare", map[string]string{"api_token": tok})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("Enroll error %v", err)
	}
	if got != "PUT /domains/a.example.org" {
		t.Fatalf("request %s", got)
	}
	if w, err := c.Delete(context.Background(), "a.example.org"); err != nil || w != "left a record" {
		t.Fatalf("Delete = %q, %v", w, err)
	}
	srv.Close()
	if _, err := c.List(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("closed server: %v", err)
	}
	os.WriteFile(f, []byte("short"), 0600)
	if err := c.Available(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("short secret: %v", err)
	}
	if err := New(srv.URL, filepath.Join(t.TempDir(), "x")).Available(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing secret: %v", err)
	}
}

// TestRedactBeforeClip: a credential straddling the 500-byte clip of the
// service's message is redacted before clipping.
func TestRedactBeforeClip(t *testing.T) {
	secret := strings.Repeat("k", 40)
	tok := "tokSECRETvalue0123456789"
	for _, pad := range []int{480, 490, 495, 499} {
		msg := strings.Repeat("é", pad/2) + tok + " end"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"` + msg + `"}`))
		}))
		f := filepath.Join(t.TempDir(), "s")
		os.WriteFile(f, []byte(secret), 0600)
		_, err := New(srv.URL, f).Enroll(context.Background(), "a.example.org", "cloudflare", map[string]string{"api_token": tok})
		srv.Close()
		if err == nil || strings.Contains(err.Error(), tok[:4]) {
			t.Errorf("pad %d: %v", pad, err)
		}
		if !utf8.ValidString(err.Error()) {
			t.Errorf("pad %d: clipped inside a rune", pad)
		}
	}
}

// planFixture is a DNS plan as the domains service answers it (contract
// §12.2), every field set.
const planFixture = `{"name":"team-b.example.org","checked_at":"2026-11-13T09:12:44Z","can_write":true,
 "items":[{"set":"caa","name":"team-b.example.org","type":"CAA",
  "want":["0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01\""],
  "live":["0 issue \"digicert.com\""],"status":"missing","severity":"warning","fix":"auto","steps":["add CAA team-b.example.org"]}],
 "caa":{"issuer":"letsencrypt.org","account_uri":"https://acme-v02.api.letsencrypt.org/acme/acct/123","would_issue":true},
 "dnssec":{"state":"ds_missing","zone":"example.org","provider_can_sign":true,
  "ds":[{"key_tag":2371,"algorithm":13,"digest_type":2,"digest":"1F98AB"}],
  "steps":["Add this DS at your registrar: key tag 2371, algorithm 13, digest type 2, digest 1F98AB"]}}`

func planServer(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	secret := strings.Repeat("k", 40)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	f := filepath.Join(t.TempDir(), "s")
	os.WriteFile(f, []byte(secret), 0600)
	return New(srv.URL, f)
}

// TestPlanDecodes: the plan JSON round-trips every field; refresh=1 is
// passed through; the main domain's plan is GET /main/dns.
func TestPlanDecodes(t *testing.T) {
	var got []string
	c := planServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		w.Write([]byte(planFixture))
	})
	p, err := c.Plan(context.Background(), "team-b.example.org", true)
	if err != nil {
		t.Fatal(err)
	}
	want := Plan{Name: "team-b.example.org", CheckedAt: time.Date(2026, 11, 13, 9, 12, 44, 0, time.UTC), CanWrite: true,
		Items: []PlanItem{{Set: "caa", Name: "team-b.example.org", Type: "CAA",
			Want:   []string{`0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01"`},
			Live:   []string{`0 issue "digicert.com"`},
			Status: "missing", Severity: "warning", Fix: "auto", Steps: []string{"add CAA team-b.example.org"}}},
		CAA: PlanCAA{Issuer: "letsencrypt.org", AccountURI: "https://acme-v02.api.letsencrypt.org/acme/acct/123", WouldIssue: true},
		DNSSEC: PlanDNSSEC{State: "ds_missing", Zone: "example.org", ProviderCanSign: true,
			DS:    []DS{{KeyTag: 2371, Algorithm: 13, DigestType: 2, Digest: "1F98AB"}},
			Steps: []string{"Add this DS at your registrar: key tag 2371, algorithm 13, digest type 2, digest 1F98AB"}}}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("plan\n got %+v\nwant %+v", p, want)
	}
	// Round trip: the same JSON object back.
	b, _ := json.Marshal(p)
	var a, e any
	json.Unmarshal(b, &a)
	json.Unmarshal([]byte(planFixture), &e)
	if !reflect.DeepEqual(a, e) {
		t.Fatalf("round trip\n got %s", b)
	}
	if _, err := c.Plan(context.Background(), "team-b.example.org", false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MainPlan(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MainPlan(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if w := []string{"GET /domains/team-b.example.org/dns?refresh=1", "GET /domains/team-b.example.org/dns", "GET /main/dns?refresh=1", "GET /main/dns"}; !reflect.DeepEqual(got, w) {
		t.Fatalf("requests %q", got)
	}
}

// TestApplySetsBody: POST /domains/{name}/dns/apply {"sets": [...]}, the
// domain object back (with caa_ok and dnssec).
func TestApplySetsBody(t *testing.T) {
	var method, path, body string
	c := planServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		method, path, body = r.Method, r.URL.Path, string(b)
		w.WriteHeader(202)
		w.Write([]byte(`{"name":"team-b.example.org","provider":"cloudflare","records_ok":true,"cert_not_after":null,"last_error":"","state":"records","caa_ok":true,"dnssec":"unsigned"}`))
	})
	d, err := c.ApplySets(context.Background(), "team-b.example.org", []string{"caa", "nomail"})
	if err != nil || d.State != "records" || !d.CAAOK || d.DNSSEC != "unsigned" {
		t.Fatalf("ApplySets = %+v, %v", d, err)
	}
	if method != "POST" || path != "/domains/team-b.example.org/dns/apply" || body != `{"sets":["caa","nomail"]}` {
		t.Fatalf("request %s %s %s", method, path, body)
	}
}

// TestEnableDNSSEC409IsAPIError: the service's 409 "can't sign" is an
// APIError with its message; the body is exactly {"enable": true}.
func TestEnableDNSSEC409IsAPIError(t *testing.T) {
	var path, body string
	c := planServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		path, body = r.URL.Path, string(b)
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"porkbun can't sign the zone through its API"}`))
	})
	_, err := c.EnableDNSSEC(context.Background(), "team-b.example.org")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 409 || ae.Message != "porkbun can't sign the zone through its API" {
		t.Fatalf("EnableDNSSEC = %v", err)
	}
	if path != "/domains/team-b.example.org/dnssec" || body != `{"enable":true}` {
		t.Fatalf("request %s %s", path, body)
	}
}
