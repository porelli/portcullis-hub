package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
)

// signInCertActions is enroll's certificate actions for the routes.
type signInCertActions struct {
	mu      sync.Mutex
	revokes []string
}

const routeP12Password = "ABCDE-FGHJK-MNPQR-STVWX"

func (f *signInCertActions) CreateBrowserCertificate(_ context.Context, r invite.BrowserCertRequest) (*invite.BrowserCert, error) {
	return &invite.BrowserCert{P12: []byte("PKCS12-BYTES"), Password: routeP12Password, Serial: "1a:2b:3c",
		Filename: r.User + "-browser-certificate-20261111.p12", NotAfter: time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)}, nil
}

func (f *signInCertActions) RenewYubiKeyCertificate(context.Context, string, string, string) (*invite.IssuedCert, error) {
	return nil, &invite.APIError{Status: 403, Message: "no"}
}

func (f *signInCertActions) RevokeCertificate(_ context.Context, user, serial string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = append(f.revokes, user+"/"+serial)
	return nil
}

// signInEnv: the real tools and routes; alice with a security key and a
// browser certificate, browser_cert switched on, a people verifier
// (security_key), enroll faked.
func signInEnv(t *testing.T) (*toolEnv, *signInCertActions) {
	t.Helper()
	e := newToolEnv(t, nil, nil)
	e.ll.AddUser("alice", "alice@example.org", "Alice", "")
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	h := e.s.Hub
	h.SetPeople(e.s.Directory)
	later := time.Now().Add(60 * 24 * time.Hour)
	h.SetSignInSources(hub.SignInSources{
		Passkeys: func(context.Context) (map[string][]keycloak.PasskeyCredential, error) {
			return map[string][]keycloak.PasskeyCredential{"alice": {{ID: "k", Type: string(signin.SecurityKey), Label: "YubiKey 5C"}},
				"root": {{ID: "r", Type: string(signin.SecurityKey)}}}, nil
		},
		Certificates: func(context.Context) ([]invite.CertRecord, error) {
			return []invite.CertRecord{
				{User: "alice", Serial: "0a:02", Kind: invite.KindBrowser, NotBefore: time.Now().Add(-time.Hour), NotAfter: later},
				{User: "alice", Serial: "0a:01", Kind: invite.KindYubiKey, NotBefore: time.Now().Add(-time.Hour), NotAfter: later},
				{User: "bob", Serial: "0b:01", Kind: invite.KindBrowser, NotAfter: later},
			}, nil
		},
	})
	if _, err := h.SetMethod(context.Background(), signin.BrowserCert, true, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	h.SetFreshAuth(hub.ListenerPeople, &fakeFreshAuth{})
	h.SetFreshAuthReadyForTest(true)
	ca := &signInCertActions{}
	h.SetCertActions(ca)
	return e, ca
}

// TestCreateBrowserCertAnswerNoStore: 200 with no-store and no-cache;
// the body is {p12, password, filename, certificate}; the buffer is
// zeroed after the write; nothing of it reaches the audit.
func TestCreateBrowserCertAnswerNoStore(t *testing.T) {
	e, _ := signInEnv(t)
	var zeroed []byte
	orig := zeroBytes
	zeroBytes = func(b []byte) { orig(b); zeroed = b }
	t.Cleanup(func() { zeroBytes = orig })
	r, b := doAs(t, e.ppl, "Alice", "POST", "/api/me/signin/browser-certificates", `{"days":30,"code":"c","code_verifier":"v","nonce":"n"}`)
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("create = %d %v %s", r.StatusCode, r.Header, b)
	}
	var v struct {
		P12, Password, Filename string
		Certificate             hub.CertRow
	}
	dec := json.NewDecoder(strings.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if p12, _ := base64.StdEncoding.DecodeString(v.P12); string(p12) != "PKCS12-BYTES" || v.Password != routeP12Password ||
		v.Filename != "alice-browser-certificate-20261111.p12" || v.Certificate.Serial != "1a:2b:3c" || v.Certificate.Kind != "browser" || v.Certificate.Status != "valid" {
		t.Errorf("answer = %+v", v)
	}
	if len(zeroed) == 0 || strings.Trim(string(zeroed), "\x00") != "" {
		t.Error("the answer buffer wasn't zeroed")
	}
	for _, a := range readAudit(t, e.audit) {
		if strings.Contains(a.Detail+a.Error, routeP12Password) || strings.Contains(a.Detail+a.Error, v.P12) {
			t.Errorf("audit holds a secret: %+v", a)
		}
	}
	// Strict body: unknown fields 400, over 8 KiB 413.
	if r, _ := doAs(t, e.ppl, "alice", "POST", "/api/me/signin/browser-certificates", `{"days":1,"user":"bob"}`); r.StatusCode != 400 {
		t.Errorf("unknown field = %d", r.StatusCode)
	}
	if r, _ := doAs(t, e.ppl, "alice", "POST", "/api/me/signin/browser-certificates", `{"code":"`+strings.Repeat("a", 9<<10)+`"}`); r.StatusCode != 413 {
		t.Errorf("big body = %d", r.StatusCode)
	}
}

// TestMySignInRoutesCallerOnly: no X-Forwarded-User 401 on every route;
// no route takes a username; the Hub listener 404; the view is the
// caller's; revoke acts only on the caller's browser certificate.
func TestMySignInRoutesCallerOnly(t *testing.T) {
	e, ca := signInEnv(t)
	routes := [][3]string{
		{"GET", "/api/me/signin", ""}, {"GET", "/api/me/signin/history", ""},
		{"POST", "/api/me/signin/browser-certificates", `{}`}, {"DELETE", "/api/me/signin/certificates/0a:02", ""},
		{"POST", "/api/me/signin/yubikey-certificate/renew", `{"csr":"x"}`}, {"PUT", "/api/me/signin/password", `{}`},
		{"DELETE", "/api/me/signin/password", ""},
	}
	for _, rt := range routes {
		if r, _ := doAs(t, e.ppl, "", rt[0], rt[1], rt[2]); r.StatusCode != 401 {
			t.Errorf("no caller %s %s = %d", rt[0], rt[1], r.StatusCode)
		}
		if r, _ := doAs(t, e.hub, "root", rt[0], rt[1], rt[2]); r.StatusCode != 404 {
			t.Errorf("hub listener %s %s = %d", rt[0], rt[1], r.StatusCode)
		}
	}
	// Only the D25 routes under /api/me/signin, none taking a username.
	n := 0
	for _, p := range e.s.peopleMux().patterns {
		_, path, _ := strings.Cut(p, " ")
		if !strings.HasPrefix(path, "/api/me/signin") {
			continue
		}
		n++
		if strings.Contains(path, "{user") || !slices.Contains(peopleAppRoutes, p) {
			t.Errorf("route %s isn't a D25 route", p)
		}
	}
	if n != 7 {
		t.Errorf("%d routes under /api/me/signin, want the 7 of D25", n)
	}
	r, b := doAs(t, e.ppl, "ALICE", "GET", "/api/me/signin", "")
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" || !strings.Contains(b, `"user":"alice"`) || strings.Contains(b, "0b:01") ||
		!strings.Contains(b, "YubiKey 5C") {
		t.Errorf("view = %d %s", r.StatusCode, b)
	}
	// History: the cursor passed through; malformed 400; limit bounds.
	if r, b := doAs(t, e.ppl, "alice", "GET", "/api/me/signin/history?limit=5", ""); r.StatusCode != 200 || !strings.Contains(b, `"entries":`) {
		t.Errorf("history = %d %s", r.StatusCode, b)
	}
	for _, q := range []string{"?before=yesterday", "?limit=0", "?limit=101", "?limit=x", "?before=2026-11-01T00:00:00Z,bogus"} {
		if r, _ := doAs(t, e.ppl, "alice", "GET", "/api/me/signin/history"+q, ""); r.StatusCode != 400 {
			t.Errorf("history%s = %d", q, r.StatusCode)
		}
	}
	if r, _ := doAs(t, e.ppl, "alice", "GET", "/api/me/signin/history?before=2026-11-01T00:00:00Z", ""); r.StatusCode != 200 {
		t.Errorf("history with a cursor = %d", r.StatusCode)
	}
	// Revoke: bob's and alice's YubiKey serials 404; her own browser one 204.
	for _, s := range []string{"0b:01", "0a:01"} {
		if r, _ := doAs(t, e.ppl, "alice", "DELETE", "/api/me/signin/certificates/"+s, ""); r.StatusCode != 404 {
			t.Errorf("revoke %s = %d", s, r.StatusCode)
		}
	}
	if r, b := doAs(t, e.ppl, "alice", "DELETE", "/api/me/signin/certificates/0a:02", ""); r.StatusCode != 204 {
		t.Errorf("revoke own = %d %s", r.StatusCode, b)
	}
	if len(ca.revokes) != 1 || ca.revokes[0] != "alice/0a:02" {
		t.Errorf("revokes %v", ca.revokes)
	}
	// Renewal without a presented certificate: 403.
	if r, b := doAs(t, e.ppl, "alice", "POST", "/api/me/signin/yubikey-certificate/renew", `{"csr":"x"}`); r.StatusCode != 403 || !strings.Contains(b, "present your current YubiKey certificate") {
		t.Errorf("renew = %d %s", r.StatusCode, b)
	}
	// The page.
	if r, b := doAs(t, e.ppl, "alice", "GET", "/signin", ""); r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(b, "freshauth-callback.js") || r.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("page = %d %s", r.StatusCode, b)
	}
}
