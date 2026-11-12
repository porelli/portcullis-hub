package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
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
	mu       sync.Mutex
	revokes  []string
	issues   []string
	issueErr error
	// labels: the passkey renames signInEnv's PasskeyLabel source got.
	labels []string
}

// alicePasskeyID is alice's security key in signInEnv.
const alicePasskeyID = "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"

const routeP12Password = "ABCDE-FGHJK-MNPQR-STVWX"

func (f *signInCertActions) CreateBrowserCertificate(_ context.Context, r invite.BrowserCertRequest) (*invite.BrowserCert, error) {
	return &invite.BrowserCert{P12: []byte("PKCS12-BYTES"), Password: routeP12Password, Serial: "1a:2b:3c",
		Filename: r.User + "-browser-certificate-20261111.p12", NotAfter: time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)}, nil
}

func (f *signInCertActions) RenewYubiKeyCertificate(context.Context, string, string, string) (*invite.IssuedCert, error) {
	return &invite.IssuedCert{PEM: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", Serial: "77:88", NotAfter: time.Now().Add(365 * 24 * time.Hour)}, nil
}

func (f *signInCertActions) IssueYubiKeyCertificate(_ context.Context, user, csr string) (*invite.IssuedCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	f.issues = append(f.issues, user)
	return &invite.IssuedCert{PEM: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", Serial: "99:aa", NotAfter: time.Now().Add(365 * 24 * time.Hour)}, nil
}

// fixtureLeafSerial is the serial of ../hub/testdata/traefik-client-cert.txt's leaf.
const fixtureLeafSerial = "3f:8a:1b:2c:4d:5e:6f:70:81:92:a3:b4:c5:d6:e7:f8:01:23:45:67"

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
	ca := &signInCertActions{}
	h.SetSignInSources(hub.SignInSources{
		Passkeys: func(context.Context) (map[string][]keycloak.PasskeyCredential, error) {
			return map[string][]keycloak.PasskeyCredential{"alice": {{ID: alicePasskeyID, Type: string(signin.SecurityKey), Label: "YubiKey 5C"}},
				"root": {{ID: "r", Type: string(signin.SecurityKey)}}}, nil
		},
		PasskeyLabel: func(_ context.Context, user, id, label string) (string, error) {
			ca.mu.Lock()
			defer ca.mu.Unlock()
			ca.labels = append(ca.labels, user+" "+id+" "+label)
			if user != "alice" || id != alicePasskeyID {
				return "", keycloak.ErrPasskeyNotFound
			}
			return "YubiKey 5C", nil
		},
		Certificates: func(context.Context) ([]invite.CertRecord, error) {
			return []invite.CertRecord{
				{User: "alice", Serial: "0a:02", Kind: invite.KindBrowser, NotBefore: time.Now().Add(-time.Hour), NotAfter: later},
				{User: "alice", Serial: "0a:01", Kind: invite.KindYubiKey, NotBefore: time.Now().Add(-time.Hour), NotAfter: later},
				{User: "alice", Serial: fixtureLeafSerial, Kind: invite.KindYubiKey, NotBefore: time.Now().Add(-time.Hour), NotAfter: later},
				{User: "bob", Serial: "0b:01", Kind: invite.KindBrowser, NotAfter: later},
			}, nil
		},
	})
	if _, err := h.SetMethod(context.Background(), signin.BrowserCert, true, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	h.SetFreshAuth(hub.ListenerPeople, &fakeFreshAuth{})
	h.SetFreshAuthReadyForTest(true)
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
		{"DELETE", "/api/me/signin/password", ""}, {"PUT", "/api/me/signin/passkeys/" + alicePasskeyID + "/label", `{"label":"x"}`},
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
	if n != 8 {
		t.Errorf("%d routes under /api/me/signin, want the 8 of D25 (with polish 1's passkey rename)", n)
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
	// The presented certificate: one header renews; two are 403 (fix
	// round 1, m3).
	raw, err := os.ReadFile("../hub/testdata/traefik-client-cert.txt")
	if err != nil {
		t.Fatal(err)
	}
	hdr := strings.TrimSpace(string(raw))
	renew := func(values ...string) int {
		req, _ := http.NewRequest("POST", e.ppl.URL+"/api/me/signin/yubikey-certificate/renew", strings.NewReader(`{"csr":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(ProxySecretHeader, testSecret)
		req.Header.Set("X-Forwarded-User", "alice")
		for _, v := range values {
			req.Header.Add(presentedCertHeader, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := renew(hdr); c != 200 {
		t.Errorf("one header = %d", c)
	}
	if c := renew(hdr, hdr); c != 403 {
		t.Errorf("two headers = %d", c)
	}
	// The page.
	if r, b := doAs(t, e.ppl, "alice", "GET", "/signin", ""); r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(b, "freshauth-callback.js") || r.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("page = %d %s", r.StatusCode, b)
	}
}

// TestMySignInAccountURLAndCertFresh (Task 8 fix round 1): the view
// carries the account console's signing-in page (Config.AccountURL), the
// methods a fresh sign-in may use to create a certificate (D26) and the
// 409 text the page shows when none fits.
func TestMySignInAccountURLAndCertFresh(t *testing.T) {
	e, _ := signInEnv(t)
	r, b := doAs(t, e.ppl, "alice", "GET", "/api/me/signin", "")
	var v struct {
		AccountURL       string   `json:"account_url"`
		CertFresh        []string `json:"cert_fresh"`
		CertFreshRefusal string   `json:"cert_fresh_refusal"`
	}
	if r.StatusCode != 200 || json.Unmarshal([]byte(b), &v) != nil {
		t.Fatalf("view = %d %s", r.StatusCode, b)
	}
	if v.CertFresh == nil || slices.Contains(v.CertFresh, "password") || slices.Contains(v.CertFresh, "browser_cert") || !slices.Contains(v.CertFresh, "security_key") {
		t.Errorf("cert_fresh = %v", v.CertFresh)
	}
	if v.CertFreshRefusal != "creating a certificate needs a passkey or YubiKey sign-in that people.example.org accepts" {
		t.Errorf("cert_fresh_refusal = %q", v.CertFreshRefusal)
	}
	if v.AccountURL != "" {
		t.Errorf("account_url = %q without Config.AccountURL", v.AccountURL)
	}
}

// TestRenameOwnPasskeyRoute: PUT /api/me/signin/passkeys/{id}/label on
// the people listener only (204; strict body; 8 KiB), refused while
// impersonated (403, Keycloak not called, nothing audited ok).
func TestRenameOwnPasskeyRoute(t *testing.T) {
	e, ca := signInEnv(t)
	path := "/api/me/signin/passkeys/" + alicePasskeyID + "/label"
	if r, b := doAs(t, e.ppl, "Alice", "PUT", path, `{"label":"Office key"}`); r.StatusCode != 204 {
		t.Fatalf("rename = %d %s", r.StatusCode, b)
	}
	if strings.Join(ca.labels, ",") != "alice "+alicePasskeyID+" Office key" {
		t.Errorf("source calls = %v", ca.labels)
	}
	var ok []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "signin.passkey.label" && a.Result == "ok" {
			ok = append(ok, a)
		}
	}
	if len(ok) != 1 || ok[0].Detail != "YubiKey 5C → Office key" || ok[0].Actor != "alice" {
		t.Errorf("audit = %+v", ok)
	}
	if r, _ := doAs(t, e.ppl, "alice", "PUT", path, `{"label":"x","extra":1}`); r.StatusCode != 400 {
		t.Errorf("unknown field = %d", r.StatusCode)
	}
	if r, _ := doAs(t, e.ppl, "alice", "PUT", path, `{"label":"`+strings.Repeat("x", 9<<10)+`"}`); r.StatusCode != 413 {
		t.Errorf("9 KiB body = %d", r.StatusCode)
	}
	if r, b := doAs(t, e.ppl, "alice", "PUT", "/api/me/signin/passkeys/"+"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"+"/label", `{"label":"Mine now"}`); r.StatusCode != 404 || strings.TrimSpace(b) != "no such passkey" {
		t.Errorf("foreign id = %d %s", r.StatusCode, b)
	}
	if r, _ := doAs(t, e.hub, "alice", "PUT", path, `{"label":"Office key"}`); r.StatusCode != 404 {
		t.Errorf("hub listener = %d, want 404", r.StatusCode)
	}
	// Impersonated: 403 with the read-only text, Keycloak not called.
	before := len(ca.labels)
	req, _ := http.NewRequest("PUT", e.ppl.URL+path, strings.NewReader(`{"label":"Hijacked"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set(ImpersonationHeader, "imp-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || strings.TrimSpace(string(b)) != "not while you are signed in as someone else: Stop first" {
		t.Errorf("impersonated = %d %s", resp.StatusCode, b)
	}
	if len(ca.labels) != before {
		t.Error("an impersonated rename reached Keycloak")
	}
	// Impersonated by the token alone (an act claim, no header): 403 too.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice","act":{"sub":"root"}}`))
	treq, _ := http.NewRequest("PUT", e.ppl.URL+path, strings.NewReader(`{"label":"Hijacked"}`))
	treq.Header.Set("Content-Type", "application/json")
	treq.Header.Set(ProxySecretHeader, testSecret)
	treq.Header.Set("X-Forwarded-User", "alice")
	treq.Header.Set("X-Forwarded-Access-Token", "eyJhbGciOiJub25lIn0."+payload+".sig")
	tresp, err := http.DefaultClient.Do(treq)
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := io.ReadAll(tresp.Body)
	tresp.Body.Close()
	if tresp.StatusCode != 403 || strings.TrimSpace(string(tb)) != "not while you are signed in as someone else: Stop first" {
		t.Errorf("act-claim token = %d %s", tresp.StatusCode, tb)
	}
	// Cross-origin (another site's page posting the browser's cookies):
	// refused before the handler.
	creq, _ := http.NewRequest("PUT", e.ppl.URL+path, strings.NewReader(`{"label":"Hijacked"}`))
	creq.Header.Set("Content-Type", "application/json")
	creq.Header.Set(ProxySecretHeader, testSecret)
	creq.Header.Set("X-Forwarded-User", "alice")
	creq.Header.Set("Sec-Fetch-Site", "cross-site")
	creq.Header.Set("Origin", "https://evil.example")
	cresp, err := http.DefaultClient.Do(creq)
	if err != nil {
		t.Fatal(err)
	}
	cresp.Body.Close()
	if cresp.StatusCode != 403 {
		t.Errorf("cross-origin = %d, want 403", cresp.StatusCode)
	}
	if len(ca.labels) != before {
		t.Error("an impersonated or cross-origin rename reached Keycloak")
	}
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "signin.passkey.label" && a.Result == "ok" && strings.Contains(a.Detail, "Hijacked") {
			t.Errorf("an impersonated rename was audited ok: %+v", a)
		}
	}
}
