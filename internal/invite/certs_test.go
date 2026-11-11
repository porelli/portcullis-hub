package invite

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEnroll is enroll's internal listener: it records each request and
// answers status with body.
type fakeEnroll struct {
	mu     sync.Mutex
	secret string
	status int
	body   string
	method string
	path   string
	auth   string
	ctype  string
	req    string
	calls  int
}

func newFakeEnroll(t *testing.T) (*fakeEnroll, *Client) {
	t.Helper()
	f := &fakeEnroll{secret: strings.Repeat("s", 40), status: 201}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		f.calls++
		f.method, f.path, f.auth, f.ctype, f.req = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(b)
		if f.auth != "Bearer "+f.secret {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(f.status)
		io.WriteString(w, f.body)
	}))
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(file, []byte(f.secret+"\n"), 0600)
	return f, New(srv.URL+"/internal/invites", file)
}

func (f *fakeEnroll) answer(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

// testCertPEM is a self-signed certificate (CN alice) as PEM.
func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "alice"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCreateBrowserCertificateShape(t *testing.T) {
	f, c := newFakeEnroll(t)
	p12 := []byte("\x30\x82not-really-a-p12\x00\xff")
	f.answer(201, fmt.Sprintf(`{"p12":%q,"password":"ABCDE-FGHJK-MNPQR-STVWX","serial":"1a:2b","not_after":"2026-12-11T00:00:00Z","filename":"alice-browser-certificate-20261111.p12"}`, base64.StdEncoding.EncodeToString(p12)))
	bc, err := c.CreateBrowserCertificate(context.Background(), BrowserCertRequest{User: "alice", Days: 30, MaxDays: 30, MaxActive: 3})
	if err != nil {
		t.Fatal(err)
	}
	if f.method != http.MethodPost || f.path != "/internal/browser-certificates" || f.ctype != "application/json" {
		t.Errorf("request %s %s (%s)", f.method, f.path, f.ctype)
	}
	if f.req != `{"user":"alice","days":30,"max_days":30,"max_active":3}` {
		t.Errorf("request body = %s", f.req)
	}
	if string(bc.P12) != string(p12) || bc.Password != "ABCDE-FGHJK-MNPQR-STVWX" || bc.Serial != "1a:2b" ||
		bc.Filename != "alice-browser-certificate-20261111.p12" || !bc.NotAfter.Equal(time.Date(2026, 12, 11, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("answer: serial %s, filename %s, not_after %s, p12 %d bytes", bc.Serial, bc.Filename, bc.NotAfter, len(bc.P12))
	}
	// String and every fmt verb never print the secrets.
	val := *bc
	type wrap struct{ C BrowserCert }
	for _, s := range []string{bc.String(), val.String(), val.GoString(), fmt.Sprint(bc), fmt.Sprint(val),
		fmt.Sprintf("%v %+v %#v %s %q %x %d", bc, bc, bc, bc, bc, bc, bc),
		fmt.Sprintf("%v %+v %#v %s %q %x %d", val, val, val, val, val, val, val),
		fmt.Sprintf("%v %+v %#v", []BrowserCert{val}, wrap{val}, &wrap{val})} {
		if strings.Contains(s, "ABCDE") || strings.Contains(s, "not-really") || strings.Contains(s, base64.StdEncoding.EncodeToString(p12)) {
			t.Errorf("secret printed: %s", s)
		}
	}
	if !strings.Contains(bc.String(), "1a:2b") {
		t.Errorf("String = %s", bc.String())
	}
	// Clear zeroes the .p12 in place.
	buf := bc.P12
	bc.Clear()
	if bc.P12 != nil || bc.Password != "" || strings.Trim(string(buf), "\x00") != "" {
		t.Errorf("Clear left %q / %q", buf, bc.Password)
	}
	// Protected names never reach enroll.
	calls := f.calls
	for _, u := range []string{"admin", "Portcullis-Hub", "portcullis-enroll"} {
		_, err := c.CreateBrowserCertificate(context.Background(), BrowserCertRequest{User: u, Days: 1, MaxDays: 30, MaxActive: 3})
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != 409 || ae.Message != "protected account" {
			t.Errorf("%s = %v", u, err)
		}
	}
	if f.calls != calls {
		t.Error("a protected name reached enroll")
	}
}

func TestYubiKeyCertificateActionsShape(t *testing.T) {
	f, c := newFakeEnroll(t)
	ctx := context.Background()
	crt := testCertPEM(t)
	f.answer(201, fmt.Sprintf(`{"certificate":%q,"serial":"0a:0b","not_after":"2027-11-11T00:00:00Z"}`, crt))
	ic, err := c.IssueYubiKeyCertificate(ctx, "alice", "CSR-PEM")
	if err != nil || ic.PEM != crt || ic.Serial != "0a:0b" || ic.NotAfter.Year() != 2027 {
		t.Fatalf("issue = %+v, %v", ic, err)
	}
	if f.path != "/internal/yubikey-certificates" || f.req != `{"user":"alice","csr":"CSR-PEM"}` {
		t.Errorf("issue request %s %s", f.path, f.req)
	}
	ic, err = c.RenewYubiKeyCertificate(ctx, "alice", "PRESENTED", "CSR-PEM")
	if err != nil || ic.Serial != "0a:0b" {
		t.Fatalf("renew = %+v, %v", ic, err)
	}
	if f.path != "/internal/yubikey-certificates/renew" || f.req != `{"user":"alice","presented":"PRESENTED","csr":"CSR-PEM"}` {
		t.Errorf("renew request %s %s", f.path, f.req)
	}
	f.answer(204, "")
	if err := c.RevokeCertificate(ctx, "alice", "0a:0b"); err != nil {
		t.Fatal(err)
	}
	if f.path != "/internal/certificates/revoke" || f.req != `{"user":"alice","serial":"0a:0b"}` || f.auth != "Bearer "+f.secret {
		t.Errorf("revoke request %s %s", f.path, f.req)
	}
	// A 201 that isn't one parsable certificate is refused.
	for _, bad := range []string{
		`{"certificate":"not pem","serial":"01","not_after":"2027-01-01T00:00:00Z"}`,
		fmt.Sprintf(`{"certificate":%q,"serial":"","not_after":"2027-01-01T00:00:00Z"}`, crt),
		fmt.Sprintf(`{"certificate":%q,"serial":"01"}`, crt),
		fmt.Sprintf(`{"certificate":%q,"serial":"01","not_after":"2027-01-01T00:00:00Z"}`, crt+crt),
		`{"certificate":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n","serial":"01","not_after":"2027-01-01T00:00:00Z"}`,
	} {
		f.answer(201, bad)
		if _, err := c.IssueYubiKeyCertificate(ctx, "alice", "CSR"); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// Revoke wants 204.
	f.answer(200, "{}")
	if err := c.RevokeCertificate(ctx, "alice", "01"); err == nil {
		t.Error("revoke accepted 200")
	}
	calls := f.calls
	if _, err := c.IssueYubiKeyCertificate(ctx, "admin", "CSR"); !isStatus(err, 409) {
		t.Errorf("issue admin = %v", err)
	}
	if _, err := c.RenewYubiKeyCertificate(ctx, "portcullis-x", "P", "CSR"); !isStatus(err, 409) {
		t.Errorf("renew portcullis-x = %v", err)
	}
	if err := c.RevokeCertificate(ctx, "PORTCULLIS-HUB", "01"); !isStatus(err, 409) {
		t.Errorf("revoke portcullis-hub = %v", err)
	}
	if f.calls != calls {
		t.Error("a protected name reached enroll")
	}
}

func isStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

// TestCertificateActionsPassStatus: 400/403/404/409 come back as
// APIError{Status, Message} with enroll's text (≤ 200 characters); any
// other failure is an error without enroll's text.
func TestCertificateActionsPassStatus(t *testing.T) {
	f, c := newFakeEnroll(t)
	ctx := context.Background()
	actions := map[string]func() error{
		"browser": func() error {
			_, err := c.CreateBrowserCertificate(ctx, BrowserCertRequest{User: "alice", Days: 31, MaxDays: 30, MaxActive: 3})
			return err
		},
		"issue":  func() error { _, err := c.IssueYubiKeyCertificate(ctx, "alice", "CSR"); return err },
		"renew":  func() error { _, err := c.RenewYubiKeyCertificate(ctx, "alice", "P", "CSR"); return err },
		"revoke": func() error { return c.RevokeCertificate(ctx, "alice", "01") },
	}
	for name, act := range actions {
		for _, st := range []int{400, 403, 404, 409} {
			f.answer(st, `{"error":"you already have 3 browser certificates, the most allowed: revoke one first"}`)
			var ae *APIError
			if err := act(); !errors.As(err, &ae) || ae.Status != st || ae.Message != "you already have 3 browser certificates, the most allowed: revoke one first" {
				t.Errorf("%s %d = %v", name, st, err)
			}
		}
		// Long and control-character texts are clipped to 200 characters.
		f.answer(409, `{"error":"`+strings.Repeat("é", 300)+`\n"}`)
		var ae *APIError
		if err := act(); !errors.As(err, &ae) || len([]rune(ae.Message)) != 200 || strings.ContainsRune(ae.Message, '\n') {
			t.Errorf("%s long = %q", name, ae.Message)
		}
		f.answer(503, `{"error":"vault sealed"}`)
		if err := act(); err == nil || !isStatus(err, 503) || strings.Contains(err.Error(), "vault sealed") {
			t.Errorf("%s 503 = %v", name, err)
		}
		f.answer(409, `not json`)
		if err := act(); !isStatus(err, 409) || err.(*APIError).Message != "" {
			t.Errorf("%s 409 not json = %v", name, err)
		}
		// Bodies over 1 MiB are refused.
		f.answer(409, `{"error":"`+strings.Repeat("a", maxActionBody)+`"}`)
		if err := act(); err == nil || isStatus(err, 409) {
			t.Errorf("%s huge = %v", name, err)
		}
	}
	// No secret: not configured, nothing sent.
	if _, err := New(c.APIURL, filepath.Join(t.TempDir(), "x")).IssueYubiKeyCertificate(ctx, "alice", "CSR"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no secret = %v", err)
	}
	// A request over enroll's 64 KiB limit isn't sent.
	calls := f.calls
	if _, err := c.IssueYubiKeyCertificate(ctx, "alice", strings.Repeat("x", maxActionRequest)); !isStatus(err, 413) || f.calls != calls {
		t.Errorf("huge request = %v", err)
	}
	// The request body never shows up in an error.
	f.answer(400, `{"error":"bad csr"}`)
	if _, err := c.IssueYubiKeyCertificate(ctx, "alice", "SECRET-CSR-TEXT"); err == nil || strings.Contains(err.Error(), "SECRET-CSR-TEXT") || strings.Contains(err.Error(), f.secret) {
		t.Errorf("error = %v", err)
	}
}

// TestBrowserCertNoSecretInErrors: a 201 that can't be used is an error
// that never quotes the answer (the .p12 and its password).
func TestBrowserCertNoSecretInErrors(t *testing.T) {
	f, c := newFakeEnroll(t)
	p12 := base64.StdEncoding.EncodeToString([]byte("P12-SECRET-BYTES"))
	pw := "PASSW-RDXXS-ECRET-TTTTT"
	good := map[string]any{"p12": p12, "password": pw, "serial": "1a", "not_after": "2026-12-11T00:00:00Z", "filename": "alice-browser-certificate-20261111.p12"}
	variant := func(k string, v any) string {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	for _, bad := range []string{
		`{"p12":"` + p12 + `","password":"` + pw + `"`, // truncated
		variant("p12", "!!not base64 "+pw),
		variant("p12", ""),
		variant("password", nil),
		variant("password", "passw-rdxxs-ecret-ttttt"),
		variant("password", "PASSWRDXXSECRETTTTTT"),
		variant("password", "OOOOO-RDXXS-ECRET-TTTTT"),
		variant("serial", nil),
		variant("not_after", "soon "+pw),
		variant("filename", "../"+pw+".p12"),
		variant("filename", "alice.exe"),
		variant("extra", pw),
		variant("password", 12345),
		`{"p12":"` + p12 + `","password":"` + pw + `","serial":"1a","not_after":"2026-12-11T00:00:00Z","filename":"a.p12"} {"x":1}`,
	} {
		f.answer(201, bad)
		bc, err := c.CreateBrowserCertificate(context.Background(), BrowserCertRequest{User: "alice", Days: 30, MaxDays: 30, MaxActive: 3})
		if err == nil {
			t.Errorf("accepted %s", bad)
			continue
		}
		if bc != nil {
			t.Errorf("a certificate with the error: %s", bad)
		}
		msg := fmt.Sprintf("%v %+v", err, err)
		for _, s := range []string{pw, p12, "P12-SECRET", "PASSW"} {
			if strings.Contains(msg, s) {
				t.Errorf("error quotes the answer: %s", msg)
			}
		}
	}
	// A non-2xx answer that echoes them: only the error field, and only
	// for the passed-on statuses.
	f.answer(500, `{"error":"`+pw+`","p12":"`+p12+`"}`)
	_, err := c.CreateBrowserCertificate(context.Background(), BrowserCertRequest{User: "alice", Days: 30, MaxDays: 30, MaxActive: 3})
	if err == nil || strings.Contains(err.Error(), pw) || strings.Contains(err.Error(), p12) {
		t.Errorf("500 = %v", err)
	}
}

// TestCertificateAnswersStrict: a 201 with anything after its one JSON
// value is refused.
func TestCertificateAnswersStrict(t *testing.T) {
	f, c := newFakeEnroll(t)
	ctx := context.Background()
	good := fmt.Sprintf(`{"p12":%q,"password":"ABCDE-FGHJK-MNPQR-STVWX","serial":"1a","not_after":"2026-12-11T00:00:00Z","filename":"alice-browser-certificate-20261111.p12"}`, base64.StdEncoding.EncodeToString([]byte("p12")))
	f.answer(201, good+"\n")
	if _, err := c.CreateBrowserCertificate(ctx, BrowserCertRequest{User: "alice", Days: 1, MaxDays: 30, MaxActive: 3}); err != nil {
		t.Fatalf("good answer: %v", err)
	}
	for _, tail := range []string{"}", "]", "{}", " 1", `"x"`, ","} {
		f.answer(201, good+tail)
		if _, err := c.CreateBrowserCertificate(ctx, BrowserCertRequest{User: "alice", Days: 1, MaxDays: 30, MaxActive: 3}); err == nil {
			t.Errorf("browser: accepted trailing %q", tail)
		}
	}
	crt := testCertPEM(t)
	issued := fmt.Sprintf(`{"certificate":%q,"serial":"0a","not_after":"2027-11-11T00:00:00Z"}`, crt)
	f.answer(201, issued)
	if _, err := c.IssueYubiKeyCertificate(ctx, "alice", "CSR"); err != nil {
		t.Fatalf("good issued: %v", err)
	}
	for _, tail := range []string{"}", "]", "{}", " null"} {
		f.answer(201, issued+tail)
		if _, err := c.IssueYubiKeyCertificate(ctx, "alice", "CSR"); err == nil {
			t.Errorf("issue: accepted trailing %q", tail)
		}
	}
}

// TestCertificateNoRedirect: a 3xx is never followed: the actions get an
// *APIError with that status, and the redirect target sees nothing.
func TestCertificateNoRedirect(t *testing.T) {
	hits := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(201)
	}))
	defer elsewhere.Close()
	_, c := newFakeEnroll(t) // for its secret file
	ctx := context.Background()
	for _, st := range []int{301, 302, 303, 307, 308} {
		redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, st)
		}))
		rc := New(redir.URL+"/internal/invites", c.SecretFile)
		if err := rc.RevokeCertificate(ctx, "alice", "01"); !isStatus(err, st) {
			t.Errorf("%d revoke = %v", st, err)
		}
		if _, err := rc.CreateBrowserCertificate(ctx, BrowserCertRequest{User: "alice", Days: 1, MaxDays: 30, MaxActive: 3}); !isStatus(err, st) {
			t.Errorf("%d browser = %v", st, err)
		}
		if _, err := rc.IssueYubiKeyCertificate(ctx, "alice", "CSR"); !isStatus(err, st) {
			t.Errorf("%d issue = %v", st, err)
		}
		if _, err := rc.Certificates(ctx); !isStatus(err, st) {
			t.Errorf("%d list = %v", st, err)
		}
		// A client built by hand (no CheckRedirect) doesn't follow either.
		hand := &Client{APIURL: rc.APIURL, SecretFile: rc.SecretFile, HTTP: &http.Client{Timeout: 5 * time.Second}}
		if err := hand.RevokeCertificate(ctx, "alice", "01"); !isStatus(err, st) {
			t.Errorf("%d hand-built revoke = %v", st, err)
		}
		redir.Close()
	}
	if hits != 0 {
		t.Errorf("redirect followed %d times", hits)
	}
}
