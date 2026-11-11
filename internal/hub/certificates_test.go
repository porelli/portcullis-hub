package hub

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// fakeCertActions is enroll's certificate actions.
type fakeCertActions struct {
	mu      sync.Mutex
	creates []invite.BrowserCertRequest
	renews  []string // user|presented|csr
	revokes []string // user/serial
	err     error
}

const testP12Password = "ABCDE-FGHJK-MNPQR-STVWX"

func (f *fakeCertActions) CreateBrowserCertificate(_ context.Context, r invite.BrowserCertRequest) (*invite.BrowserCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, r)
	if f.err != nil {
		return nil, f.err
	}
	return &invite.BrowserCert{P12: []byte("PKCS12-BYTES"), Password: testP12Password, Serial: "1a:2b:3c",
		Filename: r.User + "-browser-certificate-20261111.p12", NotAfter: time.Date(2026, 12, 11, 0, 0, 0, 0, time.UTC)}, nil
}

func (f *fakeCertActions) RenewYubiKeyCertificate(_ context.Context, user, presented, csr string) (*invite.IssuedCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renews = append(f.renews, user+"|"+presented+"|"+csr)
	if f.err != nil {
		return nil, f.err
	}
	return &invite.IssuedCert{PEM: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", Serial: "77:88", NotAfter: time.Date(2027, 11, 11, 0, 0, 0, 0, time.UTC)}, nil
}

func (f *fakeCertActions) RevokeCertificate(_ context.Context, user, serial string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = append(f.revokes, user+"/"+serial)
	return f.err
}

func (f *fakeCertActions) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.creates), len(f.renews), len(f.revokes)
}

// certFixture: alice (passkeys), ann an administrator, people on
// strong, browser_cert on, a people verifier whose pc_fresh is method
// (settable), enroll's actions faked.
type certFixture struct {
	f     *fixture
	audit *fakeAudit
	src   *fakeSignInSrc
	ca    *fakeCertActions
	fa    *methodFreshAuth
	ctx   context.Context
}

func newCertFixture(t *testing.T, certs ...invite.CertRecord) *certFixture {
	t.Helper()
	f, audit := signInFixture(t)
	ctx := context.Background()
	if _, err := f.h.SetMethod(ctx, signin.BrowserCert, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	p := newFakePeople("alice", "bob")
	p.addGroup(lldap.AdminGroup, "root", "ann")
	src := &fakeSignInSrc{keys: map[string][]signin.Method{"alice": {signin.SecurityKey}, "root": {signin.SecurityKey}, "ann": {signin.SecurityKey}}, certs: certs}
	wireSignIn(f.h, p, src)
	ca := &fakeCertActions{}
	f.h.SetCertActions(ca)
	fa := &methodFreshAuth{method: "security_key"}
	f.h.SetFreshAuth(ListenerPeople, fa)
	f.h.freshAuthReady.Store(true)
	f.h.cfg.CertExpiryWarnDays = 7
	return &certFixture{f: f, audit: audit, src: src, ca: ca, fa: fa, ctx: ctx}
}

// setPeopleRule makes the people core page use a template with rule.
func setPeopleRule(f *fixture, rule signin.Node) {
	setSignIn(f, func(si *state.SignIn) {
		si.Templates["custom-people"] = state.SignInTemplate{Name: "People rule", Rule: rule, Enabled: true}
		si.Core["people"] = "custom-people"
	})
}

func TestCertFreshAllowed(t *testing.T) {
	on := allOn()
	on[signin.BrowserCert] = true
	for _, c := range []struct {
		rule signin.Node
		want []signin.Method
	}{
		{siLeaves("any", "security_key", "yubikey_cert"), []signin.Method{signin.SecurityKey, signin.YubiKeyCert}},
		{siLeaves("any", "password"), nil},
		{siLeaves("any", "browser_cert", "security_key"), []signin.Method{signin.SecurityKey}},
		{siLeaves("any", "passkey_synced", "password"), []signin.Method{signin.PasskeySynced}},
	} {
		compiled, err := signin.Compile(c.rule, on)
		if err != nil {
			t.Fatal(err)
		}
		if got := certFreshAllowed(compiled, on); !slices.Equal(got, c.want) {
			t.Errorf("%v: %v, want %v", c.rule, got, c.want)
		}
	}
	if got := certFreshAllowed(signinNodeZero(), on); got != nil {
		t.Errorf("no rule: %v", got)
	}
}

func signinNodeZero() signin.Node { return signin.Node{} }

// TestCreateBrowserCertFreshRules (D26): people on strong — a
// security_key proof creates, passkey_synced and password are refused
// (403), browser_cert is refused even where people's template accepts
// it; people on any[password] is 409 before any proof is spent.
func TestCreateBrowserCertFreshRules(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	bc, err := h.CreateBrowserCertificate(c.ctx, "Alice", 30, testProof)
	if err != nil || bc.Serial != "1a:2b:3c" {
		t.Fatalf("security_key: %+v %v", bc, err)
	}
	bc.Clear()
	for _, m := range []string{"passkey_synced", "password"} {
		setSignIn(c.f, func(si *state.SignIn) { si.Methods["password"] = true })
		c.fa.method = m
		if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 30, testProof); statusOf(err) != 403 || err.Error() != freshauth.Message {
			t.Errorf("%s: %v", m, err)
		}
	}
	// people's template accepts browser_cert: still never for a new
	// certificate.
	setPeopleRule(c.f, siLeaves("any", "browser_cert", "security_key"))
	c.fa.method = "browser_cert"
	if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 30, testProof); statusOf(err) != 403 {
		t.Errorf("browser_cert: %v", err)
	}
	if e := c.audit.last(); e.Action != "cert.create" || e.Result != "refused" || !strings.Contains(e.Detail, "pc_fresh names browser_cert") {
		t.Errorf("browser_cert audit = %+v", e)
	}
	// any[password]: no method may approve it — 409 before the proof.
	setPeopleRule(c.f, siLeaves("any", "password"))
	calls := c.fa.calls.Load()
	if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 30, testProof); statusOf(err) != 409 ||
		err.Error() != "creating a certificate needs a passkey or YubiKey sign-in that people.example.org accepts" {
		t.Errorf("any[password]: %v", err)
	}
	if c.fa.calls.Load() != calls {
		t.Error("the proof was spent")
	}
	if n, _, _ := c.ca.counts(); n != 1 {
		t.Errorf("enroll called %d times, want 1", n)
	}
}

// TestCreateBrowserCertPassesLimits: days 0 or over the effective limit
// 400 before enroll; enroll gets days, MaxDays and MaxActive.
func TestCreateBrowserCertPassesLimits(t *testing.T) {
	c := newCertFixture(t)
	h := c.f.h
	setSignIn(c.f, func(si *state.SignIn) { si.Limits.BrowserCertDays, si.Limits.BrowserCertMaxActive = 20, 4 })
	for _, d := range []int{0, -1, 21} {
		if _, err := h.CreateBrowserCertificate(c.ctx, "alice", d, testProof); statusOf(err) != 400 {
			t.Errorf("days %d: %v", d, err)
		}
	}
	if n, _, _ := c.ca.counts(); n != 0 {
		t.Fatal("enroll called for refused days")
	}
	bc, err := h.CreateBrowserCertificate(c.ctx, "alice", 20, testProof)
	if err != nil {
		t.Fatal(err)
	}
	bc.Clear()
	if got := c.ca.creates[0]; got != (invite.BrowserCertRequest{User: "alice", Days: 20, MaxDays: 20, MaxActive: 4}) {
		t.Errorf("request = %+v", got)
	}
	// A stored lifetime above the ceiling applies as the ceiling (30 d).
	setSignIn(c.f, func(si *state.SignIn) { si.Limits.BrowserCertDays = 90 })
	if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 31, testProof); statusOf(err) != 400 {
		t.Errorf("over the ceiling: %v", err)
	}
	// enroll's 409 is passed through.
	c.ca.err = &invite.APIError{Status: 409, Message: "you already have 4 browser certificates, the most allowed: revoke one first"}
	if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 5, testProof); statusOf(err) != 409 || !strings.Contains(err.Error(), "already have 4") {
		t.Errorf("enroll 409: %v", err)
	}
	c.ca.err = &invite.APIError{Status: 500}
	if _, err := h.CreateBrowserCertificate(c.ctx, "alice", 5, testProof); statusOf(err) != 503 {
		t.Errorf("enroll 500: %v", err)
	}
}

func TestCreateBrowserCertOffRefused(t *testing.T) {
	c := newCertFixture(t)
	if _, err := c.f.h.SetMethod(c.ctx, signin.BrowserCert, false, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := c.f.h.CreateBrowserCertificate(c.ctx, "alice", 5, testProof); statusOf(err) != 409 || err.Error() != "browser certificates are off on this server" {
		t.Errorf("off: %v", err)
	}
	if n, _, _ := c.ca.counts(); n != 0 || c.fa.calls.Load() != 0 {
		t.Error("enroll or the verifier called while off")
	}
}

// TestCertAuditHasNoSecrets: cert.create's detail is "browser <serial>
// until <date>", never the password, the .p12 or a proof.
func TestCertAuditHasNoSecrets(t *testing.T) {
	c := newCertFixture(t)
	bc, err := c.f.h.CreateBrowserCertificate(c.ctx, "alice", 30, testProof)
	if err != nil {
		t.Fatal(err)
	}
	bc.Clear()
	e := c.audit.last()
	if e.Action != "cert.create" || e.Result != "ok" || e.Target != "alice" || e.Actor != "alice" || e.Detail != "browser 1a:2b:3c until 2026-12-11" {
		t.Errorf("audit = %+v", e)
	}
	for _, x := range auditAll(c.audit) {
		s := x.Detail + x.Error
		for _, secret := range []string{testP12Password, "PKCS12", "UEtDUzEy", testProof.Code, testProof.CodeVerifier, testProof.Nonce} {
			if strings.Contains(s, secret) {
				t.Errorf("audit %+v holds %q", x, secret)
			}
		}
	}
}

// TestRevokeOwnOnlyBrowser: the caller's own YubiKey certificate and
// another person's serial are 404 (enroll not called); the caller's own
// browser certificate is revoked through enroll and audited.
func TestRevokeOwnOnlyBrowser(t *testing.T) {
	later := time.Now().Add(100 * 24 * time.Hour)
	c := newCertFixture(t,
		invite.CertRecord{User: "alice", Serial: "0a:01", Kind: invite.KindYubiKey, NotAfter: later},
		invite.CertRecord{User: "alice", Serial: "0a:02", Kind: invite.KindBrowser, NotAfter: later},
		invite.CertRecord{User: "bob", Serial: "0b:01", Kind: invite.KindBrowser, NotAfter: later})
	h := c.f.h
	for _, s := range []string{"0a:01", "0b:01", "zz", "", "0a:03"} {
		if err := h.RevokeOwnBrowserCertificate(c.ctx, "alice", s); statusOf(err) != 404 {
			t.Errorf("serial %q: %v", s, err)
		}
	}
	if _, _, n := c.ca.counts(); n != 0 {
		t.Fatal("enroll called for a refused serial")
	}
	if err := h.RevokeOwnBrowserCertificateAs(c.ctx, directory.Actor{User: "Alice", Via: directory.ViaAI, Client: "portcullis-ai-claude"}, "0A02"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.ca.revokes, []string{"alice/0a:02"}) {
		t.Errorf("revokes %v", c.ca.revokes)
	}
	if e := c.audit.last(); e.Action != "cert.revoke" || e.Result != "ok" || e.Detail != "browser 0a:02" || e.Via != directory.ViaAI || e.Actor != "alice" {
		t.Errorf("audit = %+v", e)
	}
	c.src.set(func(s *fakeSignInSrc) { s.certErr = errors.New("enroll down") })
	if err := h.RevokeOwnBrowserCertificate(c.ctx, "alice", "0a:02"); statusOf(err) != 503 {
		t.Errorf("list down: %v", err)
	}
}

func traefikFixture(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	b, err := os.ReadFile("testdata/traefik-client-cert.txt")
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile("testdata/traefik-client-cert-leaf.pem")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(p)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b)), leaf
}

// TestPresentedCertPEM: Traefik's header (URL-escaped, leaf then CA) →
// the leaf's PEM; garbage → an error.
func TestPresentedCertPEM(t *testing.T) {
	hdr, leaf := traefikFixture(t)
	if !strings.Contains(hdr, ",") || !strings.Contains(hdr, "%2") {
		t.Fatal("the fixture isn't two URL-escaped entries")
	}
	got, err := presentedCertPEM(hdr)
	if err != nil {
		t.Fatal(err)
	}
	want := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	if got != want {
		t.Errorf("PEM = %q", got)
	}
	// Unescaped base64 (a literal '+') works too.
	first, _, _ := strings.Cut(hdr, ",")
	plain := strings.NewReplacer("%2B", "+", "%2F", "/", "%3D", "=").Replace(first)
	if got, err := presentedCertPEM(plain); err != nil || got != want {
		t.Errorf("unescaped: %v", err)
	}
	for _, bad := range []string{"", "garbage", "%zz", "QUJD", strings.Repeat("A", maxPresentedHeader+1), "-----BEGIN CERTIFICATE-----"} {
		if _, err := presentedCertPEM(bad); err == nil {
			t.Errorf("%.20q accepted", bad)
		}
	}
}

// TestRenewUsesPresentedCert (review I1): no header 403; the caller's
// own valid YubiKey leaf → enroll gets its real PEM; the same leaf as a
// browser certificate, someone else's or revoked → 403, enroll not
// called.
func TestRenewUsesPresentedCert(t *testing.T) {
	hdr, leaf := traefikFixture(t)
	serial := "3f:8a:1b:2c:4d:5e:6f:70:81:92:a3:b4:c5:d6:e7:f8:01:23:45:67"
	later := time.Now().Add(100 * 24 * time.Hour)
	for _, rec := range []invite.CertRecord{
		{User: "alice", Serial: serial, Kind: invite.KindBrowser, NotAfter: later},
		{User: "bob", Serial: serial, Kind: invite.KindYubiKey, NotAfter: later},
		{User: "alice", Serial: serial, Kind: invite.KindYubiKey, NotAfter: later, Revoked: true},
		{User: "alice", Serial: serial, Kind: invite.KindYubiKey, NotAfter: time.Now().Add(-time.Hour)},
	} {
		c := newCertFixture(t, rec)
		if _, err := c.f.h.RenewYubiKeyCertificate(c.ctx, "alice", hdr, "CSR"); statusOf(err) != 403 || err.Error() != "present your current YubiKey certificate" {
			t.Errorf("%+v: %v", rec, err)
		}
		if _, n, _ := c.ca.counts(); n != 0 {
			t.Errorf("%+v: enroll called", rec)
		}
	}
	c := newCertFixture(t, invite.CertRecord{User: "alice", Serial: serial, Kind: invite.KindYubiKey, NotAfter: later})
	for _, h := range []string{"", "garbage"} {
		if _, err := c.f.h.RenewYubiKeyCertificate(c.ctx, "alice", h, "CSR"); statusOf(err) != 403 {
			t.Errorf("header %q: %v", h, err)
		}
	}
	ic, err := c.f.h.RenewYubiKeyCertificate(c.ctx, "alice", hdr, "CSR")
	if err != nil || ic.Serial != "77:88" {
		t.Fatalf("renew: %+v %v", ic, err)
	}
	want := "alice|" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})) + "|CSR"
	if !slices.Equal(c.ca.renews, []string{want}) {
		t.Errorf("enroll got %q", c.ca.renews)
	}
	if e := c.audit.last(); e.Action != "cert.renew" || e.Result != "ok" || !strings.HasPrefix(e.Detail, "yubikey 3f8a1b2c") || strings.Contains(e.Detail, "CSR") {
		t.Errorf("audit = %+v", e)
	}
	// enroll's 403 is passed through.
	c.ca.err = &invite.APIError{Status: 403, Message: "only a YubiKey certificate renews"}
	if _, err := c.f.h.RenewYubiKeyCertificate(c.ctx, "alice", hdr, "CSR"); statusOf(err) != 403 || err.Error() != "only a YubiKey certificate renews" {
		t.Errorf("enroll 403: %v", err)
	}
}

// TestOwnCertificatesProtectedNames (D32, review I3): admin,
// portcullis-hub and portcullis-x get the server text (409) for create,
// renew and revoke, enroll never called; an lldap_admin member creates
// a browser certificate.
func TestOwnCertificatesProtectedNames(t *testing.T) {
	hdr, _ := traefikFixture(t)
	c := newCertFixture(t)
	h := c.f.h
	const text = "this account's certificates are managed from the server: ./portcullis cert revoke <serial>"
	for _, u := range []string{"admin", "portcullis-hub", "portcullis-x"} {
		_, err1 := h.CreateBrowserCertificate(c.ctx, u, 5, testProof)
		_, err2 := h.RenewYubiKeyCertificate(c.ctx, u, hdr, "CSR")
		err3 := h.RevokeOwnBrowserCertificate(c.ctx, u, "01")
		for i, err := range []error{err1, err2, err3} {
			if statusOf(err) != 409 || err.Error() != text {
				t.Errorf("%s action %d: %v", u, i, err)
			}
		}
	}
	if a, b, d := c.ca.counts(); a+b+d != 0 || c.fa.calls.Load() != 0 {
		t.Error("enroll or the verifier called for a protected account")
	}
	bc, err := h.CreateBrowserCertificate(c.ctx, "ann", 5, testProof)
	if err != nil {
		t.Fatalf("ann (an administrator): %v", err)
	}
	bc.Clear()
}

// TestExpiringFollowsWarnDays: core's grammar for
// HUB_CERT_EXPIRY_WARN_DAYS, and the status it gives.
func TestExpiringFollowsWarnDays(t *testing.T) {
	for v, want := range map[string]int{"10": 10, "0": 0, "abc": 7, "": 7, "-1": 7, " 5": 7, "5d": 7, "007": 7, "99999999999999999999999": maxWarnDays} {
		if got := ParseCertExpiryWarnDays(v); got != want {
			t.Errorf("%q → %d, want %d", v, got, want)
		}
	}
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	nine := now.Add(9 * 24 * time.Hour)
	if s := certStatus(false, nine, now, 10); s != CertExpiring {
		t.Errorf("10 days, 9 left: %s", s)
	}
	if s := certStatus(false, nine, now, 7); s != CertValid {
		t.Errorf("7 days, 9 left: %s", s)
	}
	if s := certStatus(false, now.Add(time.Hour), now, 0); s != CertValid {
		t.Errorf("0 days: %s", s)
	}
	if s := certStatus(true, nine, now, 7); s != CertRevoked {
		t.Errorf("revoked: %s", s)
	}
	if s := certStatus(false, now, now, 7); s != CertExpired {
		t.Errorf("expired: %s", s)
	}
}

func auditAll(a *fakeAudit) []directory.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.entries)
}
