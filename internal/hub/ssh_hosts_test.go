package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/state"
)

// fakeFresh is a fresh-auth verifier that accepts every proof as user
// with method.
type fakeFresh struct{ method string }

func (f fakeFresh) Verify(_ context.Context, _ freshauth.Proof, user string) (*freshauth.Result, error) {
	return &freshauth.Result{User: user, Method: f.method, AuthTime: time.Now()}, nil
}
func (fakeFresh) Info() freshauth.AuthorizeInfo { return freshauth.AuthorizeInfo{} }

type hostFixture struct {
	*sshFixture
	key  ssh.Signer
	code *cliapi.EnrolCode
}

func newHostFixture(t *testing.T) *hostFixture {
	t.Helper()
	f := &hostFixture{sshFixture: newSSHFixture(t)}
	f.h.SetFreshAuth(ListenerHub, fakeFresh{method: "security_key"})
	f.h.SetFreshAuthReadyForTest(true)
	f.compile(t) // CA keys known
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.key, _ = ssh.NewSignerFromKey(priv)
	code, err := f.h.CreateHost(context.Background(), directory.Actor{User: "root"}, HostInput{ID: "web-2", Names: []string{"web-2.example.com"}, HostGroups: []string{"web"}, Managed: true}, freshauth.Proof{})
	if err != nil {
		t.Fatal(err)
	}
	f.code, err = cliapi.ParseEnrolCode(code)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *hostFixture) enrolRequest(t *testing.T, signer ssh.Signer, challenge string) cliapi.EnrolRequest {
	t.Helper()
	sig, err := sshsig.Sign(bytes.NewReader(cliapi.EnrolMessage("example.org", f.code.HostID, challenge)), signer, sshsig.HashSHA512, cliapi.NSHostEnrol)
	if err != nil {
		t.Fatal(err)
	}
	return cliapi.EnrolRequest{HostID: f.code.HostID, Secret: f.code.Secret, HostKey: cliapi.NormalAuthorizedKey(signer.PublicKey()),
		Proof: string(sshsig.Armor(sig)), SSHDVersion: "OpenSSH_9.6p1", Ceiling: cliapi.DefaultCeiling()}
}

func (f *hostFixture) enrol(t *testing.T) *cliapi.Bundle {
	t.Helper()
	ch, err := f.h.EnrolChallenge(f.code.HostID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.h.Enrol(context.Background(), f.enrolRequest(t, f.key, ch), "192.0.2.12")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnrolCodeSingleUse15Min(t *testing.T) {
	f := newHostFixture(t)
	if f.code.Domain != "example.org" || f.code.HostID != "web-2" || strings.Join(f.code.HostGroups, ",") != "all,web" ||
		!strings.HasPrefix(f.code.UserCAFP, "SHA256:") || !f.code.Expires.Equal(sshNow.Add(15*time.Minute)) {
		t.Errorf("code %+v", f.code)
	}
	if e := f.audit.lastOf("ssh.host.create"); strings.Contains(e.Detail, f.code.Secret) || e.Result != "ok" {
		t.Errorf("audit %+v", e)
	}
	if strings.Contains(f.h.sshHostForTest("web-2").EnrolHash, f.code.Secret) || f.h.sshHostForTest("web-2").EnrolHash != secretHash(f.code.Secret) {
		t.Error("the stored hash")
	}
	b := f.enrol(t)
	if b.HostID != "web-2" || b.Serial == 0 {
		t.Errorf("first bundle %+v", b)
	}
	// Used: a second enrolment with the same code is refused.
	if _, err := f.h.EnrolChallenge("web-2"); err == nil {
		t.Error("a challenge after the code was used")
	}
	// Expired: a new code 16 minutes later refuses.
	f2 := newHostFixture(t)
	f2.advance(16 * time.Minute)
	if _, err := f2.h.EnrolChallenge("web-2"); err == nil {
		t.Error("an expired code opened a challenge")
	}
}

func TestEnrolWrongSecret403(t *testing.T) {
	f := newHostFixture(t)
	ch, _ := f.h.EnrolChallenge("web-2")
	req := f.enrolRequest(t, f.key, ch)
	req.Secret = random32()
	_, err := f.h.Enrol(context.Background(), req, "192.0.2.12")
	if sshStatusOf(err) != 403 {
		t.Fatalf("%v", err)
	}
	e := f.audit.lastOf("ssh.host.enrol")
	if e.Result != "refused" || e.Error != "wrong secret" || strings.Contains(e.Detail, req.Secret) {
		t.Errorf("audit %+v", e)
	}
	// The code still works.
	if f.h.sshHostForTest("web-2").EnrolHash == "" {
		t.Error("a wrong secret used the code up")
	}
}

func TestEnrolProofOverChallenge(t *testing.T) {
	f := newHostFixture(t)
	ch, _ := f.h.EnrolChallenge("web-2")
	// A proof over a challenge the Hub never gave.
	if _, err := f.h.Enrol(context.Background(), f.enrolRequest(t, f.key, random32()), ""); sshStatusOf(err) != 403 {
		t.Errorf("foreign challenge: %v", err)
	}
	// A proof by another key than the posted one.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(priv)
	req := f.enrolRequest(t, other, ch)
	req.HostKey = cliapi.NormalAuthorizedKey(f.key.PublicKey())
	if _, err := f.h.Enrol(context.Background(), req, ""); sshStatusOf(err) != 403 {
		t.Errorf("another key's proof: %v", err)
	}
	// The good one, then the same challenge again.
	if _, err := f.h.Enrol(context.Background(), f.enrolRequest(t, f.key, ch), ""); err != nil {
		t.Fatal(err)
	}
	f.h.newEnrolCode("web-2")
	f.h.mu.RLock()
	f.code.Secret = "" // a new code's secret is unknown here: the challenge reuse is the point
	f.h.mu.RUnlock()
	if f.h.consumeChallenge("web-2", f.clock(), func(c string) bool { return c == ch }) {
		t.Error("a used challenge is still live")
	}
}

func TestEnrolPinsHostKey(t *testing.T) {
	f := newHostFixture(t)
	f.enrol(t)
	hst := f.h.sshHostForTest("web-2")
	if hst.HostKey != cliapi.NormalAuthorizedKey(f.key.PublicKey()) || hst.KeyFP != cliapi.Fingerprint(f.key.PublicKey()) || hst.EnrolHash != "" || hst.Ceiling == nil {
		t.Errorf("host %+v", hst)
	}
	if hst.HostCert == "" {
		t.Error("no host certificate at enrolment")
	}
	if e := f.audit.lastOf("ssh.host.enrol"); e.Result != "ok" || !strings.Contains(e.Detail, hst.KeyFP) {
		t.Errorf("audit %+v", e)
	}
	// RSA host keys are refused.
	f2 := newHostFixture(t)
	ch, _ := f2.h.EnrolChallenge("web-2")
	req := f2.enrolRequest(t, f2.key, ch)
	req.HostKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0"
	if _, err := f2.h.Enrol(context.Background(), req, ""); err == nil {
		t.Error("a non-ed25519 host key pinned")
	}
}

// signedReq is a host request signed by key.
func signedReq(t *testing.T, key ssh.Signer, id, method, target string, body []byte, tm time.Time, nonce string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	ts := tm.UTC().Format(time.RFC3339)
	sig, err := sshsig.Sign(bytes.NewReader(cliapi.HostRequestMessage(id, method, r.URL.Path, r.URL.RawQuery, ts, nonce, body)), key, sshsig.HashSHA512, cliapi.NSHostRequest)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(cliapi.HeaderHostID, id)
	r.Header.Set(cliapi.HeaderHostTime, ts)
	r.Header.Set(cliapi.HeaderHostNonce, nonce)
	r.Header.Set(cliapi.HeaderHostSignature, cliapi.EncodeSignatureHeader(sshsig.Armor(sig)))
	return r
}

func newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestHostRequestSignature(t *testing.T) {
	f := newHostFixture(t)
	f.enrol(t)
	body := []byte(`{"x":1}`)
	n := newNonce()
	r := signedReq(t, f.key, "web-2", "POST", "/api/cli/v1/hosts/report", body, f.clock(), n)
	if id, err := f.h.VerifyHostRequest(r, body); err != nil || id != "web-2" {
		t.Fatalf("good: %v", err)
	}
	if _, err := f.h.VerifyHostRequest(signedReq(t, f.key, "web-2", "POST", "/api/cli/v1/hosts/report", body, f.clock(), n), body); err == nil {
		t.Error("nonce replay accepted")
	}
	for name, r := range map[string]*http.Request{
		"+61 s": signedReq(t, f.key, "web-2", "POST", "/api/cli/v1/hosts/report", body, f.clock().Add(61*time.Second), newNonce()),
		"-61 s": signedReq(t, f.key, "web-2", "POST", "/api/cli/v1/hosts/report", body, f.clock().Add(-61*time.Second), newNonce()),
	} {
		if _, err := f.h.VerifyHostRequest(r, body); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := f.h.VerifyHostRequest(signedReq(t, f.key, "web-2", "POST", "/api/cli/v1/hosts/report", body, f.clock(), newNonce()), []byte(`{"x":2}`)); err == nil {
		t.Error("body hash mismatch accepted")
	}
	r = signedReq(t, f.key, "web-2", "GET", "/api/cli/v1/hosts/bundle?since=1", nil, f.clock(), newNonce())
	r.URL.RawQuery = "since=0"
	if _, err := f.h.VerifyHostRequest(r, nil); err == nil {
		t.Error("query change accepted")
	}
	// Unpinned host (web-1 in the fixture has a key, web-3 doesn't exist).
	_, err := f.h.VerifyHostRequest(signedReq(t, f.key, "web-3", "GET", "/api/cli/v1/hosts/bundle?since=0", nil, f.clock(), newNonce()), nil)
	if code, text := SSHErrorStatus(err); code != 403 || text != TextRemoved {
		t.Errorf("unknown host: %d %s", code, text)
	}
	// Another host's key.
	if _, err := f.h.VerifyHostRequest(signedReq(t, f.key, "web-1", "GET", "/api/cli/v1/hosts/bundle?since=0", nil, f.clock(), newNonce()), nil); err == nil {
		t.Error("web-2's key accepted for web-1")
	}
}

func TestBundleLongPollReturnsOnChange(t *testing.T) {
	f := newHostFixture(t)
	b := f.enrol(t)
	done := make(chan *cliapi.Bundle, 1)
	go func() {
		got, _ := f.h.HostBundle(context.Background(), "web-2", b.Serial)
		done <- got
	}()
	time.Sleep(50 * time.Millisecond)
	f.people.set(func(p *sshPeople) { p.users["carol"] = map[string]int{"ssh_web": 11} })
	f.compile(t)
	select {
	case got := <-done:
		if got == nil || got.Serial <= b.Serial {
			t.Fatalf("long-poll answer %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll didn't return on the change")
	}
	// since below the current serial: at once.
	got, err := f.h.HostBundle(context.Background(), "web-2", 0)
	if err != nil || got == nil {
		t.Errorf("since 0: %v", err)
	}
}

func TestBundleLongPoll204After55s(t *testing.T) {
	old := bundlePollMax
	bundlePollMax = 100 * time.Millisecond
	defer func() { bundlePollMax = old }()
	if old != 55*time.Second {
		t.Errorf("the hold is %s, want 55 s", old)
	}
	f := newHostFixture(t)
	b := f.enrol(t)
	got, err := f.h.HostBundle(context.Background(), "web-2", b.Serial)
	if err != nil || got != nil {
		t.Errorf("%+v %v, want 204", got, err)
	}
}

func TestBundleSizeCap4MiB(t *testing.T) {
	f := newHostFixture(t)
	f.enrol(t)
	// A revoked list of 5 MiB makes every bundle too large.
	var keys []string
	for i := 0; i < 60000; i++ {
		keys = append(keys, hostKey(t))
	}
	f.h.sshrev.mu.Lock()
	var list []RevokedKey
	for _, k := range keys {
		pk, _, _ := cliapi.ParseAuthorizedKey(k)
		list = append(list, RevokedKey{Key: k, FP: cliapi.Fingerprint(pk)})
	}
	f.h.saveRevokedLocked(list)
	f.h.sshrev.mu.Unlock()
	f.compile(t)
	_, err := f.h.HostBundle(context.Background(), "web-2", 0)
	if sshStatusOf(err) != 503 {
		t.Errorf("an oversized bundle served: %v", err)
	}
	if !f.h.sshhosts.oversize["web-2"] {
		t.Error("no doctor input")
	}
}

func TestRemoveHostUnpins(t *testing.T) {
	f := newHostFixture(t)
	f.enrol(t)
	if err := f.h.RemoveHost(context.Background(), directory.Actor{User: "root"}, "web-2", freshauth.Proof{}); err != nil {
		t.Fatal(err)
	}
	_, err := f.h.VerifyHostRequest(signedReq(t, f.key, "web-2", "GET", "/api/cli/v1/hosts/bundle?since=0", nil, f.clock(), newNonce()), nil)
	if code, text := SSHErrorStatus(err); code != 403 || text != TextRemoved {
		t.Errorf("%d %s", code, text)
	}
	f.compile(t)
	if _, ok := f.h.sshCompiled().Bundles["web-2"]; ok {
		t.Error("a removed host still compiled")
	}
	f.h.mu.RLock()
	got := revokedHostKeys(f.h.st.SSH.Clone())
	f.h.mu.RUnlock()
	if len(got) != 1 || got[0] != cliapi.NormalAuthorizedKey(f.key.PublicKey()) {
		t.Errorf("revoked host keys %v", got)
	}
	if f.audit.lastOf("ssh.host.remove").Result != "ok" {
		t.Error("not audited")
	}
}

func TestHostEndpointsOff503(t *testing.T) {
	f := newHostFixture(t)
	f.enrol(t)
	f.h.mu.Lock()
	f.h.st.SSH.Settings.Enabled = false
	f.h.mu.Unlock()
	check := func(name string, err error) {
		if code, text := SSHErrorStatus(err); code != 503 || text != TextHostsOff {
			t.Errorf("%s: %d %s", name, code, text)
		}
	}
	_, err := f.h.EnrolChallenge("web-2")
	check("challenge", err)
	_, err = f.h.Enrol(context.Background(), cliapi.EnrolRequest{HostID: "web-2"}, "")
	check("enrol", err)
	_, err = f.h.HostBundle(context.Background(), "web-2", 0)
	check("bundle", err)
	_, err = f.h.VerifyHostRequest(signedReq(t, f.key, "web-2", "GET", "/x", nil, f.clock(), newNonce()), nil)
	check("signed request", err)
	check("report", f.h.HostReport(context.Background(), "web-2", cliapi.Report{}))
}

func TestCreateHostNeedsFresh(t *testing.T) {
	f := newSSHFixture(t)
	f.compile(t)
	// No fresh-auth verifier: refused, nothing created.
	_, err := f.h.CreateHost(context.Background(), directory.Actor{User: "root"}, HostInput{ID: "db-1", Names: []string{"db-1.example.com"}, Managed: true}, freshauth.Proof{})
	if err == nil {
		t.Fatal("created without a fresh sign-in")
	}
	if _, ok := f.h.sshHostOKForTest("db-1"); ok {
		t.Error("host created anyway")
	}
	_ = state.SSHHost{}
}
