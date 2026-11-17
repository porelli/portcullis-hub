package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// fakeCLIVerifier answers every proof with res (or err), once per code.
type fakeCLIVerifier struct {
	mu     sync.Mutex
	res    freshauth.Result
	err    error
	used   map[string]bool
	proofs int
}

func (v *fakeCLIVerifier) VerifyAnyUser(_ context.Context, p freshauth.Proof) (*freshauth.Result, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.proofs++
	if v.err != nil {
		return nil, v.err
	}
	if v.used == nil {
		v.used = map[string]bool{}
	}
	if v.used[p.Code] {
		return nil, &freshauth.Error{Reason: "code exchange refused: invalid_grant (expired, replayed or wrong verifier)"}
	}
	v.used[p.Code] = true
	r := v.res
	return &r, nil
}

type fakeKCUsers struct {
	disabled map[string]bool
	err      error
}

func (k fakeKCUsers) ListedUser(_ context.Context, u string) (*keycloak.UserStatus, error) {
	if k.err != nil {
		return nil, k.err
	}
	return &keycloak.UserStatus{Username: u, Enabled: !k.disabled[u]}, nil
}

type signFixture struct {
	*sshFixture
	v      *fakeCLIVerifier
	signer ssh.Signer
	codes  int
}

func newSignFixture(t *testing.T, user, method string) *signFixture {
	t.Helper()
	f := &signFixture{sshFixture: newSSHFixture(t), v: &fakeCLIVerifier{res: freshauth.Result{User: user, Method: method, AuthTime: sshNow}}}
	f.h.SetCLIVerifier(f.v)
	f.h.SetCLIClientReadyForTest(true)
	f.h.SetSSHKeycloak(fakeKCUsers{})
	f.compile(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.signer, _ = ssh.NewSignerFromKey(priv)
	return f
}

// request is a certificate request for signer with a valid key proof.
func (f *signFixture) request(t *testing.T, signer ssh.Signer, groups ...string) cliapi.CertRequest {
	t.Helper()
	f.codes++
	code := fmt.Sprintf("code-%d", f.codes)
	norm := cliapi.NormalAuthorizedKey(signer.PublicKey())
	sig, err := sshsig.Sign(bytes.NewReader(cliapi.KeyProofMessage("example.org", "nonce-1", code, norm)), signer, sshsig.HashSHA512, cliapi.NSKeyProof)
	if err != nil {
		t.Fatal(err)
	}
	if groups == nil {
		groups = []string{}
	}
	return cliapi.CertRequest{Code: code, CodeVerifier: strings.Repeat("v", 43), Nonce: "nonce-1", RedirectURI: "http://127.0.0.1:38917/callback",
		PublicKey: norm + " laptop", KeyProof: string(sshsig.Armor(sig)), HostGroups: groups}
}

func sshStatusOf(err error) int {
	s, _ := SSHErrorStatus(err)
	return s
}

func TestSignHappyPath(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if ans.User != "alice" || len(ans.Certificates) != 2 || len(ans.Refused) != 0 {
		t.Fatalf("answer %+v", ans)
	}
	all, web := ans.Certificates[0], ans.Certificates[1]
	if all.HostGroup != "all" || web.HostGroup != "web" || strings.Join(web.Principals, ",") != "u:alice@web" {
		t.Errorf("certificates %+v", ans.Certificates)
	}
	if strings.Join(web.Hosts, ",") != "web-1.example.com,192.0.2.11" || len(ans.HostCAs) != 1 {
		t.Errorf("hosts %v host CAs %v", web.Hosts, ans.HostCAs)
	}
	k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(web.Certificate))
	cert := k.(*ssh.Certificate)
	if _, _, req, ok := cliapi.ParseKeyID(cert.KeyId); !ok || !strings.HasPrefix(cert.KeyId, "pc:alice:web:") || len(req) != 16 {
		t.Errorf("key id %q", cert.KeyId)
	}
	if len(f.ssh.signs) != 2 || f.ssh.signs[1].Extensions[0] != "permit-pty" || f.ssh.signs[0].ValidSeconds != 4*3600 || f.ssh.signs[1].ValidSeconds != 8*3600 {
		t.Errorf("signs %+v", f.ssh.signs)
	}
}

func TestSignRefusesPasswordTotpBrowserCert(t *testing.T) {
	for _, m := range []string{"password", "totp", "browser_cert"} {
		f := newSignFixture(t, "alice", m)
		ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if len(ans.Certificates) != 0 || len(ans.Refused) != 2 {
			t.Errorf("%s: %+v", m, ans)
		}
		for _, r := range ans.Refused {
			if !strings.Contains(r.Reason, "sign in with --method") {
				t.Errorf("%s: reason %q", m, r.Reason)
			}
		}
		if len(f.ssh.signs) != 0 {
			t.Errorf("%s: enroll called", m)
		}
	}
}

func TestSignImpersonated403(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	f.v.res.Impersonated = true
	_, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if sshStatusOf(err) != 403 || err.Error() != TextImpersonated {
		t.Errorf("%v", err)
	}
}

func TestSignProtectedNames409(t *testing.T) {
	for _, u := range []string{"admin", "portcullis-hub", "portcullis-x"} {
		f := newSignFixture(t, u, "security_key")
		_, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
		if sshStatusOf(err) != 409 {
			t.Errorf("%s: %v", u, err)
		}
		if len(f.ssh.signs) != 0 {
			t.Errorf("%s: enroll called", u)
		}
	}
}

func TestSignDisabledKeycloakUser409(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	f.h.SetSSHKeycloak(fakeKCUsers{disabled: map[string]bool{"alice": true}})
	_, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if sshStatusOf(err) != 409 || err.Error() != TextDisabled {
		t.Errorf("%v", err)
	}
	f.h.SetSSHKeycloak(fakeKCUsers{err: errors.New("down")})
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50"); sshStatusOf(err) != 503 {
		t.Errorf("Keycloak down: %v", err)
	}
}

func TestSignNotInLLDAP409(t *testing.T) {
	f := newSignFixture(t, "zed", "security_key")
	_, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if sshStatusOf(err) != 409 || err.Error() != TextNotInDirectory {
		t.Errorf("%v", err)
	}
}

func TestSignKeyProofWrong403(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	req := f.request(t, f.signer)
	// The proof is for another code.
	other := f.request(t, f.signer)
	req.KeyProof = other.KeyProof
	_, err := f.h.SignSSH(context.Background(), req, "192.0.2.50")
	if sshStatusOf(err) != 403 || err.Error() != TextFreshRequired {
		t.Errorf("%v", err)
	}
	if e := f.audit.lastOf("ssh.certificate.issue"); e.Result != "refused" || e.Error != "key proof" || e.Actor != "alice" {
		t.Errorf("audit %+v", e)
	}
	// A proof by another key.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other2, _ := ssh.NewSignerFromKey(priv)
	req = f.request(t, f.signer)
	req.KeyProof = f.request(t, other2).KeyProof
	if _, err := f.h.SignSSH(context.Background(), req, "192.0.2.50"); sshStatusOf(err) != 403 {
		t.Errorf("another key's proof: %v", err)
	}
	// A SHA-256 proof (the namespace and hash are pinned).
	req = f.request(t, f.signer)
	sig, _ := sshsig.Sign(bytes.NewReader(cliapi.KeyProofMessage("example.org", req.Nonce, req.Code, cliapi.NormalAuthorizedKey(f.signer.PublicKey()))), f.signer, sshsig.HashSHA256, cliapi.NSKeyProof)
	req.KeyProof = string(sshsig.Armor(sig))
	if _, err := f.h.SignSSH(context.Background(), req, "192.0.2.50"); sshStatusOf(err) != 403 {
		t.Errorf("sha256 proof: %v", err)
	}
}

func TestSignKeyTypeRefused(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs, _ := ssh.NewSignerFromKey(rk)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ps, _ := ssh.NewSignerFromKey(p384)
	for name, s := range map[string]ssh.Signer{"rsa": rs, "p384": ps} {
		_, err := f.h.SignSSH(context.Background(), f.request(t, s), "192.0.2.50")
		if sshStatusOf(err) != 400 || err.Error() != TextKeyType {
			t.Errorf("%s: %v", name, err)
		}
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es, _ := ssh.NewSignerFromKey(p256)
	if _, err := f.h.SignSSH(context.Background(), f.request(t, es), "192.0.2.51"); err != nil {
		t.Errorf("p256: %v", err)
	}
}

func TestSignRevokedKeyRefused(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	if _, err := f.h.RevokeKeys("root", "lost laptop", []string{cliapi.NormalAuthorizedKey(f.signer.PublicKey())}, "alice"); err != nil {
		t.Fatal(err)
	}
	_, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if sshStatusOf(err) != 403 || err.Error() != TextKeyRevoked {
		t.Errorf("%v", err)
	}
}

func TestSignUnknownHostGroupListedNotRevealed(t *testing.T) {
	f := newSignFixture(t, "bob", "security_key")
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer, "web", "all", "db"), "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Certificates) != 1 || ans.Certificates[0].HostGroup != "web" {
		t.Errorf("certificates %+v", ans.Certificates)
	}
	if len(ans.Refused) != 2 || ans.Refused[0].Reason != TextNotAvailable || ans.Refused[1].Reason != TextNotAvailable {
		t.Errorf("refused %+v (all exists but isn't bob's: same text as db, which doesn't exist)", ans.Refused)
	}
}

func TestSignValidSecondsFromMerge(t *testing.T) {
	f := newSignFixture(t, "bob", "security_key")
	f.people.set(func(p *sshPeople) {
		p.pending = map[string]map[string]time.Time{"bob": {"ssh_deploy": sshNow.Add(20 * time.Minute)}}
	})
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ssh.signs) != 1 || f.ssh.signs[0].ValidSeconds != 20*60 {
		t.Errorf("valid seconds %+v", f.ssh.signs)
	}
	if !ans.Certificates[0].ValidBefore.Equal(sshNow.Add(20 * time.Minute)) {
		t.Errorf("valid before %v", ans.Certificates[0].ValidBefore)
	}
}

func TestSignRoleNotCurrentFailsClosed(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	f.ssh.mangle = func(hg string, r *cliapi.RoleSpec) { r.Principals = append(r.Principals, "u:mallory@web") }
	f.h.sshrt.mu.Lock()
	f.h.sshrt.roles = nil
	f.h.sshrt.mu.Unlock()
	_, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if sshStatusOf(err) != 503 {
		t.Errorf("%v", err)
	}
	if len(f.ssh.signs) != 0 {
		t.Error("signed with a role that isn't current")
	}
}

func TestSignTemplateUnmetListed(t *testing.T) {
	f := newSignFixture(t, "alice", "passkey_synced")
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Certificates) != 0 || len(ans.Refused) != 2 {
		t.Fatalf("%+v", ans)
	}
	for _, r := range ans.Refused {
		if !strings.HasPrefix(r.Reason, r.HostGroup+" needs ") || !strings.HasSuffix(r.Reason, ": sign in with --method passkey_device") && !strings.HasSuffix(r.Reason, ": sign in with --method security_key") {
			t.Errorf("reason %q", r.Reason)
		}
	}
	// A host group on the standard template accepts a synced passkey.
	f.h.mu.Lock()
	g := f.h.st.SSH.HostGroups["web"]
	g.Template = "standard"
	f.h.st.SSH.HostGroups["web"] = g
	f.h.mu.Unlock()
	ans, _ = f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if len(ans.Certificates) != 1 || ans.Certificates[0].HostGroup != "web" {
		t.Errorf("standard: %+v (%+v)", ans.Certificates, ans.Refused)
	}
	_ = signin.PasskeySynced
}

func TestSignLimits(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	f.v.err = &freshauth.Error{Reason: "nonce mismatch"}
	for i := 0; i < 10; i++ {
		if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.66"); sshStatusOf(err) != 403 {
			t.Fatalf("refusal %d: %v", i, err)
		}
	}
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.66"); sshStatusOf(err) != 429 {
		t.Errorf("11th refusal: %v", err)
	}
	// Another address still works.
	f.v.err = nil
	for i := 0; i < 6; i++ {
		if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), fmt.Sprintf("192.0.2.%d", 100+i)); err != nil {
			t.Fatalf("signing %d: %v", i, err)
		}
	}
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.120"); sshStatusOf(err) != 429 {
		t.Errorf("7th signing: %v", err)
	}
	f.advance(time.Minute)
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.121"); err != nil {
		t.Errorf("a minute later: %v", err)
	}
}

func TestSignAuditAndIssuedIndex(t *testing.T) {
	f := newSignFixture(t, "bob", "security_key")
	req := f.request(t, f.signer)
	if _, err := f.h.SignSSH(context.Background(), req, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	e := f.audit.lastOf("ssh.certificate.issue")
	fp := cliapi.Fingerprint(f.signer.PublicKey())
	for _, want := range []string{"web:", "principals=s:deploy@web,u:bob@web", "key=ssh-ed25519 " + fp, "serial=", "until=", "flow=loopback", "method=security_key", "addr=192.0.2.50"} {
		if !strings.Contains(e.Detail, want) {
			t.Errorf("audit detail %q lacks %q", e.Detail, want)
		}
	}
	if e.Actor != "bob" || e.Target != "bob" || e.Result != "ok" {
		t.Errorf("audit %+v", e)
	}
	st, err := os.Stat(f.h.issuedPath())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("issued.jsonl %v %v", st, err)
	}
	raw, _ := os.ReadFile(f.h.issuedPath())
	key := strings.Fields(req.PublicKey)[1]
	for _, secret := range []string{key, req.Code, req.CodeVerifier, "BEGIN SSH SIGNATURE"} {
		if strings.Contains(string(raw), secret) || strings.Contains(e.Detail, secret) {
			t.Errorf("%q leaked", secret[:10])
		}
	}
	recs := f.h.IssuedFor("bob")
	if len(recs) != 1 || recs[0].KeyFP != fp || recs[0].Flow != "loopback" || recs[0].Addr != "192.0.2.50" {
		t.Errorf("issued %+v", recs)
	}
}

func TestSign16Max(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	f.h.mu.Lock()
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("g%02d", i)
		f.h.st.SSH.HostGroups[id] = state.SSHHostGroup{}
		f.h.st.SSH.Grants = append(f.h.st.SSH.Grants, state.SSHGrant{ID: "x" + id, Group: "ssh_web", GroupID: 11, HostGroup: id, Accounts: []string{"{username}"}, Sudo: "none"})
	}
	f.h.mu.Unlock()
	f.compile(t)
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Certificates) != 16 || len(ans.Refused) != 6 || ans.Refused[5].Reason != TextTooManyCerts {
		t.Errorf("%d issued, refused %+v", len(ans.Certificates), ans.Refused)
	}
}

func TestRevokeOwnOnlyOwnKeys(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	bobKey := hostKey(t) // a key never issued to alice
	n, err := f.h.RevokeOwnSSH(context.Background(), cliapi.RevocationRequest{Code: "rv-1", CodeVerifier: strings.Repeat("v", 43), Nonce: "n", RedirectURI: "http://127.0.0.1:38917/callback",
		PublicKeys: []string{cliapi.NormalAuthorizedKey(f.signer.PublicKey()), bobKey}}, "192.0.2.50")
	if err != nil || n != 1 {
		t.Fatalf("revoked %d %v", n, err)
	}
	keys := f.h.RevokedKeys()
	if len(keys) != 1 || keys[0] != cliapi.NormalAuthorizedKey(f.signer.PublicKey()) {
		t.Errorf("revoked list %v", keys)
	}
	l, _ := f.h.sshRevokedList()
	if l[0].Until.IsZero() || !l[0].Until.After(sshNow.Add(8*time.Hour)) || l[0].Actor != "alice" {
		t.Errorf("entry %+v (until = last valid_before + 24 h)", l[0])
	}
}

func TestSignLogsNoSecret(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	f := newSignFixture(t, "alice", "security_key")
	f.ssh.signErr = errors.New("vault sealed")
	req := f.request(t, f.signer)
	if _, err := f.h.SignSSH(context.Background(), req, "192.0.2.50"); sshStatusOf(err) != http.StatusServiceUnavailable {
		t.Errorf("%v", err)
	}
	for _, s := range []string{strings.Fields(req.PublicKey)[1], req.Code, req.KeyProof[:40]} {
		if strings.Contains(buf.String(), s) {
			t.Errorf("log holds %q", s[:10])
		}
	}
}
