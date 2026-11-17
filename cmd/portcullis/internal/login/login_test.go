package login

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/loopback"
	"github.com/portcullis/hub/internal/cliapi"
)

type fakeHub struct {
	// principal overrides the certificate's principal (hostile answers).
	principal string
	t         *testing.T
	srv       *httptest.Server
	ca        ssh.Signer
	mu        sync.Mutex
	reqs      []cliapi.CertRequest
	status    int // != 0: answer this status to certificates
	refuse    bool
	proofOK   bool
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	_, ca, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(ca)
	f := &fakeHub{t: t, ca: s}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cli/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(cliapi.HeaderCLI) != cliapi.CLIHeaderValue("1.0.0") {
			t.Errorf("header %q", r.Header.Get(cliapi.HeaderCLI))
		}
		json.NewEncoder(w).Encode(cliapi.Config{API: 1, Domain: "example.org", Issuer: "https://auth.example.org/realms/portcullis",
			AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth", ClientID: "portcullis-cli", RedirectPorts: []int{38917, 38918, 38919}, MinCLI: ""})
	})
	mux.HandleFunc("/realms/portcullis/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		t.Error("the CLI called the token endpoint")
	})
	mux.HandleFunc("POST /api/cli/v1/ssh/certificates", f.certificates)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHub) certificates(w http.ResponseWriter, r *http.Request) {
	var req cliapi.CertRequest
	if err := cliapi.DecodeStrict(r.Body, cliapi.MaxCertRequest, &req); err != nil {
		f.t.Errorf("request: %v", err)
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	pub, norm, err := cliapi.ParseAuthorizedKey(req.PublicKey)
	if err != nil {
		f.t.Fatalf("key: %v", err)
	}
	sig, err := sshsig.Unarmor([]byte(req.KeyProof))
	f.proofOK = err == nil && sshsig.Verify(bytes.NewReader(cliapi.KeyProofMessage("example.org", req.Nonce, req.Code, norm)), sig, pub, sshsig.HashSHA512, cliapi.NSKeyProof) == nil
	if f.status != 0 {
		w.WriteHeader(f.status)
		fmt.Fprintf(w, `{"error":"a fresh sign-in is required"}`)
		return
	}
	ans := cliapi.CertAnswer{User: "alice", Certificates: []cliapi.IssuedCert{}, Refused: []cliapi.Refusal{}, HostCAs: []string{cliapi.NormalAuthorizedKey(f.ca.PublicKey())}, RevokedHostKeys: []string{}}
	if f.refuse {
		ans.Refused = append(ans.Refused, cliapi.Refusal{HostGroup: "web", Reason: "web needs a YubiKey touch: sign in with --method security_key"})
	} else {
		until := time.Now().Add(8 * time.Hour).Truncate(time.Second)
		pr := "u:alice@web"
		if f.principal != "" {
			pr = f.principal
		}
		c := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, KeyId: "pc:alice:web:0123456789abcdef", ValidPrincipals: []string{pr},
			ValidBefore: uint64(until.Unix()), Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
		c.SignCert(rand.Reader, f.ca)
		ans.Certificates = append(ans.Certificates, cliapi.IssuedCert{HostGroup: "web", Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))),
			Principals: []string{pr}, Serial: "1", ValidBefore: until, Hosts: []string{"web-1.example.org"}})
	}
	json.NewEncoder(w).Encode(ans)
}

func freePorts(t *testing.T) {
	t.Helper()
	old := loopback.Ports
	var ps []int
	for i := 0; i < 3; i++ {
		ln, _ := net.Listen("tcp4", "127.0.0.1:0")
		ps = append(ps, ln.Addr().(*net.TCPAddr).Port)
		ln.Close()
	}
	loopback.Ports = ps
	t.Cleanup(func() { loopback.Ports = old })
}

// browser plays Keycloak: checks the URL and sends the code back.
func browser(t *testing.T, seen *url.URL, code string) func(string) error {
	return func(u string) error {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		*seen = *p
		q := p.Query()
		go func() {
			time.Sleep(20 * time.Millisecond)
			resp, err := http.Get(q.Get("redirect_uri") + "?state=" + url.QueryEscape(q.Get("state")) + "&code=" + code)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

func opts(t *testing.T, f *fakeHub, ag agent.ExtendedAgent, seen *url.URL) Options {
	freePorts(t)
	var stderr bytes.Buffer
	return Options{Domain: "example.org", Version: "1.0.0", Home: t.TempDir(), ConfigDir: t.TempDir(), Stdout: io.Discard, Stderr: &stderr,
		PeopleURL: f.srv.URL, HTTP: f.srv.Client(), OpenBrowser: browser(t, seen, "the-code"), AllowAuthorizeHost: "auth.example.org",
		Agent: func() (agent.ExtendedAgent, func(), error) {
			if ag == nil {
				return nil, nil, errors.New("no agent")
			}
			return ag, func() {}, nil
		}}
}

func TestAuthorizeURLExact(t *testing.T) {
	cfg := &cliapi.Config{AuthorizeURL: "https://auth.example.org/realms/portcullis/protocol/openid-connect/auth"}
	u, _ := url.Parse(AuthorizeURL(cfg, "http://127.0.0.1:38917/callback", "S", "N", strings.Repeat("v", 43), ""))
	q := u.Query()
	want := map[string]string{"client_id": "portcullis-cli", "response_type": "code", "scope": "openid", "redirect_uri": "http://127.0.0.1:38917/callback",
		"state": "S", "nonce": "N", "code_challenge_method": "S256", "prompt": "login", "max_age": "0"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Get("code_challenge") == "" || q.Has("pc_method") || len(q) != len(want)+1 {
		t.Errorf("params %v", q)
	}
	u2, _ := url.Parse(AuthorizeURL(cfg, "http://127.0.0.1:38917/callback", "S", "N", strings.Repeat("v", 43), "security_key"))
	if u2.Query().Get("pc_method") != "security_key" {
		t.Error("pc_method")
	}
	// An unknown method is a usage error, before anything is bound.
	o := Options{Method: "magic", Domain: "example.org", Stderr: io.Discard}
	if _, err := DoSignIn(context.Background(), &o, cfg); api.ExitCode(err) != api.ExitUsage {
		t.Errorf("--method magic = %v", err)
	}
}

func TestLoginPostsProofNeverCallsTokenEndpoint(t *testing.T) {
	f := newFakeHub(t)
	kr := agent.NewKeyring().(agent.ExtendedAgent)
	var seen url.URL
	o := opts(t, f, kr, &seen)
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 1 {
		t.Fatalf("requests %d", len(f.reqs))
	}
	r := f.reqs[0]
	if r.Code != "the-code" || r.Nonce != seen.Query().Get("nonce") || r.RedirectURI != seen.Query().Get("redirect_uri") || len(r.CodeVerifier) < 43 || r.OwnKey {
		t.Errorf("request %+v", r)
	}
	if len(res.Answer.Certificates) != 1 {
		t.Errorf("answer %+v", res.Answer)
	}
	keys, _ := kr.List()
	if len(keys) != 1 || keys[0].Comment != "portcullis example.org web" {
		t.Errorf("agent %v", keys)
	}
	// Nothing secret printed.
	out := o.Stderr.(*bytes.Buffer).String()
	if strings.Contains(out, "the-code") || strings.Contains(out, r.CodeVerifier) {
		t.Errorf("stderr %s", out)
	}
}

func TestKeyProofVerifies(t *testing.T) {
	f := newFakeHub(t)
	var seen url.URL
	if _, err := Run(context.Background(), opts(t, f, agent.NewKeyring().(agent.ExtendedAgent), &seen)); err != nil {
		t.Fatal(err)
	}
	if !f.proofOK {
		t.Error("the Hub-side sshsig.Verify failed")
	}
}

func TestExitCodes(t *testing.T) {
	f := newFakeHub(t)
	var seen url.URL
	f.refuse = true
	_, err := Run(context.Background(), opts(t, f, agent.NewKeyring().(agent.ExtendedAgent), &seen))
	if api.ExitCode(err) != api.ExitNoCert {
		t.Errorf("all refused: %v (%d)", err, api.ExitCode(err))
	}
	f.refuse, f.status = false, 403
	if _, err := Run(context.Background(), opts(t, f, agent.NewKeyring().(agent.ExtendedAgent), &seen)); api.ExitCode(err) != api.ExitRefused {
		t.Errorf("403: %v", err)
	}
	f.status = 426
	if _, err := Run(context.Background(), opts(t, f, agent.NewKeyring().(agent.ExtendedAgent), &seen)); api.ExitCode(err) != api.ExitError {
		t.Errorf("426: %v", err)
	}
	o := opts(t, f, agent.NewKeyring().(agent.ExtendedAgent), &seen)
	o.PeopleURL = "https://127.0.0.1:1"
	if _, err := Run(context.Background(), o); api.ExitCode(err) != api.ExitUnreachable {
		t.Errorf("dial: %v", err)
	}
	o.Domain = "not a domain"
	if _, err := Run(context.Background(), o); api.ExitCode(err) != api.ExitUsage {
		t.Errorf("bad domain: %v", err)
	}
}

func TestKeyFlagSignsThroughAgent(t *testing.T) {
	f := newFakeHub(t)
	kr := agent.NewKeyring().(agent.ExtendedAgent)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "my fido stand-in"})
	pk, _ := ssh.NewPublicKey(pub)
	var seen url.URL
	o := opts(t, f, kr, &seen)
	o.KeyFile = filepath.Join(t.TempDir(), "id.pub")
	os.WriteFile(o.KeyFile, ssh.MarshalAuthorizedKey(pk), 0o644)
	if _, err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !f.proofOK || !f.reqs[0].OwnKey || f.reqs[0].PublicKey != cliapi.NormalAuthorizedKey(pk) {
		t.Errorf("proof %v request %+v", f.proofOK, f.reqs[0])
	}
	keys, _ := kr.List()
	if len(keys) != 1 {
		t.Errorf("the agent got a copy of the own key: %v", keys)
	}
	if _, err := os.Stat(filepath.Join(o.Home, ".ssh/portcullis/example.org/web-cert.pub")); err != nil {
		t.Error("no certificate file for --key")
	}
}

func TestNoAgentRefusesWithHint(t *testing.T) {
	f := newFakeHub(t)
	var seen url.URL
	_, err := Run(context.Background(), opts(t, f, nil, &seen))
	if err == nil || !strings.Contains(err.Error(), "no ssh-agent") && !strings.Contains(err.Error(), "no agent") {
		t.Errorf("err %v", err)
	}
	if len(f.reqs) != 0 {
		t.Error("signed in without an agent")
	}
}

func TestWriteFiles0600(t *testing.T) {
	f := newFakeHub(t)
	var seen url.URL
	o := opts(t, f, nil, &seen)
	o.WriteFiles = true
	if _, err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(o.Home, ".ssh/portcullis/example.org/id"))
	// Windows has no mode bits: the file is private through the user
	// profile's ACL (os.Stat reports 0666 there).
	if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("id %v %v", st, err)
	}
	raw, _ := os.ReadFile(filepath.Join(o.Home, ".ssh/portcullis/example.org/id"))
	k, err := ssh.ParseRawPrivateKey(raw)
	if err != nil || k == nil {
		t.Errorf("id isn't a private key: %v", err)
	}
	// M7: with no agent, ssh must be pointed at the private key itself.
	cfg, _ := os.ReadFile(filepath.Join(o.Home, ".ssh/portcullis/example.org/config"))
	if !strings.Contains(string(cfg), "  IdentityFile ~/.ssh/portcullis/example.org/id\n") {
		t.Errorf("config doesn't name the private key:\n%s", cfg)
	}
}

// A hostile answer: an escape sequence in a principal (signed into the
// certificate too) refuses the whole answer; nothing reaches the
// terminal, the agent or the files.
func TestHostileAnswerRefused(t *testing.T) {
	for _, p := range []string{"u:alice@web\x1b[2J", "u:bob@web", "s:deploy@db", "u:alice@web\n"} {
		f := newFakeHub(t)
		f.principal = p
		kr := agent.NewKeyring().(agent.ExtendedAgent)
		var seen url.URL
		o := opts(t, f, kr, &seen)
		var stdout bytes.Buffer
		o.Stdout = &stdout
		_, err := Run(context.Background(), o)
		if err == nil || strings.ContainsRune(err.Error(), 0x1b) {
			t.Errorf("%q: %v", p, err)
		}
		keys, _ := kr.List()
		if len(keys) != 0 || stdout.Len() != 0 || strings.ContainsRune(o.Stderr.(*bytes.Buffer).String(), 0x1b) {
			t.Errorf("%q: agent %v stdout %q", p, keys, stdout.String())
		}
		if _, err := os.Stat(filepath.Join(o.Home, ".ssh/portcullis")); err == nil {
			t.Errorf("%q: files written", p)
		}
	}
}
