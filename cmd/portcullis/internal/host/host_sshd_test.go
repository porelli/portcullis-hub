//go:build sshd

package host

// The host agent against real sshd (plan C26, Task 14): for each of
// Debian 13, Ubuntu 24.04 and Rocky 9 (pinned bases), a container with
// openssh-server, the CLI enrolled against a fake Hub served on the
// container network's gateway (TLS with a test CA, the first user CA
// pinned by the code), then real SSH logins with test-CA certificates.
// Containers: --rm, a cli-sshd- name, their own network, sshd published
// on 127.0.0.1 only. PORTCULLIS_DOCKER_TEST=require: no docker is a
// failure, not a skip.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

func docker(t *testing.T, stdin []byte, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustDocker(t *testing.T, stdin []byte, args ...string) string {
	t.Helper()
	out, err := docker(t, stdin, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(out)
}

// sshdHub is the fake Hub: one host, its code, the bundle the test sets.
type sshdHub struct {
	mu      sync.Mutex
	t       *testing.T
	domain  string
	secret  string
	chal    map[string]bool
	hostKey ssh.PublicKey
	bundle  cliapi.Bundle
	reports []cliapi.Report
}

func (h *sshdHub) setBundle(edit func(*cliapi.Bundle)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	edit(&h.bundle)
	h.bundle.Serial++
}

func (h *sshdHub) lastReport() cliapi.Report {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reports) == 0 {
		return cliapi.Report{}
	}
	return h.reports[len(h.reports)-1]
}

func (h *sshdHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	body := make([]byte, 0)
	if r.Body != nil {
		b := new(bytes.Buffer)
		b.ReadFrom(r.Body)
		body = b.Bytes()
	}
	ans := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
	switch {
	case r.URL.Path == "/api/cli/v1/hosts/enrol/challenge":
		c := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		h.chal[c] = true
		ans(cliapi.EnrolChallenge{Challenge: c})
	case r.URL.Path == "/api/cli/v1/hosts/enrol":
		var req cliapi.EnrolRequest
		if err := cliapi.UnmarshalStrict(body, &req); err != nil || req.Secret != h.secret {
			w.WriteHeader(403)
			return
		}
		k, _, _ := cliapi.ParseAuthorizedKey(req.HostKey)
		sig, _ := sshsig.Unarmor([]byte(req.Proof))
		ok := false
		for c := range h.chal {
			if sshsig.Verify(bytes.NewReader(cliapi.EnrolMessage(h.domain, req.HostID, c)), sig, k, sshsig.HashSHA512, cliapi.NSHostEnrol) == nil {
				ok = true
				delete(h.chal, c)
			}
		}
		if !ok {
			w.WriteHeader(403)
			return
		}
		h.hostKey = k
		ans(h.bundle)
	default:
		// Signed host requests.
		sig, err := sshsig.Unarmor(cliapi.DecodeSignatureHeader(r.Header.Get(cliapi.HeaderHostSignature)))
		msg := cliapi.HostRequestMessage(r.Header.Get(cliapi.HeaderHostID), r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get(cliapi.HeaderHostTime), r.Header.Get(cliapi.HeaderHostNonce), body)
		if err != nil || h.hostKey == nil || sshsig.Verify(bytes.NewReader(msg), sig, h.hostKey, sshsig.HashSHA512, cliapi.NSHostRequest) != nil {
			h.t.Errorf("a host request with a bad signature: %s", r.URL.Path)
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"bad signature"}`))
			return
		}
		switch r.URL.Path {
		case "/api/cli/v1/hosts/bundle":
			since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
			if h.bundle.Serial > since {
				ans(h.bundle)
				return
			}
			w.WriteHeader(204)
		case "/api/cli/v1/hosts/report":
			var rep cliapi.Report
			if err := cliapi.UnmarshalStrict(body, &rep); err != nil {
				h.t.Errorf("report: %v", err)
			}
			h.reports = append(h.reports, rep)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}
}

// tlsFor is a CA and a server certificate for ip.
func tlsFor(t *testing.T, ip net.IP) (*tls.Config, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cli-sshd test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ip.String()}, IPAddresses: []net.IP{ip}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srv, caCert, &srvKey.PublicKey, caKey)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}}}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func userCert(t *testing.T, ca ssh.Signer, principal, keyID string) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	c := &ssh.Certificate{Key: s.PublicKey(), CertType: ssh.UserCert, KeyId: keyID, ValidPrincipals: []string{principal},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(c, s)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// sshRun logs in as user with signer and runs cmd (an error = refused).
func sshRun(addr, user string, signer ssh.Signer, cmd string) (string, error) {
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	return strings.TrimSpace(string(out)), err
}

func TestHostAgentAgainstRealSSHD(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil || exec.Command("docker", "info").Run() != nil {
		if os.Getenv("PORTCULLIS_DOCKER_TEST") == "require" {
			t.Fatal("PORTCULLIS_DOCKER_TEST=require but no docker daemon")
		}
		t.Skip("no docker daemon")
	}
	arch := mustDocker(t, nil, "version", "-f", "{{.Server.Arch}}")
	bin := filepath.Join(t.TempDir(), "portcullis")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, "../..")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, out)
	}
	for _, osName := range []string{"debian", "ubuntu", "rocky"} {
		t.Run(osName, func(t *testing.T) { runSSHDCase(t, osName, bin) })
	}
}

func runSSHDCase(t *testing.T, osName, bin string) {
	tag := fmt.Sprintf("cli-sshd-%s-%d", osName, os.Getpid())
	mustDocker(t, nil, "build", "-q", "-t", tag, "-f", "testdata/sshd/Dockerfile."+osName, "testdata/sshd")
	t.Cleanup(func() { exec.Command("docker", "rmi", "-f", tag).Run() })
	netName := tag + "-net"
	mustDocker(t, nil, "network", "create", netName)
	t.Cleanup(func() { exec.Command("docker", "network", "rm", netName).Run() })
	gw := net.ParseIP(mustDocker(t, nil, "network", "inspect", "-f", "{{(index .IPAM.Config 0).Gateway}}", netName))
	if gw == nil {
		t.Fatal("no gateway")
	}
	// The fake Hub on the network's gateway only.
	caSigner := func() ssh.Signer { _, k, _ := ed25519.GenerateKey(rand.Reader); s, _ := ssh.NewSignerFromKey(k); return s }()
	secret := make([]byte, 32)
	rand.Read(secret)
	hub := &sshdHub{t: t, domain: "example.org", secret: base64.RawURLEncoding.EncodeToString(secret), chal: map[string]bool{},
		bundle: cliapi.Bundle{Version: 1, HostID: "web-1", Serial: 1, UserCAs: []string{cliapi.NormalAuthorizedKey(caSigner.PublicKey())},
			Accounts: []cliapi.Account{{Name: "alice", Kind: "person", UID: 20001, Principals: []string{"u:alice@web"}, Sudo: true},
				{Name: "bob", Kind: "person", UID: 20002, Principals: []string{"u:bob@web"}}},
			Locked: []string{}, Remove: []string{}, RevokedKeys: []string{}}}
	ln, err := net.Listen("tcp", net.JoinHostPort(gw.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	tc, caPEM := tlsFor(t, gw)
	srv := httptest.NewUnstartedServer(hub)
	srv.Listener.Close()
	srv.Listener = ln
	srv.TLS = tc
	srv.StartTLS()
	t.Cleanup(srv.Close)
	code := cliapi.EnrolCode{Domain: "example.org", HostID: "web-1", HostGroups: []string{"all", "web"}, UserCAFP: cliapi.Fingerprint(caSigner.PublicKey()),
		HostCAFP: "SHA256:none", Secret: hub.secret, Expires: time.Now().Add(15 * time.Minute)}
	// The container.
	name := tag
	mustDocker(t, nil, "run", "-d", "--rm", "--name", name, "--network", netName, "-p", "127.0.0.1::22", tag)
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	port := mustDocker(t, nil, "port", name, "22/tcp")
	addr := port[strings.LastIndex(port, "\n")+1:]
	mustDocker(t, nil, "cp", bin, name+":/usr/local/bin/portcullis")
	mustDocker(t, caPEM, "exec", "-i", name, "sh", "-c", "cat > /ca.pem")
	_, bgPriv, _ := ed25519.GenerateKey(rand.Reader)
	bg, _ := ssh.NewSignerFromKey(bgPriv)
	mustDocker(t, ssh.MarshalAuthorizedKey(bg.PublicKey()), "exec", "-i", name, "sh", "-c", "cat > /home/breakglass/.ssh/authorized_keys && chown breakglass: /home/breakglass/.ssh/authorized_keys && chmod 600 /home/breakglass/.ssh/authorized_keys")
	mainBefore := mustDocker(t, nil, "exec", name, "sha256sum", "/etc/ssh/sshd_config")
	exec_ := func(args ...string) (string, error) { return docker(t, nil, append([]string{"exec", name}, args...)...) }
	waitSSH := func() {
		for i := 0; i < 50; i++ {
			if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				c.Close()
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("sshd on %s never answered", addr)
	}
	waitSSH()
	// Enrol (the code on stdin, never argv).
	if out, err := docker(t, []byte(code.String()), "exec", "-i", name, "/usr/local/bin/portcullis", "host", "enroll", "--service", "none",
		"--people-url", "https://"+net.JoinHostPort(gw.String(), strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)), "--ca-file", "/ca.pem"); err != nil {
		t.Fatalf("enroll: %v\n%s", err, out)
	}
	time.Sleep(time.Second) // sshd re-executes on SIGHUP
	waitSSH()
	// alice: a person account, certificate-only, with sudo.
	alice := userCert(t, caSigner, "u:alice@web", "pc:alice:web:0123456789abcdef")
	out, err := sshRun(addr, "alice", alice, "id -un; sudo -n true && echo SUDO")
	if err != nil || !strings.Contains(out, "alice") || !strings.Contains(out, "SUDO") {
		t.Fatalf("alice: %v %q", err, out)
	}
	// bob: no sudo.
	if out, err := sshRun(addr, "bob", userCert(t, caSigner, "u:bob@web", "pc:bob:web:0123456789abcdef"), "sudo -n true && echo SUDO; id -un"); err != nil || strings.Contains(out, "SUDO") {
		t.Errorf("bob: %v %q", err, out)
	}
	// A shared-kind principal for alice's account, another host group, root: refused.
	for name, c := range map[string][2]string{"s:alice": {"alice", "s:alice@web"}, "db": {"alice", "u:alice@db"}, "root": {"root", "s:root@web"}} {
		if _, err := sshRun(addr, c[0], userCert(t, caSigner, c[1], "pc:x:web:0123456789abcdef"), "true"); err == nil {
			t.Errorf("%s: logged in", name)
		}
	}
	// breakglass: its own key.
	if out, err := sshRun(addr, "breakglass", bg, "id -un"); err != nil || out != "breakglass" {
		t.Errorf("breakglass: %v %q", err, out)
	}
	// A hand-edited principals file is healed at the next apply, reported fixed.
	exec_("sh", "-c", "echo u:mallory@web > /etc/ssh/portcullis/principals/alice")
	hub.setBundle(func(*cliapi.Bundle) {})
	if out, err := exec_("/usr/local/bin/portcullis", "host", "sync", "--once"); err != nil {
		t.Errorf("sync: %v %s", err, out)
	}
	if got, _ := exec_("cat", "/etc/ssh/portcullis/principals/alice"); strings.TrimSpace(got) != "u:alice@web" {
		t.Errorf("not healed: %q", got)
	}
	if !hasFinding(hub.lastReport(), cliapi.FindingDrift, "/etc/ssh/portcullis/principals/alice", "fixed") {
		t.Errorf("drift not reported: %+v", hub.lastReport().Findings)
	}
	// bob leaves: locked, refused.
	hub.setBundle(func(b *cliapi.Bundle) { b.Accounts = b.Accounts[:1]; b.Locked = []string{"bob"} })
	exec_("/usr/local/bin/portcullis", "host", "sync", "--once")
	if _, err := sshRun(addr, "bob", userCert(t, caSigner, "u:bob@web", "pc:bob:web:0123456789abcdef"), "true"); err == nil {
		t.Error("bob still logs in after losing access")
	}
	// TrustedUserCAKeys before the Include: a Problem, the files kept.
	exec_("sed", "-i", "1i TrustedUserCAKeys /x", "/etc/ssh/sshd_config")
	hub.setBundle(func(*cliapi.Bundle) {})
	exec_("/usr/local/bin/portcullis", "host", "sync", "--once")
	if r := hub.lastReport(); r.Applied || !hasFinding(r, cliapi.FindingDrift, "", "") {
		t.Errorf("override not a Problem: %+v", r)
	}
	exec_("sed", "-i", "1d", "/etc/ssh/sshd_config")
	exec_("sh", "-c", "kill -HUP 1")
	time.Sleep(time.Second)
	waitSSH()
	// Remove: Portcullis's paths gone, the box's own ones unchanged.
	if out, err := exec_("/usr/local/bin/portcullis", "host", "remove"); err != nil {
		t.Fatalf("remove: %v %s", err, out)
	}
	time.Sleep(time.Second)
	waitSSH()
	if _, err := sshRun(addr, "alice", alice, "true"); err == nil {
		t.Error("alice logs in after host remove")
	}
	if out, err := sshRun(addr, "breakglass", bg, "id -un"); err != nil || out != "breakglass" {
		t.Errorf("breakglass after remove: %v %q", err, out)
	}
	if after := mustDocker(t, nil, "exec", name, "sha256sum", "/etc/ssh/sshd_config"); after != mainBefore {
		t.Error("the main sshd_config changed")
	}
	if out, _ := exec_("sh", "-c", "ls /etc/ssh/sshd_config.d/50-portcullis.conf /etc/ssh/portcullis 2>&1"); !strings.Contains(out, "No such file") {
		t.Errorf("files left: %s", out)
	}
	_ = sha256.Sum256
	_ = hex.EncodeToString
	_ = context.Background
}

func hasFinding(r cliapi.Report, kind, subject, detail string) bool {
	for _, f := range r.Findings {
		if f.Kind == kind && (subject == "" || f.Subject == subject) && (detail == "" || f.Detail == detail) {
			return true
		}
	}
	return false
}
