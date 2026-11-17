package sshconf

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

var update = flag.Bool("update", false, "rewrite testdata")

func cert(t *testing.T) (string, string) {
	t.Helper()
	_, ca, _ := ed25519.GenerateKey(rand.Reader)
	caS, _ := ssh.NewSignerFromKey(ca)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	c := &ssh.Certificate{Key: pk, CertType: ssh.UserCert, ValidPrincipals: []string{"u:alice@web"}, ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
	c.SignCert(rand.Reader, caS)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))), cliapi.NormalAuthorizedKey(caS.PublicKey())
}

func answer(t *testing.T) (*cliapi.CertAnswer, string) {
	c, hostCA := cert(t)
	return &cliapi.CertAnswer{User: "alice", Certificates: []cliapi.IssuedCert{{HostGroup: "web", Certificate: c,
		Hosts: []string{"web-1.example.com", "web-2.example.com", "10.20.0.11", "10.20.0.12"}}}, HostCAs: []string{hostCA}, RevokedHostKeys: []string{}}, hostCA
}

func TestConfigGolden(t *testing.T) {
	home := t.TempDir()
	ans, _ := answer(t)
	if err := Write(home, "example.com", ans, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXf2yZXNFwHqiadxQBruvDLwOZYX4l4+MUIDqyknOMZ", nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(home, ".ssh/portcullis/example.com/config"))
	p := "testdata/config.golden"
	if *update {
		os.WriteFile(p, got, 0o644)
	}
	want, _ := os.ReadFile(p)
	if string(got) != string(want) {
		t.Errorf("config\n%s\nwant\n%s", got, want)
	}
}

func TestKnownHostsCertAuthorityScoped(t *testing.T) {
	home := t.TempDir()
	ans, hostCA := answer(t)
	revoked := cliapi.NormalAuthorizedKey(mustPub(t))
	ans.RevokedHostKeys = []string{revoked}
	if err := Write(home, "example.com", ans, "ssh-ed25519 AAAA", nil); err != nil {
		t.Fatal(err)
	}
	kh, _ := os.ReadFile(filepath.Join(home, ".ssh/portcullis/example.com/known_hosts"))
	want := "@cert-authority web-1.example.com,web-2.example.com,10.20.0.11,10.20.0.12 " + hostCA + "\n@revoked * " + revoked + "\n"
	if string(kh) != want {
		t.Errorf("known_hosts %q", kh)
	}
	// An injected host name is refused, nothing written.
	ans.Certificates[0].Hosts = []string{"x\nProxyCommand evil"}
	if err := Write(t.TempDir(), "example.com", ans, "ssh-ed25519 AAAA", nil); err == nil {
		t.Error("an injected name written")
	}
}

func mustPub(t *testing.T) ssh.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	return pk
}

func TestInstallAsksAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh/config"), []byte("Host old\n  User me\n"), 0o600)
	if done, err := Install(home, func() bool { return false }); done || err != nil {
		t.Errorf("no: %v %v", done, err)
	}
	if Installed(home) {
		t.Error("installed after no")
	}
	if done, err := Install(home, func() bool { return true }); !done || err != nil {
		t.Errorf("yes: %v %v", done, err)
	}
	asked := false
	if done, _ := Install(home, func() bool { asked = true; return true }); done || asked {
		t.Error("asked again / added twice")
	}
	raw, _ := os.ReadFile(filepath.Join(home, ".ssh/config"))
	if !strings.HasPrefix(string(raw), cliapi.IncludeLine+"\n") || !strings.Contains(string(raw), "Host old") || strings.Count(string(raw), "Include") != 1 {
		t.Errorf("config %q", raw)
	}
}

func TestDirModes(t *testing.T) {
	home := t.TempDir()
	ans, _ := answer(t)
	if err := Write(home, "example.com", ans, "ssh-ed25519 AAAA", []byte("PRIVATE")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".ssh/portcullis/example.com")
	if runtime.GOOS == "windows" {
		// No mode bits on Windows: the user profile's ACL keeps it private.
		t.Skip("no Unix modes on Windows")
	}
	st, _ := os.Stat(dir)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir %o", st.Mode().Perm())
	}
	st, _ = os.Stat(filepath.Join(dir, "id"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("id %o", st.Mode().Perm())
	}
	for _, f := range []string{"id.pub", "web-cert.pub", "known_hosts", "config"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	// Without --write-files the next login removes the private key, and
	// a host group no longer granted loses its certificate file.
	ans.Certificates[0].HostGroup = "all"
	Write(home, "example.com", ans, "ssh-ed25519 AAAA", nil)
	if _, err := os.Stat(filepath.Join(dir, "id")); err == nil {
		t.Error("id kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "web-cert.pub")); err == nil {
		t.Error("stale certificate kept")
	}
	if err := Remove(home, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("logout left the directory")
	}
}
