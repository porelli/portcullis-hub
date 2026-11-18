package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

var update = flag.Bool("update", false, "rewrite testdata")

func caKey(t *testing.T) (string, string) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return cliapi.NormalAuthorizedKey(k), cliapi.Fingerprint(k)
}

func trustOpts(t *testing.T) TrustOptions {
	ca, _ := caKey(t)
	return TrustOptions{Domain: "example.org", HostGroup: "web", CAKey: ca, Persons: []string{"alice"}, Accounts: []string{"deploy"}, Breakglass: "breakglass", ServiceNone: false}
}

func TestDropInGolden(t *testing.T) {
	got := DropIn(SyncOrigin("example.com", "web-1"), true)
	p := "testdata/dropin.golden"
	if *update {
		os.WriteFile(p, got, 0o644)
	}
	want, _ := os.ReadFile(p)
	if string(got) != string(want) {
		t.Errorf("drop-in\n%s\nwant\n%s", got, want)
	}
	spec := "# Written by portcullis host sync (example.com, host web-1). Do not edit.\nTrustedUserCAKeys /etc/ssh/portcullis/user_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/portcullis/principals/%u\nRevokedKeys /etc/ssh/portcullis/revoked_keys\nHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\nMatch Group portcullis-users\n    AuthorizedKeysFile none\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n"
	if string(got) != spec {
		t.Errorf("not the spec §8.9 text")
	}
	for _, v := range [][]byte{got, DropIn(TrustOrigin("example.com", "web"), false)} {
		if strings.Contains(string(v), "ChallengeResponse") || strings.Contains(string(v), "Match all") {
			t.Error("S3: never ChallengeResponseAuthentication, no Match all")
		}
	}
	if strings.Contains(string(DropIn(TrustOrigin("example.com", "web"), false)), "HostCertificate") {
		t.Error("trust without a host certificate names one")
	}
}

func TestRevokedKeysCreatedEmptyFirst(t *testing.T) {
	sys := newFakeSys(t)
	addTrustAccounts(sys)
	if err := Trust(context.Background(), sys, trustOpts(t)); err != nil {
		t.Fatal(err)
	}
	ri, di := slices.Index(sys.writes, RevokedKeysFile), slices.Index(sys.writes, DropInFile)
	if ri < 0 || di < 0 || ri > di || len(sys.files[RevokedKeysFile]) != 0 {
		t.Errorf("writes %v", sys.writes)
	}
	if got := string(sys.files[PrincipalsFile("alice")]); got != "u:alice@web\nup:alice@web\n" {
		t.Errorf("alice %q", got)
	}
	if got := string(sys.files[PrincipalsFile("deploy")]); got != "s:deploy@web\nsp:deploy@web\n" {
		t.Errorf("deploy %q", got)
	}
	if sys.reloads != 1 {
		t.Errorf("reloads %d", sys.reloads)
	}
}

func TestTransactionRollsBackOnSshdT(t *testing.T) {
	sys := newFakeSys(t)
	sys.files[UserCAFile] = []byte("ssh-ed25519 OLD\n")
	before := sys.snapshot()
	sys.sshdT = errors.New("exit status 255")
	err := Trust(context.Background(), sys, trustOpts(t))
	if err == nil || !strings.Contains(err.Error(), "sshd -t") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(sys.snapshot(), before) {
		t.Error("files not restored byte for byte")
	}
	if sys.reloads != 0 {
		t.Error("sshd reloaded")
	}
}

func TestNoIncludeRefusesWithLines(t *testing.T) {
	sys := newFakeSys(t)
	sys.files[MainConfig] = []byte("UsePAM yes\n")
	before := sys.snapshot()
	err := Trust(context.Background(), sys, trustOpts(t))
	if err == nil || !strings.Contains(err.Error(), IncludeLine) {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(sys.snapshot(), before) {
		t.Error("files changed")
	}
}

func TestApplyRefusesWhenEffectiveConfigDiffers(t *testing.T) {
	sys := newFakeSys(t)
	sys.files[MainConfig] = []byte("TrustedUserCAKeys /x\nInclude /etc/ssh/sshd_config.d/*.conf\n")
	before := sys.snapshot()
	err := Trust(context.Background(), sys, trustOpts(t))
	if err == nil || !strings.Contains(err.Error(), "trustedusercakeys") || !strings.Contains(err.Error(), "/x") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(sys.snapshot(), before) || sys.reloads != 0 {
		t.Error("files changed or sshd reloaded")
	}
	// An earlier drop-in that sets it first: the same.
	sys = newFakeSys(t)
	sys.files[DropInDir+"/10-cloud.conf"] = []byte("TrustedUserCAKeys /y\n")
	if err := Trust(context.Background(), sys, trustOpts(t)); err == nil {
		t.Error("an earlier drop-in's TrustedUserCAKeys passed")
	}
}

func TestTrustCAKeyPinnedFetch(t *testing.T) {
	sys := newFakeSys(t)
	ca, fp := caKey(t)
	other, _ := caKey(t)
	o := trustOpts(t)
	o.CAKey, o.CAFingerprint = "", fp
	o.Fetch = func(context.Context, string) ([]byte, error) {
		b, _ := json.Marshal(cliapi.CAAnswer{UserCAs: []string{other}, HostCAs: []string{}})
		return b, nil
	}
	if err := Trust(context.Background(), sys, o); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("a key not matching the fingerprint: %v", err)
	}
	o.Fetch = func(context.Context, string) ([]byte, error) {
		b, _ := json.Marshal(cliapi.CAAnswer{UserCAs: []string{other, ca}, HostCAs: []string{}})
		return b, nil
	}
	if err := Trust(context.Background(), sys, o); err != nil {
		t.Fatal(err)
	}
	if string(sys.files[UserCAFile]) != ca+"\n" {
		t.Errorf("CA %q", sys.files[UserCAFile])
	}
	o.CAFingerprint = ""
	if err := Trust(context.Background(), newFakeSys(t), o); err == nil {
		t.Error("an unpinned fetch")
	}
}

func TestTrustNoConnectionWithoutRevokedKeys(t *testing.T) {
	sys := newFakeSys(t)
	o := trustOpts(t)
	o.Fetch = func(context.Context, string) ([]byte, error) {
		t.Error("dialled without --revoked-keys")
		return nil, errors.New("no")
	}
	if err := Trust(context.Background(), sys, o); err != nil {
		t.Fatal(err)
	}
}

func TestTrustRevokedKeysTimer(t *testing.T) {
	sys := newFakeSys(t)
	o := trustOpts(t)
	o.RevokedKeys, o.Self = true, "/usr/local/bin/portcullis"
	bad, _ := caKey(t)
	o.Fetch = func(context.Context, string) ([]byte, error) { return []byte(bad + "\n"), nil }
	if err := Trust(context.Background(), sys, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sys.files[revokedTimer]), "OnUnitActiveSec=5min") || !strings.Contains(string(sys.files[revokedService]), `ExecStart="/usr/local/bin/portcullis" host revoked-keys`) {
		t.Errorf("units %q %q", sys.files[revokedTimer], sys.files[revokedService])
	}
	if !sys.ran("systemctl enable --now portcullis-revoked-keys.timer") {
		t.Error("timer not enabled")
	}
	if string(sys.files[RevokedKeysFile]) != bad+"\n" {
		t.Errorf("first fetch %q", sys.files[RevokedKeysFile])
	}
	// A failed or garbled fetch keeps the last file.
	if err := FetchRevokedKeys(context.Background(), sys, func(context.Context, string) ([]byte, error) { return nil, errors.New("down") }); err == nil {
		t.Error("a failed fetch")
	}
	FetchRevokedKeys(context.Background(), sys, func(context.Context, string) ([]byte, error) { return []byte("garbage\n"), nil })
	if string(sys.files[RevokedKeysFile]) != bad+"\n" {
		t.Error("the last file was replaced")
	}
}

func TestTrustBreakglassRequired(t *testing.T) {
	o := trustOpts(t)
	o.Breakglass = ""
	if err := Trust(context.Background(), newFakeSys(t), o); err == nil || !strings.Contains(err.Error(), "break-glass") {
		t.Errorf("no break-glass: %v", err)
	}
	o.Breakglass = "ops" // exists, no authorized_keys
	if err := Trust(context.Background(), newFakeSys(t), o); err == nil || !strings.Contains(err.Error(), "authorized_keys") {
		t.Errorf("no key: %v", err)
	}
	o.Breakglass, o.NoBreakglass = "", true
	if err := Trust(context.Background(), newFakeSys(t), o); err != nil {
		t.Errorf("console access: %v", err)
	}
	o = trustOpts(t)
	o.Accounts = []string{"breakglass"}
	if err := Trust(context.Background(), newFakeSys(t), o); err == nil {
		t.Error("the break-glass account as a Portcullis account")
	}
}

func TestTrustNeverTouchesMainConfig(t *testing.T) {
	sys := newFakeSys(t)
	before := string(sys.files[MainConfig])
	if err := Trust(context.Background(), sys, trustOpts(t)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(sys.writes, MainConfig) || string(sys.files[MainConfig]) != before {
		t.Error("the main sshd_config was written")
	}
	for _, w := range sys.writes {
		if strings.Contains(w, "authorized_keys") {
			t.Errorf("wrote %s", w)
		}
	}
}

func TestOpenSSHFloor8_2(t *testing.T) {
	sys := newFakeSys(t)
	sys.version = "OpenSSH_8.1p1"
	err := Trust(context.Background(), sys, trustOpts(t))
	if err == nil || !strings.Contains(err.Error(), "8.2") || !strings.Contains(err.Error(), "TrustedUserCAKeys") {
		t.Errorf("8.1: %v", err)
	}
	sys.version = "OpenSSH_8.2p1"
	if err := Trust(context.Background(), sys, trustOpts(t)); err != nil {
		t.Errorf("8.2: %v", err)
	}
	sys = newFakeSys(t)
	sys.goos = "windows"
	if err := Trust(context.Background(), sys, trustOpts(t)); err == nil || !strings.Contains(err.Error(), "Windows hosts") {
		t.Errorf("windows: %v", err)
	}
}

func TestRevokedTimerRefusesUnsafeBinary(t *testing.T) {
	for name, edit := range map[string]func(*fakeSys){
		"user-owned binary":   func(s *fakeSys) { s.owners["/home/ops/Downloads/portcullis"] = ownerOf{1002, 0o755} },
		"group-writable dir":  func(s *fakeSys) { s.owners["/home/ops/Downloads"] = ownerOf{0, 0o775} },
		"world-writable /tmp": func(s *fakeSys) { s.owners["/home"] = ownerOf{0, 0o1777} },
		"link to a user file": func(s *fakeSys) {
			s.links["/home/ops/Downloads/portcullis"] = "/home/ops/bin/p"
			s.owners["/home/ops/bin/p"] = ownerOf{1002, 0o755}
		},
	} {
		sys := newFakeSys(t)
		edit(sys)
		before := sys.snapshot()
		o := trustOpts(t)
		o.RevokedKeys, o.Self = true, "/home/ops/Downloads/portcullis"
		o.Fetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("no") }
		err := Trust(context.Background(), sys, o)
		if err == nil || !strings.Contains(err.Error(), "root") {
			t.Errorf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(sys.snapshot(), before) {
			t.Errorf("%s: files written", name)
		}
	}
	// A root-owned path with a space and a %: quoted.
	sys := newFakeSys(t)
	o := trustOpts(t)
	o.RevokedKeys, o.Self = true, "/opt/port cullis/100%/portcullis"
	o.Fetch = func(context.Context, string) ([]byte, error) { return []byte{}, nil }
	if err := Trust(context.Background(), sys, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sys.files[revokedService]), `ExecStart="/opt/port cullis/100%%/portcullis" host revoked-keys`) {
		t.Errorf("unit %s", sys.files[revokedService])
	}
	if got := xmlEscape(`/a&b<c>`); got != "/a&amp;b&lt;c&gt;" {
		t.Errorf("xml %q", got)
	}
}

// addTrustAccounts: alice and deploy exist, neither with sudo.
func addTrustAccounts(sys *fakeSys) {
	sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("alice:x:1600:1600::/home/alice:/bin/bash\ndeploy:x:1601:1601::/home/deploy:/bin/bash\n")...)
}

// V-M2: host trust runs the managed hosts' sudo check. An account with
// sudo, an unknown one, or --approved-only gets only the approved form;
// each account's form is reported.
func TestTrustApprovedOnlyForSudo(t *testing.T) {
	for name, c := range map[string]struct {
		setup         func(*fakeSys)
		approvedOnly  bool
		alice, deploy string
	}{
		"deploy has sudo": {func(s *fakeSys) { addTrustAccounts(s); s.sudoers["deploy"] = true }, false, "u:alice@web\nup:alice@web\n", "sp:deploy@web\n"},
		"alice in docker": {func(s *fakeSys) {
			addTrustAccounts(s)
			s.files["/etc/group"] = append(s.files["/etc/group"], []byte("docker:x:990:alice\n")...)
		}, false, "up:alice@web\n", "s:deploy@web\nsp:deploy@web\n"},
		"not created yet": {func(*fakeSys) {}, false, "up:alice@web\n", "sp:deploy@web\n"},
		"--approved-only": {addTrustAccounts, true, "up:alice@web\n", "sp:deploy@web\n"},
	} {
		sys := newFakeSys(t)
		c.setup(sys)
		o := trustOpts(t)
		o.ApprovedOnly = c.approvedOnly
		var notes []string
		o.Note = func(s string) { notes = append(notes, s) }
		if err := Trust(context.Background(), sys, o); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := string(sys.files[PrincipalsFile("alice")]); got != c.alice {
			t.Errorf("%s: alice %q", name, got)
		}
		if got := string(sys.files[PrincipalsFile("deploy")]); got != c.deploy {
			t.Errorf("%s: deploy %q", name, got)
		}
		if len(notes) != 2 {
			t.Errorf("%s: notes %v", name, notes)
		}
	}
}
