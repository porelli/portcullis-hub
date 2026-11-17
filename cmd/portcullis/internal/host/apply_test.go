package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
)

var applyNow = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

func bundle(t *testing.T) *cliapi.Bundle {
	ca, _ := caKey(t)
	return &cliapi.Bundle{Version: 1, HostID: "web-1", Serial: 3, UserCAs: []string{ca},
		Accounts: []cliapi.Account{
			{Name: "alice", Kind: "person", UID: 20001, Principals: []string{"up:alice@all", "up:alice@web"}, Sudo: true},
			{Name: "bob", Kind: "person", UID: 20002, Principals: []string{"u:bob@web"}},
			{Name: "deploy", Kind: "shared", Principals: []string{"s:deploy@web"}},
		}, Locked: []string{}, Remove: []string{}, RevokedKeys: []string{}}
}

func apply(t *testing.T, sys *fakeSys, b *cliapi.Bundle, c cliapi.Ceiling, prev *State) (*State, []cliapi.Finding, error) {
	t.Helper()
	return Apply(context.Background(), sys, b, c, prev, ApplyOptions{Domain: "example.org", Now: applyNow})
}

func kinds(fs []cliapi.Finding) map[string][]string {
	out := map[string][]string{}
	for _, f := range fs {
		out[f.Kind] = append(out[f.Kind], f.Subject)
	}
	return out
}

func TestCreatePersonAccount(t *testing.T) {
	sys := newFakeSys(t)
	if _, _, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil); err != nil {
		t.Fatal(err)
	}
	if !sys.ran("useradd -u 20001 -U -G portcullis-users -m -s /bin/bash -c portcullis alice alice") {
		t.Errorf("runs %v", sys.runs)
	}
	if got := string(sys.files[PrincipalsFile("alice")]); got != "up:alice@all\nup:alice@web\n" {
		t.Errorf("alice principals %q", got)
	}
	if got := string(sys.files[SudoersFile]); !strings.Contains(got, "alice ALL=(ALL:ALL) NOPASSWD: ALL\n") || strings.Contains(got, "bob") || sys.modes[SudoersFile] != 0o440 {
		t.Errorf("sudoers %q %o", got, sys.modes[SudoersFile])
	}
	sys2 := newFakeSys(t)
	delete(sys2.files, "/bin/bash")
	apply(t, sys2, bundle(t), cliapi.DefaultCeiling(), nil)
	if !sys2.ran("useradd -u 20001 -U -G portcullis-users -m -s /bin/sh -c portcullis alice alice") {
		t.Errorf("no bash: %v", sys2.runs)
	}
}

func TestAccountsConflictNeverAdopted(t *testing.T) {
	sys := newFakeSys(t)
	sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("bob:x:1500:1500:Bob:/home/bob:/bin/bash\n")...)
	_, fs, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(kinds(fs)[cliapi.FindingAccountConflict], "bob") {
		t.Errorf("findings %v", fs)
	}
	if _, ok := sys.files[PrincipalsFile("bob")]; ok || sys.ran("usermod -U -e  -s /bin/bash bob") || sys.ran("useradd -u 20002") {
		t.Error("the local bob was adopted or changed")
	}
}

func TestAccountInvalidSkipped(t *testing.T) {
	sys := newFakeSys(t)
	b := bundle(t)
	long := strings.Repeat("a", 40)
	b.Accounts = append(b.Accounts, cliapi.Account{Name: "1alice", Kind: "person", Principals: []string{}}, cliapi.Account{Name: long, Kind: "person", Principals: []string{}})
	_, fs, err := apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	inv := kinds(fs)[cliapi.FindingAccountInvalid]
	if !slices.Contains(inv, "1alice") || !slices.Contains(inv, long) || sys.ran("useradd -u 0") {
		t.Errorf("findings %v", fs)
	}
}

func TestCeilingRefusesRootAndProtected(t *testing.T) {
	sys := newFakeSys(t)
	b := bundle(t)
	b.Accounts = append(b.Accounts, cliapi.Account{Name: "root", Kind: "shared", Principals: []string{"sp:root@all"}, Sudo: true},
		cliapi.Account{Name: "breakglass", Kind: "shared", Principals: []string{"s:breakglass@all"}},
		cliapi.Account{Name: "daemon", Kind: "shared", Principals: []string{"s:daemon@all"}})
	_, fs, err := apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ceil := kinds(fs)[cliapi.FindingCeiling]
	for _, n := range []string{"root", "breakglass", "daemon"} {
		if !slices.Contains(ceil, n) {
			t.Errorf("%s not refused: %v", n, fs)
		}
		if _, ok := sys.files[PrincipalsFile(n)]; ok {
			t.Errorf("%s got a principals file", n)
		}
	}
	// With allow_root_login, root works (a shared account).
	c := cliapi.DefaultCeiling()
	c.AllowRootLogin = true
	sys = newFakeSys(t)
	apply(t, sys, b, c, nil)
	if got := string(sys.files[PrincipalsFile("root")]); got != "sp:root@all\n" {
		t.Errorf("root %q", got)
	}
}

func TestBundleKindMismatchRefused(t *testing.T) {
	for _, a := range []cliapi.Account{
		{Name: "deploy", Kind: "shared", Principals: []string{"u:deploy@web"}},
		{Name: "alice", Kind: "person", UID: 20001, Principals: []string{"u:bob@web"}},
		{Name: "alice", Kind: "person", UID: 20001, Principals: []string{"s:alice@web"}},
		{Name: "alice", Kind: "admin", Principals: []string{"u:alice@web"}},
		// Bare principals never reach a principals file (security review 2:
		// Vault would sign them for a role listing them).
		{Name: "root", Kind: "shared", Principals: []string{"root"}},
		{Name: "alice", Kind: "person", UID: 20001, Principals: []string{"alice"}},
		{Name: "alice", Kind: "person", UID: 20001, Principals: []string{"u:alice@web", "root"}},
		{Name: "deploy", Kind: "shared", Principals: []string{"s:deploy@web,root"}},
		{Name: "deploy", Kind: "shared", Principals: []string{"s:deploy@web", "*"}},
	} {
		b := bundle(t)
		b.Accounts = []cliapi.Account{a}
		if err := ValidateBundle(b, "web-1", nil); err == nil {
			t.Errorf("%+v accepted", a)
		}
	}
	b := bundle(t)
	if err := ValidateBundle(b, "web-2", nil); err == nil {
		t.Error("another host's bundle")
	}
	if err := ValidateBundle(b, "web-1", nil); err != nil {
		t.Error(err)
	}
}

func TestLockOnLoss(t *testing.T) {
	sys := newFakeSys(t)
	st, _, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b := bundle(t)
	b.Accounts = b.Accounts[:1] // bob lost access
	b.Locked = []string{"bob", "breakglass"}
	st, _, err = apply(t, sys, b, cliapi.DefaultCeiling(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !sys.ran("usermod -L -e 1 -s /usr/sbin/nologin bob") || !sys.ran("loginctl terminate-user bob") {
		t.Errorf("runs %v", sys.runs)
	}
	if _, ok := sys.files[PrincipalsFile("bob")]; ok {
		t.Error("bob's principals file kept")
	}
	if sys.ran("usermod -L -e 1 -s /usr/sbin/nologin breakglass") {
		t.Error("a protected account locked")
	}
	if !slices.Equal(st.Locked, []string{"bob"}) {
		t.Errorf("locked %v", st.Locked)
	}
	// loginctl failing: pkill.
	sys.handler["loginctl"] = func([]string) ([]byte, error) { return nil, errors.New("no logind") }
	lock(context.Background(), sys, "bob")
	if !sys.ran("pkill -KILL -u bob") {
		t.Error("no pkill fallback")
	}
}

func TestRemoveAccountKeepsHome(t *testing.T) {
	sys := newFakeSys(t)
	st, _, _ := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	b := bundle(t)
	b.Accounts = b.Accounts[:1]
	b.Remove = []string{"bob", "ops"}
	st, _, err := apply(t, sys, b, cliapi.DefaultCeiling(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !sys.ran("userdel bob") || sys.ran("userdel -r") || !sys.dirs[RemovedHomes+"/bob-20261115"] {
		t.Errorf("runs %v dirs %v", sys.runs, sys.dirs)
	}
	if sys.ran("userdel ops") {
		t.Error("an account Portcullis didn't create was removed")
	}
	if !slices.Contains(st.Removed, "bob") {
		t.Errorf("removed %v", st.Removed)
	}
}

func TestSharedAccountsOnlyWhenOptedIn(t *testing.T) {
	sys := newFakeSys(t)
	_, fs, _ := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	if !slices.Contains(kinds(fs)[cliapi.FindingAccountMissing], "deploy") || sys.ran("useradd -m -s /bin/bash deploy") {
		t.Errorf("findings %v", fs)
	}
	sys = newFakeSys(t)
	b := bundle(t)
	b.Options.CreateSharedAccounts = true
	apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if !sys.ran("useradd -m -s /bin/bash deploy") {
		t.Errorf("runs %v", sys.runs)
	}
}

// A visudo refusal fails closed (L-B1): the old file goes, nobody keeps
// Portcullis sudo on a file that can't be updated.
func TestSudoersValidatedFailClosed(t *testing.T) {
	sys := newFakeSys(t)
	sys.files[SudoersFile] = []byte("old\n")
	sys.handler["visudo"] = func([]string) ([]byte, error) { return []byte("parse error"), errors.New("exit 1") }
	_, fs, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sys.files[SudoersFile]; ok {
		t.Error("the old sudoers file was kept")
	}
	if !slices.Contains(kinds(fs)[cliapi.FindingDrift], SudoersFile) {
		t.Errorf("findings %v", fs)
	}
	if !sys.ran("visudo -cf " + sudoersCheck) {
		t.Error("visudo -cf not run")
	}
}

func TestSudoersCeilingAllowSudoFalse(t *testing.T) {
	sys := newFakeSys(t)
	c := cliapi.DefaultCeiling()
	c.AllowSudo = false
	_, fs, _ := apply(t, sys, bundle(t), c, nil)
	if _, ok := sys.files[SudoersFile]; ok {
		t.Error("sudoers written")
	}
	if !slices.Contains(kinds(fs)[cliapi.FindingCeiling], "alice") {
		t.Errorf("findings %v", fs)
	}
}

func TestMaxAccounts(t *testing.T) {
	sys := newFakeSys(t)
	c := cliapi.DefaultCeiling()
	c.MaxAccounts = 1
	_, fs, _ := apply(t, sys, bundle(t), c, nil)
	if !slices.Contains(kinds(fs)[cliapi.FindingCeiling], "bob") || sys.ran("useradd -u 20002") {
		t.Errorf("findings %v", fs)
	}
}

func TestUIDOutsideRangeSkipped(t *testing.T) {
	sys := newFakeSys(t)
	c := cliapi.DefaultCeiling()
	c.UIDRange = [2]int{30000, 39999}
	_, fs, _ := apply(t, sys, bundle(t), c, nil)
	if !slices.Contains(kinds(fs)[cliapi.FindingCeiling], "alice") || sys.ran("useradd -u 20001") {
		t.Errorf("findings %v", fs)
	}
}

func TestAuthorizedKeysSharedCounted(t *testing.T) {
	sys := newFakeSys(t)
	sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("deploy:x:1500:1500::/home/deploy:/bin/bash\n")...)
	sys.files["/home/deploy/.ssh/authorized_keys"] = sys.files["/home/breakglass/.ssh/authorized_keys"]
	_, fs, _ := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	for _, f := range fs {
		if f.Kind == cliapi.FindingAuthorizedKeysShared && f.Subject == "deploy" && f.Detail == "1 authorized_keys entries" {
			return
		}
	}
	t.Errorf("findings %v", fs)
}

func TestReloadOnlyOnChange(t *testing.T) {
	sys := newFakeSys(t)
	b := bundle(t)
	st, _, err := apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if err != nil || sys.reloads != 1 {
		t.Fatalf("first apply: %v reloads %d", err, sys.reloads)
	}
	st, fs, err := apply(t, sys, b, cliapi.DefaultCeiling(), st)
	if err != nil || sys.reloads != 1 || len(kinds(fs)[cliapi.FindingDrift]) != 0 {
		t.Errorf("an unchanged apply reloaded (%d) or drifted (%v): %v", sys.reloads, fs, err)
	}
	// A hand-edited principals file is put back and reported fixed.
	sys.files[PrincipalsFile("alice")] = []byte("u:mallory@web\n")
	_, fs, err = apply(t, sys, b, cliapi.DefaultCeiling(), st)
	if err != nil || string(sys.files[PrincipalsFile("alice")]) != "up:alice@all\nup:alice@web\n" || sys.reloads != 2 {
		t.Errorf("drift not healed: %v %q %d", err, sys.files[PrincipalsFile("alice")], sys.reloads)
	}
	if d := kinds(fs)[cliapi.FindingDrift]; !slices.Contains(d, PrincipalsFile("alice")) {
		t.Errorf("drift findings %v", fs)
	}
}

func TestApplyFailureRestoresFiles(t *testing.T) {
	sys := newFakeSys(t)
	st, _, _ := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	before := sys.snapshot()
	b := bundle(t)
	b.Accounts = b.Accounts[:1]
	revokedKey, _ := caKey(t)
	b.RevokedKeys = []string{revokedKey}
	sys.sshdT = errors.New("exit 255")
	if _, _, err := apply(t, sys, b, cliapi.DefaultCeiling(), st); err == nil {
		t.Fatal("applied despite sshd -t")
	}
	after := sys.snapshot()
	// What could widen (or needs sshd -t) is rolled back...
	for _, p := range []string{UserCAFile, DropInFile, SudoersFile, PrincipalsFile("alice")} {
		if before[p] != after[p] {
			t.Errorf("%s changed", p)
		}
	}
	// ...what narrows applies anyway (M4): bob's principals gone, the new
	// revoked key listed.
	if _, ok := after[PrincipalsFile("bob")]; ok {
		t.Error("the rollback brought bob's principals back")
	}
	if !strings.Contains(after[RevokedKeysFile], strings.Fields(revokedKey)[1]) {
		t.Errorf("the revocation was rolled back: %q", after[RevokedKeysFile])
	}
	_ = reflect.DeepEqual
}

func TestHostCertificateMustBeOurs(t *testing.T) {
	_, ca, _ := ed25519.GenerateKey(rand.Reader)
	caS, _ := ssh.NewSignerFromKey(ca)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ours, _ := ssh.NewPublicKey(pub)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	theirs, _ := ssh.NewPublicKey(other)
	mk := func(k ssh.PublicKey, typ uint32) string {
		c := &ssh.Certificate{Key: k, CertType: typ, ValidPrincipals: []string{"web-1.example.org"}, ValidBefore: ssh.CertTimeInfinity}
		c.SignCert(rand.Reader, caS)
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c)))
	}
	b := bundle(t)
	b.HostCertificate = mk(ours, ssh.HostCert)
	if err := ValidateBundle(b, "web-1", ours); err != nil {
		t.Errorf("ours: %v", err)
	}
	b.HostCertificate = mk(theirs, ssh.HostCert)
	if err := ValidateBundle(b, "web-1", ours); err == nil {
		t.Error("another key's host certificate")
	}
	b.HostCertificate = mk(ours, ssh.UserCert)
	if err := ValidateBundle(b, "web-1", ours); err == nil {
		t.Error("a user certificate as the host certificate")
	}
}

// "Ours" is strict: the exact comment AND portcullis-users. An account
// with only one of them is never modified, locked or removed.
func TestOursNeedsCommentAndGroup(t *testing.T) {
	sys := newFakeSys(t)
	sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("bob:x:20002:20002:portcullis bob:/home/bob:/bin/bash\ncarol:x:20003:20003:Carol:/home/carol:/bin/bash\n")...)
	sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte("portcullis-users:x:999:carol\n")...)
	b := bundle(t)
	b.Accounts = append(b.Accounts[:1], cliapi.Account{Name: "bob", Kind: "person", UID: 20002, Principals: []string{"u:bob@web"}},
		cliapi.Account{Name: "carol", Kind: "person", UID: 20003, Principals: []string{"u:carol@web"}})
	_, fs, err := apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := kinds(fs)[cliapi.FindingAccountConflict]
	if !slices.Contains(conf, "bob") || !slices.Contains(conf, "carol") {
		t.Errorf("findings %v", fs)
	}
	b.Accounts = b.Accounts[:1]
	b.Locked, b.Remove = []string{"bob", "carol"}, []string{"bob", "carol"}
	apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	for _, n := range []string{"bob", "carol"} {
		if sys.ran("usermod -L -e 1 -s /usr/sbin/nologin "+n) || sys.ran("userdel "+n) || sys.ran("usermod -U -e  -s /bin/bash "+n) {
			t.Errorf("%s was changed: %v", n, sys.runs)
		}
		if _, ok := sys.files[PrincipalsFile(n)]; ok {
			t.Errorf("%s got principals", n)
		}
	}
}

// TestPrincipalsFilesOnlyNamespaced: every principals file Apply and Trust
// write holds only u:/s: principals of its own account (the host-side
// fence: no account accepts its own name, root or a bare name).
func TestPrincipalsFilesOnlyNamespaced(t *testing.T) {
	check := func(name string, sys *fakeSys) {
		t.Helper()
		n := 0
		for p, body := range sys.files {
			if !strings.HasPrefix(p, PrincipalsDir+"/") {
				continue
			}
			n++
			acct := strings.TrimPrefix(p, PrincipalsDir+"/")
			for _, l := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				if _, a, _, ok := cliapi.ParsePrincipal(l); !ok || a != acct {
					t.Errorf("%s: %s holds %q", name, p, l)
				}
			}
		}
		if n == 0 {
			t.Errorf("%s: no principals file written", name)
		}
	}
	sys := newFakeSys(t)
	if _, _, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil); err != nil {
		t.Fatal(err)
	}
	check("apply", sys)
	tsys := newFakeSys(t)
	if err := Trust(context.Background(), tsys, trustOpts(t)); err != nil {
		t.Fatal(err)
	}
	check("trust", tsys)
}

// TestInvalidRevokedKeyDroppedNotRefused (FR-H1): a revoked-key line
// that isn't a public key is dropped and reported; the bundle still
// applies (refusing it would freeze the host for good).
func TestInvalidRevokedKeyDroppedNotRefused(t *testing.T) {
	sys := newFakeSys(t)
	b := bundle(t)
	good, _ := caKey(t)
	b.RevokedKeys = []string{"", "FP:SHA256:abc", good}
	if err := ValidateBundle(b, "web-1", nil); err != nil {
		t.Fatalf("refused: %v", err)
	}
	_, fs, err := apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(sys.files[RevokedKeysFile])); strings.Count(got, "\n") != 0 || !strings.HasPrefix(got, "ssh-ed25519 ") {
		t.Errorf("revoked_keys %q (only the good key)", got)
	}
	found := false
	for _, f := range fs {
		found = found || (f.Subject == RevokedKeysFile && strings.Contains(f.Detail, "2 revoked key line(s)"))
	}
	if !found {
		t.Errorf("not reported: %+v", fs)
	}
	// A bad user CA still refuses the bundle.
	b.UserCAs = []string{"not a key"}
	if err := ValidateBundle(b, "web-1", nil); err == nil {
		t.Error("a bad user CA accepted")
	}
}

// TestCeilingNoSudoRefusesAccountsWithSudo (FR-H4): with allow_sudo off,
// a shared account that has sudo some other way (a cloud-init sudoers
// rule, the sudo / wheel group, uid 0) gets no principals file.
func TestCeilingNoSudoRefusesAccountsWithSudo(t *testing.T) {
	for name, setup := range map[string]func(sys *fakeSys){
		"a sudoers rule (sudo -l)": func(sys *fakeSys) { sys.sudoers["ubuntu"] = true },
		"sudo group": func(sys *fakeSys) {
			sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte("sudo:x:27:ubuntu\n")...)
		},
		"wheel as primary group": func(sys *fakeSys) {
			sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte("wheel:x:1000:\n")...)
		},
		"sudo -l unreadable (fail closed)": func(sys *fakeSys) {
			sys.handler["env"] = func(args []string) ([]byte, error) {
				if args[1] == "sudo" {
					return []byte("sudo: unable to resolve host"), fmt.Errorf("exit status 1")
				}
				return sys.idGroups(args[len(args)-1])
			}
		},
	} {
		sys := newFakeSys(t)
		sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n")...)
		setup(sys)
		b := bundle(t)
		b.Accounts = []cliapi.Account{{Name: "ubuntu", Kind: "shared", Principals: []string{"s:ubuntu@web"}}}
		c := cliapi.DefaultCeiling()
		c.AllowSudo = false
		_, fs, err := apply(t, sys, b, c, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := sys.files[PrincipalsFile("ubuntu")]; ok {
			t.Errorf("%s: ubuntu got a principals file under allow_sudo=false", name)
		}
		if k := kinds(fs)[cliapi.FindingCeiling]; !slices.Contains(k, "ubuntu") {
			t.Errorf("%s: not reported: %+v", name, fs)
		}
		// Allowed by the ceiling (RR-H1): only a grant the Hub marks
		// privileged gives the account principals.
		sys2 := newFakeSys(t)
		sys2.files["/etc/passwd"] = append(sys2.files["/etc/passwd"], []byte("ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n")...)
		setup(sys2)
		_, fs2, err := apply(t, sys2, b, cliapi.DefaultCeiling(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := sys2.files[PrincipalsFile("ubuntu")]; ok || !slices.Contains(kinds(fs2)[cliapi.FindingCeiling], "ubuntu") {
			t.Errorf("%s: allow_sudo on, a plain grant: principals written or not reported (%+v)", name, fs2)
		}
		sys3 := newFakeSys(t)
		sys3.files["/etc/passwd"] = append(sys3.files["/etc/passwd"], []byte("ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n")...)
		setup(sys3)
		bp := bundle(t)
		bp.Accounts = []cliapi.Account{{Name: "ubuntu", Kind: "shared", Principals: []string{"sp:ubuntu@web"}}}
		if _, _, err := apply(t, sys3, bp, cliapi.DefaultCeiling(), nil); err != nil {
			t.Fatal(err)
		}
		if _, ok := sys3.files[PrincipalsFile("ubuntu")]; !ok {
			t.Errorf("%s: allow_sudo on, a privileged grant: no principals file", name)
		}
	}
}

// TestCeilingNoSudoChecksPortcullisAccounts (review of FR-H4): a
// Portcullis account with a hand-added sudoers rule gets no principals
// under allow_sudo=false; Portcullis's own previous rule doesn't count
// (its file goes first).
func TestCeilingNoSudoChecksPortcullisAccounts(t *testing.T) {
	sys := newFakeSys(t)
	if _, _, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sys.files[SudoersFile]), "alice ") {
		t.Fatalf("no Portcullis sudo for alice: %q", sys.files[SudoersFile])
	}
	c := cliapi.DefaultCeiling()
	c.AllowSudo = false
	if _, _, err := apply(t, sys, bundle(t), c, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := sys.files[PrincipalsFile("alice")]; !ok {
		t.Error("alice lost her principals for Portcullis's own (previous) sudo rule")
	}
	sys.sudoers["alice"] = true // a hand-added rule elsewhere
	_, fs, err := apply(t, sys, bundle(t), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sys.files[PrincipalsFile("alice")]; ok {
		t.Error("alice kept her principals with a foreign sudo rule under allow_sudo=false")
	}
	if k := kinds(fs)[cliapi.FindingCeiling]; !slices.Contains(k, "alice") {
		t.Errorf("not reported: %+v", fs)
	}
}

// TestReusedNameNotUnlocked (final review M11): an account Portcullis made
// for a former person keeps its uid; a bundle naming the name with
// another uid never unlocks it (account_conflict) — the Hub removes it
// first.
func TestReusedNameNotUnlocked(t *testing.T) {
	sys := newFakeSys(t)
	sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("alice:x:20009:20009:portcullis alice:/home/alice:/usr/sbin/nologin\n")...)
	sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte("portcullis-users:x:999:alice\n")...)
	prev := &State{Locked: []string{"alice"}}
	_, fs, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), prev)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(kinds(fs)[cliapi.FindingAccountConflict], "alice") {
		t.Errorf("findings %v", fs)
	}
	if _, ok := sys.files[PrincipalsFile("alice")]; ok || sys.ran("usermod -U -e  -s /bin/bash alice") {
		t.Error("the former person's account was unlocked or given principals")
	}
	if strings.Contains(string(sys.files[SudoersFile]), "alice") {
		t.Error("sudo for the former person's account")
	}
}

// L-B2: a shared account that doesn't exist (and isn't created) gets no
// principals file — a later local account of that name would get the
// grant at once.
func TestMissingSharedAccountNoPrincipals(t *testing.T) {
	sys := newFakeSys(t)
	_, fs, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(kinds(fs)[cliapi.FindingAccountMissing], "deploy") {
		t.Errorf("findings %v", fs)
	}
	if _, ok := sys.files[PrincipalsFile("deploy")]; ok {
		t.Error("principals written for a missing shared account")
	}
}

// L-B4: --ca-file, read by root on every agent start, must be absolute
// and root's alone (the file and every parent).
func TestCheckRootFile(t *testing.T) {
	sys := newFakeSys(t)
	if err := CheckRootFile(sys, "/etc/ssl/ca.pem"); err != nil {
		t.Errorf("root-owned: %v", err)
	}
	if err := CheckRootFile(sys, "ca.pem"); err == nil {
		t.Error("a relative path accepted")
	}
	sys.owners["/home/alice/ca.pem"] = ownerOf{uid: 1000, mode: 0o644}
	if err := CheckRootFile(sys, "/home/alice/ca.pem"); err == nil {
		t.Error("a user's file accepted")
	}
	sys.owners["/tmp"] = ownerOf{uid: 0, mode: 0o777}
	if err := CheckRootFile(sys, "/tmp/ca.pem"); err == nil {
		t.Error("a file in a world-writable directory accepted")
	}
	sys.links["/etc/ssl/link.pem"] = "/home/alice/ca.pem"
	if err := CheckRootFile(sys, "/etc/ssl/link.pem"); err == nil {
		t.Error("a symlink to a user's file accepted")
	}
}

// RR-M2: a failed apply's rollback never brings back a sudo rule the new
// bundle removed.
func TestApplyFailureKeepsSudoRemoved(t *testing.T) {
	sys := newFakeSys(t)
	b := bundle(t)
	b.Accounts[1].Sudo, b.Accounts[1].Principals = true, []string{"up:bob@web"} // bob had sudo (an approved grant)
	st, _, err := apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if err != nil || !strings.Contains(string(sys.files[SudoersFile]), "bob ALL") {
		t.Fatalf("setup: %v %q", err, sys.files[SudoersFile])
	}
	b2 := bundle(t) // bob without sudo
	b2.Serial++
	sys.sshdT = errors.New("exit 255")
	if _, _, err := apply(t, sys, b2, cliapi.DefaultCeiling(), st); err == nil {
		t.Fatal("applied despite sshd -t")
	}
	got := string(sys.files[SudoersFile])
	if strings.Contains(got, "bob ALL") || !strings.Contains(got, "alice ALL") {
		t.Errorf("sudoers after the rollback: %q", got)
	}
}

// RR-H1: Portcullis's own old rule for an account the bundle no longer
// gives sudo doesn't count as "sudo by other means" (it goes first).
func TestOwnOldSudoRuleNotInTheWay(t *testing.T) {
	sys := newFakeSys(t)
	sys.files[SudoersFile] = SudoersBody([]string{"alice", "bob"})
	sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("bob:x:20002:20002:portcullis bob:/home/bob:/bin/bash\n")...)
	sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte("portcullis-users:x:999:bob\n")...)
	if _, fs, err := apply(t, sys, bundle(t), cliapi.DefaultCeiling(), nil); err != nil || slices.Contains(kinds(fs)[cliapi.FindingCeiling], "bob") {
		t.Fatalf("%v %+v", err, fs)
	}
	if _, ok := sys.files[PrincipalsFile("bob")]; !ok {
		t.Error("bob refused for Portcullis's own old rule")
	}
	if strings.Contains(string(sys.files[SudoersFile]), "bob") {
		t.Error("bob kept sudo")
	}
}

// RR-M4, N-L2, N-L3: root-equivalent groups and doas rules count as sudo;
// no sudo installed means no sudoers rule; "may run" wins over the other
// phrase.
func TestSudoViaMore(t *testing.T) {
	via := func(setup func(sys *fakeSys)) string {
		sys := newFakeSys(t)
		sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("ansible:x:1500:1500::/home/ansible:/bin/bash\n")...)
		sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte("ansible:x:1500:\n")...)
		setup(sys)
		acc, err := loadAccounts(sys)
		if err != nil {
			t.Fatal(err)
		}
		return acc.sudoVia(context.Background(), sys, "ansible")
	}
	for _, g := range []string{"docker", "lxd", "incus", "libvirt", "disk"} {
		if v := via(func(sys *fakeSys) {
			sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte(g+":x:990:ansible\n")...)
		}); v == "" {
			t.Errorf("the %s group isn't sudo", g)
		}
	}
	if v := via(func(sys *fakeSys) { sys.files["/etc/doas.conf"] = []byte("permit nopass ansible as root\n") }); v == "" {
		t.Error("a doas rule isn't sudo")
	}
	if v := via(func(sys *fakeSys) {
		sys.files["/etc/group"] = append(sys.files["/etc/group"], []byte("ops2:x:991:ansible\n")...)
		sys.files["/etc/doas.conf"] = []byte("# none\npermit persist :ops2\n")
	}); v == "" {
		t.Error("a doas group rule isn't sudo")
	}
	if v := via(func(sys *fakeSys) { sys.files["/etc/doas.conf"] = []byte("permit :wheelz\n") }); v != "" {
		t.Errorf("an unrelated doas rule: %q", v)
	}
	for _, p := range []string{"/etc/sudoers", "/etc/sudoers.d"} {
		if v := via(func(sys *fakeSys) {
			delete(sys.files, "/usr/bin/sudo")
			if p == "/etc/sudoers.d" {
				sys.dirs[p] = true
			} else {
				sys.files[p] = []byte("root ALL=(ALL) ALL\n")
			}
		}); v == "" {
			t.Errorf("%s without a sudo command found isn't sudo", p)
		}
	}
	if v := via(func(sys *fakeSys) {
		delete(sys.files, "/usr/bin/sudo")
		sys.handler["env"] = func(args []string) ([]byte, error) {
			if args[1] == "sudo" {
				t.Error("sudo -l run without sudo installed")
			}
			return sys.idGroups(args[len(args)-1])
		}
	}); v != "" {
		t.Errorf("no sudo installed: %q", v)
	}
	if v := via(func(sys *fakeSys) {
		sys.handler["env"] = func(args []string) ([]byte, error) {
			if args[1] == "sudo" {
				return []byte("User ansible may run the following commands on web-1:\n    (ALL) /bin/echo is not allowed to run sudo on\n"), nil
			}
			return sys.idGroups(args[len(args)-1])
		}
	}); v == "" {
		t.Error("a rule quoting the other phrase read as no sudo")
	}
	if v := via(func(sys *fakeSys) {
		sys.handler["env"] = func(args []string) ([]byte, error) {
			if args[1] == "id" {
				return nil, errors.New("exit 1")
			}
			return nil, nil
		}
	}); v == "" {
		t.Error("id failing isn't fail closed")
	}
	if v := via(func(sys *fakeSys) {
		sys.handler["env"] = func(args []string) ([]byte, error) {
			if args[1] == "sudo" {
				return []byte("Sudoers-Eintrag gefunden\n"), nil
			}
			return sys.idGroups(args[len(args)-1])
		}
	}); v == "" {
		t.Error("unexpected sudo output isn't fail closed")
	}
}

// Ruling RR3: on an account with sudo by other means only the approved
// (sp:/up:) principals are written.
func TestSudoCapableKeepsOnlyApprovedPrincipals(t *testing.T) {
	sys := newFakeSys(t)
	sys.files["/etc/passwd"] = append(sys.files["/etc/passwd"], []byte("ansible:x:1500:1500::/home/ansible:/bin/bash\n")...)
	sys.sudoers["ansible"] = true
	b := bundle(t)
	b.Accounts = []cliapi.Account{{Name: "ansible", Kind: "shared", Principals: []string{"sp:ansible@all", "s:ansible@web"}}}
	_, fs, err := apply(t, sys, b, cliapi.DefaultCeiling(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(sys.files[PrincipalsFile("ansible")]); got != "sp:ansible@all\n" {
		t.Errorf("principals %q", got)
	}
	if !slices.Contains(kinds(fs)[cliapi.FindingCeiling], "ansible") {
		t.Errorf("the left-out principal isn't reported: %+v", fs)
	}
}
