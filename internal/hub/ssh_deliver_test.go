package hub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

func TestCompileDeliversChangedRolesOnly(t *testing.T) {
	f := newSSHFixture(t)
	f.compile(t)
	puts, _ := f.ssh.counts()
	if puts != 2 {
		t.Fatalf("first compile put %d roles, want hg-all and hg-web", puts)
	}
	if got := strings.Join(f.ssh.roles["web"].Principals, ","); got != "s:deploy@web,u:alice@web,u:bob@web" {
		t.Errorf("hg-web %s", got)
	}
	f.compile(t)
	if p, _ := f.ssh.counts(); p != 2 {
		t.Errorf("an unchanged compile put %d more roles", p-2)
	}
	// bob leaves ssh_web: only hg-web changes.
	f.people.set(func(p *sshPeople) { delete(p.users["bob"], "ssh_web") })
	f.compile(t)
	if p, _ := f.ssh.counts(); p != 3 || f.ssh.puts[2] != "web" {
		t.Errorf("puts %v", f.ssh.puts)
	}
}

func TestCompileDeletesStaleRole(t *testing.T) {
	f := newSSHFixture(t)
	f.ssh.roles["old"] = cliapi.RoleSpec{Principals: []string{"u:x@old"}}
	f.compile(t)
	if _, ok := f.ssh.roles["old"]; ok {
		t.Error("stale hg-old kept")
	}
	f.h.mu.Lock()
	f.h.st.SSH.Grants = f.h.st.SSH.Grants[:1] // only ssh_web → web
	f.h.mu.Unlock()
	f.compile(t)
	if _, ok := f.ssh.roles["all"]; ok {
		t.Error("hg-all kept without grants")
	}
	if _, ok := f.ssh.roles["web"]; !ok {
		t.Error("hg-web deleted")
	}
}

func TestEnsureRoleCurrentReadBackMismatchFails(t *testing.T) {
	f := newSSHFixture(t)
	f.compile(t)
	if err := f.h.ensureRoleCurrent(context.Background(), "web"); err != nil {
		t.Fatalf("current role: %v", err)
	}
	// Vault now stores something else (an operator edit, a policy that
	// dropped a field): the read-back differs → fail closed.
	f.ssh.mangle = func(hg string, r *cliapi.RoleSpec) { r.MaxTTLSeconds = 43200 }
	f.h.sshrt.mu.Lock()
	delete(f.h.sshrt.roles, "web") // the Hub must re-put
	f.h.sshrt.mu.Unlock()
	if err := f.h.ensureRoleCurrent(context.Background(), "web"); err == nil {
		t.Error("a role whose read-back differs is current")
	}
	if f.h.sshrt.roleErr["web"] == "" {
		t.Error("no doctor input")
	}
	if err := f.h.ensureRoleCurrent(context.Background(), "nope"); err == nil {
		t.Error("a host group without a role is current")
	}
}

func TestCompileMembershipUnavailableKeepsLast(t *testing.T) {
	f := newSSHFixture(t)
	f.compile(t)
	before := f.h.sshCompiled()
	puts, dels := f.ssh.counts()
	f.people.set(func(p *sshPeople) { p.err = errDirDown })
	if err := f.h.compileSSH(context.Background()); err == nil {
		t.Fatal("compile with the directory down succeeded")
	}
	if f.h.sshCompiled() != before {
		t.Error("the last compilation was replaced")
	}
	if p, d := f.ssh.counts(); p != puts || d != dels {
		t.Error("roles were touched with the directory down")
	}
	if f.h.sshrt.dirErr == "" {
		t.Error("no doctor input")
	}
}

func TestSerialBumpsOnBundleChangeOnly(t *testing.T) {
	f := newSSHFixture(t)
	f.compile(t)
	s1 := f.h.st.SSH.Hosts["web-1"].Serial
	if s1 == 0 || f.h.sshCompiled().Bundles["web-1"].Serial != s1 {
		t.Fatalf("serial %d", s1)
	}
	ch := f.h.sshChanged()
	f.now = f.now.Add(time.Minute)
	f.compile(t)
	if s := f.h.st.SSH.Hosts["web-1"].Serial; s != s1 {
		t.Errorf("an unchanged bundle moved %d → %d", s1, s)
	}
	select {
	case <-ch:
		t.Error("long-polls woken without a change")
	default:
	}
	f.people.set(func(p *sshPeople) { delete(p.users["alice"], "ssh_admins") })
	f.compile(t)
	if s := f.h.st.SSH.Hosts["web-1"].Serial; s <= s1 {
		t.Errorf("a changed bundle kept serial %d", s)
	}
	select {
	case <-ch:
	default:
		t.Error("long-polls not woken")
	}
}

func TestHostCertRenewedAtOneThird(t *testing.T) {
	f := newSSHFixture(t)
	f.compile(t)
	if len(f.ssh.hostSigns) != 1 || f.ssh.hostSigns[0].HostID != "web-1" || strings.Join(f.ssh.hostSigns[0].Principals, ",") != "web-1.example.com,192.0.2.11" {
		t.Fatalf("enrol-time host certificate %+v", f.ssh.hostSigns)
	}
	cert := f.h.st.SSH.Hosts["web-1"].HostCert
	if f.h.sshCompiled().Bundles["web-1"].HostCertificate != cert || cert == "" {
		t.Error("the bundle doesn't carry the host certificate")
	}
	f.now = f.now.Add(59 * 24 * time.Hour) // 31 days left of 90: more than a third
	f.compile(t)
	if len(f.ssh.hostSigns) != 1 {
		t.Error("renewed too early")
	}
	f.now = f.now.Add(2 * 24 * time.Hour) // 29 days left: ≤ ⅓
	f.compile(t)
	if len(f.ssh.hostSigns) != 2 || f.h.st.SSH.Hosts["web-1"].HostCert == cert {
		t.Error("not renewed at ⅓ remaining life")
	}
	if f.audit.lastOf("ssh.host_certificate.issue").Target != "web-1" {
		t.Error("renewal not audited")
	}
}

func TestCompileOffWritesNothing(t *testing.T) {
	f := newSSHFixture(t)
	f.h.mu.Lock()
	f.h.st.SSH.Settings.Enabled = false
	f.h.mu.Unlock()
	f.compile(t)
	if p, _ := f.ssh.counts(); p != 0 || f.h.sshCompiled() != nil {
		t.Error("SSH off wrote roles")
	}
}

func TestSSHSharedAccount(t *testing.T) {
	f := newSSHFixture(t)
	if !f.h.SSHSharedAccount("deploy") || f.h.SSHSharedAccount("alice") || f.h.SSHSharedAccount("{username}") {
		t.Error("SSHSharedAccount")
	}
}
