package hub

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/state"
)

// fakeSSHDir answers the directory's group check: groups → id; own =
// groups the caller is in (refused for delegates).
type fakeSSHDir struct {
	ids map[string]int
	own map[string]bool
}

func (d fakeSSHDir) CheckSSHGrantGroup(_ context.Context, c *directory.Caller, g string) (int, error) {
	id, ok := d.ids[g]
	if !ok {
		return 0, statusErr(404, "no group %s", g)
	}
	if !c.Admin && d.own[g] {
		return 0, statusErr(403, directory.TextSSHOwnGroup)
	}
	return id, nil
}

func newGrantFixture(t *testing.T) *signFixture {
	t.Helper()
	f := newSignFixture(t, "alice", "security_key")
	f.h.SetSSHDirectory(fakeSSHDir{ids: map[string]int{"ssh_web": 11, "ssh_admins": 12, "ssh_deploy": 13, "ssh_ops": 14}})
	f.h.SetFreshAuth(ListenerHub, fakeFresh{method: "security_key"})
	f.h.SetFreshAuthReadyForTest(true)
	f.h.mu.Lock()
	g := f.h.st.SSH.HostGroups["web"]
	g.Delegable = true
	f.h.st.SSH.HostGroups["web"] = g
	f.h.st.SSH.HostGroups["db"] = state.SSHHostGroup{}
	f.h.mu.Unlock()
	return f
}

var (
	asAdmin    = &directory.Caller{User: "root", Admin: true}
	asDelegate = &directory.Caller{User: "sam", Perms: map[string]bool{directory.PermSSHAccess: true}}
	asAI       = &directory.Caller{User: "root", Admin: true, Via: directory.ViaAI, Client: "portcullis-ai-claude-code"}
)

func TestSSHAccessHolderNonPrivilegedOnly(t *testing.T) {
	f := newGrantFixture(t)
	g := state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "full"}
	_, err := f.h.SaveGrant(context.Background(), asDelegate, g, "ssh_ops", nil)
	if err == nil || err.Error() != TextOnlyAdminsPrivileged {
		t.Errorf("sudo by a delegate = %v", err)
	}
	for name, edit := range map[string]func(*state.SSHGrant){
		"root":  func(g *state.SSHGrant) { g.Sudo, g.Accounts = "none", []string{"root"} },
		"agent": func(g *state.SSHGrant) { g.Sudo, g.AgentForwarding = "none", true },
		"all":   func(g *state.SSHGrant) { g.Sudo, g.HostGroup = "none", "all" },
	} {
		x := g
		edit(&x)
		if _, err := f.h.SaveGrant(context.Background(), asDelegate, x, "", nil); err == nil {
			t.Errorf("%s by a delegate accepted", name)
		}
	}
	g.Sudo = "none"
	saved, err := f.h.SaveGrant(context.Background(), asDelegate, g, "", nil)
	if err != nil || saved.GroupID != 14 || !strings.HasPrefix(saved.ID, "g-") {
		t.Fatalf("plain grant by a delegate = %+v %v", saved, err)
	}
	// A widening edit by the delegate is refused; narrowing is fine.
	w := *saved
	w.PortForwarding = true
	if _, err := f.h.SaveGrant(context.Background(), asDelegate, w, "", nil); err == nil || err.Error() != TextOnlyAdminsWiden {
		t.Errorf("widening edit = %v", err)
	}
	n := *saved
	n.TTLHours = 2
	if _, err := f.h.SaveGrant(context.Background(), asDelegate, n, "", nil); err != nil {
		t.Errorf("narrowing edit = %v", err)
	}
	// Delegates can't touch privileged grants at all.
	if err := f.h.DeleteGrant(context.Background(), asDelegate, "g-admins"); err == nil {
		t.Error("a delegate deleted a privileged grant")
	}
	if err := f.h.DeleteGrant(context.Background(), asDelegate, saved.ID); err != nil {
		t.Errorf("delete own plain grant = %v", err)
	}
}

func TestSSHAccessHolderNonDelegableHostGroup403(t *testing.T) {
	f := newGrantFixture(t)
	g := state.SSHGrant{Group: "ssh_ops", HostGroup: "db", Accounts: []string{"{username}"}}
	if _, err := f.h.SaveGrant(context.Background(), asDelegate, g, "", nil); sshStatusOf(err) != 403 && !strings.Contains(err.Error(), "delegable") {
		t.Errorf("db = %v", err)
	}
	if _, err := f.h.PreviewGrant(context.Background(), asDelegate, g); err == nil {
		t.Error("a delegate previewed a non-delegable host group")
	}
	nobody := &directory.Caller{User: "eve"}
	if _, err := f.h.SaveGrant(context.Background(), nobody, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"deploy"}}, "", nil); err == nil {
		t.Error("someone without ssh_access saved a grant")
	}
}

func TestSSHAccessHolderOwnGroup403Hub(t *testing.T) {
	f := newGrantFixture(t)
	f.h.SetSSHDirectory(fakeSSHDir{ids: map[string]int{"ssh_ops": 14}, own: map[string]bool{"ssh_ops": true}})
	_, err := f.h.SaveGrant(context.Background(), asDelegate, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"{username}"}}, "", nil)
	if err == nil || err.Error() != directory.TextSSHOwnGroup {
		t.Errorf("%v", err)
	}
}

func TestPrivilegedNeedsAdminFreshAndTypedName(t *testing.T) {
	f := newGrantFixture(t)
	p := &freshauth.Proof{Code: "c"}
	g := state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "full"}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, g, "", p); err == nil || !strings.Contains(err.Error(), "type the group's name") {
		t.Errorf("no typed name = %v", err)
	}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, g, "ssh_ops", nil); err == nil {
		t.Error("no fresh sign-in accepted")
	}
	f.h.SetFreshAuthReadyForTest(false)
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, g, "ssh_ops", p); err == nil {
		t.Error("fresh auth unavailable accepted")
	}
	f.h.SetFreshAuthReadyForTest(true)
	saved, err := f.h.SaveGrant(context.Background(), asAdmin, g, "ssh_ops", p)
	if err != nil {
		t.Fatal(err)
	}
	// A plain widening edit needs the fresh sign-in too (no typed name).
	plain, _ := f.h.SaveGrant(context.Background(), asAdmin, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"deploy"}}, "", nil)
	if plain == nil {
		t.Fatal("a new plain grant by an admin needs no fresh sign-in")
	}
	w := *plain
	w.Accounts = append(w.Accounts, "backup")
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, w, "", nil); err == nil {
		t.Error("an admin's widening edit without a fresh sign-in")
	}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, w, "", p); err != nil {
		t.Errorf("widening with a fresh sign-in = %v", err)
	}
	_ = saved
}

func TestGrantAuditBeforeAfter(t *testing.T) {
	f := newGrantFixture(t)
	p := &freshauth.Proof{Code: "c"}
	saved, err := f.h.SaveGrant(context.Background(), asAdmin, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "full"}, "ssh_ops", p)
	if err != nil {
		t.Fatal(err)
	}
	e := f.audit.lastOf("ssh.grant.create")
	if e.Target != saved.ID || !strings.Contains(e.Detail, "- → ssh_ops→web") || !strings.Contains(e.Detail, "privileged=true") || e.Actor != "root" {
		t.Errorf("create audit %+v", e)
	}
	d, _ := f.h.SaveGrant(context.Background(), asDelegate, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"deploy"}}, "", nil)
	if d == nil {
		t.Fatal("delegate grant")
	}
	if e := f.audit.lastOf("ssh.grant.create"); !strings.HasSuffix(e.Detail, "as ssh_access") || e.Actor != "sam" {
		t.Errorf("delegate audit %+v", e)
	}
	n := *d
	n.TTLHours = 1
	f.h.SaveGrant(context.Background(), asDelegate, n, "", nil)
	if e := f.audit.lastOf("ssh.grant.update"); !strings.Contains(e.Detail, "ttl=0 pf=false af=false → ssh_ops→web") {
		t.Errorf("update audit %+v", e)
	}
}

func TestGrantNeverViaMCPPrivileged(t *testing.T) {
	f := newGrantFixture(t)
	p := &freshauth.Proof{Code: "c"}
	_, err := f.h.SaveGrant(context.Background(), asAI, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "full"}, "ssh_ops", p)
	if sshStatusOf(err) != 403 && (err == nil || !strings.Contains(err.Error(), "AI")) {
		t.Errorf("privileged via AI = %v", err)
	}
	if _, err := f.h.SaveGrant(context.Background(), asAI, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"deploy"}}, "", nil); err != nil {
		t.Errorf("plain via AI = %v", err)
	}
}

func TestSharedAccountNamedLikePersonRefused(t *testing.T) {
	f := newGrantFixture(t)
	_, err := f.h.SaveGrant(context.Background(), asAdmin, state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"bob"}}, "", nil)
	if sshStatusOf(err) != 409 && (err == nil || !strings.Contains(err.Error(), "username")) {
		t.Errorf("shared account bob = %v", err)
	}
}

func TestRevokeOnLeave(t *testing.T) {
	f := newGrantFixture(t)
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if err != nil || len(ans.Certificates) != 2 {
		t.Fatalf("%+v %v", ans, err)
	}
	// Another login (another key) only for all.
	other := newSignFixture(t, "alice", "security_key")
	_ = other
	f.people.set(func(p *sshPeople) { delete(p.users["alice"], "ssh_web") })
	f.compile(t)
	keys := f.h.RevokedKeys()
	if len(keys) != 1 || keys[0] != cliapi.NormalAuthorizedKey(f.signer.PublicKey()) {
		t.Fatalf("revoked %v", keys)
	}
	l, _ := f.h.sshRevokedList()
	if l[0].Actor != "-" || l[0].Reason != "left ssh_web" {
		t.Errorf("entry %+v", l[0])
	}
	if e := f.audit.lastOf("ssh.certificate.revoke"); e.Actor != "-" || e.Target != "alice" || e.Result != "ok" {
		t.Errorf("audit %+v", e)
	}
	// Still in ssh_admins: an all-only certificate (another key) stays.
	f.people.set(func(p *sshPeople) { p.users["alice"]["ssh_web"] = 11 })
	f.compile(t)
	_, priv := newSigner(t)
	ans, err = f.h.SignSSH(context.Background(), f.request(t, priv, "all"), "192.0.2.51")
	if err != nil || len(ans.Certificates) != 1 {
		t.Fatalf("%+v %v", ans, err)
	}
	f.people.set(func(p *sshPeople) { delete(p.users["alice"], "ssh_web") })
	f.compile(t)
	for _, k := range f.h.RevokedKeys() {
		if k == cliapi.NormalAuthorizedKey(priv.PublicKey()) {
			t.Error("the all certificate's key was revoked on leaving ssh_web")
		}
	}
}

func TestRevokeOnLeaveKeyUnknown(t *testing.T) {
	f := newGrantFixture(t)
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	os.Remove(f.h.keysPath()) // keys.json lost
	f.people.set(func(p *sshPeople) { delete(p.users["alice"], "ssh_web") })
	f.compile(t)
	fp := cliapi.Fingerprint(f.signer.PublicKey())
	l, _ := f.h.sshRevokedList()
	if len(l) != 1 || l[0].FP != fp || l[0].Key != "" {
		t.Fatalf("revoked %+v", l)
	}
	if e := f.audit.lastOf("ssh.certificate.revoke"); e.Result == "ok" || !strings.Contains(e.Error, TextRevocationIncomplete+" "+fp) {
		t.Errorf("audit %+v", e)
	}
	if _, ok := f.h.sshRevocationsIncomplete()[fp]; !ok {
		t.Error("no doctor input")
	}
	// The account side: alice no longer has web principals on web-1.
	for _, a := range f.h.sshCompiled().Bundles["web-1"].Accounts {
		if a.Name == "alice" {
			for _, p := range a.Principals {
				if p == "u:alice@web" {
					t.Error("alice still has u:alice@web")
				}
			}
		}
	}
	// The fingerprint is never signed again.
	f.people.set(func(p *sshPeople) { p.users["alice"]["ssh_web"] = 11 })
	f.compile(t)
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.52"); sshStatusOf(err) != 403 {
		t.Errorf("signing a fingerprint-only revoked key = %v", err)
	}
}

func TestSignKeyRecordFailureIssuesNothing(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	os.MkdirAll(f.h.keysPath(), 0o700) // keys.json can't be written
	_, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if sshStatusOf(err) != 503 {
		t.Errorf("%v", err)
	}
	if len(f.ssh.signs) != 0 {
		t.Error("enroll signed although the key couldn't be recorded")
	}
	if strings.Contains(err.Error(), "AAAA") {
		t.Error("key material in the error")
	}
}

func TestKeysKeptWhileRevoked(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	fp := cliapi.Fingerprint(f.signer.PublicKey())
	f.h.RevokeFingerprints("root", "lost", []string{fp}, "alice")
	f.h.pruneKeys(f.now.Add(100 * 24 * time.Hour))
	if f.h.issuedKey(fp) == "" {
		t.Error("a revoked key's record was pruned")
	}
	f.h.sshrev.mu.Lock()
	f.h.saveRevokedLocked(nil)
	f.h.sshrev.mu.Unlock()
	f.h.pruneKeys(f.now.Add(100 * 24 * time.Hour))
	if f.h.issuedKey(fp) != "" {
		t.Error("an old, unrevoked key's record kept")
	}
}
