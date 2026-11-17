package hub

import (
	"context"
	"os"
	"slices"
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
	// (On "db": a new grant beside ssh_ops's web grant is judged against
	// it, M5 — see TestSecondGrantCantWiden.)
	plain, _ := f.h.SaveGrant(context.Background(), asAdmin, state.SSHGrant{Group: "ssh_ops", HostGroup: "db", Accounts: []string{"deploy"}}, "", nil)
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
	// (Another group: a second ssh_ops→web grant adding deploy would widen
	// the first, which a delegate can't, M5.)
	d, _ := f.h.SaveGrant(context.Background(), asDelegate, state.SSHGrant{Group: "ssh_admins", HostGroup: "web", Accounts: []string{"deploy"}}, "", nil)
	if d == nil {
		t.Fatal("delegate grant")
	}
	if e := f.audit.lastOf("ssh.grant.create"); !strings.HasSuffix(e.Detail, "as ssh_access") || e.Actor != "sam" {
		t.Errorf("delegate audit %+v", e)
	}
	n := *d
	n.TTLHours = 1
	f.h.SaveGrant(context.Background(), asDelegate, n, "", nil)
	if e := f.audit.lastOf("ssh.grant.update"); !strings.Contains(e.Detail, "ttl=0 pf=false af=false → ssh_admins→web") {
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
	// L-C2: a restarted Hub (same data directory) still reports it.
	h2, err := newTestHub(Config{ProjectDir: t.TempDir(), ProjectHostDir: "/hp", DataDir: f.h.cfg.DataDir, Domain: "example.org"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h2.Wait)
	if _, ok := h2.sshRevocationsIncomplete()[fp]; !ok {
		t.Error("the incomplete revocation is gone after a restart")
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
	// FR-H1: every bundle still carries only parseable revoked keys (a
	// fingerprint-only entry would make every managed host refuse it).
	f.compile(t) // the revocation was recorded after the first compile
	for id, b := range f.h.sshCompiled().Bundles {
		for _, k := range b.RevokedKeys {
			if _, _, err := cliapi.ParseAuthorizedKey(k); err != nil {
				t.Errorf("bundle %s carries a revoked key that isn't a public key: %q", id, k)
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
	f.h.pruneKeys(f.clock().Add(100 * 24 * time.Hour))
	if f.h.issuedKey(fp) == "" {
		t.Error("a revoked key's record was pruned")
	}
	f.h.sshrev.mu.Lock()
	f.h.saveRevokedLocked(nil)
	f.h.sshrev.mu.Unlock()
	f.h.pruneKeys(f.clock().Add(100 * 24 * time.Hour))
	if f.h.issuedKey(fp) != "" {
		t.Error("an old, unrevoked key's record kept")
	}
}

// TestRevokeOnLosingOnePrincipal (FR-H2): bob holds u:bob@web (ssh_web)
// and s:deploy@web (ssh_deploy) in one certificate; leaving ssh_deploy
// revokes the key although u:bob@web is still his (the host can't fence
// one holder out of a shared principal).
func TestRevokeOnLosingOnePrincipal(t *testing.T) {
	f := newGrantFixture(t)
	f.v.res.User = "bob"
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer, "web"), "192.0.2.60")
	if err != nil || len(ans.Certificates) != 1 || !slices.Contains(ans.Certificates[0].Principals, "s:deploy@web") || !slices.Contains(ans.Certificates[0].Principals, "u:bob@web") {
		t.Fatalf("%+v %v", ans, err)
	}
	f.people.set(func(p *sshPeople) { delete(p.users["bob"], "ssh_deploy") })
	f.compile(t)
	keys := f.h.RevokedKeys()
	if len(keys) != 1 || keys[0] != cliapi.NormalAuthorizedKey(f.signer.PublicKey()) {
		t.Fatalf("revoked %v (want bob's key: s:deploy@web is gone)", keys)
	}
	l, _ := f.h.sshRevokedList()
	if l[0].Reason != "left ssh_deploy" && !strings.Contains(l[0].Reason, "ssh_deploy") {
		t.Errorf("reason %q", l[0].Reason)
	}
	// Signing in again gives only what bob still holds.
	f.compile(t)
	_, s2 := newSigner(t)
	ans, err = f.h.SignSSH(context.Background(), f.request(t, s2, "web"), "192.0.2.61")
	if err != nil || len(ans.Certificates) != 1 || slices.Contains(ans.Certificates[0].Principals, "s:deploy@web") {
		t.Fatalf("after leaving: %+v %v", ans, err)
	}
}

// TestCloudDefaultAccountGrantIsPrivileged (FR-H4): a shared grant of a
// cloud image's default user is privileged — refused for a delegate and
// through the AI, and an administrator needs the typed name + fresh
// sign-in.
func TestCloudDefaultAccountGrantIsPrivileged(t *testing.T) {
	f := newGrantFixture(t)
	g := state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"ubuntu"}, Sudo: "none"}
	if _, err := f.h.SaveGrant(context.Background(), asDelegate, g, "", nil); err == nil || err.Error() != TextOnlyAdminsPrivileged {
		t.Errorf("delegate: %v", err)
	}
	if _, err := f.h.SaveGrant(context.Background(), asAI, g, "ssh_ops", nil); err == nil {
		t.Error("AI accepted")
	}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, g, "", nil); sshStatusOf(err) != 400 {
		t.Errorf("admin without the typed name: %v", err)
	}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, g, "ssh_ops", nil); sshStatusOf(err) != 403 {
		t.Errorf("admin without a fresh sign-in: %v", err)
	}
}

// TestSecondGrantCantWiden (M5): a new grant for the same group and host
// group is compared with the existing ones: extra accounts or port
// forwarding need a fresh sign-in from an administrator, and are refused
// for a delegate and through the AI — as the equivalent edit is.
func TestSecondGrantCantWiden(t *testing.T) {
	f := newGrantFixture(t)
	g := state.SSHGrant{Group: "ssh_web", HostGroup: "web", Accounts: []string{"{username}", "deploy"}, Sudo: "none"}
	if _, err := f.h.SaveGrant(context.Background(), asAI, g, "", nil); err == nil {
		t.Error("AI: a second grant adding deploy accepted")
	}
	if _, err := f.h.SaveGrant(context.Background(), asDelegate, g, "", nil); err == nil || err.Error() != TextOnlyAdminsWiden {
		t.Errorf("delegate: %v", err)
	}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, g, "", nil); sshStatusOf(err) != 403 {
		t.Errorf("admin without a fresh sign-in: %v", err)
	}
	pf := state.SSHGrant{Group: "ssh_web", HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "none", PortForwarding: true}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, pf, "", nil); sshStatusOf(err) != 403 {
		t.Errorf("admin, port forwarding, no fresh sign-in: %v", err)
	}
	// The same access again (no widening) needs nothing more.
	same := state.SSHGrant{Group: "ssh_web", HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "none"}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, same, "", nil); err != nil {
		t.Errorf("a non-widening second grant: %v", err)
	}
	// With the fresh sign-in the admin may.
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, g, "", &freshauth.Proof{Code: "c"}); err != nil {
		t.Errorf("admin with a fresh sign-in: %v", err)
	}
}

// L-C4: a delegate's preview runs the directory's group check (a group
// they couldn't grant to isn't previewed: it lists members).
func TestDelegatePreviewChecksGroup(t *testing.T) {
	f := newGrantFixture(t)
	f.h.SetSSHDirectory(fakeSSHDir{ids: map[string]int{"ssh_web": 11, "ssh_ops": 14}, own: map[string]bool{"ssh_ops": true}})
	g := state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"{username}"}}
	if _, err := f.h.PreviewGrant(context.Background(), asDelegate, g); err == nil || err.Error() != directory.TextSSHOwnGroup {
		t.Errorf("delegate preview of a refused group = %v", err)
	}
	if _, err := f.h.PreviewGrant(context.Background(), asAdmin, g); err != nil {
		t.Errorf("admin preview = %v", err)
	}
}

// L-C1: fingerprints named as one person's are checked: another person's
// key isn't revoked under their name.
func TestRevokeOfChecksPerson(t *testing.T) {
	f := newGrantFixture(t)
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	fp := cliapi.Fingerprint(f.signer.PublicKey())
	a := directory.Actor{User: "root"}
	if n, err := f.h.RevokeSSHCertificatesOf(a, "bob", []string{fp}, ""); err == nil || n != 0 {
		t.Errorf("alice's key revoked as bob's: %d %v", n, err)
	}
	if keys := f.h.RevokedKeys(); len(keys) != 0 {
		t.Errorf("revoked %v", keys)
	}
	if n, err := f.h.RevokeSSHCertificatesOf(a, "alice", []string{fp}, ""); err != nil || n != 1 {
		t.Errorf("alice's own key: %d %v", n, err)
	}
}

// RR-H1: a shared account that a managed host reports with sudo, or a
// managed host that hasn't reported yet, makes a grant of it privileged
// (no delegate, no AI, the whole privileged path for an admin); the bundle
// marks an account privileged only for a grant saved through that path.
func TestHostReportedSudoMakesGrantPrivileged(t *testing.T) {
	f := newGrantFixture(t)
	g := state.SSHGrant{Group: "ssh_deploy", HostGroup: "web", Accounts: []string{"ansible"}}
	setHost := func(checked bool, capable ...string) {
		f.h.mu.Lock()
		h := f.h.st.SSH.Hosts["web-1"]
		h.SudoChecked, h.SudoCapable = checked, capable
		f.h.st.SSH.Hosts["web-1"] = h
		f.h.mu.Unlock()
	}
	for name, set := range map[string]func(){
		"reported with sudo": func() { setHost(true, "ansible") },
		"not reported yet":   func() { setHost(false) },
	} {
		set()
		if _, err := f.h.SaveGrant(context.Background(), asDelegate, g, "", nil); err == nil || err.Error() != TextOnlyAdminsPrivileged {
			t.Errorf("%s: delegate = %v", name, err)
		}
		if _, err := f.h.SaveGrant(context.Background(), asAI, g, "ssh_deploy", &freshauth.Proof{Code: "c"}); err == nil {
			t.Errorf("%s: via AI accepted", name)
		}
	}
	// A plain grant saved while the host had no sudo account, then the
	// host reports one: the grant shows privileged, the bundle doesn't
	// mark the account (the host refuses it) until an admin saves it again
	// through the privileged path.
	setHost(true)
	saved, err := f.h.SaveGrant(context.Background(), asAdmin, g, "", &freshauth.Proof{Code: "c"})
	if err != nil {
		t.Fatal(err)
	}
	setHost(true, "ansible")
	f.compile(t)
	acct := func() cliapi.Account {
		for _, a := range f.h.sshCompiled().Bundles["web-1"].Accounts {
			if a.Name == "ansible" {
				return a
			}
		}
		return cliapi.Account{}
	}
	if a := acct(); a.Name == "" || a.Privileged {
		t.Errorf("before approval: %+v", a)
	}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, *saved, "", &freshauth.Proof{Code: "c"}); err == nil {
		t.Error("an unchanged re-save approved without the typed name")
	}
	if _, err := f.h.SaveGrant(context.Background(), asAdmin, *saved, "ssh_deploy", &freshauth.Proof{Code: "c"}); err != nil {
		t.Fatal(err)
	}
	f.compile(t)
	if a := acct(); !a.Privileged {
		t.Errorf("after approval: %+v", a)
	}
}

// RR-M3: an issued index that can't be written means nothing is issued
// (a certificate missing from it could never be revoked on leave).
func TestIssuedIndexFailureIssuesNothing(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	os.MkdirAll(f.h.issuedPath(), 0o700) // issued.jsonl can't be written
	ans, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50")
	if sshStatusOf(err) != 503 || ans != nil {
		t.Errorf("issued anyway (answer %v): %v", ans != nil, err)
	}
	if e := f.audit.lastOf("ssh.certificate.issue"); e.Result == "ok" {
		t.Errorf("audited as issued: %+v", e)
	}
}

// RR-M5: an automatic revocation (leaving a group) of a person's own key
// expires 24 h after its last certificate; an explicit one is permanent;
// an administrator can take a key off the list (typed fingerprint, fresh
// sign-in, never through the AI; audited).
func TestOwnKeyAutoRevocationExpires(t *testing.T) {
	f := newGrantFixture(t)
	req := f.request(t, f.signer)
	req.OwnKey = true
	ans, err := f.h.SignSSH(context.Background(), req, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	fp := cliapi.Fingerprint(f.signer.PublicKey())
	f.people.set(func(p *sshPeople) { delete(p.users["alice"], "ssh_web") })
	f.compile(t)
	l, _ := f.h.sshRevokedList()
	var last time.Time
	for _, c := range ans.Certificates {
		if c.ValidBefore.After(last) {
			last = c.ValidBefore
		}
	}
	if len(l) != 1 || l[0].FP != fp || !l[0].Until.Equal(last.Add(24*time.Hour)) {
		t.Fatalf("automatic revocation of an own key: %+v (last %v)", l, last)
	}
	// Explicit: permanent.
	if _, err := f.h.RevokeAllSSH(directory.Actor{User: "alice"}, "alice", "I lost a device"); err != nil {
		t.Fatal(err)
	}
	if l, _ := f.h.sshRevokedList(); len(l) != 1 || !l[0].Until.IsZero() {
		t.Fatalf("explicit revocation of an own key: %+v", l)
	}
	// Un-revoke.
	p := freshauth.Proof{Code: "c"}
	if err := f.h.UnrevokeSSHKey(context.Background(), directory.Actor{User: "root", Via: directory.ViaAI}, fp, fp, p); err == nil {
		t.Error("un-revoked through the AI")
	}
	if err := f.h.UnrevokeSSHKey(context.Background(), rootActor, fp, "SHA256:other", p); err == nil || err.Error() != TextUnrevokeConfirm {
		t.Errorf("a wrong typed fingerprint = %v", err)
	}
	if err := f.h.UnrevokeSSHKey(context.Background(), rootActor, fp, fp, p); err != nil {
		t.Fatal(err)
	}
	if l, _ := f.h.sshRevokedList(); len(l) != 0 {
		t.Errorf("still revoked: %+v", l)
	}
	if e := f.audit.lastOf("ssh.certificate.unrevoke"); e.Result != "ok" || !strings.Contains(e.Detail, fp) {
		t.Errorf("audit %+v", e)
	}
}

// N-L6: a stale grant (its group deleted and re-created: another id)
// isn't what a new grant is compared with.
func TestStaleGrantNotMerged(t *testing.T) {
	f := newGrantFixture(t)
	f.h.mu.Lock()
	f.h.st.SSH.Grants = append(f.h.st.SSH.Grants, state.SSHGrant{ID: "g-stale", Group: "ssh_ops", GroupID: 99, HostGroup: "web", Accounts: []string{"deploy", "backup"}, Sudo: "none"})
	f.h.mu.Unlock()
	g := state.SSHGrant{Group: "ssh_ops", HostGroup: "web", Accounts: []string{"deploy", "backup", "{username}"}}
	if _, err := f.h.SaveGrant(context.Background(), asDelegate, g, "", nil); err != nil {
		t.Errorf("a new grant judged against a stale one: %v", err)
	}
}
