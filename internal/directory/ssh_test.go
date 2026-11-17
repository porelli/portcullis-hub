package directory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// A new username equal to a shared SSH account of a grant is refused
// (409), directly and through the CSV import (contract §18.12).
func TestCreateUserRefusesSharedSSHAccountName(t *testing.T) {
	e, _ := evalEnv(t)
	e.svc.SSHSharedAccount = func(name string) bool { return name == "deploy" }
	_, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "deploy", Email: "deploy@example.org"})
	wantStatus(t, "CreateUser deploy", err, 409)
	if err == nil || !strings.Contains(err.Error(), "deploy is a shared SSH account name; pick another username") {
		t.Errorf("error %v", err)
	}
	if e.ll.HasUser("deploy") {
		t.Fatal("account created")
	}
	req := directory.ApplyRequest{Rows: []directory.ApplyRow{{User: "deploy", Create: true, Email: "deploy@example.org"}}}
	if res, err := e.svc.ImportApply(ctx, asRoot, req); err != nil || res.Rows[0].OK || e.ll.HasUser("deploy") {
		t.Fatalf("ImportApply = %+v %v", res, err)
	}
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org"}); err != nil {
		t.Errorf("an unrelated username refused: %v", err)
	}
}

// sshEnv is helpEnv plus ssh_access → ssh_mgrs ("sam" holds it), the
// grant group ssh_web (alice, bob) and a privileged grant group
// ssh_admins (carol).
func sshEnv(t *testing.T) *env {
	t.Helper()
	e := helpEnv(t)
	cfg, _ := e.svc.Store.Load()
	cfg.Permissions[directory.PermSSHAccess] = "ssh_mgrs"
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("ssh_mgrs")
	e.ll.AddGroup("ssh_web")
	e.ll.AddGroup("ssh_admins")
	e.ll.AddUser("sam", "sam@example.org", "Sam", "", "ssh_mgrs")
	e.ll.AddUser("carol", "carol@example.org", "Carol", "", "ssh_admins")
	e.kc.Import("carol", kctest.Credential{ID: "c", Type: "webauthn-passwordless"})
	e.svc.SSHGroups = func() directory.SSHGroups {
		return directory.SSHGroups{Granting: []string{"ssh_admins", "ssh_web"}, Privileged: []string{"ssh_admins"}}
	}
	return e
}

func TestGrantGroupIsGuarding(t *testing.T) {
	e := sshEnv(t)
	m, err := e.svc.Membership(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if m.Guarding["ssh_web"] != "an SSH access group" || m.Guarding["ssh_admins"] != "an SSH access group" {
		t.Errorf("guarding %v", m.Guarding)
	}
	// Its rule may use only admin-only fields: a rule on a person-editable
	// field is refused.
	cfg, _ := e.svc.Store.Load()
	cfg.Fields = append(cfg.Fields, directory.Field{Name: "team", Label: "Team", Kind: directory.FieldKindText})
	e.svc.Store.Save(cfg)
	err = e.svc.SetGroupRule(ctx, asRoot, "ssh_web", mustRule(t, `team = "ops"`))
	if err == nil {
		t.Error("a guarding SSH group took a rule on a field anyone may edit")
	}
}

func TestPrivilegedMembersProtectedTargets(t *testing.T) {
	e := sshEnv(t)
	helga := callerFor(t, e, "helga")
	err := e.svc.CheckHelp(ctx, helga, "carol")
	if status(err) != 403 || !strings.Contains(err.Error(), "privileged SSH access") {
		t.Errorf("setup link check for carol = %v", err)
	}
	if _, err := e.svc.SendInvite(ctx, helga, "carol", false); status(err) != 403 {
		t.Errorf("setup link to carol = %v", err)
	}
	if err := e.svc.CheckHelp(ctx, helga, "alice"); err != nil {
		t.Errorf("alice (an ordinary grant's member) = %v", err)
	}
}

func TestSSHAccessHolderOwnGroup403(t *testing.T) {
	e := sshEnv(t)
	sam := callerFor(t, e, "sam")
	if !sam.Perms[directory.PermSSHAccess] {
		t.Fatalf("sam = %+v", sam)
	}
	if id, err := e.svc.CheckSSHGrantGroup(ctx, sam, "ssh_web"); err != nil || id == 0 {
		t.Fatalf("ssh_web = %d %v", id, err)
	}
	e.ll.AddUser("sam2", "sam2@example.org", "Sam2", "", "ssh_mgrs", "ssh_web")
	if _, err := e.svc.CheckSSHGrantGroup(ctx, callerFor(t, e, "sam2"), "ssh_web"); status(err) != 403 || err.Error() != directory.TextSSHOwnGroup {
		t.Errorf("own group = %v", err)
	}
}

func TestSSHAccessHolderProtectedGroup403(t *testing.T) {
	e := sshEnv(t)
	sam := callerFor(t, e, "sam")
	for _, g := range []string{"lldap_admin", "hr_editors", "ssh_mgrs", "ssh_admins"} {
		if _, err := e.svc.CheckSSHGrantGroup(ctx, sam, g); status(err) != 403 {
			t.Errorf("%s = %v", g, err)
		}
	}
	if _, err := e.svc.CheckSSHGrantGroup(ctx, sam, "nope"); status(err) != 404 {
		t.Errorf("missing group = %v", err)
	}
	// Without the permission.
	if _, err := e.svc.CheckSSHGrantGroup(ctx, callerFor(t, e, "eddie"), "ssh_web"); status(err) != 403 {
		t.Errorf("eddie = %v", err)
	}
	// Admins may grant to any group.
	if _, err := e.svc.CheckSSHGrantGroup(ctx, asRoot, "ssh_admins"); err != nil {
		t.Errorf("root = %v", err)
	}
}
