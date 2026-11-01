package directory_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// delegateEnv: hr_editors (edit_details), hr_inviters (invite) and
// hr_removers (remove); "eddie" edits, "ivy" invites, "rex" removes, "hera"
// holds all three; "bob" is an ordinary user.
func delegateEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	cfg, err := e.svc.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Permissions = map[string]string{
		directory.PermEditDetails: "hr_editors",
		directory.PermInvite:      "hr_inviters",
		directory.PermRemove:      "hr_removers",
	}
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("hr_editors")
	e.ll.AddGroup("hr_inviters")
	e.ll.AddGroup("hr_removers")
	e.ll.AddUser("eddie", "eddie@example.org", "Eddie", "", "hr_editors")
	e.ll.AddUser("edna", "edna@example.org", "Edna", "", "hr_editors")
	e.ll.AddUser("ivy", "ivy@example.org", "Ivy", "", "hr_inviters")
	e.ll.AddUser("rex", "rex@example.org", "Rex", "", "hr_removers")
	e.ll.AddUser("hera", "hera@example.org", "Hera", "", "hr_editors", "hr_inviters", "hr_removers")
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	return e
}

func callerFor(t *testing.T, e *env, user string) *directory.Caller {
	t.Helper()
	c, err := e.svc.CallerFor(ctx, user)
	if err != nil {
		t.Fatalf("CallerFor(%s): %v", user, err)
	}
	return c
}

func TestCallerFor(t *testing.T) {
	e := delegateEnv(t)
	if _, err := e.svc.CallerFor(ctx, " "); status(err) != 403 {
		t.Errorf("empty user = %v", err)
	}
	if c := callerFor(t, e, "root"); !c.Admin || c.User != "root" {
		t.Errorf("root = %+v", c)
	}
	if c := callerFor(t, e, "Hera"); c.Admin || !c.Perms[directory.PermEditDetails] || !c.Perms[directory.PermInvite] || !c.Perms[directory.PermRemove] {
		t.Errorf("hera = %+v", c)
	}
	if c := callerFor(t, e, "eddie"); c.Admin || !c.Perms[directory.PermEditDetails] || c.Perms[directory.PermInvite] || c.Perms[directory.PermRemove] {
		t.Errorf("eddie = %+v", c)
	}
	if c := callerFor(t, e, "ghost"); c.Admin || len(c.Perms) != 0 || c.User != "ghost" {
		t.Errorf("unknown = %+v", c)
	}
	// An "admin" key in permissions grants nothing.
	cfg, _ := e.svc.Store.Load()
	cfg.Permissions["admin"] = "hr_editors"
	e.svc.Store.Save(cfg)
	if c := callerFor(t, e, "eddie"); c.Admin || c.Perms["admin"] {
		t.Errorf("admin permission key = %+v", c)
	}
	// No Store: no delegated permissions; admins still work.
	e.svc.Store = nil
	if c := callerFor(t, e, "hera"); len(c.Perms) != 0 {
		t.Errorf("no store = %+v", c)
	}
	if c := callerFor(t, e, "root"); !c.Admin {
		t.Errorf("no store root = %+v", c)
	}
}

func TestDelegateCannotEscalate(t *testing.T) {
	e := delegateEnv(t)
	e.kc.Import("root")
	eddie, ivy, rex, bob := callerFor(t, e, "eddie"), callerFor(t, e, "ivy"), callerFor(t, e, "rex"), callerFor(t, e, "bob")
	before := len(e.ll.Mutations)
	check := func(name string, err error) {
		t.Helper()
		if status(err) != 403 {
			t.Errorf("%s = %v (status %d), want 403", name, err, status(err))
		}
	}
	r := func(_ *directory.Result, err error) error { return err }

	check("editor edits self", e.svc.UpdateUser(ctx, eddie, "eddie", nil, strptr("Boss")))
	check("editor edits another editor", e.svc.UpdateUser(ctx, eddie, "edna", nil, strptr("X")))
	check("editor edits an inviter", e.svc.UpdateUser(ctx, eddie, "ivy", nil, strptr("X")))
	check("editor edits an admin", e.svc.UpdateUser(ctx, eddie, "root", strptr("me@example.org"), nil))
	check("editor edits core admin", e.svc.UpdateUser(ctx, eddie, "admin", nil, strptr("X")))
	check("editor edits service", e.svc.UpdateUser(ctx, eddie, "portcullis-hub", nil, strptr("X")))
	check("inviter re-invites an admin", r(e.svc.SendInvite(ctx, ivy, "root")))
	check("inviter re-invites self", r(e.svc.SendInvite(ctx, ivy, "ivy")))
	check("inviter re-invites a remover", r(e.svc.SendInvite(ctx, ivy, "rex")))
	check("remover removes an admin", r(e.svc.DeleteUser(ctx, rex, "root", "root")))
	check("remover removes self", r(e.svc.DeleteUser(ctx, rex, "rex", "rex")))
	check("remover removes an editor", r(e.svc.DeleteUser(ctx, rex, "eddie", "eddie")))

	// Wrong permission.
	check("editor invites", r(e.svc.SendInvite(ctx, eddie, "bob")))
	check("editor removes", r(e.svc.DeleteUser(ctx, eddie, "bob", "bob")))
	check("inviter edits", e.svc.UpdateUser(ctx, ivy, "bob", nil, strptr("X")))
	check("nobody creates", r(e.svc.CreateUser(ctx, bob, directory.CreateRequest{Username: "zed", Email: "zed@example.org"})))
	if err := e.svc.UpdateUser(ctx, ivy, "bob", nil, strptr("X")); err == nil || !strings.Contains(err.Error(), "needs edit_details") {
		t.Errorf("message = %v", err)
	}
	// A Caller resolved before losing the permission is re-checked.
	edna := callerFor(t, e, "edna")
	e.ll.RemoveMember("hr_editors", "edna")
	check("stale caller", e.svc.UpdateUser(ctx, edna, "bob", nil, strptr("X")))

	// Inviters: no password onboarding, no groups, nobody protected.
	check("inviter password onboarding", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Onboarding: directory.OnboardPassword, Generate: true})))
	if _, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Groups: []string{"lldap_admin"}}); status(err) != 400 {
		t.Errorf("inviter with groups = %v", err)
	}
	check("inviter creates self", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "ivy", Email: "ivy@example.org"})))
	check("inviter creates admin", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "admin", Email: "a@example.org"})))

	// Admin-only operations, even holding every permission.
	hera := callerFor(t, e, "hera")
	adminOnly := map[string]error{
		"SetPassword":             r(e.svc.SetPassword(ctx, hera, "bob", "", true, "")),
		"RequirePasskey":          e.svc.RequirePasskey(ctx, hera, "bob"),
		"ClearActions":            e.svc.ClearActions(ctx, hera, "bob"),
		"RemovePasskeys":          r(e.svc.RemovePasskeys(ctx, hera, "bob", "bob", true)),
		"RemoveStaleKeycloakUser": e.svc.RemoveStaleKeycloakUser(ctx, hera, "ghost", "ghost"),
		"AddMember":               e.svc.AddMember(ctx, hera, "hr_editors", "bob"),
		"AddMember (admin)":       e.svc.AddMember(ctx, hera, "lldap_admin", "hera"),
		"RemoveMember":            e.svc.RemoveMember(ctx, hera, "hr_editors", "eddie"),
		"CreateGroup":             e.svc.CreateGroup(ctx, hera, "new_group"),
		"DeleteGroup":             e.svc.DeleteGroup(ctx, hera, "hr_editors", "hr_editors"),
		"CreateField":             e.svc.CreateField(ctx, hera, directory.Field{Name: "department", Label: "Department", Kind: directory.FieldKindText}),
		"UpdateField":             e.svc.UpdateField(ctx, hera, directory.Field{Name: "department", Label: "Dept"}),
		"DeleteField":             e.svc.DeleteField(ctx, hera, "department", "department"),
	}
	for name, err := range adminOnly {
		check(name, err)
		if err != nil && !strings.Contains(err.Error(), "admins only") {
			t.Errorf("%s message = %q", name, err)
		}
	}

	if got := e.ll.Mutations[before:]; len(got) != 0 {
		t.Errorf("delegates changed LLDAP: %v", got)
	}
	if len(e.invites.users) != 0 {
		t.Errorf("invites created: %v", e.invites.users)
	}
	entries, err := e.svc.Recent(100)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, en := range entries {
		if en.Result != "refused" {
			t.Errorf("entry %+v not refused", en)
		}
		refused++
	}
	if want := 22 + len(adminOnly); refused != want {
		t.Errorf("refused audit entries = %d, want %d", refused, want)
	}
	for _, en := range entries {
		if en.Action == "user.update" && en.Target == "eddie" && en.Actor != "eddie" {
			t.Errorf("actor = %+v", en)
		}
	}
}

func TestDelegateAllowed(t *testing.T) {
	e := delegateEnv(t)
	eddie, ivy, rex := callerFor(t, e, "eddie"), callerFor(t, e, "ivy"), callerFor(t, e, "rex")

	if err := e.svc.UpdateUser(ctx, eddie, "bob", strptr("robert@example.org"), strptr("Robert")); err != nil {
		t.Fatalf("editor edits bob: %v", err)
	}
	res, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "nina", Email: "nina@example.org"})
	if err != nil || res.Invite == nil {
		t.Fatalf("inviter creates nina: %+v %v", res, err)
	}
	for _, g := range []string{"lldap_admin", "hr_editors", "hr_inviters", "hr_removers"} {
		for _, m := range e.ll.GroupMembers(g) {
			if m == "nina" {
				t.Errorf("nina is in %s", g)
			}
		}
	}
	if res, err := e.svc.SendInvite(ctx, ivy, "bob"); err != nil || res.Invite == nil {
		t.Errorf("inviter re-invites bob: %v", err)
	}
	if _, err := e.svc.DeleteUser(ctx, rex, "nina", "nina"); err != nil {
		t.Errorf("remover removes nina: %v", err)
	}
	if e.ll.HasUser("nina") {
		t.Error("nina still exists")
	}
	entries, _ := e.svc.Recent(100)
	for _, en := range entries {
		if en.Result != "ok" {
			t.Errorf("entry = %+v", en)
		}
	}
	if len(entries) != 4 || entries[3].Actor != "eddie" || entries[2].Actor != "ivy" || entries[0].Actor != "rex" {
		t.Errorf("entries = %+v", entries)
	}
}
