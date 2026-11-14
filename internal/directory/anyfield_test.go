package directory_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

func groupView(t *testing.T, e *env, name string) directory.GroupView {
	t.Helper()
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range ov.Groups {
		if g.Name == name {
			return g
		}
	}
	t.Fatalf("no group %s in %+v", name, ov.Groups)
	return directory.GroupView{}
}

// TestAllowAnyFieldOnAppAdminGroup: an app admin group's rule may use a
// field delegates can edit only once an admin turns on its option; the
// refusal names both fixes; setting and clearing it are audited and
// apply at validation and at re-evaluation.
func TestAllowAnyFieldOnAppAdminGroup(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("admin_app") // App "app"'s admin group (newEnv)
	cityRule := mustRule(t, `city = "Milan"`)
	err := e.svc.ConvertApply(ctx, asRoot, "admin_app", cityRule, nil)
	wantStatus(t, "ConvertApply city (option off)", err, 409)
	if err == nil || !strings.Contains(err.Error(), "make city admin-only") || !strings.Contains(err.Error(), "Allow any profile field in this group's rule") {
		t.Errorf("refusal = %v, want both fixes", err)
	}
	if v := groupView(t, e, "admin_app"); v.AllowAnyField == nil || *v.AllowAnyField {
		t.Errorf("admin_app allow_any_field = %v, want false (offered)", v.AllowAnyField)
	}
	if v := groupView(t, e, "milan"); v.AllowAnyField != nil {
		t.Errorf("milan (not guarding) allow_any_field = %v, want absent", *v.AllowAnyField)
	}

	// Admins only.
	for name, c := range map[string]*directory.Caller{
		"plain":    {User: "alice"},
		"delegate": {User: "alice", Perms: map[string]bool{directory.PermEditDetails: true, directory.PermInvite: true, directory.PermRemove: true}},
	} {
		if st := status(e.svc.SetAllowAnyField(ctx, c, "admin_app", true)); st != 403 {
			t.Errorf("%s SetAllowAnyField = %d, want 403", name, st)
		}
	}
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "admin_app", true); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "group.allow_any_field"); a.Target != "admin_app" || a.Detail != "allow=true" || a.Result != "ok" || a.Actor != "root" {
		t.Errorf("audit = %+v", a)
	}
	raw, _ := os.ReadFile(e.svc.Store.Path)
	if !strings.Contains(string(raw), "allow_any_field: true") {
		t.Errorf("directory.yaml lacks the option:\n%s", raw)
	}
	if v := groupView(t, e, "admin_app"); v.AllowAnyField == nil || !*v.AllowAnyField {
		t.Errorf("admin_app allow_any_field = %v, want true", v.AllowAnyField)
	}
	// Validation: now allowed; the option survives the conversion.
	if err := e.svc.ConvertApply(ctx, asRoot, "admin_app", cityRule, nil); err != nil {
		t.Fatalf("ConvertApply city (option on): %v", err)
	}
	if err := e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `city = "Milan" and not city is empty`)); err != nil {
		t.Errorf("SetGroupRule city (option on): %v", err)
	}
	// Still never a rule matching a person with no details.
	wantStatus(t, "SetGroupRule matches empty", e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `not city = "Rome"`)), 409)
	// Re-evaluation: the matching people are added.
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "admin_app", "bob", "carol")
	if v := groupView(t, e, "admin_app"); v.AddsBlocked != "" {
		t.Errorf("adds blocked = %q", v.AddsBlocked)
	}
	if p, err := e.svc.PrivilegeProblem(ctx, "admin_app"); err != nil || p != "" {
		t.Errorf("PrivilegeProblem (option on) = %q, %v", p, err)
	}

	// dave (Rome) is added by hand.
	if err := e.svc.AddException(ctx, asRoot, "admin_app", directory.Exception{User: "dave", Reason: "on call", Include: true}); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "admin_app", "bob", "carol", "dave")

	// Clearing fails closed: audited; the rule is suspended, so the people
	// it added leave at once (each audited group.remove_member on the
	// group), the one added by hand stays, nobody new joins, privileged
	// values are refused again.
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "admin_app", false); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "group.allow_any_field"); a.Detail != "allow=false" || a.Result != "ok" {
		t.Errorf("audit = %+v", a)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "admin_app", "dave")
	removed := map[string]bool{}
	for _, a := range groupEntries(t, e, "admin_app") {
		if a.Action == "group.remove_member" && a.Result == "ok" {
			removed[a.Detail] = true
		}
	}
	if !removed["bob (rule suspended: allow_any_field off)"] || !removed["carol (rule suspended: allow_any_field off)"] || len(removed) != 2 {
		t.Errorf("removals audited = %v", removed)
	}
	setCity(t, e, "dave", "Milan")
	e.ll.AddUser("erin", "erin@example.org", "Erin", "")
	setCity(t, e, "erin", "Milan")
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "admin_app", "dave")
	v := groupView(t, e, "admin_app")
	if !v.RuleSuspended || !strings.Contains(v.AddsBlocked, "suspended") || !strings.Contains(v.AddsBlocked, "make city admin-only") ||
		!strings.Contains(v.AddsBlocked, "turn \"Allow any profile field in this group's rule\" back on") || len(v.Matches) != 0 {
		t.Errorf("view = suspended %v, adds blocked %q, matches %v", v.RuleSuspended, v.AddsBlocked, v.Matches)
	}
	if p, _ := e.svc.PrivilegeProblem(ctx, "admin_app"); p == "" {
		t.Error("PrivilegeProblem (option off) = \"\", want the field reason")
	}
	wantStatus(t, "SetGroupRule city (option off)", e.svc.SetGroupRule(ctx, asRoot, "admin_app", cityRule), 409)
	// Missing in directory.yaml = false (no migration).
	cfg, _ := e.svc.Store.Load()
	if cfg.Groups["admin_app"].AllowAnyField {
		t.Error("cleared option still stored")
	}
	if raw, _ := os.ReadFile(e.svc.Store.Path); strings.Contains(string(raw), "allow_any_field") {
		t.Errorf("a false option is written:\n%s", raw)
	}
}

// TestAllowAnyFieldFieldMayLoseAdminOnly: a field used only by the rules
// of groups with the option on may stop being admin-only; one used by a
// permission group's rule may not.
func TestAllowAnyFieldFieldMayLoseAdminOnly(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("admin_app")
	if err := e.svc.ConvertApply(ctx, asRoot, "admin_app", mustRule(t, `office = "HQ"`), nil); err != nil {
		t.Fatal(err)
	}
	office := directory.Field{Name: "office", Label: "Office", Kind: directory.FieldKindText}
	wantStatus(t, "office not admin-only (option off)", e.svc.UpdateField(ctx, asRoot, office), 409)
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "admin_app", true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpdateField(ctx, asRoot, office); err != nil {
		t.Errorf("office not admin-only (option on): %v", err)
	}
}

// TestAllowAnyFieldNeverOnPermissionOrAdminGroups: the option can't be
// turned on for a permission, administrator or built-in group, and a
// group with it on still can't become a permission group while its rule
// uses an editable field, nor use one once it is.
func TestAllowAnyFieldNeverOnPermissionOrAdminGroups(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("hr")
	e.ll.AddGroup("extra_admins")
	if err := e.svc.SetPermission(ctx, asRoot, directory.PermEditDetails, "hr"); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"hr", "lldap_admin", "extra_admins"} {
		wantStatus(t, "SetAllowAnyField "+g, e.svc.SetAllowAnyField(ctx, asRoot, g, true), 409)
	}
	wantStatus(t, "SetAllowAnyField ghost", e.svc.SetAllowAnyField(ctx, asRoot, "ghost", true), 404)
	if v := groupView(t, e, "hr"); v.AllowAnyField != nil {
		t.Errorf("hr allow_any_field = %v, want absent (never offered)", *v.AllowAnyField)
	}
	err := e.svc.ConvertApply(ctx, asRoot, "hr", mustRule(t, `city = "Milan"`), nil)
	wantStatus(t, "permission group city", err, 409)
	if err == nil || !strings.Contains(err.Error(), "make city admin-only") || strings.Contains(err.Error(), "Allow any profile field") {
		t.Errorf("permission group refusal = %v, want only the admin-only fix", err)
	}
	// admin_app with the option on and a city rule can't become a
	// permission group; with an admin-only rule it can, and then its rule
	// can't use city.
	e.ll.AddGroup("admin_app")
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "admin_app", true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "admin_app", mustRule(t, `city = "Milan"`), nil); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "SetPermission admin_app", e.svc.SetPermission(ctx, asRoot, directory.PermInvite, "admin_app"), 409)
	if err := e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `office = "HQ"`)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetPermission(ctx, asRoot, directory.PermInvite, "admin_app"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "SetGroupRule city on a permission group", e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `city = "Milan"`)), 409)
	if v := groupView(t, e, "admin_app"); v.AllowAnyField != nil {
		t.Errorf("admin_app as a permission group: allow_any_field = %v, want absent", *v.AllowAnyField)
	}
	// Clearing is always allowed.
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "admin_app", false); err != nil {
		t.Errorf("clearing on a permission group: %v", err)
	}
}

// TestAllowAnyFieldOnPrivilegedGroup: a group named in a privileged
// setting row (App.PrivilegedGroups) takes the option like admin_<app>.
func TestAllowAnyFieldOnPrivilegedGroup(t *testing.T) {
	e := guardEnv(t)
	e.svc.Apps = func() []directory.App {
		return []directory.App{{ID: "immich", Name: "Immich", Enabled: true, AccessGroup: "users_immich", PrivilegedGroups: []string{"milan"}}}
	}
	cityRule := mustRule(t, `city = "Milan"`)
	err := e.svc.ConvertApply(ctx, asRoot, "milan", cityRule, nil)
	wantStatus(t, "privileged city (option off)", err, 409)
	if err == nil || !strings.Contains(err.Error(), "a privileged value of app immich") || !strings.Contains(err.Error(), "Allow any profile field") {
		t.Errorf("refusal = %v", err)
	}
	if v := groupView(t, e, "milan"); v.AllowAnyField == nil {
		t.Error("the option isn't offered on a privileged group")
	}
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "milan", true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "milan", cityRule, nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.svc.PrivilegeProblem(ctx, "milan"); p != "" {
		t.Errorf("PrivilegeProblem = %q", p)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "milan", "bob", "carol")
}

// TestAllowAnyFieldStillSkipsDelegateCreated: with the option on, an
// account a delegate created (created_by) is still not added.
func TestAllowAnyFieldStillSkipsDelegateCreated(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("admin_app")
	cfg, _ := e.svc.Store.Load()
	cfg.CreatedBy["carol"] = "ivy"
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "admin_app", true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "admin_app", mustRule(t, `city = "Milan"`), nil); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "admin_app", "bob")
}

// TestDeleteGroupReportsAllowAnyField: the purge report names the option.
func TestDeleteGroupReportsAllowAnyField(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("admin_app")
	if err := e.svc.SetAllowAnyField(ctx, asRoot, "admin_app", true); err != nil {
		t.Fatal(err)
	}
	if err := deleteErr(e.svc.DeleteGroup(ctx, asRoot, "admin_app", "admin_app")); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "group.delete"); !strings.Contains(a.Detail, "allow_any_field of admin_app") || strings.Contains(a.Detail, "empty entry") {
		t.Errorf("group.delete detail = %q", a.Detail)
	}
}
