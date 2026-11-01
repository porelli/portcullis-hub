package directory_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/rules"
)

func mustRule(t *testing.T, text string) *rules.Expr {
	t.Helper()
	e, err := rules.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newestAudit(t *testing.T, e *env, action string) directory.AuditEntry {
	t.Helper()
	all, err := e.svc.Recent(1000)
	if err != nil {
		t.Fatal(err)
	}
	var found *directory.AuditEntry
	for i := range all {
		if all[i].Action == action && (found == nil || !all[i].Time.Before(found.Time)) {
			found = &all[i]
		}
	}
	if found == nil {
		t.Fatalf("no %s audit entry in %+v", action, all)
	}
	return *found
}

func wantStatus(t *testing.T, name string, err error, want int) {
	t.Helper()
	if st := status(err); st != want {
		t.Errorf("%s = %v (status %d), want %d", name, err, st, want)
	}
}

func TestConvertKeepsAsExceptions(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("office", "bob", "dave", "alice", "portcullis-hub")
	future := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	if err := e.svc.SetMemberExpiry(ctx, asRoot, "office", "alice", &future); err != nil {
		t.Fatal(err)
	}
	rule := mustRule(t, `city = "Milan"`)

	p, err := e.svc.ConvertPreview(ctx, asRoot, "office", rule)
	if err != nil {
		t.Fatal(err)
	}
	want := &directory.ConvertPreview{Matching: []string{"bob", "carol"}, KeptAsException: []string{"alice", "dave"}, Joining: []string{"carol"}, ExpiryDropped: []string{}}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("preview = %+v, want %+v", p, want)
	}
	if cfg, _ := store.Load(); cfg.Groups["office"].Rule != nil {
		t.Errorf("preview changed the group: %+v", cfg.Groups["office"])
	}

	// keep must be a subset of KeptAsException.
	for _, bad := range [][]string{{"bob"}, {"carol"}, {"admin"}, {"portcullis-hub"}, {"ghost"}} {
		wantStatus(t, "ConvertApply keep "+bad[0], e.svc.ConvertApply(ctx, asRoot, "office", rule, bad), 400)
	}
	if cfg, _ := store.Load(); cfg.Groups["office"].Rule != nil {
		t.Fatalf("refused convert changed the group")
	}

	if err := e.svc.ConvertApply(ctx, asRoot, "office", rule, []string{"Alice"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	gc := cfg.Groups["office"]
	if gc == nil || rules.Format(gc.Rule) != `city = "Milan"` || len(gc.Expiry) != 0 {
		t.Fatalf("group config = %+v", gc)
	}
	if len(gc.Exceptions) != 1 {
		t.Fatalf("exceptions = %+v", gc.Exceptions)
	}
	ex := gc.Exceptions[0]
	day := time.Now().UTC().Format("2006-01-02")
	if ex.User != "alice" || !ex.Include || ex.By != "root" || ex.Reason != "member before the rule (set by root on "+day+")" {
		t.Errorf("exception = %+v", ex)
	}
	if ex.Until == nil || !ex.Until.Equal(future) {
		t.Errorf("manual expiry not carried over: %v", ex.Until)
	}
	if a := newestAudit(t, e, "group.rule"); a.Result != "ok" || a.Target != "office" || !strings.Contains(a.Detail, `city = "Milan"`) || !strings.Contains(a.Detail, "alice") {
		t.Errorf("audit = %+v", a)
	}

	// The evaluator removes the rest (dave), adds carol, keeps alice and
	// never touches the service account.
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "office", "alice", "bob", "carol", "portcullis-hub")

	// Already rule-based: convert is refused.
	_, err = e.svc.ConvertPreview(ctx, asRoot, "office", rule)
	wantStatus(t, "ConvertPreview rule group", err, 409)
	wantStatus(t, "ConvertApply rule group", e.svc.ConvertApply(ctx, asRoot, "office", rule, nil), 409)
	_, err = e.svc.ConvertPreview(ctx, asRoot, "nope", rule)
	wantStatus(t, "ConvertPreview missing group", err, 404)
}

func TestSetGroupRule(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("rome", "bob")
	// Manual → rule needs the review step.
	wantStatus(t, "SetGroupRule on manual", e.svc.SetGroupRule(ctx, asRoot, "rome", mustRule(t, `city = "Rome"`)), 409)
	wantStatus(t, "SetGroupRule missing", e.svc.SetGroupRule(ctx, asRoot, "nope", nil), 404)
	if err := e.svc.ConvertApply(ctx, asRoot, "rome", mustRule(t, `city = "Rome"`), []string{"bob"}); err != nil {
		t.Fatal(err)
	}
	// Changing the rule of a rule group.
	if err := e.svc.SetGroupRule(ctx, asRoot, "rome", mustRule(t, `city in ("Rome", "Milan")`)); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "group.rule"); !strings.Contains(a.Detail, `city in ("Rome", "Milan")`) {
		t.Errorf("audit = %+v", a)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "rome", "bob", "carol", "dave")

	// Validation: 400s.
	for name, r := range map[string]*rules.Expr{
		"invalid":         {Op: "nope"},
		"unknown field":   mustRule(t, `office = "x"`),
		"reports_to city": {Op: rules.OpReportsTo, Field: "city", Values: []string{"bob"}},
		"empty all":       {Op: rules.OpAll},
	} {
		wantStatus(t, name, e.svc.SetGroupRule(ctx, asRoot, "rome", r), 400)
	}
	if err := e.svc.SetGroupRule(ctx, asRoot, "rome", mustRule(t, `office = "x"`)); err == nil || !strings.Contains(err.Error(), "office") {
		t.Errorf("unknown field message = %v", err)
	}
	// reports_to works on a person-kind "manager".
	if err := e.svc.SetGroupRule(ctx, asRoot, "rome", &rules.Expr{Op: rules.OpReportsTo, Field: "manager", Values: []string{"bob"}}); err != nil {
		t.Errorf("reports_to manager: %v", err)
	}

	// nil: manual again, members stay, exceptions dropped.
	if err := e.svc.SetGroupRule(ctx, asRoot, "rome", nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	if gc := cfg.Groups["rome"]; gc != nil && (gc.Rule != nil || len(gc.Exceptions) != 0) {
		t.Errorf("still rule-based: %+v", gc)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "rome", "bob", "carol", "dave")
	if a := newestAudit(t, e, "group.rule"); !strings.Contains(a.Detail, "manual") {
		t.Errorf("audit = %+v", a)
	}
}

func TestReportsToNeedsPersonManager(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: t.TempDir() + "/directory.yaml"}
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "manager", Label: "Manager", Kind: directory.FieldKindText}); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.PreviewRule(ctx, asRoot, &rules.Expr{Op: rules.OpReportsTo, Field: "manager", Values: []string{"bob"}})
	wantStatus(t, "reports_to on text manager", err, 400)
}

func TestRuleOnBuiltinRefused(t *testing.T) {
	e, _ := evalEnv(t)
	rule := mustRule(t, `city = "Milan"`)
	groups := []string{"lldap_admin", "lldap_strict_readonly"}
	for g := range directory.ProtectedGroups("extra_admins", "") {
		groups = append(groups, g)
	}
	groups = append(groups, "ops_admins") // core metrics group (group-gate map)
	for _, g := range groups {
		if !e.ll.HasGroup(g) {
			e.ll.AddGroup(g)
		}
		wantStatus(t, "SetGroupRule "+g, e.svc.SetGroupRule(ctx, asRoot, g, rule), 409)
		_, err := e.svc.ConvertPreview(ctx, asRoot, g, rule)
		wantStatus(t, "ConvertPreview "+g, err, 409)
		wantStatus(t, "ConvertApply "+g, e.svc.ConvertApply(ctx, asRoot, g, rule, nil), 409)
		wantStatus(t, "SetPermission "+g, e.svc.SetPermission(ctx, asRoot, directory.PermInvite, g), 409)
	}
	cfg, _ := e.svc.Store.Load()
	if len(cfg.Groups) != 0 || len(cfg.Permissions) != 0 {
		t.Errorf("config changed: %+v %+v", cfg.Groups, cfg.Permissions)
	}
	// Expiry on lldap_admin would bypass the last-admin guardrail.
	future := time.Now().Add(time.Hour)
	wantStatus(t, "SetMemberExpiry lldap_admin", e.svc.SetMemberExpiry(ctx, asRoot, "lldap_admin", "root", &future), 409)
}

// guardEnv: city (editable by delegates) and office (admin only).
func guardEnv(t *testing.T) *env {
	t.Helper()
	e, _ := evalEnv(t)
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "office", Label: "Office", Kind: directory.FieldKindText, AdminOnly: true}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRuleOnPermissionGroupNeedsAdminOnlyFields(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("hr")
	e.ll.AddGroup("team")
	if err := e.svc.SetPermission(ctx, asRoot, directory.PermEditDetails, "hr"); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "permission.set"); a.Target != directory.PermEditDetails || !strings.Contains(a.Detail, "hr") {
		t.Errorf("audit = %+v", a)
	}
	bad := mustRule(t, `office = "HQ" and city = "Milan"`)
	_, err := e.svc.ConvertPreview(ctx, asRoot, "hr", bad)
	wantStatus(t, "ConvertPreview city", err, 409)
	err = e.svc.ConvertApply(ctx, asRoot, "hr", bad, nil)
	wantStatus(t, "ConvertApply city", err, 409)
	if err == nil || !strings.Contains(err.Error(), "city") || strings.Contains(err.Error(), "office") {
		t.Errorf("message = %v", err)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "hr", mustRule(t, `office = "HQ"`), nil); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "SetGroupRule city", e.svc.SetGroupRule(ctx, asRoot, "hr", bad), 409)
	// The field can't lose admin-only now (existing guard).
	wantStatus(t, "UpdateField office", e.svc.UpdateField(ctx, asRoot, directory.Field{Name: "office", Label: "Office", Kind: directory.FieldKindText}), 409)

	// Granting a permission to a rule group built on editable fields.
	if err := e.svc.ConvertApply(ctx, asRoot, "team", mustRule(t, `city = "Milan"`), nil); err != nil {
		t.Fatal(err)
	}
	err = e.svc.SetPermission(ctx, asRoot, directory.PermRemove, "team")
	wantStatus(t, "SetPermission team", err, 409)
	if err == nil || !strings.Contains(err.Error(), "city") {
		t.Errorf("message = %v", err)
	}
	wantStatus(t, "SetPermission bad perm", e.svc.SetPermission(ctx, asRoot, "admin", "hr"), 400)
	wantStatus(t, "SetPermission missing group", e.svc.SetPermission(ctx, asRoot, directory.PermInvite, "nope"), 409)

	// Empty group removes the grant.
	if err := e.svc.SetPermission(ctx, asRoot, directory.PermEditDetails, ""); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.svc.Store.Load()
	if _, ok := cfg.Permissions[directory.PermEditDetails]; ok {
		t.Errorf("permissions = %v", cfg.Permissions)
	}
	// hr is no longer guarding: an editable field is allowed now.
	if err := e.svc.SetGroupRule(ctx, asRoot, "hr", bad); err != nil {
		t.Errorf("SetGroupRule after revoke: %v", err)
	}
}

func TestRuleOnAppAdminGroupNeedsAdminOnlyFields(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("admin_app") // App "app"'s admin group (newEnv)
	err := e.svc.ConvertApply(ctx, asRoot, "admin_app", mustRule(t, `city = "Milan"`), nil)
	wantStatus(t, "ConvertApply city", err, 409)
	if err == nil || !strings.Contains(err.Error(), "city") {
		t.Errorf("message = %v", err)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "admin_app", mustRule(t, `office = "HQ"`), nil); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "SetGroupRule city", e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `not city is empty`)), 409)
}

func TestExceptionNeedsReason(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("manual")
	if err := e.svc.ConvertApply(ctx, asRoot, "milan", mustRule(t, `city = "Milan"`), nil); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(24 * time.Hour)
	for name, ex := range map[string]directory.Exception{
		"no reason":    {User: "dave", Include: true},
		"blank reason": {User: "dave", Reason: " \t\n", Include: true},
		"long reason":  {User: "dave", Reason: strings.Repeat("é", 501), Include: true},
		"past until":   {User: "dave", Reason: "x", Include: true, Until: &past},
	} {
		wantStatus(t, name, e.svc.AddException(ctx, asRoot, "milan", ex), 400)
	}
	wantStatus(t, "unknown user", e.svc.AddException(ctx, asRoot, "milan", directory.Exception{User: "ghost", Reason: "x"}), 404)
	wantStatus(t, "unknown group", e.svc.AddException(ctx, asRoot, "nope", directory.Exception{User: "dave", Reason: "x"}), 404)
	wantStatus(t, "manual group", e.svc.AddException(ctx, asRoot, "manual", directory.Exception{User: "dave", Reason: "x"}), 409)
	for _, u := range []string{"admin", "portcullis-hub"} {
		wantStatus(t, "protected "+u, e.svc.AddException(ctx, asRoot, "milan", directory.Exception{User: u, Reason: "x", Include: true}), 409)
	}
	if cfg, _ := store.Load(); len(cfg.Groups["milan"].Exceptions) != 0 {
		t.Fatalf("refused exceptions stored: %+v", cfg.Groups["milan"].Exceptions)
	}

	if err := e.svc.AddException(ctx, asRoot, "milan", directory.Exception{User: "DAVE", Reason: "  covers Milan  ", Include: true, Until: &future, By: "mallory"}); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "group.exception"); a.Target != "milan" || !strings.Contains(a.Detail, "dave") || !strings.Contains(a.Detail, "include=true") || !strings.Contains(a.Detail, "until=") {
		t.Errorf("audit = %+v", a)
	}
	// Replaces the exception for the same user.
	if err := e.svc.AddException(ctx, asRoot, "milan", directory.Exception{User: "dave", Reason: "covers Milan", Include: true, Until: &future}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	exs := cfg.Groups["milan"].Exceptions
	if len(exs) != 1 {
		t.Fatalf("exceptions = %+v", exs)
	}
	ex := exs[0]
	if ex.User != "dave" || ex.Reason != "covers Milan" || ex.By != "root" || !ex.Include || ex.Until == nil || ex.Until.Location() != time.UTC || ex.At.IsZero() || ex.At.Location() != time.UTC {
		t.Errorf("exception = %+v", ex)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "milan", "bob", "carol", "dave")

	// Remove.
	wantStatus(t, "RemoveException none", e.svc.RemoveException(ctx, asRoot, "milan", "bob"), 404)
	wantStatus(t, "RemoveException protected", e.svc.RemoveException(ctx, asRoot, "milan", "admin"), 409)
	if err := e.svc.RemoveException(ctx, asRoot, "milan", "Dave"); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := store.Load(); len(cfg.Groups["milan"].Exceptions) != 0 {
		t.Errorf("exceptions = %+v", cfg.Groups["milan"].Exceptions)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "milan", "bob", "carol")
}

func TestSetMemberExpiry(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("contractors", "bob")
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-time.Minute)
	wantStatus(t, "past", e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "bob", &past), 400)
	wantStatus(t, "not a member", e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "carol", &future), 409)
	wantStatus(t, "unknown user", e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "ghost", &future), 404)
	wantStatus(t, "unknown group", e.svc.SetMemberExpiry(ctx, asRoot, "nope", "bob", &future), 404)
	wantStatus(t, "protected", e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "admin", &future), 409)
	if err := e.svc.ConvertApply(ctx, asRoot, "milan", mustRule(t, `city = "Milan"`), nil); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, time.Now().UTC())
	wantStatus(t, "rule group", e.svc.SetMemberExpiry(ctx, asRoot, "milan", "bob", &future), 409)

	if err := e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "BOB", &future); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	if at, ok := cfg.Groups["contractors"].Expiry["bob"]; !ok || !at.Equal(future) || at.Location() != time.UTC {
		t.Errorf("expiry = %+v", cfg.Groups["contractors"].Expiry)
	}
	if a := newestAudit(t, e, "group.expiry"); a.Target != "contractors" || !strings.Contains(a.Detail, "bob") || !strings.Contains(a.Detail, "until=") {
		t.Errorf("audit = %+v", a)
	}
	if err := e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "bob", nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ = store.Load()
	if gc := cfg.Groups["contractors"]; gc != nil && len(gc.Expiry) != 0 {
		t.Errorf("expiry not removed: %+v", gc.Expiry)
	}
}

func TestPreviewRule(t *testing.T) {
	e, _ := evalEnv(t)
	e.ll.AddUser("zed", "zed@example.org", "Zed", "")
	setCity(t, e, "zed", "MILAN")
	setCity(t, e, "portcullis-hub", "Milan") // never a rule member
	// Any signed-in caller, including one with no permissions.
	bob := callerFor(t, e, "bob")
	got, err := e.svc.PreviewRule(ctx, bob, mustRule(t, `city = "milan"`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bob", "carol", "zed"}; !reflect.DeepEqual(got, want) {
		t.Errorf("preview = %v, want %v", got, want)
	}
	got, err = e.svc.PreviewRule(ctx, bob, mustRule(t, `city = "Paris"`))
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("no match = %#v %v", got, err)
	}
	_, err = e.svc.PreviewRule(ctx, bob, mustRule(t, `office = "x"`))
	wantStatus(t, "unknown field", err, 400)
	_, err = e.svc.PreviewRule(ctx, bob, &rules.Expr{Op: rules.OpIs, Field: "city"})
	wantStatus(t, "invalid", err, 400)
	_, err = e.svc.PreviewRule(ctx, bob, nil)
	wantStatus(t, "nil rule", err, 400)
	_, err = e.svc.PreviewRule(ctx, nil, mustRule(t, `city = "milan"`))
	wantStatus(t, "no caller", err, 403)
	// Not audited.
	all, _ := e.svc.Recent(1000)
	for _, a := range all {
		if strings.Contains(a.Action, "preview") {
			t.Errorf("preview audited: %+v", a)
		}
	}
}

func TestManualAgainKeepsTemporaryAccess(t *testing.T) {
	e, store := evalEnv(t)
	if err := e.svc.ConvertApply(ctx, asRoot, "milan", mustRule(t, `city = "Milan"`), nil); err != nil {
		t.Fatal(err)
	}
	soon := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	e.ll.AddUser("zed", "zed@example.org", "Zed", "")
	for _, ex := range []directory.Exception{
		{User: "dave", Reason: "temp", Include: true, Until: &soon},    // member: becomes expiry
		{User: "zed", Reason: "temp", Include: true, Until: &soon},     // removed below: no expiry
		{User: "carol", Reason: "leave", Include: false, Until: &soon}, // kept out: no expiry
	} {
		if err := e.svc.AddException(ctx, asRoot, "milan", ex); err != nil {
			t.Fatal(err)
		}
	}
	evaluate(t, e, time.Now().UTC())
	e.ll.RemoveMember("milan", "zed")
	if err := e.svc.SetGroupRule(ctx, asRoot, "milan", nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	gc := cfg.Groups["milan"]
	if gc == nil || gc.Rule != nil || len(gc.Exceptions) != 0 {
		t.Fatalf("group = %+v", gc)
	}
	if len(gc.Expiry) != 1 || !gc.Expiry["dave"].Equal(soon) {
		t.Errorf("expiry = %+v", gc.Expiry)
	}
	if a := newestAudit(t, e, "group.rule"); !strings.Contains(a.Detail, "expiry=dave@") || !strings.Contains(a.Detail, "dropped_exceptions=3") {
		t.Errorf("audit = %+v", a)
	}
	// The expiry is enforced on the now-manual group.
	evaluate(t, e, soon)
	wantMembers(t, e, "milan", "bob")
}

func TestEvaluatorBlocksAddsToGuardingGroupOnEditableField(t *testing.T) {
	e, _ := evalEnv(t)
	if err := e.svc.ConvertApply(ctx, asRoot, "milan", mustRule(t, `city = "Milan"`), nil); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "milan", "bob", "carol")
	// An app enabled later uses milan as its admin group.
	e.svc.Apps = func() []directory.App {
		return []directory.App{{ID: "late", Name: "Late", Enabled: true, AccessGroup: "users_late", AdminGroup: "milan"}}
	}
	setCity(t, e, "dave", "Milan") // would join
	setCity(t, e, "carol", "Rome") // leaves: removals still apply
	for i := 0; i < 2; i++ {
		rep := evaluate(t, e, time.Now().UTC())
		wantMembers(t, e, "milan", "bob")
		found := false
		for _, msg := range rep.Errors {
			found = found || (strings.Contains(msg, "milan") && strings.Contains(msg, "city") && strings.Contains(msg, "admin group of app late"))
		}
		if !found {
			t.Errorf("run %d: errors = %v", i, rep.Errors)
		}
	}
	cfg, _ := e.svc.Store.Load()
	got, err := e.svc.DesiredFromLLDAP(ctx, cfg, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["milan"], map[string]bool{"bob": true}) {
		t.Errorf("desired = %v", got["milan"])
	}
}

func TestConvertReportsDroppedExpiry(t *testing.T) {
	e, _ := evalEnv(t)
	e.ll.AddGroup("office", "bob", "dave")
	until := time.Now().Add(time.Hour)
	for _, u := range []string{"bob", "dave"} {
		if err := e.svc.SetMemberExpiry(ctx, asRoot, "office", u, &until); err != nil {
			t.Fatal(err)
		}
	}
	rule := mustRule(t, `city = "Milan"`)
	p, err := e.svc.ConvertPreview(ctx, asRoot, "office", rule)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.ExpiryDropped, []string{"bob"}) {
		t.Errorf("ExpiryDropped = %v", p.ExpiryDropped)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "office", rule, []string{"dave"}); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "group.rule"); !strings.Contains(a.Detail, "dropped_expiry=bob") {
		t.Errorf("audit = %+v", a)
	}
}

func TestNilGroupConfigEntry(t *testing.T) {
	e, store := evalEnv(t)
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "site", Label: "Site", Kind: directory.FieldKindList, Values: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	cfg.Groups["ghost"] = nil
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save with a nil group entry: %v", err)
	}
	if err := e.svc.UpdateField(ctx, asRoot, directory.Field{Name: "site", Label: "Site", Kind: directory.FieldKindList, Values: []string{"a"}}); err != nil {
		t.Errorf("UpdateField: %v", err)
	}
	if err := e.svc.DeleteField(ctx, asRoot, "site", "site"); err != nil {
		t.Errorf("DeleteField: %v", err)
	}
	if _, err := e.svc.DesiredFromLLDAP(ctx, &directory.Config{Groups: map[string]*directory.GroupConfig{"ghost": nil}}, time.Now()); err != nil {
		t.Errorf("Desired: %v", err)
	}
}
