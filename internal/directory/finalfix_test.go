package directory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// failGroupDelete is an LLDAP whose DeleteGroup fails.
type failGroupDelete struct{ directory.Directory }

func (failGroupDelete) DeleteGroup(context.Context, int) error {
	return errors.New("simulated LLDAP failure")
}

// Live E2E B2 / final review C1: deleting a group purges its rule,
// exceptions, grace entries and permission grants, so a group re-created
// with the same name starts clean; a failed LLDAP delete changes nothing.
func TestDeleteGroupPurgesConfig(t *testing.T) {
	e, store := evalEnv(t)
	until := time.Now().UTC().Add(time.Hour)
	setRule(t, store, "milan", `city = "Milan"`, directory.Exception{User: "dave", Reason: "visiting", By: "root", Include: true, Until: &until, At: time.Now().UTC()})
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "milan", "bob", "carol", "dave")
	cfg, _ := store.Load()
	cfg.Permissions[directory.PermInvite] = "milan"
	cfg.Grace = append(cfg.Grace, directory.GraceEntry{User: "zed", Group: "milan", At: time.Now().UTC(), Until: time.Now().UTC().Add(time.Hour)})
	cfg.Groups["other"] = &directory.GroupConfig{Expiry: map[string]time.Time{"bob": until}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	e.kc.Import("bob")
	e.kc.Update("bob", func(u *kctest.User) { u.Sessions = 2 })

	// A failed LLDAP delete leaves directory.yaml as it was.
	real := e.svc.LLDAP
	e.svc.LLDAP = failGroupDelete{real}
	if _, err := e.svc.DeleteGroup(ctx, asRoot, "milan", "milan"); err == nil {
		t.Fatal("DeleteGroup with a failing LLDAP succeeded")
	}
	e.svc.LLDAP = real
	if c, _ := store.Load(); c.Groups["milan"] == nil || c.Permissions[directory.PermInvite] != "milan" || len(c.Grace) != 1 {
		t.Fatalf("failed delete changed directory.yaml: %+v", c)
	}
	if e.kc.Get("bob").Sessions != 2 {
		t.Error("failed delete signed members out")
	}

	res, err := e.svc.DeleteGroup(ctx, asRoot, "milan", "milan")
	if err != nil || len(res.Warnings) != 0 || e.ll.HasGroup("milan") {
		t.Fatalf("DeleteGroup: %+v %v", res, err)
	}
	c, _ := store.Load()
	if c.Groups["milan"] != nil || c.Permissions[directory.PermInvite] != "" || len(c.Grace) != 0 {
		t.Errorf("leftovers after delete: groups=%v perms=%v grace=%v", c.Groups, c.Permissions, c.Grace)
	}
	if c.Groups["other"] == nil {
		t.Error("another group's config was purged")
	}
	if e.kc.Get("bob").Sessions != 0 {
		t.Error("former member still has Keycloak sessions")
	}
	if a := newestAudit(t, e, "group.delete"); !strings.Contains(a.Detail, "purged=") || !strings.Contains(a.Detail, "rule of milan") || !strings.Contains(a.Detail, "sign_out=bob,carol,dave") {
		t.Errorf("audit = %+v", a)
	}

	// Re-created: no rule, no exception, no permission; the evaluator
	// leaves it empty.
	if res, err := e.svc.CreateGroup(ctx, asRoot, "milan"); err != nil || len(res.Warnings) != 0 {
		t.Fatalf("CreateGroup: %+v %v", res, err)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "milan")
	if c, _ := store.Load(); c.Groups["milan"] != nil {
		t.Errorf("re-created group has config %+v", c.Groups["milan"])
	}
	ov, _ := e.svc.Overview(ctx, "root")
	for _, g := range ov.Groups {
		if g.Name == "milan" && (g.Rule != nil || len(g.Exceptions) != 0) {
			t.Errorf("re-created group view = %+v", g)
		}
	}
}

// A group deleted in LLDAP's own UI leaves directory.yaml behind: creating
// the name again purges it and says so.
func TestCreateGroupPurgesLeftovers(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "Ghost", `city = "Milan"`)
	cfg, _ := store.Load()
	cfg.Permissions[directory.PermRemove] = "Ghost"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.CreateGroup(ctx, asRoot, "ghost")
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "rule of Ghost") || !strings.Contains(res.Warnings[0], "permission remove") {
		t.Fatalf("CreateGroup: %+v %v", res, err)
	}
	c, _ := store.Load()
	if len(c.Groups) != 0 || len(c.Permissions) != 0 {
		t.Errorf("leftovers kept: %+v %+v", c.Groups, c.Permissions)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "ghost")
}

// I3 + M3: RemoveMember signs the removed user out of Keycloak (a failure
// is a warning) and drops their expiry, so a re-add has none.
func TestRemoveMemberLogsOutAndDropsExpiry(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("office", "bob", "carol")
	until := time.Now().UTC().Add(time.Hour)
	if err := e.svc.SetMemberExpiry(ctx, asRoot, "office", "bob", &until); err != nil {
		t.Fatal(err)
	}
	e.kc.Import("bob")
	e.kc.Update("bob", func(u *kctest.User) { u.Sessions = 3 })
	res, err := e.svc.RemoveMember(ctx, asRoot, "office", "bob")
	if err != nil || len(res.Warnings) != 0 {
		t.Fatalf("RemoveMember: %+v %v", res, err)
	}
	if e.kc.Get("bob").Sessions != 0 {
		t.Error("removed member still has Keycloak sessions")
	}
	if c, _ := store.Load(); c.Groups["office"] != nil {
		t.Errorf("expiry kept after removal: %+v", c.Groups["office"])
	}
	if err := e.svc.AddMember(ctx, asRoot, "office", "bob"); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, until.Add(time.Minute))
	wantMembers(t, e, "office", "bob", "carol")
	ov, _ := e.svc.Overview(ctx, "root")
	for _, m := range usersByName(ov)["bob"].Memberships {
		if m.Group == "office" && m.Until != nil {
			t.Errorf("re-added membership has a stale expiry: %+v", m)
		}
	}

	// Keycloak down: removed anyway, warned.
	e.kc.SetDown(true)
	res, err = e.svc.RemoveMember(ctx, asRoot, "office", "carol")
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "carol") {
		t.Errorf("RemoveMember with Keycloak down: %+v %v", res, err)
	}
	wantMembers(t, e, "office", "bob")
}

// I1(a): a guarding group's rule must not match a person with no details
// (every brand-new account).
func TestGuardingRuleMustNotMatchEmpty(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("admin_app") // app "app"'s admin group
	e.ll.AddGroup("hr")
	e.ll.AddGroup("team")
	for _, r := range []string{`office is empty`, `not office = "HQ"`, `office = "HQ" or office is empty`} {
		_, err := e.svc.ConvertPreview(ctx, asRoot, "admin_app", mustRule(t, r))
		wantStatus(t, "ConvertPreview "+r, err, 409)
		err = e.svc.ConvertApply(ctx, asRoot, "admin_app", mustRule(t, r), nil)
		wantStatus(t, "ConvertApply "+r, err, 409)
		if err == nil || !strings.Contains(err.Error(), "no details") {
			t.Errorf("message = %v", err)
		}
		wantStatus(t, "ConvertApplyReviewed "+r, e.svc.ConvertApplyReviewed(ctx, asRoot, "admin_app", mustRule(t, r), nil, &directory.ConvertPreview{}), 409)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "admin_app", mustRule(t, `office = "HQ"`), nil); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "SetGroupRule empty", e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `not office = "Branch"`)), 409)

	// reports-to: an empty person has no manager, so "reports-to" doesn't
	// match them and "not reports-to" does. (manager is a person field;
	// admin-only so a guarding rule may use it.)
	adminOnly := true
	if _, err := e.svc.PatchField(ctx, asRoot, "manager", directory.FieldPatch{AdminOnly: &adminOnly}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "SetGroupRule not reports-to", e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `not manager reports-to "anna"`)), 409)
	if err := e.svc.SetGroupRule(ctx, asRoot, "admin_app", mustRule(t, `manager reports-to "anna"`)); err != nil {
		t.Errorf("SetGroupRule reports-to: %v", err)
	}

	// Permission groups too, and a grant to a rule group matching empty.
	if err := e.svc.SetPermission(ctx, asRoot, directory.PermEditDetails, "hr"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "ConvertApply hr", e.svc.ConvertApply(ctx, asRoot, "hr", mustRule(t, `office is empty`), nil), 409)
	if err := e.svc.ConvertApply(ctx, asRoot, "team", mustRule(t, `office is empty`), nil); err != nil {
		t.Fatal(err) // an ordinary group may
	}
	wantStatus(t, "SetPermission team", e.svc.SetPermission(ctx, asRoot, directory.PermRemove, "team"), 409)
}

// I1(b): the evaluator never adds a delegate-created account to a guarding
// group; once an admin acts on the account (clearing created_by) it does.
func TestEvaluatorSkipsDelegateCreatedInGuardingGroups(t *testing.T) {
	e := guardEnv(t)
	e.ll.AddGroup("admin_app")
	e.ll.AddGroup("hq")
	e.ll.AddUser("nina", "nina@example.org", "", "")
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "nina", map[string][]string{"office": {"HQ"}}, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.svc.Store.Load()
	cfg.CreatedBy["nina"] = "ivy"
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"admin_app", "hq"} {
		if err := e.svc.ConvertApply(ctx, asRoot, g, mustRule(t, `office = "HQ"`), nil); err != nil {
			t.Fatal(err)
		}
	}
	rep := evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "admin_app")
	wantMembers(t, e, "hq", "nina") // not guarding: added
	found := false
	for _, er := range rep.Errors {
		found = found || (strings.Contains(er, "admin_app") && strings.Contains(er, "nina") && strings.Contains(er, "delegate"))
	}
	if !found {
		t.Errorf("errors = %v", rep.Errors)
	}
	if d, _ := e.svc.DesiredFromLLDAP(ctx, cfg, time.Now().UTC()); d["admin_app"]["nina"] {
		t.Errorf("Desired adds nina to admin_app: %v", d["admin_app"])
	}
	if _, err := e.svc.SetPassword(ctx, asRoot, "nina", "", true, ""); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "admin_app", "nina")
}

// Triage (a) + I6: a list value is stored as the field's defined value
// whatever its case; the audit detail records old→new per changed field.
func TestSetDetailsCanonicalListValueAndAudit(t *testing.T) {
	e, _ := evalEnv(t)
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "team", Label: "Team", Kind: directory.FieldKindList, Values: []string{"Sales", "R&D"}}); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 200)
	if err := e.svc.SetDetails(ctx, asRoot, "bob", map[string][]string{"team": {"sALES"}, "city": {long}, "manager": {"carol"}}); err != nil {
		t.Fatal(err)
	}
	users, _ := e.svc.LLDAP.ListUsers(ctx)
	for _, u := range users {
		if u.ID == "bob" && (len(u.Attributes["team"]) != 1 || u.Attributes["team"][0] != "Sales") {
			t.Errorf("team = %v, want [Sales]", u.Attributes["team"])
		}
	}
	a := newestAudit(t, e, "user.details")
	for _, want := range []string{`team=""→"Sales"`, `city="Milan"→"xxxx`, `manager=""→"carol"`, "…"} {
		if !strings.Contains(a.Detail, want) {
			t.Errorf("audit detail %q lacks %q", a.Detail, want)
		}
	}
	if strings.Contains(a.Detail, long) {
		t.Error("long value not clipped in the audit detail")
	}
	// The rule on the canonical value matches.
	if got, err := e.svc.PreviewRule(ctx, asRoot, mustRule(t, `team = "Sales"`)); err != nil || len(got) != 1 || got[0] != "bob" {
		t.Errorf("PreviewRule = %v %v", got, err)
	}
	// Unchanged fields aren't listed.
	if err := e.svc.SetDetails(ctx, asRoot, "bob", map[string][]string{"team": {"Sales"}, "city": {"Rome"}}); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "user.details"); strings.Contains(a.Detail, "team=") || !strings.Contains(a.Detail, `city="xxx`) || !strings.Contains(a.Detail, `→"Rome"`) {
		t.Errorf("audit detail = %q", a.Detail)
	}
}

// M2: deleting a user warns about the people whose person fields still
// name them and the rules that name them (reports-to).
func TestDeleteUserListsReferences(t *testing.T) {
	e, store := evalEnv(t)
	if err := e.svc.SetDetails(ctx, asRoot, "bob", map[string][]string{"manager": {"dave"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetDetails(ctx, asRoot, "carol", map[string][]string{"manager": {"Dave"}}); err != nil {
		t.Fatal(err)
	}
	setRule(t, store, "milan", `manager reports-to "dave"`)
	res, err := e.svc.DeleteUser(ctx, asRoot, "dave", "dave")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "manager of bob, manager of carol, rule of milan") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	res, err = e.svc.DeleteUser(ctx, asRoot, "alice", "alice")
	if err != nil || len(res.Warnings) != 0 {
		t.Errorf("unreferenced delete: %+v %v", res, err)
	}
}

// M4: an "added" exception with an end isn't published while the group's
// rule matches the user anyway (they stay by rule); it is once they stop
// matching.
func TestPublishSkipsIncludeEndOfRuleMatch(t *testing.T) {
	e, store := evalEnv(t)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	now := time.Now().UTC()
	setRule(t, store, "milan", `city = "Milan"`,
		directory.Exception{User: "bob", Reason: "x", By: "root", Include: true, Until: &until, At: now},
		directory.Exception{User: "dave", Reason: "x", By: "root", Include: true, Until: &until, At: now})
	evaluate(t, e, now)
	pub, err := e.svc.Publish(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub.Expiring) != 1 || pub.Expiring[0].User != "dave" {
		t.Errorf("expiring = %+v, want only dave", pub.Expiring)
	}
	setCity(t, e, "bob", "Rome")
	pub, _ = e.svc.Publish(ctx, now)
	if len(pub.Expiring) != 2 {
		t.Errorf("expiring after bob moved = %+v", pub.Expiring)
	}
	// Rule groups the evaluator skips (an administrator group) keep it.
	setRule(t, store, "lldap_password_manager", `city = "Milan"`,
		directory.Exception{User: "carol", Reason: "x", By: "root", Include: true, Until: &until, At: now})
	e.ll.AddGroup("lldap_password_manager", "carol")
	pub, _ = e.svc.Publish(ctx, now)
	found := false
	for _, x := range pub.Expiring {
		found = found || (x.User == "carol" && x.Group == "lldap_password_manager")
	}
	if !found {
		t.Errorf("skipped group's exception end not published: %+v", pub.Expiring)
	}
}

func expiringHas(pub *directory.Published, group, user string) bool {
	for _, x := range pub.Expiring {
		if x.Group == group && x.User == user {
			return true
		}
	}
	return false
}

// Security review of M4: only an "added" exception's end is ever dropped,
// and only for a current member in the evaluator's real desired set; grace
// entries and manual expiries are always published.
func TestPublishSuppressesOnlyKeptExceptionEnds(t *testing.T) {
	e, store := evalEnv(t)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	now := time.Now().UTC()
	inc := func(u string) directory.Exception {
		return directory.Exception{User: u, Reason: "x", By: "root", Include: true, Until: &until, At: now}
	}
	setRule(t, store, "milan", `city = "Milan"`, inc("bob"), inc("carol"))
	evaluate(t, e, now)
	wantMembers(t, e, "milan", "bob", "carol")

	// carol matches but is not a member right now: published.
	e.ll.RemoveMember("milan", "carol")
	pub, err := e.svc.Publish(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if expiringHas(pub, "milan", "bob") || !expiringHas(pub, "milan", "carol") {
		t.Errorf("member+desired bob suppressed, non-member carol published: %+v", pub.Expiring)
	}

	// A grace entry and a manual expiry of the rule-matching member bob
	// are always published.
	cfg, _ := store.Load()
	cfg.Grace = append(cfg.Grace, directory.GraceEntry{User: "bob", Group: "milan", At: now.Add(-time.Minute), Until: now.Add(5 * time.Minute)})
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	pub, _ = e.svc.Publish(ctx, now)
	n := 0
	for _, x := range pub.Expiring {
		if x.Group == "milan" && x.User == "bob" {
			n++
			if !x.At.Equal(now.Add(-time.Minute).UTC()) {
				t.Errorf("bob entry = %+v, want only the grace one", x)
			}
		}
	}
	if n != 1 {
		t.Errorf("grace entry of bob: %d entries in %+v", n, pub.Expiring)
	}
	cfg, _ = store.Load()
	cfg.Grace = nil
	cfg.Groups["milan"].Expiry = map[string]time.Time{"bob": until}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if pub, _ = e.svc.Publish(ctx, now); !expiringHas(pub, "milan", "bob") {
		t.Errorf("manual expiry of bob suppressed: %+v", pub.Expiring)
	}

	// Adds blocked (a permission group whose rule uses a delegate-editable
	// field): not suppressed.
	e.ll.AddGroup("hr", "bob")
	cfg, _ = store.Load()
	delete(cfg.Groups, "milan")
	cfg.Permissions[directory.PermEditDetails] = "hr"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	setRule(t, store, "hr", `city = "Milan"`, inc("bob"))
	if pub, _ = e.svc.Publish(ctx, now); !expiringHas(pub, "hr", "bob") {
		t.Errorf("adds-blocked group's exception end suppressed: %+v", pub.Expiring)
	}

	// A delegate-created member of a guarding group: not suppressed.
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "office", Label: "Office", Kind: directory.FieldKindText, AdminOnly: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "bob", map[string][]string{"office": {"HQ"}}, nil); err != nil {
		t.Fatal(err)
	}
	setRule(t, store, "hr", `office = "HQ"`, inc("bob"))
	if pub, _ = e.svc.Publish(ctx, now); expiringHas(pub, "hr", "bob") {
		t.Errorf("admin-only guarding rule, member+desired: should be suppressed: %+v", pub.Expiring)
	}
	cfg, _ = store.Load()
	cfg.CreatedBy["bob"] = "ivy"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if pub, _ = e.svc.Publish(ctx, now); !expiringHas(pub, "hr", "bob") {
		t.Errorf("delegate-created member of a guarding group suppressed: %+v", pub.Expiring)
	}
}
