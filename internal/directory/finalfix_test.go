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
	if a := newestAudit(t, e, "group.delete"); !strings.Contains(a.Detail, "purged=") || !strings.Contains(a.Detail, "rule of milan") || !strings.Contains(a.Detail, "logout=bob,carol,dave") {
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
