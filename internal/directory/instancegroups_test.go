package directory_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// TestInstanceGroups: an instance's groups are created and deleted through
// the guarded group operations; protected and permission groups survive a
// delete with a warning; missing groups are no error (retries).
func TestInstanceGroups(t *testing.T) {
	e, store := evalEnv(t)
	cfg, _ := store.Load()
	cfg.Permissions[directory.PermInvite] = "inviters"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("inviters")
	if err := e.svc.ResolveActor(ctx, directory.Human("root")); err != nil {
		t.Errorf("ResolveActor(root) = %v", err)
	}
	for _, a := range []string{"alice", "", "nobody"} {
		if err := e.svc.ResolveActor(ctx, directory.Human(a)); err == nil {
			t.Errorf("ResolveActor(%q) accepted", a)
		}
	}
	if made, w, err := e.svc.CreateInstanceGroup(ctx, directory.Human("root"), "users_grafana-b"); err != nil || !made || len(w) != 0 || !e.ll.HasGroup("users_grafana-b") {
		t.Fatalf("create: %v %v %v", made, w, err)
	}
	if made, w, err := e.svc.CreateInstanceGroup(ctx, directory.Human("root"), "users_grafana-b"); err != nil || made || len(w) != 1 || !strings.Contains(w[0], "already exists") {
		t.Errorf("create existing: %v %v %v", made, w, err)
	}
	// Purged leftovers are a warning, but the group was created (an undo
	// must delete it).
	cfg, _ = store.Load()
	cfg.Groups["users_grafana-c"] = &directory.GroupConfig{Expiry: map[string]time.Time{"alice": time.Now().Add(time.Hour)}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if made, w, err := e.svc.CreateInstanceGroup(ctx, directory.Human("root"), "users_grafana-c"); err != nil || !made || len(w) != 1 || !strings.Contains(w[0], "purged leftovers") {
		t.Errorf("create with leftovers: %v %v %v", made, w, err)
	}
	e.ll.AddGroup("admin_grafana-b", "alice")
	if w, err := e.svc.DeleteInstanceGroup(ctx, directory.Human("root"), "admin_grafana-b"); err != nil || len(w) != 0 || e.ll.HasGroup("admin_grafana-b") {
		t.Fatalf("delete: %v %v", w, err)
	}
	if a := newestAudit(t, e, "group.delete"); a.Actor != "root" || a.Target != "admin_grafana-b" || !strings.Contains(a.Detail, "sign_out=alice") {
		t.Errorf("audit = %+v", a)
	}
	if w, err := e.svc.DeleteInstanceGroup(ctx, directory.Human("root"), "admin_grafana-b"); err != nil || len(w) != 0 {
		t.Errorf("delete again: %v %v", w, err)
	}
	for _, g := range []string{"lldap_admin", "extra_admins", "ops_admins", "inviters"} {
		e.ll.AddGroup(g)
		w, err := e.svc.DeleteInstanceGroup(ctx, directory.Human("root"), g)
		if err != nil || len(w) != 1 || !strings.Contains(w[0], "kept") || !e.ll.HasGroup(g) {
			t.Errorf("%s: %v %v", g, w, err)
		}
	}
	// A rule group is kept too (its membership is an admin's rule).
	e.ll.AddGroup("milan")
	setRule(t, store, "milan", `city = "Milan"`)
	if w, err := e.svc.DeleteInstanceGroup(ctx, directory.Human("root"), "milan"); err != nil || len(w) != 1 || !strings.Contains(w[0], "rule group") || !e.ll.HasGroup("milan") {
		t.Errorf("rule group: %v %v", w, err)
	}
	// Not an admin: refused like the Users & Groups page.
	e.ll.AddGroup("users_x")
	if _, err := e.svc.DeleteInstanceGroup(ctx, directory.Human("alice"), "users_x"); err == nil || !e.ll.HasGroup("users_x") {
		t.Errorf("non-admin delete: %v", err)
	}
}

// MissingInstanceGroups: names that are no LLDAP group, case-insensitive,
// deduplicated; read-only.
func TestMissingInstanceGroups(t *testing.T) {
	e := newEnv(t)
	e.ll.AddGroup("users_grafana")
	got, err := e.svc.MissingInstanceGroups(ctx, []string{"USERS_grafana", "admin_grafana", "admin_grafana", "", "users_x"})
	if err != nil || strings.Join(got, ",") != "admin_grafana,users_x" {
		t.Errorf("missing = %v %v", got, err)
	}
	if e.ll.HasGroup("admin_grafana") {
		t.Error("the check created a group")
	}
}

// TestDeleteInstanceGroupKeptUnavailable: while Users & Groups doesn't
// answer DeleteInstanceGroup answers a *KeptUnavailableError (errors.Is
// ErrKeptUnavailable: an enable's Stop retries it), its text the warning
// for people; a protected group's is a plain warning.
func TestDeleteInstanceGroupKeptUnavailable(t *testing.T) {
	e := newEnv(t)
	e.ll.AddGroup("lldap_admin")
	w, err := e.svc.DeleteInstanceGroup(ctx, directory.Human("root"), "lldap_admin")
	if err != nil || len(w) != 1 || errors.Is(err, directory.ErrKeptUnavailable) {
		t.Fatalf("protected: %v %v", w, err)
	}
	e.ll.AddGroup("users_x")
	e.svc.LLDAP = brokenDir{e.svc.LLDAP}
	w, err = e.svc.DeleteInstanceGroup(ctx, directory.Human("root"), "users_x")
	var kept *directory.KeptUnavailableError
	if !errors.Is(err, directory.ErrKeptUnavailable) || !errors.As(err, &kept) || kept.Group != "users_x" || len(w) != 0 ||
		!strings.Contains(err.Error(), "group users_x was kept: users & groups is not available") {
		t.Fatalf("unavailable: %v %v", w, err)
	}
}

// TestCheckBindGroups (apps, contract §11.9): the groups an instance is
// bound to must exist (matched case-insensitively, answered as LLDAP
// names them); the users group may not be a built-in, administrator or
// permission group, the admins group may (lldap_admin included); Users &
// Groups down is 503.
func TestCheckBindGroups(t *testing.T) {
	e, store := evalEnv(t)
	cfg, _ := store.Load()
	cfg.Permissions[directory.PermInvite] = "inviters"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"Team", "inviters", "lldap_admin", "lldap_password_manager", "lldap_strict_readonly", "extra_admins", "milan"} {
		e.ll.AddGroup(g)
	}
	setRule(t, store, "milan", `city = "Milan"`)
	status := func(err error) int {
		var de *directory.Error
		if errors.As(err, &de) {
			return de.Status
		}
		return 0
	}
	if u, a, err := e.svc.CheckBindGroups(ctx, "team", "lldap_admin"); err != nil || u != "Team" || a != "lldap_admin" {
		t.Errorf("ok = %q %q %v", u, a, err)
	}
	// A rule group is a fine users group (its rule decides who uses it).
	if u, _, err := e.svc.CheckBindGroups(ctx, "milan", "Team"); err != nil || u != "milan" {
		t.Errorf("rule group = %q %v", u, err)
	}
	for _, g := range []string{"lldap_admin", "LLDAP_ADMIN", "lldap_password_manager", "lldap_strict_readonly", "extra_admins", "inviters"} {
		if _, _, err := e.svc.CheckBindGroups(ctx, g, "Team"); status(err) != 400 || !strings.Contains(err.Error(), "the users group can't be a built-in or administrator group") {
			t.Errorf("users %s = %v", g, err)
		}
	}
	if _, _, err := e.svc.CheckBindGroups(ctx, "nope", "Team"); err == nil || err.Error() != "unknown group nope" {
		t.Errorf("unknown users = %v", err)
	}
	if _, _, err := e.svc.CheckBindGroups(ctx, "Team", "gone"); err == nil || err.Error() != "unknown group gone" {
		t.Errorf("unknown admins = %v", err)
	}
	// Case-only twins (fix round 1): the exact name wins; a name matching
	// two of them only by case is ambiguous (400); a unique folded match
	// is used as LLDAP spells it.
	e.ll.AddGroup("Ops")
	e.ll.AddGroup("OPS")
	if u, a, err := e.svc.CheckBindGroups(ctx, "Ops", "OPS"); err != nil || u != "Ops" || a != "OPS" {
		t.Errorf("exact twins = %q %q %v", u, a, err)
	}
	if _, _, err := e.svc.CheckBindGroups(ctx, "ops", "Team"); status(err) != 400 ||
		err.Error() != "group ops is ambiguous: OPS and Ops differ only in case; use the exact name" {
		t.Errorf("ambiguous users = %v", err)
	}
	if _, _, err := e.svc.CheckBindGroups(ctx, "Team", "oPs"); status(err) != 400 || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("ambiguous admins = %v", err)
	}
	if _, _, err := e.svc.CheckBindGroups(ctx, "nope", "Team"); !errors.Is(err, directory.ErrUnknownGroup) {
		t.Errorf("unknown is not ErrUnknownGroup: %v", err)
	}
	e.svc.LLDAP = brokenDir{e.svc.LLDAP}
	if _, _, err := e.svc.CheckBindGroups(ctx, "Team", "Team"); status(err) != 503 {
		t.Errorf("down = %v", err)
	}
}
