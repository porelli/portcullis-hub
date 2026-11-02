package directory_test

import (
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
	if err := e.svc.ResolveActor(ctx, "root"); err != nil {
		t.Errorf("ResolveActor(root) = %v", err)
	}
	for _, a := range []string{"alice", "", "nobody"} {
		if err := e.svc.ResolveActor(ctx, a); err == nil {
			t.Errorf("ResolveActor(%q) accepted", a)
		}
	}
	if made, w, err := e.svc.CreateInstanceGroup(ctx, "root", "users_grafana-b"); err != nil || !made || len(w) != 0 || !e.ll.HasGroup("users_grafana-b") {
		t.Fatalf("create: %v %v %v", made, w, err)
	}
	if made, w, err := e.svc.CreateInstanceGroup(ctx, "root", "users_grafana-b"); err != nil || made || len(w) != 1 || !strings.Contains(w[0], "already exists") {
		t.Errorf("create existing: %v %v %v", made, w, err)
	}
	// Purged leftovers are a warning, but the group was created (an undo
	// must delete it).
	cfg, _ = store.Load()
	cfg.Groups["users_grafana-c"] = &directory.GroupConfig{Expiry: map[string]time.Time{"alice": time.Now().Add(time.Hour)}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if made, w, err := e.svc.CreateInstanceGroup(ctx, "root", "users_grafana-c"); err != nil || !made || len(w) != 1 || !strings.Contains(w[0], "purged leftovers") {
		t.Errorf("create with leftovers: %v %v %v", made, w, err)
	}
	e.ll.AddGroup("admin_grafana-b", "alice")
	if w, err := e.svc.DeleteInstanceGroup(ctx, "root", "admin_grafana-b"); err != nil || len(w) != 0 || e.ll.HasGroup("admin_grafana-b") {
		t.Fatalf("delete: %v %v", w, err)
	}
	if a := newestAudit(t, e, "group.delete"); a.Actor != "root" || a.Target != "admin_grafana-b" || !strings.Contains(a.Detail, "sign_out=alice") {
		t.Errorf("audit = %+v", a)
	}
	if w, err := e.svc.DeleteInstanceGroup(ctx, "root", "admin_grafana-b"); err != nil || len(w) != 0 {
		t.Errorf("delete again: %v %v", w, err)
	}
	for _, g := range []string{"lldap_admin", "extra_admins", "ops_admins", "inviters"} {
		e.ll.AddGroup(g)
		w, err := e.svc.DeleteInstanceGroup(ctx, "root", g)
		if err != nil || len(w) != 1 || !strings.Contains(w[0], "kept") || !e.ll.HasGroup(g) {
			t.Errorf("%s: %v %v", g, w, err)
		}
	}
	// A rule group is kept too (its membership is an admin's rule).
	e.ll.AddGroup("milan")
	setRule(t, store, "milan", `city = "Milan"`)
	if w, err := e.svc.DeleteInstanceGroup(ctx, "root", "milan"); err != nil || len(w) != 1 || !strings.Contains(w[0], "rule group") || !e.ll.HasGroup("milan") {
		t.Errorf("rule group: %v %v", w, err)
	}
	// Not an admin: refused like the Users & Groups page.
	e.ll.AddGroup("users_x")
	if _, err := e.svc.DeleteInstanceGroup(ctx, "alice", "users_x"); err == nil || !e.ll.HasGroup("users_x") {
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
