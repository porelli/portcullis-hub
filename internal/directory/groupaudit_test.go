package directory_test

import (
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// groupEntries is the audit entries ForGroup(g) keeps, newest first.
func groupEntries(t *testing.T, e *env, g string) []directory.AuditEntry {
	t.Helper()
	got, err := e.svc.RecentMatching(1000, directory.AuditScan, directory.ForGroup(g))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestCreateUserAuditsEachGroup: a manual group a new account is put in
// gets its own group.add_member entry, so the group's History shows it;
// no other group's History does.
func TestCreateUserAuditsEachGroup(t *testing.T) {
	e := newEnv(t)
	e.ll.AddGroup("users_app")
	e.ll.AddGroup("users_apps")
	e.ll.AddGroup("ops")
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "dave", Email: "dave@example.org", Groups: []string{"users_app", "ops"}}); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"users_app", "ops"} {
		got := groupEntries(t, e, g)
		if len(got) != 1 || got[0].Action != "group.add_member" || got[0].Target != g || got[0].Detail != "dave (account created)" || got[0].Result != "ok" || got[0].Actor != "root" {
			t.Errorf("%s history = %+v", g, got)
		}
	}
	if got := groupEntries(t, e, "users_apps"); len(got) != 0 {
		t.Errorf("users_apps history = %+v, want none", got)
	}
	// The person's history keeps them too (their username first).
	adds := 0
	got, _ := e.svc.RecentMatching(1000, directory.AuditScan, directory.ForUser("dave"))
	for _, a := range got {
		if a.Action == "group.add_member" {
			adds++
		}
	}
	if adds != 2 {
		t.Errorf("dave's history = %+v", got)
	}
	// A refused create adds nobody and says so nowhere but user.create.
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "dave", Email: "dave2@example.org", Groups: []string{"users_apps"}}); status(err) != 409 {
		t.Fatalf("dup create = %v", err)
	}
	if got := groupEntries(t, e, "users_apps"); len(got) != 0 {
		t.Errorf("users_apps history after a refused create = %+v", got)
	}
}

// TestDeleteUserAuditsEachGroup: deleting an account audits its removal
// from each group it was in, on that group.
func TestDeleteUserAuditsEachGroup(t *testing.T) {
	e := newEnv(t)
	e.ll.AddGroup("users_app", "alice")
	e.ll.AddGroup("ops", "alice")
	e.ll.AddGroup("other")
	if err := deleteErr(e.svc.DeleteUser(ctx, asRoot, "alice", "alice")); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"users_app", "ops"} {
		got := groupEntries(t, e, g)
		if len(got) != 1 || got[0].Action != "group.remove_member" || got[0].Detail != "alice (account deleted)" || got[0].Result != "ok" {
			t.Errorf("%s history = %+v", g, got)
		}
	}
	if got := groupEntries(t, e, "other"); len(got) != 0 {
		t.Errorf("other history = %+v", got)
	}
}
