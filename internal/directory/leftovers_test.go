package directory_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// brokenAudit points the audit log at a path that can't be written.
func brokenAudit(t *testing.T, e *env) {
	t.Helper()
	e.svc.Audit = &directory.AuditLog{Path: filepath.Join(t.TempDir(), "missing", "audit.jsonl")}
}

// A membership change that succeeded in LLDAP signs the removed users out
// even when writing the audit entry fails afterwards.
func TestSignOutDespiteAuditFailure(t *testing.T) {
	e, _ := evalEnv(t)
	e.ll.AddGroup("office", "bob", "carol")
	e.kc.Import("bob")
	e.kc.Update("bob", func(u *kctest.User) { u.Sessions = 2 })
	e.kc.Import("carol")
	e.kc.Update("carol", func(u *kctest.User) { u.Sessions = 2 })
	brokenAudit(t, e)

	_, err := e.svc.RemoveMember(ctx, asRoot, "office", "bob")
	if err == nil || !strings.Contains(err.Error(), "audit log failed") {
		t.Fatalf("RemoveMember: %v", err)
	}
	wantMembers(t, e, "office", "carol")
	if e.kc.Get("bob").Sessions != 0 {
		t.Error("RemoveMember: removed member not signed out after the audit write failed")
	}

	_, err = e.svc.DeleteGroup(ctx, asRoot, "office", "office")
	if err == nil || !strings.Contains(err.Error(), "audit log failed") {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if e.ll.HasGroup("office") {
		t.Fatal("group not deleted")
	}
	if e.kc.Get("carol").Sessions != 0 {
		t.Error("DeleteGroup: former member not signed out after the audit write failed")
	}
}

// A rule group whose rule matches an empty person that later becomes a
// guarding group (an app enabled with it as admin_group) gets no
// additions; the evaluator reports it every run and Desired agrees.
func TestEvaluatorBlocksEmptyMatchInNewGuardingGroup(t *testing.T) {
	e := guardEnv(t)
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "dept", Label: "Dept", Kind: directory.FieldKindText, AdminOnly: true}); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("leads")
	if err := e.svc.ConvertApply(ctx, asRoot, "leads", mustRule(t, `not dept = "X"`), nil); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, time.Now().UTC())
	wantMembers(t, e, "leads", "alice", "bob", "carol", "dave", "root")

	apps := e.svc.Apps
	e.svc.Apps = func() []directory.App {
		return append(apps(), directory.App{ID: "late", Name: "Late", Enabled: true, AccessGroup: "users_late", AdminGroup: "leads"})
	}
	e.ll.AddUser("erin", "erin@example.org", "Erin", "") // a new, empty account
	for run := 0; run < 2; run++ {
		rep := evaluate(t, e, time.Now().UTC())
		wantMembers(t, e, "leads", "alice", "bob", "carol", "dave", "root")
		found := false
		for _, er := range rep.Errors {
			found = found || (strings.Contains(er, "leads") && strings.Contains(er, "no details"))
		}
		if !found {
			t.Errorf("run %d: errors = %v", run, rep.Errors)
		}
	}
	cfg, _ := e.svc.Store.Load()
	if d, _ := e.svc.DesiredFromLLDAP(ctx, cfg, time.Now().UTC()); d["leads"]["erin"] {
		t.Errorf("Desired adds erin to leads: %v", d["leads"])
	}
}
