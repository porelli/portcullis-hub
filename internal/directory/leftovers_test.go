package directory_test

import (
	"path/filepath"
	"strings"
	"testing"

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
