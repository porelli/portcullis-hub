package directory_test

import (
	"context"
	"errors"
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

// failSetAttrs is an LLDAP whose SetUserAttributes fails.
type failSetAttrs struct{ directory.Directory }

func (failSetAttrs) SetUserAttributes(context.Context, string, map[string][]string, []string) error {
	return errors.New("simulated LLDAP failure")
}

// userAttrs returns user's custom attributes (nil if no such user).
func userAttrs(t *testing.T, e *env, user string) map[string][]string {
	t.Helper()
	us, err := e.svc.LLDAP.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range us {
		if u.ID == user {
			return u.Attributes
		}
	}
	return nil
}

func invitedUsers(e *env) []string {
	e.invites.mu.Lock()
	defer e.invites.mu.Unlock()
	return append([]string{}, e.invites.users...)
}

// An import create row writes the account and its details in one locked
// run: nothing (OnChange, so no evaluation either) ever sees the account
// without them, and there is one audit entry.
func TestImportCreateSetsAttrsAtomically(t *testing.T) {
	e, _ := evalEnv(t)
	var seenEmpty bool
	e.svc.OnChange = func() {
		if a := userAttrs(t, e, "zed"); a != nil && len(a["city"]) == 0 {
			seenEmpty = true
		}
	}
	req := directory.ApplyRequest{Rows: []directory.ApplyRow{{User: "zed", Create: true, Email: "zed@example.org", DisplayName: "Zed", Attrs: map[string][]string{"city": {" Milan "}}}}}
	res, err := e.svc.ImportApply(ctx, asRoot, req)
	if err != nil || len(res.Rows) != 1 || !res.Rows[0].OK || res.Rows[0].Invite == nil {
		t.Fatalf("ImportApply = %+v %v", res, err)
	}
	if got := userAttrs(t, e, "zed")["city"]; len(got) != 1 || got[0] != "Milan" {
		t.Errorf("zed city = %v", got)
	}
	if seenEmpty {
		t.Error("a change notification saw zed without details")
	}
	entries, _ := e.svc.Recent(100)
	creates := 0
	for _, a := range entries {
		if a.Target == "zed" {
			if a.Action != "user.create" {
				t.Errorf("extra audit entry %+v", a)
			}
			if a.Action == "user.create" {
				creates++
			}
			if !strings.Contains(a.Detail, "city=") {
				t.Errorf("create audit detail = %q", a.Detail)
			}
		}
	}
	if creates != 1 {
		t.Errorf("user.create entries for zed = %d", creates)
	}
}

// An invalid attribute (or a failing write of the details) creates no
// account and sends no invite.
func TestCreateUserInvalidAttrCreatesNothing(t *testing.T) {
	e, _ := evalEnv(t)
	for _, attrs := range []map[string][]string{{"city": {" "}}, {"nope": {"x"}}, {"manager": {"ghost"}}} {
		_, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Attrs: attrs})
		wantStatus(t, "CreateUser invalid attrs", err, 400)
		if e.ll.HasUser("zed") {
			t.Fatalf("%v: account created", attrs)
		}
	}
	req := directory.ApplyRequest{Rows: []directory.ApplyRow{{User: "zed", Create: true, Email: "zed@example.org", Attrs: map[string][]string{"city": {""}}}}}
	if res, err := e.svc.ImportApply(ctx, asRoot, req); err != nil || res.Rows[0].OK || e.ll.HasUser("zed") {
		t.Fatalf("ImportApply invalid attr = %+v %v", res, err)
	}

	real := e.svc.LLDAP
	e.svc.LLDAP = failSetAttrs{real}
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Attrs: map[string][]string{"city": {"Milan"}}}); err == nil {
		t.Fatal("CreateUser with a failing attribute write succeeded")
	}
	e.svc.LLDAP = real
	if e.ll.HasUser("zed") {
		t.Error("failed attribute write left the account behind")
	}
	if inv := invitedUsers(e); len(inv) != 0 {
		t.Errorf("invites sent: %v", inv)
	}
}

// A delegate without edit_details can't create an account with details
// (directly or by import); with both permissions they can.
func TestCreateUserAttrsNeedEditDetails(t *testing.T) {
	e := delegateEnv(t)
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "city", Label: "City", Kind: directory.FieldKindText}); err != nil {
		t.Fatal(err)
	}
	ivy := callerFor(t, e, "ivy")
	attrs := map[string][]string{"city": {"Milan"}}
	_, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Attrs: attrs})
	wantStatus(t, "inviter creates with details", err, 403)
	req := directory.ApplyRequest{Rows: []directory.ApplyRow{{User: "zed", Create: true, Email: "zed@example.org", Attrs: attrs}}}
	if res, err := e.svc.ImportApply(ctx, ivy, req); err != nil || res.Rows[0].OK {
		t.Errorf("inviter import with details = %+v %v", res, err)
	}
	if e.ll.HasUser("zed") || len(invitedUsers(e)) != 0 {
		t.Fatal("account created or invited without edit_details")
	}
	hera := callerFor(t, e, "hera")
	if res, err := e.svc.ImportApply(ctx, hera, req); err != nil || !res.Rows[0].OK {
		t.Fatalf("hera import = %+v %v", res, err)
	}
	if got := userAttrs(t, e, "zed")["city"]; len(got) != 1 || got[0] != "Milan" {
		t.Errorf("zed city = %v", got)
	}
}
