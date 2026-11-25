package directory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// Verified emails (contract §9.8): directory.yaml email_verified.<uuid> =
// {email, at, by}; verified only while it holds the current LLDAP email.

func storeEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	return e
}

func verifiedRecord(t *testing.T, e *env, user string) (directory.EmailVerification, bool) {
	t.Helper()
	cfg, err := e.svc.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	v, ok := cfg.EmailVerified[e.ll.UUIDOf(user)]
	return v, ok
}

func verifiedEmails(t *testing.T, e *env) map[string]string {
	t.Helper()
	m, err := e.svc.Membership(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return m.VerifiedEmails
}

func overviewVerified(t *testing.T, e *env, user string) bool {
	t.Helper()
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range ov.Users {
		if u.Username == user {
			return u.EmailVerified
		}
	}
	t.Fatalf("%s not in the overview", user)
	return false
}

func TestAdminSetEmailVerified(t *testing.T) {
	e := storeEnv(t)
	if err := e.svc.UpdateUser(ctx, asRoot, "alice", strptr("Alice.New@example.org"), nil); err != nil {
		t.Fatal(err)
	}
	v, ok := verifiedRecord(t, e, "alice")
	if !ok || v.Email != "Alice.New@example.org" || v.By != "admin:root" || v.At.IsZero() || v.At.Location() != time.UTC {
		t.Fatalf("record = %+v %v", v, ok)
	}
	if got := verifiedEmails(t, e)["alice"]; got != "Alice.New@example.org" {
		t.Errorf("VerifiedEmails[alice] = %q", got)
	}
	if !overviewVerified(t, e, "alice") {
		t.Error("the person view says not verified")
	}
	raw, _ := os.ReadFile(e.svc.Store.Path)
	if !strings.Contains(string(raw), "email_verified:") {
		t.Errorf("directory.yaml:\n%s", raw)
	}
}

// TestAdminSaveWithoutChangeNotVerified (ruling C9): an admin saving a
// person with the email they already have never verifies it.
func TestAdminSaveWithoutChangeNotVerified(t *testing.T) {
	e := storeEnv(t)
	if err := e.svc.UpdateUser(ctx, asRoot, "alice", strptr(" ALICE@example.org "), strptr("Alice A")); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "alice"); ok {
		t.Fatalf("an unchanged email was verified: %+v", v)
	}
	if overviewVerified(t, e, "alice") {
		t.Error("the person view says verified")
	}
}

// TestSelfSetEmailNotVerified: changing your own email never verifies it,
// and clears the verification you had.
func TestSelfSetEmailNotVerified(t *testing.T) {
	e := storeEnv(t)
	e.ll.AddUser("rita", "rita@example.org", "Rita", "", "lldap_admin")
	rita := &directory.Caller{User: "rita", Admin: true}
	if err := e.svc.MarkEmailVerified(ctx, rita, "root"); err != nil {
		t.Fatal(err)
	}
	if _, ok := verifiedRecord(t, e, "root"); !ok {
		t.Fatal("not marked")
	}
	if err := e.svc.UpdateUser(ctx, asRoot, "root", strptr("root2@example.org"), nil); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "root"); ok {
		t.Fatalf("own change left a record: %+v", v)
	}
	if _, ok := verifiedEmails(t, e)["root"]; ok {
		t.Error("root's own email counts as verified")
	}
}

func TestVerificationClearedByLLDAPEdit(t *testing.T) {
	e := storeEnv(t)
	if err := e.svc.UpdateUser(ctx, asRoot, "alice", strptr("alice2@example.org"), nil); err != nil {
		t.Fatal(err)
	}
	if verifiedEmails(t, e)["alice"] != "alice2@example.org" {
		t.Fatal("not verified")
	}
	// LLDAP's own UI changes it (not through the Hub).
	other := "alice3@example.org"
	if err := e.svc.LLDAP.UpdateUser(ctx, "alice", &other, nil); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedEmails(t, e)["alice"]; ok {
		t.Errorf("VerifiedEmails[alice] = %q after an LLDAP edit", v)
	}
	if overviewVerified(t, e, "alice") {
		t.Error("the person view says verified")
	}
}

// TestInviteEmailVerified (ruling C8): an invite by an admin, or by a
// delegate holding edit_details, stores the email verified; an inviter
// without edit_details doesn't.
func TestInviteEmailVerified(t *testing.T) {
	e := delegateEnv(t)
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "dave", Email: "dave@example.org"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "dave"); !ok || v.Email != "dave@example.org" || v.By != "admin:root" {
		t.Errorf("admin invite: %+v %v", v, ok)
	}
	if _, err := e.svc.CreateUser(ctx, callerFor(t, e, "hera"), directory.CreateRequest{Username: "hank", Email: "hank@example.org"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "hank"); !ok || v.By != "admin:hera" {
		t.Errorf("edit_details delegate invite: %+v %v", v, ok)
	}
	if _, err := e.svc.CreateUser(ctx, callerFor(t, e, "ivy"), directory.CreateRequest{Username: "ian", Email: "ian@example.org"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "ian"); ok {
		t.Errorf("an inviter without edit_details verified: %+v", v)
	}
	// A re-created name starts unverified (the record is the old uuid's).
	if _, err := e.svc.DeleteUser(ctx, asRoot, "dave", "dave"); err != nil {
		t.Fatal(err)
	}
	e.ll.AddUser("dave", "dave@example.org", "Dave", "")
	if _, ok := verifiedEmails(t, e)["dave"]; ok {
		t.Error("a re-created dave is verified")
	}
}

// TestCSVImportEmailVerified (ruling C8): an import's creates and email
// changes are admin-set; an unchanged email in an update row isn't.
func TestCSVImportEmailVerified(t *testing.T) {
	e := storeEnv(t)
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	res, err := e.svc.ImportApply(ctx, asRoot, directory.ApplyRequest{Rows: []directory.ApplyRow{
		{User: "nora", Create: true, Email: "nora@example.org", DisplayName: "Nora"},
		{User: "alice", Email: "alice.csv@example.org"},
		{User: "bob", Email: "bob@example.org", DisplayName: "Bobby"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Rows {
		if !r.OK {
			t.Fatalf("row %+v", r)
		}
	}
	got := verifiedEmails(t, e)
	if got["nora"] != "nora@example.org" || got["alice"] != "alice.csv@example.org" {
		t.Errorf("VerifiedEmails = %v", got)
	}
	if _, ok := got["bob"]; ok {
		t.Error("an unchanged email in an import row was verified")
	}
	if v, _ := verifiedRecord(t, e, "nora"); v.By != "admin:root" {
		t.Errorf("nora by %q", v.By)
	}
}

func TestMarkEmailVerified(t *testing.T) {
	e := delegateEnv(t)
	if err := e.svc.MarkEmailVerified(ctx, callerFor(t, e, "eddie"), "bob"); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "bob"); !ok || v.Email != "bob@example.org" || v.By != "admin:eddie" {
		t.Errorf("record = %+v %v", v, ok)
	}
	if l := lastAuditLine(t, e); !strings.Contains(l, `"action":"user.email_verified"`) || !strings.Contains(l, `"target":"bob"`) || !strings.Contains(l, `"result":"ok"`) {
		t.Errorf("audit = %s", l)
	}
	// Without edit_details: refused.
	if err := e.svc.MarkEmailVerified(ctx, callerFor(t, e, "ivy"), "bob"); status(err) != 403 {
		t.Errorf("inviter = %v", err)
	}
	// Your own email: only by code.
	if err := e.svc.MarkEmailVerified(ctx, asRoot, "root"); status(err) != 403 {
		t.Errorf("own = %v", err)
	}
	// No email: 400 with the contract's text.
	e.ll.AddUser("noemail", "", "No Email", "")
	err := e.svc.MarkEmailVerified(ctx, asRoot, "noemail")
	if status(err) != 400 || err.Error() != "this person has no email" {
		t.Errorf("no email = %v", err)
	}
	if err := e.svc.MarkEmailVerified(ctx, asRoot, "nobody"); status(err) != 404 {
		t.Errorf("unknown = %v", err)
	}
}

// TestVerifyOwnEmail: the code path's record (by "code"), audited
// email.verified; refused (410) when the email or the account changed
// since the code was sent.
func TestVerifyOwnEmail(t *testing.T) {
	e := storeEnv(t)
	uuid, email, err := e.svc.OwnEmail(ctx, "Alice")
	if err != nil || uuid != e.ll.UUIDOf("alice") || email != "alice@example.org" {
		t.Fatalf("OwnEmail = %q %q %v", uuid, email, err)
	}
	if err := e.svc.VerifyOwnEmail(ctx, directory.Human("alice"), uuid, "old@example.org"); status(err) != 410 {
		t.Errorf("changed email = %v", err)
	}
	if err := e.svc.VerifyOwnEmail(ctx, directory.Human("alice"), "other-uuid", email); status(err) != 410 {
		t.Errorf("other account = %v", err)
	}
	if err := e.svc.VerifyOwnEmail(ctx, directory.Human("alice"), uuid, email); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "alice"); !ok || v.By != "code" || v.Email != email {
		t.Errorf("record = %+v %v", v, ok)
	}
	if l := lastAuditLine(t, e); !strings.Contains(l, `"action":"email.verified"`) || !strings.Contains(l, `"actor":"alice"`) {
		t.Errorf("audit = %s", l)
	}
	// The protected accounts: refused.
	for _, p := range []string{directory.CoreAdmin, "portcullis-hub"} {
		if _, _, err := e.svc.OwnEmail(ctx, p); status(err) != 409 {
			t.Errorf("OwnEmail(%s) = %v", p, err)
		}
		if err := e.svc.VerifyOwnEmail(ctx, directory.Human(p), "u", "x@example.org"); status(err) != 409 {
			t.Errorf("VerifyOwnEmail(%s) = %v", p, err)
		}
	}
}

// TestAIEmailNotVerified (security review): a change through the AI —
// create, invite, update, an admin's included — stores the email
// unverified and clears an earlier verification; the AI can't mark one.
func TestAIEmailNotVerified(t *testing.T) {
	e := storeEnv(t)
	ai := &directory.Caller{User: "root", Admin: true, Via: directory.ViaAI, Client: "portcullis-ai-claude"}
	if err := e.svc.MarkEmailVerified(ctx, asRoot, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpdateUser(ctx, ai, "alice", strptr("alice.ai@example.org"), nil); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "alice"); ok {
		t.Errorf("an AI change left a record: %+v", v)
	}
	if _, err := e.svc.CreateUser(ctx, ai, directory.CreateRequest{Username: "zoe", Email: "zoe@example.org"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "zoe"); ok {
		t.Errorf("an AI create verified: %+v", v)
	}
	if err := e.svc.MarkEmailVerified(ctx, ai, "zoe"); status(err) != 403 {
		t.Errorf("AI mark = %v", err)
	}
	if _, ok := verifiedRecord(t, e, "zoe"); ok {
		t.Error("the AI marked an email verified")
	}
}

// TestStalePermissionNotVerified (security review): edit_details is
// re-checked when the verification is recorded, never taken from a
// Caller resolved earlier.
func TestStalePermissionNotVerified(t *testing.T) {
	e := delegateEnv(t)
	// ivy invites; her Caller claims edit_details she doesn't hold (as a
	// Caller resolved before her removal from hr_editors would).
	stale := &directory.Caller{User: "ivy", Perms: map[string]bool{directory.PermInvite: true, directory.PermEditDetails: true}}
	if _, err := e.svc.CreateUser(ctx, stale, directory.CreateRequest{Username: "sam", Email: "sam@example.org"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "sam"); ok {
		t.Errorf("a stale edit_details verified: %+v", v)
	}
	// eddie resolved as an editor, then removed from hr_editors: his
	// update is refused (the gate) and nothing is recorded.
	eddie := callerFor(t, e, "eddie")
	e.ll.RemoveMember("hr_editors", "eddie")
	if err := e.svc.UpdateUser(ctx, eddie, "bob", strptr("bob2@example.org"), nil); status(err) != 403 {
		t.Errorf("stale eddie = %v", err)
	}
	if _, ok := verifiedRecord(t, e, "bob"); ok {
		t.Error("a stale editor verified")
	}
	// hera still holds it: verified.
	if _, err := e.svc.CreateUser(ctx, callerFor(t, e, "hera"), directory.CreateRequest{Username: "tom", Email: "tom@example.org"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "tom"); !ok || v.By != "admin:hera" {
		t.Errorf("hera: %+v %v", v, ok)
	}
}

// TestVerificationPrunedBySync (fix round 1): the evaluator's run drops a
// record LLDAP no longer holds — an email changed in LLDAP's own UI, an
// account deleted outside the Hub — so changing the email back later
// (A→B→A) doesn't make it verified again.
func TestVerificationPrunedBySync(t *testing.T) {
	e := storeEnv(t)
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	for _, u := range []string{"alice", "bob"} {
		if err := e.svc.MarkEmailVerified(ctx, asRoot, u); err != nil {
			t.Fatal(err)
		}
	}
	b := "alice.b@example.org"
	if err := e.svc.LLDAP.UpdateUser(ctx, "alice", &b, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.DeleteUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Evaluate(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if v, ok := verifiedRecord(t, e, "alice"); ok {
		t.Errorf("alice's record survived the LLDAP change: %+v", v)
	}
	cfg, _ := e.svc.Store.Load()
	if len(cfg.EmailVerified) != 0 {
		t.Errorf("records left: %+v", cfg.EmailVerified)
	}
	// A→B→A: back to the address that was verified.
	a := "alice@example.org"
	if err := e.svc.LLDAP.UpdateUser(ctx, "alice", &a, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := verifiedEmails(t, e)["alice"]; ok {
		t.Error("A→B→A: alice's old address counts as verified again")
	}
	// A record that still holds is kept.
	if err := e.svc.MarkEmailVerified(ctx, asRoot, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Evaluate(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, ok := verifiedRecord(t, e, "alice"); !ok {
		t.Error("a current record was pruned")
	}
}

func TestDeleteUserDropsVerification(t *testing.T) {
	e := storeEnv(t)
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	if err := e.svc.MarkEmailVerified(ctx, asRoot, "bob"); err != nil {
		t.Fatal(err)
	}
	uuid := e.ll.UUIDOf("bob")
	if _, err := e.svc.DeleteUser(ctx, asRoot, "bob", "bob"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.svc.Store.Load()
	if _, ok := cfg.EmailVerified[uuid]; ok {
		t.Error("the deleted account's record is kept")
	}
}

// TestFailedVerificationClearFails (fix round 1): your own email change
// whose clearing can't be written fails the operation (never only logged).
func TestFailedVerificationClearFails(t *testing.T) {
	e := storeEnv(t)
	e.ll.AddUser("rita", "rita@example.org", "Rita", "", "lldap_admin")
	if err := e.svc.MarkEmailVerified(ctx, &directory.Caller{User: "rita", Admin: true}, "root"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(e.svc.Store.Path)
	os.Chmod(e.svc.Store.Path, 0o400)
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700); os.Chmod(e.svc.Store.Path, 0o600) })
	err := e.svc.UpdateUser(ctx, asRoot, "root", strptr("root.new@example.org"), nil)
	if status(err) != 503 || !strings.Contains(err.Error(), "clearing its verification failed") {
		t.Errorf("failed clear = %v", err)
	}
}
