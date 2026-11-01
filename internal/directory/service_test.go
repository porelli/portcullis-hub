package directory_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
)

const svcPass = "service-password-0123456789"
const inviteSecret = "invite-shared-secret-0123456789abcdef"

type env struct {
	secretFile string
	svc        *directory.Service
	ll         *lldaptest.Server
	kc         *kctest.Server
	audit      string
	invites    *fakeInvites
}

// fakeInvites is core's invite API (contract §9.4).
type fakeInvites struct {
	mu     sync.Mutex
	srv    *httptest.Server
	users  []string
	fail   bool
	refuse map[string]bool // core answers 409 for these
}

func newInvites(t *testing.T) *fakeInvites {
	f := &fakeInvites{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+inviteSecret || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(401)
			return
		}
		if f.fail {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": "boom"})
			return
		}
		var req struct{ Username string }
		json.NewDecoder(r.Body).Decode(&req)
		if f.refuse[req.Username] {
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(map[string]string{"error": "user is an administrator"})
			return
		}
		f.users = append(f.users, req.Username)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{"url": "https://enroll.example.org/invite/tok-" + req.Username, "expires_at": time.Now().Add(72 * time.Hour).UTC()})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ll := lldaptest.New(t, "portcullis-hub", svcPass)
	ll.AddUser("root", "root@example.org", "Root", "rootpass-123456", "lldap_admin")
	ll.AddUser("alice", "alice@example.org", "Alice", "alicepass-12345")
	credDir := t.TempDir()
	os.WriteFile(filepath.Join(credDir, "username"), []byte("portcullis-hub\n"), 0600)
	os.WriteFile(filepath.Join(credDir, "password"), []byte(svcPass+"\n"), 0600)
	kc := kctest.New(t)
	kc.Importable = ll.HasUser
	inv := newInvites(t)
	secretFile := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secretFile, []byte(inviteSecret+"\n"), 0600)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	gateMap := filepath.Join(t.TempDir(), "group-gate-map.conf")
	os.WriteFile(gateMap, []byte("# core\nauth=lldap_admin\nmetrics = ops_admins\ngrafana=users_grafana\n"), 0644)
	svc := &directory.Service{
		LLDAP:       lldap.New(ll.HTTP.URL, ll.LDAPURL(), ll.BaseDN, credDir),
		KC:          keycloak.New(kc.HTTP.URL, "admin", "admin"),
		Invites:     invite.New(inv.srv.URL, secretFile),
		Audit:       &directory.AuditLog{Path: audit},
		AdminGroups: func() map[string]bool { return directory.ProtectedGroups("extra_admins", gateMap) },
		Apps: func() []directory.App {
			return []directory.App{{ID: "app", Name: "App", Enabled: true, AccessGroup: "users_app", AdminGroup: "admin_app"}, {ID: "other", Name: "Other", AccessGroup: "users_other"}}
		},
	}
	return &env{svc: svc, ll: ll, kc: kc, audit: audit, invites: inv, secretFile: secretFile}
}

func status(err error) int {
	var de *directory.Error
	if errors.As(err, &de) {
		return de.Status
	}
	if err != nil {
		return 500
	}
	return 0
}

var ctx = context.Background()

func TestOverview(t *testing.T) {
	e := newEnv(t)
	e.kc.Import("alice", kctest.Credential{ID: "w", Type: "webauthn-passwordless"})
	e.ll.AddGroup("users_app", "alice")
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !ov.Available || ov.ServiceUser != "portcullis-hub" || ov.KeycloakError != "" || ov.InvitesError != "" {
		t.Fatalf("ov = %+v", ov)
	}
	byName := map[string]directory.UserView{}
	for _, u := range ov.Users {
		byName[u.Username] = u
	}
	if a := byName["alice"]; a.Keycloak == nil || !a.Keycloak.Imported || a.Keycloak.Passkeys != 1 || len(a.Groups) != 1 {
		t.Errorf("alice = %+v %+v", a, a.Keycloak)
	}
	if r := byName["root"]; !r.Self || r.Keycloak.Imported {
		t.Errorf("root = %+v", r)
	}
	if byName["portcullis-hub"].Protected != "service" || byName["admin"].Protected != "core-admin" {
		t.Error("protection flags")
	}
	// users_app exists; only admin_app is suggested: "other" isn't enabled,
	// so its group users_other must not be.
	if len(ov.Suggestions) != 1 || ov.Suggestions[0].Group != "admin_app" {
		t.Errorf("suggestions = %+v", ov.Suggestions)
	}
	for _, g := range ov.Groups {
		if g.Name == "users_app" && (len(g.UsedBy) != 1 || g.UsedBy[0] != "app") {
			t.Errorf("used_by = %v", g.UsedBy)
		}
		if g.Name == "lldap_admin" && !g.Builtin {
			t.Error("lldap_admin not builtin")
		}
	}

	// Unconfigured: not an error, the page says why.
	e.svc.LLDAP = lldap.New("", "", "", filepath.Join(t.TempDir(), "none"))
	ov, err = e.svc.Overview(ctx, "root")
	if err != nil || ov.Available || !strings.Contains(ov.Reason, "not configured") {
		t.Errorf("unconfigured = %+v, %v", ov, err)
	}
	if err := e.svc.CreateGroup(ctx, asRoot, "x"); status(err) != 503 {
		t.Errorf("mutation while unconfigured = %v", err)
	}
}

func TestCreateUserInvite(t *testing.T) {
	e := newEnv(t)
	e.ll.AddGroup("users_app")
	res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "dave", Email: "dave@example.org", DisplayName: "Dave", Groups: []string{"users_app"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Invite == nil || !strings.HasPrefix(res.Invite.URL, "https://enroll.example.org/invite/") || res.Password != "" || len(res.Warnings) != 0 {
		t.Fatalf("res = %+v", res)
	}
	if !e.ll.HasUser("dave") || e.ll.Password("dave") != "" {
		t.Error("invite user must exist without a password")
	}
	if m := e.ll.GroupMembers("users_app"); len(m) != 1 || m[0] != "dave" {
		t.Errorf("members = %v", m)
	}
	// Pre-imported into Keycloak, no required action (the invite registers the key).
	if u := e.kc.Get("dave"); u == nil || len(u.RequiredActions) != 0 {
		t.Errorf("kc dave = %+v", u)
	}
	// Invites unavailable: refuse before creating anything.
	e.svc.Invites = invite.New(e.invites.srv.URL, filepath.Join(t.TempDir(), "missing"))
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "erin", Email: "erin@example.org"}); status(err) != 503 || e.ll.HasUser("erin") {
		t.Errorf("no invites = %v", err)
	}
}

func TestCreateUserPassword(t *testing.T) {
	e := newEnv(t)
	res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "frank", Email: "frank@example.org", Onboarding: "password", Generate: true, RequirePasskey: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Password) < 20 || e.ll.Password("frank") != res.Password || res.Invite != nil {
		t.Errorf("generated password not set: %+v", res)
	}
	if u := e.kc.Get("frank"); u == nil || len(u.RequiredActions) != 1 || u.RequiredActions[0] != keycloak.PasskeyAction {
		t.Errorf("kc frank = %+v", u)
	}
	res, err = e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "gina", Email: "gina@example.org", Onboarding: "password", Password: "admin-chosen-pw"})
	if err != nil || res.Password != "" || e.ll.Password("gina") != "admin-chosen-pw" {
		t.Errorf("provided password: %+v %v", res, err)
	}
	// LDAP failure rolls the user back.
	e.ll.FailPassword = 53
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "hank", Email: "hank@example.org", Onboarding: "password", Generate: true}); err == nil || e.ll.HasUser("hank") {
		t.Errorf("rollback: %v, exists=%v", err, e.ll.HasUser("hank"))
	}
}

func TestCreateUserValidation(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		req  directory.CreateRequest
		want int
	}{
		{directory.CreateRequest{Username: "Bad Name", Email: "x@example.org"}, 400},
		{directory.CreateRequest{Username: "portcullis-hub", Email: "x@example.org"}, 400},
		{directory.CreateRequest{Username: "admin", Email: "x@example.org"}, 400},
		{directory.CreateRequest{Username: "ok", Email: "not-an-email"}, 400},
		{directory.CreateRequest{Username: "ok", Email: "x@example.org", DisplayName: "a\nb"}, 400},
		{directory.CreateRequest{Username: "ok", Email: "x@example.org", Onboarding: "password", Password: "short"}, 400},
		{directory.CreateRequest{Username: "ok", Email: "x@example.org", Onboarding: "magic"}, 400},
		{directory.CreateRequest{Username: "ok", Email: "x@example.org", Groups: []string{"nope"}}, 400},
		{directory.CreateRequest{Username: "alice", Email: "x@example.org"}, 409},
	}
	for _, c := range cases {
		if _, err := e.svc.CreateUser(ctx, asRoot, c.req); status(err) != c.want {
			t.Errorf("%+v: %v, want %d", c.req, err, c.want)
		}
	}
	if e.ll.HasUser("ok") {
		t.Error("invalid request created a user")
	}
	if _, err := e.svc.CreateUser(ctx, &directory.Caller{}, directory.CreateRequest{Username: "ok", Email: "x@example.org"}); status(err) != 403 {
		t.Errorf("no actor = %v", err)
	}
}

func TestGuardrails(t *testing.T) {
	e := newEnv(t)
	// root is the only human lldap_admin member besides core's admin.
	e.ll.AddUser("solo", "solo@example.org", "", "solopass-123456")

	check := func(name string, err error, want int) {
		t.Helper()
		if status(err) != want {
			t.Errorf("%s: %v (status %d), want %d", name, err, status(err), want)
		}
	}
	_, err := e.svc.DeleteUser(ctx, asRoot, "portcullis-hub", "portcullis-hub")
	check("delete service", err, 409)
	_, err = e.svc.DeleteUser(ctx, asRoot, "admin", "admin")
	check("delete core admin", err, 409)
	_, err = e.svc.DeleteUser(ctx, asRoot, "root", "root")
	check("delete self", err, 409)
	_, err = e.svc.DeleteUser(ctx, asRoot, "alice", "alic")
	check("bad confirm", err, 400)
	_, err = e.svc.SetPassword(ctx, asRoot, "portcullis-hub", "", true, "")
	check("password service", err, 409)
	_, err = e.svc.SetPassword(ctx, asRoot, "admin", "", true, "")
	check("password core admin", err, 409)
	check("update service", e.svc.UpdateUser(ctx, asRoot, "portcullis-hub", nil, strptr("x")), 409)
	check("remove service from admin", e.svc.RemoveMember(ctx, asRoot, "lldap_admin", "portcullis-hub"), 409)
	check("add service to group", e.svc.AddMember(ctx, asRoot, "lldap_password_manager", "portcullis-hub"), 409)
	check("remove core admin", e.svc.RemoveMember(ctx, asRoot, "lldap_admin", "admin"), 409)
	check("remove self", e.svc.RemoveMember(ctx, asRoot, "lldap_admin", "root"), 409)
	check("delete builtin group", e.svc.DeleteGroup(ctx, asRoot, "lldap_admin", "lldap_admin"), 409)
	check("create lldap_ group", e.svc.CreateGroup(ctx, asRoot, "lldap_x"), 400)
	check("passkeys service", e.svc.RequirePasskey(ctx, asRoot, "portcullis-hub"), 409)
	_, err = e.svc.SendInvite(ctx, asRoot, "portcullis-hub")
	check("invite service", err, 409)

	// Last human admin: admin + root are humans; another admin (solo)
	// removing root works only while admin is still a member. The service
	// account (an lldap_admin member, not human) then tries to remove solo.
	check("add solo", e.svc.AddMember(ctx, asRoot, "lldap_admin", "solo"), 0)
	check("remove root by solo", e.svc.RemoveMember(ctx, asAdmin("solo"), "lldap_admin", "root"), 0)
	// Simulate admin having been dropped from lldap_admin elsewhere (LLDAP UI).
	e.ll.RemoveMember("lldap_admin", "admin")
	check("last human by delete", deleteErr(e.svc.DeleteUser(ctx, asAdmin("portcullis-hub"), "solo", "solo")), 409)
	check("last human by removal", e.svc.RemoveMember(ctx, asAdmin("portcullis-hub"), "lldap_admin", "solo"), 409)
	if m := e.ll.GroupMembers("lldap_admin"); len(m) != 2 {
		t.Errorf("lldap_admin = %v", m)
	}
	check("missing user", e.svc.AddMember(ctx, asAdmin("solo"), "lldap_admin", "ghost"), 404)
	check("missing group", e.svc.AddMember(ctx, asAdmin("solo"), "ghosts", "alice"), 404)
}

func deleteErr(_ *directory.Result, err error) error { return err }

func strptr(s string) *string { return &s }

func TestUserLifecycle(t *testing.T) {
	e := newEnv(t)
	e.kc.Import("alice", kctest.Credential{ID: "w", Type: "webauthn"})

	if err := e.svc.UpdateUser(ctx, asRoot, "alice", strptr("new@example.org"), strptr("Alice N")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpdateUser(ctx, asRoot, "alice", strptr("bad"), nil); status(err) != 400 {
		t.Errorf("bad email = %v", err)
	}
	res, err := e.svc.SetPassword(ctx, asRoot, "alice", "", true, "")
	if err != nil || len(res.Password) < 20 || e.ll.Password("alice") != res.Password {
		t.Fatalf("reset: %+v %v", res, err)
	}
	if e.kc.Get("alice").Sessions != 0 {
		t.Error("password reset should sign the user out")
	}
	if _, err := e.svc.SetPassword(ctx, asRoot, "alice", "tiny", false, ""); status(err) != 400 {
		t.Errorf("short password = %v", err)
	}
	if res, err := e.svc.SetPassword(ctx, asRoot, "alice", "an-admin-chosen-one", false, ""); err != nil || res.Password != "" || e.ll.Password("alice") != "an-admin-chosen-one" {
		t.Errorf("set: %+v %v", res, err)
	}

	res, err = e.svc.RemovePasskeys(ctx, asRoot, "alice", "alice", true)
	if err != nil || res.Count != 1 || res.Invite == nil {
		t.Fatalf("reset passkeys: %+v %v", res, err)
	}
	if u := e.kc.Get("alice"); len(u.Credentials) != 0 || len(u.RequiredActions) != 0 {
		t.Errorf("after reset+invite: %+v", u)
	}
	if _, err := e.svc.RemovePasskeys(ctx, asRoot, "alice", "nope", false); status(err) != 400 {
		t.Errorf("bad confirm = %v", err)
	}
	if res, err := e.svc.RemovePasskeys(ctx, asRoot, "alice", "alice", false); err != nil || len(e.kc.Get("alice").RequiredActions) != 1 || res.Invite != nil {
		t.Errorf("remove w/o invite: %+v %v", res, err)
	}
	if err := e.svc.ClearActions(ctx, asRoot, "alice"); err != nil || len(e.kc.Get("alice").RequiredActions) != 0 {
		t.Errorf("clear: %v", err)
	}
	// RequirePasskey on a user Keycloak hasn't imported yet imports them.
	e.ll.AddUser("ivy", "ivy@example.org", "", "")
	if err := e.svc.RequirePasskey(ctx, asRoot, "ivy"); err != nil || e.kc.Get("ivy") == nil {
		t.Errorf("require on unimported: %v", err)
	}
	inv, err := e.svc.SendInvite(ctx, asRoot, "ivy")
	if err != nil || inv.Invite == nil {
		t.Errorf("invite: %+v %v", inv, err)
	}
	e.invites.fail = true
	if _, err := e.svc.SendInvite(ctx, asRoot, "ivy"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("invite failure = %v", err)
	}

	dres, err := e.svc.DeleteUser(ctx, asRoot, "alice", "alice")
	if err != nil || len(dres.Warnings) != 0 {
		t.Fatalf("delete: %+v %v", dres, err)
	}
	if e.ll.HasUser("alice") || e.kc.Get("alice") != nil {
		t.Error("alice should be gone from LLDAP and Keycloak")
	}
}

func TestGroups(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.CreateGroup(ctx, asRoot, "users_app"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CreateGroup(ctx, asRoot, "USERS_APP"); status(err) != 409 {
		t.Errorf("case-duplicate = %v", err)
	}
	if err := e.svc.CreateGroup(ctx, asRoot, "bad name"); status(err) != 400 {
		t.Errorf("bad name = %v", err)
	}
	if err := e.svc.AddMember(ctx, asRoot, "users_app", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.AddMember(ctx, asRoot, "users_app", "alice"); status(err) != 409 {
		t.Errorf("duplicate member = %v", err)
	}
	if err := e.svc.RemoveMember(ctx, asRoot, "users_app", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveMember(ctx, asRoot, "users_app", "alice"); status(err) != 404 {
		t.Errorf("not a member = %v", err)
	}
	if err := e.svc.DeleteGroup(ctx, asRoot, "users_app", "users"); status(err) != 400 {
		t.Errorf("bad confirm = %v", err)
	}
	if err := e.svc.DeleteGroup(ctx, asRoot, "users_app", "users_app"); err != nil || e.ll.HasGroup("users_app") {
		t.Errorf("delete: %v", err)
	}
}

func TestAudit(t *testing.T) {
	e := newEnv(t)
	res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "jack", Email: "jack@example.org", Onboarding: "password", Generate: true})
	if err != nil {
		t.Fatal(err)
	}
	pw2, err := e.svc.SetPassword(ctx, asRoot, "jack", "", true, "")
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetPassword(ctx, asRoot, "jack", "admin-provided-secret", false, "")
	e.svc.DeleteUser(ctx, asRoot, "root", "root") // refused
	inv, _ := e.svc.SendInvite(ctx, asRoot, "jack")

	raw, _ := os.ReadFile(e.audit)
	for _, secret := range []string{res.Password, pw2.Password, "admin-provided-secret", svcPass, inviteSecret, inv.Invite.URL} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("audit log contains a secret: %q", secret)
		}
	}
	if st, _ := os.Stat(e.audit); st.Mode().Perm() != 0600 {
		t.Errorf("audit mode = %v", st.Mode())
	}
	entries, err := e.svc.Recent(100)
	if err != nil || len(entries) != 5 {
		t.Fatalf("entries = %d, %v", len(entries), err)
	}
	if entries[0].Action != "user.invite" || entries[1].Result != "refused" || entries[1].Actor != "root" || entries[4].Action != "user.create" || entries[4].Target != "jack" {
		t.Errorf("entries = %+v", entries)
	}
	for i := 0; i < 150; i++ {
		e.svc.Audit.Append(directory.AuditEntry{Actor: "x", Action: "test", Target: "t", Result: "ok"})
	}
	if entries, _ := e.svc.Recent(100); len(entries) != 100 {
		t.Errorf("recent = %d", len(entries))
	}
}

// userOps is every Service method that changes a user, called on target.
// asRoot is the test administrator (root is an lldap_admin member).
var asRoot = &directory.Caller{User: "root", Admin: true}

func asAdmin(user string) *directory.Caller { return &directory.Caller{User: user, Admin: true} }

// TestProtectedAccountsParity fails when a new mutating method appears
// that isn't listed here (or in nonUserOps), so no operation can skip
// checkTarget or the delegate checks.
func userOps(s *directory.Service, c *directory.Caller, target string) map[string]func() error {
	r := func(_ *directory.Result, err error) error { return err }
	return map[string]func() error{
		"CreateUser": func() error {
			return r(s.CreateUser(ctx, c, directory.CreateRequest{Username: target, Email: "x@example.org"}))
		},
		"UpdateUser":              func() error { return s.UpdateUser(ctx, c, target, strptr("x@example.org"), nil) },
		"DeleteUser":              func() error { return r(s.DeleteUser(ctx, c, target, target)) },
		"SetPassword":             func() error { return r(s.SetPassword(ctx, c, target, "", true, target)) },
		"SendInvite":              func() error { return r(s.SendInvite(ctx, c, target)) },
		"RequirePasskey":          func() error { return s.RequirePasskey(ctx, c, target) },
		"ClearActions":            func() error { return s.ClearActions(ctx, c, target) },
		"RemovePasskeys":          func() error { return r(s.RemovePasskeys(ctx, c, target, target, true)) },
		"AddMember":               func() error { return s.AddMember(ctx, c, "users_app", target) },
		"RemoveMember":            func() error { return s.RemoveMember(ctx, c, "lldap_admin", target) },
		"RemoveStaleKeycloakUser": func() error { return s.RemoveStaleKeycloakUser(ctx, c, target, target) },
		"AddException": func() error {
			return s.AddException(ctx, c, "users_app", directory.Exception{User: target, Reason: "x", Include: true})
		},
		"RemoveException": func() error { return s.RemoveException(ctx, c, "users_app", target) },
		"SetMemberExpiry": func() error {
			until := time.Now().Add(time.Hour)
			return s.SetMemberExpiry(ctx, c, "users_app", target, &until)
		},
		"SetDetails": func() error { return s.SetDetails(ctx, c, target, map[string][]string{}) },
	}
}

// nonUserOps are the exported methods that don't change a user. The
// evaluator (Evaluate, RunEvaluator) targets nobody: it leaves protected
// accounts alone, see TestProtectedAccountsNeverRuleMembers. The group
// and field operations are admin-only (TestDelegateCannotEscalate).
var nonUserOps = map[string]bool{"Overview": true, "OverviewFor": true, "Recent": true, "CallerFor": true, "CreateGroup": true, "DeleteGroup": true, "CreateField": true, "UpdateField": true, "PatchField": true, "PeopleOverview": true, "DeleteField": true, "Evaluate": true, "RunEvaluator": true, "Desired": true, "DesiredFromLLDAP": true, "Pending": true,
	// Group config: admin-only; ConvertApply's keep list can only name
	// non-protected members (TestConvertKeepsAsExceptions), PreviewRule
	// changes nothing and never lists protected accounts.
	"SetGroupRule": true, "ConvertPreview": true, "ConvertApply": true, "ConvertApplyReviewed": true, "SetPermission": true, "PreviewRule": true,
	// CSV import: ImportReview is read-only; ImportApply operates on multiple rows and reuses CreateUser/DeleteUser/SetDetails which each check targets.
	"ImportReview": true, "ImportApply": true,
	// Read-only views for the Hub's publishing (policy expiring, user attributes).
	"Publish": true, "SharedFields": true}

func TestProtectedAccountsParity(t *testing.T) {
	e := newEnv(t)
	e.ll.AddGroup("users_app", "admin", "portcullis-hub")
	// Set up Store early so SetDetails can work
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	cfg, _ := e.svc.Store.Load()
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	ops := userOps(e.svc, asRoot, "x")
	typ := reflect.TypeOf(e.svc)
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if _, ok := ops[name]; !ok && !nonUserOps[name] {
			t.Errorf("Service.%s is not covered by the protected-account parity test: add it to userOps or nonUserOps", name)
		}
	}
	before := len(e.ll.Mutations)
	for _, target := range []string{directory.CoreAdmin, "portcullis-hub"} {
		for name, op := range userOps(e.svc, asRoot, target) {
			err := op()
			if st := status(err); st != 409 && !(name == "CreateUser" && st == 400) {
				t.Errorf("%s(%s) = %v (status %d), want refusal", name, target, err, st)
			}
			if target == directory.CoreAdmin && name != "CreateUser" && !strings.Contains(err.Error(), "./portcullis invite admin") {
				t.Errorf("%s(admin) message = %q", name, err)
			}
		}
	}

	if got := e.ll.Mutations[before:]; len(got) != 0 {
		t.Errorf("protected accounts were changed by an admin: %v", got)
	}

	// A delegate holding every permission: every user-targeting operation
	// refuses (403) the protected accounts, administrators, members of
	// permission groups and the delegate themselves.
	cfg, _ = e.svc.Store.Load()
	cfg.Permissions = map[string]string{directory.PermEditDetails: "hr_edit", directory.PermInvite: "hr_invite", directory.PermRemove: "hr_remove"}
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("hr_edit")
	e.ll.AddGroup("hr_invite")
	e.ll.AddGroup("hr_remove")
	e.ll.AddGroup("ops_admins")
	e.ll.AddGroup("lldap_password_manager")
	e.ll.AddUser("hera", "hera@example.org", "", "", "hr_edit", "hr_invite", "hr_remove")
	e.ll.AddUser("inv", "inv@example.org", "", "", "hr_invite")
	e.ll.AddUser("otto", "otto@example.org", "", "", "ops_admins")
	e.ll.AddUser("pm", "pm@example.org", "", "", "lldap_password_manager")
	e.kc.Import("root")
	e.kc.Import("inv")
	hera, err := e.svc.CallerFor(ctx, "hera")
	if err != nil || hera.Admin || len(hera.Perms) != 3 {
		t.Fatalf("hera = %+v %v", hera, err)
	}
	before = len(e.ll.Mutations)
	for _, target := range []string{directory.CoreAdmin, "portcullis-hub", "root", "otto", "pm", "inv", "hera", "HERA"} {
		for name, op := range userOps(e.svc, hera, target) {
			if err := op(); status(err) != 403 {
				t.Errorf("delegate %s(%s) = %v (status %d), want 403", name, target, err, status(err))
			}
		}
	}
	if got := e.ll.Mutations[before:]; len(got) != 0 {
		t.Errorf("protected accounts were changed: %v", got)
	}
	if len(e.invites.users) != 0 || e.kc.Get("admin") != nil || e.kc.Get("portcullis-hub") != nil {
		t.Errorf("invites %v / keycloak touched for protected accounts", e.invites.users)
	}
}

func TestProtectedGroups(t *testing.T) {
	f := filepath.Join(t.TempDir(), "map.conf")
	os.WriteFile(f, []byte("# comment\nhub=lldap_admin\nmetrics=ops\nMETRICS2=x\nwiki=users_wiki\ntraefik=\nenroll = enrollers\npeople=*\n"), 0644)
	got := directory.ProtectedGroups("a, b c", f)
	for _, g := range []string{"lldap_admin", "lldap_password_manager", "a", "b", "c", "ops", "enrollers"} {
		if !got[g] {
			t.Errorf("missing %s in %v", g, got)
		}
	}
	if got["users_wiki"] || got["x"] || got[""] || got["*"] { // people=*: any signed-in user, no group
		t.Errorf("app groups must not be protected: %v", got)
	}
	if got := directory.ProtectedGroups("", filepath.Join(t.TempDir(), "none")); len(got) != 2 {
		t.Errorf("no map file = %v", got)
	}
}

func TestAdministrators(t *testing.T) {
	e := newEnv(t)
	e.ll.AddUser("bea", "bea@example.org", "", "bea-password-123", "lldap_admin")
	e.ll.AddGroup("ops_admins")
	e.ll.AddGroup("extra_admins")
	e.ll.AddUser("otto", "otto@example.org", "", "", "ops_admins")
	e.ll.AddUser("xena", "xena@example.org", "", "", "extra_admins")
	e.kc.Import("bea", kctest.Credential{ID: "w", Type: "webauthn"})

	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range ov.Users {
		wantAdmin := map[string]bool{"admin": true, "bea": true, "otto": true, "xena": true, "root": true, "portcullis-hub": true}[u.Username]
		if u.Admin != wantAdmin {
			t.Errorf("%s admin = %v", u.Username, u.Admin)
		}
		if u.Username == "bea" && u.ServerInvite != "./portcullis invite bea" {
			t.Errorf("bea server invite = %q", u.ServerInvite)
		}
		if u.Username == "portcullis-hub" && (u.Keycloak != nil || u.ServerInvite != "") {
			t.Errorf("service account shows keycloak/invite: %+v", u)
		}
	}
	for _, g := range ov.Groups {
		if want := g.Name == "lldap_admin" || g.Name == "lldap_password_manager" || g.Name == "ops_admins" || g.Name == "extra_admins"; g.Admin != want {
			t.Errorf("group %s admin = %v", g.Name, g.Admin)
		}
	}

	// No invites for administrators, yourself included; core isn't asked.
	for _, who := range []string{"bea", "otto", "xena", "root"} {
		_, err := e.svc.SendInvite(ctx, asRoot, who)
		if status(err) != 409 || !strings.Contains(err.Error(), "administrators are recovered from the server: ./portcullis invite "+who) {
			t.Errorf("invite %s = %v", who, err)
		}
	}
	// Reset passkeys → new invite is refused before anything is removed.
	if _, err := e.svc.RemovePasskeys(ctx, asRoot, "bea", "bea", true); status(err) != 409 || len(e.kc.Get("bea").Credentials) != 1 {
		t.Errorf("reset+invite for admin = %v, creds %v", err, e.kc.Get("bea").Credentials)
	}
	if len(e.invites.users) != 0 {
		t.Fatalf("core was asked for admin invites: %v", e.invites.users)
	}
	// Password and passkey reset for another admin: typed confirmation.
	if _, err := e.svc.SetPassword(ctx, asRoot, "bea", "", true, "be"); status(err) != 400 || e.ll.Password("bea") != "bea-password-123" {
		t.Errorf("password for another admin without confirm = %v", err)
	}
	if _, err := e.svc.SetPassword(ctx, asRoot, "otto", "", true, "otto"); err != nil {
		t.Errorf("confirmed password = %v", err)
	}
	if _, err := e.svc.RemovePasskeys(ctx, asRoot, "bea", "bea", false); err != nil || len(e.kc.Get("bea").Credentials) != 0 {
		t.Errorf("confirmed reset = %v", err)
	}
	// Creating an administrator in invite mode: created, no invite, server hint.
	res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "nora", Email: "nora@example.org", Groups: []string{"ops_admins"}})
	if err != nil || res.Invite != nil || res.ServerInvite != "./portcullis invite nora" || !e.ll.HasUser("nora") || len(e.invites.users) != 0 {
		t.Errorf("create admin = %+v %v", res, err)
	}
	// ... even when invites aren't configured at all.
	e.svc.Invites = nil
	if res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "nils", Email: "nils@example.org", Groups: []string{"lldap_admin"}}); err != nil || res.ServerInvite == "" {
		t.Errorf("create admin without invites = %+v %v", res, err)
	}
	e.svc.Invites = invite.New(e.invites.srv.URL, e.secretFile)

	// Core's own 409 (it knows groups the Hub doesn't) is handled the same way.
	e.invites.mu.Lock()
	e.invites.refuse = map[string]bool{"alice": true, "zed": true}
	e.invites.mu.Unlock()
	if _, err := e.svc.SendInvite(ctx, asRoot, "alice"); status(err) != 409 || !strings.Contains(err.Error(), "./portcullis invite alice") || !strings.Contains(err.Error(), "user is an administrator") {
		t.Errorf("core 409 = %v", err)
	}
	res, err = e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org"})
	if err != nil || res.Invite != nil || res.ServerInvite != "./portcullis invite zed" || len(res.Warnings) != 1 {
		t.Errorf("create with core 409 = %+v %v", res, err)
	}

	flagged := 0
	entries, _ := e.svc.Recent(100)
	for _, en := range entries {
		if strings.Contains(en.Detail, "target_is_lldap_admin=true") {
			flagged++
		}
	}
	// Refused password, confirmed password, refused reset+invite, confirmed reset.
	if flagged != 4 {
		t.Errorf("flagged = %d", flagged)
	}
}

func usersByName(ov *directory.Overview) map[string]directory.UserView {
	m := map[string]directory.UserView{}
	for _, u := range ov.Users {
		m[u.Username] = u
	}
	return m
}

// One user's credentials lookup failing (Keycloak answers 500 or 404 for
// a federated user whose LDAP entry is gone) degrades only that row.
func TestOverviewOneBrokenUser(t *testing.T) {
	for _, code := range []int{500, 404} {
		e := newEnv(t)
		e.ll.AddUser("bob", "bob@example.org", "", "")
		e.kc.Import("alice", kctest.Credential{ID: "w", Type: "webauthn"})
		e.kc.Import("bob")
		e.kc.Update("bob", func(u *kctest.User) { u.CredentialsStatus = code })
		ov, err := e.svc.Overview(ctx, "root")
		if err != nil {
			t.Fatal(err)
		}
		if ov.KeycloakError != "" {
			t.Errorf("%d: banner for one broken user: %q", code, ov.KeycloakError)
		}
		u := usersByName(ov)
		if a := u["alice"].Keycloak; a == nil || a.Error != "" || a.Passkeys != 1 {
			t.Errorf("%d: alice = %+v", code, a)
		}
		if b := u["bob"].Keycloak; b == nil || !b.Imported || !strings.Contains(b.Error, fmt.Sprintf("HTTP %d", code)) {
			t.Errorf("%d: bob = %+v", code, b)
		}
		if r := u["root"].Keycloak; r == nil || r.Imported || r.Error != "" {
			t.Errorf("%d: root = %+v", code, r)
		}
		if len(ov.StaleKeycloak) != 0 {
			t.Errorf("%d: bob is in LLDAP, not stale: %+v", code, ov.StaleKeycloak)
		}
	}
}

// A user LLDAP has but Keycloak never imported: "not signed in yet", no
// error anywhere.
func TestOverviewNeverImported(t *testing.T) {
	e := newEnv(t)
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil || ov.KeycloakError != "" {
		t.Fatalf("ov = %+v, %v", ov, err)
	}
	a := usersByName(ov)["alice"].Keycloak
	if a == nil || a.Imported || a.Error != "" || a.RequiredActions == nil {
		t.Errorf("alice = %+v", a)
	}
	if e.kc.Get("alice") != nil {
		t.Error("Overview must not import users")
	}
}

func TestOverviewKeycloakDown(t *testing.T) {
	e := newEnv(t)
	e.kc.Import("alice")
	e.kc.SetDown(true)
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatalf("Keycloak down must not fail the page: %v", err)
	}
	if ov.KeycloakError == "" || len(ov.Users) == 0 {
		t.Errorf("ov = %+v", ov)
	}
	for _, u := range ov.Users {
		if u.Keycloak != nil {
			t.Errorf("%s: per-row status despite the outage: %+v", u.Username, u.Keycloak)
		}
	}
}

// slowKC never answers the credential lookups within the timeout.
type slowKC struct{ directory.Keycloak }

func (slowKC) UserStatuses(ctx context.Context) (map[string]keycloak.UserStatus, error) {
	<-ctx.Done()
	return map[string]keycloak.UserStatus{"alice": {Username: "alice", Error: ctx.Err().Error()}}, nil
}

func TestOverviewKeycloakTimeout(t *testing.T) {
	e := newEnv(t)
	e.svc.KC = slowKC{}
	e.svc.KeycloakTimeout = 50 * time.Millisecond
	start := time.Now()
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil || time.Since(start) > 5*time.Second {
		t.Fatalf("ov = %+v, %v", ov, err)
	}
	if !strings.Contains(ov.KeycloakError, "didn't answer") {
		t.Errorf("banner = %q", ov.KeycloakError)
	}
	if a := usersByName(ov)["alice"].Keycloak; a == nil || a.Error == "" {
		t.Errorf("alice = %+v", a)
	}
}

func TestStaleKeycloakRecords(t *testing.T) {
	e := newEnv(t)
	e.kc.Import("alice")
	e.kc.Import("e2ecert") // LLDAP entry deleted outside the Hub
	e.kc.Update("e2ecert", func(u *kctest.User) { u.CredentialsStatus = 500 })
	e.kc.Import("kclocal") // a Keycloak-local user, not federated
	e.kc.Update("kclocal", func(u *kctest.User) { u.FederationLink = "" })

	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if ov.KeycloakError != "" {
		t.Errorf("banner = %q", ov.KeycloakError)
	}
	if len(ov.StaleKeycloak) != 1 || ov.StaleKeycloak[0].Username != "e2ecert" || !strings.Contains(ov.StaleKeycloak[0].Reason, "HTTP 500") {
		t.Fatalf("stale = %+v", ov.StaleKeycloak)
	}
	if a := usersByName(ov)["alice"].Keycloak; a == nil || a.Error != "" {
		t.Errorf("alice = %+v", a)
	}

	check := func(name string, err error, want int) {
		t.Helper()
		if got := status(err); got != want {
			t.Errorf("%s = %v (status %d), want %d", name, err, got, want)
		}
	}
	check("no confirm", e.svc.RemoveStaleKeycloakUser(ctx, asRoot, "e2ecert", "nope"), 400)
	check("no actor", e.svc.RemoveStaleKeycloakUser(ctx, &directory.Caller{}, "e2ecert", "e2ecert"), 403)
	check("exists in LLDAP", e.svc.RemoveStaleKeycloakUser(ctx, asRoot, "alice", "alice"), 409)
	check("not federated", e.svc.RemoveStaleKeycloakUser(ctx, asRoot, "kclocal", "kclocal"), 409)
	check("unknown", e.svc.RemoveStaleKeycloakUser(ctx, asRoot, "ghost", "ghost"), 404)
	e.kc.Import("admin")
	check("core admin", e.svc.RemoveStaleKeycloakUser(ctx, asRoot, "admin", "admin"), 409)
	check("service account", e.svc.RemoveStaleKeycloakUser(ctx, asRoot, "portcullis-hub", "portcullis-hub"), 409)
	if e.kc.Get("alice") == nil || e.kc.Get("kclocal") == nil || e.kc.Get("admin") == nil || e.kc.Get("e2ecert") == nil {
		t.Fatal("a refused removal deleted something")
	}

	check("remove", e.svc.RemoveStaleKeycloakUser(ctx, asRoot, "e2ecert", "e2ecert"), 0)
	if e.kc.Get("e2ecert") != nil {
		t.Error("stale record still in Keycloak")
	}
	entries, _ := e.svc.Recent(1)
	if len(entries) != 1 || entries[0].Action != "keycloak.remove_stale" || entries[0].Target != "e2ecert" || entries[0].Result != "ok" || !strings.Contains(entries[0].Detail, "keycloak_id=") {
		t.Errorf("audit = %+v", entries)
	}
	if ov, _ := e.svc.Overview(ctx, "root"); len(ov.StaleKeycloak) != 0 {
		t.Errorf("stale after removal = %+v", ov.StaleKeycloak)
	}
}

// Deleting a user removes the Keycloak copy; if that fails the result
// warns, the audit entry says so, and the copy is listed as stale.
func TestDeleteUserKeycloakCopy(t *testing.T) {
	e := newEnv(t)
	e.ll.AddUser("bob", "bob@example.org", "", "")
	e.ll.AddUser("carl", "carl@example.org", "", "")
	e.kc.Import("bob")
	e.kc.Import("carl")

	res, err := e.svc.DeleteUser(ctx, asRoot, "bob", "bob")
	if err != nil || len(res.Warnings) != 0 || e.kc.Get("bob") != nil {
		t.Fatalf("delete bob: %+v %v", res, err)
	}
	entries, _ := e.svc.Recent(1)
	if entries[0].Detail != "keycloak_copy=removed" {
		t.Errorf("audit = %+v", entries[0])
	}

	e.kc.SetDeleteStatus(500)
	res, err = e.svc.DeleteUser(ctx, asRoot, "carl", "carl")
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "Stale Keycloak records") {
		t.Fatalf("delete carl: %+v %v", res, err)
	}
	entries, _ = e.svc.Recent(1)
	if !strings.Contains(entries[0].Detail, "keycloak_copy=FAILED") {
		t.Errorf("audit = %+v", entries[0])
	}
	e.kc.SetDeleteStatus(0)
	ov, _ := e.svc.Overview(ctx, "root")
	if len(ov.StaleKeycloak) != 1 || ov.StaleKeycloak[0].Username != "carl" {
		t.Errorf("stale = %+v", ov.StaleKeycloak)
	}
}

// Live E2E B1: Keycloak removes the federated copy, then answers 500. The
// Hub looks the id up again: gone = removed, no warning.
func TestDeleteUserKeycloak500AfterDelete(t *testing.T) {
	e := newEnv(t)
	e.ll.AddUser("bob", "bob@example.org", "", "")
	e.kc.Import("bob")
	e.kc.SetDeleteStatusAfter(500)
	res, err := e.svc.DeleteUser(ctx, asRoot, "bob", "bob")
	if err != nil || len(res.Warnings) != 0 || e.kc.Get("bob") != nil {
		t.Fatalf("delete bob: %+v %v", res, err)
	}
	if entries, _ := e.svc.Recent(1); entries[0].Detail != "keycloak_copy=removed" {
		t.Errorf("audit = %+v", entries[0])
	}
}
