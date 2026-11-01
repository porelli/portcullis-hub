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
	"github.com/portcullis/hub/internal/rules"
)

// delegateEnv: hr_editors (edit_details), hr_inviters (invite) and
// hr_removers (remove); "eddie" edits, "ivy" invites, "rex" removes, "hera"
// holds all three; "bob" is an ordinary user.
func delegateEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	cfg, err := e.svc.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Permissions = map[string]string{
		directory.PermEditDetails: "hr_editors",
		directory.PermInvite:      "hr_inviters",
		directory.PermRemove:      "hr_removers",
	}
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("hr_editors")
	e.ll.AddGroup("hr_inviters")
	e.ll.AddGroup("hr_removers")
	e.ll.AddUser("eddie", "eddie@example.org", "Eddie", "", "hr_editors")
	e.ll.AddUser("edna", "edna@example.org", "Edna", "", "hr_editors")
	e.ll.AddUser("ivy", "ivy@example.org", "Ivy", "", "hr_inviters")
	e.ll.AddUser("rex", "rex@example.org", "Rex", "", "hr_removers")
	e.ll.AddUser("hera", "hera@example.org", "Hera", "", "hr_editors", "hr_inviters", "hr_removers")
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	return e
}

func callerFor(t *testing.T, e *env, user string) *directory.Caller {
	t.Helper()
	c, err := e.svc.CallerFor(ctx, user)
	if err != nil {
		t.Fatalf("CallerFor(%s): %v", user, err)
	}
	return c
}

func TestCallerFor(t *testing.T) {
	e := delegateEnv(t)
	if _, err := e.svc.CallerFor(ctx, " "); status(err) != 403 {
		t.Errorf("empty user = %v", err)
	}
	if c := callerFor(t, e, "root"); !c.Admin || c.User != "root" {
		t.Errorf("root = %+v", c)
	}
	if c := callerFor(t, e, "Hera"); c.Admin || !c.Perms[directory.PermEditDetails] || !c.Perms[directory.PermInvite] || !c.Perms[directory.PermRemove] {
		t.Errorf("hera = %+v", c)
	}
	if c := callerFor(t, e, "eddie"); c.Admin || !c.Perms[directory.PermEditDetails] || c.Perms[directory.PermInvite] || c.Perms[directory.PermRemove] {
		t.Errorf("eddie = %+v", c)
	}
	if c := callerFor(t, e, "ghost"); c.Admin || len(c.Perms) != 0 || c.User != "ghost" {
		t.Errorf("unknown = %+v", c)
	}
	// An "admin" key in permissions grants nothing.
	cfg, _ := e.svc.Store.Load()
	cfg.Permissions["admin"] = "hr_editors"
	e.svc.Store.Save(cfg)
	if c := callerFor(t, e, "eddie"); c.Admin || c.Perms["admin"] {
		t.Errorf("admin permission key = %+v", c)
	}
	// No Store: no delegated permissions; admins still work.
	e.svc.Store = nil
	if c := callerFor(t, e, "hera"); len(c.Perms) != 0 {
		t.Errorf("no store = %+v", c)
	}
	if c := callerFor(t, e, "root"); !c.Admin {
		t.Errorf("no store root = %+v", c)
	}
}

func TestDelegateCannotEscalate(t *testing.T) {
	e := delegateEnv(t)
	e.kc.Import("root")

	// Create an AdminOnly field for testing (before the "before" marker)
	if err := e.svc.LLDAP.AddUserAttribute(ctx, "secret", false); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.svc.Store.Load()
	cfg.Fields = append(cfg.Fields, directory.Field{Name: "secret", Label: "Secret", Kind: directory.FieldKindText, AdminOnly: true})
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	eddie, ivy, rex, bob := callerFor(t, e, "eddie"), callerFor(t, e, "ivy"), callerFor(t, e, "rex"), callerFor(t, e, "bob")
	before := len(e.ll.Mutations)
	check := func(name string, err error) {
		t.Helper()
		if status(err) != 403 {
			t.Errorf("%s = %v (status %d), want 403", name, err, status(err))
		}
	}
	r := func(_ *directory.Result, err error) error { return err }
	r2 := func(_ *directory.ConvertPreview, err error) error { return err }

	check("editor edits self", e.svc.UpdateUser(ctx, eddie, "eddie", nil, strptr("Boss")))
	check("editor edits another editor", e.svc.UpdateUser(ctx, eddie, "edna", nil, strptr("X")))
	check("editor edits an inviter", e.svc.UpdateUser(ctx, eddie, "ivy", nil, strptr("X")))
	check("editor edits an admin", e.svc.UpdateUser(ctx, eddie, "root", strptr("me@example.org"), nil))
	check("editor edits core admin", e.svc.UpdateUser(ctx, eddie, "admin", nil, strptr("X")))
	check("editor edits service", e.svc.UpdateUser(ctx, eddie, "portcullis-hub", nil, strptr("X")))
	check("editor SetDetails self", e.svc.SetDetails(ctx, eddie, "eddie", map[string][]string{}))
	check("editor SetDetails admin", e.svc.SetDetails(ctx, eddie, "root", map[string][]string{}))
	check("editor SetDetails permission-group member", e.svc.SetDetails(ctx, eddie, "ivy", map[string][]string{}))
	check("inviter re-invites an admin", r(e.svc.SendInvite(ctx, ivy, "root")))
	check("inviter re-invites self", r(e.svc.SendInvite(ctx, ivy, "ivy")))
	check("inviter re-invites a remover", r(e.svc.SendInvite(ctx, ivy, "rex")))
	check("remover removes an admin", r(e.svc.DeleteUser(ctx, rex, "root", "root")))
	check("remover removes self", r(e.svc.DeleteUser(ctx, rex, "rex", "rex")))
	check("remover removes an editor", r(e.svc.DeleteUser(ctx, rex, "eddie", "eddie")))

	// Wrong permission.
	check("editor invites", r(e.svc.SendInvite(ctx, eddie, "bob")))
	check("editor removes", r(e.svc.DeleteUser(ctx, eddie, "bob", "bob")))
	check("inviter edits", e.svc.UpdateUser(ctx, ivy, "bob", nil, strptr("X")))
	check("nobody creates", r(e.svc.CreateUser(ctx, bob, directory.CreateRequest{Username: "zed", Email: "zed@example.org"})))
	if err := e.svc.UpdateUser(ctx, ivy, "bob", nil, strptr("X")); err == nil || !strings.Contains(err.Error(), "needs edit_details") {
		t.Errorf("message = %v", err)
	}
	// A Caller resolved before losing the permission is re-checked.
	edna := callerFor(t, e, "edna")
	e.ll.RemoveMember("hr_editors", "edna")
	check("stale caller", e.svc.UpdateUser(ctx, edna, "bob", nil, strptr("X")))

	// Inviters: no password onboarding, no groups, nobody protected.
	check("inviter password onboarding", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Onboarding: directory.OnboardPassword, Generate: true})))
	if _, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Groups: []string{"lldap_admin"}}); status(err) != 400 {
		t.Errorf("inviter with groups = %v", err)
	}
	check("inviter creates self", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "ivy", Email: "ivy@example.org"})))
	check("inviter creates admin", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "admin", Email: "a@example.org"})))

	// Admin-only operations, even holding every permission.
	hera := callerFor(t, e, "hera")

	adminOnly := map[string]error{
		"SetPassword":             r(e.svc.SetPassword(ctx, hera, "bob", "", true, "")),
		"RequirePasskey":          e.svc.RequirePasskey(ctx, hera, "bob"),
		"ClearActions":            e.svc.ClearActions(ctx, hera, "bob"),
		"RemovePasskeys":          r(e.svc.RemovePasskeys(ctx, hera, "bob", "bob", true)),
		"RemoveStaleKeycloakUser": e.svc.RemoveStaleKeycloakUser(ctx, hera, "ghost", "ghost"),
		"AddMember":               e.svc.AddMember(ctx, hera, "hr_editors", "bob"),
		"AddMember (admin)":       e.svc.AddMember(ctx, hera, "lldap_admin", "hera"),
		"RemoveMember":            e.svc.RemoveMember(ctx, hera, "hr_editors", "eddie"),
		"CreateGroup":             e.svc.CreateGroup(ctx, hera, "new_group"),
		"DeleteGroup":             e.svc.DeleteGroup(ctx, hera, "hr_editors", "hr_editors"),
		"CreateField":             e.svc.CreateField(ctx, hera, directory.Field{Name: "department", Label: "Department", Kind: directory.FieldKindText}),
		"UpdateField":             e.svc.UpdateField(ctx, hera, directory.Field{Name: "department", Label: "Dept"}),
		"DeleteField":             e.svc.DeleteField(ctx, hera, "department", "department"),
		"SetGroupRule":            e.svc.SetGroupRule(ctx, hera, "hr_editors", nil),
		"ConvertPreview":          r2(e.svc.ConvertPreview(ctx, hera, "hr_editors", &rules.Expr{Op: rules.OpEmpty, Field: "department"})),
		"ConvertApply":            e.svc.ConvertApply(ctx, hera, "hr_editors", &rules.Expr{Op: rules.OpEmpty, Field: "department"}, nil),
		"AddException":            e.svc.AddException(ctx, hera, "hr_editors", directory.Exception{User: "bob", Reason: "x", Include: true}),
		"RemoveException":         e.svc.RemoveException(ctx, hera, "hr_editors", "bob"),
		"SetMemberExpiry":         e.svc.SetMemberExpiry(ctx, hera, "hr_editors", "eddie", nil),
		"SetPermission":           e.svc.SetPermission(ctx, hera, directory.PermEditDetails, ""),
		"SetDetails AdminOnly":    e.svc.SetDetails(ctx, hera, "bob", map[string][]string{"secret": {"value"}}),
	}
	for name, err := range adminOnly {
		check(name, err)
		if err != nil && !strings.Contains(err.Error(), "admins only") && !strings.Contains(err.Error(), "admin-only") {
			t.Errorf("%s message = %q", name, err)
		}
	}

	if got := e.ll.Mutations[before:]; len(got) != 0 {
		t.Errorf("delegates changed LLDAP: %v", got)
	}
	if len(e.invites.users) != 0 {
		t.Errorf("invites created: %v", e.invites.users)
	}
	entries, err := e.svc.Recent(100)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, en := range entries {
		if en.Result != "refused" {
			t.Errorf("entry %+v not refused", en)
		}
		refused++
	}
	if want := 25 + len(adminOnly); refused != want {
		t.Errorf("refused audit entries = %d, want %d", refused, want)
	}
	for _, en := range entries {
		if en.Action == "user.update" && en.Target == "eddie" && en.Actor != "eddie" {
			t.Errorf("actor = %+v", en)
		}
	}
}

func TestDelegateAllowed(t *testing.T) {
	e := delegateEnv(t)
	eddie, ivy, rex := callerFor(t, e, "eddie"), callerFor(t, e, "ivy"), callerFor(t, e, "rex")

	if err := e.svc.UpdateUser(ctx, eddie, "bob", strptr("robert@example.org"), strptr("Robert")); err != nil {
		t.Fatalf("editor edits bob: %v", err)
	}
	res, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "nina", Email: "nina@example.org"})
	if err != nil || res.Invite == nil {
		t.Fatalf("inviter creates nina: %+v %v", res, err)
	}
	for _, g := range []string{"lldap_admin", "hr_editors", "hr_inviters", "hr_removers"} {
		for _, m := range e.ll.GroupMembers(g) {
			if m == "nina" {
				t.Errorf("nina is in %s", g)
			}
		}
	}
	if res, err := e.svc.SendInvite(ctx, ivy, "nina"); err != nil || res.Invite == nil {
		t.Errorf("inviter re-invites nina (delegate-created, no credentials): %v", err)
	}
	if _, err := e.svc.DeleteUser(ctx, rex, "nina", "nina"); err != nil {
		t.Errorf("remover removes nina: %v", err)
	}
	if e.ll.HasUser("nina") {
		t.Error("nina still exists")
	}
	entries, _ := e.svc.Recent(100)
	for _, en := range entries {
		if en.Result != "ok" {
			t.Errorf("entry = %+v", en)
		}
	}
	if len(entries) != 4 || entries[3].Actor != "eddie" || entries[2].Actor != "ivy" || entries[0].Actor != "rex" {
		t.Errorf("entries = %+v", entries)
	}
}

// TestDelegateInviteKeyless: delegates re-invite only accounts a delegate
// created that have no Keycloak credential of any kind (an invite would
// hand them a working account); Keycloak trouble fails closed. Admins are
// unaffected.
func TestDelegateInviteKeyless(t *testing.T) {
	e := delegateEnv(t)
	ivy := callerFor(t, e, "ivy")
	e.ll.AddUser("carl", "carl@example.org", "", "")
	e.ll.AddUser("olga", "olga@example.org", "", "")
	e.ll.AddUser("dina", "dina@example.org", "", "")
	e.ll.AddUser("nora", "nora@example.org", "", "")
	e.kc.Import("bob", kctest.Credential{ID: "w", Type: "webauthn-passwordless"})
	e.kc.Import("carl", kctest.Credential{ID: "p", Type: "password"})
	e.kc.Import("olga", kctest.Credential{ID: "o", Type: "otp"})
	e.kc.Import("nora")
	e.kc.Import("stale", kctest.Credential{ID: "c", Type: "otp"})
	cfg, _ := e.svc.Store.Load()
	for _, u := range []string{"bob", "carl", "olga", "dina"} { // not nora: admin-created
		cfg.CreatedBy[u] = "ivy"
	}
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	r := func(_ *directory.Result, err error) error { return err }
	refusedWant := 0
	refused := func(name string, err error) {
		t.Helper()
		refusedWant++
		if status(err) != 403 {
			t.Errorf("%s = %v (status %d), want 403", name, err, status(err))
		}
	}

	refused("passkey", r(e.svc.SendInvite(ctx, ivy, "bob")))
	refused("password credential", r(e.svc.SendInvite(ctx, ivy, "carl")))
	refused("otp credential", r(e.svc.SendInvite(ctx, ivy, "olga")))
	err := r(e.svc.SendInvite(ctx, ivy, "nora"))
	refused("admin-created, no credentials", err)
	if err == nil || !strings.Contains(err.Error(), "only an admin can re-invite nora") {
		t.Errorf("message = %v", err)
	}
	refused("create over a Keycloak copy with a credential", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "stale", Email: "stale@example.org"})))
	if e.ll.HasUser("stale") {
		t.Error("stale created")
	}
	if err := r(e.svc.SendInvite(ctx, ivy, "dina")); err != nil {
		t.Errorf("delegate-created, no credentials = %v", err)
	}
	if err := r(e.svc.SendInvite(ctx, asRoot, "bob")); err != nil {
		t.Errorf("admin re-invites bob = %v", err)
	}
	if err := r(e.svc.SendInvite(ctx, asRoot, "nora")); err != nil {
		t.Errorf("admin re-invites nora = %v", err)
	}
	e.kc.SetDown(true)
	refused("Keycloak down", r(e.svc.SendInvite(ctx, ivy, "dina")))
	refused("Keycloak down, create", r(e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "erin", Email: "erin@example.org"})))
	if e.ll.HasUser("erin") {
		t.Error("erin created")
	}
	e.kc.SetDown(false)
	e.svc.KC = nil
	refused("no Keycloak", r(e.svc.SendInvite(ctx, ivy, "dina")))
	entries, _ := e.svc.Recent(100)
	n := 0
	for _, en := range entries {
		if en.Result == "refused" {
			n++
		}
	}
	if n != refusedWant {
		t.Errorf("refused entries = %d, want %d: %+v", n, refusedWant, entries)
	}
}

func TestUniqueEmails(t *testing.T) {
	e := delegateEnv(t)
	r := func(_ *directory.Result, err error) error { return err }
	if err := r(e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "alice2", Email: " ALICE@example.org "})); status(err) != 409 || e.ll.HasUser("alice2") {
		t.Errorf("admin create with a used email = %v", err)
	}
	if err := r(e.svc.CreateUser(ctx, callerFor(t, e, "ivy"), directory.CreateRequest{Username: "alice3", Email: "alice@example.org"})); status(err) != 409 {
		t.Errorf("delegate create with a used email = %v", err)
	}
	if err := e.svc.UpdateUser(ctx, asRoot, "bob", strptr("Alice@Example.org"), nil); status(err) != 409 {
		t.Errorf("admin update to a used email = %v", err)
	}
	if err := e.svc.UpdateUser(ctx, callerFor(t, e, "eddie"), "bob", strptr("alice@example.org"), nil); status(err) != 409 {
		t.Errorf("delegate update to a used email = %v", err)
	}
	if err := e.svc.UpdateUser(ctx, asRoot, "bob", strptr("BOB@example.org"), nil); err != nil {
		t.Errorf("own email, new case = %v", err)
	}
}

func TestTombstones(t *testing.T) {
	e := delegateEnv(t)
	cfg, _ := e.svc.Store.Load()
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cfg.Groups["milan"] = &directory.GroupConfig{
		Exceptions: []directory.Exception{{User: "Bob", Reason: "x", By: "root", Include: true, At: at}, {User: "dora", Reason: "y", By: "root", Include: true, At: at}},
		Expiry:     map[string]time.Time{"bob": at, "carl": at},
	}
	cfg.CreatedBy = map[string]string{"bob": "ivy"}
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	ivy := callerFor(t, e, "ivy")
	if _, err := e.svc.DeleteUser(ctx, callerFor(t, e, "rex"), "bob", "bob"); err != nil {
		t.Fatal(err)
	}
	cfg, _ = e.svc.Store.Load()
	if _, ok := cfg.Deleted["bob"]; !ok {
		t.Errorf("no tombstone: %v", cfg.Deleted)
	}
	g := cfg.Groups["milan"]
	if len(g.Exceptions) != 1 || g.Exceptions[0].User != "dora" || len(g.Expiry) != 1 || cfg.CreatedBy["bob"] != "" {
		t.Errorf("not purged: %+v %v", g, cfg.CreatedBy)
	}

	_, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "bob", Email: "bob2@example.org"})
	if status(err) != 409 || !strings.Contains(err.Error(), "was deleted; an admin must re-create it") || e.ll.HasUser("bob") {
		t.Errorf("delegate re-creates bob = %v", err)
	}
	if _, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "dora", Email: "dora@example.org"}); status(err) != 409 || e.ll.HasUser("dora") {
		t.Errorf("delegate creates a name in exceptions = %v", err)
	}
	if _, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "carl", Email: "carl@example.org"}); status(err) != 409 || e.ll.HasUser("carl") {
		t.Errorf("delegate creates a name in expiry = %v", err)
	}
	res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "bob", Email: "bob2@example.org"})
	if err != nil || len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, " "), "deleted") {
		t.Fatalf("admin re-creates bob = %+v %v", res, err)
	}
	cfg, _ = e.svc.Store.Load()
	if _, ok := cfg.Deleted["bob"]; ok {
		t.Error("tombstone kept after an admin re-created bob")
	}
}

// TestDeleteTombstoneFirst: the tombstone is saved before LLDAP is
// touched; if it can't be, nothing is deleted.
func TestDeleteTombstoneFirst(t *testing.T) {
	e := delegateEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "missing-dir", "directory.yaml")}
	if _, err := e.svc.DeleteUser(ctx, asRoot, "bob", "bob"); status(err) != 503 || !e.ll.HasUser("bob") {
		t.Errorf("delete with an unwritable directory.yaml = %v (bob exists: %v)", err, e.ll.HasUser("bob"))
	}
	entries, _ := e.svc.Recent(1)
	if len(entries) != 1 || entries[0].Action != "user.delete" || entries[0].Result == "ok" {
		t.Errorf("audit = %+v", entries)
	}
}

func TestDemotedAdminRefused(t *testing.T) {
	e := delegateEnv(t)
	e.ll.AddUser("bea", "bea@example.org", "", "", "lldap_admin")
	bea := callerFor(t, e, "bea")
	e.ll.RemoveMember("lldap_admin", "bea")
	if err := e.svc.UpdateUser(ctx, bea, "bob", nil, strptr("X")); status(err) != 403 {
		t.Errorf("demoted admin = %v", err)
	}
	if err := e.svc.CreateGroup(ctx, bea, "g"); status(err) != 403 || e.ll.HasGroup("g") {
		t.Errorf("demoted admin creates a group = %v", err)
	}
}

func TestCreatedBy(t *testing.T) {
	e := delegateEnv(t)
	if _, err := e.svc.CreateUser(ctx, callerFor(t, e, "ivy"), directory.CreateRequest{Username: "nina", Email: "nina@example.org"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "omar", Email: "omar@example.org"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.svc.Store.Load()
	if cfg.CreatedBy["nina"] != "ivy" || cfg.CreatedBy["omar"] != "" {
		t.Errorf("created_by = %v", cfg.CreatedBy)
	}
}

// failDelete is an LLDAP whose DeleteUser fails.
type failDelete struct{ directory.Directory }

func (failDelete) DeleteUser(context.Context, string) error {
	return errors.New("simulated LLDAP failure")
}

// TestDeletePurgeAfterSuccess: only the tombstone is written before the
// LLDAP delete; exceptions, expiries and created_by go only once the
// delete succeeded, so a failed delete leaves the person's exclusions in
// force.
func TestDeletePurgeAfterSuccess(t *testing.T) {
	e, store := evalEnv(t)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	setRule(t, store, "milan", `city = "Milan"`, directory.Exception{User: "bob", Reason: "moved", By: "root", Include: false, At: t0})
	cfg, _ := store.Load()
	cfg.Groups["team"] = &directory.GroupConfig{Expiry: map[string]time.Time{"bob": t0.Add(240 * time.Hour)}}
	cfg.CreatedBy["bob"] = "ivy"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	real := e.svc.LLDAP
	e.svc.LLDAP = failDelete{real}
	if _, err := e.svc.DeleteUser(ctx, asRoot, "bob", "bob"); err == nil || !e.ll.HasUser("bob") {
		t.Fatalf("failed delete = %v (bob exists: %v)", err, e.ll.HasUser("bob"))
	}
	cfg, _ = store.Load()
	if ex := cfg.Groups["milan"].Exceptions; len(ex) != 1 || ex[0].User != "bob" {
		t.Errorf("exceptions after a failed delete = %+v", ex)
	}
	if len(cfg.Groups["team"].Expiry) != 1 || cfg.CreatedBy["bob"] != "ivy" {
		t.Errorf("expiry/created_by after a failed delete = %v %v", cfg.Groups["team"].Expiry, cfg.CreatedBy)
	}
	if _, ok := cfg.Deleted["bob"]; !ok {
		t.Error("tombstone not written before the delete")
	}
	evaluate(t, e, t0)
	wantMembers(t, e, "milan", "carol")

	e.svc.LLDAP = real
	if _, err := e.svc.DeleteUser(ctx, asRoot, "bob", "bob"); err != nil {
		t.Fatal(err)
	}
	cfg, _ = store.Load()
	if len(cfg.Groups["milan"].Exceptions) != 0 || len(cfg.Groups["team"].Expiry) != 0 || cfg.CreatedBy["bob"] != "" {
		t.Errorf("not purged after delete: %+v %v %v", cfg.Groups["milan"].Exceptions, cfg.Groups["team"].Expiry, cfg.CreatedBy)
	}
	if _, ok := cfg.Deleted["bob"]; !ok {
		t.Error("tombstone missing after delete")
	}
}

// TestAdminCreatePurgesLeftovers: a name deleted outside the Hub can still
// be named in exceptions, expiries and created_by; an admin creating it
// starts clean, and is told.
func TestAdminCreatePurgesLeftovers(t *testing.T) {
	e := delegateEnv(t)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cfg, _ := e.svc.Store.Load()
	cfg.Groups["milan"] = &directory.GroupConfig{Exceptions: []directory.Exception{{User: "Zoe", Reason: "x", By: "root", Include: true, At: t0}, {User: "bob", Reason: "y", By: "root", Include: true, At: t0}}}
	cfg.Groups["team"] = &directory.GroupConfig{Expiry: map[string]time.Time{"zoe": t0}}
	cfg.CreatedBy["zoe"] = "ivy"
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zoe", Email: "zoe@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(res.Warnings, " ")
	if !strings.Contains(w, "milan") || !strings.Contains(w, "team") || !strings.Contains(w, "created_by") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	cfg, _ = e.svc.Store.Load()
	if ex := cfg.Groups["milan"].Exceptions; len(ex) != 1 || ex[0].User != "bob" {
		t.Errorf("exceptions = %+v", ex)
	}
	if len(cfg.Groups["team"].Expiry) != 0 || cfg.CreatedBy["zoe"] != "" {
		t.Errorf("leftovers = %v %v", cfg.Groups["team"].Expiry, cfg.CreatedBy)
	}
	res, err = e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "yuri", Email: "yuri@example.org"})
	if err != nil || strings.Contains(strings.Join(res.Warnings, " "), "purged") {
		t.Errorf("clean create = %+v %v", res, err)
	}
}

// TestAdminCredentialActionClearsCreatedBy: once an admin acts on an
// account's sign-in, delegates can no longer re-invite it.
func TestAdminCredentialActionClearsCreatedBy(t *testing.T) {
	e := delegateEnv(t)
	ivy := callerFor(t, e, "ivy")
	r := func(_ *directory.Result, err error) error { return err }
	actions := map[string]func(user string) error{
		"SetPassword":    func(u string) error { return r(e.svc.SetPassword(ctx, asRoot, u, "", true, "")) },
		"SendInvite":     func(u string) error { return r(e.svc.SendInvite(ctx, asRoot, u)) },
		"RemovePasskeys": func(u string) error { return r(e.svc.RemovePasskeys(ctx, asRoot, u, u, false)) },
		"RequirePasskey": func(u string) error { return e.svc.RequirePasskey(ctx, asRoot, u) },
	}
	for name, act := range actions {
		user := "n-" + strings.ToLower(name)
		if _, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: user, Email: user + "@example.org"}); err != nil {
			t.Fatal(err)
		}
		if cfg, _ := e.svc.Store.Load(); cfg.CreatedBy[user] != "ivy" {
			t.Fatalf("%s: created_by = %v", name, cfg.CreatedBy)
		}
		if err := act(user); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg, _ := e.svc.Store.Load(); cfg.CreatedBy[user] != "" {
			t.Errorf("%s kept created_by", name)
		}
		e.kc.Update(user, func(u *kctest.User) { u.Credentials = nil }) // no Keycloak credential left either
		if err := r(e.svc.SendInvite(ctx, ivy, user)); status(err) != 403 {
			t.Errorf("after %s, delegate re-invite = %v", name, err)
		}
	}
	// A delegate's own re-invite keeps created_by.
	if _, err := e.svc.CreateUser(ctx, ivy, directory.CreateRequest{Username: "kept", Email: "kept@example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := r(e.svc.SendInvite(ctx, ivy, "kept")); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := e.svc.Store.Load(); cfg.CreatedBy["kept"] != "ivy" {
		t.Error("delegate re-invite cleared created_by")
	}
}
