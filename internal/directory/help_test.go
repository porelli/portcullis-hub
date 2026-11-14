package directory_test

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// helpEnv is delegateEnv plus sign_in_help → hr_help: "helga" holds it;
// alice is ordinary, with a passkey (an account that can sign in).
func helpEnv(t *testing.T) *env {
	t.Helper()
	e := delegateEnv(t)
	cfg, _ := e.svc.Store.Load()
	cfg.Permissions[directory.PermSignInHelp] = "hr_help"
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("hr_help")
	e.ll.AddUser("helga", "helga@example.org", "Helga", "", "hr_help")
	e.kc.Import("alice", kctest.Credential{ID: "w", Type: "webauthn-passwordless"})
	e.kc.Import("root", kctest.Credential{ID: "r", Type: "webauthn-passwordless"})
	e.kc.Import("eddie", kctest.Credential{ID: "e", Type: "webauthn-passwordless"})
	return e
}

// TestHelpPermission: sign_in_help is a delegated permission (CallerFor,
// SetPermission) and makes its group a permission group.
func TestHelpPermission(t *testing.T) {
	e := helpEnv(t)
	if c := callerFor(t, e, "helga"); c.Admin || !c.Perms[directory.PermSignInHelp] || len(c.Perms) != 1 {
		t.Errorf("helga = %+v", c)
	}
	if err := e.svc.SetPermission(ctx, asRoot, directory.PermSignInHelp, "hr_editors"); err != nil {
		t.Fatalf("SetPermission(sign_in_help) = %v", err)
	}
	if err := e.svc.SetPermission(ctx, asRoot, directory.PermSignInHelp, "hr_help"); err != nil {
		t.Fatal(err)
	}
	// helga's group is a permission group: other delegates can't target her.
	if err := e.svc.CheckDelegate(ctx, callerFor(t, e, "rex"), directory.PermRemove, "helga"); status(err) != 403 || !strings.Contains(err.Error(), "holds a delegated permission") {
		t.Errorf("rex → helga = %v", err)
	}
}

// TestHelpScopeDirectory (D32): a holder sends a setup link to an
// account that can already sign in (no keyless / created_by rule) and
// removes passkeys, audited "as sign_in_help"; never on themselves, an
// administrator, a protected account or a permission-group member; a
// holder removed from the group is refused at once (fresh snapshot);
// invite alone never removes passkeys.
func TestHelpScopeDirectory(t *testing.T) {
	e := helpEnv(t)
	helga := callerFor(t, e, "helga")
	if err := e.svc.CheckHelp(ctx, helga, "alice"); err != nil {
		t.Fatalf("CheckHelp(alice) = %v", err)
	}
	res, err := e.svc.SendInvite(ctx, helga, "alice", false)
	if err != nil || res.Invite == nil {
		t.Fatalf("invite alice = %+v %v", res, err)
	}
	if _, err := e.svc.RemovePasskeys(ctx, helga, "alice", "alice", false); err != nil {
		t.Fatalf("remove passkeys = %v", err)
	}
	entries, _ := e.svc.Recent(20)
	got := map[string]string{}
	for _, en := range entries {
		if en.Actor == "helga" && en.Result == "ok" {
			got[en.Action] = en.Detail
		}
	}
	if got["user.invite"] != "as sign_in_help" || got["user.remove_passkeys"] != "new_invite=false; as sign_in_help" {
		t.Errorf("audit details = %v", got)
	}
	// An admin's invite keeps its empty detail.
	if _, err := e.svc.SendInvite(ctx, asRoot, "bob", false); err != nil {
		t.Fatal(err)
	}
	if en, _ := e.svc.Recent(1); en[0].Detail != "" {
		t.Errorf("admin invite detail = %q", en[0].Detail)
	}
	for _, target := range []string{"helga", "root", directory.CoreAdmin, "portcullis-hub", "eddie"} {
		if err := e.svc.CheckHelp(ctx, helga, target); status(err) != 403 {
			t.Errorf("CheckHelp(%s) = %v", target, err)
		}
		if _, err := e.svc.SendInvite(ctx, helga, target, false); status(err) != 403 {
			t.Errorf("invite %s = %v", target, err)
		}
		if _, err := e.svc.RemovePasskeys(ctx, helga, target, target, false); status(err) != 403 {
			t.Errorf("remove passkeys %s = %v", target, err)
		}
	}
	// Invite only: no passkey removal, no help.
	ivy := callerFor(t, e, "ivy")
	if _, err := e.svc.RemovePasskeys(ctx, ivy, "alice", "alice", false); status(err) != 403 {
		t.Errorf("ivy remove passkeys = %v", err)
	}
	if err := e.svc.CheckHelp(ctx, ivy, "alice"); status(err) != 403 || !strings.Contains(err.Error(), "needs sign_in_help") {
		t.Errorf("ivy CheckHelp = %v", err)
	}
	// Removed from hr_help: refused with the resolved Caller.
	e.ll.RemoveMember("hr_help", "helga")
	if err := e.svc.CheckHelp(ctx, helga, "alice"); status(err) != 403 {
		t.Errorf("removed holder CheckHelp = %v", err)
	}
	if _, err := e.svc.SendInvite(ctx, helga, "alice", false); status(err) != 403 {
		t.Errorf("removed holder invite = %v", err)
	}
	// Admins may help anyone (the protected accounts are the routes' own
	// answer); a demoted admin is refused.
	if err := e.svc.CheckHelp(ctx, asRoot, "eddie"); err != nil {
		t.Errorf("admin CheckHelp = %v", err)
	}
	if err := e.svc.CheckHelp(ctx, asAdmin("bob"), "alice"); status(err) != 403 {
		t.Errorf("not an admin any more = %v", err)
	}
	if err := e.svc.CheckHelp(ctx, nil, "alice"); status(err) != 403 {
		t.Errorf("nil caller = %v", err)
	}
}

// TestAdminTakeoverUnchanged: an admin removing another admin's
// passkeys or setting their password still types the name, then it
// runs (flagged in the audit).
func TestAdminTakeoverUnchanged(t *testing.T) {
	e := helpEnv(t)
	e.ll.AddUser("ann", "ann@example.org", "Ann", "", "lldap_admin")
	e.kc.Import("ann", kctest.Credential{ID: "a", Type: "webauthn-passwordless"})
	if _, err := e.svc.RemovePasskeys(ctx, asRoot, "ann", "", false); status(err) != 400 {
		t.Errorf("no typed name = %v", err)
	}
	if _, err := e.svc.RemovePasskeys(ctx, asRoot, "ann", "ann", false); err != nil {
		t.Errorf("typed = %v", err)
	}
	if _, err := e.svc.SetPassword(ctx, asRoot, "ann", "", true, ""); status(err) != 400 {
		t.Errorf("password, no typed name = %v", err)
	}
	if _, err := e.svc.SetPassword(ctx, asRoot, "ann", "", true, "ann"); err != nil {
		t.Errorf("password, typed = %v", err)
	}
	entries, _ := e.svc.Recent(10)
	flagged := 0
	for _, en := range entries {
		if en.Result == "ok" && strings.Contains(en.Detail, "target_is_lldap_admin=true") {
			flagged++
		}
	}
	if flagged != 2 {
		t.Errorf("flagged entries = %d: %+v", flagged, entries)
	}
	// A holder never sets a password.
	if _, err := e.svc.SetPassword(ctx, callerFor(t, e, "helga"), "alice", "", true, "alice"); status(err) != 403 {
		t.Errorf("holder password = %v", err)
	}
}

// TestDelegatesNeverReserved (review I1): no delegate, whatever the
// permission, acts on a reserved portcullis-* account (403), even one
// that is no administrator.
func TestDelegatesNeverReserved(t *testing.T) {
	e := helpEnv(t)
	e.ll.AddUser("portcullis-breakglass", "bg@example.org", "Break glass", "")
	e.kc.Import("portcullis-breakglass", kctest.Credential{ID: "b", Type: "webauthn-passwordless"})
	cfg, _ := e.svc.Store.Load()
	cfg.CreatedBy["portcullis-breakglass"] = "ivy"
	e.svc.Store.Save(cfg)
	const u = "portcullis-breakglass"
	r := func(_ *directory.Result, err error) error { return err }
	for name, err := range map[string]error{
		"edit_details UpdateUser":       e.svc.UpdateUser(ctx, callerFor(t, e, "eddie"), u, strptr("x@example.org"), nil),
		"invite SendInvite":             r(e.svc.SendInvite(ctx, callerFor(t, e, "ivy"), u, false)),
		"remove DeleteUser":             r(e.svc.DeleteUser(ctx, callerFor(t, e, "rex"), u, u)),
		"sign_in_help CheckHelp":        e.svc.CheckHelp(ctx, callerFor(t, e, "helga"), u),
		"sign_in_help SendInvite":       r(e.svc.SendInvite(ctx, callerFor(t, e, "helga"), u, false)),
		"sign_in_help RemovePasskeys":   r(e.svc.RemovePasskeys(ctx, callerFor(t, e, "helga"), u, u, false)),
		"sign_in_help CheckDelegate":    e.svc.CheckDelegate(ctx, callerFor(t, e, "helga"), directory.PermSignInHelp, u),
		"remove CheckDelegate (MCP)":    e.svc.CheckDelegate(ctx, callerFor(t, e, "rex"), directory.PermRemove, u),
		"edit_details CheckDelegate":    e.svc.CheckDelegate(ctx, callerFor(t, e, "eddie"), directory.PermEditDetails, u),
		"sign_in_help remove, PORTCULL": r(e.svc.RemovePasskeys(ctx, callerFor(t, e, "helga"), "Portcullis-Breakglass", "Portcullis-Breakglass", false)),
	} {
		if status(err) != 403 || !strings.Contains(err.Error(), "reserved account") {
			t.Errorf("%s = %v", name, err)
		}
	}
	if !e.ll.HasUser(u) || len(e.kc.Get(u).Credentials) != 1 {
		t.Error("the reserved account was changed")
	}
	// Admins keep today's rules: an admin removes its passkeys.
	if _, err := e.svc.RemovePasskeys(ctx, asRoot, u, u, false); err != nil {
		t.Errorf("admin = %v", err)
	}
}

// TestHelpNeverAdministrators (review m5): a holder against an
// administrator from lldap_password_manager or from a core-subdomain
// group (group-gate-map.conf) is refused.
func TestHelpNeverAdministrators(t *testing.T) {
	e := helpEnv(t)
	e.ll.AddGroup("lldap_password_manager")
	e.ll.AddGroup("ops_admins")
	e.ll.AddUser("pm", "pm@example.org", "", "", "lldap_password_manager")
	e.ll.AddUser("otto", "otto@example.org", "", "", "ops_admins")
	helga := callerFor(t, e, "helga")
	for _, u := range []string{"pm", "otto"} {
		e.kc.Import(u, kctest.Credential{ID: "k-" + u, Type: "webauthn-passwordless"})
		if err := e.svc.CheckHelp(ctx, helga, u); status(err) != 403 || !strings.Contains(err.Error(), "is an administrator") {
			t.Errorf("CheckHelp(%s) = %v", u, err)
		}
		if _, err := e.svc.SendInvite(ctx, helga, u, false); status(err) != 403 {
			t.Errorf("invite %s = %v", u, err)
		}
		if _, err := e.svc.RemovePasskeys(ctx, helga, u, u, false); status(err) != 403 {
			t.Errorf("remove passkeys %s = %v", u, err)
		}
	}
}

// TestHelpRemovePasskeysPromotionRace (review m1): alice promoted to
// administrator between gate and the action — the action's own snapshot
// refuses the holder; nothing is removed.
func TestHelpRemovePasskeysPromotionRace(t *testing.T) {
	e := helpEnv(t)
	helga := callerFor(t, e, "helga")
	directory.SetAfterGateForTest(e.svc, func() { e.ll.AddMember("lldap_admin", "alice") })
	if _, err := e.svc.RemovePasskeys(ctx, helga, "alice", "alice", false); status(err) != 403 || !strings.Contains(err.Error(), "is an administrator") {
		t.Errorf("promoted meanwhile = %v", err)
	}
	if n := len(e.kc.Get("alice").Credentials); n != 1 {
		t.Errorf("alice's passkeys = %d, want 1", n)
	}
}

// TestRemoveAuthenticatorsTargets (Task 8): remove-passkeys' targets and
// rules: a holder on alice removes her otp credentials only (detail "2
// removed; as sign_in_help"); a holder on an administrator 403; an admin
// on another admin needs the typed name (400); portcullis-hub 409.
func TestRemoveAuthenticatorsTargets(t *testing.T) {
	e := helpEnv(t)
	e.kc.Import("alice", kctest.Credential{ID: "w", Type: "webauthn-passwordless"}, kctest.Credential{ID: "o1", Type: "otp"}, kctest.Credential{ID: "o2", Type: "otp"})
	e.kc.Import("root", kctest.Credential{ID: "r", Type: "webauthn-passwordless"}, kctest.Credential{ID: "ro", Type: "otp"})
	e.ll.AddUser("bea", "bea@example.org", "Bea", "", "lldap_admin")
	e.kc.Import("bea", kctest.Credential{ID: "bo", Type: "otp"})
	helga := callerFor(t, e, "helga")
	res, err := e.svc.RemoveAuthenticators(ctx, helga, "alice", "alice")
	if err != nil || res.Count != 2 {
		t.Fatalf("holder on alice = %+v %v", res, err)
	}
	if cr := e.kc.Get("alice").Credentials; len(cr) != 1 || cr[0].Type != "webauthn-passwordless" {
		t.Errorf("alice after = %+v", cr)
	}
	entries, _ := e.svc.Recent(5)
	if en := entries[0]; en.Action != "user.remove_authenticators" || en.Actor != "helga" || en.Result != "ok" || en.Detail != "2 removed; as sign_in_help" {
		t.Errorf("audit = %+v", en)
	}
	if _, err := e.svc.RemoveAuthenticators(ctx, helga, "alice", ""); status(err) != 400 {
		t.Errorf("no typed name = %v", err)
	}
	for _, target := range []string{"root", "helga", "eddie"} {
		if _, err := e.svc.RemoveAuthenticators(ctx, helga, target, target); status(err) != 403 {
			t.Errorf("holder on %s = %v", target, err)
		}
	}
	if len(e.kc.Get("root").Credentials) != 2 {
		t.Error("a refused call removed root's credentials")
	}
	// An admin on another admin: the typed name.
	if _, err := e.svc.RemoveAuthenticators(ctx, asRoot, "bea", ""); status(err) != 400 || len(e.kc.Get("bea").Credentials) != 1 {
		t.Errorf("admin on bea without the name = %v", err)
	}
	if res, err := e.svc.RemoveAuthenticators(ctx, asRoot, "bea", "bea"); err != nil || res.Count != 1 {
		t.Errorf("admin on bea = %+v %v", res, err)
	}
	// The takeover rule (review L2): another administrator's removal is
	// flagged in the audit; the confirm itself isn't the check — "bea"
	// typed for another admin passed only through checkAdminTakeover.
	if en, _ := e.svc.Recent(1); en[0].Action != "user.remove_authenticators" || en[0].Detail != "1 removed target_is_lldap_admin=true" {
		t.Errorf("admin on bea audit = %+v", en[0])
	}
	if _, err := e.svc.RemoveAuthenticators(ctx, asRoot, "bea", "be"); status(err) != 400 || !strings.Contains(err.Error(), "bea is an administrator: type the username to confirm") {
		t.Errorf("admin on bea with a wrong name = %v, want checkAdminTakeover's 400", err)
	}
	// An ordinary person: no flag.
	e.kc.Import("alice", kctest.Credential{ID: "o3", Type: "otp"})
	if _, err := e.svc.RemoveAuthenticators(ctx, asRoot, "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	if en, _ := e.svc.Recent(1); en[0].Detail != "1 removed" {
		t.Errorf("admin on alice audit = %+v", en[0])
	}
	for _, target := range []string{"portcullis-hub", directory.CoreAdmin} {
		if _, err := e.svc.RemoveAuthenticators(ctx, asRoot, target, target); status(err) != 409 {
			t.Errorf("admin on %s = %v", target, err)
		}
	}
	// An ordinary person (no permission): 403.
	if _, err := e.svc.RemoveAuthenticators(ctx, callerFor(t, e, "ivy"), "alice", "alice"); status(err) != 403 {
		t.Errorf("ivy = %v", err)
	}
}

// TestInviteAuthenticator (T8, P12): SendInvite passes authenticator to
// enroll; true is refused (409, enroll not asked) while totp is off.
func TestInviteAuthenticator(t *testing.T) {
	e := helpEnv(t)
	on := false
	e.svc.AuthenticatorMethodOn = func() bool { return on }
	if _, err := e.svc.SendInvite(ctx, asRoot, "alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SendInvite(ctx, asRoot, "alice", true); status(err) != 409 || err.Error() != "authenticator apps are off on this server" {
		t.Errorf("totp off = %v", err)
	}
	on = true
	if _, err := e.svc.SendInvite(ctx, asRoot, "alice", true); err != nil {
		t.Fatal(err)
	}
	e.invites.mu.Lock()
	bodies := append([]string(nil), e.invites.bodies...)
	e.invites.mu.Unlock()
	if len(bodies) != 2 || bodies[0] != `{"username":"alice","authenticator":false}` || bodies[1] != `{"username":"alice","authenticator":true}` {
		t.Errorf("bodies = %q", bodies)
	}
	// The audit records the choice (review L1); a holder's too.
	if en, _ := e.svc.Recent(1); en[0].Action != "user.invite" || en[0].Detail != "authenticator=true" {
		t.Errorf("invite audit = %+v", en[0])
	}
	if _, err := e.svc.SendInvite(ctx, callerFor(t, e, "helga"), "alice", true); err != nil {
		t.Fatal(err)
	}
	if en, _ := e.svc.Recent(1); en[0].Detail != "authenticator=true; as sign_in_help" {
		t.Errorf("holder invite audit = %+v", en[0])
	}
	// The dialog's switch is in every caller's overview (review L6): the
	// route takes it from holders and delegates too.
	for _, who := range []string{"root", "helga", "ivy"} {
		ov, err := e.svc.OverviewFor(ctx, callerFor(t, e, who))
		if err != nil || !ov.AuthenticatorOn {
			t.Errorf("%s's overview: authenticator_on %v, %v", who, ov != nil && ov.AuthenticatorOn, err)
		}
	}
	// Unset (no hook): off.
	e.svc.AuthenticatorMethodOn = nil
	if _, err := e.svc.SendInvite(ctx, asRoot, "alice", true); status(err) != 409 {
		t.Errorf("no hook = %v", err)
	}
}
