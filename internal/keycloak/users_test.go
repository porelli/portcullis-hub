package keycloak_test

import (
	"context"
	"errors"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

func TestUserManagement(t *testing.T) {
	f := kctest.New(t)
	f.Importable = func(u string) bool { return u == "carol" }
	f.Import("alice", kctest.Credential{ID: "p1", Type: "password"}, kctest.Credential{ID: "w1", Type: "webauthn-passwordless"}, kctest.Credential{ID: "w2", Type: "webauthn"})
	f.Import("bob")
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()

	st, err := c.UserStatuses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 || st["alice"].Passkeys != 2 || st["bob"].Passkeys != 0 {
		t.Errorf("statuses = %+v", st)
	}

	// Lazy import: carol exists only in LDAP until looked up.
	if _, ok := st["carol"]; ok {
		t.Fatal("carol listed before import")
	}
	if err := c.RequirePasskey(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	if u := f.Get("carol"); u == nil || len(u.RequiredActions) != 1 || u.RequiredActions[0] != keycloak.PasskeyAction {
		t.Errorf("carol = %+v", u)
	}
	// Idempotent.
	if err := c.RequirePasskey(ctx, "carol"); err != nil || len(f.Get("carol").RequiredActions) != 1 {
		t.Errorf("second RequirePasskey: %v %v", err, f.Get("carol").RequiredActions)
	}
	if _, err := c.ImportUser(ctx, "nobody"); !errors.Is(err, keycloak.ErrUserNotFound) {
		t.Errorf("ImportUser(nobody) = %v", err)
	}

	n, err := c.RemovePasskeys(ctx, "alice", true)
	if err != nil || n != 2 {
		t.Fatalf("RemovePasskeys = %d, %v", n, err)
	}
	a := f.Get("alice")
	if len(a.Credentials) != 1 || a.Credentials[0].Type != "password" || a.Sessions != 0 || len(a.RequiredActions) != 1 {
		t.Errorf("alice after = %+v", a)
	}
	if err := c.SetUserRequiredActions(ctx, "alice", nil); err != nil || len(f.Get("alice").RequiredActions) != 0 {
		t.Errorf("clear: %v", err)
	}
	if _, err := c.RemovePasskeys(ctx, "bob", false); err != nil || len(f.Get("bob").RequiredActions) != 0 {
		t.Errorf("remove without action: %v %+v", err, f.Get("bob"))
	}
	if err := c.LogoutUser(ctx, "nobody"); err != nil {
		t.Errorf("LogoutUser(never imported) = %v", err)
	}
	if err := c.DeleteUserByID(ctx, f.Get("bob").ID); err != nil || f.Get("bob") != nil {
		t.Errorf("delete: %v", err)
	}
	if err := c.DeleteUserByID(ctx, "00000000-0000-0000-0000-999999999999"); err != nil {
		t.Errorf("delete missing = %v", err)
	}
}

func TestUserStatusesPerUserErrors(t *testing.T) {
	f := kctest.New(t)
	f.Import("alice", kctest.Credential{ID: "w1", Type: "webauthn"})
	f.Import("stale")
	f.Import("gone")
	f.Import("local")
	f.Update("stale", func(u *kctest.User) { u.CredentialsStatus = 500 })
	f.Update("gone", func(u *kctest.User) { u.CredentialsStatus = 404 })
	f.Update("local", func(u *kctest.User) { u.FederationLink = "" })
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()

	st, err := c.UserStatuses(ctx)
	if err != nil {
		t.Fatalf("one broken user must not fail the whole list: %v", err)
	}
	if a := st["alice"]; a.Error != "" || a.Passkeys != 1 || !a.LDAPFederated {
		t.Errorf("alice = %+v", a)
	}
	if s := st["stale"]; s.ErrorStatus != 500 || s.Error != "list credentials: HTTP 500" || !s.LDAPFederated {
		t.Errorf("stale = %+v", s)
	}
	if g := st["gone"]; g.ErrorStatus != 404 {
		t.Errorf("gone = %+v", g)
	}
	if l := st["local"]; l.LDAPFederated || l.Error != "" {
		t.Errorf("local = %+v", l)
	}

	// ListedUser reads the list only: no credentials, no LDAP import.
	u, err := c.ListedUser(ctx, "STALE")
	if err != nil || u == nil || u.Username != "stale" || !u.LDAPFederated {
		t.Errorf("ListedUser(stale) = %+v, %v", u, err)
	}
	if u, err := c.ListedUser(ctx, "nobody"); err != nil || u != nil {
		t.Errorf("ListedUser(nobody) = %+v, %v", u, err)
	}

	// An outage is a realm-level error.
	f.SetDown(true)
	if _, err := c.UserStatuses(ctx); err == nil {
		t.Error("Keycloak down: want an error")
	}
	if _, err := c.ListedUser(ctx, "stale"); err == nil {
		t.Error("ListedUser with Keycloak down: want an error")
	}
}

func TestCredentialCount(t *testing.T) {
	f := kctest.New(t)
	f.Import("alice", kctest.Credential{ID: "p1", Type: "password"}, kctest.Credential{ID: "w1", Type: "webauthn-passwordless"}, kctest.Credential{ID: "w2", Type: "webauthn"})
	f.Import("bob", kctest.Credential{ID: "p2", Type: "password"})
	f.Import("olga", kctest.Credential{ID: "o", Type: "otp"})
	f.Import("nora")
	f.Import("gone").CredentialsStatus = 500
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	for user, want := range map[string]int{"alice": 3, "bob": 1, "olga": 1, "nora": 0, "nobody": 0} {
		if n, err := c.CredentialCount(ctx, user); err != nil || n != want {
			t.Errorf("CredentialCount(%s) = %d, %v; want %d", user, n, err, want)
		}
	}
	if _, err := c.CredentialCount(ctx, "gone"); err == nil {
		t.Error("credential lookup failure not reported")
	}
	f.SetDown(true)
	if _, err := c.CredentialCount(ctx, "bob"); err == nil {
		t.Error("outage not reported")
	}
}
