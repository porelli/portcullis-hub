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
