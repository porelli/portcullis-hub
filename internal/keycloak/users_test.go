package keycloak_test

import (
	"context"
	"errors"
	"strings"
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

// Keycloak deletes a federated user's copy and then answers 500 (optimistic
// lock, live E2E B1): the id is looked up again and "not found" = removed.
// A 500 that left the user in place stays an error.
func TestDeleteUserByID5xxButGone(t *testing.T) {
	f := kctest.New(t)
	f.Import("bob")
	f.Import("carl")
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	f.SetDeleteStatusAfter(500)
	if err := c.DeleteUserByID(ctx, f.Get("bob").ID); err != nil || f.Get("bob") != nil {
		t.Errorf("delete then 500: %v (bob %+v)", err, f.Get("bob"))
	}
	f.SetDeleteStatusAfter(0)
	f.SetDeleteStatus(500)
	if err := c.DeleteUserByID(ctx, f.Get("carl").ID); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("500 and still there = %v", err)
	}
}

// TestImportUserLink: the id and the LDAP link (LDAP_ID = LLDAP's uuid,
// imported on lookup); none for a user without one.
func TestImportUserLink(t *testing.T) {
	f := kctest.New(t)
	f.Importable = func(u string) bool { return u == "carol" }
	f.LDAPUUID = func(u string) string { return "148d3233-69a7-30ad-bb6f-e305b3891f0a" }
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	id, link, err := c.ImportUserLink(ctx, "carol")
	if err != nil || id != f.Get("carol").ID || link != "148d3233-69a7-30ad-bb6f-e305b3891f0a" {
		t.Errorf("ImportUserLink(carol) = %q %q %v", id, link, err)
	}
	f.Import("local")
	f.Update("local", func(u *kctest.User) { u.LDAPID = "" })
	if id, link, err := c.ImportUserLink(ctx, "local"); err != nil || id == "" || link != "" {
		t.Errorf("ImportUserLink(local) = %q %q %v", id, link, err)
	}
	if _, _, err := c.ImportUserLink(ctx, "nobody"); !errors.Is(err, keycloak.ErrUserNotFound) {
		t.Errorf("ImportUserLink(nobody) = %v", err)
	}
}

func TestSignInCredentialsTypes(t *testing.T) {
	f := kctest.New(t)
	f.Import("alice",
		kctest.Credential{ID: "p1", Type: "password"},
		kctest.Credential{ID: "w1", Type: "webauthn-passwordless", UserLabel: "Phone", CreatedDate: 1794260205000},
		kctest.Credential{ID: "w2", Type: "portcullis-device-passkey", UserLabel: "Laptop"},
		kctest.Credential{ID: "w3", Type: "portcullis-security-key", UserLabel: "YubiKey 5"},
		kctest.Credential{ID: "w4", Type: "webauthn"},
		kctest.Credential{ID: "o1", Type: "otp"})
	f.Import("Bob")
	f.Import("broken", kctest.Credential{ID: "w5", Type: "portcullis-security-key"})
	f.Update("broken", func(u *kctest.User) { u.CredentialsStatus = 500 })
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()

	got, err := c.SignInCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"w1": "passkey_synced", "w2": "passkey_device", "w3": "security_key", "w4": "passkey_synced"}
	if len(got["alice"]) != len(want) {
		t.Fatalf("alice = %+v", got["alice"])
	}
	for _, pk := range got["alice"] {
		if want[pk.ID] != pk.Type {
			t.Errorf("%s: type %q, want %q", pk.ID, pk.Type, want[pk.ID])
		}
		if pk.ID == "w1" && (pk.Label != "Phone" || pk.Created.UnixMilli() != 1794260205000) {
			t.Errorf("w1 = %+v", pk)
		}
	}
	// Known, none set up; unreadable: left out (unknown).
	if b, ok := got["bob"]; !ok || len(b) != 0 {
		t.Errorf("bob = %+v, %v", b, ok)
	}
	if _, ok := got["broken"]; ok {
		t.Error("a user whose credentials can't be read must be unknown")
	}
	for typ, m := range map[string]string{"webauthn-passwordless": "passkey_synced", "webauthn": "passkey_synced", "portcullis-device-passkey": "passkey_device", "portcullis-security-key": "security_key"} {
		if k, ok := keycloak.PasskeyKind(typ); !ok || string(k) != m {
			t.Errorf("PasskeyKind(%s) = %s, %v", typ, k, ok)
		}
	}
	if _, ok := keycloak.PasskeyKind("password"); ok {
		t.Error("password is not a passkey")
	}
	f.SetDown(true)
	if _, err := c.SignInCredentials(ctx); err == nil {
		t.Error("Keycloak down: want an error")
	}
}

func TestRemovePasskeysRemovesEveryKind(t *testing.T) {
	f := kctest.New(t)
	f.Import("alice",
		kctest.Credential{ID: "p1", Type: "password"},
		kctest.Credential{ID: "w1", Type: "webauthn-passwordless"},
		kctest.Credential{ID: "w2", Type: "portcullis-device-passkey"},
		kctest.Credential{ID: "w3", Type: "portcullis-security-key"},
		kctest.Credential{ID: "w4", Type: "webauthn"})
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	if st, err := c.UserStatuses(ctx); err != nil || st["alice"].Passkeys != 4 {
		t.Errorf("statuses = %+v, %v", st, err)
	}
	n, err := c.RemovePasskeys(ctx, "alice", false)
	if err != nil || n != 4 {
		t.Fatalf("RemovePasskeys = %d, %v", n, err)
	}
	if a := f.Get("alice"); len(a.Credentials) != 1 || a.Credentials[0].Type != "password" {
		t.Errorf("alice after = %+v", a.Credentials)
	}
}
