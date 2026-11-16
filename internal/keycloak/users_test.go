package keycloak_test

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"reflect"
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
	f.Import("off", kctest.Credential{ID: "w6", Type: "portcullis-security-key"})
	f.Update("off", func(u *kctest.User) { u.Enabled = false })
	f.Import("broken", kctest.Credential{ID: "w5", Type: "portcullis-security-key"})
	f.Update("broken", func(u *kctest.User) { u.CredentialsStatus = 500 })
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()

	got, err := c.SignInCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"w1": "passkey_synced", "w2": "passkey_device", "w3": "security_key", "w4": "passkey_synced", "o1": "totp"}
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
	if o, ok := got["off"]; !ok || o != nil {
		t.Errorf("a disabled user = %+v, %v; want nil (no methods at all)", o, ok)
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

// TestSignInCredentialsAAGUID: each passkey's AAGUID comes from its
// credentialData, lowercase and hyphenated; a zero AAGUID or unreadable
// data is "" (unknown model), never an error.
func TestSignInCredentialsAAGUID(t *testing.T) {
	f := kctest.New(t)
	f.Import("alice",
		kctest.Credential{ID: "k1", Type: "portcullis-security-key", CredentialData: `{"aaguid":"CB69481E-8FF7-4039-93EC-0A2729A154A8","credentialId":"x"}`},
		kctest.Credential{ID: "k2", Type: "webauthn-passwordless", CredentialData: `{"aaguid":"00000000-0000-0000-0000-000000000000"}`},
		kctest.Credential{ID: "k3", Type: "portcullis-device-passkey", CredentialData: "not json"})
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	got, err := c.SignInCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"k1": "cb69481e-8ff7-4039-93ec-0a2729a154a8", "k2": "", "k3": ""}
	if len(got["alice"]) != 3 {
		t.Fatalf("alice = %+v", got["alice"])
	}
	for _, pk := range got["alice"] {
		if pk.AAGUID != want[pk.ID] {
			t.Errorf("%s: AAGUID %q, want %q", pk.ID, pk.AAGUID, want[pk.ID])
		}
	}
}

// passkeyLabelFixture: alice has security key K1 "YubiKey", synced
// passkey K2 "iPhone" and a password labelled "Laptop"; bob has B1.
func passkeyLabelFixture(t *testing.T) (*kctest.Server, *keycloak.Client) {
	t.Helper()
	f := kctest.New(t)
	f.Import("alice",
		kctest.Credential{ID: "K1", Type: "portcullis-security-key", UserLabel: "YubiKey"},
		kctest.Credential{ID: "K2", Type: "webauthn-passwordless", UserLabel: "iPhone"},
		kctest.Credential{ID: "P1", Type: "password", UserLabel: "Laptop"})
	f.Import("bob", kctest.Credential{ID: "B1", Type: "portcullis-security-key", UserLabel: "Bob's key"})
	return f, keycloak.New(f.HTTP.URL, "admin", "admin")
}

func credLabel(f *kctest.Server, user, id string) string {
	var got string
	f.Update(user, func(u *kctest.User) {
		for _, c := range u.Credentials {
			if c.ID == id {
				got = c.UserLabel
			}
		}
	})
	return got
}

// TestSetPasskeyLabel: the caller's own passkey only (404 otherwise),
// unique among their other credentials case-insensitively (409), sent
// text/plain; Keycloak's own 409 is ErrPasskeyLabelTaken too.
func TestSetPasskeyLabel(t *testing.T) {
	f, c := passkeyLabelFixture(t)
	ctx := context.Background()
	old, err := c.SetPasskeyLabel(ctx, "alice", "K1", "Office key")
	if err != nil || old != "YubiKey" {
		t.Fatalf("SetPasskeyLabel = %q, %v", old, err)
	}
	if got := credLabel(f, "alice", "K1"); got != "Office key" {
		t.Errorf("stored label = %q", got)
	}
	var ct string
	f.Update("alice", func(u *kctest.User) { ct = u.LabelContentType })
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	for _, id := range []string{"K9", "P1", "B1"} {
		if _, err := c.SetPasskeyLabel(ctx, "alice", id, "New"); !errors.Is(err, keycloak.ErrPasskeyNotFound) {
			t.Errorf("%s: err = %v, want ErrPasskeyNotFound", id, err)
		}
	}
	for _, l := range []string{"iphone", "laptop"} {
		if _, err := c.SetPasskeyLabel(ctx, "alice", "K1", l); !errors.Is(err, keycloak.ErrPasskeyLabelTaken) {
			t.Errorf("%q: err = %v, want ErrPasskeyLabelTaken", l, err)
		}
	}
	if got := credLabel(f, "alice", "K1"); got != "Office key" {
		t.Errorf("a refused rename changed the label to %q", got)
	}
	if _, err := c.SetPasskeyLabel(ctx, "nobody", "K1", "X"); !errors.Is(err, keycloak.ErrUserNotFound) {
		t.Errorf("unknown user: err = %v", err)
	}
	f.Update("alice", func(u *kctest.User) { u.LabelStatus = 409 })
	if _, err := c.SetPasskeyLabel(ctx, "alice", "K1", "Fresh name"); !errors.Is(err, keycloak.ErrPasskeyLabelTaken) {
		t.Errorf("Keycloak 409: err = %v", err)
	}
	f.Update("alice", func(u *kctest.User) { u.LabelStatus = 500 })
	if _, err := c.SetPasskeyLabel(ctx, "alice", "K1", "Fresh name"); err == nil || errors.Is(err, keycloak.ErrPasskeyLabelTaken) || errors.Is(err, keycloak.ErrPasskeyNotFound) {
		t.Errorf("Keycloak 500: err = %v", err)
	}
}

// TestSetPasskeyLabelRecase: recasing a passkey's own name isn't a
// duplicate of itself.
func TestSetPasskeyLabelRecase(t *testing.T) {
	f, c := passkeyLabelFixture(t)
	old, err := c.SetPasskeyLabel(context.Background(), "alice", "K1", "yubikey")
	if err != nil || old != "YubiKey" {
		t.Fatalf("SetPasskeyLabel = %q, %v", old, err)
	}
	if got := credLabel(f, "alice", "K1"); got != "yubikey" {
		t.Errorf("stored label = %q", got)
	}
	// Saving an unchanged name never 409s, even when another credential
	// (here the password) shares it: nothing is sent.
	f.Update("alice", func(u *kctest.User) {
		for i := range u.Credentials {
			if u.Credentials[i].ID == "P1" {
				u.Credentials[i].UserLabel = "YUBIKEY"
			}
		}
		u.LabelStatus = 500 // a PUT would fail
	})
	if old, err := c.SetPasskeyLabel(context.Background(), "alice", "K1", "yubikey"); err != nil || old != "yubikey" {
		t.Errorf("unchanged label = %q, %v", old, err)
	}
}

// TestSignInCredentialsOTP (T4): an otp credential is listed with the
// passkeys as Type "totp", with its label and creation time and no AAGUID.
func TestSignInCredentialsOTP(t *testing.T) {
	f := kctest.New(t)
	f.Import("alice",
		kctest.Credential{ID: "o1", Type: "otp", UserLabel: "Authenticator 2026-11-14 09:00:00", CreatedDate: 1794260205000},
		kctest.Credential{ID: "k1", Type: "portcullis-security-key", UserLabel: "YubiKey"})
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	got, err := c.SignInCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var o *keycloak.PasskeyCredential
	for i := range got["alice"] {
		if got["alice"][i].ID == "o1" {
			o = &got["alice"][i]
		}
	}
	if o == nil || o.Type != "totp" || o.Label != "Authenticator 2026-11-14 09:00:00" || o.Created.UnixMilli() != 1794260205000 || o.AAGUID != "" {
		t.Errorf("otp = %+v (all %+v)", o, got["alice"])
	}
	if len(got["alice"]) != 2 {
		t.Errorf("alice = %+v", got["alice"])
	}
}

// The otp credentialData (its policy, never the secret, which the admin
// API never returns) is in no field and no log line.
func TestSignInCredentialsNeverKeepsCredentialData(t *testing.T) {
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	const data = `{"subType":"totp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1","aaguid":"cb69481e-8ff7-4039-93ec-0a2729a154a8"}`
	f := kctest.New(t)
	f.Import("alice", kctest.Credential{ID: "o1", Type: "otp", UserLabel: "Phone", CredentialData: data})
	f.Import("bob", kctest.Credential{ID: "o2", Type: "otp", CredentialData: data})
	f.Update("bob", func(u *kctest.User) { u.CredentialsStatus = 500 })
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	got, err := c.SignInCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	for _, needle := range []string{"subType", "HmacSHA1", "cb69481e"} {
		if strings.Contains(string(b), needle) || strings.Contains(logs.String(), needle) {
			t.Errorf("%q leaked: %s / %s", needle, b, logs.String())
		}
	}
	if len(got["alice"]) != 1 || got["alice"][0].AAGUID != "" {
		t.Errorf("alice = %+v", got["alice"])
	}
}

func otpLabelFixture(t *testing.T) (*kctest.Server, *keycloak.Client) {
	t.Helper()
	f := kctest.New(t)
	f.Import("alice",
		kctest.Credential{ID: "O1", Type: "otp", UserLabel: "Phone"},
		kctest.Credential{ID: "O2", Type: "otp", UserLabel: "Tablet"},
		kctest.Credential{ID: "K1", Type: "portcullis-security-key", UserLabel: "YubiKey"},
		kctest.Credential{ID: "P1", Type: "password"})
	f.Import("bob", kctest.Credential{ID: "B1", Type: "otp", UserLabel: "Bob's phone"})
	return f, keycloak.New(f.HTTP.URL, "admin", "admin")
}

// T6: SetAuthenticatorLabel renames an own otp credential only.
func TestSetAuthenticatorLabelRefusesPasskey(t *testing.T) {
	f, c := otpLabelFixture(t)
	ctx := context.Background()
	old, err := c.SetAuthenticatorLabel(ctx, "alice", "O1", "Work phone")
	if err != nil || old != "Phone" || credLabel(f, "alice", "O1") != "Work phone" {
		t.Fatalf("rename = %q, %v (%q)", old, err, credLabel(f, "alice", "O1"))
	}
	for _, id := range []string{"K1", "P1", "B1", "nope"} {
		if _, err := c.SetAuthenticatorLabel(ctx, "alice", id, "X"); !errors.Is(err, keycloak.ErrAuthenticatorNotFound) {
			t.Errorf("%s: %v, want ErrAuthenticatorNotFound", id, err)
		}
	}
	for _, l := range []string{"tablet", "YUBIKEY"} {
		if _, err := c.SetAuthenticatorLabel(ctx, "alice", "O1", l); !errors.Is(err, keycloak.ErrPasskeyLabelTaken) {
			t.Errorf("%q: %v, want a duplicate", l, err)
		}
	}
	if credLabel(f, "alice", "K1") != "YubiKey" {
		t.Error("a passkey was renamed")
	}
}

func TestSetPasskeyLabelRefusesOTP(t *testing.T) {
	f, c := otpLabelFixture(t)
	if _, err := c.SetPasskeyLabel(context.Background(), "alice", "O1", "X"); !errors.Is(err, keycloak.ErrPasskeyNotFound) {
		t.Errorf("otp via SetPasskeyLabel: %v", err)
	}
	if credLabel(f, "alice", "O1") != "Phone" {
		t.Error("an authenticator was renamed")
	}
}

// RemoveAuthenticators deletes the otp credentials only, then signs out.
func TestRemoveAuthenticatorsOnlyOTP(t *testing.T) {
	f, c := otpLabelFixture(t)
	f.Update("alice", func(u *kctest.User) { u.Sessions = 2 })
	n, err := c.RemoveAuthenticators(context.Background(), "alice")
	if err != nil || n != 2 {
		t.Fatalf("RemoveAuthenticators = %d, %v", n, err)
	}
	a := f.Get("alice")
	var types []string
	for _, cr := range a.Credentials {
		types = append(types, cr.Type)
	}
	if strings.Join(types, ",") != "portcullis-security-key,password" || a.Sessions != 0 {
		t.Errorf("after: %v, sessions %d", types, a.Sessions)
	}
	if b := f.Get("bob"); len(b.Credentials) != 1 {
		t.Error("bob's authenticator went too")
	}
	// None left: 0, still signed out, no error.
	if n, err := c.RemoveAuthenticators(context.Background(), "alice"); err != nil || n != 0 {
		t.Errorf("again = %d, %v", n, err)
	}
}

// T12: the realm's OTP policy and the two required actions' max_auth_age.
func TestOTPPolicyReadsRealmAndActions(t *testing.T) {
	f := kctest.New(t)
	realm := func(reusable bool) map[string]any {
		return map[string]any{"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30,
			"otpPolicyLookAheadWindow": 1, "otpPolicyInitialCounter": 0, "otpPolicyCodeReusable": reusable}
	}
	f.SetRealm(realm(false), map[string]map[string]string{"CONFIGURE_TOTP": {"max_auth_age": "300"}, "delete_credential": {"max_auth_age": "300"}})
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	p, err := c.OTPPolicy(ctx)
	want := keycloak.OTPPolicy{Type: "totp", Algorithm: "HmacSHA1", Digits: 6, Period: 30, LookAhead: 1, InitialCounter: 0, CodeReusable: false, ConfigureMaxAge: 300, DeleteMaxAge: 300}
	if err != nil || p == nil || !reflect.DeepEqual(*p, want) {
		t.Fatalf("OTPPolicy = %+v, %v", p, err)
	}
	// A missing action config or an unreadable value reads as 0 (drift).
	f.SetRealm(realm(true), map[string]map[string]string{"CONFIGURE_TOTP": {"max_auth_age": "five"}})
	p, err = c.OTPPolicy(ctx)
	if err != nil || p.ConfigureMaxAge != 0 || p.DeleteMaxAge != 0 || !p.CodeReusable {
		t.Errorf("drift = %+v, %v", p, err)
	}
	// Absent policy fields (review T7-L1): named in Unset, never read as
	// the wanted zero values.
	fields := realm(false)
	delete(fields, "otpPolicyCodeReusable")
	delete(fields, "otpPolicyInitialCounter")
	f.SetRealm(fields, map[string]map[string]string{"CONFIGURE_TOTP": {"max_auth_age": "300"}, "delete_credential": {"max_auth_age": "300"}})
	p, err = c.OTPPolicy(ctx)
	if err != nil || strings.Join(p.Unset, ",") != "otpPolicyCodeReusable,otpPolicyInitialCounter" {
		t.Errorf("absent fields = %+v, %v", p, err)
	}
	f.SetRealm(realm(false), map[string]map[string]string{"CONFIGURE_TOTP": {"max_auth_age": "300"}, "delete_credential": {"max_auth_age": "300"}})
	if p, _ = c.OTPPolicy(ctx); len(p.Unset) != 0 {
		t.Errorf("all present: Unset %v", p.Unset)
	}
	f.SetDown(true)
	if _, err := c.OTPPolicy(ctx); err == nil {
		t.Error("Keycloak down: want an error")
	}
}

// TestUserSignInCredentials: one user's entry, as SignInCredentials
// lists it: their keys, nil when disabled, not found when unknown, an
// error when their credentials can't be read.
func TestUserSignInCredentials(t *testing.T) {
	f := kctest.New(t)
	f.Import("alice", kctest.Credential{ID: "p1", Type: "password"}, kctest.Credential{ID: "w3", Type: "portcullis-security-key", UserLabel: "YubiKey"}, kctest.Credential{ID: "o1", Type: "otp"})
	f.Import("bob")
	f.Import("off", kctest.Credential{ID: "w6", Type: "portcullis-security-key"})
	f.Update("off", func(u *kctest.User) { u.Enabled = false })
	f.Import("broken", kctest.Credential{ID: "w5", Type: "portcullis-security-key"})
	f.Update("broken", func(u *kctest.User) { u.CredentialsStatus = 500 })
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	ctx := context.Background()
	all, err := c.SignInCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		keys, found, err := c.UserSignInCredentials(ctx, u)
		if err != nil || !found || keys == nil || !reflect.DeepEqual(keys, all[u]) {
			t.Errorf("%s = %+v %v %v, all %+v", u, keys, found, err, all[u])
		}
	}
	if keys, found, err := c.UserSignInCredentials(ctx, "off"); err != nil || !found || keys != nil {
		t.Errorf("disabled = %+v %v %v", keys, found, err)
	}
	if _, found, err := c.UserSignInCredentials(ctx, "nobody"); err != nil || found {
		t.Errorf("unknown = %v %v", found, err)
	}
	if _, _, err := c.UserSignInCredentials(ctx, "broken"); err == nil {
		t.Error("unreadable credentials: want an error")
	}
	if _, _, err := c.UserSignInCredentials(ctx, "a*"); err == nil {
		t.Error("an invalid username: want an error")
	}
}
