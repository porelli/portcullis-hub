package keycloak_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// RevalidateUsers lists every page; Keycloak (the fake's RemoveInvalid)
// drops LDAP-linked users LDAP no longer has — never local users, never
// while LDAP is unreachable. The Hub deletes nothing itself.
func TestRevalidateUsers(t *testing.T) {
	kc := kctest.New(t)
	inLDAP := map[string]bool{}
	for i := 0; i < keycloak.RevalidatePageSize+50; i++ {
		name := fmt.Sprintf("user%04d", i)
		kc.Import(name)
		inLDAP[name] = true
	}
	kc.Import("local-admin").FederationLink = ""
	kc.Importable = func(u string) bool { return inLDAP[u] }
	kc.RemoveInvalid = true
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")

	n, err := c.RevalidateUsers(context.Background())
	if err != nil || n != keycloak.RevalidatePageSize+51 {
		t.Fatalf("RevalidateUsers = %d, %v", n, err)
	}
	delete(inLDAP, "user0003")
	delete(inLDAP, "user0240")
	kc.LDAPDown = true
	if _, err := c.RevalidateUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if kc.Get("user0003") == nil {
		t.Error("removed while LDAP was down")
	}
	kc.LDAPDown = false
	if _, err := c.RevalidateUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	// One pass may skip a user the removals shifted; the next gets it.
	if _, err := c.RevalidateUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if kc.Get("user0003") != nil || kc.Get("user0240") != nil {
		t.Error("users gone from LDAP still in Keycloak")
	}
	if kc.Get("local-admin") == nil || kc.Get("user0004") == nil {
		t.Error("a local or a current user was removed")
	}
	kc.SetDown(true)
	if _, err := c.RevalidateUsers(context.Background()); err == nil {
		t.Error("no error with Keycloak down")
	}
}
