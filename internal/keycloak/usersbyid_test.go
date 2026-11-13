package keycloak_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

func TestUsernamesByID(t *testing.T) {
	f := kctest.New(t)
	alice := f.Import("Alice")
	f.Import("local")
	f.Update("local", func(u *kctest.User) { u.FederationLink = "" })
	f.Import("other")
	f.Update("other", func(u *kctest.User) { u.FederationLink = "not-ldap" })
	for i := 0; i < 450; i++ { // more than two pages
		f.Import(fmt.Sprintf("u%03d", i))
	}
	c := keycloak.New(f.HTTP.URL, "admin", "admin")
	got, err := c.UsernamesByID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[alice.ID] != "alice" {
		t.Errorf("alice: %q", got[alice.ID])
	}
	if len(got) != 451 {
		t.Errorf("%d users, want 451 (federated only)", len(got))
	}
	for _, u := range got {
		if u == "local" || u == "other" {
			t.Errorf("non-federated user %s listed", u)
		}
	}
}
