package keycloak_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// TestRequireImpersonationNotice (D45): the action is added once and the
// other required actions are kept; RequiredActions and UserEnabled read
// the user; an unknown user is ErrUserNotFound.
func TestRequireImpersonationNotice(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	kc.Import("alice")
	kc.Update("alice", func(u *kctest.User) { u.RequiredActions = []string{"UPDATE_PASSWORD"} })
	for range 2 {
		if err := c.RequireImpersonationNotice(ctx, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"UPDATE_PASSWORD", keycloak.ImpersonationNoticeAction}
	if got := kc.Get("alice").RequiredActions; !reflect.DeepEqual(got, want) {
		t.Errorf("required actions = %v, want %v", got, want)
	}
	if got, err := c.RequiredActions(ctx, "alice"); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("RequiredActions = %v, %v", got, err)
	}
	if on, err := c.UserEnabled(ctx, "alice"); err != nil || !on {
		t.Errorf("UserEnabled = %v, %v", on, err)
	}
	kc.Update("alice", func(u *kctest.User) { u.Enabled = false })
	if on, err := c.UserEnabled(ctx, "alice"); err != nil || on {
		t.Errorf("disabled: UserEnabled = %v, %v", on, err)
	}
	if err := c.RequireImpersonationNotice(ctx, "nobody"); !errors.Is(err, keycloak.ErrUserNotFound) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := c.RequiredActions(ctx, "nobody"); !errors.Is(err, keycloak.ErrUserNotFound) {
		t.Errorf("unknown RequiredActions: %v", err)
	}
	if _, err := c.UserEnabled(ctx, "nobody"); !errors.Is(err, keycloak.ErrUserNotFound) {
		t.Errorf("unknown UserEnabled: %v", err)
	}
}
