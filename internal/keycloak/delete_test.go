package keycloak_test

import (
	"context"
	"errors"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// TestDeleteClient: only a client tagged with the instance is deleted; a
// missing one is fine (retries), anything else is left alone.
func TestDeleteClient(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	kc.AddClient("chat-b", map[string]string{keycloak.OwnerAttr: "chat-b"})
	kc.AddClient("chat-c", map[string]string{keycloak.OwnerAttr: "chat-c"})
	kc.AddClient("untagged", nil)
	if err := c.DeleteClient(ctx, "chat-b", "chat-b"); err != nil {
		t.Fatal(err)
	}
	if kc.ClientByClientID("chat-b") != nil {
		t.Errorf("chat-b still there: %v", kc.Calls)
	}
	if err := c.DeleteClient(ctx, "chat-b", "chat-b"); err != nil {
		t.Errorf("retry: %v", err)
	}
	var ce *keycloak.ConflictError
	for _, tc := range [][2]string{{"chat-c", "chat-b"}, {"untagged", "untagged"}, {keycloak.ForwardAuthClient, keycloak.ForwardAuthClient}, {"chat-c", ""}} {
		if err := c.DeleteClient(ctx, tc[0], tc[1]); !errors.As(err, &ce) {
			t.Errorf("DeleteClient(%s, %s) = %v", tc[0], tc[1], err)
		}
	}
	if kc.ClientByClientID("chat-c") == nil || kc.ClientByClientID("untagged") == nil {
		t.Error("a foreign client was deleted")
	}
}
