package keycloak_test

import (
	"context"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// TestClientOwner: any client with that clientId exists, with its owner
// tag ("" untagged); none is false.
func TestClientOwner(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	kc.AddClient("chat-b", map[string]string{keycloak.OwnerAttr: "chat-b"})
	kc.AddClient("untagged", nil)
	for id, want := range map[string]struct {
		exists bool
		owner  string
	}{"chat-b": {true, "chat-b"}, "untagged": {true, ""}, "chat-c": {false, ""}} {
		got, owner, err := c.ClientOwner(ctx, id)
		if err != nil || got != want.exists || owner != want.owner {
			t.Errorf("ClientOwner(%s) = %v %q %v, want %v %q", id, got, owner, err, want.exists, want.owner)
		}
	}
}
