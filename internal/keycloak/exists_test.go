package keycloak_test

import (
	"context"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// TestClientExists: true for any client with that clientId (any owner),
// false for none.
func TestClientExists(t *testing.T) {
	ctx := context.Background()
	kc := kctest.New(t)
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	kc.AddClient("chat-b", map[string]string{keycloak.OwnerAttr: "chat-b"})
	kc.AddClient("untagged", nil)
	for id, want := range map[string]bool{"chat-b": true, "untagged": true, "chat-c": false} {
		got, err := c.ClientExists(ctx, id)
		if err != nil || got != want {
			t.Errorf("ClientExists(%s) = %v %v, want %v", id, got, err, want)
		}
	}
}
