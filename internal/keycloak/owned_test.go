package keycloak_test

import (
	"context"
	"slices"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
)

// TestClientIDsOwnedBy: only the clients whose owner tag equals the
// instance id; never another instance's, an untagged one or core's.
func TestClientIDsOwnedBy(t *testing.T) {
	kc := kctest.New(t)
	kc.AddClient("gone", map[string]string{keycloak.OwnerAttr: "gone"})
	kc.AddClient("gone-mcp", map[string]string{keycloak.OwnerAttr: "gone"})
	kc.AddClient("gone-2", map[string]string{keycloak.OwnerAttr: "gone-2"})
	kc.AddClient("untagged", nil)
	kc.AddClient(keycloak.ForwardAuthClient, map[string]string{keycloak.OwnerAttr: "gone"})
	c := keycloak.New(kc.HTTP.URL, "admin", "admin")
	got, err := c.ClientIDsOwnedBy(context.Background(), "gone")
	if err != nil || !slices.Equal(got, []string{"gone", "gone-mcp"}) {
		t.Errorf("%v %v", got, err)
	}
	if _, err := c.ClientIDsOwnedBy(context.Background(), ""); err == nil {
		t.Error("no owner accepted")
	}
}
