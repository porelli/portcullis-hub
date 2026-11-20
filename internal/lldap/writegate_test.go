package lldap

import (
	"context"
	"errors"
	"testing"

	"github.com/portcullis/hub/internal/fsutil"
)

// TestNoLLDAPWriteWhileStandingBy: mutations and password changes ask
// the write gate before anything is sent; queries don't.
func TestNoLLDAPWriteWhileStandingBy(t *testing.T) {
	standBy := errors.New("this Hub is standing by: another Hub is the active writer")
	fsutil.SetWriteGate(func() error { return standBy })
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	c := New("http://127.0.0.1:1", "ldap://127.0.0.1:1", "dc=x", t.TempDir())
	ctx := context.Background()
	if err := c.graphql(ctx, "  mutation($u: String!) { deleteUser(userId: $u) { ok } }", nil, nil); !errors.Is(err, standBy) {
		t.Errorf("mutation = %v, want the gate's error", err)
	}
	if err := c.SetPassword(ctx, "alice", "a-new-password-123"); !errors.Is(err, standBy) {
		t.Errorf("SetPassword = %v, want the gate's error", err)
	}
	if err := c.graphql(ctx, "query { users { id } }", nil, nil); errors.Is(err, standBy) {
		t.Error("a query was refused")
	}
	if isMutation("query { a }") || !isMutation("\n mutation { a }") {
		t.Error("isMutation")
	}
}
