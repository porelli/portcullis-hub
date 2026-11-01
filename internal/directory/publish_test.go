package directory_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// Publish: pending expiries, shared fields only, every user but the
// service account; OnChange fires after mutations, outside the lock.
func TestPublishAndOnChange(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.ll.AddGroup("contractors", "alice")
	var changes, inside atomic.Int32
	e.svc.OnChange = func() {
		changes.Add(1)
		// Evaluate takes the service lock: deadlocks if OnChange is
		// called with it held.
		if inside.Add(1) == 1 {
			if _, err := e.svc.Evaluate(ctx, time.Now()); err != nil {
				t.Errorf("Evaluate in OnChange: %v", err)
			}
		}
		inside.Add(-1)
	}

	for _, f := range []directory.Field{
		{Name: "cost_center", Label: "Cost center", Kind: directory.FieldKindText, ShareWithApps: true},
		{Name: "teams", Label: "Teams", Kind: directory.FieldKindText, Multi: true, ShareWithApps: true},
		{Name: "clearance", Label: "Clearance", Kind: directory.FieldKindText, AdminOnly: true},
	} {
		if err := e.svc.CreateField(ctx, asRoot, f); err != nil {
			t.Fatal(err)
		}
	}
	if n := changes.Load(); n != 3 {
		t.Errorf("OnChange after 3 field creates: %d", n)
	}
	if err := e.svc.SetDetails(ctx, asRoot, "alice", map[string][]string{"cost_center": {"CC-1"}, "teams": {"a", "b"}, "clearance": {"secret"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "portcullis-hub", map[string][]string{"cost_center": {"svc"}}, nil); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	if err := e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "alice", &until); err != nil {
		t.Fatal(err)
	}
	if n := changes.Load(); n != 5 {
		t.Errorf("OnChange after details + expiry: %d", n)
	}
	// A refused mutation changes nothing.
	if err := e.svc.SetDetails(ctx, asRoot, "portcullis-hub", map[string][]string{"cost_center": {"x"}}); err == nil {
		t.Fatal("service account edited")
	}
	if n := changes.Load(); n != 5 {
		t.Errorf("OnChange after a refusal: %d", n)
	}

	pub, err := e.svc.Publish(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(pub.Expiring); got != fmt.Sprint([]directory.Expiring{{User: "alice", Group: "contractors", At: until}}) {
		t.Errorf("expiring = %s", got)
	}
	if len(pub.Fields) != 2 || pub.Fields[0].Name != "cost_center" || pub.Fields[1].Name != "teams" || !pub.Fields[1].Multi {
		t.Errorf("fields = %+v", pub.Fields)
	}
	want := map[string]map[string][]string{"alice": {"cost_center": {"CC-1"}, "teams": {"a", "b"}}}
	if !reflect.DeepEqual(pub.Users, want) {
		t.Errorf("users = %v", pub.Users)
	}

	// Broken directory.yaml: an error, never a partial view.
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := os.WriteFile(e.svc.Store.Path, []byte("version: 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Publish(ctx, time.Now()); err == nil {
		t.Error("corrupt directory.yaml published")
	}
}
