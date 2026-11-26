package hub

import (
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// TestDeletedDefaultInstanceNotListed (test server, 2026-11-26): deleting
// a template's only (default) instance keeps the delete's own final op
// record (contract §11.7: a deleted instance's record outlives it), but
// that record must not make the default instance "installed" again: it
// is not listed by Instances() (the Apps page), and it doesn't rank as
// a default instance with state for the catalog's claims. Enabling or
// creating it again is a fresh default instance.
func TestDeletedDefaultInstanceNotListed(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.SetAudit(&fakeAudit{})
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 0)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.DeleteInstance("grafana", "grafana", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if r := f.h.LastOp("grafana"); r == nil || r.Op != OpDelete || !r.OK {
		t.Fatalf("the delete's record = %+v", r)
	}
	for _, v := range f.h.Instances() {
		if v.ID == "grafana" {
			t.Errorf("deleted default instance still listed: %+v", v)
		}
	}
	f.h.mu.RLock()
	tier := f.h.claimTierLocked("grafana")
	f.h.mu.RUnlock()
	if tier != 0 {
		t.Errorf("claim tier of a deleted default instance = %d, want 0", tier)
	}
	// A failed operation on the (implicit) default instance afterwards is
	// listed again: only a finished delete's record is ignored.
	f.h.recordOp("grafana", OpRecord{Op: OpEnable, OK: false, Error: "boom"})
	listed := false
	for _, v := range f.h.Instances() {
		listed = listed || v.ID == "grafana"
	}
	if !listed {
		t.Error("a failed enable's record no longer lists the default instance")
	}
	// Enabling it again is a fresh default instance.
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
}
