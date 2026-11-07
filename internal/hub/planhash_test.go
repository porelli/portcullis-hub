package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// Plan 4 Task 17a fix round 1 (G46): SaveSettings with ExpectPlanHash
// recomputes the preview (another hash 409) and checks its stored inputs
// again under the commit's mu: a save that lands between the preview and
// the commit is refused, nothing stored.
func TestSaveSettingsExpectPlanHash(t *testing.T) {
	f, _ := secretFixture(t)
	saveSecret(t, f, "secretapp", "api_key", setSecret("s3cret-value-1"))
	actor := directory.Human("admin")
	u := SettingsUpdate{Values: map[string]json.RawMessage{"api_url": json.RawMessage(`"https://a.example.org"`)}}
	p, err := f.h.PreviewSettings(context.Background(), "secretapp", u)
	if err != nil || len(p.PlanHash) != 64 {
		t.Fatalf("preview = %+v %v", p, err)
	}
	statusOf := func(err error) int {
		var se *StatusError
		if err != nil && errors.As(err, &se) {
			return se.Status
		}
		return 0
	}
	// Another hash: 409.
	wrong := u
	wrong.ExpectPlanHash = strings.Repeat("0", 64)
	if _, err := f.h.SaveSettings("secretapp", wrong, actor); statusOf(err) != 409 {
		t.Fatalf("wrong hash = %v", err)
	}
	// A save landing between the recomputed preview and the commit: 409.
	other := SettingsUpdate{Values: map[string]json.RawMessage{"api_url": json.RawMessage(`"https://b.example.org"`)}}
	f.h.testHookSave = func() {
		f.h.testHookSave = nil
		if _, err := f.h.SaveSettings("secretapp", other, actor); err != nil {
			t.Errorf("the save in between: %v", err)
		}
	}
	planned := u
	planned.ExpectPlanHash = p.PlanHash
	if _, err := f.h.SaveSettings("secretapp", planned, actor); statusOf(err) != 409 || !strings.Contains(err.Error(), "changed while saving") {
		t.Fatalf("raced save = %v", err)
	}
	if v := f.h.st.Settings["secretapp"].Values["api_url"]; v != "https://b.example.org" {
		t.Errorf("api_url = %v, want the save in between's", v)
	}
	// A fresh preview's hash saves.
	p, _ = f.h.PreviewSettings(context.Background(), "secretapp", u)
	planned.ExpectPlanHash = p.PlanHash
	if _, err := f.h.SaveSettings("secretapp", planned, actor); err != nil {
		t.Fatal(err)
	}
	if v := f.h.st.Settings["secretapp"].Values["api_url"]; v != "https://a.example.org" {
		t.Errorf("api_url = %v", v)
	}
}
