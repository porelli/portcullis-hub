package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// myAppsEnv: newSetEnv with vault enabled and storage_quota rows
// (default 10GiB, office_milan 1TiB): bob (users_vault, office_milan)
// gets 1 TiB.
func myAppsEnv(t *testing.T) *setEnv {
	t.Helper()
	e := newSetEnv(t)
	if code, b := e.do(t, "root", "POST", "/api/templates/enable", `{"id":"vault"}`); code != 200 {
		t.Fatalf("enable = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"person":{"storage_quota":{"default":"10GiB","rows":[{"group":"office_milan","value":"1TiB"}]}}}`); code != 200 {
		t.Fatalf("save = %d %s", code, b)
	}
	e.s.Hub.Wait()
	return e
}

func myAppsOf(t *testing.T, e *setEnv, user string) []hub.MyApp {
	t.Helper()
	r, b := doAs(t, e.ppl, user, "GET", "/api/me/apps", "")
	if r.StatusCode != 200 {
		t.Fatalf("%s GET /api/me/apps = %d %s", user, r.StatusCode, b)
	}
	var ans struct {
		Apps []hub.MyApp `json:"apps"`
	}
	if err := json.Unmarshal([]byte(b), &ans); err != nil || ans.Apps == nil {
		t.Fatalf("answer %s: %v", b, err)
	}
	return ans.Apps
}

func TestMyAppsCallerCaseFolded(t *testing.T) {
	e := myAppsEnv(t)
	e.ll.AddUser("bob2", "bob2@example.org", "Bob 2", "")
	apps := myAppsOf(t, e, "BOB")
	if len(apps) != 1 || apps[0].ID != "vault" || len(apps[0].Values) != 1 || apps[0].Values[0].Value != "1 TiB" || apps[0].Values[0].Reason.Group != "office_milan" {
		t.Errorf("BOB's apps = %+v, want bob's vault quota", apps)
	}
	if apps := myAppsOf(t, e, "Bob2"); len(apps) != 0 {
		t.Errorf("Bob2's apps = %+v, want none", apps)
	}
	if apps := myAppsOf(t, e, "dana"); len(apps) != 0 {
		t.Errorf("dana's apps = %+v, want none", apps)
	}
}

func TestMyAppsNoCaller(t *testing.T) {
	e := myAppsEnv(t)
	if r, _ := doAs(t, e.ppl, "", "GET", "/api/me/apps", ""); r.StatusCode != 401 {
		t.Errorf("no X-Forwarded-User = %d, want 401", r.StatusCode)
	}
}

func TestMyAppsDirectoryDown(t *testing.T) {
	e := myAppsEnv(t)
	e.ll.HTTP.Close()
	r, b := doAs(t, e.ppl, "bob", "GET", "/api/me/apps", "")
	if r.StatusCode != 503 || strings.TrimSpace(b) != directory.GenericUnavailable {
		t.Errorf("directory down = %d %q, want 503 %q", r.StatusCode, b, directory.GenericUnavailable)
	}
}
