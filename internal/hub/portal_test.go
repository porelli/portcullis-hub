package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readPortal(t *testing.T, f *fixture) PortalDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.data, "portal-apps.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc PortalDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestPortalFile(t *testing.T) {
	f := newFixture(t)
	if doc := readPortal(t, f); doc.Version != PortalVersion || len(doc.Apps) != 0 {
		t.Errorf("initial portal = %+v", doc)
	}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	doc := readPortal(t, f)
	if len(doc.Apps) != 1 || doc.Apps[0].ID != "grafana" || doc.Apps[0].AccessGroup != "users_grafana" || doc.Apps[0].AdminGroup != "admin_grafana" || doc.Apps[0].AuthMethod != "header-auth" {
		t.Errorf("portal = %+v", doc)
	}
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	if doc := readPortal(t, f); len(doc.Apps) != 0 {
		t.Errorf("after disable = %+v", doc)
	}
}
