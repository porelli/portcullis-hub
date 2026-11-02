package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// domains lists the enrolled domains listed instances have hostnames on:
// not unused enrolled domains, not domains that are no longer enrolled, and
// always as an array.
func TestPortalDomains(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady}, Domain{Name: "unused.example.net", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f.data, "portal-apps.json"))
	if err != nil || !strings.Contains(string(raw), `"domains": []`) {
		t.Errorf("no instance on an extra domain: %s (%v)", raw, err)
	}
	if err := f.h.Enable("chat"); err != nil { // main domain only
		t.Fatal(err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "grafana.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if doc := readPortal(t, f); len(doc.Domains) != 0 {
		t.Errorf("disabled instance counted: %v", doc.Domains)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	if doc := readPortal(t, f); strings.Join(doc.Domains, ",") != "team-b.example.org" {
		t.Errorf("domains = %v, want only the used enrolled domain", doc.Domains)
	}
	// The domain is no longer enrolled: not listed (the portal then hides
	// URLs on it).
	doms.set(Domain{Name: "unused.example.net", State: DomainReady})
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if doc := readPortal(t, f); doc.Domains == nil || len(doc.Domains) != 0 {
		t.Errorf("domains after unenroll = %#v", doc.Domains)
	}
}
