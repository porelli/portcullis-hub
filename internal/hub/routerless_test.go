package hub

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/policy"
)

// Task 13: Router-less instances (method custom, zero HTTP routers) must:
// - publish no hosts in the policy file and deny nothing;
// - have a portal entry with empty `urls` and a `note`;
// - have My apps entries with `URL ""`;
// - never get a Keycloak client or access role.

// routerlessFixture loads the SMB fixture which is router-less, with secrets configured.
func routerlessFixture(t *testing.T) *fixture {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", smbID, "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", smbID, "compose.yml"))
	var secrets string
	f := newInstanceFixtureCfg(t, nil, nil, map[string][2]string{smbID: {string(m), string(c)}}, func(root string, cfg *Config) {
		secrets = filepath.Join(root, "secrets")
		if err := os.Mkdir(secrets, 0700); err != nil {
			t.Fatal(err)
		}
		cfg.SecretsDir = secrets
	})
	if f.h.Template(smbID) == nil {
		t.Fatalf("smbfixture not loaded")
	}
	return f
}

func TestRouterlessEnableNoPolicyHosts(t *testing.T) {
	// The SMB fixture is router-less: method custom, zero HTTP routers.
	f := routerlessFixture(t)

	tm := f.h.Template(smbID)
	if tm == nil {
		t.Fatal("smbfixture template not found")
	}
	if !tm.Manifest.Routerless() {
		t.Fatal("SMB fixture is not router-less")
	}

	// Set up directory and groups for enabling.
	people := newFakePeople()
	people.addGroup("users_" + smbID)
	people.addGroup("admin_" + smbID)
	f.h.SetPeople(people)
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{}})

	// Enable the instance (the default instance, id = template id).
	if err := f.h.Enable(smbID); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// The policy file must have no entry for this instance.
	policyPath := f.h.policyPath()
	b, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("ReadFile policy: %v", err)
	}
	var doc policy.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("Unmarshal policy: %v", err)
	}

	// Check that no policy, group or public host is published for smbfixture.
	for host := range doc.Policies {
		t.Errorf("policy published host %q for router-less instance", host)
	}
	for host := range doc.Groups {
		t.Errorf("groups published host %q for router-less instance", host)
	}
	for host := range doc.PublicPaths {
		t.Errorf("public_paths published host %q for router-less instance", host)
	}

	// Check that reconcile reports no exposure drift (it may report
	// enabled_not_running, which is fine for a test without containers).
	drift := f.h.Reconcile(context.Background())
	for _, item := range drift.Items {
		if item.ID == smbID && item.Kind != DriftNotRunning {
			t.Errorf("reconcile reported unexpected drift for router-less instance: %v", item)
		}
	}

	// Check that no Keycloak client was created.
	// The SMB fixture has no keycloak_clients in its manifest, so this
	// is checking the general rule: router-less instances get no clients.
	// The fakeIdP doesn't track clients, but we can verify from the manifest.
	if len(tm.Manifest.Clients) != 0 {
		t.Errorf("router-less template has %d Keycloak clients, want 0", len(tm.Manifest.Clients))
	}
}

func TestRouterlessPortalEntry(t *testing.T) {
	f := routerlessFixture(t)

	tm := f.h.Template(smbID)
	if tm == nil || !tm.Manifest.Routerless() {
		t.Fatal("SMB fixture is not router-less")
	}

	// Set up directory and enable the instance.
	people := newFakePeople()
	people.addGroup("users_" + smbID)
	people.addGroup("admin_" + smbID)
	f.h.SetPeople(people)
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{}})

	if err := f.h.Enable(smbID); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// Get the portal document.
	portal := f.h.Portal()

	if len(portal.Apps) != 1 {
		t.Fatalf("portal has %d apps, want 1", len(portal.Apps))
	}

	app := portal.Apps[0]
	if app.ID != smbID {
		t.Errorf("app ID = %q, want %s", app.ID, smbID)
	}

	// Check that URLs is empty (not nil).
	if app.URLs == nil {
		t.Error("URLs is nil, want []")
	}
	if len(app.URLs) != 0 {
		t.Errorf("len(URLs) = %d, want 0", len(app.URLs))
	}

	// Check that Note is present with the template's auth.notes.
	if app.Note == "" {
		t.Error("Note is empty, want auth.notes")
	}
	expectedNote := "No web page: file sharing over SMB."
	if app.Note != expectedNote {
		t.Errorf("Note = %q, want %q", app.Note, expectedNote)
	}

	// Check that access_group is users_smbfixture (the default instance).
	if app.AccessGroup != "users_"+smbID {
		t.Errorf("AccessGroup = %q, want users_%s", app.AccessGroup, smbID)
	}
}

func TestRouterlessMyApps(t *testing.T) {
	f := routerlessFixture(t)

	tm := f.h.Template(smbID)
	if tm == nil || !tm.Manifest.Routerless() {
		t.Fatal("SMB fixture is not router-less")
	}

	// Set up directory with alice in the access group, bob not.
	people := newFakePeople()
	people.addGroup("users_"+smbID, "alice")
	people.addGroup("admin_" + smbID)
	people.addGroup("other_group", "bob")
	f.h.SetPeople(people)
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{}})

	if err := f.h.Enable(smbID); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// Call MyApps for a user in the population.
	ctx := context.Background()
	apps, err := f.h.MyApps(ctx, "alice")
	if err != nil {
		t.Fatalf("MyApps: %v", err)
	}

	if len(apps.Apps) != 1 {
		t.Fatalf("len(Apps) = %d, want 1", len(apps.Apps))
	}

	app := apps.Apps[0]
	if app.ID != smbID {
		t.Errorf("app ID = %q, want %s", app.ID, smbID)
	}

	// Check that URL is exactly "" (empty string).
	if app.URL != "" {
		t.Errorf("URL = %q, want empty string", app.URL)
	}

	// Check that a user NOT in the population does not see the app.
	apps, err = f.h.MyApps(ctx, "bob")
	if err != nil {
		t.Fatalf("MyApps for bob: %v", err)
	}

	if len(apps.Apps) != 0 {
		t.Errorf("bob sees %d apps, want 0", len(apps.Apps))
	}
}

func TestRouterlessAccessRoleNeverEnforced(t *testing.T) {
	// Regression test for F49: AccessRoleEnforced is false for router-less
	// (method custom) instances. No change to accessrole.go is needed; this
	// test just confirms the invariant.
	f := routerlessFixture(t)

	tm := f.h.Template(smbID)
	if tm == nil {
		t.Fatal("smbfixture template not found")
	}
	if !tm.Manifest.Routerless() {
		t.Fatal("SMB fixture is not router-less")
	}

	// AccessRoleEnforced should be false for custom method.
	if tm.Manifest.AccessRoleEnforced() {
		t.Error("AccessRoleEnforced() = true for router-less custom instance")
	}
}
