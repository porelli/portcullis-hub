package hub

import (
	"github.com/portcullis/hub/internal/directory"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// otherOwnPort moves template other off grafana's default port (both can
// run).
func otherOwnPort(t *testing.T, f *fixture) {
	t.Helper()
	writeFile(t, filepath.Join(f.src, "other", "manifest.yaml"), strings.ReplaceAll(otherManifest, "3300", "3500"))
	f.h.Discover()
}

// Enabling creates the instance's missing derived groups as the enabling
// admin (instancegroups.go); the Apps banner lists / creates missing ones.

func TestEnableAsCreatesMissingDefaultGroups(t *testing.T) {
	f := newFixture(t)
	g := &fakeGroups{}
	f.h.SetGroups(g)
	res, err := f.h.EnableAs("grafana", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if !f.h.IsEnabled("grafana") {
		t.Fatal("not enabled")
	}
	if got := strings.Join(g.Calls(), ","); got != "+users_grafana:alice,+admin_grafana:alice" {
		t.Errorf("groups = %s", got)
	}
	if strings.Join(res.GroupsCreated, ",") != "users_grafana,admin_grafana" || len(res.Warnings) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestEnableAsKeepsExistingGroups(t *testing.T) {
	f := newFixture(t)
	g := &fakeGroups{existing: map[string]bool{"users_grafana": true}}
	f.h.SetGroups(g)
	res, err := f.h.EnableAs("grafana", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(g.Calls(), ","); got != "+admin_grafana:alice" {
		t.Errorf("groups = %s", got)
	}
	if strings.Join(res.GroupsCreated, ",") != "admin_grafana" {
		t.Errorf("result = %+v", res)
	}
	// Enabled already, all there: nothing.
	if res, err := f.h.EnableAs("grafana", directory.Human("alice")); err != nil || len(res.GroupsCreated)+len(res.Warnings) != 0 || len(g.Calls()) != 1 {
		t.Errorf("again: %+v %v %v", res, err, g.Calls())
	}
}

func TestEnableAsInstanceGroups(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	g := &fakeGroups{}
	f.h.SetGroups(g)
	if _, err := f.h.EnableAs("grafana-b", directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(g.Calls(), ","); got != "+users_grafana-b:alice,+admin_grafana-b:alice" {
		t.Errorf("groups = %s", got)
	}
	if !f.h.IsEnabled("grafana-b") {
		t.Error("not enabled")
	}
}

func TestEnableAsActorRefused(t *testing.T) {
	f := newFixture(t)
	g := &fakeGroups{actorErr: errors.New("not an administrator")}
	f.h.SetGroups(g)
	if _, err := f.h.EnableAs("grafana", directory.Human("dana")); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	if f.h.IsEnabled("grafana") || len(g.Calls()) != 0 {
		t.Errorf("enabled=%v calls=%v", f.h.IsEnabled("grafana"), g.Calls())
	}
}

func TestEnableAsGroupFailureNotEnabled(t *testing.T) {
	f := newFixture(t)
	g := &fakeGroups{createErr: func(name string) error {
		if strings.HasPrefix(name, "admin_") {
			return errors.New("lldap down")
		}
		return nil
	}}
	f.h.SetGroups(g)
	res, err := f.h.EnableAs("grafana", directory.Human("alice"))
	if err == nil || !strings.Contains(err.Error(), "admin_grafana") {
		t.Fatalf("err = %v", err)
	}
	if f.h.IsEnabled("grafana") {
		t.Error("enabled after a group failure")
	}
	if strings.Join(res.GroupsCreated, ",") != "users_grafana" {
		t.Errorf("result = %+v", res)
	}
}

// No actor, no users & groups, or the check failing: enabled with a
// warning, nothing created (missing groups only deny: fail closed).
func TestEnableAsWarnings(t *testing.T) {
	f := newFixture(t)
	otherOwnPort(t, f)
	g := &fakeGroups{}
	f.h.SetGroups(g)
	res, err := f.h.EnableAs("grafana", directory.Human(""))
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "no signed-in user") || len(g.Calls()) != 0 || !f.h.IsEnabled("grafana") {
		t.Errorf("no actor: %+v %v %v", res, err, g.Calls())
	}
	g.missingErr = errors.New("lldap down")
	res, err = f.h.EnableAs("other", directory.Human("alice"))
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "Create missing groups") || len(g.Calls()) != 0 {
		t.Errorf("check failing: %+v %v %v", res, err, g.Calls())
	}

	f2 := newFixture(t)
	res, err = f2.h.EnableAs("grafana", directory.Human("alice"))
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "not available") {
		t.Errorf("no users & groups: %+v %v", res, err)
	}
}

// A manifest group that isn't the derived name is never created.
func TestEnableAsSharedGroupOnlyWarned(t *testing.T) {
	f := newFixture(t)
	m := strings.ReplaceAll(grafanaManifest, "users_grafana", "users_media")
	m = strings.ReplaceAll(m, "admin_grafana", "admin_media")
	m = strings.ReplaceAll(m, "3300", "3400")
	writeFile(t, filepath.Join(f.src, "shared", "manifest.yaml"), m)
	writeFile(t, filepath.Join(f.src, "shared", "compose.yml"), strings.ReplaceAll(grafanaCompose, "grafana", "shared"))
	f.h.Discover()
	if f.h.Template("shared") == nil {
		t.Fatal("template shared not discovered")
	}
	g := &fakeGroups{}
	f.h.SetGroups(g)
	res, err := f.h.EnableAs("shared", directory.Human("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Calls()) != 0 || len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "users_media is missing") {
		t.Errorf("result = %+v calls=%v", res, g.Calls())
	}
	rep := f.h.MissingGroups(context.Background())
	if len(rep.Instances) != 1 || rep.Instances[0].Instance != "shared" || len(rep.Instances[0].Creatable) != 0 || strings.Join(rep.Instances[0].Other, ",") != "users_media,admin_media" {
		t.Errorf("report = %+v", rep)
	}
}

func TestMissingGroupsCreate(t *testing.T) {
	f := newFixture(t)
	otherOwnPort(t, f)
	g := &fakeGroups{existing: map[string]bool{"users_grafana": true, "admin_grafana": true, "users_other": true}}
	f.h.SetGroups(g)
	for _, id := range []string{"grafana", "other"} {
		if _, err := f.h.EnableAs(id, directory.Human("alice")); err != nil {
			t.Fatal(err)
		}
	}
	if rep := f.h.MissingGroups(context.Background()); len(rep.Instances) != 0 || rep.Error != "" {
		t.Errorf("nothing missing: %+v", rep)
	}
	// Deleted directly in LLDAP.
	g.mu.Lock()
	delete(g.existing, "users_grafana")
	delete(g.existing, "users_other")
	g.mu.Unlock()
	rep := f.h.MissingGroups(context.Background())
	if len(rep.Instances) != 2 || rep.Instances[0].Instance != "grafana" || strings.Join(rep.Instances[0].Creatable, ",") != "users_grafana" || rep.Instances[1].Instance != "other" {
		t.Fatalf("report = %+v", rep)
	}
	// The actor must resolve: nothing created.
	g.actorErr = errors.New("not an administrator")
	if _, err := f.h.CreateMissingGroups(context.Background(), nil, directory.Human("dana")); err == nil || len(g.Calls()) != 0 {
		t.Errorf("actor: %v %v", err, g.Calls())
	}
	g.actorErr = nil
	if _, err := f.h.CreateMissingGroups(context.Background(), nil, ""); err == nil {
		t.Error("no actor accepted")
	}
	// One instance, then all.
	res, err := f.h.CreateMissingGroups(ctx, ids, directory.Human("alice"))
	if err != nil || len(res) != 1 || strings.Join(res[0].Created, ",") != "users_other" {
		t.Fatalf("other: %+v %v", res, err)
	}
	res, err = f.h.CreateMissingGroups(context.Background(), nil, directory.Human("alice"))
	if err != nil || len(res) != 2 || strings.Join(res[0].Created, ",") != "users_grafana" || len(res[1].Created) != 0 {
		t.Fatalf("all: %+v %v", res, err)
	}
	if got := strings.Join(g.Calls(), ","); got != "+users_other:alice,+users_grafana:alice" {
		t.Errorf("calls = %s", got)
	}
	if rep := f.h.MissingGroups(context.Background()); len(rep.Instances) != 0 {
		t.Errorf("still missing: %+v", rep)
	}
	// Not enabled: refused per instance.
	if res, _ := f.h.CreateMissingGroups(ctx, ids, directory.Human("alice")); len(res) != 1 || res[0].Error == "" {
		t.Errorf("unknown: %+v", res)
	}
}
