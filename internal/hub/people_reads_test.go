package hub

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// TestGroupUsesMatchesPurge: GroupUses lists exactly the rows and records
// PurgeGroupSettings drops — the exact name, another case only when bound
// to the group's id — and the privileged use (App.PrivilegedGroups).
func TestGroupUsesMatchesPurge(t *testing.T) {
	f, audit, people := privFixture(t)
	if _, err := f.h.EnableAs("privapp", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{
		"role": {Default: raw("user"), Rows: rows("office_milan", "admin")},
		"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro")},
	}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	id := people.id("office_milan")
	f.h.mu.Lock()
	s := f.h.st.Settings["privapp"]
	s.Groups = map[string][]state.GroupValue{"libraries": {
		{Group: "OFFICE_MILAN", GroupID: id, Value: []any{"/a"}},       // another case, same id: named
		{Group: "Office_Milan", GroupID: id + 999, Value: []any{"/b"}}, // another case, another id: not
		{Group: "office_rome", GroupID: id + 1, Value: []any{"/c"}},
	}}
	f.h.st.Settings["privapp"] = s
	f.h.mu.Unlock()

	v, err := f.h.GroupUses(context.Background(), "office_milan")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Apps) != 1 || v.Apps[0].Role != "privileged" || v.Apps[0].Instance != "privapp" {
		t.Errorf("apps = %+v", v.Apps)
	}
	var listed []string
	for _, r := range v.Settings {
		listed = append(listed, r.Instance+"/"+r.Key+" "+r.Scope+" "+r.Value)
	}
	slices.Sort(listed)
	if want := "privapp/libraries group /a|privapp/role person Administrator|privapp/tier person Pro"; strings.Join(listed, "|") != want {
		t.Errorf("settings = %q\nwant %q", strings.Join(listed, "|"), want)
	}
	if v.Permissions == nil || len(v.Permissions) != 0 {
		t.Errorf("permissions = %#v", v.Permissions)
	}
	// Admin and access groups.
	if v, _ := f.h.GroupUses(context.Background(), "admin_privapp"); len(v.Apps) < 1 || v.Apps[0].Role != "admin" {
		t.Errorf("admin_privapp = %+v", v)
	}
	if v, _ := f.h.GroupUses(context.Background(), "users_privapp"); len(v.Apps) != 1 || v.Apps[0].Role != "access" {
		t.Errorf("users_privapp = %+v", v)
	}
	if _, err := f.h.GroupUses(context.Background(), "nosuch"); statusOf(err) != 404 {
		t.Errorf("unknown = %v", err)
	}
	if _, err := f.h.GroupUses(context.Background(), "bad name"); statusOf(err) != 400 {
		t.Errorf("malformed = %v", err)
	}

	// The purge drops exactly those.
	before := len(auditsOf(audit, "settings.purge"))
	f.h.PurgeGroupSettings(context.Background(), directory.Human("root"), "office_milan", id)
	var purged []string
	for _, a := range auditsOf(audit, "settings.purge")[before:] {
		purged = append(purged, a.Target)
	}
	slices.Sort(purged)
	if want := "privapp/libraries privapp/role privapp/tier"; strings.Join(purged, " ") != want {
		t.Errorf("purged %v, want %s", purged, want)
	}
	if recs := storedSettings(f, "privapp").Groups["libraries"]; len(recs) != 2 {
		t.Errorf("records left = %+v", recs)
	}
	if v, _ := f.h.GroupUses(context.Background(), "office_milan"); len(v.Settings) != 0 || len(v.Apps) != 0 {
		t.Errorf("after the purge = %+v", v)
	}
}

// TestPersonAppsDirectoryDown: any directory failure (502 unreachable
// too) is 503; an unknown person 404.
func TestPersonAppsDirectoryDown(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.EnableAs("privapp", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	v, err := f.h.PersonApps(context.Background(), "Alice")
	if err != nil || len(v.Apps) != 1 || v.Apps[0].Via[0].Group != "users_privapp" {
		t.Fatalf("alice = %+v %v", v, err)
	}
	if _, err := f.h.PersonApps(context.Background(), "zed"); statusOf(err) != 404 {
		t.Errorf("unknown = %v", err)
	}
	people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 502, Msg: "LLDAP unreachable"} })
	if _, err := f.h.PersonApps(context.Background(), "alice"); statusOf(err) != 503 {
		t.Errorf("unreachable = %v", err)
	}
	if _, err := f.h.GroupUses(context.Background(), "office_milan"); statusOf(err) != 503 {
		t.Errorf("GroupUses unreachable = %v", err)
	}
}

// accessEnd: no end when some group has none, else the latest.
func TestAccessEnd(t *testing.T) {
	a, b := time.Unix(100, 0), time.Unix(200, 0)
	if accessEnd(nil) != nil || accessEnd([]PersonVia{{Until: &a}, {}}) != nil {
		t.Error("an endless membership ends")
	}
	if e := accessEnd([]PersonVia{{Until: &b}, {Until: &a}}); e == nil || !e.Equal(b) {
		t.Errorf("end = %v", e)
	}
}
