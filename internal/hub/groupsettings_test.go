package hub

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// privFixture loads testdata/settings/privapp (native-oidc, access and
// admin groups; role: privileged person enum with an {{ADMIN_GROUP}}
// row; tier: person enum; libraries: group-scope list, file + env;
// motd, banner: instance strings) with a fake directory: alice and bob
// in users_privapp and office_milan, carol in users_privapp (expired),
// dave only in admin_privapp, erin in no group.
func privFixture(t *testing.T) (*fixture, *fakeAudit, *fakePeople) {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", "privapp", "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", "privapp", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"privapp": {string(m), string(c)}})
	if f.h.Template("privapp") == nil {
		t.Fatalf("privapp fixture not loaded (see the log)")
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	people := newFakePeople("erin")
	people.addGroup("users_privapp", "alice", "bob", "carol")
	people.addGroup("admin_privapp", "dave")
	people.addGroup("office_milan", "alice", "bob")
	people.set(func(p *fakePeople) { p.expired["carol"] = map[string]bool{"users_privapp": true} })
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_privapp": true, "admin_privapp": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	return f, audit, people
}

// raw marshals v as a JSON value.
func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func rows(kv ...any) []GroupValueInput {
	var out []GroupValueInput
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, GroupValueInput{Group: kv[i].(string), Value: raw(kv[i+1])})
	}
	return out
}

func storedSettings(f *fixture, id string) state.InstanceSettings {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	return f.h.st.Settings[id].Clone()
}

// resolved is user → key → resolved value of instance id now.
func resolved(t *testing.T, f *fixture, people *fakePeople, id string) map[string]map[string]settings.Resolved {
	t.Helper()
	m, err := people.Membership(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	tmpl := f.h.findLocked(id)
	if tmpl == nil {
		t.Fatalf("no instance %s", id)
	}
	return f.h.resolvePeopleLocked(tmpl, m)
}

func auditsOf(a *fakeAudit, action string) []directory.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []directory.AuditEntry
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func usersOf(p Population) []string {
	var out []string
	for _, x := range p.People {
		out = append(out, x.User)
	}
	return out
}

func TestPopulationRules(t *testing.T) {
	f, _, people := privFixture(t)
	m, err := people.Membership(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	base := *f.h.Template("privapp")
	variant := func(id string, fn func(a *templates.Auth)) *templates.Template {
		v := base
		v.ID, v.TemplateID = id, id
		fn(&v.Manifest.Auth)
		return &v
	}
	f.h.mu.Lock()
	f.h.st.SignIn["nat"] = state.SignInNative
	f.h.mu.Unlock()
	cases := []struct {
		name string
		t    *templates.Template
		want []string
		why  bool
	}{
		// Group access on: users_privapp minus carol (expired); dave
		// (admin_privapp only) and erin get nothing.
		{"group access", &base, []string{"alice", "bob"}, false},
		// The access role enforced (native-oidc, group_access false).
		{"access role", variant("privapp", func(a *templates.Auth) { a.GroupAccess = false }), []string{"alice", "bob"}, false},
		// No access group: every user but the service account.
		{"open", variant("privapp", func(a *templates.Auth) {
			a.Method, a.GroupAccess, a.AccessGroup = "header-auth", false, ""
		}), []string{"admin", "alice", "bob", "carol", "dave", "erin"}, false},
		// sign_in native: nobody, with the reason.
		{"native sign-in", variant("nat", func(a *templates.Auth) {
			a.Method, a.GroupAccess = "custom", true
			a.NativeLogin = &templates.NativeLogin{Supported: true, AllowWithoutGateway: true}
		}), nil, true},
		// Identity-less routes: custom without native_login, public.
		{"custom", variant("privapp", func(a *templates.Auth) { a.Method, a.NativeLogin = "custom", nil }), nil, true},
		{"public", variant("privapp", func(a *templates.Auth) { a.Method = "public" }), nil, true},
	}
	for _, c := range cases {
		f.h.mu.RLock()
		p := f.h.populationLocked(c.t, m)
		f.h.mu.RUnlock()
		if got := usersOf(p); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: population = %v, want %v (why %q)", c.name, got, c.want, p.Why)
		}
		if (p.Why != "") != c.why {
			t.Errorf("%s: why = %q", c.name, p.Why)
		}
	}
	f.h.mu.RLock()
	p := f.h.populationLocked(cases[2].t, m)
	f.h.mu.RUnlock()
	if !strings.Contains(fmtWhy(f, cases[3].t, m), "per-person values need Portcullis sign-in") {
		t.Errorf("native why = %q", fmtWhy(f, cases[3].t, m))
	}
	for _, x := range p.People {
		if x.User == "carol" {
			if _, ok := x.Groups["users_privapp"]; ok {
				t.Errorf("carol's expired membership still counts: %+v", x.Groups)
			}
		}
	}
	if ok, err := f.h.InPopulation(context.Background(), "privapp", "Alice"); err != nil || !ok {
		t.Errorf("InPopulation alice = %v %v", ok, err)
	}
	if ok, err := f.h.InPopulation(context.Background(), "privapp", "dave"); err != nil || ok {
		t.Errorf("InPopulation dave = %v %v", ok, err)
	}
}

func fmtWhy(f *fixture, t *templates.Template, m *directory.Membership) string {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	return f.h.populationLocked(t, m).Why
}

func TestSavePersonRows(t *testing.T) {
	f, audit, people := privFixture(t)
	milan := people.id("office_milan")
	_, err := f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{
		"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro")},
	}}, "root")
	if err != nil {
		t.Fatal(err)
	}
	s := storedSettings(f, "privapp")
	if got := s.Person["tier"].Rows; len(got) != 1 || got[0].GroupID != milan || got[0].Group != "office_milan" || got[0].Value != "pro" {
		t.Errorf("rows = %+v (office_milan id %d)", got, milan)
	}
	var found bool
	for _, e := range auditsOf(audit, "settings.change") {
		if e.Target == "privapp/tier" && strings.Contains(e.Detail, "group=office_milan") && e.Actor == "root" {
			found = true
		}
	}
	if !found {
		t.Errorf("no row audit: %+v", auditsOf(audit, "settings.change"))
	}
	if r := resolved(t, f, people, "privapp"); r["alice"]["tier"].Value != "pro" || r["carol"]["tier"].Value != nil {
		t.Errorf("resolved = %+v", r)
	}

	for name, u := range map[string]SettingsUpdate{
		"unknown group":   {Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("ghost", "pro")}}},
		"default parses":  {Person: map[string]PersonChange{"tier": {Default: raw("gold")}}},
		"no default":      {Person: map[string]PersonChange{"tier": {Rows: rows("office_milan", "pro")}}},
		"privileged def":  {Person: map[string]PersonChange{"role": {Default: raw("admin")}}},
		"placeholder dup": {Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows(templates.PlaceholderAdminGroup, "pro", "admin_privapp", "basic")}}},
		"duplicate group": {Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro", "office_milan", "basic")}}},
	} {
		if _, err := f.h.SaveSettings("privapp", u, "root"); statusOf(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	people.set(func(p *fakePeople) {
		p.privilege["office_milan"] = "its rule uses fields delegates can edit: office_location"
	})
	_, err = f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{"role": {Default: raw("user"), Rows: rows("office_milan", "admin")}}}, "root")
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "its rule uses fields delegates can edit: office_location") {
		t.Errorf("privileged row from a steerable group = %v", err)
	}
	// The directory down: per-group saves can't bind ids (503), nothing
	// is stored.
	people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 503, Msg: "LLDAP down"} })
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("users_privapp", "pro")}}}, "root"); statusOf(err) != 503 {
		t.Errorf("directory down = %v", err)
	}
	if got := storedSettings(f, "privapp").Person["tier"].Rows; len(got) != 1 {
		t.Errorf("refused saves changed the rows: %+v", got)
	}
}

func TestPlaceholderRowsBound(t *testing.T) {
	f, _, people := privFixture(t)
	res, err := f.h.CreateInstanceAs("privapp", "privapp2", nil, "root")
	if err != nil {
		t.Fatal(err)
	}
	want := people.id("admin_privapp2")
	if want == 0 {
		t.Fatalf("admin_privapp2 not created (warnings %v)", res.Warnings)
	}
	r := storedSettings(f, "privapp2").Person["role"].Rows
	if len(r) != 1 || r[0].Group != templates.PlaceholderAdminGroup || r[0].GroupID != want {
		t.Errorf("rows = %+v, want {{ADMIN_GROUP}} bound to %d", r, want)
	}
	f.h.mu.RLock()
	pc := f.h.personConfigLocked(f.h.findLocked("privapp2"), "role")
	f.h.mu.RUnlock()
	if len(pc.Rows) != 1 || pc.Rows[0].Group != "admin_privapp2" || pc.Rows[0].GroupID != want || pc.Default != "user" {
		t.Errorf("person config = %+v", pc)
	}
	people.addGroup("admin_privapp2", "dave")
	people.addGroup("users_privapp2", "dave")
	if got := resolved(t, f, people, "privapp2")["dave"]["role"].Value; got != "admin" {
		t.Errorf("dave's role = %v", got)
	}

	// The default instance: bound by EnableAs after its groups exist.
	if _, err := f.h.EnableAs("privapp", "root"); err != nil {
		t.Fatal(err)
	}
	r = storedSettings(f, "privapp").Person["role"].Rows
	if len(r) != 1 || r[0].GroupID != people.id("admin_privapp") {
		t.Errorf("default instance rows = %+v", r)
	}
	// A missing group leaves the row unbound, with a warning.
	f.h.mu.Lock()
	s := f.h.st.Settings["privapp"]
	s.Person["role"] = state.PersonSetting{Default: "user", Rows: []state.GroupValue{{Group: templates.PlaceholderAdminGroup, Value: "admin"}}}
	f.h.st.Settings["privapp"] = s
	f.h.mu.Unlock()
	people.deleteGroup("admin_privapp")
	if w := f.h.bindPlaceholderRows(context.Background(), "privapp"); len(w) == 0 || !strings.Contains(strings.Join(w, ";"), "admin_privapp") {
		t.Errorf("warnings = %v", w)
	}
	if r := storedSettings(f, "privapp").Person["role"].Rows; r[0].GroupID != 0 {
		t.Errorf("bound to a missing group: %+v", r)
	}
}

func TestRecreatedGroupInheritsNothing(t *testing.T) {
	f, audit, people := privFixture(t)
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro")}}}, "root"); err != nil {
		t.Fatal(err)
	}
	old := people.id("office_milan")
	people.deleteGroup("office_milan")
	people.addGroup("office_milan", "alice")
	if people.id("office_milan") == old {
		t.Fatal("re-created group kept its id")
	}
	if got := resolved(t, f, people, "privapp")["alice"]["tier"]; got.Value != "basic" || got.Reason.Source != settings.ReasonDefault {
		t.Errorf("alice after re-create = %+v", got)
	}
	// Saving the same rows again (the panel resends them) never binds the
	// old value to the new group: 409 until the row is removed and added.
	_, err := f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro")}}}, "root")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "office_milan was re-created") {
		t.Errorf("stale rebind = %v", err)
	}
	if got := storedSettings(f, "privapp").Person["tier"].Rows; len(got) != 1 || got[0].GroupID != old {
		t.Errorf("refused save changed the row: %+v", got)
	}
	// Same for group records.
	f.h.mu.Lock()
	s := f.h.st.Settings["privapp"]
	s.Groups = map[string][]state.GroupValue{"libraries": {{Group: "office_milan", GroupID: old, Value: []any{"/a"}}}}
	f.h.st.Settings["privapp"] = s
	f.h.mu.Unlock()
	_, err = f.h.SaveSettings("privapp", SettingsUpdate{Groups: map[string][]GroupValueInput{"libraries": rows("office_milan", []string{"/a"})}}, "root")
	if statusOf(err) != 409 {
		t.Errorf("stale record rebind = %v", err)
	}
	// LLDAP looking wrong (the bootstrap admin gone): no purge.
	people.set(func(p *fakePeople) { delete(p.users, "admin") })
	if w := f.h.reconcileGroupRows(context.Background(), "privapp"); len(w) == 0 {
		t.Error("no warning for the skipped purge")
	}
	if got := storedSettings(f, "privapp").Person["tier"].Rows; len(got) != 1 {
		t.Errorf("purged against a wrong LLDAP: %+v", got)
	}
	people.set(func(p *fakePeople) { p.users["admin"] = true })
	f.h.reconcileGroupRows(context.Background(), "privapp")
	if got := storedSettings(f, "privapp").Person["tier"].Rows; len(got) != 0 {
		t.Errorf("row kept: %+v", got)
	}
	purges := auditsOf(audit, "settings.purge")
	if len(purges) != 2 || purges[0].Actor != "hub" || purges[0].Target != "privapp/tier" || purges[1].Target != "privapp/libraries" || !strings.Contains(purges[0].Detail, "office_milan") {
		t.Errorf("purge audit = %+v", purges)
	}
	if !slices.Contains(f.h.triggeredDeliveries(), "privapp") {
		t.Errorf("no delivery triggered: %v", f.h.triggeredDeliveries())
	}
}

// hubDirectory wires a real directory service (lldaptest) into f: as
// the Hub's People and Groups, with GroupDeleted → PurgeGroupSettings.
func hubDirectory(t *testing.T, f *fixture) (*directory.Service, *lldaptest.Server) {
	t.Helper()
	ll := lldaptest.New(t, "portcullis-hub", "service-password-0123456789")
	ll.AddUser("root", "root@example.org", "Root", "rootpass-123456", "lldap_admin")
	ll.AddUser("alice", "alice@example.org", "Alice", "")
	ll.AddGroup("users_privapp", "alice")
	ll.AddGroup("admin_privapp")
	credDir := t.TempDir()
	os.WriteFile(filepath.Join(credDir, "username"), []byte("portcullis-hub\n"), 0600)
	os.WriteFile(filepath.Join(credDir, "password"), []byte("service-password-0123456789\n"), 0600)
	dir := &directory.Service{
		LLDAP: lldap.New(ll.HTTP.URL, ll.LDAPURL(), ll.BaseDN, credDir),
		Audit: &directory.AuditLog{Path: filepath.Join(t.TempDir(), "audit.jsonl")},
		Apps:  f.h.DirectoryApps,
	}
	dir.GroupDeleted = f.h.PurgeGroupSettings
	f.h.SetPeople(dir)
	f.h.SetGroups(dir)
	return dir, ll
}

func TestPurgeOnHubDelete(t *testing.T) {
	f, audit, _ := privFixture(t)
	dir, ll := hubDirectory(t, f)
	ll.AddGroup("office_milan", "alice")
	if _, err := f.h.CreateInstanceAs("privapp", "privapp2", nil, "root"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"privapp", "privapp2"} {
		if _, err := f.h.SaveSettings(id, SettingsUpdate{
			Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro", "users_privapp", "basic")}},
			Groups: map[string][]GroupValueInput{"libraries": rows("office_milan", []string{"/milan"})},
		}, "root"); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if _, err := dir.DeleteGroup(context.Background(), &directory.Caller{User: "root", Admin: true}, "office_milan", "office_milan"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"privapp", "privapp2"} {
		s := storedSettings(f, id)
		if r := s.Person["tier"].Rows; len(r) != 1 || r[0].Group != "users_privapp" {
			t.Errorf("%s rows = %+v", id, r)
		}
		if len(s.Groups["libraries"]) != 0 {
			t.Errorf("%s records = %+v", id, s.Groups["libraries"])
		}
		if !slices.Contains(f.h.triggeredDeliveries(), id) {
			t.Errorf("%s: no delivery triggered (%v)", id, f.h.triggeredDeliveries())
		}
	}
	var n int
	for _, e := range auditsOf(audit, "settings.purge") {
		if e.Actor == "root" && strings.Contains(e.Detail, "office_milan") {
			n++
		}
	}
	if n != 4 {
		t.Errorf("purge audits = %+v", auditsOf(audit, "settings.purge"))
	}

	// P21: deleting an instance deletes its groups while its lock is
	// held; the purge they trigger must not deadlock (no inline delivery
	// or restart).
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("admin_privapp2", "pro")}}}, "root"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.h.DeleteInstance("privapp2", "privapp2", "root")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("DeleteInstance deadlocked in the group purge")
	}
	if r := storedSettings(f, "privapp").Person["tier"].Rows; len(r) != 0 {
		t.Errorf("rows naming the deleted instance's group = %+v", r)
	}
}

func TestRestoreDropsMismatchedRows(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.CreateInstanceAs("privapp", "privapp2", nil, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings("privapp2", SettingsUpdate{Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro", "users_privapp", "pro")}}}, "root"); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("privapp2", "root")
	if err != nil {
		t.Fatal(err)
	}
	people.deleteGroup("office_milan")
	people.addGroup("office_milan", "alice")
	res, err := f.h.RestoreInstance("privapp2", entry.Archive, "root")
	if err != nil {
		t.Fatal(err)
	}
	if r := storedSettings(f, "privapp2").Person["tier"].Rows; len(r) != 1 || r[0].Group != "users_privapp" {
		t.Errorf("rows after restore = %+v", r)
	}
	if !strings.Contains(strings.Join(res.Warnings, ";"), "office_milan") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	// Into a new id: the placeholder row is bound to the new id's group.
	res, err = f.h.RestoreInstanceAs(entry.Archive, "privapp3", "root")
	if err != nil {
		t.Fatal(err)
	}
	r := storedSettings(f, "privapp3").Person["role"].Rows
	if len(r) != 1 || r[0].Group != templates.PlaceholderAdminGroup || r[0].GroupID == 0 || r[0].GroupID != people.id("admin_privapp3") {
		t.Errorf("restore-as role rows = %+v (admin_privapp3 %d; warnings %v)", r, people.id("admin_privapp3"), res.Warnings)
	}
}

func TestPrivilegedAfterTemplateUpdate(t *testing.T) {
	f, audit, people := privFixture(t)
	people.set(func(p *fakePeople) {
		p.privilege["office_milan"] = "its rule uses fields delegates can edit: office_location"
	})
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{
		Values: vals("motd", "hello", "banner", "42"),
		Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro")}},
	}, "root"); err != nil {
		t.Fatal(err)
	}
	if got := resolved(t, f, people, "privapp")["alice"]["tier"].Value; got != "pro" {
		t.Fatalf("alice before = %v", got)
	}
	old := *f.h.Template("privapp")
	// The update: tier becomes privileged, motd goes, banner is an int.
	m := string(mustRead(t, filepath.Join("testdata", "settings", "privapp", "manifest.yaml")))
	m = strings.Replace(m, "    - key: tier\n      label: Tier\n      type: enum\n      scope: person\n", "    - key: tier\n      label: Tier\n      type: enum\n      scope: person\n      privileged: true\n", 1)
	m = strings.Replace(m, "    - key: motd\n      label: Message of the day\n      type: string\n      applies: restart\n      delivery: [{env: PRIVAPP_MOTD}]\n", "", 1)
	m = strings.Replace(m, "    - key: banner\n      label: Banner\n      type: string\n", "    - key: banner\n      label: Banner\n      type: int\n", 1)
	writeFile(t, filepath.Join(f.src, "privapp", "manifest.yaml"), m)
	f.h.Discover()
	nt := f.h.Template("privapp")
	if nt == nil || optionByKey(nt, "motd") != nil || !optionByKey(nt, "tier").Privileged {
		t.Fatal("update not loaded")
	}
	inc := SettingsIncompatibilities(&old, nt, storedSettings(f, "privapp"))
	joined := strings.Join(inc, "\n")
	for _, want := range []string{"motd", "banner", "tier"} {
		if !strings.Contains(joined, want) {
			t.Errorf("incompatibilities lack %s: %v", want, inc)
		}
	}
	// Discover changed nothing; resolution gives the office_milan row
	// nothing at once.
	if s := storedSettings(f, "privapp"); s.Values["motd"] != "hello" || len(s.Person["tier"].Rows) != 1 {
		t.Errorf("Discover changed settings: %+v", s)
	}
	if got := resolved(t, f, people, "privapp")["alice"]["tier"].Value; got != "basic" {
		t.Errorf("a privileged value from a steerable group still applies: %v", got)
	}
	// The retyped banner's stored value is not used either.
	f.h.mu.RLock()
	if v, ok := f.h.effectiveValue(nt, optionByKey(nt, "banner"), f.h.st.Settings["privapp"]); ok {
		t.Errorf("retyped banner = %v", v)
	}
	f.h.mu.RUnlock()
	// The sync's prune drops the removed and retyped values (audited);
	// the next reconcile drops the row with a warning.
	f.h.SyncSourcesAs(SyncAPI)
	s := storedSettings(f, "privapp")
	if _, ok := s.Values["motd"]; ok {
		t.Errorf("motd kept: %+v", s.Values)
	}
	if _, ok := s.Values["banner"]; ok {
		t.Errorf("retyped banner kept: %+v", s.Values)
	}
	var pruned []string
	for _, e := range auditsOf(audit, "settings.purge") {
		pruned = append(pruned, e.Target)
	}
	if !slices.Contains(pruned, "privapp/motd") || !slices.Contains(pruned, "privapp/banner") {
		t.Errorf("prune audits = %v", pruned)
	}
	w := f.h.reconcileGroupRows(context.Background(), "privapp")
	if !strings.Contains(strings.Join(w, ";"), "office_milan") {
		t.Errorf("warnings = %v", w)
	}
	if got := storedSettings(f, "privapp").Person["tier"].Rows; len(got) != 0 {
		t.Errorf("row kept: %+v", got)
	}
}

func TestGroupScopeRecords(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Groups: map[string][]GroupValueInput{
		"libraries": rows("users_privapp", []string{"/b", "/c"}, "office_milan", []string{"/a"}),
	}}, "root"); err != nil {
		t.Fatal(err)
	}
	got := storedSettings(f, "privapp").Groups["libraries"]
	if len(got) != 2 || got[0].Group != "users_privapp" || got[0].GroupID != people.id("users_privapp") || got[1].Group != "office_milan" || got[1].GroupID != people.id("office_milan") {
		t.Errorf("records = %+v", got)
	}
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Groups: map[string][]GroupValueInput{
		"libraries": rows("office_milan", []string{"/a"}, "office_milan", []string{"/b"}),
	}}, "root"); statusOf(err) != 400 {
		t.Errorf("duplicate group = %v", err)
	}
	env := envOf(t, f, "privapp")
	want := `PRIVAPP_LIBRARIES='[{"group":"users_privapp","value":["/b","/c"]},{"group":"office_milan","value":["/a"]}]'`
	if !strings.Contains(env, want) {
		t.Errorf("env lacks %s:\n%s", want, env)
	}
}

func TestGroupScopeNotPersonResolved(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Groups: map[string][]GroupValueInput{
		"libraries": rows("users_privapp", []string{"/b"}, "office_milan", []string{"/a"}),
	}}, "root"); err != nil {
		t.Fatal(err)
	}
	r := resolved(t, f, people, "privapp")
	if _, ok := r["alice"]["libraries"]; ok {
		t.Errorf("alice got a per-person value of a group option: %+v", r["alice"])
	}
	if _, ok := r["alice"]["tier"]; !ok {
		t.Errorf("alice lacks the person options: %+v", r["alice"])
	}
}

// triggeredDeliveries are the instances TriggerDelivery queued, sorted.
func (h *Hub) triggeredDeliveries() []string {
	h.deliveryMu.Lock()
	defer h.deliveryMu.Unlock()
	return slices.Sorted(maps.Keys(h.lastTrigger))
}

// Group records reach the env only when the directory snapshot fetched
// for the write has their group with the same id (fail closed).
func TestGroupRecordsNeedTheDirectory(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Groups: map[string][]GroupValueInput{
		"libraries": rows("users_privapp", []string{"/b"}, "office_milan", []string{"/a"}),
	}}, "root"); err != nil {
		t.Fatal(err)
	}
	// office_milan re-created straight in LLDAP; no reconcile has run.
	people.deleteGroup("office_milan")
	people.addGroup("office_milan", "alice")
	if err := f.h.save("privapp", SettingsUpdate{Values: vals("motd", "x")}); err != nil {
		t.Fatal(err)
	}
	if want := `PRIVAPP_LIBRARIES='[{"group":"users_privapp","value":["/b"]}]'`; !strings.Contains(envOf(t, f, "privapp"), want) {
		t.Errorf("env lacks %s:\n%s", want, envOf(t, f, "privapp"))
	}
	// The directory down: no group values at all, also on enable.
	people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 502, Msg: "LLDAP unreachable"} })
	if err := f.h.save("privapp", SettingsUpdate{Values: vals("motd", "y")}); err != nil {
		t.Fatal(err)
	}
	if want := `PRIVAPP_LIBRARIES='[]'`; !strings.Contains(envOf(t, f, "privapp"), want) {
		t.Errorf("env lacks %s:\n%s", want, envOf(t, f, "privapp"))
	}
	people.set(func(p *fakePeople) { p.err = nil })
	if err := f.h.save("privapp", SettingsUpdate{Values: vals("motd", "z")}); err != nil {
		t.Fatal(err)
	}
	// Its data file delivered once (a people file never delivered fails
	// a start with the directory down: P6), then disabled.
	if err := f.h.Enable("privapp"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Disable("privapp"); err != nil {
		t.Fatal(err)
	}
	people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 502, Msg: "LLDAP unreachable"} })
	if err := f.h.Enable("privapp"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if want := `PRIVAPP_LIBRARIES='[]'`; !strings.Contains(envOf(t, f, "privapp"), want) {
		t.Errorf("enable: env lacks %s:\n%s", want, envOf(t, f, "privapp"))
	}
	// h.membership keeps the directory's 502.
	if _, err := f.h.InPopulation(context.Background(), "privapp", "alice"); statusOf(err) != 502 {
		t.Errorf("unreachable = %v", err)
	}
}

// A template's starting row whose group was deleted (and purged) comes
// back, bound to the new group, when "create missing groups" or an enable
// re-creates that group; rows the admin entered never do.
func TestReseedTemplateRows(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.EnableAs("privapp", "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{Person: map[string]PersonChange{"role": {Default: raw("user"),
		Rows: rows(templates.PlaceholderAdminGroup, "admin", "office_milan", "admin")}}}, "root"); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"admin_privapp", "office_milan"} {
		id := people.id(g)
		people.deleteGroup(g)
		f.h.PurgeGroupSettings(context.Background(), "root", g, id)
	}
	f.h.groups.(*fakeGroups).set(func(g *fakeGroups) { delete(g.existing, "admin_privapp") })
	if r := storedSettings(f, "privapp").Person["role"].Rows; len(r) != 0 {
		t.Fatalf("rows after the purge = %+v", r)
	}
	people.addGroup("office_milan")
	res, err := f.h.CreateMissingGroups(context.Background(), nil, "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || !slices.Contains(res[0].Created, "admin_privapp") {
		t.Fatalf("created = %+v", res)
	}
	r := storedSettings(f, "privapp").Person["role"].Rows
	if len(r) != 1 || r[0].Group != templates.PlaceholderAdminGroup || r[0].GroupID != people.id("admin_privapp") || r[0].Value != "admin" {
		t.Errorf("rows = %+v (admin_privapp %d)", r, people.id("admin_privapp"))
	}
	// The group existing already: nothing comes back (an admin may have
	// removed the row on purpose).
	f.h.mu.Lock()
	s := f.h.st.Settings["privapp"]
	p := s.Person["role"]
	p.Rows = nil
	s.Person["role"] = p
	f.h.st.Settings["privapp"] = s
	f.h.mu.Unlock()
	if _, err := f.h.CreateMissingGroups(context.Background(), nil, "root"); err != nil {
		t.Fatal(err)
	}
	if r := storedSettings(f, "privapp").Person["role"].Rows; len(r) != 0 {
		t.Errorf("a row the admin removed came back: %+v", r)
	}
}

// The purge matches the deleted group's exact name; another case only
// for rows bound to the deleted id.
func TestPurgeMatchesExactName(t *testing.T) {
	f, _, people := privFixture(t)
	other := people.addGroup("Office_Milan", "bob")
	if _, err := f.h.SaveSettings("privapp", SettingsUpdate{
		Person: map[string]PersonChange{"tier": {Default: raw("basic"), Rows: rows("office_milan", "pro")}},
		Groups: map[string][]GroupValueInput{"libraries": rows("Office_Milan", []string{"/m"})},
	}, "root"); err != nil {
		t.Fatal(err)
	}
	id := people.id("office_milan")
	people.deleteGroup("office_milan")
	f.h.PurgeGroupSettings(context.Background(), "root", "office_milan", id)
	s := storedSettings(f, "privapp")
	if len(s.Person["tier"].Rows) != 0 {
		t.Errorf("tier rows = %+v", s.Person["tier"].Rows)
	}
	if r := s.Groups["libraries"]; len(r) != 1 || r[0].Group != "Office_Milan" || r[0].GroupID != other {
		t.Errorf("another group's record (case only) was purged: %+v", r)
	}
	f.h.PurgeGroupSettings(context.Background(), "root", "OFFICE_MILAN", other)
	if r := storedSettings(f, "privapp").Groups["libraries"]; len(r) != 0 {
		t.Errorf("same id, other case kept: %+v", r)
	}
}

// A row bound after the reconcile's snapshot was taken is never purged
// with that (older) snapshot: the race behind TestReseedTemplateRows'
// flake, made deterministic.
func TestReconcileKeepsRowsBoundAfterSnapshot(t *testing.T) {
	f, _, people := privFixture(t)
	if _, err := f.h.EnableAs("privapp", "root"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	old := people.id("admin_privapp")
	people.deleteGroup("admin_privapp")
	// The snapshot lacks admin_privapp; right after it, the group is
	// re-created and the row re-bound to the new id (as
	// CreateMissingGroups does).
	people.set(func(p *fakePeople) {
		p.onMembership = func() {
			nid := people.addGroup("admin_privapp")
			f.h.mu.Lock()
			s := f.h.st.Settings["privapp"]
			pr := s.Person["role"]
			for i := range pr.Rows {
				if pr.Rows[i].GroupID == old {
					pr.Rows[i].GroupID = nid
				}
			}
			s.Person["role"] = pr
			f.h.st.Settings["privapp"] = s
			f.h.mu.Unlock()
		}
	})
	f.h.reconcileGroupRows(context.Background(), "privapp")
	r := storedSettings(f, "privapp").Person["role"].Rows
	if len(r) != 1 || r[0].GroupID != people.id("admin_privapp") {
		t.Errorf("rows = %+v: a row bound after the snapshot was purged with it", r)
	}
	// The next run (a fresh snapshot) keeps it too: the group exists.
	f.h.reconcileGroupRows(context.Background(), "privapp")
	if r := storedSettings(f, "privapp").Person["role"].Rows; len(r) != 1 {
		t.Errorf("rows after a fresh reconcile = %+v", r)
	}
}
