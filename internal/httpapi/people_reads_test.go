package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// auditFixture appends entries for groups eng / ops / engineering and the
// people dave / davey, oldest first.
func auditFixture(t *testing.T, l *directory.AuditLog) {
	t.Helper()
	at := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	for i, e := range []directory.AuditEntry{
		{Action: "group.rule", Target: "eng", Detail: `rule: dept = "Eng"`},
		{Action: "group.exception", Target: "eng", Detail: "add user=dave include=true until=never reason=helps"},
		{Action: "group.sync", Target: "eng:dave", Detail: "+ rule"},
		{Action: "group.rule", Target: "engineering"},
		{Action: "group.add_member", Target: "ops:dave"},
		{Action: "user.update", Target: "DAVE"},
		{Action: "group.exception", Target: "ops", Detail: "remove user=dave"},
		{Action: "group.exception", Target: "ops", Detail: "remove user=davey"},
		{Action: "group.exception", Target: "ops", Detail: "remove xuser=dave"},
		{Action: "group.add_member", Target: "eng:dave", Via: directory.ViaAI, Client: "portcullis-ai-claude"},
	} {
		e.Time, e.Actor, e.Result = at.Add(time.Duration(i)*time.Minute), "root", "ok"
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
}

func auditKeys(t *testing.T, body string) string {
	t.Helper()
	var es []directory.AuditEntry
	if err := json.Unmarshal([]byte(body), &es); err != nil {
		t.Fatalf("answer %s: %v", body, err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Action+"@"+e.Target)
	}
	return strings.Join(out, " ")
}

// TestAuditGroupFilter: ?group=<g> keeps the entries whose target is g or
// starts with "g:" (group.rule, group.exception, group.sync's <g>:<id>),
// never another group's (engineering is no substring match); it combines
// with via; malformed names are 400; non-admins (delegates too) get 403.
func TestAuditGroupFilter(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t) // bob, carl, rule group eng (these are audited too)
	l := &directory.AuditLog{Path: e.s.Directory.Audit.Path}
	auditFixture(t, l)
	for _, srv := range []*httptest.Server{e.hub, e.people} {
		got := auditKeys(t, mustDo(t, srv, "root", "GET", "/api/directory/audit?group=eng", "", 200))
		want := "group.add_member@eng:dave group.sync@eng:dave group.exception@eng group.rule@eng"
		if !strings.HasPrefix(got, want) {
			t.Errorf("group=eng = %s, want it to start with %s", got, want)
		}
		if strings.Contains(got, "engineering") || strings.Contains(got, "ops") {
			t.Errorf("group=eng has another group's entries: %s", got)
		}
		if got := auditKeys(t, mustDo(t, srv, "root", "GET", "/api/directory/audit?via=ai&group=eng", "", 200)); got != "group.add_member@eng:dave" {
			t.Errorf("via=ai&group=eng = %s", got)
		}
		if got := auditKeys(t, mustDo(t, srv, "root", "GET", "/api/directory/audit?group=ops", "", 200)); got != "group.exception@ops group.exception@ops group.exception@ops group.add_member@ops:dave" {
			t.Errorf("group=ops = %s", got)
		}
		for _, q := range []string{"?group=", "?group=bad%20name", "?group=-x", "?via=ai&group=a/b"} {
			mustDo(t, srv, "root", "GET", "/api/directory/audit"+q, "", 400)
		}
	}
	// Delegates and everyone else: 403, filtered or not.
	e.ll.AddGroup("helpers", "carl")
	mustDo(t, e.people, "root", "PUT", "/api/directory/permissions/edit_details", `{"group":"helpers"}`, 200)
	mustDo(t, e.people, "bob", "GET", "/api/directory/audit?group=eng", "", 403)
	mustDo(t, e.people, "carl", "GET", "/api/directory/audit?user=carl", "", 403)
}

// TestAuditUserFilter: ?user=<u> keeps target u, <group>:<u> and a detail
// token user=<u> (followed by a space or the end), lowercased; never
// davey's or xuser=; combines with via and group.
func TestAuditUserFilter(t *testing.T) {
	e := newPeopleEnv(t)
	auditFixture(t, e.s.Directory.Audit)
	got := auditKeys(t, mustDo(t, e.hub, "root", "GET", "/api/directory/audit?user=Dave", "", 200))
	want := "group.add_member@eng:dave group.exception@ops user.update@DAVE group.add_member@ops:dave group.sync@eng:dave group.exception@eng"
	if got != want {
		t.Errorf("user=Dave = %s\nwant %s", got, want)
	}
	if got := auditKeys(t, mustDo(t, e.people, "root", "GET", "/api/directory/audit?user=davey", "", 200)); got != "group.exception@ops" {
		t.Errorf("user=davey = %s", got)
	}
	if got := auditKeys(t, mustDo(t, e.hub, "root", "GET", "/api/directory/audit?user=dave&via=ai", "", 200)); got != "group.add_member@eng:dave" {
		t.Errorf("user=dave&via=ai = %s", got)
	}
	if got := auditKeys(t, mustDo(t, e.hub, "root", "GET", "/api/directory/audit?user=dave&group=ops", "", 200)); got != "group.exception@ops group.add_member@ops:dave" {
		t.Errorf("user=dave&group=ops = %s", got)
	}
	for _, q := range []string{"?user=", "?user=a%20b", "?user=-x", "?user=dave&via=human"} {
		mustDo(t, e.hub, "root", "GET", "/api/directory/audit"+q, "", 400)
	}
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	mustDo(t, e.people, "bob", "GET", "/api/directory/audit?user=bob", "", 403)
}

// readsEnv: myAppsEnv (vault: storage_quota default 10GiB, office_milan
// 1TiB; bob in users_vault and office_milan) plus notes (access group
// users_notes, no options: bob has access but no values), dana a
// delegate (helpers holds edit_details), bob's users_vault membership
// ending in 2099.
func readsEnv(t *testing.T) *setEnv {
	t.Helper()
	e := newSetEnvWith(t, map[string][2]string{"notes": {
		"name: Notes\ncategory: tools\nai: {unsupported: test fixture}\nauth:\n  method: forward-auth\n  group_access: true\n  access_group: users_notes\n",
		"services:\n  web:\n    image: x\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.notes.rule: Host(`notes.${PORTCULLIS_DOMAIN}`)\n      traefik.http.routers.notes.middlewares: portcullis-auth@docker,portcullis-groups@docker\n",
	}})
	e.ll.AddGroup("users_notes", "bob")
	opOK(t, e.hub, "POST", "/api/templates/enable", `{"id":"vault"}`)
	opOK(t, e.hub, "POST", "/api/templates/enable", `{"id":"notes"}`)
	if code, b := e.do(t, "root", "PUT", "/api/instances/vault/settings", `{"person":{"storage_quota":{"default":"10GiB","rows":[{"group":"office_milan","value":"1TiB"}]}}}`); code != 200 {
		t.Fatalf("save = %d %s", code, b)
	}
	e.s.Hub.Wait()
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/edit_details", `{"group":"helpers"}`, 200)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/groups/users_vault/members/bob/expiry", `{"until":"2099-01-02T03:04:05Z"}`, 200)
	return e
}

// TestPersonAppsRoute: an admin gets bob's apps (via his granting groups,
// each with its end; an app with no value listed too) and his values with
// from; delegates and everyone else 403; unknown 404; malformed 400; the
// directory down 503; no Hub 503.
func TestPersonAppsRoute(t *testing.T) {
	e := readsEnv(t)
	for _, srv := range []*httptest.Server{e.hub, e.ppl} {
		b := mustDo(t, srv, "root", "GET", "/api/directory/users/BOB/apps", "", 200)
		var v hub.PersonAppsView
		if err := json.Unmarshal([]byte(b), &v); err != nil {
			t.Fatalf("answer %s: %v", b, err)
		}
		if len(v.Apps) != 2 || v.Apps[0].Instance != "notes" || v.Apps[1].Instance != "vault" {
			t.Fatalf("apps = %s", b)
		}
		notes, vault := v.Apps[0], v.Apps[1]
		if len(notes.Via) != 1 || notes.Via[0].Group != "users_notes" || notes.Via[0].Until != nil || notes.Until != nil {
			t.Errorf("notes = %+v", notes)
		}
		end := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
		if len(vault.Via) != 1 || vault.Via[0].Group != "users_vault" || vault.Via[0].Until == nil || !vault.Via[0].Until.Equal(end) || vault.Until == nil || !vault.Until.Equal(end) || vault.Name != "Vault" {
			t.Errorf("vault = %+v", vault)
		}
		if len(v.Values) != 1 || v.Values[0] != (hub.PersonValue{Instance: "vault", App: "Vault", Key: "storage_quota", Label: "Storage quota", Value: "1 TiB", From: "office_milan"}) {
			t.Errorf("values = %+v", v.Values)
		}
		// root: the default.
		b = mustDo(t, srv, "root", "GET", "/api/directory/users/root/apps", "", 200)
		if !strings.Contains(b, `"value":"10 GiB","from":"default"`) {
			t.Errorf("root's apps = %s", b)
		}
		// dana: no apps, empty lists (never null).
		if b := strings.TrimSpace(mustDo(t, srv, "root", "GET", "/api/directory/users/dana/apps", "", 200)); b != `{"apps":[],"values":[]}` {
			t.Errorf("dana's apps = %s", b)
		}
		mustDo(t, srv, "root", "GET", "/api/directory/users/nobody/apps", "", 404)
		mustDo(t, srv, "root", "GET", "/api/directory/users/-bad/apps", "", 400)
	}
	// A delegate (dana holds edit_details) and anyone else: 403.
	mustDo(t, e.ppl, "dana", "GET", "/api/directory/users/bob/apps", "", 403)
	mustDo(t, e.ppl, "bob", "GET", "/api/directory/users/bob/apps", "", 403)
	mustDo(t, e.hub, "dana", "GET", "/api/directory/users/bob/apps", "", 403)
	// No Hub: 503.
	noHub := &Server{Directory: e.s.Directory}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/directory/users/bob/apps", nil)
	req.Header.Set("X-Forwarded-User", "root")
	req.SetPathValue("username", "bob")
	noHub.handlePersonApps(rr, req)
	if rr.Code != 503 {
		t.Errorf("no Hub = %d %s", rr.Code, rr.Body)
	}
	// Without Users & Groups: 503.
	if r, _ := doAs(t, e.noDir, "root", "GET", "/api/directory/users/bob/apps", ""); r.StatusCode != 503 {
		t.Errorf("no directory = %d", r.StatusCode)
	}
	// The directory down: 503 on both listeners.
	e.ll.HTTP.Close()
	for _, srv := range []*httptest.Server{e.hub, e.ppl} {
		if r, b := doAs(t, srv, "root", "GET", "/api/directory/users/bob/apps", ""); r.StatusCode != 503 {
			t.Errorf("directory down = %d %s", r.StatusCode, b)
		}
	}
	var se *hub.StatusError
	if _, err := e.s.Hub.PersonApps(context.Background(), "bob"); !errors.As(err, &se) || se.Status != 503 {
		t.Errorf("PersonApps with the directory down = %v", err)
	}
}

// TestGroupUsesRoute: the access / admin group's apps, office_milan's
// settings row (exactly what PurgeGroupSettings drops for it), helpers'
// permission; delegates and everyone else 403; unknown 404; malformed
// 400.
func TestGroupUsesRoute(t *testing.T) {
	e := readsEnv(t)
	uses := func(srv *httptest.Server, g string) hub.GroupUsesView {
		t.Helper()
		var v hub.GroupUsesView
		b := mustDo(t, srv, "root", "GET", "/api/directory/groups/"+g+"/uses", "", 200)
		if err := json.Unmarshal([]byte(b), &v); err != nil || v.Apps == nil || v.Settings == nil || v.Permissions == nil {
			t.Fatalf("%s uses = %s (%v)", g, b, err)
		}
		return v
	}
	for _, srv := range []*httptest.Server{e.hub, e.ppl} {
		if v := uses(srv, "users_vault"); len(v.Apps) != 1 || v.Apps[0] != (hub.GroupApp{Instance: "vault", Name: "Vault", Role: "access"}) || len(v.Settings) != 0 || len(v.Permissions) != 0 {
			t.Errorf("users_vault = %+v", v)
		}
		if v := uses(srv, "admin_vault"); len(v.Apps) != 1 || v.Apps[0].Role != "admin" {
			t.Errorf("admin_vault = %+v", v)
		}
		if v := uses(srv, "helpers"); len(v.Apps) != 0 || len(v.Settings) != 0 || strings.Join(v.Permissions, ",") != "edit_details" {
			t.Errorf("helpers = %+v", v)
		}
		v := uses(srv, "office_milan")
		want := hub.GroupSetting{Instance: "vault", App: "Vault", Key: "storage_quota", Label: "Storage quota", Scope: "person", Value: "1 TiB"}
		if len(v.Apps) != 0 || len(v.Settings) != 1 || v.Settings[0] != want || len(v.Permissions) != 0 {
			t.Errorf("office_milan = %+v", v)
		}
		mustDo(t, srv, "root", "GET", "/api/directory/groups/nosuch/uses", "", 404)
		mustDo(t, srv, "root", "GET", "/api/directory/groups/-bad/uses", "", 400)
		// Case matters: OFFICE_MILAN is no LLDAP group.
		mustDo(t, srv, "root", "GET", "/api/directory/groups/OFFICE_MILAN/uses", "", 404)
	}
	mustDo(t, e.ppl, "dana", "GET", "/api/directory/groups/helpers/uses", "", 403)
	mustDo(t, e.ppl, "bob", "GET", "/api/directory/groups/office_milan/uses", "", 403)
	mustDo(t, e.hub, "dana", "GET", "/api/directory/groups/helpers/uses", "", 403)
	// What it lists is what PurgeGroupSettings drops.
	listed := uses(e.hub, "office_milan").Settings
	m, err := e.s.Directory.Membership(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	id := m.Groups["office_milan"].ID
	e.s.Hub.PurgeGroupSettings(context.Background(), directory.Human("root"), "office_milan", id)
	purges := 0
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "settings.purge" && strings.Contains(a.Detail, "group=office_milan") {
			purges++
			if a.Target != listed[0].Instance+"/"+listed[0].Key {
				t.Errorf("purged %s, listed %+v", a.Target, listed)
			}
		}
	}
	if purges != len(listed) {
		t.Errorf("purged %d rows, listed %d", purges, len(listed))
	}
	if v := uses(e.hub, "office_milan"); len(v.Settings) != 0 {
		t.Errorf("after the purge = %+v", v)
	}
}
