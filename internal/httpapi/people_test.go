package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/policy"
)

// peopleEnv: both listeners over one Server with a directory store.
type peopleEnv struct {
	s      *Server
	hub    *httptest.Server
	people *httptest.Server
	ll     *lldaptest.Server
}

func newPeopleEnv(t *testing.T) *peopleEnv {
	t.Helper()
	s, ll, _ := newDirFixture(t, func(d *directory.Service) {
		d.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	})
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PeopleHandler()
	if err != nil {
		t.Fatal(err)
	}
	e := &peopleEnv{s: s, hub: httptest.NewServer(h), people: httptest.NewServer(p), ll: ll}
	t.Cleanup(e.hub.Close)
	t.Cleanup(e.people.Close)
	return e
}

func mustDo(t *testing.T, srv *httptest.Server, user, method, path, body string, want int) string {
	t.Helper()
	r, b := doAs(t, srv, user, method, path, body)
	if r.StatusCode != want {
		t.Fatalf("%s %s %s = %d (%s), want %d", user, method, path, r.StatusCode, strings.TrimSpace(b), want)
	}
	return b
}

// setup: fields department (list) and manager (person), bob in
// Engineering reporting to root, a group eng converted to a rule group
// and evaluated, so bob is in it by rule.
func (e *peopleEnv) setup(t *testing.T) {
	t.Helper()
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	e.ll.AddUser("carl", "carl@example.org", "Carl", "")
	e.ll.AddGroup("eng", "carl")
	p := e.people
	mustDo(t, p, "root", "POST", "/api/directory/fields", `{"name":"department","label":"Department","kind":"list","values":["Eng","Sales"]}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/fields", `{"name":"manager","label":"Manager","kind":"person","share_with_apps":false}`, 200)
	mustDo(t, p, "root", "PUT", "/api/directory/users/bob/details", `{"attrs":{"department":["Eng"],"manager":["root"]}}`, 200)
	b := mustDo(t, p, "root", "POST", "/api/directory/groups/eng/convert-preview", `{"rule":"department = \"Eng\""}`, 200)
	var prev directory.ConvertPreview
	json.Unmarshal([]byte(b), &prev)
	if strings.Join(prev.Joining, ",") != "bob" || strings.Join(prev.KeptAsException, ",") != "carl" {
		t.Fatalf("convert preview = %s", b)
	}
	body, _ := json.Marshal(map[string]interface{}{"rule": `department = "Eng"`, "keep": []string{"carl"}, "preview": prev})
	mustDo(t, p, "root", "POST", "/api/directory/groups/eng/convert", string(body), 200)
	if _, err := e.s.Directory.Evaluate(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

// peopleAppRoutes are the only app routes of the people listener
// (contract §5.1, G12): exactly nine, all caller-only — the five My apps
// and credential routes, the two confirmation routes (Task 14) and Task
// 21's two AI routes.
var peopleAppRoutes = []string{
	"GET /api/me/apps",
	"PUT /api/me/apps/{instance}/values/{key}",
	"DELETE /api/me/apps/{instance}/values/{key}",
	"POST /api/me/apps/{instance}/credentials/{key}",
	"DELETE /api/me/apps/{instance}/credentials/{key}",
	"GET /confirm/{id}",
	"POST /api/me/confirmations/{id}",
	"GET /api/me/ai",
	"DELETE /api/me/ai/connections/{client}",
}

// TestPeopleListenerHasNoAppRoutes: the people mux registers exactly the
// directory API, peopleAppRoutes, /healthz, the page and its assets —
// compared as sets of the patterns PeopleHandler registers.
func TestPeopleListenerHasNoAppRoutes(t *testing.T) {
	e := newPeopleEnv(t)
	dir := &recordingMux{ServeMux: http.NewServeMux()}
	e.s.registerDirectory(dir)
	want := map[string]bool{"/healthz": true, "/": true, "/static/": true}
	for _, p := range append(append([]string{}, dir.patterns...), peopleAppRoutes...) {
		want[p] = true
	}
	got := map[string]bool{}
	for _, p := range e.s.peopleMux().patterns {
		if got[p] {
			t.Errorf("people pattern %q registered twice", p)
		}
		got[p] = true
	}
	for p := range got {
		if !want[p] {
			t.Errorf("people listener registers %q, which is not allowed", p)
		}
	}
	for p := range want {
		if !got[p] {
			t.Errorf("people listener lacks %q", p)
		}
	}
	// The caller-only app routes: on people, never on the Hub listener.
	e.s.Hub.SetPeople(e.s.Directory)
	if r, b := doAs(t, e.people, "bob", "GET", "/api/me/apps", ""); r.StatusCode != 200 || !strings.Contains(b, `"apps":`) {
		t.Errorf("people GET /api/me/apps = %d %s", r.StatusCode, b)
	}
	if r, _ := doAs(t, e.hub, "root", "GET", "/api/me/apps", ""); r.StatusCode != 404 {
		t.Errorf("hub GET /api/me/apps = %d, want 404", r.StatusCode)
	}
	// The two AI routes are people-only (G12; the confirmation routes are
	// on both listeners: TestHubListenerConfirmRoutes).
	for _, rt := range [][2]string{{"GET", "/api/me/ai"}, {"DELETE", "/api/me/ai/connections/portcullis-ai-claude"}} {
		if r, _ := doAs(t, e.hub, "root", rt[0], rt[1], ""); r.StatusCode != 404 {
			t.Errorf("hub %s %s = %d, want 404", rt[0], rt[1], r.StatusCode)
		}
	}
	for _, path := range []string{"/api/templates", "/api/settings", "/api/drift", "/api/templates/compose/x",
		"/api/status", "/api/sources", "/api/portal/apps", "/api/domains", "/api/instances", "/api/backups",
		"/api/instances/x/backups", "/api/instances/x/op", "/api/instances/x/settings", "/api/instances/defaults?template=demo", "/static/index.html", "/nope",
		"/api/folders", "/api/folders/x/op", "/api/doctor", "/api/doctor/op", "/api/settings/local-networks"} {
		if r, _ := doAs(t, e.people, "root", "GET", path, ""); r.StatusCode != 404 {
			t.Errorf("people GET %s = %d, want 404", path, r.StatusCode)
		}
	}
	if r, _ := doAs(t, e.people, "root", "POST", "/api/templates/enable", `{"id":"demo"}`); r.StatusCode != 404 {
		t.Errorf("people enable = %d, want 404", r.StatusCode)
	}
	// The hub listener still has them.
	if r, _ := doAs(t, e.hub, "root", "GET", "/api/templates", ""); r.StatusCode != 200 {
		t.Errorf("hub /api/templates = %d", r.StatusCode)
	}
	r, b := doAs(t, e.people, "bob", "GET", "/", "")
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || !strings.Contains(b, "People") {
		t.Errorf("people page = %d %q", r.StatusCode, b)
	}
	if r, _ := do(t, e.people, "GET", "/healthz", "", false); r.StatusCode != 200 {
		t.Errorf("healthz = %d", r.StatusCode)
	}
	// Same chain: the proxy secret and the CSRF guard.
	if r, _ := do(t, e.people, "GET", "/api/directory/me", "", false); r.StatusCode != 401 {
		t.Errorf("no proxy secret = %d", r.StatusCode)
	}
	req, _ := http.NewRequest("POST", e.people.URL+"/api/directory/fields", strings.NewReader(`{}`))
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set("Content-Type", "text/plain")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain mutation = %d", resp.StatusCode)
	}
}

func TestPeopleListenerReadForEveryone(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)

	b := mustDo(t, e.people, "bob", "GET", "/api/directory/me", "", 200)
	var me struct {
		User  string   `json:"user"`
		Admin bool     `json:"admin"`
		Perms []string `json:"perms"`
	}
	json.Unmarshal([]byte(b), &me)
	if me.User != "bob" || me.Admin || me.Perms == nil || len(me.Perms) != 0 {
		t.Errorf("me = %s", b)
	}
	b = mustDo(t, e.people, "root", "GET", "/api/directory/me", "", 200)
	if !strings.Contains(b, `"admin":true`) || !strings.Contains(b, `"perms":["edit_details","invite","remove"]`) {
		t.Errorf("root me = %s", b)
	}

	b = mustDo(t, e.people, "bob", "GET", "/api/directory", "", 200)
	for _, bad := range []string{`"keycloak"`, `"stale_keycloak"`, `"keycloak_error"`, `"invites_error"`, `"server_invite"`, `"required_actions"`, `"passkeys"`} {
		if strings.Contains(b, bad) {
			t.Errorf("non-admin overview carries %s: %s", bad, b)
		}
	}
	assertNonAdminKeys(t, b)
	var ov directory.Overview
	if err := json.Unmarshal([]byte(b), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.Admin || len(ov.Fields) != 2 || len(ov.Suggestions) != 0 {
		t.Errorf("overview = %+v", ov)
	}
	// Field definitions, snake_case; share_with_apps defaults to true.
	if !strings.Contains(b, `{"name":"department","label":"Department","kind":"list","values":["Eng","Sales"],"multi":false,"share_with_apps":true,"admin_only":false}`) ||
		!strings.Contains(b, `"name":"manager","label":"Manager","kind":"person","values":null,"multi":false,"share_with_apps":false`) {
		t.Errorf("fields = %s", b)
	}
	var bob, carl *directory.UserView
	for i, u := range ov.Users {
		switch u.Username {
		case "bob":
			bob = &ov.Users[i]
		case "carl":
			carl = &ov.Users[i]
		}
	}
	if bob == nil || strings.Join(bob.Attrs["department"], ",") != "Eng" || strings.Join(bob.Attrs["manager"], ",") != "root" {
		t.Fatalf("bob = %+v", bob)
	}
	if len(bob.Memberships) != 1 || bob.Memberships[0].Group != "eng" || bob.Memberships[0].How != directory.HowRule {
		t.Errorf("bob memberships = %+v", bob.Memberships)
	}
	if carl == nil || len(carl.Memberships) != 1 || carl.Memberships[0].How != directory.HowException || !strings.Contains(carl.Memberships[0].Reason, "member before the rule") {
		t.Errorf("carl = %+v", carl)
	}
	var eng *directory.GroupView
	for i, g := range ov.Groups {
		if g.Name == "eng" {
			eng = &ov.Groups[i]
		}
	}
	if eng == nil || eng.Rule == nil || eng.Rule.Text != `department = "Eng"` || len(eng.Exceptions) != 1 || !eng.RuleAllowed {
		t.Errorf("eng = %+v", eng)
	}

	// The audit is admin-only; admins still see everything.
	mustDo(t, e.people, "bob", "GET", "/api/directory/audit", "", 403)
	mustDo(t, e.people, "root", "GET", "/api/directory/audit", "", 200)
	b = mustDo(t, e.people, "root", "GET", "/api/directory", "", 200)
	if !strings.Contains(b, `"keycloak":{`) || !strings.Contains(b, `"admin":true`) {
		t.Errorf("admin overview = %s", b)
	}
	// No signed-in user: nothing.
	mustDo(t, e.people, "", "GET", "/api/directory", "", 403)

	// Plain users read, they don't write.
	mustDo(t, e.people, "bob", "POST", "/api/directory/fields", `{"name":"x","label":"X","kind":"text"}`, 403)
	mustDo(t, e.people, "bob", "PUT", "/api/directory/users/carl/details", `{"attrs":{"department":["Sales"]}}`, 403)
	mustDo(t, e.people, "bob", "PUT", "/api/directory/permissions/invite", `{"group":"eng"}`, 403)
}

// keySet returns the sorted keys of a JSON object.
func keySet(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not an object: %s", raw)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// assertNonAdminKeys pins the EXACT keys of bob's (non-admin) view — the
// top level, bob, the rule group eng and the field department (all
// omitempty keys either set or absent as asserted): a new field anywhere
// in the Overview must be allowed here on purpose.
func assertNonAdminKeys(t *testing.T, body string) {
	t.Helper()
	var top struct {
		Users, Groups, Fields []json.RawMessage
	}
	json.Unmarshal([]byte(body), &top)
	pick := func(list []json.RawMessage, key, name string) json.RawMessage {
		for _, raw := range list {
			var m map[string]interface{}
			json.Unmarshal(raw, &m)
			if m[key] == name {
				return raw
			}
		}
		t.Fatalf("no %s %q in %s", key, name, body)
		return nil
	}
	for _, c := range []struct {
		what string
		raw  json.RawMessage
		want string
	}{
		{"top", json.RawMessage(body), "admin,available,cycles,fields,groups,invites_available,me,permissions,perms,service_user,users"},
		{"users[bob] (self)", pick(top.Users, "username", "bob"), "attrs,created,display_name,email,groups,memberships,self,username"},
		{"groups[eng]", pick(top.Groups, "name", "eng"), "created,exceptions,expiry,members,name,rule,rule_allowed,used_by"},
		{"fields[0] (department)", pick(top.Fields, "name", "department"), "admin_only,kind,label,multi,name,share_with_apps,values"},
	} {
		if got := keySet(t, c.raw); got != c.want {
			t.Errorf("%s keys = %s, want %s", c.what, got, c.want)
		}
	}
}

func TestFieldRoutes(t *testing.T) {
	e := newPeopleEnv(t)
	p := e.people
	b := mustDo(t, p, "root", "POST", "/api/directory/fields", `{"name":" office ","label":"  Office ","kind":"text"}`, 200)
	if !strings.Contains(b, `"field":{"name":"office","label":"Office","kind":"text","values":null,"multi":false,"share_with_apps":true,"admin_only":false}`) {
		t.Errorf("create = %s (want the stored, normalised field)", b)
	}
	mustDo(t, p, "root", "POST", "/api/directory/fields", `{"name":"mail","label":"Mail","kind":"text"}`, 400)
	// A partial update keeps the rest (kind, multi, share_with_apps).
	b = mustDo(t, p, "root", "PUT", "/api/directory/fields/office", `{"label":"Office location"}`, 200)
	if !strings.Contains(b, `"label":"Office location"`) || !strings.Contains(b, `"share_with_apps":true`) {
		t.Errorf("update = %s", b)
	}
	cfg, _ := e.s.Directory.Store.Load()
	if f := cfg.Fields[0]; f.Label != "Office location" || !f.ShareWithApps || f.Kind != directory.FieldKindText {
		t.Errorf("field = %+v", f)
	}
	mustDo(t, p, "root", "PUT", "/api/directory/fields/office", `{"share_with_apps":false,"admin_only":true}`, 200)
	cfg, _ = e.s.Directory.Store.Load()
	if f := cfg.Fields[0]; f.ShareWithApps || !f.AdminOnly {
		t.Errorf("field = %+v", f)
	}
	mustDo(t, p, "root", "PUT", "/api/directory/fields/nope", `{"label":"x","kind":"text"}`, 404)
	mustDo(t, p, "root", "DELETE", "/api/directory/fields/office", `{"confirm":"x"}`, 400)
	mustDo(t, p, "root", "DELETE", "/api/directory/fields/office", `{"confirm":"office"}`, 200)
}

func TestRulePreviewConverts(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	b := mustDo(t, e.people, "bob", "POST", "/api/directory/rules/preview", `{"rule":"department = \"Eng\" and not manager is empty"}`, 200)
	var out struct {
		Users []string        `json:"users"`
		Text  string          `json:"text"`
		Expr  json.RawMessage `json:"expr"`
	}
	json.Unmarshal([]byte(b), &out)
	if strings.Join(out.Users, ",") != "bob" || !strings.Contains(string(out.Expr), `"op":"all"`) || !strings.Contains(string(out.Expr), `"op":"is","field":"department","values":["Eng"]`) {
		t.Fatalf("preview = %s", b)
	}
	// And back: the tree in, the same canonical text out.
	b = mustDo(t, e.people, "bob", "POST", "/api/directory/rules/preview", `{"expr":`+string(out.Expr)+`}`, 200)
	var back struct {
		Text string `json:"text"`
	}
	json.Unmarshal([]byte(b), &back)
	if back.Text != out.Text || out.Text == "" {
		t.Errorf("round trip: %q -> %q", out.Text, back.Text)
	}
	// A text that doesn't parse: 400 {error, column}.
	r, b := doAs(t, e.people, "bob", "POST", "/api/directory/rules/preview", `{"rule":"department = "}`)
	var perr struct {
		Error  string `json:"error"`
		Column int    `json:"column"`
	}
	if r.StatusCode != 400 || json.Unmarshal([]byte(b), &perr) != nil || perr.Error == "" || perr.Column < 1 {
		t.Errorf("parse error = %d %s", r.StatusCode, b)
	}
	mustDo(t, e.people, "bob", "POST", "/api/directory/rules/preview", `{"rule":"nofield = \"x\""}`, 400)
	mustDo(t, e.people, "bob", "POST", "/api/directory/rules/preview", `{}`, 400)
	mustDo(t, e.people, "", "POST", "/api/directory/rules/preview", `{"rule":"department = \"Eng\""}`, 403)

	// Rule edits answer both forms too; manual drops the rule.
	b = mustDo(t, e.people, "root", "PUT", "/api/directory/groups/eng/rule", `{"rule":"department in (\"Eng\", \"Sales\")"}`, 200)
	if !strings.Contains(b, `"text":"department in (\"Eng\", \"Sales\")"`) || !strings.Contains(b, `"op":"in"`) {
		t.Errorf("set rule = %s", b)
	}
	mustDo(t, e.people, "root", "PUT", "/api/directory/groups/eng/rule", `{}`, 400)
	mustDo(t, e.people, "root", "PUT", "/api/directory/groups/eng/rule", `{"manual":true}`, 200)
}

func TestRulePreviewCacheInvalidated(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	preview := func() string {
		b := mustDo(t, e.people, "root", "POST", "/api/directory/rules/preview", `{"rule":"department = \"Sales\""}`, 200)
		var out struct{ Users []string }
		json.Unmarshal([]byte(b), &out)
		return strings.Join(out.Users, ",")
	}
	if got := preview(); got != "" {
		t.Fatalf("preview = %q", got)
	}
	// A mutation drops the cached snapshot at once.
	mustDo(t, e.people, "root", "PUT", "/api/directory/users/carl/details", `{"attrs":{"department":["Sales"]}}`, 200)
	if got := preview(); got != "carl" {
		t.Errorf("preview after edit = %q, want carl", got)
	}
}

func TestConvertRefusesStaleReview(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	e.ll.AddGroup("sales", "bob")
	p := e.people
	b := mustDo(t, p, "root", "POST", "/api/directory/groups/sales/convert-preview", `{"rule":"department = \"Sales\""}`, 200)
	if !strings.Contains(b, `"kept_as_exception":["bob"]`) || !strings.Contains(b, `"joining":[]`) || !strings.Contains(b, `"expiry_dropped":[]`) {
		t.Fatalf("preview = %s", b)
	}
	stale := `{"rule":"department = \"Sales\"","keep":[],"preview":` + b + `}`
	// carl now matches: the reviewed preview no longer holds.
	mustDo(t, p, "root", "PUT", "/api/directory/users/carl/details", `{"attrs":{"department":["Sales"]}}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/groups/sales/convert", stale, 409)
	mustDo(t, p, "root", "POST", "/api/directory/groups/sales/convert", `{"rule":"department = \"Sales\"","keep":[]}`, 400)
	if cfg, _ := e.s.Directory.Store.Load(); cfg.Groups["sales"] != nil {
		t.Fatal("a stale review converted the group")
	}
	b = mustDo(t, p, "root", "POST", "/api/directory/groups/sales/convert-preview", `{"rule":"department = \"Sales\""}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/groups/sales/convert", `{"rule":"department = \"Sales\"","keep":["bob"],"preview":`+b+`}`, 200)

	// Exceptions and expiries.
	mustDo(t, p, "root", "POST", "/api/directory/groups/sales/exceptions", `{"user":"root","reason":"x","include":true}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/groups/sales/exceptions", `{"user":"carl","include":false}`, 400) // no reason
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	mustDo(t, p, "root", "POST", "/api/directory/groups/sales/exceptions", `{"user":"carl","reason":"on leave","include":false,"until":"`+until+`"}`, 200)
	mustDo(t, p, "root", "DELETE", "/api/directory/groups/sales/exceptions/carl", `{}`, 200)
	mustDo(t, p, "root", "DELETE", "/api/directory/groups/sales/exceptions/carl", `{}`, 404)
	e.ll.AddGroup("temps", "bob")
	mustDo(t, p, "root", "PUT", "/api/directory/groups/temps/members/bob/expiry", `{"until":"`+until+`"}`, 200)
	// Rule group: bob stayed as an "added by hand" entry (convert keep),
	// so his entry gets the end; carl is in by the rule alone: 409.
	mustDo(t, p, "root", "PUT", "/api/directory/groups/sales/members/bob/expiry", `{"until":"`+until+`"}`, 200)
	mustDo(t, p, "root", "PUT", "/api/directory/groups/sales/members/carl/expiry", `{"until":"`+until+`"}`, 409)
	b = mustDo(t, p, "bob", "GET", "/api/directory", "", 200)
	if !strings.Contains(b, `"expiry":{"bob":"`+until+`"}`) {
		t.Errorf("expiry not shown: %s", b)
	}
	mustDo(t, p, "root", "PUT", "/api/directory/groups/temps/members/bob/expiry", `{"until":null}`, 200)
	mustDo(t, p, "root", "PUT", "/api/directory/permissions/invite", `{"group":"temps"}`, 200)
	mustDo(t, p, "root", "PUT", "/api/directory/permissions/bogus", `{"group":"temps"}`, 400)
	b = mustDo(t, p, "bob", "GET", "/api/directory/me", "", 200)
	if !strings.Contains(b, `"perms":["invite"]`) {
		t.Errorf("bob me = %s", b)
	}
	b = mustDo(t, p, "bob", "GET", "/api/directory", "", 200)
	if !strings.Contains(b, `"permissions":{"invite":"temps"}`) || !strings.Contains(b, `"perms":["invite"]`) {
		t.Errorf("permissions not shown: %s", b)
	}
}

func upload(t *testing.T, srv *httptest.Server, user string, data []byte) (*http.Response, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "people.csv")
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/api/directory/import/review", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", user)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestImportReviewUploadLimit(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	big := append([]byte("username,department\n"), bytes.Repeat([]byte("x"), 6<<20)...)
	if r, b := upload(t, e.people, "root", big); r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("6 MB upload = %d %s", r.StatusCode, b)
	}
	r, b := upload(t, e.people, "root", []byte("Username;Department\nbob;Sales\ncarl;Eng\n"))
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("upload = %d %s", r.StatusCode, b)
	}
	var out struct {
		Header []string          `json:"header"`
		Rows   [][]string        `json:"rows"`
		Review *directory.Review `json:"review"`
	}
	json.Unmarshal([]byte(b), &out)
	if strings.Join(out.Header, ",") != "username,department" || len(out.Rows) != 2 || out.Review == nil || len(out.Review.Rows) < 2 {
		t.Fatalf("upload review = %s", b)
	}
	if fx := out.Review.Effect["eng"]; fx != [2]int{0, 1} { // bob leaves (carl is in already, as an exception)
		t.Errorf("effect = %v", out.Review.Effect)
	}
	// Plain users can't review an import: refused before the body is read
	// (403, not 413).
	if r, _ := upload(t, e.people, "bob", []byte("username\nbob\n")); r.StatusCode != 403 {
		t.Errorf("plain user upload = %d", r.StatusCode)
	}
	if r, _ := upload(t, e.people, "bob", big); r.StatusCode != 403 {
		t.Errorf("plain user 6 MB upload = %d, want 403", r.StatusCode)
	}
	mustDo(t, e.people, "bob", "POST", "/api/directory/import/review", `not json`, 403)
	// Re-review of edited rows (JSON): the effect follows the edits.
	body, _ := json.Marshal(map[string]interface{}{"header": out.Header, "rows": [][]string{{"bob", "Eng"}, {"carl", "Eng"}}})
	b = mustDo(t, e.people, "root", "POST", "/api/directory/import/review", string(body), 200)
	out.Review = nil
	json.Unmarshal([]byte(b), &out)
	if _, ok := out.Review.Effect["eng"]; ok || out.Review.Rows[1].Status != "changed" {
		t.Errorf("re-review effect = %v (%s)", out.Review.Effect, b)
	}
	mustDo(t, e.people, "root", "POST", "/api/directory/import/review", `{"header":["department"],"rows":[]}`, 400)

	// A plain user's apply: 403, nothing audited.
	auditLines := func() int {
		data, _ := os.ReadFile(e.s.Directory.Audit.Path)
		return strings.Count(string(data), "\n")
	}
	n := auditLines()
	mustDo(t, e.people, "bob", "POST", "/api/directory/import/apply", `{"rows":[{"user":"carl","remove":true}]}`, 403)
	if auditLines() != n || !e.ll.HasUser("carl") {
		t.Error("a plain user's apply was audited or applied")
	}

	// Apply.
	r, b = doAs(t, e.people, "root", "POST", "/api/directory/import/apply", `{"rows":[{"user":"carl","attrs":{"department":["Eng"]}}]}`)
	if r.StatusCode != 200 || !strings.Contains(b, `"ok":true`) || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("apply = %d %s", r.StatusCode, b)
	}
}

// TestPeopleDirectoryUnavailable: without LLDAP the people listener says
// so generically; the hub listener (admins) keeps the detail.
func TestPeopleDirectoryUnavailable(t *testing.T) {
	s, _, _ := newDirFixture(t, func(d *directory.Service) {
		d.LLDAP = lldap.New("http://127.0.0.1:1", "ldap://127.0.0.1:1", "dc=x", filepath.Join(t.TempDir(), "missing"))
	})
	h, _ := s.Handler()
	p, _ := s.PeopleHandler()
	hub, people := httptest.NewServer(h), httptest.NewServer(p)
	t.Cleanup(hub.Close)
	t.Cleanup(people.Close)
	b := mustDo(t, people, "bob", "GET", "/api/directory", "", 200)
	if !strings.Contains(b, `"reason":"`+directory.GenericUnavailable+`"`) || strings.Contains(b, "missing") {
		t.Errorf("people overview = %s", b)
	}
	b = mustDo(t, hub, "root", "GET", "/api/directory", "", 200)
	if !strings.Contains(b, `"available":false`) || !strings.Contains(b, "missing") {
		t.Errorf("hub overview = %s", b)
	}
	if b := mustDo(t, people, "bob", "GET", "/api/directory/me", "", 503); strings.TrimSpace(b) != directory.GenericUnavailable {
		t.Errorf("people me = %q", b)
	}
}

func TestCoreSubdomainsHasPeople(t *testing.T) {
	if !policy.CoreSubdomains()["people"] {
		t.Error("people is not a core subdomain")
	}
}

// TestDirectoryAssetsServed: both listeners serve the directory UI's
// embedded assets, and both pages load them (the Hub's Users & Groups tab
// no longer carries its own copy of the code).
func TestDirectoryAssetsServed(t *testing.T) {
	e := newPeopleEnv(t)
	for _, srv := range []*httptest.Server{e.hub, e.people} {
		for path, ct := range map[string]string{"/static/directory.js": "text/javascript", "/static/directory.css": "text/css"} {
			r, b := doAs(t, srv, "bob", "GET", path, "")
			if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), ct) || r.Header.Get("X-Content-Type-Options") != "nosniff" || len(b) < 1000 {
				t.Errorf("%s %s = %d %q (%d bytes)", srv.URL, path, r.StatusCode, r.Header.Get("Content-Type"), len(b))
			}
		}
	}
	for _, c := range []struct {
		srv  *httptest.Server
		page string
	}{{e.hub, "hub index"}, {e.people, "people page"}} {
		_, b := doAs(t, c.srv, "root", "GET", "/", "")
		if !strings.Contains(b, `src="/static/directory.js"`) || !strings.Contains(b, `href="/static/directory.css"`) {
			t.Errorf("%s does not load directory.js/css", c.page)
		}
	}
	_, b := doAs(t, e.hub, "root", "GET", "/", "")
	if strings.Contains(b, "function renderUsers") || strings.Contains(b, "dir-users") {
		t.Error("the hub index still carries the old inline Users & Groups code")
	}
	if !strings.Contains(b, `data-tab="users"`) {
		t.Error("the hub index lost its Users & Groups tab (#users deep link)")
	}
}

// TestSettingsAssetHubOnly: the settings panel's script is served on the
// Hub listener only; the people listener serves just its own assets
// (directory.js, directory.css, myapps.js, myai.js — the Connect your AI
// card —, and confirm.js for the confirmation page).
func TestSettingsAssetHubOnly(t *testing.T) {
	e := newPeopleEnv(t)
	var allow []string
	for a, ok := range peopleStatic {
		if ok {
			allow = append(allow, a)
		}
	}
	sort.Strings(allow)
	if strings.Join(allow, ",") != "confirm.js,directory.css,directory.js,freshauth-callback.js,freshauth.js,myai.js,myapps.js" {
		t.Errorf("peopleStatic = %v, want exactly confirm.js, directory.css, directory.js, freshauth-callback.js, freshauth.js, myai.js, myapps.js", allow)
	}
	if r, b := doAs(t, e.hub, "root", "GET", "/static/settings.js", ""); r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(b, "PortcullisSettings") {
		t.Errorf("hub settings.js = %d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if r, b := doAs(t, e.people, "bob", "GET", "/static/myapps.js", ""); r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(b, "PortcullisMyApps") {
		t.Errorf("people myapps.js = %d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if r, b := doAs(t, e.people, "bob", "GET", "/static/myai.js", ""); r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(b, "PortcullisMyAI") {
		t.Errorf("people myai.js = %d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	_, pb := doAs(t, e.people, "bob", "GET", "/", "")
	if !strings.Contains(pb, `src="/static/myapps.js"`) || !strings.Contains(pb, `src="/static/myai.js"`) || strings.Contains(pb, "settings.js") {
		t.Error("the people page does not load myapps.js and myai.js, or loads settings.js")
	}
	// The shared folders and doctor UI (plan 2 Task 14): Hub only.
	for _, a := range []struct{ file, global string }{{"folders.js", "PortcullisFolders"}, {"doctor.js", "PortcullisDoctor"}} {
		if r, b := doAs(t, e.hub, "root", "GET", "/static/"+a.file, ""); r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(b, a.global) {
			t.Errorf("hub %s = %d %q", a.file, r.StatusCode, r.Header.Get("Content-Type"))
		}
		if strings.Contains(pb, a.file) {
			t.Errorf("the people page loads %s", a.file)
		}
	}
	for _, p := range []string{"/static/settings.js", "/static/folders.js", "/static/doctor.js", "/static/index.html", "/static/people.html", "/static/web.go"} {
		if r, _ := doAs(t, e.people, "bob", "GET", p, ""); r.StatusCode != 404 {
			t.Errorf("people %s = %d, want 404", p, r.StatusCode)
		}
	}
	_, b := doAs(t, e.hub, "root", "GET", "/", "")
	for _, f := range []string{"settings.js", "folders.js", "doctor.js"} {
		if !strings.Contains(b, `src="/static/`+f+`"`) {
			t.Errorf("the hub index does not load %s", f)
		}
	}
}

// F20 / G11: people.html and index.html are the fresh-auth popup's
// landing pages, with one callback source (freshauth-callback.js, fix
// round 1 of plan 4 Task 14), loaded first in <head>. It drops code and
// state from the URL at once, posts only to a same-origin opener (guarded
// read of opener.location.origin) with targetOrigin = location.origin,
// and otherwise ignores the parameters. (Checked in a browser against
// the harness: same-origin opener gets the message and the popup closes;
// a cross-origin opener gets nothing.) Every page carries
// <meta name="referrer" content="no-referrer"> as the first element of
// <head>: Traefik's security-headers@file may replace the Hub's header.
func TestPeoplePageFreshAuthCallback(t *testing.T) {
	e := newPeopleEnv(t)
	_, pb := doAs(t, e.people, "bob", "GET", "/", "")
	_, ib := doAs(t, e.hub, "root", "GET", "/", "")
	tag := `<script src="/static/freshauth-callback.js"></script>`
	for name, page := range map[string]string{"people.html": pb, "index.html": ib} {
		i := strings.Index(page, tag)
		if i < 0 || i > strings.Index(page, "<style>") || i > strings.Index(page, `src="/static/directory.js"`) {
			t.Errorf("%s: the popup callback isn't loaded first in <head>", name)
		}
		if strings.Count(page, "portcullis-fresh-auth'") != 0 || strings.Contains(page, "window.opener.location.origin") {
			t.Errorf("%s: an inline copy of the callback is left", name)
		}
	}
	for _, srv := range []*httptest.Server{e.people, e.hub} {
		if r, b := doAs(t, srv, "bob", "GET", "/static/freshauth-callback.js", ""); r.StatusCode != 200 || !strings.Contains(b, "portcullisFreshAuthCallback") {
			t.Errorf("%s freshauth-callback.js = %d", srv.URL, r.StatusCode)
		}
	}
	cb := webAsset(t, "freshauth-callback.js")
	for _, want := range []string{
		"history.replaceState(null, '', location.pathname + location.hash);",
		"try {",
		"window.opener.location.origin === location.origin",
		"op.postMessage(msg, location.origin);",
		"window.close();",
	} {
		if !strings.Contains(cb, want) {
			t.Errorf("callback lacks %q", want)
		}
	}
	if strings.Index(cb, "history.replaceState(") > strings.Index(cb, "if (window.opener &&") || strings.Contains(cb, `"*"`) || strings.Contains(cb, "'*'") {
		t.Error("the URL must be cleaned before the opener is looked at, and nothing posted to *")
	}
}

// TestPagesMetaNoReferrer (fix round 1): index.html, people.html and
// confirm.html carry <meta name="referrer" content="no-referrer"> as the
// first element of <head>.
func TestPagesMetaNoReferrer(t *testing.T) {
	for _, name := range []string{"index.html", "people.html", "confirm.html"} {
		page := webAsset(t, name)
		i := strings.Index(page, "<head>")
		if i < 0 {
			t.Fatalf("%s: no <head>", name)
		}
		rest := strings.TrimSpace(page[i+len("<head>"):])
		if !strings.HasPrefix(rest, `<meta name="referrer" content="no-referrer">`) {
			t.Errorf("%s: the first element of <head> isn't the no-referrer meta tag", name)
		}
	}
}

// ── Task 21: GET /api/me/ai, DELETE /api/me/ai/connections/{client} ──

// TestMyAICallerOnly: the caller's own connections and access-log lines
// only (X-Forwarded-User case-folded), no-store; no caller 401; the Hub
// listener 404; Keycloak down → 503 with the generic text. GET
// /api/me/apps carries the top-level ai (master on, gate present).
func TestMyAICallerOnly(t *testing.T) {
	e, kc := peopleToolEnv(t)
	for _, u := range []string{"alice", "ALICE"} {
		r, b := doAs(t, e.ppl, u, "GET", "/api/me/ai", "")
		if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: GET /api/me/ai = %d %q %s", u, r.StatusCode, r.Header.Get("Cache-Control"), b)
		}
		var v struct {
			Connections []struct {
				Client, Label string
			} `json:"connections"`
			Activity []struct {
				User, Tool string
			} `json:"activity"`
		}
		if err := json.Unmarshal([]byte(b), &v); err != nil {
			t.Fatal(err)
		}
		if len(v.Connections) != 1 || v.Connections[0].Client != "portcullis-ai-claude" || v.Connections[0].Label != "Claude" {
			t.Errorf("%s's connections = %s", u, b)
		}
		if len(v.Activity) != 1 || v.Activity[0].User != "alice" || v.Activity[0].Tool != "tool_of_alice" {
			t.Errorf("%s's activity = %s", u, b)
		}
		if strings.Contains(b, "bob") || strings.Contains(b, "portcullis-ai-claude-code") {
			t.Errorf("%s sees bob's data: %s", u, b)
		}
	}
	if r, _ := doAs(t, e.ppl, "", "GET", "/api/me/ai", ""); r.StatusCode != 401 {
		t.Errorf("no caller = %d, want 401", r.StatusCode)
	}
	if r, _ := doAs(t, e.hub, "root", "GET", "/api/me/ai", ""); r.StatusCode != 404 {
		t.Errorf("hub listener = %d, want 404", r.StatusCode)
	}
	_, b := doAs(t, e.ppl, "alice", "GET", "/api/me/apps", "")
	if !strings.Contains(b, `"ai":{"aggregate_url":"https://mcp.example.org/mcp"`) {
		t.Errorf("alice's /api/me/apps has no top-level ai: %s", b)
	}
	kc.mu.Lock()
	kc.err = errors.New("keycloak at 10.0.0.9 refused: secret-detail")
	kc.mu.Unlock()
	r, b := doAs(t, e.ppl, "alice", "GET", "/api/me/ai", "")
	if r.StatusCode != 503 || strings.TrimSpace(b) != directory.GenericUnavailable {
		t.Errorf("Keycloak down = %d %q, want 503 with the generic text", r.StatusCode, b)
	}
}

// TestDisconnectAI: revokes only the caller's consent and offline
// sessions for that AI client (204, audited ai.connection.revoke as a
// human), a client id that isn't an AI client 404, no caller 401, the
// Hub listener 404, Keycloak down 503 generic; refusals count toward the
// people listener's refused-save limit (429).
func TestDisconnectAI(t *testing.T) {
	e, kc := peopleToolEnv(t)
	if r, b := doAs(t, e.ppl, "Alice", "DELETE", "/api/me/ai/connections/portcullis-ai-claude", ""); r.StatusCode != 204 {
		t.Fatalf("disconnect = %d %s", r.StatusCode, b)
	}
	kc.mu.Lock()
	revoked := append([]string{}, kc.revoked...)
	kc.mu.Unlock()
	if strings.Join(revoked, ",") != "alice/portcullis-ai-claude" {
		t.Errorf("revoked %v, want only alice's Claude connection", revoked)
	}
	var got *directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "ai.connection.revoke" {
			got = &a
		}
	}
	if got == nil || got.Actor != "alice" || got.Target != "alice" || got.Via != "" || got.Client != "" || got.Result != "ok" || got.Detail != "portcullis-ai-claude" {
		t.Errorf("audit = %+v", got)
	}
	for _, c := range []string{"grafana", "portcullis-fresh-auth", "portcullis-forward-auth"} {
		if r, _ := doAs(t, e.ppl, "alice", "DELETE", "/api/me/ai/connections/"+c, ""); r.StatusCode != 404 {
			t.Errorf("disconnect %s = %d, want 404", c, r.StatusCode)
		}
	}
	if r, _ := doAs(t, e.ppl, "", "DELETE", "/api/me/ai/connections/portcullis-ai-claude", ""); r.StatusCode != 401 {
		t.Errorf("no caller = %d, want 401", r.StatusCode)
	}
	if r, _ := doAs(t, e.hub, "root", "DELETE", "/api/me/ai/connections/portcullis-ai-claude", ""); r.StatusCode != 404 {
		t.Errorf("hub listener = %d, want 404", r.StatusCode)
	}
	// The CSRF guard (fix round 1): no JSON Content-Type 415, a
	// cross-origin request 403 — neither reaches Keycloak.
	before := len(revoked)
	for _, c := range []struct {
		name, ctype, site, origin string
		want                      int
	}{
		{"no content type", "", "", "", http.StatusUnsupportedMediaType},
		{"text/plain", "text/plain", "", "", http.StatusUnsupportedMediaType},
		{"cross-site", "application/json", "cross-site", "https://evil.example", http.StatusForbidden},
	} {
		req, _ := http.NewRequest("DELETE", e.ppl.URL+"/api/me/ai/connections/portcullis-ai-claude-code", nil)
		req.Header.Set(ProxySecretHeader, testSecret)
		req.Header.Set("X-Forwarded-User", "alice")
		if c.ctype != "" {
			req.Header.Set("Content-Type", c.ctype)
		}
		if c.site != "" {
			req.Header.Set("Sec-Fetch-Site", c.site)
			req.Header.Set("Origin", c.origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: DELETE = %d, want %d", c.name, resp.StatusCode, c.want)
		}
	}
	kc.mu.Lock()
	if len(kc.revoked) != before {
		t.Errorf("a refused request reached Keycloak: %v", kc.revoked)
	}
	kc.mu.Unlock()
	kc.mu.Lock()
	kc.err = errors.New("keycloak at 10.0.0.9 refused: secret-detail")
	kc.mu.Unlock()
	if r, b := doAs(t, e.ppl, "alice", "DELETE", "/api/me/ai/connections/portcullis-ai-claude-code", ""); r.StatusCode != 503 || strings.TrimSpace(b) != directory.GenericUnavailable {
		t.Errorf("Keycloak down = %d %q, want 503 generic", r.StatusCode, b)
	}
	kc.mu.Lock()
	kc.err = nil
	kc.mu.Unlock()
	// Ten refusals in the minute (three above), then 429 — also for a
	// client that exists; bob is not affected.
	for i := 0; i < 7; i++ {
		doAs(t, e.ppl, "alice", "DELETE", "/api/me/ai/connections/nope", "")
	}
	if r, _ := doAs(t, e.ppl, "alice", "DELETE", "/api/me/ai/connections/portcullis-ai-claude", ""); r.StatusCode != 429 {
		t.Errorf("after ten refusals = %d, want 429", r.StatusCode)
	}
	if r, _ := doAs(t, e.ppl, "bob", "DELETE", "/api/me/ai/connections/portcullis-ai-claude-code", ""); r.StatusCode != 204 {
		t.Errorf("bob = %d, want 204", r.StatusCode)
	}
}
