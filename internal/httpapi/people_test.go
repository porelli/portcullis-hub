package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
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

func TestPeopleListenerHasNoAppRoutes(t *testing.T) {
	e := newPeopleEnv(t)
	for _, path := range []string{"/api/templates", "/api/settings", "/api/drift", "/api/templates/compose/x",
		"/api/status", "/api/sources", "/api/portal/apps", "/static/index.html", "/nope"} {
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

func TestFieldRoutes(t *testing.T) {
	e := newPeopleEnv(t)
	p := e.people
	mustDo(t, p, "root", "POST", "/api/directory/fields", `{"name":"office","label":"Office","kind":"text"}`, 200)
	mustDo(t, p, "root", "POST", "/api/directory/fields", `{"name":"mail","label":"Mail","kind":"text"}`, 400)
	// A partial update keeps the rest (kind, multi, share_with_apps).
	mustDo(t, p, "root", "PUT", "/api/directory/fields/office", `{"label":"Office location"}`, 200)
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
	mustDo(t, p, "root", "PUT", "/api/directory/groups/sales/members/bob/expiry", `{"until":"`+until+`"}`, 409) // rule group
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
	// Plain users can't review an import.
	if r, _ := upload(t, e.people, "bob", []byte("username\nbob\n")); r.StatusCode != 403 {
		t.Errorf("plain user upload = %d", r.StatusCode)
	}
	// Re-review of edited rows (JSON): the effect follows the edits.
	body, _ := json.Marshal(map[string]interface{}{"header": out.Header, "rows": [][]string{{"bob", "Eng"}, {"carl", "Eng"}}})
	b = mustDo(t, e.people, "root", "POST", "/api/directory/import/review", string(body), 200)
	out.Review = nil
	json.Unmarshal([]byte(b), &out)
	if _, ok := out.Review.Effect["eng"]; ok || out.Review.Rows[1].Status != "changed" {
		t.Errorf("re-review effect = %v (%s)", out.Review.Effect, b)
	}
	mustDo(t, e.people, "root", "POST", "/api/directory/import/review", `{"header":["department"],"rows":[]}`, 400)

	// Apply.
	r, b = doAs(t, e.people, "root", "POST", "/api/directory/import/apply", `{"rows":[{"user":"carl","attrs":{"department":["Eng"]}}]}`)
	if r.StatusCode != 200 || !strings.Contains(b, `"ok":true`) || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("apply = %d %s", r.StatusCode, b)
	}
}

func TestCoreSubdomainsHasPeople(t *testing.T) {
	if !policy.CoreSubdomains["people"] {
		t.Error("people is not a core subdomain")
	}
}
