package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// Person-entered values (Task 15A): the people listener's own-value
// routes and the Hub listener's admin routes.

const (
	entAlice  = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	entAlice2 = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
	entBob    = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
)

// entryEnv: newSetEnv plus the Hub's entryapp fixture (custom, access
// group entryapp: alice, alice2, bob; ext_id unique + admin_override,
// nick without), enabled; dana (helpers) holds edit_details.
func entryEnv(t *testing.T) *setEnv {
	t.Helper()
	dir := filepath.Join("..", "hub", "testdata", "settings", "entryapp")
	m, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	e := newSetEnvWith(t, map[string][2]string{"entryapp": {string(m), string(c)}})
	e.ll.AddUser("alice", "alice@example.org", "Alice", "")
	e.ll.AddUser("alice2", "alice2@example.org", "Alice 2", "")
	e.ll.AddGroup("entryapp", "alice", "alice2", "bob")
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/"+directory.PermEditDetails, `{"group":"helpers"}`, 200)
	if code, b := e.do(t, "root", "POST", "/api/templates/enable", `{"id":"entryapp"}`); code != 200 {
		t.Fatalf("enable = %d %s", code, b)
	}
	e.s.Hub.Wait()
	return e
}

func valueBody(v string) string { return `{"value":"` + v + `"}` }

func TestPutOwnValueRoute(t *testing.T) {
	e := entryEnv(t)
	const path = "/api/me/apps/entryapp/values/ext_id"
	r, b := doAs(t, e.ppl, "Alice", "PUT", path, valueBody(entAlice))
	if r.StatusCode != 200 {
		t.Fatalf("PUT = %d %s", r.StatusCode, b)
	}
	var me hub.MyEntry
	if err := json.Unmarshal([]byte(b), &me); err != nil || me.Key != "ext_id" || me.Value != entAlice || me.Input.Pattern == "" {
		t.Errorf("answer = %s (%v)", b, err)
	}
	apps := myAppsOf(t, e, "alice")
	if len(apps) != 1 || len(apps[0].Entries) == 0 || apps[0].Entries[0].Value != entAlice {
		t.Errorf("alice's apps = %+v", apps)
	}
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"value":"` + entAlice + `","extra":1}`, 400},
		{`{"value":"` + strings.Repeat("a", 5<<10) + `"}`, 413},
		{`{"value":"` + entAlice + `"} {}`, 400},
		{`{"value":"XYZ"}`, 400},
	} {
		if r, b := doAs(t, e.ppl, "alice", "PUT", path, c.body); r.StatusCode != c.want {
			t.Errorf("body %.40q = %d %s, want %d", c.body, r.StatusCode, b, c.want)
		}
	}
	// No caller: 401.
	if r, _ := doAs(t, e.ppl, "", "PUT", path, valueBody(entAlice)); r.StatusCode != 401 {
		t.Errorf("no caller = %d", r.StatusCode)
	}
	// The CSRF guard as for the directory API: JSON only, same origin.
	req, _ := http.NewRequest("PUT", e.ppl.URL+path, strings.NewReader(valueBody(entAlice)))
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("Content-Type", "text/plain")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain = %v %v", resp.StatusCode, err)
	}
	req, _ = http.NewRequest("PUT", e.ppl.URL+path, strings.NewReader(valueBody(entAlice)))
	req.Header.Set(ProxySecretHeader, testSecret)
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site = %v %v", resp.StatusCode, err)
	}
	// Someone else's value: 409, never naming the holder.
	r, b = doAs(t, e.ppl, "bob", "PUT", path, valueBody(entAlice))
	if r.StatusCode != 409 || strings.Contains(strings.ToLower(b), "alice") {
		t.Errorf("bob = %d %s", r.StatusCode, b)
	}
	// Outside the population, unknown key, unknown app: the same 404.
	var notFound []string
	for _, c := range []struct{ user, path string }{
		{"dana", path}, {"alice", "/api/me/apps/entryapp/values/nope"}, {"alice", "/api/me/apps/vault/values/ext_id"}, {"alice", "/api/me/apps/ghost/values/ext_id"},
	} {
		r, b := doAs(t, e.ppl, c.user, "PUT", c.path, valueBody(entAlice))
		if r.StatusCode != 404 {
			t.Errorf("%s %s = %d %s", c.user, c.path, r.StatusCode, b)
		}
		notFound = append(notFound, b)
	}
	for _, b := range notFound[1:] {
		if b != notFound[0] {
			t.Errorf("404 bodies differ: %q vs %q", b, notFound[0])
		}
	}
	// DELETE: 204, also when nothing is set.
	for range 2 {
		if r, b := doAs(t, e.ppl, "ALICE", "DELETE", path, ""); r.StatusCode != 204 {
			t.Errorf("DELETE = %d %s", r.StatusCode, b)
		}
	}
	if apps := myAppsOf(t, e, "alice"); apps[0].Entries[0].Value != nil {
		t.Errorf("after DELETE = %+v", apps[0].Entries[0])
	}
}

func TestOwnValueRoutesOnlyOnPeople(t *testing.T) {
	e := entryEnv(t)
	for _, m := range []string{"PUT", "DELETE"} {
		if r, _ := doAs(t, e.hub, "root", m, "/api/me/apps/entryapp/values/ext_id", valueBody(entAlice)); r.StatusCode != 404 {
			t.Errorf("hub %s own value = %d, want 404", m, r.StatusCode)
		}
		if r, _ := doAs(t, e.ppl, "root", m, "/api/instances/entryapp/settings/entries/ext_id/alice", valueBody(entAlice)); r.StatusCode != 404 {
			t.Errorf("people %s admin entry = %d, want 404", m, r.StatusCode)
		}
	}
}

func TestAdminEntryRoutesAdminOnly(t *testing.T) {
	e := entryEnv(t)
	const path = "/api/instances/entryapp/settings/entries/ext_id/alice"
	for _, user := range []string{"dana", "bob", "alice"} {
		for _, m := range []string{"PUT", "DELETE"} {
			if code, b := e.do(t, user, m, path, valueBody(entAlice)); code != 403 {
				t.Errorf("%s %s = %d %s, want 403", user, m, code, b)
			}
		}
	}
	if code, _ := e.do(t, "", "PUT", path, valueBody(entAlice)); code != 401 {
		t.Errorf("no user = %d", code)
	}
	code, b := e.do(t, "root", "PUT", path, valueBody(entAlice))
	var row hub.EntryRow
	if code != 200 || json.Unmarshal([]byte(b), &row) != nil || row.User != "alice" || row.SetBy != "root" || row.Value != entAlice {
		t.Fatalf("admin PUT = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "PUT", "/api/instances/entryapp/settings/entries/nick/alice", `{"value":"Ali"}`); code != 403 {
		t.Errorf("without admin_override = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "PUT", "/api/instances/entryapp/settings/entries/ext_id/bob", valueBody(entAlice)); code != 409 {
		t.Errorf("admin duplicate = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "PUT", path, `{"value":"`+entAlice+`","x":1}`); code != 400 {
		t.Errorf("unknown field = %d %s", code, b)
	}
	if code, b := e.do(t, "root", "DELETE", path, ""); code != 204 {
		t.Errorf("admin DELETE = %d %s", code, b)
	}
	var seen bool
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "settings.person_value" && a.Target == "entryapp/ext_id/alice" && a.Detail == "cleared" && a.Actor == "root" {
			seen = true
		}
	}
	if !seen {
		t.Error("the admin's clear was not audited")
	}
}

// T15 review M1: a name that is another's prefix never sees its data.
func TestOwnValuesPrefixNames(t *testing.T) {
	e := entryEnv(t)
	mustDo(t, e.ppl, "alice", "PUT", "/api/me/apps/entryapp/values/ext_id", valueBody(entAlice), 200)
	mustDo(t, e.ppl, "alice2", "PUT", "/api/me/apps/entryapp/values/ext_id", valueBody(entAlice2), 200)
	_, a := doAs(t, e.ppl, "ALICE", "GET", "/api/me/apps", "")
	if !strings.Contains(a, entAlice) || strings.Contains(a, entAlice2) || strings.Contains(a, "alice2") {
		t.Errorf("ALICE sees %s", a)
	}
	_, b := doAs(t, e.ppl, "alice2", "GET", "/api/me/apps", "")
	if !strings.Contains(b, entAlice2) || strings.Contains(b, entAlice) {
		t.Errorf("alice2 sees %s", b)
	}
	// alice2 can't clear alice's value through her own route.
	mustDo(t, e.ppl, "alice2", "DELETE", "/api/me/apps/entryapp/values/ext_id", "", 204)
	if _, a := doAs(t, e.ppl, "alice", "GET", "/api/me/apps", ""); !strings.Contains(a, entAlice) {
		t.Errorf("alice's value gone after alice2's DELETE: %s", a)
	}
}

// Fix round 1 M6: refused saves past the per-caller limit answer 429.
func TestOwnValueRefusalsLimited(t *testing.T) {
	e := entryEnv(t)
	const path = "/api/me/apps/entryapp/values/ext_id"
	for range 10 {
		mustDo(t, e.ppl, "bob", "PUT", path, valueBody("nope"), 400)
	}
	mustDo(t, e.ppl, "bob", "PUT", path, valueBody(entBob), 429)
	mustDo(t, e.ppl, "alice", "PUT", path, valueBody(entAlice), 200)
}
