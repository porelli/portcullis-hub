package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
)

// settledOf decodes an answer's applied / why (applied nil: absent).
func settledOf(t *testing.T, body string) (applied *bool, why string, has bool) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("answer %q: %v", body, err)
	}
	if raw, ok := m["applied"]; ok {
		var b bool
		json.Unmarshal(raw, &b)
		applied = &b
	}
	if raw, ok := m["why"]; ok {
		json.Unmarshal(raw, &why)
		has = true
	}
	return applied, why, has
}

func wantApplied(t *testing.T, what, body string) {
	t.Helper()
	applied, why, has := settledOf(t, body)
	if applied == nil || !*applied || has {
		t.Errorf("%s: answer %s, want applied:true and no why (%q)", what, body, why)
	}
}

func hasEntry(t *testing.T, d *directory.Service, group, user string) bool {
	t.Helper()
	cfg, err := d.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	gc := cfg.Groups[group]
	if gc == nil {
		return false
	}
	for _, ex := range gc.Exceptions {
		if strings.EqualFold(ex.User, user) {
			return true
		}
	}
	return false
}

// Every membership mutation is applied to LLDAP when its answer comes
// back: no Evaluate call in between.
func TestSettleAppliesAtOnce(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	e.ll.AddUser("dave", "dave@example.org", "Dave", "")
	p := e.people

	b := mustDo(t, p, "root", "POST", "/api/directory/groups/eng/members", `{"username":"dave","reason":"helps out"}`, 200)
	wantApplied(t, "add by hand", b)
	if !slices.Contains(e.ll.GroupMembers("eng"), "dave") {
		t.Fatalf("dave not in eng when the add answered: %v", e.ll.GroupMembers("eng"))
	}
	// Kept out: bob (in by the rule) leaves at once.
	b = mustDo(t, p, "root", "POST", "/api/directory/groups/eng/exceptions", `{"user":"bob","reason":"on leave","include":false}`, 200)
	wantApplied(t, "keep out", b)
	if slices.Contains(e.ll.GroupMembers("eng"), "bob") {
		t.Fatalf("bob still in eng: %v", e.ll.GroupMembers("eng"))
	}
	b = mustDo(t, p, "root", "DELETE", "/api/directory/groups/eng/exceptions/bob", `{}`, 200)
	wantApplied(t, "remove exception", b)
	if !slices.Contains(e.ll.GroupMembers("eng"), "bob") {
		t.Fatalf("bob not back in eng: %v", e.ll.GroupMembers("eng"))
	}
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	b = mustDo(t, p, "root", "PUT", "/api/directory/groups/eng/members/dave/expiry", `{"until":"`+until+`"}`, 200)
	wantApplied(t, "expiry", b)
	b = mustDo(t, p, "root", "DELETE", "/api/directory/groups/eng/members/dave", `{}`, 200)
	wantApplied(t, "remove by hand", b)
	if slices.Contains(e.ll.GroupMembers("eng"), "dave") {
		t.Fatalf("dave still in eng: %v", e.ll.GroupMembers("eng"))
	}
	// A rule change: nobody matches "Sales", bob leaves (carl stays: kept).
	b = mustDo(t, p, "root", "PUT", "/api/directory/groups/eng/rule", `{"rule":"department = \"Sales\""}`, 200)
	wantApplied(t, "rule", b)
	if slices.Contains(e.ll.GroupMembers("eng"), "bob") {
		t.Fatalf("bob still in eng after the rule change: %v", e.ll.GroupMembers("eng"))
	}
	// A manual group answers the same way.
	e.ll.AddGroup("temps")
	b = mustDo(t, p, "root", "POST", "/api/directory/groups/temps/members", `{"username":"dave"}`, 200)
	wantApplied(t, "manual add", b)
	b = mustDo(t, p, "root", "DELETE", "/api/directory/groups/temps/members/dave", `{}`, 200)
	wantApplied(t, "manual remove", b)
	// Creating a person into a rule group: they are in it at once.
	b = mustDo(t, e.hub, "root", "POST", "/api/directory/users", `{"username":"erin","email":"erin@example.org","groups":["eng"],"reasons":{"eng":"new hire"},"onboarding":"password","generate_password":true}`, 200)
	wantApplied(t, "create user", b)
	if !slices.Contains(e.ll.GroupMembers("eng"), "erin") {
		t.Fatalf("erin not in eng when the create answered: %v", e.ll.GroupMembers("eng"))
	}
	// Without groups: no applied field.
	b = mustDo(t, e.hub, "root", "POST", "/api/directory/users", `{"username":"fay","email":"fay@example.org","onboarding":"password","generate_password":true}`, 200)
	if a, _, has := settledOf(t, b); a != nil || has {
		t.Errorf("create without groups = %s, want no applied", b)
	}
}

// LLDAP goes down between the mutation and the evaluation: the entry is
// stored, the answer says it wasn't applied and why; once LLDAP is back
// the entry can be removed.
func TestSettleLLDAPDown(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	e.ll.AddUser("dave", "dave@example.org", "Dave", "")
	cred := filepath.Join(e.s.Directory.LLDAP.(*lldap.Client).CredentialsDir, "password")
	var down atomic.Bool
	e.s.callHook = func(method string, _ ...any) {
		if method == "Settle" && down.Load() {
			if err := os.Rename(cred, cred+".off"); err != nil {
				t.Error(err)
			}
		}
	}
	down.Store(true)
	b := mustDo(t, e.people, "root", "POST", "/api/directory/groups/eng/members", `{"username":"dave","reason":"helps out"}`, 200)
	down.Store(false)
	applied, why, _ := settledOf(t, b)
	if applied == nil || *applied || !strings.Contains(why, "LLDAP") {
		t.Fatalf("answer = %s, want applied:false naming LLDAP", b)
	}
	if strings.Contains(why, "svc-password") || strings.Contains(why, "/") {
		t.Fatalf("why leaks the password: %q", why)
	}
	if !hasEntry(t, e.s.Directory, "eng", "dave") {
		t.Fatal("the entry wasn't stored")
	}
	if slices.Contains(e.ll.GroupMembers("eng"), "dave") {
		t.Fatal("dave in eng although LLDAP was down")
	}
	if err := os.Rename(cred+".off", cred); err != nil {
		t.Fatal(err)
	}
	b = mustDo(t, e.people, "root", "DELETE", "/api/directory/groups/eng/exceptions/dave", `{}`, 200)
	wantApplied(t, "remove after recovery", b)
	if hasEntry(t, e.s.Directory, "eng", "dave") {
		t.Fatal("the entry is still there")
	}
}

// An evaluation that hangs: the answer comes back within the 5 s bound,
// 200, applied:false naming the timeout; the change is stored.
func TestSettleTimeout(t *testing.T) {
	var block atomic.Bool
	release := make(chan struct{})
	e := newPeopleEnvWith(t, func(d *directory.Service) {
		cl := d.LLDAP.(*lldap.Client)
		target, _ := url.Parse(cl.HTTPURL)
		rp := httputil.NewSingleHostReverseProxy(target)
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if block.Load() {
				select {
				case <-r.Context().Done():
				case <-release:
				}
				http.Error(w, "blocked", http.StatusServiceUnavailable)
				return
			}
			rp.ServeHTTP(w, r)
		}))
		t.Cleanup(proxy.Close)
		t.Cleanup(func() { close(release) })
		cl.HTTPURL = proxy.URL
	})
	e.setup(t)
	e.ll.AddUser("dave", "dave@example.org", "Dave", "")
	e.s.callHook = func(method string, _ ...any) {
		if method == "Settle" {
			block.Store(true)
		}
	}
	start := time.Now()
	b := mustDo(t, e.people, "root", "POST", "/api/directory/groups/eng/members", `{"username":"dave","reason":"helps out"}`, 200)
	took := time.Since(start)
	block.Store(false)
	if took > 7*time.Second {
		t.Errorf("answered after %v, want ~5 s", took)
	}
	applied, why, _ := settledOf(t, b)
	if applied == nil || *applied || !strings.Contains(why, "timed out") {
		t.Fatalf("answer = %s, want applied:false naming the timeout", b)
	}
	if !hasEntry(t, e.s.Directory, "eng", "dave") {
		t.Fatal("the entry wasn't stored")
	}
}

// The MCP tool answers applied / why like the route (parity).
func TestMCPAddMemberApplied(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	e.ll.AddGroup("settlers")
	e.ll.AddUser("dave", "dave@example.org", "Dave", "")
	e.ll.AddUser("erin", "erin@example.org", "Erin", "")
	txt, isErr, _ := e.tool(t, "add_member", map[string]any{"group": "settlers", "username": "dave"})
	if isErr {
		t.Fatalf("add_member: %s", txt)
	}
	wantApplied(t, "add_member", txt)
	if !slices.Contains(e.ll.GroupMembers("settlers"), "dave") {
		t.Fatal("dave not in settlers")
	}
	r, body := doAs(t, e.hub, "root", "POST", "/api/directory/groups/settlers/members", `{"username":"erin"}`)
	if r.StatusCode != 200 {
		t.Fatalf("http add = %d %s", r.StatusCode, body)
	}
	if keySet(t, json.RawMessage(txt)) != keySet(t, json.RawMessage(body)) {
		t.Errorf("tool answer %s, http answer %s", txt, body)
	}
	txt, isErr, _ = e.tool(t, "remove_member", map[string]any{"group": "settlers", "username": "dave"})
	if isErr {
		t.Fatalf("remove_member: %s", txt)
	}
	wantApplied(t, "remove_member", txt)
}

// A refused mutation runs no evaluation and answers no applied.
func TestSettleNotOnRefusal(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	rec := &callRec{}
	e.s.callHook = rec.hook
	p := e.people
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/directory/groups/eng/members", `{"username":"nobody","reason":"x"}`},
		{"POST", "/api/directory/groups/eng/members", `{"username":"carl"}`}, // no reason
		{"DELETE", "/api/directory/groups/eng/exceptions/root", `{}`},
		{"PUT", "/api/directory/groups/eng/members/bob/expiry", `{"until":null}`},
		{"POST", "/api/directory/groups/nope/exceptions", `{"user":"bob","reason":"x","include":true}`},
	} {
		r, b := doAs(t, p, "root", c.method, c.path, c.body)
		if r.StatusCode < 400 {
			t.Errorf("%s %s = %d %s, want a refusal", c.method, c.path, r.StatusCode, b)
		}
		if strings.Contains(b, `"applied"`) {
			t.Errorf("%s %s answered %s", c.method, c.path, b)
		}
	}
	// bob is no admin of eng: refused by the gate.
	r, b := doAs(t, p, "bob", "POST", "/api/directory/groups/eng/members", `{"username":"carl","reason":"x"}`)
	if r.StatusCode != 403 {
		t.Errorf("bob add = %d %s", r.StatusCode, b)
	}
	for _, call := range rec.take() {
		if strings.HasPrefix(call, "Settle") {
			t.Errorf("a refused mutation settled: %q", call)
		}
	}
	tools := newToolEnv(t, nil, nil)
	trec := &callRec{}
	tools.s.callHook = trec.hook
	if txt, isErr, _ := tools.tool(t, "add_member", map[string]any{"group": "nope", "username": "nobody"}); !isErr {
		t.Errorf("add_member to nothing = %s", txt)
	}
	for _, call := range trec.take() {
		if strings.HasPrefix(call, "Settle") {
			t.Errorf("a refused tool call settled: %q", call)
		}
	}
}

// DELETE members on a rule group removes the "added by hand" entry
// (audited group.exception) and the person leaves at once; someone in by
// the rule alone is refused 409. The MCP remove_member alike.
func TestRemoveMemberRuleGroup(t *testing.T) {
	e := newPeopleEnv(t)
	e.setup(t)
	e.ll.AddUser("dave", "dave@example.org", "Dave", "")
	p := e.people
	mustDo(t, p, "root", "POST", "/api/directory/groups/eng/members", `{"username":"dave","reason":"helps out"}`, 200)
	if !slices.Contains(e.ll.GroupMembers("eng"), "dave") {
		t.Fatal("dave not added")
	}
	b := mustDo(t, p, "root", "DELETE", "/api/directory/groups/eng/members/dave", `{}`, 200)
	wantApplied(t, "remove by hand", b)
	if slices.Contains(e.ll.GroupMembers("eng"), "dave") || hasEntry(t, e.s.Directory, "eng", "dave") {
		t.Fatalf("dave still in eng (%v) or entry kept", e.ll.GroupMembers("eng"))
	}
	found := false
	for _, a := range readAudit(t, e.s.Directory.Audit.Path) {
		if a.Action == "group.exception" && a.Target == "eng" && a.Actor == "root" && strings.HasPrefix(a.Detail, "remove user=dave include=true") {
			found = true
		}
		if a.Action == "group.remove_member" && a.Target == "eng" {
			t.Errorf("audited as a membership removal: %+v", a)
		}
	}
	if !found {
		t.Error("no group.exception remove entry for dave")
	}
	// bob is in by the rule only.
	r, body := doAs(t, p, "root", "DELETE", "/api/directory/groups/eng/members/bob", `{}`)
	if r.StatusCode != 409 || !strings.Contains(body, "bob matches the rule of eng: keep them out instead") || strings.Contains(body, "applied") {
		t.Fatalf("remove bob = %d %s", r.StatusCode, body)
	}
	if !slices.Contains(e.ll.GroupMembers("eng"), "bob") {
		t.Fatal("bob removed")
	}
}

func TestMCPRemoveMemberRuleGroup(t *testing.T) {
	e, _ := directoryToolEnv(t)
	mustDo(t, e.hub, "root", "POST", "/api/directory/fields", `{"name":"team","label":"Team","kind":"text"}`, 200)
	e.ll.AddGroup("crew")
	e.ll.AddUser("gus", "gus@example.org", "Gus", "")
	e.ll.AddUser("hal", "hal@example.org", "Hal", "")
	mustDo(t, e.hub, "root", "PUT", "/api/directory/users/hal/details", `{"attrs":{"team":["x"]}}`, 200)
	mustDo(t, e.hub, "root", "POST", "/api/directory/groups/crew/convert", `{"rule":"team = \"x\"","preview":{"matching":["hal"],"kept_as_exception":[],"joining":["hal"],"expiry_dropped":[]}}`, 200)
	// add_exception on an unguarded rule group is W: no confirmation.
	txt, isErr, conf := e.tool(t, "add_exception", map[string]any{"group": "crew", "user": "gus", "include": true, "reason": "visiting"})
	if isErr || conf != "" {
		t.Fatalf("add_exception = %q %v (confirmation %q), want class W", txt, isErr, conf)
	}
	wantApplied(t, "add_exception", txt)
	if !slices.Contains(e.ll.GroupMembers("crew"), "gus") {
		t.Fatal("gus not in crew")
	}
	txt, isErr, _ = e.tool(t, "remove_member", map[string]any{"group": "crew", "username": "gus"})
	if isErr {
		t.Fatalf("remove_member gus = %s", txt)
	}
	wantApplied(t, "remove_member", txt)
	if slices.Contains(e.ll.GroupMembers("crew"), "gus") {
		t.Fatal("gus still in crew")
	}
	txt, isErr, _ = e.tool(t, "remove_member", map[string]any{"group": "crew", "username": "hal"})
	if !isErr || !strings.Contains(txt, "hal matches the rule of crew: keep them out instead") {
		t.Fatalf("remove_member hal = %q %v", txt, isErr)
	}
}

// Only admins see the evaluator's reasons.
func TestSettledForNonAdmin(t *testing.T) {
	admin := &directory.Caller{User: "root", Admin: true}
	delegate := &directory.Caller{User: "bob", Perms: map[string]bool{"invite": true}}
	if st := settledFor(admin, false, "stored, but not applied: x"); st.Why != "stored, but not applied: x" {
		t.Errorf("admin why = %q", st.Why)
	}
	if st := settledFor(delegate, false, "stored, but not applied: x"); st.Why != whyNotAdmin || st.Applied {
		t.Errorf("delegate = %+v", st)
	}
	if st := settledFor(delegate, true, ""); st.Why != "" || !st.Applied {
		t.Errorf("delegate ok = %+v", st)
	}
	if whyNotAdmin != "saved, not applied yet: it applies at the next directory sync" {
		t.Error(whyNotAdmin)
	}
}
