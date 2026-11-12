package httpapi

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/keycloak"
)

// Plan 4 Task 19: the Portcullis MCP's people tools on /mcp/people
// (contract §5.1, §15.9, §15.10; G1, G38, G39).

// peopleSelfTools are the people tools every signed-in person sees.
var peopleSelfTools = []string{"directory", "disconnect_ai", "my_ai_connections", "my_apps", "my_browser_certificate", "my_file_share_password", "my_password", "my_profile",
	"my_sign_in", "revoke_my_certificate"}

// peopleConnKC is the AI Keycloak with per-person connections (MyAI,
// DisconnectAI): revokes are recorded as user/client and drop the
// connection.
type peopleConnKC struct {
	aiScopesKC
	mu      sync.Mutex
	conns   map[string][]keycloak.AIConnection
	revoked []string
	// err: AIConnections and RevokeAIConnection fail (Keycloak down).
	err error
}

func (k *peopleConnKC) AIConnections(_ context.Context, user string, clients []string) ([]keycloak.AIConnection, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return nil, k.err
	}
	var out []keycloak.AIConnection
	for _, c := range k.conns[user] {
		if slices.Contains(clients, c.Client) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (k *peopleConnKC) RevokeAIConnection(_ context.Context, user, client string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return k.err
	}
	k.revoked = append(k.revoked, user+"/"+client)
	k.conns[user] = slices.DeleteFunc(k.conns[user], func(c keycloak.AIConnection) bool { return c.Client == client })
	return nil
}

// peopleToolEnv: the real tools, dana a delegate holding perms (through
// the group delegates), erin an ordinary person, the AI connections of
// alice and bob in Keycloak.
func peopleToolEnv(t *testing.T, perms ...string) (*toolEnv, *peopleConnKC) {
	t.Helper()
	gate := t.TempDir()
	e := newToolEnvWith(t, mcpEnvOpts{extra: map[string][2]string{"vault": {setVaultManifest, setVaultCompose}},
		cfg: func(c *hub.Config) { c.MCPGateDataDir = gate }})
	e.s.Directory.Invites = &markerInviter{}
	var log strings.Builder
	for i, u := range []string{"alice", "bob"} {
		b, _ := json.Marshal(map[string]any{"time": time.Now().UTC().Add(time.Duration(i) * time.Second).Format(time.RFC3339), "user": u, "client": mcpClient,
			"resource": aiappResource, "instance": "aiapp", "companion": "tok", "via": "direct", "method": "tools/call",
			"tool": "tool_of_" + u, "args_sha256": strings.Repeat("a", 64), "decision": "allow", "upstream_status": 200, "duration_ms": 3})
		log.Write(append(b, '\n'))
	}
	os.WriteFile(filepath.Join(gate, hub.AccessLogName), []byte(log.String()), 0o640)
	e.ll.AddUser("dana", "dana@example.org", "Dana", "")
	e.ll.AddUser("erin", "erin@example.org", "Erin", "")
	e.ll.AddGroup("delegates", "dana")
	for _, p := range perms {
		mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/"+p, `{"group":"delegates"}`, 200)
	}
	now := time.Now().UTC().Truncate(time.Second)
	kc := &peopleConnKC{conns: map[string][]keycloak.AIConnection{
		"alice": {{Client: keycloak.AIClientIDs.Claude, Consented: &now}},
		"bob":   {{Client: keycloak.AIClientIDs.ClaudeCode, Consented: &now}},
	}}
	e.s.Hub.SetAIKeycloak(kc)
	return e, kc
}

// people calls a people tool as user (2025-11-25: the text forms).
func (e *toolEnv) people(t *testing.T, user, tool string, args any) (string, bool) {
	t.Helper()
	return resultText(e.call(t, "/mcp/people", user, "2025-11-25", tool, args, nil))
}

// peopleAccept calls a people U tool on 2026-07-28 with the accept reply.
func (e *toolEnv) peopleAccept(t *testing.T, user, tool string, args any) (string, bool) {
	t.Helper()
	return resultText(e.call(t, "/mcp/people", user, "2026-07-28", tool, args, urlElicit,
		map[string]any{"inputResponses": map[string]any{secretFormInputKey: map[string]any{"action": "accept"}}}))
}

// peopleSchemas are the people tools' input property names, as listed to
// user.
func (e *toolEnv) peopleSchemas(t *testing.T, user string) map[string][]string {
	t.Helper()
	code, a := e.rpc(t, rpcCall{path: "/mcp/people", user: user, version: "2025-11-25", method: "tools/list", params: map[string]any{}})
	if code != 200 {
		t.Fatal(code)
	}
	out := map[string][]string{}
	for _, x := range a["result"].(map[string]any)["tools"].([]any) {
		tl := x.(map[string]any)
		s, _ := tl["inputSchema"].(map[string]any)
		props, _ := s["properties"].(map[string]any)
		names := []string{}
		for p := range props {
			names = append(names, p)
		}
		sort.Strings(names)
		out[tl["name"].(string)] = names
	}
	return out
}

func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		t.Fatalf("%v: %s", err, a)
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return reflect.DeepEqual(x, y)
}

// TestPeopleToolsCallerOnly (ruling 1): alice's my_apps is her GET
// /api/me/apps; no tool takes another username but the delegate tools;
// the delegate tools are listed only to holders of their permission (and
// admins), and refused when called anyway — "403: not allowed: needs
// <perm>", the twin's own refusal — audited refused via ai with the
// client, nothing run.
func TestPeopleToolsCallerOnly(t *testing.T) {
	e, _ := peopleToolEnv(t, directory.PermEditDetails)
	if got := e.list(t, "/mcp/people", "alice", "2025-11-25"); !slices.Equal(got, peopleSelfTools) {
		t.Errorf("alice's people tools = %v, want %v", got, peopleSelfTools)
	}
	if got, want := e.list(t, "/mcp/people", "dana", "2026-07-28"), append(slices.Clone(peopleSelfTools), "update_person"); !slices.Equal(got, sorted(want)) {
		t.Errorf("dana's people tools = %v, want %v", got, sorted(want))
	}
	if got, want := e.list(t, "/mcp/people", "root", "2025-06-18"), append(slices.Clone(peopleSelfTools), peopleDelegateTools...); !slices.Equal(got, sorted(want)) {
		t.Errorf("root's people tools = %v, want %v", got, sorted(want))
	}
	// my_apps = GET /api/me/apps for the same person (alice's vault
	// quota from office_milan; bob's apps aren't hers).
	e.ll.AddGroup("users_vault", "alice", "bob")
	e.ll.AddGroup("office_milan", "alice")
	opOK(t, e.hub, "POST", "/api/templates/enable", `{"id":"vault"}`)
	mustDo(t, e.hub, "root", "PUT", "/api/instances/vault/settings", `{"person":{"storage_quota":{"default":"10GiB","rows":[{"group":"office_milan","value":"1TiB"}]}}}`, 200)
	e.s.Hub.Wait()
	txt, isErr := e.people(t, "alice", "my_apps", map[string]any{})
	_, http := doAs(t, e.ppl, "alice", "GET", "/api/me/apps", "")
	if isErr || !jsonEqual(t, txt, http) || !strings.Contains(txt, `"1 TiB"`) {
		t.Errorf("alice's my_apps = %s (isError %v), GET /api/me/apps = %s", txt, isErr, http)
	}
	// Only the delegate tools take a username (or any other person).
	for name, props := range e.peopleSchemas(t, "root") {
		delegate := slices.Contains(peopleDelegateTools, name)
		if delegate != slices.Contains(props, "username") {
			t.Errorf("%s: properties %v (delegate %v)", name, props, delegate)
		}
		for _, p := range props {
			if !delegate && regexp.MustCompile(`(?i)user|person|member|who|name`).MatchString(p) {
				t.Errorf("%s takes %q: a caller-only tool names no one", name, p)
			}
		}
	}
	// Called anyway: refused with the twin's 403, audited, nothing done.
	for _, c := range []struct {
		tool, perm, action string
		args               map[string]any
	}{
		{"update_person", directory.PermEditDetails, "user.update", map[string]any{"username": "erin", "display_name": "X"}},
		{"invite_person", directory.PermInvite, "user.create", map[string]any{"username": "zed", "email": "zed@example.org", "display_name": "Zed"}},
		{"delete_person", directory.PermRemove, "user.delete", map[string]any{"username": "erin"}},
	} {
		n := len(readAudit(t, e.audit))
		txt, isErr := e.people(t, "alice", c.tool, c.args)
		if !isErr || txt != "403: not allowed: needs "+c.perm {
			t.Errorf("alice's %s = %q %v", c.tool, txt, isErr)
		}
		got := readAudit(t, e.audit)[n:]
		if len(got) != 1 || got[0].Action != c.action || got[0].Result != "refused" || got[0].Actor != "alice" || got[0].Via != "ai" || got[0].Client != mcpClient {
			t.Errorf("alice's %s audit = %+v", c.tool, got)
		}
	}
	if !e.ll.HasUser("erin") || e.ll.HasUser("zed") {
		t.Error("a refused delegate tool changed LLDAP")
	}
	// A holder: the same method as the twin, the directory's guardrails.
	if txt, isErr := e.people(t, "dana", "update_person", map[string]any{"username": "erin", "display_name": "Erin E."}); isErr {
		t.Errorf("dana's update_person erin = %q", txt)
	}
	if a := lastEntry(t, e, "user.update"); a.Actor != "dana" || a.Target != "erin" || a.Result != "ok" || a.Via != "ai" || a.Client != mcpClient {
		t.Errorf("update audit %+v", a)
	}
	if txt, isErr := e.people(t, "dana", "update_person", map[string]any{"username": "root", "display_name": "X"}); !isErr || !strings.HasPrefix(txt, "403: not allowed: root is an administrator") {
		t.Errorf("dana's update_person root = %q %v", txt, isErr)
	}
	// my_profile is the caller's own record.
	txt, _ = e.people(t, "dana", "my_profile", map[string]any{})
	var me struct {
		User   string   `json:"user"`
		Perms  []string `json:"perms"`
		Person struct {
			Username string `json:"username"`
		} `json:"person"`
	}
	if json.Unmarshal([]byte(txt), &me) != nil || me.User != "dana" || me.Person.Username != "dana" || !slices.Equal(me.Perms, []string{directory.PermEditDetails}) {
		t.Errorf("dana's my_profile = %s", txt)
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	sort.Strings(s)
	return s
}

// TestPeopleToolsNoAppScope: no people tool is an app, settings, drift
// or instance operation (§5.1: the people listener has none).
func TestPeopleToolsNoAppScope(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	tools := e.s.tools(ScopePeople)
	if len(tools) == 0 {
		t.Fatal("no people tools")
	}
	for _, tl := range tools {
		_, path, _ := strings.Cut(tl.Twin, " ")
		if path == "" {
			path = tl.Twin
		}
		for _, bad := range []string{"/api/templates", "/api/settings", "/api/drift", "/api/instances"} {
			if strings.HasPrefix(path, bad) || strings.Contains(tl.Name, strings.Trim(strings.TrimPrefix(bad, "/api/"), "s")+"_") {
				t.Errorf("people tool %s (twin %s) is under %s", tl.Name, tl.Twin, bad)
			}
		}
	}
	// No admin tool's name or twin leaks onto the people resource except
	// the delegate twins (§15.10: per scope, the same directory route).
	admin := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		admin[tl.Name] = tl
	}
	for _, tl := range tools {
		if a, ok := admin[tl.Name]; ok && (!slices.Contains(peopleDelegateTools, tl.Name) || a.Twin != tl.Twin) {
			t.Errorf("people tool %s shares an admin tool's name (twin %s vs %s)", tl.Name, tl.Twin, a.Twin)
		}
	}
}

var peopleConfirmTextRe = regexp.MustCompile(`open https://people\.example\.org/confirm/([A-Z2-7-]+), then ask me to try again\.$`)

// TestDelegateDeleteNeedsConfirmation (ruling 4): delete_person by a
// holder of remove asks for a confirmation on
// people.<d>/confirm/<id> (the people listener's, never the Hub's), with
// the typed check the person's name; nothing is deleted before approval;
// the approved retry deletes through the directory (audited via ai, the
// client and the confirmation); the directory's guardrails still apply
// after a confirmation (an administrator can't be removed by a delegate).
func TestDelegateDeleteNeedsConfirmation(t *testing.T) {
	e, _ := peopleToolEnv(t, directory.PermRemove)
	args := map[string]any{"username": "erin"}
	res := e.call(t, "/mcp/people", "dana", "2026-07-28", "delete_person", args, urlElicit)
	el := elicitation(t, res, confirmInputKey)
	if !strings.HasPrefix(el["url"].(string), "https://people.example.org/confirm/") {
		t.Fatalf("confirmation url %v", el["url"])
	}
	txt, _ := e.people(t, "dana", "delete_person", args)
	m := peopleConfirmTextRe.FindStringSubmatch(txt)
	if m == nil {
		// The 2025-11-25 call found the pending one: still waiting.
		if !strings.HasPrefix(txt, textStillWaiting) {
			t.Fatalf("delete_person (text form) = %q", txt)
		}
		m = []string{"", strings.TrimPrefix(el["url"].(string), "https://people.example.org/confirm/")}
	}
	id := m[1]
	if !e.ll.HasUser("erin") {
		t.Fatal("erin was deleted before the confirmation")
	}
	if _, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, id, "dana"); err == nil {
		t.Error("the people tool's confirmation is on the Hub listener")
	}
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerPeople, id, "dana")
	if err != nil {
		t.Fatal(err)
	}
	if v.Typed != "erin" || !strings.Contains(strings.Join(v.Consequences, " "), "erin") {
		t.Errorf("page typed %q, consequences %v", v.Typed, v.Consequences)
	}
	if _, err := e.s.Hub.ConfirmationPage(hub.ListenerPeople, id, "erin"); err == nil {
		t.Error("someone else sees dana's confirmation")
	}
	decidePeople(t, e, id, "dana", "erin")
	if txt, isErr := e.people(t, "dana", "delete_person", args); isErr {
		t.Fatalf("approved delete_person = %q", txt)
	}
	if e.ll.HasUser("erin") {
		t.Error("erin wasn't deleted")
	}
	if a := lastEntry(t, e, "user.delete"); a.Actor != "dana" || a.Target != "erin" || a.Result != "ok" || a.Via != "ai" || a.Client != mcpClient ||
		!strings.HasSuffix(a.Detail, "confirmation "+id) {
		t.Errorf("delete audit %+v", a)
	}
	// A guarded target (fix round 1): refused at once with the
	// directory's 403, audited refused via ai, no confirmation made.
	for _, target := range []string{"root", "dana", "admin", "portcullis-hub"} {
		n := len(readAudit(t, e.audit))
		txt, isErr := e.people(t, "dana", "delete_person", map[string]any{"username": target})
		if !isErr || !strings.HasPrefix(txt, "403: not allowed") || strings.Contains(txt, "/confirm/") {
			t.Errorf("dana's delete_person %s = %q %v, want the 403 at once", target, txt, isErr)
		}
		got := readAudit(t, e.audit)[n:]
		if len(got) != 1 || got[0].Action != "user.delete" || got[0].Result != "refused" || got[0].Via != "ai" || got[0].Client != mcpClient {
			t.Errorf("delete_person %s audit = %+v", target, got)
		}
	}
	if txt, _ := e.people(t, "dana", "delete_person", map[string]any{"username": "root"}); !strings.Contains(txt, "root is an administrator") {
		t.Errorf("delete_person root = %q", txt)
	}
	if !e.ll.HasUser("root") {
		t.Error("root was deleted by a delegate")
	}
}

func decidePeople(t *testing.T, e *toolEnv, id, user, typed string) {
	t.Helper()
	d := hub.Decision{Approve: true, Typed: typed, Proof: freshauth.Proof{Code: "good-code", CodeVerifier: strings.Repeat("v", 43), Nonce: "n0nce"}}
	if _, err := e.s.Hub.DecideConfirmation(context.Background(), hub.ListenerPeople, id, user, d); err != nil {
		t.Fatalf("decide %s: %v", id, err)
	}
}

// TestInvitePersonForm (ruling 3, T18's invite ruling): invite_person is
// U — the people page's invite form, pre-filled, where the link is shown
// to the delegate; core is never asked by the tool and nobody is created;
// accepted, it reports what the directory knows (exists, the caller's own
// newest invite), never the client's word and never a link.
func TestInvitePersonForm(t *testing.T) {
	e, _ := peopleToolEnv(t, directory.PermInvite)
	inv := e.s.Directory.Invites.(*markerInviter)
	args := map[string]any{"username": "frank", "email": "frank@example.org", "display_name": "Frank F"}
	txt, isErr := e.people(t, "dana", "invite_person", args)
	q := url.Values{"username": {"frank"}, "email": {"frank@example.org"}, "display_name": {"Frank F"}}
	form := "https://people.example.org/#invite?" + q.Encode()
	if !isErr || !strings.Contains(txt, form) {
		t.Errorf("invite_person = %q, want the form %s", txt, form)
	}
	res := e.call(t, "/mcp/people", "dana", "2026-07-28", "invite_person", args, urlElicit)
	if el := elicitation(t, res, secretFormInputKey); el["url"] != form {
		t.Errorf("elicitation url %v, want %s", el["url"], form)
	}
	txt, isErr = e.peopleAccept(t, "dana", "invite_person", args)
	var st map[string]any
	if isErr || json.Unmarshal([]byte(txt), &st) != nil || st["exists"] != false || st["last_invite"] != nil || st["pending"] != false {
		t.Errorf("accepted before anything was done = %s", txt)
	}
	if len(inv.users) != 0 || e.ll.HasUser("frank") {
		t.Fatal("the tool issued an invite or created the person")
	}
	// The delegate creates frank on the people page.
	mustDo(t, e.ppl, "dana", "POST", "/api/directory/users", `{"username":"frank","email":"frank@example.org","display_name":"Frank F","onboarding":"invite"}`, 200)
	txt, isErr = e.peopleAccept(t, "dana", "invite_person", args)
	noInviteLink(t, "invite_person", txt)
	st = nil
	if isErr || json.Unmarshal([]byte(txt), &st) != nil || st["exists"] != true || st["last_invite"] == nil || st["pending"] != true {
		t.Errorf("accepted after the invite = %s", txt)
	}
	// A secret-looking argument is refused with the form.
	if txt, isErr := e.people(t, "dana", "invite_person", map[string]any{"username": "frank", "email": "f@x", "display_name": "F", "password": "x"}); !isErr || !strings.HasPrefix(txt, textSecretArgs+"https://people.example.org/#invite?") {
		t.Errorf("password argument = %q", txt)
	}
}

// myAppsURL is an app link or companion URL of the test apps.
var myAppsURL = regexp.MustCompile(`"url":"https://aiapp\.example\.org(/mcp|/hdr/mcp)?"`)

// TestPeopleToolsStripped (G39, G1): directory and my_profile carry no
// invite link, password or server-invite internals (a server invite is
// the fixed text); my_file_share_password answers the People page's link
// only and creates nothing.
func TestPeopleToolsStripped(t *testing.T) {
	e, _ := peopleToolEnv(t)
	// An invite and a fallback password exist (HTTP), with marker values.
	mustDo(t, e.hub, "root", "POST", "/api/directory/users/erin/invite", `{}`, 200)
	pw := mustDo(t, e.hub, "root", "POST", "/api/directory/users/dana/password", `{"generate":true}`, 200)
	var p struct {
		Password string `json:"password"`
	}
	if json.Unmarshal([]byte(pw), &p) != nil || p.Password == "" {
		t.Fatalf("no generated password: %s", pw)
	}
	srvInv := regexp.MustCompile(`"server_invite":"([^"]*)"`)
	for _, user := range []string{"root", "alice"} {
		for _, tool := range []string{"directory", "my_profile", "my_apps", "my_ai_connections"} {
			txt, isErr := e.people(t, user, tool, map[string]any{})
			if isErr {
				t.Errorf("%s's %s = %q", user, tool, txt)
			}
			if tool == "my_apps" {
				// Task 21 (G13): My apps lists AI apps, with the app's
				// link and its companions' resource URLs; any other
				// "url" (an invite link) still fails below.
				txt = myAppsURL.ReplaceAllString(txt, "")
			}
			noInviteLink(t, tool, txt)
			if strings.Contains(txt, p.Password) {
				t.Errorf("%s's %s holds the password", user, tool)
			}
			for _, m := range srvInv.FindAllStringSubmatch(txt, -1) {
				if !regexp.MustCompile(`^run \./portcullis invite \S+ on the server$`).MatchString(m[1]) {
					t.Errorf("%s's %s server_invite %q", user, tool, m[1])
				}
			}
		}
	}
	if txt, _ := e.people(t, "root", "directory", map[string]any{}); !strings.Contains(txt, `"server_invite":"run ./portcullis invite root on the server"`) {
		t.Errorf("root's directory: no fixed server-invite text: %.300s", txt)
	}
	txt, isErr := e.people(t, "alice", "my_file_share_password", map[string]any{})
	var out map[string]any
	if isErr || json.Unmarshal([]byte(txt), &out) != nil || out["link"] != "https://people.example.org/#myapps" || len(out) != 2 {
		t.Errorf("my_file_share_password = %s", txt)
	}
	for _, a := range readAudit(t, e.audit) {
		if strings.HasPrefix(a.Action, "credential.") {
			t.Errorf("my_file_share_password made a credential change: %+v", a)
		}
	}
}

// TestDisconnectAIOwnOnly (ruling 7): my_ai_connections is the caller's
// own; disconnect_ai revokes the caller's own connection only (13b's
// DisconnectAI, audited ai.connection.revoke via ai), and a client that
// isn't one of the Hub's AI clients is 404.
func TestDisconnectAIOwnOnly(t *testing.T) {
	e, kc := peopleToolEnv(t)
	txt, isErr := e.people(t, "alice", "my_ai_connections", map[string]any{})
	if isErr || !strings.Contains(txt, keycloak.AIClientIDs.Claude) || strings.Contains(txt, keycloak.AIClientIDs.ClaudeCode) ||
		!strings.Contains(txt, "tool_of_alice") || strings.Contains(txt, "tool_of_bob") {
		t.Errorf("alice's my_ai_connections = %s", txt)
	}
	if txt, isErr := e.people(t, "alice", "disconnect_ai", map[string]any{"client": keycloak.AIClientIDs.ClaudeCode}); isErr {
		t.Errorf("disconnect_ai = %q", txt)
	}
	if txt, isErr := e.people(t, "alice", "disconnect_ai", map[string]any{"client": "grafana"}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("disconnect_ai grafana = %q %v", txt, isErr)
	}
	kc.mu.Lock()
	revoked := slices.Clone(kc.revoked)
	kc.mu.Unlock()
	if !slices.Equal(revoked, []string{"alice/" + keycloak.AIClientIDs.ClaudeCode}) {
		t.Errorf("revoked %v, want only alice's", revoked)
	}
	if a := lastEntry(t, e, "ai.connection.revoke"); a.Actor != "alice" || a.Target != "alice" || a.Via != "ai" || a.Client != mcpClient || a.Result != "ok" {
		t.Errorf("revoke audit %+v", a)
	}
}

// TestPeopleToolParity (ruling 8): every people tool's twin is a people
// listener route, never a
// Hub-only route; every caller-only app route of the people listener but
// the confirmation routes and the credential routes has a tool; W and D
// tools name their audit action; the classes are as ruled.
func TestPeopleToolParity(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	routes := map[string]bool{}
	for _, p := range e.s.peopleMux().patterns {
		routes[p] = true
	}
	tools := e.s.tools(ScopePeople)
	byName := map[string]Tool{}
	twins := map[string]bool{}
	for _, tl := range tools {
		byName[tl.Name] = tl
		twins[tl.Twin] = true
		if !routes[tl.Twin] {
			t.Errorf("people tool %s: twin %q is no people-listener route", tl.Name, tl.Twin)
		}
	}
	for _, r := range []string{"GET /api/me/apps", "GET /api/me/ai", "DELETE /api/me/ai/connections/{client}", "GET /api/directory", "GET /api/directory/me"} {
		if !twins[r] {
			t.Errorf("route %s has no people tool", r)
		}
	}
	// Final review hub-mcp M4: every people-listener route has a people
	// tool or a stated reason, so a new route can't pass silently.
	for r := range routes {
		why, none := peopleNoToolRoutes[r]
		switch {
		case twins[r] && none:
			t.Errorf("route %s has a people tool and is in peopleNoToolRoutes (%s)", r, why)
		case !twins[r] && !none:
			t.Errorf("people route %s: no people tool has it as Twin, and it isn't in peopleNoToolRoutes", r)
		case none && strings.TrimSpace(why) == "":
			t.Errorf("peopleNoToolRoutes %s: no reason", r)
		}
	}
	for r := range peopleNoToolRoutes {
		if !routes[r] {
			t.Errorf("peopleNoToolRoutes %s is no people-listener route", r)
		}
	}
	want := map[string]ToolClass{
		"my_apps": ClassRead, "my_profile": ClassRead, "directory": ClassRead, "my_ai_connections": ClassRead,
		"my_file_share_password": ClassRead, "disconnect_ai": ClassWrite,
		"update_person": ClassWrite, "invite_person": ClassSecret, "delete_person": ClassDestructive,
		"my_sign_in": ClassRead, "my_browser_certificate": ClassRead, "my_password": ClassRead, "revoke_my_certificate": ClassWrite,
		// Help to reset (sign-in part 2 Task 7): sign_in_help.
		"person_sign_in": ClassRead, "revoke_person_certificate": ClassDestructive, "remove_passkeys": ClassDestructive,
	}
	if len(tools) != len(want) {
		t.Errorf("%d people tools, want %d", len(tools), len(want))
	}
	for n, c := range want {
		if tl, ok := byName[n]; !ok || tl.Class != c {
			t.Errorf("people tool %s: class %q, want %q", n, tl.Class, c)
		}
	}
	for n, p := range map[string]string{"update_person": directory.PermEditDetails, "invite_person": directory.PermInvite, "delete_person": directory.PermRemove,
		"person_sign_in": directory.PermSignInHelp, "revoke_person_certificate": directory.PermSignInHelp, "remove_passkeys": directory.PermSignInHelp} {
		if byName[n].Perm != p {
			t.Errorf("%s: perm %q, want %q", n, byName[n].Perm, p)
		}
	}
	if byName["delete_person"].Twin != "DELETE /api/directory/users/{username}" || destructiveTwins[byName["delete_person"].Twin] == "" {
		t.Errorf("delete_person twin %q", byName["delete_person"].Twin)
	}
}

// TestPeopleDelegateToolsOffAggregate (G38): the gate keeps the people
// tools named in its delegate list out of "all my apps" (§15.9) — a name
// convention, so the delegate tools (those with a Perm) are exactly
// peopleDelegateTools, the gate's list.
func TestPeopleDelegateToolsOffAggregate(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	var perm []string
	for _, tl := range e.s.tools(ScopePeople) {
		if tl.Perm != "" {
			perm = append(perm, tl.Name)
		}
	}
	if !slices.Equal(sorted(perm), sorted(peopleDelegateTools)) {
		t.Errorf("delegate tools %v, the gate filters %v", perm, peopleDelegateTools)
	}
	if !slices.Equal(sorted(peopleDelegateTools), []string{"delete_person", "invite_person", "person_sign_in", "remove_passkeys", "revoke_person_certificate", "update_person"}) {
		t.Errorf("peopleDelegateTools = %v (G38)", peopleDelegateTools)
	}
}

// TestCoreAggregateDelegatesComplete (G38): the gate's delegateTools
// (mcp-gate/internal/aggregate) is exactly peopleDelegateTools (sibling
// core checkout, PORTCULLIS_CORE_DIR in CI; skipped without one).
func TestCoreAggregateDelegatesComplete(t *testing.T) {
	core := os.Getenv("PORTCULLIS_CORE_DIR")
	if core == "" {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	b, err := os.ReadFile(filepath.Join(core, "mcp-gate", "internal", "aggregate", "aggregate.go"))
	if err != nil {
		t.Skipf("no core checkout: %v", err)
	}
	m := regexp.MustCompile(`var delegateTools = \[\]string\{([^}]*)\}`).FindSubmatch(b)
	if m == nil {
		t.Fatal("the gate's delegateTools list wasn't found")
	}
	var gate []string
	for _, q := range regexp.MustCompile(`"([a-z_]+)"`).FindAllSubmatch(m[1], -1) {
		gate = append(gate, string(q[1]))
	}
	if !slices.Equal(sorted(gate), sorted(peopleDelegateTools)) {
		t.Errorf("the gate filters %v, the Hub's delegate tools are %v", gate, peopleDelegateTools)
	}
}

// TestPeopleToolsInjectedArgs (fix round 1): a caller-only tool given
// another person's name (or any undeclared argument) is refused — the
// schema has no such field — and nothing runs or changes.
func TestPeopleToolsInjectedArgs(t *testing.T) {
	e, kc := peopleToolEnv(t)
	n := len(readAudit(t, e.audit))
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"my_apps", map[string]any{"username": "bob"}},
		{"my_profile", map[string]any{"user": "bob"}},
		{"my_ai_connections", map[string]any{"username": "bob"}},
		{"disconnect_ai", map[string]any{"client": keycloak.AIClientIDs.ClaudeCode, "user": "bob"}},
		{"directory", map[string]any{"as": "root"}},
	} {
		txt, isErr := e.people(t, "alice", c.tool, c.args)
		if !isErr || strings.Contains(txt, "bob@example.org") || strings.Contains(txt, "tool_of_bob") {
			t.Errorf("%s %v = %q %v, want a refusal", c.tool, c.args, txt, isErr)
		}
	}
	kc.mu.Lock()
	revoked := slices.Clone(kc.revoked)
	kc.mu.Unlock()
	if len(revoked) != 0 {
		t.Errorf("revoked %v", revoked)
	}
	for _, a := range readAudit(t, e.audit)[n:] {
		if a.Result == "ok" {
			t.Errorf("an injected call changed something: %+v", a)
		}
	}
}

// peopleNoToolRoutes: people-listener routes without a people tool, each
// with its reason (TestPeopleToolParity).
var peopleNoToolRoutes = func() map[string]string {
	const delegate = "a delegate directory route the people MCP has no tool for: delegates use the people page (the admin MCP has the tool)"
	m := map[string]string{
		"/healthz":                        "health check, no data",
		"/":                               "the people page itself",
		"/static/":                        "the page's static assets",
		"GET /confirm/{id}":               "a confirmation page: only the person, in the browser, never the AI",
		"POST /api/me/confirmations/{id}": "a confirmation decision: only the person, in the browser, with a fresh passkey",
		"PUT /api/me/apps/{instance}/values/{key}":          "a person-entered value: the person enters it on the page",
		"DELETE /api/me/apps/{instance}/values/{key}":       "a person-entered value: cleared on the page",
		"DELETE /api/me/apps/{instance}/credentials/{key}":  "a credential revoke: the person does it on the page (credentials never go through the AI)",
		"GET /api/directory/audit":                          "the delegate audit view: on the page only",
		"GET /api/directory/users/{username}/apps":          "an admin-only read (403 here for everyone else): the admin MCP has get_person_apps",
		"GET /api/directory/groups/{group}/uses":            "an admin-only read (403 here for everyone else): the admin MCP has get_group_uses",
		"POST /api/directory/users/{username}/certificates": "issuing a YubiKey certificate: administrators only, on the person's Sign-in tab (the admin MCP's issue_yubikey_certificate hands off)",
	}
	for r, why := range helpNoToolRoutes {
		m[r] = why
	}
	for _, r := range []string{
		"POST /api/directory/users/{username}/password", "POST /api/directory/users/{username}/invite",
		"POST /api/directory/users/{username}/require-passkey", "POST /api/directory/users/{username}/clear-actions",
		"DELETE /api/directory/keycloak-stale/{username}",
		"POST /api/directory/groups", "DELETE /api/directory/groups/{group}",
		"POST /api/directory/groups/{group}/members", "DELETE /api/directory/groups/{group}/members/{username}",
		"POST /api/directory/fields", "PUT /api/directory/fields/{name}", "DELETE /api/directory/fields/{name}",
		"PUT /api/directory/users/{username}/details", "POST /api/directory/rules/preview",
		"PUT /api/directory/groups/{group}/rule", "POST /api/directory/groups/{group}/convert-preview",
		"POST /api/directory/groups/{group}/convert", "POST /api/directory/groups/{group}/exceptions",
		"DELETE /api/directory/groups/{group}/exceptions/{username}", "PUT /api/directory/groups/{group}/members/{username}/expiry",
		"PUT /api/directory/permissions/{perm}", "POST /api/directory/import/review", "POST /api/directory/import/apply",
	} {
		m[r] = delegate
	}
	for r, why := range signInNoToolRoutes {
		m[r] = why
	}
	return m
}()
