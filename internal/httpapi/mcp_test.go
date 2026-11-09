package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/web"
)

// Plan 4 Task 16: the Portcullis MCP core (contract §15.10, §15.6,
// §15.3; G16, G17, G18, G40), on a table of test tools — one per class
// on the admin scope, a read and a delegated write on the people scope.

const (
	mcpAdminURL  = "https://hub.example.org/mcp"
	mcpPeopleURL = "https://people.example.org/mcp"
	mcpClient    = "portcullis-ai-claude"
)

type thingArgs struct {
	ID string `json:"id"`
}

type secretFormArgs struct {
	Name string `json:"name"`
}

type mutedArgs struct {
	FindingToken string `json:"finding_token"`
}

// mcpTestEnv: the MCP listener with the test tools registered.
type mcpTestEnv struct {
	*confirmEnv
	mu     sync.Mutex
	runs   map[string]int
	result func(tool string, c *directory.Caller) any // nil: {"ok": tool}
	seen   []*directory.Caller
}

func newMCPTestEnv(t *testing.T) *mcpTestEnv {
	t.Helper()
	e := &mcpTestEnv{confirmEnv: newConfirmEnv(t), runs: map[string]int{}}
	// Only the test tools below (the real ones have their own tests).
	e.s.mcp.mu.Lock()
	e.s.mcp.tools = nil
	e.s.mcp.gen++
	e.s.mcp.mu.Unlock()
	run := func(name string) func(context.Context, *directory.Caller, json.RawMessage) (any, error) {
		return func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
			e.mu.Lock()
			e.runs[name]++
			e.seen = append(e.seen, c)
			f := e.result
			e.mu.Unlock()
			if f != nil {
				return f(name, c), nil
			}
			return map[string]any{"ok": name, "args": json.RawMessage(args), "confirmation": confirmationID(ctx)}, nil
		}
	}
	idOf := func(args json.RawMessage) string {
		var a thingArgs
		json.Unmarshal(args, &a)
		return a.ID
	}
	s := e.s
	s.registerTool(Tool{Name: "list_things", Description: "List things.", Class: ClassRead, Scope: ScopeAdmin, Twin: "GET /api/things",
		In: struct{}{}, Run: run("list_things")})
	s.registerTool(Tool{Name: "save_thing", Description: "Save a thing.", Class: ClassWrite, Scope: ScopeAdmin, Twin: "PUT /api/things/{id}",
		Audit: "thing.save", In: thingArgs{}, Run: run("save_thing")})
	s.registerTool(Tool{Name: "delete_thing", Description: "Delete a thing.", Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/things/{id}",
		Audit: "thing.delete", In: thingArgs{}, Typed: idOf,
		Consequences: func(_ context.Context, args json.RawMessage) []string {
			return []string{"Permanently removes thing " + idOf(args) + "."}
		},
		Run: run("delete_thing")})
	s.registerTool(Tool{Name: "set_thing_secret", Description: "Set a thing's secret.", Class: ClassSecret, Scope: ScopeAdmin, Twin: "PUT /api/things/{id}/secret",
		In: secretFormArgs{}, SecretForm: func(args json.RawMessage) string {
			var a secretFormArgs
			json.Unmarshal(args, &a)
			return "https://hub.example.org/#settings/things?name=" + a.Name
		}, Run: run("set_thing_secret")})
	s.registerTool(Tool{Name: "my_things", Description: "My things.", Class: ClassRead, Scope: ScopePeople, Twin: "GET /api/me/things",
		In: struct{}{}, Run: run("my_things")})
	s.registerTool(Tool{Name: "invite_person", Description: "Invite.", Class: ClassWrite, Scope: ScopePeople, Twin: "POST /api/directory/users",
		Perm: directory.PermInvite, Audit: "user.create", In: thingArgs{}, Run: run("invite_person")})
	return e
}

func (e *mcpTestEnv) runCount(tool string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runs[tool]
}

// rpcCall is one JSON-RPC request to the MCP listener.
type rpcCall struct {
	path, user, client, version string
	method, name                string // Mcp-Method / Mcp-Name (2026-07-28)
	params                      map[string]any
	caps                        map[string]any // 2026-07-28 _meta client capabilities
	headers                     map[string]string
	drop                        []string // headers left out
}

func resourceOf(path string) string {
	if path == "/mcp/admin" {
		return mcpAdminURL
	}
	return mcpPeopleURL
}

// rpc sends c → status, the JSON-RPC answer (decoded from JSON or SSE).
func (e *mcpTestEnv) rpc(t *testing.T, c rpcCall) (int, map[string]any) {
	t.Helper()
	params := map[string]any{}
	for k, v := range c.params {
		params[k] = v
	}
	if c.version == "2026-07-28" && c.method != "initialize" {
		caps := c.caps
		if caps == nil {
			caps = map[string]any{}
		}
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
			"io.modelcontextprotocol/clientCapabilities": caps,
			"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "test", "version": "1"},
		}
	} else if c.caps != nil && c.method != "initialize" {
		// A session-version client's capabilities (the stateless Hub never
		// saw its initialize): they must not turn on an input request.
		params["_meta"] = map[string]any{"io.modelcontextprotocol/clientCapabilities": c.caps}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": c.method, "params": params})
	req, _ := http.NewRequest("POST", e.mcp.URL+c.path, strings.NewReader(string(body)))
	h := map[string]string{
		"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
		MCPSecretHeader: testMCPSecret, "X-Forwarded-User": c.user, mcpClientHeader: c.client, mcpResourceHeader: resourceOf(c.path),
	}
	if c.client == "" {
		h[mcpClientHeader] = mcpClient
	}
	if c.version != "" {
		h["Mcp-Protocol-Version"] = c.version
	}
	if c.version == "2026-07-28" {
		h["Mcp-Method"] = c.method
		if c.name != "" {
			h["Mcp-Name"] = c.name
		} else if n, ok := c.params["name"].(string); ok {
			h["Mcp-Name"] = n
		} else if u, ok := c.params["uri"].(string); ok {
			h["Mcp-Name"] = u
		}
	}
	for k, v := range c.headers {
		h[k] = v
	}
	for _, k := range c.drop {
		delete(h, k)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	text := string(raw)
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		text = ""
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				text = d
			}
		}
	}
	var out map[string]any
	if json.Unmarshal([]byte(text), &out) != nil {
		out = map[string]any{"raw": string(raw)}
	}
	return resp.StatusCode, out
}

// call is a tools/call → its result object (fails on a protocol error).
func (e *mcpTestEnv) call(t *testing.T, path, user, version, tool string, args any, caps map[string]any, extra ...map[string]any) map[string]any {
	t.Helper()
	p := map[string]any{"name": tool, "arguments": args}
	for _, x := range extra {
		for k, v := range x {
			p[k] = v
		}
	}
	code, a := e.rpc(t, rpcCall{path: path, user: user, version: version, method: "tools/call", params: p, caps: caps})
	res, ok := a["result"].(map[string]any)
	if code != 200 || !ok {
		t.Fatalf("%s %s %s: %d %v", path, tool, version, code, a)
	}
	return res
}

// resultText is a tool result's text and isError.
func resultText(res map[string]any) (string, bool) {
	isErr, _ := res["isError"].(bool)
	cs, _ := res["content"].([]any)
	if len(cs) == 0 {
		return "", isErr
	}
	c, _ := cs[0].(map[string]any)
	s, _ := c["text"].(string)
	return s, isErr
}

var urlElicit = map[string]any{"elicitation": map[string]any{"url": map[string]any{}}}

func toolNames(t *testing.T, a map[string]any) []string {
	t.Helper()
	res, _ := a["result"].(map[string]any)
	ts, _ := res["tools"].([]any)
	var out []string
	for _, x := range ts {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	sort.Strings(out)
	return out
}

func (e *mcpTestEnv) list(t *testing.T, path, user, version string) []string {
	t.Helper()
	code, a := e.rpc(t, rpcCall{path: path, user: user, version: version, method: "tools/list", params: map[string]any{}})
	if code != 200 {
		t.Fatalf("tools/list %s %s: %d %v", path, user, code, a)
	}
	return toolNames(t, a)
}

// TestMCPServesBothScopes: /mcp/admin lists only admin tools, /mcp/people
// only people tools (root through it gets no admin tool), a delegate tool
// only to holders of its permission; annotations follow the class.
func TestMCPServesBothScopes(t *testing.T) {
	e := newMCPTestEnv(t)
	admin := []string{"delete_thing", "list_things", "save_thing", "set_thing_secret"}
	for _, v := range []string{"2026-07-28", "2025-11-25", "2025-06-18"} {
		if got := e.list(t, "/mcp/admin", "root", v); !slices.Equal(got, admin) {
			t.Errorf("%s admin tools = %v, want %v", v, got, admin)
		}
		if got := e.list(t, "/mcp/people", "root", v); !slices.Equal(got, []string{"invite_person", "my_things"}) {
			t.Errorf("%s root's people tools = %v", v, got)
		}
		if got := e.list(t, "/mcp/people", "alice", v); !slices.Equal(got, []string{"my_things"}) {
			t.Errorf("%s alice's people tools = %v (no invite permission)", v, got)
		}
	}
	// An admin tool's name on the people resource is unknown there.
	code, a := e.rpc(t, rpcCall{path: "/mcp/people", user: "root", version: "2025-11-25", method: "tools/call",
		params: map[string]any{"name": "list_things", "arguments": map[string]any{}}})
	if _, ok := a["error"]; !ok && code == 200 {
		if res, _ := a["result"].(map[string]any); res != nil {
			if _, isErr := resultText(res); !isErr {
				t.Errorf("list_things through /mcp/people answered %v", a)
			}
		}
	}
	if e.runCount("list_things") != 0 {
		t.Error("an admin tool ran through /mcp/people")
	}
	// Delegate tools are refused when called anyway.
	res := e.call(t, "/mcp/people", "alice", "2025-11-25", "invite_person", map[string]any{"id": "x"}, nil)
	if txt, isErr := resultText(res); !isErr || !strings.Contains(txt, "not allowed") || e.runCount("invite_person") != 0 {
		t.Errorf("alice's invite_person = %q %v", txt, isErr)
	}
	// Annotations.
	_, a = e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2025-06-18", method: "tools/list", params: map[string]any{}})
	ann := map[string]map[string]any{}
	for _, x := range a["result"].(map[string]any)["tools"].([]any) {
		m := x.(map[string]any)
		ann[m["name"].(string)], _ = m["annotations"].(map[string]any)
		if s, _ := m["inputSchema"].(map[string]any); s["additionalProperties"] != false {
			t.Errorf("%s: inputSchema %v, want additionalProperties false", m["name"], s)
		}
	}
	want := map[string][3]any{ // readOnly, destructive, idempotent
		"list_things": {true, nil, false}, "save_thing": {false, false, true},
		"delete_thing": {false, true, false}, "set_thing_secret": {false, false, true},
	}
	for n, w := range want {
		if ann[n]["readOnlyHint"] != w[0] || ann[n]["destructiveHint"] != w[1] || ann[n]["idempotentHint"] != w[2] {
			t.Errorf("%s annotations %v, want readOnly %v destructive %v idempotent %v", n, ann[n], w[0], w[1], w[2])
		}
	}
}

// TestMCPAdminRefusesNonAdmin: alice on /mcp/admin → every tool isError
// "admins only", nothing runs; W and D refusals audited refused with via
// and client.
func TestMCPAdminRefusesNonAdmin(t *testing.T) {
	e := newMCPTestEnv(t)
	args := map[string]any{"list_things": map[string]any{}, "save_thing": map[string]any{"id": "a"},
		"delete_thing": map[string]any{"id": "a"}, "set_thing_secret": map[string]any{"name": "a"}}
	for _, v := range []string{"2026-07-28", "2025-11-25"} {
		for tool, a := range args {
			res := e.call(t, "/mcp/admin", "alice", v, tool, a, urlElicit)
			if txt, isErr := resultText(res); !isErr || txt != "admins only" {
				t.Errorf("%s %s = %q %v, want isError admins only", v, tool, txt, isErr)
			}
			if e.runCount(tool) != 0 {
				t.Errorf("%s ran for alice", tool)
			}
		}
	}
	// Every other method (fix round 1): empty lists, "admins only" for
	// reads and prompts — nothing of the admin scope reaches alice.
	e.s.Docs = web.Docs
	e.s.mcp.mu.Lock()
	e.s.mcp.gen++
	e.s.mcp.mu.Unlock()
	for _, v := range []string{"2026-07-28", "2025-11-25"} {
		for method, key := range map[string]string{"tools/list": "tools", "resources/list": "resources",
			"resources/templates/list": "resourceTemplates", "prompts/list": "prompts"} {
			code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "alice", version: v, method: method, params: map[string]any{}})
			res, _ := a["result"].(map[string]any)
			if xs, ok := res[key].([]any); code != 200 || !ok || len(xs) != 0 {
				t.Errorf("%s alice %s = %d %v, want an empty %s", v, method, code, a, key)
			}
			// root still gets them.
			_, a = e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: v, method: method, params: map[string]any{}})
			if xs, _ := a["result"].(map[string]any)[key].([]any); len(xs) == 0 {
				t.Errorf("%s root %s empty", v, method)
			}
		}
		for _, c := range []rpcCall{
			{method: "resources/read", params: map[string]any{"uri": "portcullis://docs/integration-contracts"}},
			{method: "resources/read", params: map[string]any{"uri": "portcullis://templates/aiapp"}},
			{method: "prompts/get", name: "diagnose_app", params: map[string]any{"name": "diagnose_app", "arguments": map[string]any{"app": "aiapp"}}},
			{method: "completion/complete", params: map[string]any{"ref": map[string]any{"type": "ref/prompt", "name": "diagnose_app"}, "argument": map[string]any{"name": "app", "value": "a"}}},
		} {
			c.path, c.user, c.version = "/mcp/admin", "alice", v
			_, a := e.rpc(t, c)
			if errObj, _ := a["error"].(map[string]any); errObj == nil || errObj["message"] != "admins only" || a["result"] != nil {
				t.Errorf("%s alice %s %v = %v, want the JSON-RPC error admins only", v, c.method, c.params, a)
			}
		}
		if v == "2025-11-25" { // 2026-07-28 has no ping
			if code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "alice", version: v, method: "ping", params: map[string]any{}}); code != 200 || a["result"] == nil {
				t.Errorf("%s alice ping = %d %v", v, code, a)
			}
		}
	}
	got := map[string]int{}
	for _, a := range readAudit(t, e.audit) {
		if a.Result != "refused" || a.Actor != "alice" {
			continue
		}
		got[a.Action]++
		if a.Via != "ai" || a.Client != mcpClient || !strings.Contains(a.Detail, "admins only") {
			t.Errorf("refusal %+v: want via ai, client %s", a, mcpClient)
		}
	}
	if got["thing.save"] != 2 || got["thing.delete"] != 2 || len(got) != 2 {
		t.Errorf("refusals audited %v, want thing.save and thing.delete twice each, nothing for R or U", got)
	}
}

var confirmURLRe = regexp.MustCompile(`^https://hub\.example\.org/confirm/([A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2})$`)

// elicitation is the URL-mode elicitation of an input_required result.
func elicitation(t *testing.T, res map[string]any, key string) map[string]any {
	t.Helper()
	if res["resultType"] != "input_required" {
		t.Fatalf("result %v, want input_required", res)
	}
	reqs, _ := res["inputRequests"].(map[string]any)
	ir, _ := reqs[key].(map[string]any)
	el, _ := ir["params"].(map[string]any)
	if len(reqs) != 1 || ir["method"] != "elicitation/create" || el == nil {
		t.Fatalf("inputRequests %v, want only %s, an elicitation", reqs, key)
	}
	if el["mode"] != "url" || el["requestedSchema"] != nil {
		t.Fatalf("elicitation %v: want mode url, never a form", el)
	}
	return el
}

func (e *mcpTestEnv) decide(t *testing.T, id, typed string, approve bool) {
	t.Helper()
	d := hub.Decision{Approve: approve, Typed: typed, Proof: freshauth.Proof{Code: "good-code", CodeVerifier: strings.Repeat("v", 43), Nonce: "n0nce"}}
	if _, err := e.s.Hub.DecideConfirmation(context.Background(), hub.ListenerHub, id, "root", d); err != nil {
		t.Fatalf("decide %s: %v", id, err)
	}
}

// TestMCPDestructiveNeedsConfirmation (§15.6, G17): the first call of a D
// tool creates a confirmation on the Hub listener: a 2026-07-28 client
// that declared URL elicitation gets an InputRequiredResult to
// https://hub.example.org/confirm/<id>, every other client (2026-07-28
// without the capability, 2025-11-25, 2025-06-18) the text — never
// elicitation/create; Run isn't called; a retry while pending waits;
// after approval the identical retry (any key order) runs once; a third
// call needs a new confirmation; a decline is reported; over the limit
// the text of G27.
func TestMCPDestructiveNeedsConfirmation(t *testing.T) {
	e := newMCPTestEnv(t)
	res := e.call(t, "/mcp/admin", "root", "2026-07-28", "delete_thing", map[string]any{"id": "x"}, urlElicit)
	el := elicitation(t, res, confirmInputKey)
	m := confirmURLRe.FindStringSubmatch(el["url"].(string))
	if m == nil || el["elicitationId"] != m[1] || el["message"] != "delete_thing on Portcullis (admin) needs your confirmation in your browser." {
		t.Fatalf("elicitation %v", el)
	}
	id := m[1]
	if e.runCount("delete_thing") != 0 {
		t.Fatal("Run called before the confirmation")
	}
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, id, "root")
	if err != nil {
		t.Fatal(err)
	}
	if v.Typed != "x" || v.Resource != mcpAdminURL || v.Tool != "delete_thing" || v.Arguments != `{"id":"x"}` ||
		v.Client != mcpClient || !slices.Equal(v.Consequences, []string{"Permanently removes thing x."}) {
		t.Errorf("confirmation %+v", v)
	}
	if _, err := e.s.Hub.ConfirmationPage(hub.ListenerPeople, id, "root"); err == nil {
		t.Error("an admin tool's confirmation is on the people listener")
	}
	// Retries while pending: every version waits.
	for _, ver := range []string{"2026-07-28", "2025-11-25", "2025-06-18"} {
		res = e.call(t, "/mcp/admin", "root", ver, "delete_thing", map[string]any{"id": "x"}, urlElicit)
		if txt, isErr := resultText(res); !isErr || txt != "Still waiting for your confirmation in your browser" {
			t.Errorf("%s pending retry = %q %v", ver, txt, isErr)
		}
	}
	// Without the capability, and on the session versions: the text only.
	textRe := regexp.MustCompile(`^This needs your confirmation in your browser: open (https://hub\.example\.org/confirm/[A-Z2-7-]+), then ask me to try again\.$`)
	for i, ver := range []string{"2026-07-28", "2025-11-25", "2025-06-18"} {
		res = e.call(t, "/mcp/admin", "root", ver, "delete_thing", map[string]any{"id": "t" + string(rune('0'+i))}, nil)
		if txt, isErr := resultText(res); !isErr || !textRe.MatchString(txt) || res["resultType"] == "input_required" {
			t.Errorf("%s without capability = %q %v %v", ver, txt, isErr, res)
		}
	}
	// The session versions never get an input request, even if their
	// initialize declared URL elicitation (stateless: no elicitation/create).
	res = e.call(t, "/mcp/admin", "root", "2025-11-25", "delete_thing", map[string]any{"id": "s"}, urlElicit)
	if txt, _ := resultText(res); !textRe.MatchString(txt) {
		t.Errorf("2025-11-25 = %q", txt)
	}
	if e.runCount("delete_thing") != 0 {
		t.Fatal("Run called without an approved confirmation")
	}
	// Approved: the identical retry (other key order and spacing) runs once.
	e.decide(t, id, "x", true)
	res = e.call(t, "/mcp/admin", "root", "2026-07-28", "delete_thing", json.RawMessage(` { "id" : "x" } `), urlElicit)
	txt, isErr := resultText(res)
	if isErr || e.runCount("delete_thing") != 1 || !strings.Contains(txt, `"confirmation":"`+id+`"`) {
		t.Fatalf("approved retry = %q %v (runs %d)", txt, isErr, e.runCount("delete_thing"))
	}
	// A third call: a new confirmation.
	res = e.call(t, "/mcp/admin", "root", "2026-07-28", "delete_thing", map[string]any{"id": "x"}, urlElicit)
	el = elicitation(t, res, confirmInputKey)
	if m2 := confirmURLRe.FindStringSubmatch(el["url"].(string)); m2 == nil || m2[1] == id {
		t.Errorf("third call elicitation %v, want a new confirmation", el)
	}
	if e.runCount("delete_thing") != 1 {
		t.Error("the consumed confirmation ran again")
	}
	// A cancelled URL elicitation is reported, nothing runs.
	res = e.call(t, "/mcp/admin", "root", "2026-07-28", "delete_thing", map[string]any{"id": "x"}, urlElicit,
		map[string]any{"inputResponses": map[string]any{confirmInputKey: map[string]any{"action": "cancel"}}})
	if txt, _ := resultText(res); txt != "You cancelled the confirmation; nothing was done" {
		t.Errorf("cancelled = %q", txt)
	}
	// Declined.
	res = e.call(t, "/mcp/admin", "root", "2025-11-25", "delete_thing", map[string]any{"id": "d"}, nil)
	txt, _ = resultText(res)
	did := textRe.FindStringSubmatch(txt)
	if did == nil {
		t.Fatalf("decline setup %q", txt)
	}
	e.decide(t, confirmURLRe.FindStringSubmatch(did[1])[1], "", false)
	res = e.call(t, "/mcp/admin", "root", "2025-11-25", "delete_thing", map[string]any{"id": "d"}, nil)
	if txt, _ := resultText(res); txt != "You declined this in your browser" {
		t.Errorf("declined = %q", txt)
	}
	// Over the limit (G27: 10 an hour; 7 made above).
	for i := 0; ; i++ {
		res = e.call(t, "/mcp/admin", "root", "2025-11-25", "delete_thing", map[string]any{"id": "limit-" + string(rune('a'+i))}, nil)
		txt, _ := resultText(res)
		if txt == "Too many confirmations requested; try again later" {
			break
		}
		if i > 10 || !textRe.MatchString(txt) {
			t.Fatalf("limit: %d %q", i, txt)
		}
	}
	refused := 0
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "ai.confirm" && a.Result == "refused" && a.Via == "ai" && a.Client == mcpClient {
			refused++
		}
	}
	if refused != 1 {
		t.Errorf("ai.confirm refused audited %d times, want 1", refused)
	}
	if e.runCount("delete_thing") != 1 {
		t.Error("D tool ran without its confirmation")
	}
}

// TestMCPSecretArgsRefused (G16): an argument named like a secret, or
// any undeclared one, is refused with the text and the form's URL; a U
// tool refuses every secret-looking name; registration refuses
// unreviewed secret-looking names.
func TestMCPSecretArgsRefused(t *testing.T) {
	e := newMCPTestEnv(t)
	for _, a := range []map[string]any{{"id": "a", "apiKey": "x"}, {"id": "a", "db_password": "x"}, {"id": "a", "other": 1}, {"ID": "a"}} {
		res := e.call(t, "/mcp/admin", "root", "2025-11-25", "save_thing", a, nil)
		if txt, isErr := resultText(res); !isErr || txt != "secrets are never passed through the AI; use https://hub.example.org/" {
			t.Errorf("save_thing %v = %q %v", a, txt, isErr)
		}
	}
	res := e.call(t, "/mcp/admin", "root", "2026-07-28", "set_thing_secret", map[string]any{"name": "n1", "token": "x"}, urlElicit)
	if txt, isErr := resultText(res); !isErr || txt != "secrets are never passed through the AI; use https://hub.example.org/#settings/things?name=n1" {
		t.Errorf("set_thing_secret with token = %q %v", txt, isErr)
	}
	res = e.call(t, "/mcp/people", "alice", "2025-11-25", "my_things", map[string]any{"password": "x"}, nil)
	if txt, _ := resultText(res); txt != "secrets are never passed through the AI; use https://people.example.org/" {
		t.Errorf("my_things with password = %q", txt)
	}
	// Schema errors are plain refusals.
	res = e.call(t, "/mcp/admin", "root", "2025-11-25", "save_thing", map[string]any{"id": 5}, nil)
	if txt, isErr := resultText(res); !isErr || !strings.HasPrefix(txt, "invalid arguments") {
		t.Errorf("save_thing {id: 5} = %q", txt)
	}
	res = e.call(t, "/mcp/admin", "root", "2025-11-25", "save_thing", json.RawMessage(`{"id":"a","id":"b"}`), nil)
	if txt, _ := resultText(res); !strings.HasPrefix(txt, "invalid arguments") {
		t.Errorf("duplicate keys = %q", txt)
	}
	// The gate's canon rules (fix round 1): what the gate can't pass on
	// unchanged, the Hub refuses too.
	for _, raw := range []string{`{"id":"\u2028"}`, `{"id":"a","n":0.30000000000000000001}`, `{"id":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}`} {
		res = e.call(t, "/mcp/admin", "root", "2025-11-25", "save_thing", json.RawMessage(raw), nil)
		if txt, _ := resultText(res); !strings.HasPrefix(txt, "invalid arguments") {
			t.Errorf("%s = %q", raw, txt)
		}
	}
	for _, n := range []string{"save_thing", "set_thing_secret", "my_things"} {
		if e.runCount(n) != 0 {
			t.Errorf("%s ran with refused arguments", n)
		}
	}
	// Registration.
	type apiKeyArgs struct {
		APIKey string `json:"api_key"`
	}
	run := func(context.Context, *directory.Caller, json.RawMessage) (any, error) { return nil, nil }
	if _, err := checkTool(Tool{Name: "x", Description: "x", Class: ClassRead, Scope: ScopeAdmin, Twin: "GET /x", In: apiKeyArgs{}, Run: run}, nil); err == nil {
		t.Error("api_key registered")
	}
	if _, err := checkTool(Tool{Name: "x", Description: "x", Class: ClassWrite, Audit: "doctor.mute", Scope: ScopeAdmin, Twin: "POST /x", In: mutedArgs{}, Run: run}, nil); err != nil {
		t.Errorf("finding_token (allowlisted): %v", err)
	}
	if _, err := checkTool(Tool{Name: "x", Description: "x", Class: ClassSecret, Scope: ScopeAdmin, Twin: "PUT /x", In: mutedArgs{},
		SecretForm: func(json.RawMessage) string { return "" }, Run: run}, nil); err == nil {
		t.Error("a U tool registered a secret-looking name")
	}
}

// TestNoSecretArgNames (G16): every tool the Hub registers declares only
// names secretArgRe doesn't match, or reviewed ones with a reason.
func TestNoSecretArgNames(t *testing.T) {
	for n, why := range mcpSecretNameAllow {
		if !secretArgRe.MatchString(n) || strings.TrimSpace(why) == "" {
			t.Errorf("allowlist %q: %q (must match secretArgRe and give a reason)", n, why)
		}
	}
	for n, why := range mcpFreeFormAllow {
		if strings.TrimSpace(why) == "" {
			t.Errorf("free-form allowlist %q has no reason", n)
		}
	}
	// checkTool walks the whole argument type (fix round 1).
	type inner struct {
		DBPassword string `json:"db_password"`
	}
	type nested struct {
		Outer inner `json:"outer"`
	}
	type inSlice struct {
		Rows []inner `json:"rows"`
	}
	type withMap struct {
		Values map[string]string `json:"values"`
	}
	type withAny struct {
		Value any `json:"value"`
	}
	type withRaw struct {
		Doc json.RawMessage `json:"doc"`
	}
	type embedded struct {
		inner
		ID string `json:"id"`
	}
	type okNested struct {
		Outer struct {
			FindingToken string `json:"finding_token"`
			Name         string `json:"name"`
		} `json:"outer"`
	}
	run := func(context.Context, *directory.Caller, json.RawMessage) (any, error) { return nil, nil }
	tool := func(in any, class ToolClass) Tool {
		t := Tool{Name: "x", Description: "x", Class: class, Scope: ScopeAdmin, Twin: "PUT /x", Audit: "x.save", In: in, Run: run}
		if class == ClassSecret {
			t.SecretForm = func(json.RawMessage) string { return "" }
		}
		return t
	}
	for name, in := range map[string]any{"nested": nested{}, "slice": inSlice{}, "map": withMap{}, "any": withAny{},
		"raw": withRaw{}, "embedded": embedded{}, "pointer": &nested{}} {
		if _, err := checkTool(tool(in, ClassWrite), nil); err == nil {
			t.Errorf("%s: registered", name)
		}
	}
	if _, err := checkTool(tool(okNested{}, ClassWrite), nil); err != nil {
		t.Errorf("an allowlisted nested name: %v", err)
	}
	if _, err := checkTool(tool(okNested{}, ClassSecret), nil); err == nil {
		t.Error("a U tool registered a nested secret-looking name")
	}
	mcpFreeFormAllow["x.values"] = "test"
	_, err := checkTool(tool(withMap{}, ClassWrite), nil)
	delete(mcpFreeFormAllow, "x.values")
	if err != nil {
		t.Errorf("an allowlisted map field: %v", err)
	}
	s := &Server{}
	s.registerMCPTools() // panics on an unreviewed name or type (checkTool)
	for _, scope := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range s.mcp.tools[scope] {
			for p := range tl.props {
				if secretArgRe.MatchString(p) && (mcpSecretNameAllow[p] == "" || tl.Class == ClassSecret) {
					t.Errorf("%s %s: argument %s", scope, tl.Name, p)
				}
			}
		}
	}
}

// TestMCPSecretFormElicitation: a U tool answers the URL of its form — a
// URL-mode elicitation for a 2026-07-28 client that declared it, else
// the link as text — never a form; Run runs only after the person
// accepted it.
func TestMCPSecretFormElicitation(t *testing.T) {
	e := newMCPTestEnv(t)
	form := "https://hub.example.org/#settings/things?name=n1"
	res := e.call(t, "/mcp/admin", "root", "2026-07-28", "set_thing_secret", map[string]any{"name": "n1"}, urlElicit)
	if el := elicitation(t, res, secretFormInputKey); el["url"] != form {
		t.Errorf("elicitation %v", el)
	}
	// 2026-07-28 without the capability, and the session versions even
	// when they declare it: the link as text.
	for i, ver := range []string{"2026-07-28", "2025-11-25", "2025-06-18"} {
		caps := urlElicit
		if i == 0 {
			caps = nil
		}
		res = e.call(t, "/mcp/admin", "root", ver, "set_thing_secret", map[string]any{"name": "n1"}, caps)
		if txt, isErr := resultText(res); !isErr || !strings.Contains(txt, form) || res["resultType"] == "input_required" {
			t.Errorf("%s = %q %v", ver, txt, isErr)
		}
	}
	if e.runCount("set_thing_secret") != 0 {
		t.Fatal("U tool ran before its form")
	}
	res = e.call(t, "/mcp/admin", "root", "2026-07-28", "set_thing_secret", map[string]any{"name": "n1"}, urlElicit,
		map[string]any{"inputResponses": map[string]any{secretFormInputKey: map[string]any{"action": "accept"}}})
	if _, isErr := resultText(res); isErr || e.runCount("set_thing_secret") != 1 {
		t.Errorf("after accept: %v runs %d", res, e.runCount("set_thing_secret"))
	}
}

// TestMCPOutputRedacted (G40): a result holding an instance's secret,
// the Hub's file secrets and an invite link is redacted; the set follows
// a change; over 1 MiB is clipped after redaction; an unreadable secret
// hides the result.
func TestMCPOutputRedacted(t *testing.T) {
	e := newMCPTestEnv(t)
	envFile := filepath.Join(e.data, "env", "aiapp.env")
	hdr := readEnvValue(t, envFile, "HDR_SECRET")
	if len(hdr) < 16 {
		t.Fatalf("HDR_SECRET %q", hdr)
	}
	fileSecret := filepath.Join(t.TempDir(), "invite-secret")
	os.WriteFile(fileSecret, []byte("invite-api-secret-0123456789abcdef\n"), 0o600)
	e.s.RedactFiles = []string{fileSecret, filepath.Join(t.TempDir(), "missing")}
	var out string
	e.result = func(string, *directory.Caller) any { return map[string]string{"v": out} }
	check := func(what string, secrets ...string) string {
		t.Helper()
		res := e.call(t, "/mcp/admin", "root", "2025-11-25", "list_things", map[string]any{}, nil)
		txt, isErr := resultText(res)
		if isErr {
			t.Fatalf("%s: %q", what, txt)
		}
		for _, s := range secrets {
			if strings.Contains(txt, s) {
				t.Errorf("%s: %q leaked in %q", what, s, txt)
			}
		}
		return txt
	}
	// Another instance's secret (no view: only its env file is left).
	os.WriteFile(filepath.Join(e.data, "env", "gone.env"), []byte("API_TOKEN='other-instance-token-42'\n"), 0o600)
	out = "other=other-instance-token-42 hdr=" + hdr + " proxy=" + testSecret + " gate=" + testMCPSecret + " invite-file=invite-api-secret-0123456789abcdef link=https://enroll.example.org/invite/abcDEF123"
	txt := check("first", "other-instance-token-42", hdr, testSecret, testMCPSecret, "invite-api-secret", "abcDEF123")
	if !strings.Contains(txt, "[redacted]") || !strings.Contains(txt, "[invite link hidden]") {
		t.Errorf("result %q", txt)
	}
	// The cached set follows a change of the env file.
	newHdr := "rotated-secret-value-0123456789"
	b, _ := os.ReadFile(envFile)
	os.WriteFile(envFile, []byte(strings.ReplaceAll(string(b), hdr, newHdr)), 0o600)
	out = "new=" + newHdr
	check("after change", newHdr)
	// Redact, then clip: a secret across the 1 MiB boundary leaves no prefix.
	out = strings.Repeat("a", maxToolResult-200) + newHdr + strings.Repeat("c", 150) + newHdr + strings.Repeat("b", 1<<20)
	txt = check("clipped", newHdr, newHdr[:8])
	if len(txt) > maxToolResult || !strings.HasSuffix(txt, textClipped) || !strings.Contains(txt, "[redacted]") {
		t.Errorf("clipped result: %d bytes, suffix %q", len(txt), txt[max(0, len(txt)-60):])
	}
	// The Keycloak admin password (a value the Hub holds, not a file).
	e.s.RedactLiterals = []string{"kc-admin-password-0123456789"}
	out = "kc=kc-admin-password-0123456789"
	check("keycloak admin password", "kc-admin-password-0123456789")
	// A file replaced by rename with the same size and mtime: only its
	// inode changed, and the cached set follows (fix round 1).
	replaceSameStat := func(path, old, new string) {
		t.Helper()
		if len(old) != len(new) {
			t.Fatal("same length needed")
		}
		fi, _ := os.Stat(path)
		b, _ := os.ReadFile(path)
		tmp := path + ".new"
		os.WriteFile(tmp, []byte(strings.ReplaceAll(string(b), old, new)), 0o600)
		os.Chtimes(tmp, fi.ModTime(), fi.ModTime())
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
		if fj, _ := os.Stat(path); fj.Size() != fi.Size() || !fj.ModTime().Equal(fi.ModTime()) {
			t.Fatal("size or mtime changed")
		}
	}
	out = "warm"
	check("warm")
	replaceSameStat(fileSecret, "invite-api-secret-0123456789abcdef", "invite-api-secret-ZYXWVUTSRQabcdef")
	out = "file=invite-api-secret-ZYXWVUTSRQabcdef"
	check("file secret replaced, same size and mtime", "invite-api-secret-ZYXWVUTSRQabcdef")
	sameLen := strings.Repeat("q", len(newHdr)-4) + "wxyz"
	replaceSameStat(envFile, newHdr, sameLen)
	out = "env=" + sameLen
	check("env file replaced, same size and mtime", sameLen)
	// An unreadable file secret hides the result.
	e.s.RedactFiles = []string{t.TempDir()} // a directory: exists, can't be read as a file
	res := e.call(t, "/mcp/admin", "root", "2025-11-25", "list_things", map[string]any{}, nil)
	if txt, isErr := resultText(res); !isErr || txt != "result hidden: secrets couldn't be read" {
		t.Errorf("unreadable secret: %q %v", txt, isErr)
	}
}

func readEnvValue(t *testing.T, path, key string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return strings.Trim(v, "'\"")
		}
	}
	t.Fatalf("%s: no %s", path, key)
	return ""
}

// setEnvLine sets key=value (raw) in an instance's .env, keeping every
// other line (a value a template or an old Expert save left there).
func setEnvLine(t *testing.T, path, key, value string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l != "" && !strings.HasPrefix(l, key+"=") {
			out = append(out, l)
		}
	}
	out = append([]string{key + "=" + value}, out...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestMCPProtocolVersions (§15.3): exactly the three versions, from the
// header or initialize's body; anything else 400; a 2026-07-28 header
// that doesn't match the body is -32020.
func TestMCPProtocolVersions(t *testing.T) {
	e := newMCPTestEnv(t)
	init := func(v string) map[string]any {
		return map[string]any{"protocolVersion": v, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "1"}}
	}
	for _, v := range []string{"2025-11-25", "2025-06-18"} {
		code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: v, method: "initialize", params: init(v)})
		if res, _ := a["result"].(map[string]any); code != 200 || res["protocolVersion"] != v {
			t.Errorf("initialize %s = %d %v", v, code, a)
		}
	}
	code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2026-07-28", method: "server/discover", params: map[string]any{}})
	if res, _ := a["result"].(map[string]any); code != 200 || !slices.Equal(anyStrings(res["supportedVersions"]), []string{"2026-07-28", "2025-11-25", "2025-06-18"}) {
		t.Errorf("server/discover = %d %v", code, a)
	}
	for _, c := range []rpcCall{
		{method: "tools/list", params: map[string]any{}}, // no version at all
		{method: "tools/call", params: map[string]any{"name": "list_things", "arguments": map[string]any{}}},
		{version: "2025-03-26", method: "tools/list", params: map[string]any{}},
		{version: "2027-01-01", method: "tools/list", params: map[string]any{}},
		{method: "initialize", params: init("2025-03-26")},
		{version: "2025-06-18", method: "initialize", params: init("2025-11-25")},
	} {
		c.path, c.user = "/mcp/admin", "root"
		code, a := e.rpc(t, c)
		if code != 400 {
			t.Errorf("%s %s %v = %d %v, want 400", c.version, c.method, c.params["protocolVersion"], code, a)
		}
	}
	code, a = e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2026-07-28", method: "tools/call", name: "save_thing",
		params: map[string]any{"name": "list_things", "arguments": map[string]any{}}})
	if errObj, _ := a["error"].(map[string]any); code != 400 || errObj["code"] != float64(-32020) {
		t.Errorf("Mcp-Name mismatch = %d %v, want 400 -32020", code, a)
	}
	code, a = e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2026-07-28", method: "tools/call",
		headers: map[string]string{"Mcp-Method": "tools/list"}, params: map[string]any{"name": "list_things", "arguments": map[string]any{}}})
	if errObj, _ := a["error"].(map[string]any); code != 400 || errObj["code"] != float64(-32020) {
		t.Errorf("Mcp-Method mismatch = %d %v, want 400 -32020", code, a)
	}
	if e.runCount("list_things") != 0 {
		t.Error("a refused request ran a tool")
	}
}

func anyStrings(v any) []string {
	var out []string
	xs, _ := v.([]any)
	for _, x := range xs {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// TestMCPIdentityOnlyFromGate: without the gate's X-Forwarded-User the
// listener refuses (403, mcpRoute: the identity check of Task 13a); the
// request's X-Portcullis-AI-Client is the Caller's Client (via ai) and
// the audit's client.
func TestMCPIdentityOnlyFromGate(t *testing.T) {
	e := newMCPTestEnv(t)
	code, _ := e.rpc(t, rpcCall{path: "/mcp/admin", version: "2025-11-25", method: "tools/list", params: map[string]any{}, drop: []string{"X-Forwarded-User"}})
	if code != http.StatusForbidden {
		t.Errorf("no X-Forwarded-User = %d, want 403", code)
	}
	code, _ = e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2025-11-25", method: "tools/list", params: map[string]any{}, drop: []string{mcpClientHeader}})
	if code != http.StatusForbidden {
		t.Errorf("no AI client = %d, want 403", code)
	}
	code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "Root", client: "portcullis-ai-generic", version: "2025-11-25", method: "tools/call",
		params: map[string]any{"name": "save_thing", "arguments": map[string]any{"id": "a"}}})
	if code != 200 || a["result"] == nil {
		t.Fatalf("save_thing = %d %v", code, a)
	}
	e.mu.Lock()
	c := e.seen[len(e.seen)-1]
	e.mu.Unlock()
	if c.User != "root" || c.Via != directory.ViaAI || c.Client != "portcullis-ai-generic" || !c.Admin {
		t.Errorf("caller %+v, want root via ai, client portcullis-ai-generic, admin", c)
	}
	e.call(t, "/mcp/admin", "bob", "2025-11-25", "save_thing", map[string]any{"id": "a"}, nil)
	found := false
	for _, a := range readAudit(t, e.audit) {
		if a.Actor == "bob" && a.Action == "thing.save" {
			found = a.Via == "ai" && a.Client == mcpClient
		}
	}
	if !found {
		t.Error("bob's refusal isn't audited with via ai and the client")
	}
	// The callerFrom path never takes the browser's headers: a context
	// without mcpIdentity has no caller.
	if _, err := e.s.callerFrom(context.Background()); err == nil {
		t.Error("callerFrom without the MCP identity")
	}
}

// TestMCPResourcesAndPrompts: the docs pages, each template's manifest
// (no generated value), the doctor catalogue and the three prompts on
// the admin scope; the people scope has only the docs.
func TestMCPResourcesAndPrompts(t *testing.T) {
	e := newMCPTestEnv(t)
	e.s.Docs = web.Docs
	e.s.mcp.mu.Lock()
	e.s.mcp.gen++ // Docs set after the first build
	e.s.mcp.mu.Unlock()
	read := func(path, uri string) (string, map[string]any) {
		t.Helper()
		_, a := e.rpc(t, rpcCall{path: path, user: "root", version: "2026-07-28", method: "resources/read", params: map[string]any{"uri": uri}})
		res, _ := a["result"].(map[string]any)
		cs, _ := res["contents"].([]any)
		if len(cs) != 1 {
			return "", a
		}
		txt, _ := cs[0].(map[string]any)["text"].(string)
		return txt, a
	}
	if txt, a := read("/mcp/admin", "portcullis://docs/integration-contracts"); !strings.Contains(txt, "### 15.10 The Portcullis MCP") {
		t.Errorf("docs: %v", a)
	}
	if txt, _ := read("/mcp/people", "portcullis://docs/hub"); !strings.Contains(txt, "Hub") {
		t.Error("people scope: no docs")
	}
	txt, a := read("/mcp/admin", "portcullis://templates/aiapp")
	var m struct {
		ID       string         `json:"id"`
		Manifest map[string]any `json:"manifest"`
	}
	if json.Unmarshal([]byte(txt), &m) != nil || m.ID != "aiapp" || m.Manifest["env"] == nil {
		t.Fatalf("template: %v", a)
	}
	if hdr := readEnvValue(t, filepath.Join(e.data, "env", "aiapp.env"), "HDR_SECRET"); strings.Contains(txt, hdr) {
		t.Error("the manifest resource holds a generated value")
	}
	if _, a := read("/mcp/admin", "portcullis://templates/nope"); a["error"] == nil {
		t.Errorf("unknown template: %v", a)
	}
	if txt, _ := read("/mcp/admin", "portcullis://doctor/checks"); !strings.Contains(txt, `"shared_path"`) {
		t.Errorf("doctor catalogue %q", txt)
	}
	if _, a := read("/mcp/people", "portcullis://templates/aiapp"); a["error"] == nil {
		t.Errorf("people scope read a template: %v", a)
	}
	uris := func(path, method, key, field string) []string {
		_, a := e.rpc(t, rpcCall{path: path, user: "root", version: "2026-07-28", method: method, params: map[string]any{}})
		res, _ := a["result"].(map[string]any)
		var out []string
		xs, _ := res[key].([]any)
		for _, x := range xs {
			out = append(out, x.(map[string]any)[field].(string))
		}
		sort.Strings(out)
		return out
	}
	admin := uris("/mcp/admin", "resources/list", "resources", "uri")
	for _, w := range []string{"portcullis://docs/integration-contracts", "portcullis://docs/hub", "portcullis://templates", "portcullis://doctor/checks"} {
		if !slices.Contains(admin, w) {
			t.Errorf("admin resources %v lack %s", admin, w)
		}
	}
	if got := uris("/mcp/admin", "resources/templates/list", "resourceTemplates", "uriTemplate"); !slices.Equal(got, []string{"portcullis://templates/{id}"}) {
		t.Errorf("resource templates %v", got)
	}
	for _, u := range uris("/mcp/people", "resources/list", "resources", "uri") {
		if !strings.HasPrefix(u, "portcullis://docs/") {
			t.Errorf("people resource %s", u)
		}
	}
	_, a = e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2026-07-28", method: "prompts/list", params: map[string]any{}})
	got := map[string][]string{}
	for _, x := range a["result"].(map[string]any)["prompts"].([]any) {
		p := x.(map[string]any)
		var args []string
		for _, y := range p["arguments"].([]any) {
			args = append(args, y.(map[string]any)["name"].(string))
		}
		got[p["title"].(string)] = args
	}
	want := map[string][]string{"Diagnose this app": {"app"}, "Set up an app for a team": {"app", "team"}, "Why can't <person> open <app>?": {"person", "app"}}
	for k, v := range want {
		if !slices.Equal(got[k], v) {
			t.Errorf("prompt %q arguments %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
	_, a = e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2026-07-28", method: "prompts/get", name: "why_cant_person_open_app",
		params: map[string]any{"name": "why_cant_person_open_app", "arguments": map[string]any{"person": "alice", "app": "aiapp"}}})
	if b, _ := json.Marshal(a); !strings.Contains(string(b), "why alice can't open the Portcullis app aiapp") {
		t.Errorf("prompts/get = %s", b)
	}
	if got := uris("/mcp/people", "prompts/list", "prompts", "name"); len(got) != 0 {
		t.Errorf("people prompts %v", got)
	}
}

// TestSDKBehindAdapter (G18): only internal/mcpsdk imports the MCP SDK
// or its JSON Schema library.
func TestSDKBehindAdapter(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || filepath.Base(filepath.Dir(p)) == "mcpsdk" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if strings.Contains(im.Path.Value, "github.com/modelcontextprotocol/") || strings.Contains(im.Path.Value, "github.com/google/jsonschema-go") {
				t.Errorf("%s imports %s: use internal/mcpsdk", p, im.Path.Value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// panicDocs is a docs FS whose pages panic when read.
type panicDocs struct{ fstest.MapFS }

func (panicDocs) ReadFile(string) ([]byte, error) { panic("panic-value-must-not-be-logged") }

// TestMCPToolErrors (fix round 1): a panicking Run, resource or prompt
// is recovered — logged by name, never its value — and answered
// "internal error"; Run errors carry their status like writeErr.
func TestMCPToolErrors(t *testing.T) {
	e := newMCPTestEnv(t)
	var logged strings.Builder
	var logMu sync.Mutex
	log.SetOutput(writerFunc(func(b []byte) (int, error) { logMu.Lock(); defer logMu.Unlock(); return logged.Write(b) }))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	fail := func(err error) func(context.Context, *directory.Caller, json.RawMessage) (any, error) {
		return func(context.Context, *directory.Caller, json.RawMessage) (any, error) { return nil, err }
	}
	e.s.registerTool(Tool{Name: "explode", Description: "x", Class: ClassRead, Scope: ScopeAdmin, Twin: "GET /x", In: struct{}{},
		Run: func(context.Context, *directory.Caller, json.RawMessage) (any, error) {
			panic("panic-value-must-not-be-logged")
		}})
	e.s.registerTool(Tool{Name: "busy", Description: "x", Class: ClassRead, Scope: ScopeAdmin, Twin: "GET /x", In: struct{}{},
		Run: fail(&hub.StatusError{Status: http.StatusConflict, Err: errors.New("the instance is busy")})})
	e.s.registerTool(Tool{Name: "plain", Description: "x", Class: ClassRead, Scope: ScopeAdmin, Twin: "GET /x", In: struct{}{},
		Run: fail(errors.New("something broke"))})
	e.s.registerTool(Tool{Name: "dir", Description: "x", Class: ClassRead, Scope: ScopeAdmin, Twin: "GET /x", In: struct{}{},
		Run: fail(&directory.Error{Status: http.StatusForbidden, Msg: "not allowed: admins only"})})
	res := e.call(t, "/mcp/admin", "root", "2025-11-25", "explode", map[string]any{}, nil)
	if txt, isErr := resultText(res); !isErr || txt != "internal error" {
		t.Errorf("panicking Run = %q %v", txt, isErr)
	}
	for tool, want := range map[string]string{"busy": "409: the instance is busy", "plain": "500: something broke", "dir": "403: not allowed: admins only"} {
		res := e.call(t, "/mcp/admin", "root", "2025-11-25", tool, map[string]any{}, nil)
		if txt, isErr := resultText(res); !isErr || txt != want {
			t.Errorf("%s = %q %v, want %q", tool, txt, isErr, want)
		}
	}
	e.s.Docs = panicDocs{fstest.MapFS{"docs/page.md": {Data: []byte("# x")}}}
	e.s.mcp.mu.Lock()
	e.s.mcp.gen++
	e.s.mcp.mu.Unlock()
	_, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2026-07-28", method: "resources/read", params: map[string]any{"uri": "portcullis://docs/page"}})
	if errObj, _ := a["error"].(map[string]any); errObj == nil || errObj["message"] != "internal error" {
		t.Errorf("panicking resource = %v", a)
	}
	logMu.Lock()
	l := logged.String()
	logMu.Unlock()
	if strings.Contains(l, "panic-value-must-not-be-logged") || !strings.Contains(l, "mcp: explode: panic") || !strings.Contains(l, "mcp: portcullis://docs/page: panic") {
		t.Errorf("log: %s", l)
	}
	// The listener still serves after the panics.
	if got := e.list(t, "/mcp/admin", "root", "2025-11-25"); !slices.Contains(got, "list_things") {
		t.Errorf("after the panics: %v", got)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
