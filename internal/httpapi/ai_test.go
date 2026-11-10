package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
)

// aiEnv is the instance env with the AI page test template ai-chat
// (openai_compatible and anthropic).
func aiEnv(t *testing.T) (*instEnv, string) {
	t.Helper()
	dir := filepath.Join("..", "templates", "testdata", "ai", "chat")
	m, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	e := newInstEnvOpts(t, root, instEnvOpts{extra: map[string][2]string{"ai-chat": {string(m), string(c)}}})
	if e.s.Hub.Template("ai-chat") == nil {
		t.Fatal("ai-chat not loaded (see the log)")
	}
	return e, filepath.Join(root, "data")
}

const ollamaBody = `{"name":"ollama","label":"Ollama","kind":"openai_compatible","base_url":"http://gpu.lan:11434/v1","models":{"fetch":false,"list":["llama3.3:70b"]}}`

var aiRoutes = []route{
	{"GET", "/api/ai/settings", ""},
	{"PUT", "/api/ai/settings", `{"enabled":true}`},
	{"GET", "/api/ai/providers", ""},
	{"POST", "/api/ai/providers", ollamaBody},
	{"PUT", "/api/ai/providers/ollama", ollamaBody},
	{"DELETE", "/api/ai/providers/ollama", ""},
	{"PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"sk-x"}`},
}

// TestAIRoutesAdminOnly: delegates 403, no user 401, 404 on the people
// listener; each route registered once on the Hub listener; refusals
// never reach the Hub.
func TestAIRoutesAdminOnly(t *testing.T) {
	e, _ := aiEnv(t)
	mustDo(t, e.hub, "root", "POST", "/api/ai/providers", ollamaBody, 201)
	checkAdminOnly(t, e, aiRoutes)
	for _, prefix := range []string{"settings.ai", "ai."} {
		for _, a := range e.auditActions(t, prefix) {
			if !strings.Contains(a, ":root:") {
				t.Errorf("a refused request reached the Hub: %s", a)
			}
		}
	}
	if s := e.s.Hub.AISettings(); s.Enabled {
		t.Error("a refused request changed the settings")
	}
	n := map[string]int{}
	for _, p := range e.s.hubMux().patterns {
		n[p]++
	}
	for _, p := range []string{"GET /api/ai/settings", "PUT /api/ai/settings", "GET /api/ai/providers", "POST /api/ai/providers",
		"PUT /api/ai/providers/{name}", "DELETE /api/ai/providers/{name}", "PUT /api/ai/providers/{name}/secrets/{field}"} {
		if n[p] != 1 {
			t.Errorf("hub listener registers %q %d times", p, n[p])
		}
	}
	for _, p := range e.s.peopleMux().patterns {
		if strings.Contains(p, "/api/ai") {
			t.Errorf("people listener registers %q", p)
		}
	}
}

// TestAISettingsAPI: GET the defaults, PUT only what changed, strict
// bodies, 400 with {"error"}.
func TestAISettingsAPI(t *testing.T) {
	e, _ := aiEnv(t)
	var v map[string]any
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ai/settings", "", 200)), &v)
	cl, _ := v["clients"].(map[string]any)
	claude, _ := cl["claude"].(map[string]any)
	if v["enabled"] != false || v["gate_present"] != false || claude["offered"] != true || claude["admin"] != false ||
		v["offline_idle_days"] != 7.0 || v["portcullis_people"] != true {
		t.Fatalf("defaults = %v", v)
	}
	if lim, _ := v["limits"].(map[string]any); lim["fanout"] != 4.0 || lim["person_rpm"] != 600.0 {
		t.Errorf("limits = %v", v["limits"])
	}
	if o, ok := v["allowed_origins"].([]any); !ok || len(o) != 0 {
		t.Errorf("allowed_origins = %#v, want []", v["allowed_origins"])
	}
	b := mustDo(t, e.hub, "root", "PUT", "/api/ai/settings", `{"clients":{"claude_code":{"admin":true}},"offline_max_days":60}`, 200)
	json.Unmarshal([]byte(b), &v)
	cl, _ = v["clients"].(map[string]any)
	if cc, _ := cl["claude_code"].(map[string]any); cc["admin"] != true || cc["offered"] != true || v["offline_max_days"] != 60.0 {
		t.Errorf("saved = %v", v)
	}
	for _, body := range []string{`{"offline_idle_days":31}`, `{"allowed_origins":["http://x.org"]}`, `{"gate_present":true}`, `{"enabled":true}x`, `{"clients":{"other":{}}}`} {
		r, b := doAs(t, e.hub, "root", "PUT", "/api/ai/settings", body)
		if r.StatusCode != 400 || !strings.Contains(b, `"error":`) {
			t.Errorf("%s = %d %s", body, r.StatusCode, b)
		}
	}
	got := strings.Join(e.auditActions(t, "settings.ai"), " ")
	if strings.Count(got, "settings.ai:ok:root:ai") != 1 || !strings.Contains(got, "settings.ai:refused:root:ai") {
		t.Errorf("audit = %s", got)
	}
}

// TestProviderAPI: add 201, list, update, a secret field in the body
// refused, delete 204.
func TestProviderAPI(t *testing.T) {
	e, _ := aiEnv(t)
	var a struct {
		Provider map[string]any `json:"provider"`
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "POST", "/api/ai/providers", ollamaBody, 201)), &a)
	if a.Provider["name"] != "ollama" || a.Provider["credentials"] != "admin" {
		t.Fatalf("added = %v", a.Provider)
	}
	if sec, _ := a.Provider["secrets"].(map[string]any); sec["key"].(map[string]any)["set"] != false {
		t.Errorf("secrets = %v", a.Provider["secrets"])
	}
	for _, body := range []string{
		`{"name":"x","label":"X","kind":"anthropic","key":"sk-x"}`,
		`{"name":"x","label":"X","kind":"anthropic","secrets":{"key":"sk-x"}}`,
	} {
		if r, b := doAs(t, e.hub, "root", "POST", "/api/ai/providers", body); r.StatusCode != 400 || strings.Contains(b, "sk-x") {
			t.Errorf("secret in the body = %d %s", r.StatusCode, b)
		}
	}
	if r, b := doAs(t, e.hub, "root", "POST", "/api/ai/providers", ollamaBody); r.StatusCode != 409 {
		t.Errorf("duplicate = %d %s", r.StatusCode, b)
	}
	if r, b := doAs(t, e.hub, "root", "POST", "/api/ai/providers", `{"name":"b","label":"B","kind":"bedrock","region":"us-east-1"}`); r.StatusCode != 400 ||
		!strings.Contains(b, "no installed AI page supports kind bedrock") {
		t.Errorf("bedrock = %d %s", r.StatusCode, b)
	}
	upd := strings.Replace(ollamaBody, `"label":"Ollama"`, `"label":"Ollama 2"`, 1)
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "PUT", "/api/ai/providers/ollama", upd, 200)), &a)
	if a.Provider["label"] != "Ollama 2" {
		t.Errorf("updated = %v", a.Provider)
	}
	var l struct {
		Providers []map[string]any `json:"providers"`
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ai/providers", "", 200)), &l)
	if len(l.Providers) != 1 || l.Providers[0]["used_by"] == nil {
		t.Errorf("list = %v", l.Providers)
	}
	mustDo(t, e.hub, "root", "DELETE", "/api/ai/providers/ollama", "", 204)
	mustDo(t, e.hub, "root", "DELETE", "/api/ai/providers/ollama", "", 404)
	got := strings.Join(e.auditActions(t, "ai.provider."), " ")
	for _, w := range []string{"ai.provider.add:ok:root:ollama", "ai.provider.update:ok:root:ollama", "ai.provider.delete:ok:root:ollama"} {
		if !strings.Contains(got, w) {
			t.Errorf("audit %s lacks %s", got, w)
		}
	}
}

// TestProviderSecretsNeverEchoed: a set marker is in no answer, no file
// of the data directory but the store, no log line and no error; the
// answer is {set, updated_at}; audited "key replaced" / "key cleared".
func TestProviderSecretsNeverEchoed(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	const marker = "sk-MARKER-123"
	e, data := aiEnv(t)
	var answers []string
	call := func(method, path, body string, want int) string {
		t.Helper()
		r, b := doAs(t, e.hub, "root", method, path, body)
		if r.StatusCode != want {
			t.Errorf("%s %s = %d %s, want %d", method, path, r.StatusCode, b, want)
		}
		answers = append(answers, b)
		return b
	}
	call("POST", "/api/ai/providers", ollamaBody, 201)
	b := call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker+`"}`, 200)
	var sv map[string]any
	json.Unmarshal([]byte(b), &sv)
	// restarts: the AI pages it restarted (Task 23; none select it here).
	if r, ok := sv["restarts"].([]any); sv["set"] != true || sv["updated_at"] == nil || len(sv) != 3 || !ok || len(r) != 0 {
		t.Errorf("answer = %s, want {set: true, updated_at, restarts: []}", b)
	}
	// Refusals carrying the marker never quote it.
	call("PUT", "/api/ai/providers/ollama/secrets/secret_access_key", `{"value":"`+marker+`"}`, 400)
	call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker+`'"}`, 400)
	call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker+`\n"}`, 400)
	call("PUT", "/api/ai/providers/ghost/secrets/key", `{"value":"`+marker+`"}`, 404)
	call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker+`","bogus":1}`, 400)
	call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker+`","clear":true}`, 400)
	call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker, 400)
	call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":42}`, 400)
	call("POST", "/api/ai/providers", `{"name":"x","label":"X","kind":"anthropic","key":"`+marker+`"}`, 400)
	l := call("GET", "/api/ai/providers", "", 200)
	if !strings.Contains(l, `"key":{"set":true,"updated_at":`) {
		t.Errorf("list = %s", l)
	}
	call("GET", "/api/ai/settings", "", 200)
	call("PUT", "/api/ai/providers/ollama", ollamaBody, 200)
	call("GET", "/api/instances", "", 200)
	call("GET", "/api/templates/lastop/ai-chat", "", 200)
	for _, a := range answers {
		if strings.Contains(a, "MARKER") {
			t.Errorf("an answer holds the secret: %s", a)
		}
	}
	// On disk: only the store, 0600.
	store := filepath.Join(data, "ai", "provider-secrets.json")
	if st, err := os.Stat(store); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("store = %v %v", st, err)
	}
	seen := 0
	filepath.WalkDir(data, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		seen++
		raw, _ := os.ReadFile(p)
		if bytes.Contains(raw, []byte("MARKER")) != (p == store) {
			t.Errorf("%s: holds the secret = %v", p, bytes.Contains(raw, []byte("MARKER")))
		}
		return nil
	})
	if seen < 3 {
		t.Errorf("only %d files in the data directory", seen)
	}
	// The successful set is exactly one ok entry, by root, on ollama.
	var oks []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "ai.provider.secret" && a.Result == "ok" {
			oks = append(oks, a)
		}
	}
	if len(oks) != 1 {
		t.Fatalf("ok secret audits = %+v, want exactly one", oks)
	}
	if a := oks[0]; a.Actor != "root" || a.Target != "ollama" || a.Detail != "key replaced" || a.Error != "" || a.Via != "" {
		t.Errorf("secret audit = %+v", a)
	}
	// Clear.
	b = call("PUT", "/api/ai/providers/ollama/secrets/key", `{"clear":true}`, 200)
	if strings.TrimSpace(b) != `{"set":false,"restarts":[]}` {
		t.Errorf("clear = %s", b)
	}
	if raw, _ := os.ReadFile(store); bytes.Contains(raw, []byte("MARKER")) {
		t.Error("cleared value still stored")
	}
	call("PUT", "/api/ai/providers/ollama/secrets/key", `{"clear":false}`, 400)
	var last directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "ai.provider.secret" {
			last = a
		}
	}
	if last.Detail != "key cleared" || last.Result != "ok" || last.Actor != "root" || last.Target != "ollama" {
		t.Errorf("last secret audit = %+v, want key cleared ok by root", last)
	}
	// Clearing again: nothing set, {set:false}, nothing audited.
	n := len(readAudit(t, e.audit))
	if b := call("PUT", "/api/ai/providers/ollama/secrets/key", `{"clear":true}`, 200); strings.TrimSpace(b) != `{"set":false,"restarts":[]}` {
		t.Errorf("clear unset = %s", b)
	}
	if len(readAudit(t, e.audit)) != n {
		t.Error("clearing an unset field was audited")
	}
	// A store that can't be written (read-only <data>/ai): 500, the value
	// in neither the answer, the audit nor the logs.
	if strings.Contains(logs.String(), "MARKER") {
		t.Errorf("a log line holds the secret:\n%s", logs.String())
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes: the write-failure part needs a non-root user")
	}
	os.WriteFile(store, []byte(`{}`), 0600)
	os.Chmod(filepath.Dir(store), 0500)
	t.Cleanup(func() { os.Chmod(filepath.Dir(store), 0700) })
	b = call("PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker+`"}`, 500)
	if strings.Contains(b, "MARKER") || !strings.Contains(b, `"error":`) {
		t.Errorf("write failure answer = %s", b)
	}
	var failed directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "ai.provider.secret" {
			failed = a
		}
	}
	if failed.Result != "error" || strings.Contains(failed.Error, "MARKER") || failed.Detail != "key replaced" {
		t.Errorf("write failure audit = %+v", failed)
	}
	if e.s.Hub.ModelProviders(t.Context())[0].Secrets["key"].Set {
		t.Error("a failed write marked the secret set")
	}
	if strings.Contains(logs.String(), "MARKER") {
		t.Errorf("a log line holds the secret:\n%s", logs.String())
	}
}

// aiScopesKC accepts every mcp:* scope and AI client call.
type aiScopesKC struct{}

func (aiScopesKC) EnsureMCPScope(context.Context, keycloak.MCPScope) error   { return nil }
func (aiScopesKC) DeleteMCPScope(context.Context, string) error              { return nil }
func (aiScopesKC) SetOptionalScopes(context.Context, string, []string) error { return nil }
func (aiScopesKC) EnsureAIClient(context.Context, keycloak.AIClientSpec) (bool, error) {
	return false, nil
}
func (aiScopesKC) DeleteAIClient(context.Context, string, string) error { return nil }
func (aiScopesKC) MCPScopeNames(context.Context) ([]string, error)      { return nil, nil }

// aiAppEnv: the Hub's AI test template aiapp (disabled), master switch on.
func aiAppEnv(t *testing.T) *instEnv {
	t.Helper()
	dir := filepath.Join("..", "hub", "testdata", "ai", "aiapp")
	m, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{extra: map[string][2]string{"aiapp": {string(m), string(c)}},
		seed: func(st *state.AppState) { st.AI.Enabled = true }})
	if e.s.Hub.Template("aiapp") == nil {
		t.Fatal("aiapp not loaded (see the log)")
	}
	e.s.Hub.SetAIKeycloak(aiScopesKC{})
	return e
}

// TestInstanceAIAPI (§15.11): admins only, Hub listener only; GET the
// tab; PUT on a disabled instance saves state only (restarts false);
// 404 unknown companion, 400 a mode outside modes or a bad body; audited.
func TestInstanceAIAPI(t *testing.T) {
	e := aiAppEnv(t)
	checkAdminOnly(t, e, []route{
		{"GET", "/api/instances/aiapp/ai", ""},
		{"PUT", "/api/instances/aiapp/ai", `{"companions":{"tok":{"enabled":true}}}`},
	})
	if a := e.auditActions(t, "ai."); len(a) != 0 {
		t.Fatalf("refused requests reached the Hub: %v", a)
	}
	n := map[string]int{}
	for _, p := range e.s.hubMux().patterns {
		n[p]++
	}
	for _, p := range []string{"GET /api/instances/{id}/ai", "PUT /api/instances/{id}/ai"} {
		if n[p] != 1 {
			t.Errorf("hub listener registers %q %d times", p, n[p])
		}
	}
	// The default-policy routes are gone (sign-in Task 4).
	if n["POST /api/settings/preview"]+n["/api/settings"] != 0 {
		t.Error("the default-policy routes are still registered")
	}
	var v struct {
		MasterOff  bool `json:"master_off"`
		Companions []struct {
			Name, Mode, Status, URL string
			Enabled                 bool
			Modes                   []string
		} `json:"companions"`
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/instances/aiapp/ai", "", 200)), &v)
	if v.MasterOff || len(v.Companions) != 2 || v.Companions[0].Name != "tok" || v.Companions[0].Mode != "read_write" ||
		v.Companions[0].Status != "off" || v.Companions[0].URL != "https://aiapp.example.org/mcp" {
		t.Fatalf("tab = %+v", v)
	}
	var res map[string]any
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "PUT", "/api/instances/aiapp/ai", `{"companions":{"tok":{"enabled":true,"mode":"read_only"}}}`, 200)), &res)
	if res["restarts"] != false {
		t.Errorf("answer = %v", res)
	}
	for body, want := range map[string]int{
		`{"companions":{"nope":{"enabled":true}}}`:     404,
		`{"companions":{"hdr":{"mode":"read_write"}}}`: 400,
		`{"companions":{"tok":{"enabled":1}}}`:         400,
		`{"providers":["x"]}`:                          400,
	} {
		if r, b := doAs(t, e.hub, "root", "PUT", "/api/instances/aiapp/ai", body); r.StatusCode != want || !strings.Contains(b, `"error":`) {
			t.Errorf("%s = %d %s, want %d", body, r.StatusCode, b, want)
		}
	}
	got := strings.Join(e.auditActions(t, "ai."), " ")
	if !strings.Contains(got, "ai.enable:ok:root:aiapp/tok") || !strings.Contains(got, "ai.enable:refused:root:aiapp/nope") {
		t.Errorf("audit = %s", got)
	}
}

// writeAccessLog writes the gate's access log in dir: one line per
// (user, instance, tool), one second apart, the last newest.
func writeAccessLog(t *testing.T, dir string, now time.Time, lines [][3]string) {
	t.Helper()
	var b strings.Builder
	for i, l := range lines {
		line, _ := json.Marshal(map[string]any{"time": now.Add(time.Duration(i) * time.Second).Format(time.RFC3339), "user": l[0], "client": mcpClient,
			"resource": aiappResource, "instance": l[1], "companion": "tok", "via": "direct", "method": "tools/call",
			"tool": l[2], "args_sha256": strings.Repeat("a", 64), "decision": "allow", "upstream_status": 200, "duration_ms": 3})
		b.Write(append(line, '\n'))
	}
	if err := os.WriteFile(filepath.Join(dir, hub.AccessLogName), []byte(b.String()), 0o640); err != nil {
		t.Fatal(err)
	}
}

// TestAIActivityAdminOnly (§15.11, Task 22): GET /api/ai/activity is
// admins only on the Hub listener (delegates 403, no user 401, people
// 404); instance= and user= filter (both together too), newest first;
// n is 1–200 (an explicit 0, a negative or 201 is 400, 200 is fine).
func TestAIActivityAdminOnly(t *testing.T) {
	gate := t.TempDir()
	e := newMCPEnvOpts(t, mcpEnvOpts{cfg: func(c *hub.Config) { c.MCPGateDataDir = gate }})
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	var lines [][3]string
	for i := 0; i < 210; i++ {
		lines = append(lines, [3]string{"carol", "other", fmt.Sprintf("bulk_%d", i)})
	}
	lines = append(lines, [3]string{"alice", "aiapp", "list_things"}, [3]string{"bob", "aiapp", "create_thing"},
		[3]string{"alice", "other", "x"}, [3]string{"alice", "aiapp", "newest_of_alice"})
	writeAccessLog(t, gate, now, lines)
	checkAdminOnly(t, e.instEnv, []route{{"GET", "/api/ai/activity", ""}, {"GET", "/api/ai/activity?instance=aiapp&user=alice&n=5", ""}})
	type act struct {
		Lines []hub.AccessLine `json:"lines"`
	}
	get := func(q string) []hub.AccessLine {
		t.Helper()
		var a act
		if err := json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ai/activity"+q, "", 200)), &a); err != nil {
			t.Fatal(err)
		}
		return a.Lines
	}
	tools := func(ls []hub.AccessLine) string {
		var s []string
		for _, l := range ls {
			s = append(s, l.User+"/"+l.Instance+"/"+l.Tool)
		}
		return strings.Join(s, " ")
	}
	if got := tools(get("?instance=aiapp")); got != "alice/aiapp/newest_of_alice bob/aiapp/create_thing alice/aiapp/list_things" {
		t.Errorf("instance=aiapp: %s", got)
	}
	if got := tools(get("?user=ALICE")); got != "alice/aiapp/newest_of_alice alice/other/x alice/aiapp/list_things" {
		t.Errorf("user=ALICE: %s", got)
	}
	if got := tools(get("?instance=aiapp&user=alice&n=1")); got != "alice/aiapp/newest_of_alice" {
		t.Errorf("instance+user n=1: %s", got)
	}
	if got := get(""); len(got) != 50 {
		t.Errorf("default n: %d lines, want 50", len(got))
	}
	if got := get("?n=200"); len(got) != 200 || got[0].Tool != "newest_of_alice" {
		t.Errorf("n=200: %d lines", len(got))
	}
	for _, q := range []string{"?n=201", "?n=0", "?n=-1", "?n=x", "?n=1e2"} {
		mustDo(t, e.hub, "root", "GET", "/api/ai/activity"+q, "", 400)
	}
}

// TestAuditViaFilter (§9.5, §15.11, Task 22): GET /api/directory/audit
// ?via=ai returns only the entries made through the Portcullis MCP;
// with include=access they are merged with the gate's access-log lines,
// newest first, each item tagged with its source. Without via the
// answer is the plain list as before. A bad via / include is 400;
// include=access needs via=ai. Admins only (delegates 403).
func TestAuditViaFilter(t *testing.T) {
	gate := t.TempDir()
	e := newMCPEnvOpts(t, mcpEnvOpts{cfg: func(c *hub.Config) { c.MCPGateDataDir = gate }})
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for i, en := range []directory.AuditEntry{
		{Actor: "root", Action: "group.add_member", Target: "office", Result: "ok"},
		{Actor: "root", Action: "instance.update", Target: "aiapp", Result: "ok", Via: directory.ViaAI, Client: mcpClient},
		{Actor: "root", Action: "settings.ai", Target: "settings", Result: "refused", Via: directory.ViaAI, Client: "portcullis-ai-claude-code"},
		{Actor: "dana", Action: "user.update", Target: "bob", Result: "ok"},
	} {
		en.Time = base.Add(time.Duration(2*i) * time.Second)
		if err := e.s.Directory.Audit.Append(en); err != nil {
			t.Fatal(err)
		}
	}
	// Access lines at base+1s, base+3s, base+5s, base+7s.
	var b strings.Builder
	for i, tool := range []string{"a1", "a2", "a3", "a4"} {
		line, _ := json.Marshal(map[string]any{"time": base.Add(time.Duration(2*i+1) * time.Second).Format(time.RFC3339), "user": "alice", "client": mcpClient,
			"resource": aiappResource, "instance": "aiapp", "companion": "tok", "via": "aggregate", "method": "tools/call",
			"tool": tool, "args_sha256": strings.Repeat("a", 64), "decision": "allow", "upstream_status": 200, "duration_ms": 3})
		b.Write(append(line, '\n'))
	}
	os.WriteFile(filepath.Join(gate, hub.AccessLogName), []byte(b.String()), 0o640)

	// Unfiltered: every entry, the plain list.
	var all []directory.AuditEntry
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/directory/audit", "", 200)), &all)
	n := 0
	for _, a := range all {
		if a.Action == "group.add_member" || a.Action == "user.update" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("unfiltered audit lacks the human entries: %+v", all)
	}
	// via=ai: only the two AI entries, newest first.
	var via []directory.AuditEntry
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/directory/audit?via=ai", "", 200)), &via)
	if len(via) != 2 || via[0].Action != "settings.ai" || via[1].Action != "instance.update" {
		t.Fatalf("via=ai = %+v", via)
	}
	for _, a := range via {
		if a.Via != "ai" || a.Client == "" {
			t.Errorf("via=ai entry %+v", a)
		}
	}
	// include=access: merged, newest first, tagged.
	var merged []struct {
		Source string                `json:"source"`
		Time   time.Time             `json:"time"`
		Entry  *directory.AuditEntry `json:"entry"`
		Line   *hub.AccessLine       `json:"line"`
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/directory/audit?via=ai&include=access", "", 200)), &merged)
	var order []string
	for i, m := range merged {
		switch {
		case m.Source == "audit" && m.Entry != nil && m.Line == nil:
			order = append(order, m.Entry.Action)
			if m.Entry.Via != "ai" {
				t.Errorf("merged audit entry not via ai: %+v", m.Entry)
			}
		case m.Source == "access" && m.Line != nil && m.Entry == nil:
			order = append(order, m.Line.Tool)
		default:
			t.Fatalf("item %d = %+v", i, m)
		}
		if i > 0 && m.Time.After(merged[i-1].Time) {
			t.Errorf("not newest first at %d", i)
		}
	}
	if got := strings.Join(order, " "); got != "a4 a3 settings.ai a2 instance.update a1" {
		t.Errorf("merged = %s", got)
	}
	for _, q := range []string{"?via=human", "?include=access", "?via=ai&include=everything", "?via=AI"} {
		mustDo(t, e.hub, "root", "GET", "/api/directory/audit"+q, "", 400)
	}
	checkAuditAdminOnly(t, e.instEnv, "/api/directory/audit?via=ai&include=access")
}

// checkAuditAdminOnly: the audit route is admins only (a delegate 403;
// no user 403, as every Users & Groups route: s.caller refuses an
// unattributable request).
func checkAuditAdminOnly(t *testing.T, e *instEnv, path string) {
	t.Helper()
	doAs(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"helpers"}`)
	if code, b := e.do(t, "dana", "GET", path, ""); code != 403 {
		t.Errorf("delegate %s = %d %s, want 403", path, code, b)
	}
	if code, b := e.do(t, "", "GET", path, ""); code != 403 {
		t.Errorf("no user %s = %d %s, want 403", path, code, b)
	}
}
