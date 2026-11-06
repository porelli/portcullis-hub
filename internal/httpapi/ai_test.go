package httpapi

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
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
	if sv["set"] != true || sv["updated_at"] == nil || len(sv) != 2 {
		t.Errorf("answer = %s, want {set: true, updated_at}", b)
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
	if strings.TrimSpace(b) != `{"set":false}` {
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
	if b := call("PUT", "/api/ai/providers/ollama/secrets/key", `{"clear":true}`, 200); strings.TrimSpace(b) != `{"set":false}` {
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
