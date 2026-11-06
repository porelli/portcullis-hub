package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 13a: the MCP listener (contract §15.7), the internal API
// and lazy credential minting (§15.5).

const testMCPSecret = "mcp-gate-secret-0123456789abcdef-0123"

const aiappResource = "https://aiapp.example.org/mcp"

// aiHookEngine is the fake engine with a running app container of aiapp
// and scripted AI hooks (ExecStdinSplit).
type aiHookEngine struct {
	*fakeEngine
	mu    sync.Mutex
	calls []docker.ExecInput
	// answer scripts a hook run (nil: exit 0, no output).
	answer func(in docker.ExecInput) *docker.ExecSplitResult
	// gate, if set, holds every hook run until it is closed.
	gate chan struct{}
}

func (e *aiHookEngine) ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	out, err := e.fakeEngine.ListContainers(ctx, f)
	for _, svc := range []string{"app", "tok-mcp"} {
		c := docker.Container{ID: "c-" + svc, Names: []string{"/portcullis-aiapp-" + svc + "-1"}, State: "running",
			Labels: map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: svc, docker.LabelNumber: "1"}}
		if matchLabels(c.Labels, f) {
			out = append(out, c)
		}
	}
	return out, err
}

func (e *aiHookEngine) ExecStdinSplit(_ context.Context, _ string, in docker.ExecInput) (*docker.ExecSplitResult, error) {
	e.mu.Lock()
	e.calls = append(e.calls, in)
	answer, gate := e.answer, e.gate
	e.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if answer == nil {
		return &docker.ExecSplitResult{ExecID: "x"}, nil
	}
	return answer(in), nil
}

func (e *aiHookEngine) script(f func(docker.ExecInput) *docker.ExecSplitResult) {
	e.mu.Lock()
	e.answer = f
	e.mu.Unlock()
}

// runs are the stdins of the hook runs whose argv[0] is cmd.
func (e *aiHookEngine) runs(cmd string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, c := range e.calls {
		if c.Cmd[0] == cmd {
			out = append(out, strings.TrimSpace(string(c.Stdin)))
		}
	}
	return out
}

// mintAnswer is a mint hook's success.
func mintAnswer(stdout string) func(docker.ExecInput) *docker.ExecSplitResult {
	return func(in docker.ExecInput) *docker.ExecSplitResult {
		if in.Cmd[0] != "/mint" {
			return &docker.ExecSplitResult{ExecID: "x"}
		}
		return &docker.ExecSplitResult{ExecID: "x", Stdout: []byte(stdout)}
	}
}

type mcpEnv struct {
	*instEnv
	eng   *aiHookEngine
	mcp   *httptest.Server
	ident *age.X25519Identity
	data  string
}

// newMCPEnv: the aiapp template enabled, its tok companion (app_token)
// switched on read_write, master on, a gate recipient and the MCP
// listener, alice (and bob, outside) in LLDAP, alice in users_aiapp, the
// Hub's AI clients healthy.
// prep, if any, scripts the engine before the instance starts.
func newMCPEnv(t *testing.T, seed func(*state.AppState), prep ...func(*aiHookEngine)) *mcpEnv {
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
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	recip := filepath.Join(root, "age.pub")
	os.WriteFile(recip, []byte(id.Recipient().String()+"\n"), 0o640)
	os.MkdirAll(filepath.Join(root, "project"), 0o755)
	os.WriteFile(filepath.Join(root, "project", ".env"), []byte("PORTCULLIS_MCP_GATE_IP=172.31.250.3\n"), 0o644)
	var eng *aiHookEngine
	e := newInstEnvOpts(t, root, instEnvOpts{
		extra:  map[string][2]string{"aiapp": {string(m), string(c)}},
		engine: func(f *fakeEngine) hub.Engine { eng = &aiHookEngine{fakeEngine: f}; return eng },
		cfg: func(cfg *hub.Config) {
			cfg.MCPGateRecipientFile = recip
			cfg.MCPListener = true
		},
		seed: func(st *state.AppState) {
			st.AI.Enabled = true
			st.AIInstances = map[string]state.AIInstance{"aiapp": {Companions: map[string]state.AICompanion{"tok": {Enabled: true, Mode: "read_write"}}}}
			if seed != nil {
				seed(st)
			}
		},
	})
	e.s.Hub.SetAIKeycloak(aiScopesKC{})
	e.s.Hub.SetAIClientHealth(map[string]bool{keycloak.AIClientIDs.Claude: true, keycloak.AIClientIDs.ClaudeCode: true, keycloak.AIClientIDs.Generic: true})
	e.ll.AddUser("alice", "alice@example.org", "Alice", "")
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	e.ll.AddGroup("users_aiapp", "alice")
	e.ll.AddGroup("admin_aiapp")
	e.s.Hub.SetPeople(e.s.Directory)
	for _, p := range prep {
		p(eng)
	}
	if err := e.s.Hub.Enable("aiapp"); err != nil {
		t.Fatal(err)
	}
	e.s.Hub.Wait()
	e.s.MCPSecret = testMCPSecret
	h, err := e.s.MCPHandler()
	if err != nil {
		t.Fatal(err)
	}
	me := &mcpEnv{instEnv: e, eng: eng, mcp: httptest.NewServer(h), ident: id, data: filepath.Join(root, "data")}
	t.Cleanup(me.mcp.Close)
	return me
}

// post sends body to the MCP listener with the secret.
func (e *mcpEnv) post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.mcp.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(MCPSecretHeader, testMCPSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func (e *mcpEnv) mintBody(user string) string {
	return `{"resource":"` + aiappResource + `","user":"` + user + `"}`
}

// creds decodes mcp-credentials.json strictly.
func (e *mcpEnv) creds(t *testing.T) *aigate.CredFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.data, aigate.CredsFileName))
	if err != nil {
		t.Fatal(err)
	}
	f, err := aigate.DecodeCredFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (e *mcpEnv) tok(t *testing.T) hub.CompanionView {
	t.Helper()
	v, err := e.s.Hub.InstanceAI("aiapp")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Companions {
		if c.Name == "tok" {
			return c
		}
	}
	t.Fatal("no tok companion")
	return hub.CompanionView{}
}

func (e *mcpEnv) auditOf(t *testing.T, action string) []directory.AuditEntry {
	var out []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

// TestMCPListenerSecret (§15.7): no / wrong secret → 401 on every path
// but /healthz; the secret never reaches handlers; the route table is
// exactly the contract's; X-Forwarded-User (and the AI headers) on the
// hub and people listeners never reach MCP code (its routes are 404
// there); a secret file under 32 characters refuses the start; a missing
// one = no listener and AI off (enabled: false).
func TestMCPListenerSecret(t *testing.T) {
	e := newMCPEnv(t, nil)
	send := func(srv *httptest.Server, method, path string, hdr map[string][]string, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	paths := []string{"/mcp/admin", "/mcp/people", "/internal/credentials", "/internal/confirmations",
		"/internal/confirmations/consume", "/", "/api/templates", "/nope", "/healthz/x"}
	bads := map[string]map[string][]string{
		"none":      nil,
		"wrong":     {MCPSecretHeader: {testMCPSecret + "x"}},
		"short":     {MCPSecretHeader: {testMCPSecret[:20]}},
		"empty":     {MCPSecretHeader: {""}},
		"twice":     {MCPSecretHeader: {testMCPSecret, testMCPSecret}},
		"proxy one": {ProxySecretHeader: {testMCPSecret}, "X-Forwarded-User": {"root"}},
	}
	for name, hdr := range bads {
		for _, p := range paths {
			for _, m := range []string{"GET", "POST", "DELETE"} {
				if c, _ := send(e.mcp, m, p, hdr, e.mintBody("alice")); c != 401 {
					t.Errorf("%s secret: %s %s = %d, want 401", name, m, p, c)
				}
			}
		}
		if c, _ := send(e.mcp, "POST", "/healthz", hdr, ""); c != 401 {
			t.Errorf("%s secret: POST /healthz = %d, want 401", name, c)
		}
	}
	if len(e.eng.runs("/mint")) != 0 {
		t.Fatal("a refused request ran the mint hook")
	}
	// /healthz needs no secret.
	if c, b := send(e.mcp, "GET", "/healthz", nil, ""); c != 200 || b != "ok\n" {
		t.Errorf("healthz = %d %q", c, b)
	}
	// With the secret: the route table (§15.7) and nothing else.
	ok := map[string][]string{MCPSecretHeader: {testMCPSecret}}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"POST", "/internal/confirmations", 501},
		{"POST", "/internal/confirmations/consume", 501},
		{"GET", "/internal/credentials", 404},
		{"PUT", "/internal/credentials", 404},
		{"GET", "/internal/confirmations", 404},
		{"POST", "/internal/credentials/x", 404},
		{"POST", "/internal/other", 404},
		{"GET", "/", 404},
		{"GET", "/api/templates", 404},
		{"POST", "/api/directory/groups", 404},
		{"GET", "/mcp", 404},
		{"POST", "/mcp/admin/x", 404},
		{"POST", "/healthz", 404},
	} {
		if got, _ := send(e.mcp, c.method, c.path, ok, `{}`); got != c.want {
			t.Errorf("%s %s = %d, want %d", c.method, c.path, got, c.want)
		}
	}
	got := slices.Sorted(slices.Values(e.s.mcpMux().patterns))
	want := []string{"/", "/mcp/admin", "/mcp/people", "GET /healthz", "POST /internal/confirmations", "POST /internal/confirmations/consume", "POST /internal/credentials"}
	if !slices.Equal(got, want) {
		t.Errorf("MCP routes = %v, want %v", got, want)
	}
	// /mcp/*: the resource header must be this route's, with a user and
	// a client (403 otherwise); then the stub (Tasks 14/15).
	id := func(res, user, client string) map[string][]string {
		h := map[string][]string{MCPSecretHeader: {testMCPSecret}}
		if res != "" {
			h["X-Portcullis-AI-Resource"] = []string{res}
		}
		if user != "" {
			h["X-Forwarded-User"] = []string{user}
		}
		if client != "" {
			h["X-Portcullis-AI-Client"] = []string{client}
		}
		return h
	}
	for _, c := range []struct {
		path string
		hdr  map[string][]string
		want int
	}{
		{"/mcp/admin", id("https://hub.example.org/mcp", "root", "portcullis-ai-claude"), 501},
		{"/mcp/people", id("https://people.example.org/mcp", "alice", "portcullis-ai-claude"), 501},
		{"/mcp/admin", id("https://people.example.org/mcp", "root", "portcullis-ai-claude"), 403},
		{"/mcp/people", id("https://hub.example.org/mcp", "alice", "portcullis-ai-claude"), 403},
		{"/mcp/admin", id(aiappResource, "root", "portcullis-ai-claude"), 403},
		{"/mcp/admin", id("", "root", "portcullis-ai-claude"), 403},
		{"/mcp/admin", id("https://hub.example.org/mcp", "", "portcullis-ai-claude"), 403},
		{"/mcp/admin", id("https://hub.example.org/mcp", "root", ""), 403},
	} {
		if got, b := send(e.mcp, "POST", c.path, c.hdr, `{}`); got != c.want {
			t.Errorf("%s %v = %d %s, want %d", c.path, c.hdr, got, b, c.want)
		}
	}

	// The secret and the gate's identity headers never reach a handler.
	var seen http.Header
	var seenActor directory.Actor
	spy := MCPSecret(testMCPSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seenActor = requestActor(r)
	}))
	r := httptest.NewRequest("POST", "/internal/credentials", strings.NewReader("{}"))
	r.Header.Set(MCPSecretHeader, testMCPSecret)
	spy.ServeHTTP(httptest.NewRecorder(), r)
	if seen == nil || seen.Get(MCPSecretHeader) != "" {
		t.Errorf("handler saw the secret header: %v", seen)
	}
	r = httptest.NewRequest("GET", "/healthz", nil)
	r.Header.Set(MCPSecretHeader, testMCPSecret)
	spy.ServeHTTP(httptest.NewRecorder(), r)
	if seen.Get(MCPSecretHeader) != "" {
		t.Error("/healthz saw the secret header")
	}
	route := e.s.mcpRoute("https://hub.example.org/mcp", func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seenActor = requestActor(r)
	})
	r = httptest.NewRequest("POST", "/mcp/admin", nil)
	for k, v := range id("https://hub.example.org/mcp", "Root", "portcullis-ai-claude") {
		r.Header.Set(k, v[0])
	}
	route(httptest.NewRecorder(), r)
	if seenActor != (directory.Actor{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}) {
		t.Errorf("actor = %+v", seenActor)
	}
	if seen.Get("X-Portcullis-AI-Client") != "" || seen.Get("X-Portcullis-AI-Resource") != "" {
		t.Errorf("handler saw the AI identity headers: %v", seen)
	}

	// The Hub and people listeners never serve the MCP routes, whatever
	// a request says (proxy secret, X-Forwarded-User, the MCP secret and
	// the AI headers): 404, and MCP code never runs.
	forgedHdr := map[string][]string{ProxySecretHeader: {testSecret}, "X-Forwarded-User": {"alice"}, MCPSecretHeader: {testMCPSecret},
		"X-Portcullis-AI-Client": {"portcullis-ai-claude"}, "X-Portcullis-AI-Resource": {aiappResource}}
	for _, srv := range []*httptest.Server{e.hub, e.ppl} {
		for _, p := range []string{"/internal/credentials", "/internal/confirmations", "/internal/confirmations/consume", "/mcp/admin", "/mcp/people"} {
			if c, b := send(srv, "POST", p, forgedHdr, e.mintBody("alice")); c != 404 {
				t.Errorf("%s POST %s = %d %.80s, want 404", srv.URL, p, c, b)
			}
		}
	}
	for _, p := range e.s.hubMux().patterns {
		if strings.Contains(p, "/internal/") || strings.Contains(p, "/mcp/") {
			t.Errorf("hub listener registers %q", p)
		}
	}
	for _, p := range e.s.peopleMux().patterns {
		if strings.Contains(p, "/internal/") || strings.Contains(p, "/mcp/") {
			t.Errorf("people listener registers %q", p)
		}
	}
	if len(e.eng.runs("/mint")) != 0 {
		t.Fatal("the hub or people listener ran the mint hook")
	}

	// HUB_MCP_GATE_SECRET_FILE: under 32 characters (once trimmed) or not
	// printable refuses the start; never quoting the value.
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("  "+strings.Repeat("s", 31)+"\n"), 0o600)
	if _, _, err := LoadMCPSecret(short); err == nil || strings.Contains(err.Error(), "sssss") {
		t.Errorf("31 chars: %v", err)
	}
	spaced := filepath.Join(dir, "spaced")
	os.WriteFile(spaced, []byte(strings.Repeat("s", 20)+" "+strings.Repeat("s", 20)), 0o600)
	if _, _, err := LoadMCPSecret(spaced); err == nil {
		t.Error("a secret with a space accepted")
	}
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte(testMCPSecret+"\n"), 0o600)
	if s, on, err := LoadMCPSecret(good); err != nil || !on || s != testMCPSecret {
		t.Errorf("good = %q %v %v", s, on, err)
	}
	if _, err := (&Server{Hub: e.s.Hub, MCPSecret: strings.Repeat("s", 31)}).MCPHandler(); err == nil {
		t.Error("MCPHandler accepted a 31-character secret")
	}
	// Missing: no listener (no error), and AI off in the gate file.
	if s, on, err := LoadMCPSecret(filepath.Join(dir, "missing")); err != nil || on || s != "" {
		t.Errorf("missing = %q %v %v", s, on, err)
	}
	if _, err := (&Server{Hub: e.s.Hub}).MCPHandler(); err == nil {
		t.Error("MCPHandler without a secret")
	}
	offRoot := t.TempDir()
	off := newInstEnvOpts(t, offRoot, instEnvOpts{
		cfg: func(cfg *hub.Config) {
			cfg.MCPGateRecipientFile = filepath.Join(filepath.Dir(e.data), "age.pub")
			cfg.MCPListener = false
		},
		seed: func(st *state.AppState) { st.AI.Enabled = true },
	})
	off.s.Hub.SetAIClientHealth(map[string]bool{keycloak.AIClientIDs.Generic: true})
	if err := off.s.Hub.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	gb, err := os.ReadFile(filepath.Join(offRoot, "data", aigate.GateFileName))
	if err != nil {
		t.Fatal(err)
	}
	gf, err := aigate.DecodeFile(gb)
	if err != nil || gf.Enabled || len(gf.Resources) != 0 {
		t.Errorf("gate file without the MCP listener: enabled %v, %d resources (%v)", gf != nil && gf.Enabled, len(gf.Resources), err)
	}
	// With the listener (this env), the same state publishes the companion.
	e.s.Hub.WritePolicy()
	gb, _ = os.ReadFile(filepath.Join(e.data, aigate.GateFileName))
	if gf, err := aigate.DecodeFile(gb); err != nil || !gf.Enabled || !slices.ContainsFunc(gf.Resources, func(r aigate.Resource) bool { return r.URL == aiappResource }) {
		t.Errorf("gate file with the MCP listener: %v %+v", err, gf)
	}
}

var mintStdinR = regexp.MustCompile(`^\{"action":"mint","user":"alice","instance":"aiapp","companion":"tok","name":"portcullis-ai-[a-z0-9]{12}","mode":"read_write","scopes":\["read:repository","write:repository"\]\}$`)

// TestMintCredential (§15.5, §15.7): in the population → the mint hook's
// stdin exactly; stdout {"credential":"c","id":"7"} → the entry written
// encrypted (state active), 200 {"id":"7"}, audited ai.credential.mint
// (target aiapp/tok/alice, detail id 7, never the credential); an active
// entry is answered without a hook; exit 3 → 409 no_account with the
// app's URL; exit 1 → 502 mint_failed, CompanionView.LastError set
// (redacted: no stdout); not in the population → 403; not a current
// app_token companion → 404; refused output → 502.
func TestMintCredential(t *testing.T) {
	e := newMCPEnv(t, nil)
	const cred = "c0nfidential-app-credential"
	e.eng.script(mintAnswer(`{"credential":"` + cred + `","id":"7"}`))
	if c, b := e.post(t, "/internal/credentials", e.mintBody("alice")); c != 200 || b != `{"id":"7"}` {
		t.Fatalf("mint = %d %s", c, b)
	}
	runs := e.eng.runs("/mint")
	if len(runs) != 1 || !mintStdinR.MatchString(runs[0]) {
		t.Fatalf("mint stdin = %q", runs)
	}
	f := e.creds(t)
	if len(f.Credentials) != 1 {
		t.Fatalf("credentials = %+v", f.Credentials)
	}
	got := f.Credentials[0]
	if got.Instance != "aiapp" || got.Companion != "tok" || got.User != "alice" || got.ID != "7" || got.State != aigate.StateActive || got.Age == "" {
		t.Errorf("entry = %+v", got)
	}
	if time.Since(got.MintedAt.Time) > time.Minute {
		t.Errorf("minted_at = %v", got.MintedAt)
	}
	pt, err := age.Decrypt(armorReader(got.Age), e.ident)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(pt); string(b) != cred {
		t.Errorf("decrypted = %q", b)
	}
	a := e.auditOf(t, "ai.credential.mint")
	if len(a) != 1 || a[0].Target != "aiapp/tok/alice" || a[0].Detail != "id 7" || a[0].Result != "ok" || a[0].Actor != "alice" {
		t.Errorf("audit = %+v", a)
	}
	// The credential is nowhere but in the ciphertext.
	if raw, _ := os.ReadFile(e.audit); strings.Contains(string(raw), cred) {
		t.Error("the audit holds the credential")
	}
	// Active entry: its id, no hook.
	if c, b := e.post(t, "/internal/credentials", e.mintBody("alice")); c != 200 || b != `{"id":"7"}` || len(e.eng.runs("/mint")) != 1 {
		t.Errorf("second mint = %d %s, %d runs", c, b, len(e.eng.runs("/mint")))
	}

	// bob: not in the population → 403, no hook.
	if c, _ := e.post(t, "/internal/credentials", e.mintBody("bob")); c != 403 {
		t.Errorf("bob = %d, want 403", c)
	}
	if c, _ := e.post(t, "/internal/credentials", e.mintBody("Alice")); c != 403 {
		t.Errorf("Alice (not the lowercase username) = %d, want 403", c)
	}
	// Not a current app_token companion resource → 404.
	for _, res := range []string{"https://aiapp.example.org/hdr/mcp", "https://mcp.example.org/mcp", "https://people.example.org/mcp", "https://hub.example.org/mcp", "https://other.example.org/mcp"} {
		if c, _ := e.post(t, "/internal/credentials", `{"resource":"`+res+`","user":"alice"}`); c != 404 {
			t.Errorf("%s = %d, want 404", res, c)
		}
	}
	if len(e.eng.runs("/mint")) != 1 {
		t.Fatal("a refused mint ran the hook")
	}

	// carol joins the population (a fresh directory snapshot, never the
	// gate file's): exit 3 → 409 no_account + app_url.
	e.ll.AddUser("carol", "carol@example.org", "Carol", "", "users_aiapp")
	e.eng.script(func(in docker.ExecInput) *docker.ExecSplitResult {
		return &docker.ExecSplitResult{ExecID: "x", ExitCode: 3, Stderr: []byte("no such user")}
	})
	if c, b := e.post(t, "/internal/credentials", e.mintBody("carol")); c != 409 || b != `{"app_url":"https://aiapp.example.org","code":"no_account"}` {
		t.Errorf("no account = %d %s", c, b)
	}
	if v := e.tok(t); v.LastError != "" {
		t.Errorf("no_account set LastError %q", v.LastError)
	}
	// exit 1 → 502 mint_failed; LastError has the exit code and stderr,
	// never the stdout.
	e.eng.script(func(in docker.ExecInput) *docker.ExecSplitResult {
		return &docker.ExecSplitResult{ExecID: "x", ExitCode: 1, Stdout: []byte("leaked-stdout-token"), Stderr: []byte("app said no: leaked-stdout-token")}
	})
	if c, b := e.post(t, "/internal/credentials", e.mintBody("carol")); c != 502 || b != `{"code":"mint_failed"}` {
		t.Errorf("failed = %d %s", c, b)
	}
	v := e.tok(t)
	if !strings.Contains(v.LastError, "exited 1") || !strings.Contains(v.LastError, "app said no") || strings.Contains(v.LastError, "leaked-stdout-token") || v.Status != "failed" {
		t.Errorf("LastError = %q (status %s)", v.LastError, v.Status)
	}
	// Refused output (extra key, duplicate key, escapes, bad id,
	// trailing data, two documents) → 502; nothing stored.
	for _, out := range []string{
		`{"credential":"c","id":"7","x":1}`, `{"credential":"c","id":"7","id":"8"}`, `{"credential":"c\"d","id":"7"}`,
		`{"credential":"c","id":"7 8"}`, `{"credential":"","id":"7"}`, `{"credential":"c","id":"7"} x`, `{"credential":"c","id":"7"}{}`,
		`{"credential":1,"id":"7"}`, `["c","7"]`, ``, `{"credential":"` + strings.Repeat("c", 4097) + `","id":"7"}`,
	} {
		e.eng.script(mintAnswer(out))
		if c, b := e.post(t, "/internal/credentials", e.mintBody("carol")); c != 502 || b != `{"code":"mint_failed"}` {
			t.Errorf("output %.60q = %d %s", out, c, b)
		}
	}
	if len(e.creds(t).Credentials) != 1 {
		t.Errorf("refused outputs stored: %+v", e.creds(t).Credentials)
	}
	// A success clears the mint error.
	e.eng.script(mintAnswer("{\"credential\": \"" + strings.Repeat("k", 4096) + "\", \"id\": \"9\"}\n"))
	if c, b := e.post(t, "/internal/credentials", e.mintBody("carol")); c != 200 || b != `{"id":"9"}` {
		t.Errorf("carol = %d %s", c, b)
	}
	if v := e.tok(t); v.LastError != "" || v.Credentials != 2 {
		t.Errorf("after success: LastError %q, credentials %d", v.LastError, v.Credentials)
	}
	for _, a := range readAudit(t, e.audit) {
		if strings.Contains(a.Error+a.Detail, "leaked-stdout-token") {
			t.Errorf("audit holds stdout: %+v", a)
		}
	}
	// An answer outside the contract (the directory down: 503) has a
	// fixed body; the detail is only logged.
	e.s.Hub.SetPeople(nil)
	if c, b := e.post(t, "/internal/credentials", e.mintBody("dave")); c != 503 || b != `{"error":"Service Unavailable"}` {
		t.Errorf("directory down = %d %s", c, b)
	}
}

// TestMintRefusedWhenOff: no mint (404) while the companion is off, owes
// a revoke_all, the master switch is off, or the instance is disabled —
// and never a hook run.
func TestMintRefusedWhenOff(t *testing.T) {
	// The start's owed revoke_all fails: RevokePending stays.
	failRevoke := func(g *aiHookEngine) {
		g.script(func(in docker.ExecInput) *docker.ExecSplitResult {
			if in.Cmd[0] == "/revoke" {
				return &docker.ExecSplitResult{ExecID: "x", ExitCode: 1}
			}
			return &docker.ExecSplitResult{ExecID: "x", Stdout: []byte(`{"credential":"c","id":"7"}`)}
		})
	}
	for name, seed := range map[string]func(*state.AppState){
		"companion off": func(st *state.AppState) {
			st.AIInstances["aiapp"].Companions["tok"] = state.AICompanion{Mode: "read_write"}
		},
		"revoke pending": func(st *state.AppState) {
			st.AIInstances["aiapp"].Companions["tok"] = state.AICompanion{Enabled: true, Mode: "read_write", RevokePending: true}
		},
		"master off": func(st *state.AppState) { st.AI.Enabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			e := newMCPEnv(t, seed, failRevoke)
			if name == "revoke pending" && (e.tok(t).Status == "on" || e.tok(t).LastError == "") {
				t.Fatalf("status = %s (%q): the owed revoke_all should have failed", e.tok(t).Status, e.tok(t).LastError)
			}
			if c, b := e.post(t, "/internal/credentials", e.mintBody("alice")); c != 404 {
				t.Errorf("mint = %d %s, want 404", c, b)
			}
			if len(e.eng.runs("/mint")) != 0 {
				t.Error("hook ran")
			}
		})
	}
	t.Run("instance disabled", func(t *testing.T) {
		e := newMCPEnv(t, nil)
		e.eng.script(mintAnswer(`{"credential":"c","id":"7"}`))
		if err := e.s.Hub.Disable("aiapp"); err != nil {
			t.Fatal(err)
		}
		e.s.Hub.Wait()
		if c, b := e.post(t, "/internal/credentials", e.mintBody("alice")); c != 404 {
			t.Errorf("mint = %d %s, want 404", c, b)
		}
		if len(e.eng.runs("/mint")) != 0 {
			t.Error("hook ran")
		}
	})
}

// TestConcurrentMintSingleFlight (Review Focus 2): 4 concurrent POST
// /internal/credentials for alice → one hook run, four 200 with the
// same id; a failing hook → one run, four mint_failed, one error audit;
// two people → two runs, each their own id.
func TestConcurrentMintSingleFlight(t *testing.T) {
	type ans struct {
		code int
		body string
	}
	// concurrently posts one mint per user (in that order) with the hook
	// held until every flight that can start has, then released.
	concurrently := func(e *mcpEnv, users ...string) []ans {
		gate := make(chan struct{})
		e.eng.mu.Lock()
		e.eng.gate = gate
		e.eng.mu.Unlock()
		answers := make(chan ans, len(users))
		for _, u := range users {
			go func() {
				c, b := e.post(t, "/internal/credentials", e.mintBody(u))
				answers <- ans{c, b}
			}()
		}
		deadline := time.Now().Add(10 * time.Second)
		for len(e.eng.runs("/mint")) == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		// Give the others time to join the flight (or queue on the AI
		// lock), then let the hook run.
		time.Sleep(300 * time.Millisecond)
		close(gate)
		var out []ans
		for range users {
			out = append(out, <-answers)
		}
		return out
	}
	t.Run("success", func(t *testing.T) {
		e := newMCPEnv(t, nil)
		e.eng.script(mintAnswer(`{"credential":"c-shared","id":"42"}`))
		for _, a := range concurrently(e, "alice", "alice", "alice", "alice") {
			if a.code != 200 || a.body != `{"id":"42"}` {
				t.Errorf("answer = %d %s", a.code, a.body)
			}
		}
		if n := len(e.eng.runs("/mint")); n != 1 {
			t.Errorf("mint hook ran %d times, want 1", n)
		}
		if n := len(e.auditOf(t, "ai.credential.mint")); n != 1 {
			t.Errorf("%d mint audits, want 1", n)
		}
	})
	t.Run("failure", func(t *testing.T) {
		e := newMCPEnv(t, nil)
		e.eng.script(func(in docker.ExecInput) *docker.ExecSplitResult {
			return &docker.ExecSplitResult{ExecID: "x", ExitCode: 1, Stderr: []byte("app down")}
		})
		for _, a := range concurrently(e, "alice", "alice", "alice", "alice") {
			if a.code != 502 || a.body != `{"code":"mint_failed"}` {
				t.Errorf("answer = %d %s", a.code, a.body)
			}
		}
		if n := len(e.eng.runs("/mint")); n != 1 {
			t.Errorf("mint hook ran %d times, want 1", n)
		}
		au := e.auditOf(t, "ai.credential.mint")
		if len(au) != 1 || au[0].Result != "error" {
			t.Errorf("mint audits = %+v, want one error", au)
		}
	})
	t.Run("keys", func(t *testing.T) {
		e := newMCPEnv(t, nil)
		e.ll.AddUser("carol", "carol@example.org", "Carol", "", "users_aiapp")
		e.eng.script(func(in docker.ExecInput) *docker.ExecSplitResult {
			var v struct{ User string }
			json.Unmarshal(in.Stdin, &v)
			return &docker.ExecSplitResult{ExecID: "x", Stdout: []byte(`{"credential":"c-` + v.User + `","id":"id-` + v.User + `"}`)}
		})
		got := concurrently(e, "alice", "carol")
		if got[0] == got[1] {
			t.Errorf("both answers equal: %v", got)
		}
		ids := map[string]bool{}
		for _, a := range got {
			if a.code != 200 {
				t.Errorf("answer = %d %s", a.code, a.body)
			}
			ids[a.body] = true
		}
		if !ids[`{"id":"id-alice"}`] || !ids[`{"id":"id-carol"}`] {
			t.Errorf("answers = %v", got)
		}
		if n := len(e.eng.runs("/mint")); n != 2 {
			t.Errorf("mint hook ran %d times, want 2", n)
		}
	})
}

// TestInternalAPIStrictJSON (§15.7): unknown fields, missing ones,
// trailing data and wrong types → 400; 64 KiB + 1 → 413; never a hook.
func TestInternalAPIStrictJSON(t *testing.T) {
	e := newMCPEnv(t, nil)
	e.eng.script(mintAnswer(`{"credential":"c","id":"7"}`))
	for _, body := range []string{
		`{"resource":"` + aiappResource + `","user":"alice","extra":1}`,
		`{"resource":"` + aiappResource + `"}`,
		`{"user":"alice"}`,
		`{"resource":"` + aiappResource + `","user":"alice"} {}`,
		`{"resource":"` + aiappResource + `","user":"alice"}x`,
		`{"resource":1,"user":"alice"}`,
		`{"resource":"` + aiappResource + `","user":null}`,
		`[]`, `null`, ``, `{`,
		// Case variants and duplicates (encoding/json would accept them).
		`{"resource":"` + aiappResource + `","User":"alice"}`,
		`{"Resource":"` + aiappResource + `","user":"alice"}`,
		`{"resource":"` + aiappResource + `","USER":"alice"}`,
		`{"resource":"` + aiappResource + `","user":"bob","user":"alice"}`,
		`{"resource":"https://x.example.org/mcp","resource":"` + aiappResource + `","user":"alice"}`,
	} {
		if c, b := e.post(t, "/internal/credentials", body); c != 400 || strings.Contains(b, "alice") {
			t.Errorf("%.60s = %d %s, want 400", body, c, b)
		}
	}
	pad := `{"resource":"` + aiappResource + `","user":"alice"}`
	over := pad + strings.Repeat(" ", 64<<10+1-len(pad))
	if c, _ := e.post(t, "/internal/credentials", over); c != 413 {
		t.Errorf("64 KiB + 1 = %d, want 413", c)
	}
	at := pad + strings.Repeat(" ", 64<<10-len(pad))
	if c, b := e.post(t, "/internal/credentials", at); c != 200 {
		t.Errorf("exactly 64 KiB = %d %s, want 200", c, b)
	}
	if n := len(e.eng.runs("/mint")); n != 1 {
		t.Errorf("hook runs = %d, want 1 (the valid request)", n)
	}
}

// armorReader reads an ASCII-armored age ciphertext.
func armorReader(s string) io.Reader {
	return armor.NewReader(strings.NewReader(s))
}
