package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Plan 4 Task 12a: per-instance AI support (contract §3.2 "What the Hub
// renders", §5 MCP routes, §8 mcp:* scopes, §15.5 hook I/O, §15.11).

// fakeAIKC is Keycloak's AI scope side: the mcp:* scopes and each AI
// client's exact mcp:* optional scopes.
type fakeAIKC struct {
	mu       sync.Mutex
	scopes   map[string]keycloak.MCPScope
	optional map[string][]string
	calls    []string
	// missing: clients that don't exist (SetOptionalScopes: not found).
	missing   map[string]bool
	failApply error
	// failEnsure: scope name → the error EnsureMCPScope answers.
	failEnsure map[string]error
	deleted    []string
}

func newFakeAIKC() *fakeAIKC {
	return &fakeAIKC{scopes: map[string]keycloak.MCPScope{}, optional: map[string][]string{}, missing: map[string]bool{}}
}

func (k *fakeAIKC) EnsureMCPScope(ctx context.Context, s keycloak.MCPScope) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, "ensure:"+s.Name)
	if err := k.failEnsure[s.Name]; err != nil {
		return err
	}
	k.scopes[s.Name] = s
	return nil
}

func (k *fakeAIKC) DeleteMCPScope(ctx context.Context, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, "delete:"+name)
	k.deleted = append(k.deleted, name)
	delete(k.scopes, name)
	for c, l := range k.optional {
		k.optional[c] = slices.DeleteFunc(slices.Clone(l), func(s string) bool { return s == name })
	}
	return nil
}

func (k *fakeAIKC) SetOptionalScopes(ctx context.Context, clientID string, scopes []string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, "set:"+clientID)
	if k.failApply != nil {
		return k.failApply
	}
	if k.missing[clientID] {
		return fmt.Errorf("client %s: %w", clientID, keycloak.ErrClientNotFound)
	}
	for _, s := range scopes {
		if _, ok := k.scopes[s]; !ok {
			return fmt.Errorf("client scope %s does not exist", s)
		}
	}
	k.optional[clientID] = slices.Sorted(slices.Values(scopes))
	return nil
}

func (k *fakeAIKC) opt(client string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.optional[client])
}

func (k *fakeAIKC) scope(name string) (keycloak.MCPScope, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.scopes[name]
	return s, ok
}

// seqLog records the order of hook runs and compose ups.
type seqLog struct {
	mu  sync.Mutex
	evs []string
}

func (s *seqLog) add(e string) {
	s.mu.Lock()
	s.evs = append(s.evs, e)
	s.mu.Unlock()
}

func (s *seqLog) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.evs)
}

type instAIFixture struct {
	*fixture
	kc     *fakeAIKC
	audit  *fakeAudit
	people *fakePeople
	ident  *age.X25519Identity
	seq    *seqLog
	// hookFail: argv[0] → the exit code, stdout and stderr it answers.
	mu       sync.Mutex
	hookFail map[string]docker.ExecSplitResult
}

// newInstAIFixture: domain example.com, a gate recipient, master switch on
// (Claude with the admin flag), the core env with PORTCULLIS_MCP_GATE_IP,
// the aiapp test template (and the oauth fixture as oauthapp), alice in
// users_aiapp, the Hub's AI clients healthy.
func newInstAIFixture(t *testing.T, seed func(*state.AppState)) *instAIFixture {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	a := &instAIFixture{kc: newFakeAIKC(), audit: &fakeAudit{}, ident: id, seq: &seqLog{}, hookFail: map[string]docker.ExecSplitResult{}}
	extra := map[string][2]string{
		"aiapp":    readFixture(t, filepath.Join("testdata", "ai", "aiapp")),
		"oauthapp": readFixture(t, filepath.Join("..", "templates", "testdata", "ai", "oauth")),
	}
	a.fixture = newInstanceFixtureCfg(t, func(st *state.AppState) {
		st.AI.Enabled = true
		st.AI.Clients.Claude.Admin = true
		if seed != nil {
			seed(st)
		}
	}, nil, extra, func(root string, c *Config) {
		c.Domain = "example.com"
		recip := filepath.Join(root, "age.pub")
		if err := os.WriteFile(recip, []byte(id.Recipient().String()+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		c.MCPGateRecipientFile = recip
		writeFile(t, filepath.Join(c.ProjectDir, ".env"), "CORE_VAR=core-value\nPORTCULLIS_MCP_GATE_IP=172.31.250.3\n")
	})
	for _, tid := range []string{"aiapp", "oauthapp"} {
		if a.h.Template(tid) == nil {
			t.Fatalf("template %s not loaded (see the log)", tid)
		}
	}
	a.h.SetAudit(a.audit)
	a.people = newFakePeople("carol")
	a.people.addGroup("users_aiapp", "alice")
	a.people.addGroup("users_oauthapp", "alice")
	a.people.addGroup("lldap_admin", "root")
	a.people.emails = map[string]string{"alice": "alice@example.org"}
	a.h.SetGroups(&fakeGroups{people: a.people, existing: map[string]bool{"users_aiapp": true, "users_oauthapp": true}})
	a.h.SetPeople(a.people)
	a.h.SetUserSweep(a.people, nil)
	a.h.SetAIKeycloak(a.kc)
	a.h.SetAIClientHealth(map[string]bool{keycloak.AIClientIDs.Claude: true, keycloak.AIClientIDs.ClaudeCode: true, keycloak.AIClientIDs.Generic: true})
	simulateCompose(a.fixture, 0)
	up := a.runner.upHook
	a.runner.upHook = func(p string) {
		a.seq.add("up:" + p)
		up(p)
	}
	a.engine.setExecSplit(func(cid string, in docker.ExecInput) (*docker.ExecSplitResult, error) {
		var act struct {
			Action string `json:"action"`
		}
		json.Unmarshal(in.Stdin, &act)
		a.seq.add(in.Cmd[0] + ":" + act.Action)
		a.mu.Lock()
		r, fail := a.hookFail[in.Cmd[0]]
		a.mu.Unlock()
		if fail {
			// Fresh buffers: the Hub zeroes the stdout it gets.
			r.Stdout, r.Stderr = slices.Clone(r.Stdout), slices.Clone(r.Stderr)
			return &r, nil
		}
		return &docker.ExecSplitResult{ExecID: "x"}, nil
	})
	return a
}

func (a *instAIFixture) enable(t *testing.T, id string) {
	t.Helper()
	if err := a.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
}

// stdins are the AI hook stdins of argv[0] cmd, in order.
func (a *instAIFixture) stdins(cmd string) []string {
	var out []string
	for _, c := range a.engine.SplitCalls() {
		if c.in.Cmd[0] == cmd {
			out = append(out, strings.TrimSpace(string(c.in.Stdin)))
		}
	}
	return out
}

func (a *instAIFixture) override(t *testing.T, id string) string {
	t.Helper()
	b, _ := os.ReadFile(a.h.overridePath(id))
	return string(b)
}

func (a *instAIFixture) gate(t *testing.T) *aigate.File {
	t.Helper()
	b, err := os.ReadFile(a.h.gatePath())
	if err != nil {
		t.Fatal(err)
	}
	f, err := aigate.DecodeFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (a *instAIFixture) audits(action string) []directory.AuditEntry {
	a.audit.mu.Lock()
	defer a.audit.mu.Unlock()
	var out []directory.AuditEntry
	for _, e := range a.audit.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (a *instAIFixture) companion(id, name string) state.AICompanion {
	a.h.mu.RLock()
	defer a.h.mu.RUnlock()
	return a.h.st.AIInstances[id].Companions[name]
}

func (a *instAIFixture) putCred(t *testing.T, id, companion, user string) {
	t.Helper()
	if err := a.h.creds().Put(aigate.Credential{Instance: id, Companion: companion, User: user, ID: "7", MintedAt: aigate.At(time.Now())}, []byte("app-credential-value")); err != nil {
		t.Fatal(err)
	}
}

func (a *instAIFixture) credsOf(id, companion string) []aigate.Credential {
	var out []aigate.Credential
	for _, c := range a.h.creds().Entries() {
		if c.Instance == id && c.Companion == companion {
			out = append(out, c)
		}
	}
	return out
}

var root = directory.Human("root")

const tokOverrideMCP = "traefik.http.routers.portcullis-mcp-aiapp--tok."

func TestSetAISupportOn(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	a.putCred(t, "aiapp", "tok", "alice") // a restore-as copy's leftover
	ups := len(a.runner.Calls())
	res, err := a.h.UpdateInstanceAI(context.Background(), "aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true), Mode: ptr("read_write")}}}, root)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Restarts {
		t.Error("restarts = false on an enabled instance (G49)")
	}
	// State, saved.
	if c := a.companion("aiapp", "tok"); !c.Enabled || c.Mode != "read_write" {
		t.Errorf("state = %+v", c)
	}
	if st, err := state.Load(a.h.statePath()); err != nil || !st.AIInstances["aiapp"].Companions["tok"].Enabled {
		t.Errorf("state.yaml = %+v (%v)", st.AIInstances, err)
	}
	// The scope (§8) and the three clients' exact optional scopes.
	sc, ok := a.kc.scope("mcp:aiapp.tok")
	if !ok || sc.Audience != "https://aiapp.example.com/mcp" || sc.ConsentText != "Use AI App (aiapp.example.com) as you" {
		t.Errorf("scope = %+v %v", sc, ok)
	}
	for _, s := range []string{"mcp:all", "mcp:portcullis.people", "mcp:portcullis.admin"} {
		if _, ok := a.kc.scope(s); !ok {
			t.Errorf("fixed scope %s not ensured", s)
		}
	}
	if got := a.kc.opt(keycloak.AIClientIDs.Claude); !slices.Equal(got, []string{"mcp:aiapp.tok", "mcp:all", "mcp:portcullis.admin", "mcp:portcullis.people"}) {
		t.Errorf("claude optional = %v", got)
	}
	for _, c := range []string{keycloak.AIClientIDs.ClaudeCode, keycloak.AIClientIDs.Generic} {
		if got := a.kc.opt(c); !slices.Equal(got, []string{"mcp:aiapp.tok", "mcp:all", "mcp:portcullis.people"}) {
			t.Errorf("%s optional = %v (no admin flag: no admin scope)", c, got)
		}
	}
	// The override: scale 1, the alias, the router (contract §5).
	ov := a.override(t, "aiapp")
	for _, want := range []string{
		"  tok-mcp:\n    scale: 1\n    networks:\n      default: {}\n      portcullis-proxy:\n        aliases:\n          - \"portcullis-mcp-aiapp--tok\"\n",
		`"` + tokOverrideMCP + "rule\": \"Host(`aiapp.example.com`) && (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))\"",
		`"` + tokOverrideMCP + `entrypoints": "websecure"`,
		`"` + tokOverrideMCP + `tls.options": "authaware@file"`,
		`"` + tokOverrideMCP + `service": "mcp-gate@docker"`,
		`"` + tokOverrideMCP + `middlewares": "rate-limit@file,security-headers@file"`,
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("override lacks %q:\n%s", want, ov)
		}
	}
	// Above every router of the instance, its public and sign-in routers
	// (bound + 1, bound + 2).
	m := regexp.MustCompile(regexp.QuoteMeta(tokOverrideMCP) + `priority": "(\d+)"`).FindStringSubmatch(ov)
	routes, err := templates.ParseRoutes(a.h.Template("aiapp").ReadCompose())
	if err != nil {
		t.Fatal(err)
	}
	ri := routes.Info["aiapp"]
	if m == nil {
		t.Fatalf("no priority:\n%s", ov)
	}
	if n, _ := strconv.Atoi(m[1]); n <= len(ri.Rule)+strings.Count(ri.Rule, "${")*253+2 {
		t.Errorf("priority %v not above the instance's routers, public and sign-in routers", m)
	}
	if strings.Contains(ov, "portcullis-mcp-aiapp--hdr") {
		t.Errorf("the switched-off companion is rendered:\n%s", ov)
	}
	// Env (§3.1).
	env := readFile(t, a.h.envPath("aiapp"))
	for _, want := range []string{"\nPORTCULLIS_AI_ENABLED=true\n", "\nPORTCULLIS_AI_READONLY_TOK=false\n", "\nPORTCULLIS_AI_READONLY_HDR=true\n", "\nPORTCULLIS_MCP_GATE_IP=172.31.250.3\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %q:\n%s", want, env)
		}
	}
	// compose up ran; revoke_all first, on_change last.
	if calls := a.runner.Calls(); len(calls) <= ups || calls[len(calls)-1] != "up:portcullis-aiapp" {
		t.Errorf("compose calls = %v", calls)
	}
	seq := a.seq.list()
	if i, j, k := slices.Index(seq, "/revoke:revoke_all"), slices.Index(seq, "up:portcullis-aiapp"), slices.Index(seq, "/toggle:on_change"); i < 0 || k < 0 || i > k || slices.Index(seq[i:], "up:portcullis-aiapp") < 0 || j < 0 {
		t.Errorf("sequence = %v", seq)
	}
	if got := a.stdins("/revoke"); !slices.Equal(got, []string{`{"action":"revoke_all","prefix":"portcullis-ai-"}`}) {
		t.Errorf("revoke stdin = %v", got)
	}
	if got := a.stdins("/toggle"); !slices.Equal(got, []string{`{"action":"on_change","enabled":true,"mode":"read_write","companion":"tok"}`}) {
		t.Errorf("on_change stdin = %v", got)
	}
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("credential entries kept after revoke_all: %+v", left)
	}
	// The gate file lists it.
	f := a.gate(t)
	r := resourceByURL(f, "https://aiapp.example.com/mcp")
	if r == nil || r.Mode != "read_write" || r.Scope != "mcp:aiapp.tok" {
		t.Errorf("gate resources = %v", urls(f))
	}
	if e := a.audits("ai.enable"); len(e) != 1 || e[0].Result != "ok" || e[0].Target != "aiapp/tok" || e[0].Actor != "root" {
		t.Errorf("audit = %+v", e)
	}
	if op := a.h.LastOp("aiapp"); op == nil || op.Op != OpAI || !op.OK {
		t.Errorf("op = %+v", op)
	}
}

func TestSetAISupportOff(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.putCred(t, "aiapp", "tok", "alice")
	revokes := len(a.stdins("/revoke"))
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err != nil {
		t.Fatal(err)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled {
		t.Errorf("state = %+v", c)
	}
	ov := a.override(t, "aiapp")
	if strings.Contains(ov, "portcullis-mcp-aiapp--tok") {
		t.Errorf("router or alias kept:\n%s", ov)
	}
	if !strings.Contains(ov, "  tok-mcp:\n    scale: 0\n") {
		t.Errorf("no scale 0:\n%s", ov)
	}
	if _, ok := a.kc.scope("mcp:aiapp.tok"); ok {
		t.Error("scope kept")
	}
	if got := a.kc.opt(keycloak.AIClientIDs.Generic); slices.Contains(got, "mcp:aiapp.tok") {
		t.Errorf("generic still has the scope: %v", got)
	}
	if got := a.stdins("/revoke"); len(got) != revokes+1 || got[len(got)-1] != `{"action":"revoke_all","prefix":"portcullis-ai-"}` {
		t.Errorf("revoke stdins = %v", got)
	}
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries kept: %+v", left)
	}
	if got := a.stdins("/toggle"); got[len(got)-1] != `{"action":"on_change","enabled":false,"mode":"read_write","companion":"tok"}` {
		t.Errorf("on_change = %v", got)
	}
	if r := resourceByURL(a.gate(t), "https://aiapp.example.com/mcp"); r != nil {
		t.Error("gate still lists it")
	}
	env := readFile(t, a.h.envPath("aiapp"))
	if !strings.Contains(env, "\nPORTCULLIS_AI_ENABLED=false\n") || !strings.Contains(env, "\nPORTCULLIS_AI_READONLY_TOK=true\n") {
		t.Errorf("env:\n%s", env)
	}
	if e := a.audits("ai.disable"); len(e) != 1 || e[0].Result != "ok" || e[0].Target != "aiapp/tok" {
		t.Errorf("audit = %+v", e)
	}
}

func TestSetAIModeRevokesFirst(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.putCred(t, "aiapp", "tok", "alice")
	mark := len(a.seq.list())
	if err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_only", root); err != nil {
		t.Fatal(err)
	}
	seq := a.seq.list()[mark:]
	i, j := slices.Index(seq, "/revoke:revoke_all"), slices.Index(seq, "up:portcullis-aiapp")
	if i < 0 || j < 0 || i > j {
		t.Errorf("revoke_all not before the restart: %v", seq)
	}
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries kept: %+v", left)
	}
	if !strings.Contains(readFile(t, a.h.envPath("aiapp")), "\nPORTCULLIS_AI_READONLY_TOK=true\n") {
		t.Error("read-only flag not true")
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled || c.Mode != "read_only" {
		t.Errorf("state = %+v", c)
	}
	if e := a.audits("ai.mode"); len(e) != 1 || e[0].Detail != "read_write -> read_only" || e[0].Target != "aiapp/tok" {
		t.Errorf("audit = %+v", e)
	}
	// A failing revoke_all: 502 with the redacted stderr, the mode stays.
	a.mu.Lock()
	a.hookFail["/revoke"] = docker.ExecSplitResult{ExitCode: 2, Stderr: []byte("app api down\n")}
	a.mu.Unlock()
	err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_write", root)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusBadGateway || !strings.Contains(err.Error(), "app api down") || !strings.Contains(err.Error(), "exited 2") {
		t.Errorf("err = %v", err)
	}
	if c := a.companion("aiapp", "tok"); c.Mode != "read_only" {
		t.Errorf("mode changed despite revoke_all failing: %+v", c)
	}
}

func TestAIRefusals(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	on := func(id, c string) error { return a.h.SetAISupport(context.Background(), id, c, true, root) }
	status := func(err error) int {
		var se *StatusError
		if errors.As(err, &se) {
			return se.Status
		}
		if errors.Is(err, ErrNotFound) {
			return 404
		}
		return 0
	}
	// Master switch off.
	a.h.mu.Lock()
	a.h.st.AI.Enabled = false
	a.h.mu.Unlock()
	if err := on("aiapp", "tok"); status(err) != 409 {
		t.Errorf("master off: %v", err)
	}
	a.h.mu.Lock()
	a.h.st.AI.Enabled = true
	a.h.mu.Unlock()
	// Deleting / restoring.
	for _, st := range []string{state.InstanceDeleting, state.InstanceRestoring} {
		a.h.mu.Lock()
		a.h.st.Instances["aiapp"] = state.Instance{ID: "aiapp", Template: "aiapp", State: st}
		a.h.mu.Unlock()
		if err := on("aiapp", "tok"); status(err) != 409 {
			t.Errorf("%s: %v", st, err)
		}
		a.h.mu.Lock()
		delete(a.h.st.Instances, "aiapp")
		a.h.mu.Unlock()
	}
	// LoA 3.
	for _, p := range []policy.AuthPolicy{{Factors: []string{"mtls"}, Op: "any"}, {Factors: []string{"mtls", "webauthn"}, Op: "all"}} {
		a.h.mu.Lock()
		a.h.st.AuthPolicies["aiapp"] = p
		a.h.mu.Unlock()
		err := on("aiapp", "tok")
		if status(err) != 409 || !strings.Contains(err.Error(), "needs a client certificate on every request; AI clients can't present one") {
			t.Errorf("%v: %v", p, err)
		}
	}
	a.h.mu.Lock()
	delete(a.h.st.AuthPolicies, "aiapp")
	a.h.mu.Unlock()
	// unsupported template, unknown companion, a mode outside modes.
	if err := a.h.SetAISupport(context.Background(), "grafana", "x", true, root); status(err) != 409 {
		t.Errorf("unsupported: %v", err)
	}
	if err := on("aiapp", "nope"); status(err) != 404 {
		t.Errorf("unknown companion: %v", err)
	}
	if err := a.h.SetAIMode(context.Background(), "aiapp", "hdr", "read_write", root); status(err) != 400 {
		t.Errorf("mode outside modes: %v", err)
	}
	// Another container on portcullis-proxy answers the alias.
	a.engine.mu.Lock()
	a.engine.containers = append(a.engine.containers, docker.Container{ID: "rogue", Names: []string{"/rogue"}, State: "running",
		Labels: map[string]string{}, Networks: map[string][]string{"portcullis-proxy": {"rogue", "portcullis-mcp-aiapp--tok"}}})
	a.engine.mu.Unlock()
	if err := on("aiapp", "tok"); status(err) != 409 || !strings.Contains(err.Error(), "portcullis-mcp-aiapp--tok") {
		t.Errorf("alias taken: %v", err)
	}
	// No actor.
	if err := a.h.SetAISupport(context.Background(), "aiapp", "hdr", true, directory.Actor{}); status(err) != 401 {
		t.Errorf("no actor: %v", err)
	}
	// Nothing was switched on; every refusal audited.
	if c := a.companion("aiapp", "tok"); c.Enabled {
		t.Errorf("state = %+v", c)
	}
	if len(a.stdins("/revoke")) != 0 {
		t.Error("a refused switch-on ran a hook")
	}
	for _, e := range a.audits("ai.enable") {
		if e.Result != "refused" {
			t.Errorf("audit %+v", e)
		}
	}
}

func TestAliasLengthRefused(t *testing.T) {
	long := "aiapp-" + strings.Repeat("x", 40) // 15 + 46 + 2 + 3 > 63
	err := checkAliasFits(long, "tok")
	if err == nil || !strings.Contains(err.Error(), "63") {
		t.Errorf("err = %v", err)
	}
}

func TestPolicySaveTurnsAIOff(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	mtls := &policy.AuthPolicy{Factors: []string{"mtls"}, Op: "any"}
	pv, err := a.h.PreviewSettings(context.Background(), "aiapp", SettingsUpdate{Policy: mtls})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(pv.Warnings, func(w string) bool { return strings.Contains(w, "AI support") && strings.Contains(w, "tok") }) {
		t.Errorf("preview warnings = %v", pv.Warnings)
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled {
		t.Fatal("the preview switched AI off")
	}
	res, err := a.h.SaveSettings("aiapp", SettingsUpdate{Policy: mtls}, root)
	if err != nil {
		t.Fatal(err)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled {
		t.Errorf("AI still on: %+v", c)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "AI support") }) {
		t.Errorf("save warnings = %v", res.Warnings)
	}
	if e := a.audits("ai.disable"); len(e) != 1 || e[0].Detail != "policy needs mTLS" {
		t.Errorf("audit = %+v", e)
	}
	// The Hub default (G43): every inheriting instance reaching LoA 3.
	a.h.Wait() // the save's background restart
	a.h.mu.Lock()
	delete(a.h.st.AuthPolicies, "aiapp")
	a.h.mu.Unlock()
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if w := a.h.DefaultPolicyAIWarnings(*mtls); len(w) != 1 || !strings.Contains(w[0], "aiapp") {
		t.Errorf("default preview = %v", w)
	}
	_, warnings, err := a.h.SetDefaultPolicyAs(*mtls, root)
	if err != nil {
		t.Fatal(err)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled || len(warnings) != 1 {
		t.Errorf("default save: AI %+v, warnings %v", c, warnings)
	}
	if e := a.audits("ai.disable"); len(e) != 2 || e[1].Detail != "policy needs mTLS" {
		t.Errorf("audit = %+v", e)
	}
}

func TestMCPRouterIsExposureLabel(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.mu.RLock()
	want, err := a.h.desiredRouteLabelsLocked(a.h.findLocked("aiapp"))
	a.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: "app", docker.LabelNumber: "1"}
	for k, v := range want["app"] {
		labels[k] = v
	}
	if labels[tokOverrideMCP+"rule"] == "" {
		t.Fatalf("desired labels lack the MCP router: %v", want["app"])
	}
	setApp := func(l map[string]string, nets map[string][]string) {
		a.engine.mu.Lock()
		defer a.engine.mu.Unlock()
		a.engine.containers = []docker.Container{{ID: "c1", Names: []string{"/portcullis-aiapp-app-1"}, State: "running", Labels: l, Networks: nets},
			{ID: "c2", Names: []string{"/portcullis-aiapp-tok-mcp-1"}, State: "running", Networks: map[string][]string{"portcullis-proxy": {"portcullis-mcp-aiapp--tok"}},
				Labels: map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: "tok-mcp", docker.LabelNumber: "1"}}}
	}
	drift := func() string {
		for _, d := range a.h.Reconcile(context.Background()).Items {
			if d.ID == "aiapp" && d.Kind == DriftPublicAccess {
				return d.Message
			}
		}
		return ""
	}
	setApp(labels, map[string][]string{"portcullis-proxy": {"portcullis-aiapp-app-1"}})
	if d := drift(); d != "" {
		t.Fatalf("drift with the rendered labels: %s", d)
	}
	changed := maps.Clone(labels)
	changed[tokOverrideMCP+"rule"] = "Host(`aiapp.example.com`)"
	setApp(changed, nil)
	if d := drift(); !strings.Contains(d, "portcullis-mcp-aiapp--tok") {
		t.Errorf("a widened MCP rule is no drift: %q", d)
	}
	// A portcullis-mcp- alias the Hub doesn't render is exposure drift.
	setApp(labels, map[string][]string{"portcullis-proxy": {"portcullis-mcp-aiapp--hdr"}})
	if d := drift(); !strings.Contains(d, "portcullis-mcp-aiapp--hdr") {
		t.Errorf("an extra MCP alias is no drift: %q", d)
	}
	// An image label defining a portcullis-mcp-* router is refused.
	img := maps.Clone(labels)
	img["traefik.http.routers.portcullis-mcp-aiapp--evil.rule"] = "Host(`aiapp.example.com`)"
	setApp(img, nil)
	if p := a.h.imageLabelProblem(a.h.Template("aiapp")); !strings.Contains(p, "portcullis-mcp-aiapp--evil") {
		t.Errorf("image-label problem = %q", p)
	}
}

func TestOnChangeHookOutputNeverStored(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	a.mu.Lock()
	a.hookFail["/toggle"] = docker.ExecSplitResult{ExitCode: 1, Stdout: []byte("TOKEN-MARKER\n"), Stderr: []byte("failed to apply TOKEN-MARKER\n")}
	a.mu.Unlock()
	err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root)
	var oe *OpError
	if !errors.As(err, &oe) || oe.Record.Op != OpAI {
		t.Fatalf("err = %v, want an OpError (op ai)", err)
	}
	if strings.Contains(err.Error(), "TOKEN-MARKER") || !strings.Contains(err.Error(), "exited 1") || !strings.Contains(err.Error(), "failed to apply") {
		t.Errorf("err = %q", err.Error())
	}
	v, verr := a.h.InstanceAI("aiapp")
	if verr != nil {
		t.Fatal(verr)
	}
	var tok *CompanionView
	for i := range v.Companions {
		if v.Companions[i].Name == "tok" {
			tok = &v.Companions[i]
		}
	}
	if tok == nil || !strings.Contains(tok.LastError, "exited 1") || strings.Contains(tok.LastError, "TOKEN-MARKER") {
		t.Errorf("last error = %+v", tok)
	}
	// The state was saved (a failure after the state save): AI is on.
	if c := a.companion("aiapp", "tok"); !c.Enabled {
		t.Errorf("state = %+v", c)
	}
	for _, dir := range []string{a.data, a.project} {
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if b, _ := os.ReadFile(p); strings.Contains(string(b), "TOKEN-MARKER") {
				t.Errorf("%s holds the hook's stdout", p)
			}
			return nil
		})
	}
	for _, e := range a.audits("ai.enable") {
		if strings.Contains(e.Error, "TOKEN-MARKER") {
			t.Errorf("audit holds the stdout: %+v", e)
		}
	}
	// The same request re-applies every step.
	a.mu.Lock()
	delete(a.hookFail, "/toggle")
	a.mu.Unlock()
	n := len(a.stdins("/toggle"))
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if len(a.stdins("/toggle")) != n+1 {
		t.Error("the retry didn't re-run on_change")
	}
	if op := a.h.LastOp("aiapp"); op == nil || !op.OK || op.Op != OpAI {
		t.Errorf("op after the retry = %+v", op)
	}
}

func TestAppOAuthCompanion(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "oauthapp")
	a.engine.mu.Lock()
	a.engine.containers = append(a.engine.containers, container("oauthapp-web", "portcullis-oauthapp", "web", "running"))
	a.engine.mu.Unlock()
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	if c := a.companion("oauthapp", "oauth"); !c.Enabled || c.Mode != "read_write" {
		t.Errorf("state = %+v", c)
	}
	if ov := a.override(t, "oauthapp"); strings.Contains(ov, "portcullis-mcp-") {
		t.Errorf("app_oauth rendered a router or alias:\n%s", ov)
	}
	if _, ok := a.kc.scope("mcp:oauthapp.oauth"); ok {
		t.Error("app_oauth got a scope")
	}
	for _, r := range a.gate(t).Resources {
		if r.Instance == "oauthapp" {
			t.Errorf("gate lists app_oauth: %+v", r)
		}
	}
	// revoke_all first (contract §15.5: every person's MCP tokens), then
	// on_change.
	if got := a.stdins("/revoke"); !slices.Equal(got, []string{`{"action":"revoke_all","prefix":"portcullis-ai-"}`}) {
		t.Errorf("revoke = %v", got)
	}
	if got := a.stdins("/toggle"); !slices.Equal(got, []string{`{"action":"on_change","enabled":true,"mode":"read_write","companion":"oauth"}`}) {
		t.Errorf("on_change = %v", got)
	}
	if !strings.Contains(readFile(t, a.h.envPath("oauthapp")), "\nPORTCULLIS_AI_ENABLED=true\n") {
		t.Error("env not enabled")
	}
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", false, root); err != nil {
		t.Fatal(err)
	}
	if got := a.stdins("/toggle"); got[len(got)-1] != `{"action":"on_change","enabled":false,"mode":"read_write","companion":"oauth"}` {
		t.Errorf("on_change = %v", got)
	}
}

// G49: on a disabled instance the switch only saves state.
func TestAISwitchOnDisabledInstance(t *testing.T) {
	a := newInstAIFixture(t, nil)
	res, err := a.h.UpdateInstanceAI(context.Background(), "aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true)}}}, root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Restarts {
		t.Error("restarts on a disabled instance")
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled || c.Mode != "read_write" {
		t.Errorf("state = %+v (default mode read_write)", c)
	}
	if len(a.engine.SplitCalls()) != 0 || slices.Contains(a.runner.Calls(), "up:portcullis-aiapp") {
		t.Errorf("hooks %v / compose %v ran on a disabled instance", a.engine.SplitCalls(), a.runner.Calls())
	}
	// Enabling it renders what state says.
	a.enable(t, "aiapp")
	if ov := a.override(t, "aiapp"); !strings.Contains(ov, tokOverrideMCP+"rule") {
		t.Errorf("enable didn't render the MCP router:\n%s", ov)
	}
}

// The scope helper (shared with Task 12b): every switched-on companion
// scope, mcp:all, people while on, admin only for offered clients with
// the flag while PortcullisAdmin is on; an ai_client gets mcp:all only.
func TestWantedAIScopes(t *testing.T) {
	a := newInstAIFixture(t, func(st *state.AppState) {
		st.AIInstances = map[string]state.AIInstance{"aiapp": {Companions: map[string]state.AICompanion{
			"tok": {Enabled: true, Mode: "read_write"}, "hdr": {Enabled: false, Mode: "read_only"}}},
			"oauthapp": {Companions: map[string]state.AICompanion{"oauth": {Enabled: true, Mode: "read_write"}}}}
	})
	if got := a.h.wantedAIScopes(keycloak.AIClientIDs.Claude); !slices.Equal(got, []string{"mcp:aiapp.tok", "mcp:all", "mcp:portcullis.admin", "mcp:portcullis.people"}) {
		t.Errorf("claude = %v", got)
	}
	if got := a.h.wantedAIScopes("aichat-chat-mcp"); !slices.Equal(got, []string{"mcp:all"}) {
		t.Errorf("ai_client = %v", got)
	}
	a.h.mu.Lock()
	a.h.st.AI.PortcullisAdmin, a.h.st.AI.PortcullisPeople = false, false
	a.h.mu.Unlock()
	if got := a.h.wantedAIScopes(keycloak.AIClientIDs.Claude); !slices.Equal(got, []string{"mcp:aiapp.tok", "mcp:all"}) {
		t.Errorf("claude, Portcullis MCPs off = %v", got)
	}
}

// G5: the settings engine's Retry runs no ai hook of the AI test
// template either (on_change included).
func TestRetryRunsNoAIHookAIApp(t *testing.T) {
	a := newInstAIFixture(t, func(st *state.AppState) {
		st.AIInstances = map[string]state.AIInstance{"aiapp": {Companions: map[string]state.AICompanion{"tok": {Enabled: true, Mode: "read_write"}}}}
	})
	a.enable(t, "aiapp")
	if _, err := a.h.RetryDeliveries(context.Background(), "aiapp", root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	for _, c := range a.engine.ExecCalls() {
		switch c.in.Cmd[0] {
		case "/mint", "/revoke", "/toggle":
			t.Errorf("the settings engine ran ai hook %v", c.in.Cmd)
		}
	}
	if n := len(a.engine.SplitCalls()); n != 0 {
		t.Errorf("%d AI hook runs from a retry", n)
	}
}

// A switch or mode change on a stopped instance can't run revoke_all:
// the Hub-side entries go at once, revoke_all is owed (RevokePending),
// and the next start runs it before the companion is rendered or listed;
// a failing one keeps the companion off.
func TestRevokePendingOnStoppedInstance(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if err := a.h.Disable("aiapp"); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	a.putCred(t, "aiapp", "tok", "alice")
	// Each up records whether the router was rendered then.
	up := a.runner.upHook
	a.runner.upHook = func(p string) {
		if strings.Contains(a.override(t, "aiapp"), tokOverrideMCP+"rule") {
			a.seq.add("up-rendered")
		}
		up(p)
	}
	mark := len(a.seq.list())
	if err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_only", root); err != nil {
		t.Fatal(err)
	}
	if c := a.companion("aiapp", "tok"); !c.RevokePending || c.Mode != "read_only" {
		t.Fatalf("state = %+v, want revoke_pending", c)
	}
	if left := a.credsOf("aiapp", "tok"); len(left) != 0 {
		t.Errorf("entries kept on a stopped instance: %+v", left)
	}
	if len(a.seq.list()) != mark {
		t.Errorf("hooks or compose ran on a stopped instance: %v", a.seq.list()[mark:])
	}
	a.enable(t, "aiapp")
	seq := a.seq.list()[mark:]
	i, j := slices.Index(seq, "/revoke:revoke_all"), slices.Index(seq, "up-rendered")
	if i < 0 || j < 0 || i > j {
		t.Errorf("revoke_all not before the companion was rendered: %v", seq)
	}
	if c := a.companion("aiapp", "tok"); c.RevokePending {
		t.Errorf("flag kept after a good revoke_all: %+v", c)
	}
	if r := resourceByURL(a.gate(t), "https://aiapp.example.com/mcp"); r == nil || r.Mode != "read_only" {
		t.Errorf("gate = %v", urls(a.gate(t)))
	}

	// A failing owed revoke_all keeps it off.
	if err := a.h.Disable("aiapp"); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_write", root); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.hookFail["/revoke"] = docker.ExecSplitResult{ExitCode: 5, Stderr: []byte("app down\n")}
	a.mu.Unlock()
	a.enable(t, "aiapp")
	if c := a.companion("aiapp", "tok"); !c.RevokePending {
		t.Errorf("flag cleared by a failed revoke_all: %+v", c)
	}
	if r := resourceByURL(a.gate(t), "https://aiapp.example.com/mcp"); r != nil {
		t.Error("the gate lists a companion owing a revoke_all")
	}
	if ov := a.override(t, "aiapp"); strings.Contains(ov, "portcullis-mcp-aiapp--tok") || !strings.Contains(ov, "  tok-mcp:\n    scale: 0\n") {
		t.Errorf("rendered while revoke_all is owed:\n%s", ov)
	}
	v, err := a.h.InstanceAI("aiapp")
	if err != nil || !strings.Contains(v.Companions[0].LastError, "exited 5") {
		t.Errorf("last error = %+v %v", v, err)
	}
}

// ── fix round 1 ─────────────────────────────────────────

func (a *instAIFixture) failHook(cmd string, exit int, stderr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if exit == 0 {
		delete(a.hookFail, cmd)
		return
	}
	a.hookFail[cmd] = docker.ExecSplitResult{ExitCode: exit, Stderr: []byte(stderr)}
}

func (a *instAIFixture) env(t *testing.T, id string) string {
	t.Helper()
	return readFile(t, a.h.envPath(id))
}

// R1-1: a companion owing a revoke_all counts as off in the env
// (app_oauth too) until the owed revoke succeeds; then re-rendered.
func TestRevokePendingEnvIsOff(t *testing.T) {
	a := newInstAIFixture(t, nil)
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	if c := a.companion("oauthapp", "oauth"); !c.RevokePending || !c.OnChangePending {
		t.Fatalf("state = %+v", c)
	}
	a.failHook("/revoke", 4, "app down\n")
	a.runner.upHook = func(p string) {
		a.engine.mu.Lock()
		defer a.engine.mu.Unlock()
		for _, c := range a.engine.containers {
			if c.Project() == p {
				return
			}
		}
		a.engine.containers = append(a.engine.containers, container(p+"-web", p, "web", "running"))
	}
	a.enable(t, "oauthapp")
	if env := a.env(t, "oauthapp"); !strings.Contains(env, "\nPORTCULLIS_AI_ENABLED=false\n") {
		t.Errorf("env enabled while the revoke_all is owed:\n%s", env)
	}
	if c := a.companion("oauthapp", "oauth"); !c.RevokePending {
		t.Errorf("state = %+v", c)
	}
	if got := a.stdins("/toggle"); len(got) != 0 {
		t.Errorf("on_change ran before the owed revoke_all succeeded: %v", got)
	}
	a.failHook("/revoke", 0, "")
	if err := a.h.RestartApp("oauthapp"); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if env := a.env(t, "oauthapp"); !strings.Contains(env, "\nPORTCULLIS_AI_ENABLED=true\n") {
		t.Errorf("env not enabled after the owed revoke_all:\n%s", env)
	}
	if c := a.companion("oauthapp", "oauth"); c.RevokePending || c.OnChangePending {
		t.Errorf("flags kept: %+v", c)
	}
	if got := a.stdins("/toggle"); !slices.Equal(got, []string{`{"action":"on_change","enabled":true,"mode":"read_write","companion":"oauth"}`}) {
		t.Errorf("on_change = %v", got)
	}
}

// R1-2a: a policy reaching LoA 3 saved while a switch-on is planned:
// the switch-on's commit re-checks under mu and refuses (409).
func TestAISwitchOnRacesPolicySave(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	a.h.testHookAIBeforeSave = func() {
		a.h.mu.Lock()
		a.h.st.AuthPolicies["aiapp"] = policy.AuthPolicy{Factors: []string{"mtls"}, Op: "any"}
		a.h.mu.Unlock()
	}
	err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 409 || !strings.Contains(err.Error(), mtlsRefusal) {
		t.Errorf("err = %v", err)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled {
		t.Errorf("AI switched on at LoA 3: %+v", c)
	}
	// The master switch turned off meanwhile.
	a.h.testHookAIBeforeSave = func() {
		a.h.mu.Lock()
		delete(a.h.st.AuthPolicies, "aiapp")
		a.h.st.AI.Enabled = false
		a.h.mu.Unlock()
	}
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); !errors.As(err, &se) || se.Status != 409 {
		t.Errorf("master off: %v", err)
	}
}

// R1-2b: a switch-on between SaveSettings' switch-off and its commit,
// and a default policy saved while an inheriting companion is on: 409.
func TestPolicySaveRacesSwitchOn(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	on := func() {
		a.h.mu.Lock()
		ai := a.h.st.AIInstances["aiapp"]
		ai.Companions = maps.Clone(ai.Companions)
		ai.Companions["tok"] = state.AICompanion{Enabled: true, Mode: "read_write"}
		a.h.st.AIInstances["aiapp"] = ai
		a.h.mu.Unlock()
	}
	a.h.testHookSave = on
	mtls := &policy.AuthPolicy{Factors: []string{"mtls"}, Op: "any"}
	_, err := a.h.SaveSettings("aiapp", SettingsUpdate{Policy: mtls}, root)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 409 {
		t.Errorf("save = %v", err)
	}
	a.h.mu.RLock()
	_, saved := a.h.st.AuthPolicies["aiapp"]
	a.h.mu.RUnlock()
	if saved {
		t.Error("the LoA 3 policy was committed with AI on")
	}
	a.h.testHookSave = nil
	if _, err := a.h.SetDefaultPolicy(*mtls); !errors.As(err, &se) || se.Status != 409 {
		t.Errorf("default = %v", err)
	}
	if p := a.h.DefaultPolicy(); policy.LoA(p) == 3 {
		t.Error("the default was saved")
	}
}

// R1-3: a start that can't get the AI lock within aiPendingWait records
// it (the companions' last error) and keeps the flags.
func TestPendingAIWaitsBounded(t *testing.T) {
	a := newInstAIFixture(t, nil)
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	old := aiPendingWait
	aiPendingWait = 50 * time.Millisecond
	t.Cleanup(func() { aiPendingWait = old })
	unlock := a.h.aiLock("aiapp")
	a.enable(t, "aiapp")
	unlock()
	v, err := a.h.InstanceAI("aiapp")
	if err != nil || !strings.Contains(v.Companions[0].LastError, "AI lock was busy") || v.Companions[0].Status != "failed" {
		t.Errorf("tab = %+v %v", v, err)
	}
	if c := a.companion("aiapp", "tok"); !c.RevokePending {
		t.Errorf("flag lost: %+v", c)
	}
}

// R1-4: a failed ensure still applies the other scopes and deletes the
// dropped ones.
func TestScopesApplyDespiteFailedEnsure(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.kc.mu.Lock()
	a.kc.failEnsure = map[string]error{"mcp:all": errors.New("keycloak 500")}
	a.kc.mu.Unlock()
	err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root)
	var oe *OpError
	if !errors.As(err, &oe) || !strings.Contains(err.Error(), "mcp:all") {
		t.Errorf("err = %v", err)
	}
	if !slices.Contains(a.kc.deleted, "mcp:aiapp.tok") {
		t.Errorf("the dropped scope wasn't deleted: %v", a.kc.calls)
	}
	if got := a.kc.opt(keycloak.AIClientIDs.Generic); !slices.Equal(got, []string{"mcp:portcullis.people"}) {
		t.Errorf("generic = %v (the ensured scopes only)", got)
	}
}

// R1-5: PORTCULLIS_MCP_GATE_IP is written only as an IP inside
// PORTCULLIS_PROXY_SUBNET (when set).
func TestGateIPChecked(t *testing.T) {
	a := newInstAIFixture(t, nil)
	core := filepath.Join(a.project, ".env")
	for body, want := range map[string]string{
		"PORTCULLIS_MCP_GATE_IP=172.31.250.3\nPORTCULLIS_PROXY_SUBNET=172.31.250.0/24\n": "172.31.250.3",
		"PORTCULLIS_MCP_GATE_IP=172.31.250.3\nPORTCULLIS_PROXY_SUBNET=10.0.0.0/8\n":      "",
		"PORTCULLIS_MCP_GATE_IP=not-an-ip\n":                                             "",
		"PORTCULLIS_MCP_GATE_IP=172.31.250.3\n":                                          "172.31.250.3",
	} {
		writeFile(t, core, body)
		if got := a.h.gateIP(); got != want {
			t.Errorf("%q: gate IP = %q, want %q", body, got, want)
		}
	}
}

// R1-6: every portcullis-mcp- router key is an exposure label, and a
// container still carrying an MCP router after AI went off is drift.
func TestMCPRouterLeftOverIsDrift(t *testing.T) {
	for _, k := range []string{"traefik.http.routers.portcullis-mcp-aiapp--tok.rule", "Traefik.HTTP.Routers.Portcullis-MCP-x--y.Service"} {
		if !exposureLabel("aiapp", k, false) {
			t.Errorf("%s is no exposure label", k)
		}
	}
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	a.h.mu.RLock()
	want, err := a.h.desiredRouteLabelsLocked(a.h.findLocked("aiapp"))
	a.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: "app", docker.LabelNumber: "1"}
	for k, v := range want["app"] {
		labels[k] = v
	}
	labels[tokOverrideMCP+"rule"] = "Host(`aiapp.example.com`) && (Path(`/mcp`))"
	labels[tokOverrideMCP+"service"] = "mcp-gate@docker"
	a.engine.mu.Lock()
	a.engine.containers = []docker.Container{{ID: "c1", Names: []string{"/portcullis-aiapp-app-1"}, State: "running", Labels: labels}}
	a.engine.mu.Unlock()
	var msg string
	for _, d := range a.h.Reconcile(context.Background()).Items {
		if d.ID == "aiapp" && d.Kind == DriftPublicAccess {
			msg = d.Message
		}
	}
	if !strings.Contains(msg, "unexpected routers.portcullis-mcp-aiapp--tok") {
		t.Errorf("drift = %q", msg)
	}
}

// R1-14: a switched-on companion's container without its alias is drift.
func TestMCPAliasMissingIsDrift(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.mu.RLock()
	want, _ := a.h.desiredRouteLabelsLocked(a.h.findLocked("aiapp"))
	a.h.mu.RUnlock()
	labels := map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: "app", docker.LabelNumber: "1"}
	for k, v := range want["app"] {
		labels[k] = v
	}
	a.engine.mu.Lock()
	a.engine.containers = []docker.Container{{ID: "c1", Names: []string{"/portcullis-aiapp-app-1"}, State: "running", Labels: labels},
		{ID: "c2", Names: []string{"/portcullis-aiapp-tok-mcp-1"}, State: "running", Networks: map[string][]string{"portcullis-proxy": {"portcullis-aiapp-tok-mcp-1"}},
			Labels: map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: "tok-mcp", docker.LabelNumber: "1"}}}
	a.engine.mu.Unlock()
	var msg string
	for _, d := range a.h.Reconcile(context.Background()).Items {
		if d.ID == "aiapp" && d.Kind == DriftPublicAccess {
			msg = d.Message
		}
	}
	if !strings.Contains(msg, "missing network alias portcullis-mcp-aiapp--tok") {
		t.Errorf("drift = %q", msg)
	}
}

// R1-9: a non-default instance renders its own router name and alias,
// service mcp-gate@docker untouched by the instance renaming.
func TestMCPRouterNonDefaultInstance(t *testing.T) {
	a := newInstAIFixture(t, nil)
	if err := a.h.CreateInstance("aiapp", "aiapp-b", map[string]string{"aiapp": "aiapp-b.example.com"}); err != nil {
		t.Fatal(err)
	}
	a.people.addGroup("users_aiapp-b", "alice")
	a.enable(t, "aiapp-b")
	if err := a.h.SetAISupport(context.Background(), "aiapp-b", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	ov := a.override(t, "aiapp-b")
	k := "traefik.http.routers.portcullis-mcp-aiapp-b--tok."
	for _, want := range []string{
		`"` + k + "rule\": \"Host(`aiapp-b.example.com`) && (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))\"",
		`"` + k + `service": "mcp-gate@docker"`,
		`"` + k + `middlewares": "rate-limit@file,security-headers@file"`,
		"          - \"portcullis-mcp-aiapp-b--tok\"\n",
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("override lacks %q:\n%s", want, ov)
		}
	}
	if strings.Contains(ov, "aiapp-b_portcullis-mcp") || strings.Contains(ov, "portcullis-mcp-aiapp--tok") {
		t.Errorf("router renamed or the default's rendered:\n%s", ov)
	}
	if r := resourceByURL(a.gate(t), "https://aiapp-b.example.com/mcp"); r == nil || r.Upstream != "http://portcullis-mcp-aiapp-b--tok:8080/mcp" {
		t.Errorf("gate = %v", urls(a.gate(t)))
	}
}

// R1-10: a revoke_all failing before the save never makes the next
// request re-apply companions that didn't change.
func TestPreSaveFailureNoReapply(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.failHook("/revoke", 2, "down\n")
	if err := a.h.SetAIMode(context.Background(), "aiapp", "tok", "read_only", root); err == nil {
		t.Fatal("no error")
	}
	a.failHook("/revoke", 0, "")
	ups, hooks := len(a.runner.Calls()), len(a.engine.SplitCalls())
	if _, err := a.h.UpdateInstanceAI(context.Background(), "aiapp", InstanceAIUpdate{Companions: map[string]CompanionUpdate{"tok": {Enabled: ptr(true), Mode: ptr("read_write")}}}, root); err != nil {
		t.Fatal(err)
	}
	if len(a.runner.Calls()) != ups || len(a.engine.SplitCalls()) != hooks {
		t.Errorf("an unchanged companion was re-applied: compose %v, hooks %d → %d", a.runner.Calls()[ups:], hooks, len(a.engine.SplitCalls()))
	}
}

// R1-11 / R1-13: a switch-off on a stopped instance owes revoke_all and
// on_change false (the tab says revoking); the next start runs both.
func TestOwedOnChangeAfterStoppedSwitchOff(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if err := a.h.Disable("aiapp"); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	n := len(a.stdins("/toggle"))
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err != nil {
		t.Fatal(err)
	}
	if c := a.companion("aiapp", "tok"); !c.RevokePending || !c.OnChangePending || c.Enabled {
		t.Fatalf("state = %+v", c)
	}
	v, _ := a.h.InstanceAI("aiapp")
	if v.Companions[0].Status != "revoking" {
		t.Errorf("status = %s, want revoking", v.Companions[0].Status)
	}
	a.enable(t, "aiapp")
	got := a.stdins("/toggle")
	if len(got) != n+1 || got[len(got)-1] != `{"action":"on_change","enabled":false,"mode":"read_write","companion":"tok"}` {
		t.Errorf("on_change = %v", got)
	}
	seq := a.seq.list()
	i := slices.Index(seq, "/revoke:revoke_all")
	j := -1
	for k, e := range seq {
		if e == "/toggle:on_change" {
			j = k
		}
	}
	if i < 0 || j < i {
		t.Errorf("sequence = %v", seq)
	}
	if c := a.companion("aiapp", "tok"); c.RevokePending || c.OnChangePending {
		t.Errorf("flags kept: %+v", c)
	}
}

// ── fix round 2 ─────────────────────────────────────────

// R2-1: on a running instance the hooks that run after the up are owed
// in the same commit: a crash right after the save leaves the flags.
func TestOwedFlagsPersistedAtCommit(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	var atCommit state.AICompanion
	a.h.testHookAIAfterSave = func() {
		st, err := state.Load(a.h.statePath())
		if err != nil {
			t.Error(err)
			return
		}
		atCommit = st.AIInstances["aiapp"].Companions["tok"]
	}
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err != nil {
		t.Fatal(err)
	}
	if !atCommit.RevokePending || !atCommit.OnChangePending || atCommit.Enabled {
		t.Errorf("stored at the commit = %+v, want both owed", atCommit)
	}
	if c := a.companion("aiapp", "tok"); c.RevokePending || c.OnChangePending {
		t.Errorf("flags kept after the hooks ran: %+v", c)
	}
	// A switch-on owes its on_change (its revoke_all ran before the save).
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if atCommit.RevokePending || !atCommit.OnChangePending || !atCommit.Enabled {
		t.Errorf("switch-on stored = %+v", atCommit)
	}
}

// R2-2: re-sending the same PUT retries the owed hooks of a running
// instance (here after a Hub restart: no in-memory re-apply set).
func TestResentPUTRetriesOwedHooks(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.failHook("/toggle", 1, "nope\n")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err == nil {
		t.Fatal("no error")
	}
	if c := a.companion("aiapp", "tok"); !c.OnChangePending {
		t.Fatalf("state = %+v", c)
	}
	a.h.aiErrMu.Lock()
	a.h.aiReapply = nil // as after a restart
	a.h.aiErrMu.Unlock()
	a.failHook("/toggle", 0, "")
	n := len(a.stdins("/toggle"))
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", false, root); err != nil {
		t.Fatal(err)
	}
	got := a.stdins("/toggle")
	if len(got) != n+1 || got[len(got)-1] != `{"action":"on_change","enabled":false,"mode":"read_write","companion":"tok"}` {
		t.Errorf("on_change = %v", got[n:])
	}
	if c := a.companion("aiapp", "tok"); c.OnChangePending || c.RevokePending {
		t.Errorf("flags kept: %+v", c)
	}
}

// R2-3: a companion owing a revoke_all gets no scope until it ran; then
// the scope is ensured and attached.
func TestScopeWaitsForOwedRevoke(t *testing.T) {
	a := newInstAIFixture(t, nil)
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if got := a.h.wantedAIScopes(keycloak.AIClientIDs.Generic); slices.Contains(got, "mcp:aiapp.tok") {
		t.Errorf("wanted = %v while revoke_all is owed", got)
	}
	if _, ok := a.kc.scope("mcp:aiapp.tok"); ok {
		t.Error("scope ensured while revoke_all is owed")
	}
	a.enable(t, "aiapp")
	if _, ok := a.kc.scope("mcp:aiapp.tok"); !ok {
		t.Error("no scope after the owed revoke_all")
	}
	if got := a.kc.opt(keycloak.AIClientIDs.Generic); !slices.Contains(got, "mcp:aiapp.tok") {
		t.Errorf("generic = %v", got)
	}
}
