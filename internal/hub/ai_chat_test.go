package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Plan 4 Task 23: the AI page's model providers (contract §3.2 ai.chat,
// §13.7, §15.12) and its ai_client (§8, G10).

const (
	chatMarker = "sk-CHAT-MARKER-4711"
	ollamaVar  = "PORTCULLIS_AI_PROVIDER_OLLAMA_GPU_KEY"
	chatMCPID  = "ai-chat-mcp"
)

var (
	ollamaGPU = state.ModelProvider{Name: "ollama-gpu", Label: "Ollama on the office GPU", Kind: "openai_compatible",
		BaseURL: "http://gpu.lan:11434/v1", Models: state.ProviderModels{List: []string{"llama3.3:70b", "qwen3:32b"}}}
	liteProvider = state.ModelProvider{Name: "litellm", Label: "LiteLLM", Kind: "litellm", Instance: "litellm-lab",
		Models: state.ProviderModels{Fetch: true}}
)

// chatFixture23 is newInstAIFixture plus the chatapp test template as
// ai-chat, litellm (an instance litellm-lab), an ai-chat instance
// ai-research, 41 people in users_ai-chat, and the providers ollama-gpu
// (its key the marker) and litellm.
func chatFixture23(t *testing.T, seed func(*state.AppState)) *instAIFixture {
	t.Helper()
	a := newInstAIFixture(t, seed, func(extra map[string][2]string) {
		extra["ai-chat"] = readFixture(t, filepath.Join("testdata", "ai", "chatapp"))
		extra["litellm"] = [2]string{liteLLMManifest, liteLLMCompose}
	})
	for _, id := range []string{"ai-chat", "litellm"} {
		if a.h.Template(id) == nil {
			t.Fatalf("template %s not loaded (see the log)", id)
		}
	}
	var members []string
	for i := 1; i <= 41; i++ {
		members = append(members, fmt.Sprintf("p%02d", i))
	}
	a.people.addGroup("users_ai-chat", members...)
	if err := a.h.CreateInstance("litellm", "litellm-lab", nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []state.ModelProvider{ollamaGPU, liteProvider} {
		if _, err := a.h.AddModelProvider(p, root); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := a.h.SetProviderSecret("ollama-gpu", "key", []byte(chatMarker), root); err != nil {
		t.Fatal(err)
	}
	if err := a.h.CreateInstance("ai-chat", "ai-research", nil); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *instAIFixture) providersDoc(t *testing.T, id string) ProvidersDoc {
	t.Helper()
	b, err := os.ReadFile(a.h.dataFilePath(id, templates.AIProvidersFile))
	if err != nil {
		t.Fatal(err)
	}
	var d ProvidersDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func (a *instAIFixture) envOf(t *testing.T, id string) string {
	t.Helper()
	b, _ := os.ReadFile(a.h.envPath(id))
	return string(b)
}

func (a *instAIFixture) selectProviders(t *testing.T, id string, names ...string) {
	t.Helper()
	if err := a.h.SetAIProviders(context.Background(), id, names, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
}

func aiRestartsOf(calls []string, id string) int {
	n := 0
	for _, c := range calls {
		if c == "down:"+projectName(id) {
			n++
		}
	}
	return n
}

// TestProvidersFile (§3.2 ai-providers.json, G31): both providers in the
// file with every field, mounted read-only on ai.chat.file.service; the
// key single-quoted in the env file and only in ai-chat's; the override's
// environment on ai.chat.env.service only.
func TestProvidersFile(t *testing.T) {
	a := chatFixture23(t, nil)
	a.selectProviders(t, "ai-chat", "litellm", "ollama-gpu")
	a.selectProviders(t, "ai-research", "litellm")
	a.enable(t, "ai-chat")
	a.enable(t, "ai-research")

	d := a.providersDoc(t, "ai-chat")
	if d.Version != 1 || d.Instance != "ai-chat" || len(d.Providers) != 2 || d.Providers[0].Name != "litellm" || d.Providers[1].Name != "ollama-gpu" {
		t.Fatalf("doc = %+v", d)
	}
	lite, ol := d.Providers[0], d.Providers[1]
	if lite.Kind != "litellm" || lite.BaseURL != "https://"+a.h.Template("litellm-lab").Hosts["litellm"] || !lite.Models.Fetch || len(lite.Env) != 0 {
		t.Errorf("litellm entry = %+v", lite)
	}
	if ol.Label != ollamaGPU.Label || ol.BaseURL != ollamaGPU.BaseURL || !slices.Equal(ol.Models.List, ollamaGPU.Models.List) || ol.Credentials != "admin" ||
		len(ol.Env) != 1 || ol.Env["key"] != ollamaVar {
		t.Errorf("ollama entry = %+v", ol)
	}
	// Every field present ("", {} or []).
	raw, _ := os.ReadFile(a.h.dataFilePath("ai-chat", templates.AIProvidersFile))
	for _, k := range []string{`"region": ""`, `"instance_name": ""`, `"api_version": ""`, `"deployments": {}`, `"list": []`, `"env": {}`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("ai-providers.json lacks %s:\n%s", k, raw)
		}
	}
	if st, err := os.Stat(a.h.dataFilePath("ai-chat", templates.AIProvidersFile)); err != nil || st.Mode().Perm() != 0640 {
		t.Errorf("file mode = %v %v", st, err)
	}
	if st, err := os.Stat(a.h.dataFileDir("ai-chat", templates.AIProvidersFile)); err != nil || st.Mode().Perm() != 0750 {
		t.Errorf("dir mode = %v %v", st, err)
	}
	ov := a.override(t, "ai-chat")
	if !strings.Contains(ov, `"/host/project/appfiles/ai-chat/ai-providers:/portcullis/ai:ro"`) {
		t.Errorf("override lacks the read-only mount:\n%s", ov)
	}
	cfg, api := serviceBlock(ov, "config"), serviceBlock(ov, "api")
	if !strings.Contains(cfg, "/portcullis/ai:ro") || strings.Contains(cfg, "environment") {
		t.Errorf("config service block:\n%s", cfg)
	}
	if !strings.Contains(api, "environment:\n      "+ollamaVar+": \"${"+ollamaVar+"}\"") || strings.Contains(api, "LITELLM_KEY") {
		t.Errorf("api service block (G31):\n%s", api)
	}
	if env := a.envOf(t, "ai-chat"); !strings.Contains(env, ollamaVar+"='"+chatMarker+"'\n") {
		t.Errorf("ai-chat env lacks the single-quoted key:\n%s", env)
	}
	if env := a.envOf(t, "ai-research"); strings.Contains(env, chatMarker) || strings.Contains(env, ollamaVar) {
		t.Errorf("ai-research's env holds the other selection's key:\n%s", env)
	}
	for _, id := range []string{"aiapp", "litellm-lab"} {
		if strings.Contains(a.envOf(t, id), chatMarker) {
			t.Errorf("%s's env holds the key", id)
		}
	}
	if d := a.providersDoc(t, "ai-research"); len(d.Providers) != 1 || d.Providers[0].Name != "litellm" {
		t.Errorf("ai-research doc = %+v", d)
	}
	// Deselected: the variable, its override line and the entry go.
	a.selectProviders(t, "ai-chat", "litellm")
	if env := a.envOf(t, "ai-chat"); strings.Contains(env, ollamaVar) || strings.Contains(env, chatMarker) {
		t.Errorf("deselected provider's variable kept:\n%s", env)
	}
	if strings.Contains(a.override(t, "ai-chat"), ollamaVar) {
		t.Error("deselected provider's variable kept in the override")
	}
	if d := a.providersDoc(t, "ai-chat"); len(d.Providers) != 1 {
		t.Errorf("doc after deselect = %+v", d)
	}
	if u := a.h.DeliveryStatus("ai-chat").Units[fileUnit(templates.AIProvidersFile)]; !u.OK {
		t.Errorf("unit file:ai-providers = %+v", u)
	}
}

// TestProviderSecretsNeverEchoed (Task 23 part): the key is in no data
// file, override, op record, state, audit, answer or gate file.
func TestProviderSecretsNeverEchoed(t *testing.T) {
	a := chatFixture23(t, nil)
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	a.enable(t, "ai-chat")
	v, restarts, err := a.h.UpdateModelProvider("ollama-gpu", withModels(ollamaGPU, "qwen3:32b"), root)
	if err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	sv, _, err := a.h.SetProviderSecret("ollama-gpu", "key", []byte(chatMarker+"-2"), root)
	if err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	ans, _ := json.Marshal([]any{v, restarts, sv, a.h.ModelProviders(t.Context())})
	view, _ := a.h.InstanceAI("ai-chat")
	vb, _ := json.Marshal(view)
	if err := a.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	gate, _ := os.ReadFile(a.h.gatePath())
	state, _ := os.ReadFile(a.h.statePath())
	audit, _ := json.Marshal(a.audit.entries)
	sources := map[string][]byte{"answers": ans, "tab": vb, "gate file": gate, "state": state, "audit": audit}
	sources["ai-providers.json"], _ = os.ReadFile(a.h.dataFilePath("ai-chat", templates.AIProvidersFile))
	sources["override"], _ = os.ReadFile(a.h.overridePath("ai-chat"))
	_ = filepath.WalkDir(a.h.cfg.DataDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(p, string(filepath.Separator)+"ops"+string(filepath.Separator)) {
			sources[p], _ = os.ReadFile(p)
		}
		return nil
	})
	_ = filepath.WalkDir(a.h.cfg.AppFilesDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			sources[p], _ = os.ReadFile(p)
		}
		return nil
	})
	for name, b := range sources {
		if strings.Contains(string(b), chatMarker) {
			t.Errorf("%s holds the provider secret", name)
		}
	}
	if !strings.Contains(a.envOf(t, "ai-chat"), "'"+chatMarker+"-2'") {
		t.Error("the replaced key didn't reach the env file")
	}
	// The env file shown in Expert Env: [set].
	vars, _, err := a.h.Env("ai-chat")
	if err != nil || vars[ollamaVar] != "[set]" {
		t.Errorf("Expert Env shows %q (%v)", vars[ollamaVar], err)
	}
	if err := a.h.SaveEnv("ai-chat", map[string]string{ollamaVar: "sk-other"}); statusOf(err) != 400 {
		t.Errorf("SaveEnv of a provider variable = %v, want 400", err)
	}
}

func withModels(p state.ModelProvider, models ...string) state.ModelProvider {
	p = cloneProvider(p)
	p.Models.List = models
	return p
}

// TestTwoOneKindProviders (§15.12 selection): two anthropic providers
// (kind one) → 400; a kind the template doesn't declare → 400; an unknown
// provider → 400; a non-AI page → 400. Nothing stored; audited refused.
func TestTwoOneKindProviders(t *testing.T) {
	a := chatFixture23(t, nil)
	// A second AI page declaring google, so the kind can be added.
	for _, p := range []state.ModelProvider{
		{Name: "claude-a", Label: "A", Kind: "anthropic"},
		{Name: "claude-b", Label: "B", Kind: "anthropic"},
	} {
		if _, err := a.h.AddModelProvider(p, root); err != nil {
			t.Fatal(err)
		}
	}
	a.h.mu.Lock()
	a.h.st.AI.Providers = append(a.h.st.AI.Providers, state.ModelProvider{Name: "gem", Label: "Gemini", Kind: "google", Credentials: "admin"})
	a.h.mu.Unlock()
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	for _, c := range []struct {
		names []string
		why   string
	}{
		{[]string{"claude-a", "claude-b"}, "at most one"},
		{[]string{"gem"}, "google"},
		{[]string{"ghost"}, "no model provider"},
		{[]string{"ollama-gpu", "ollama-gpu"}, "twice"},
	} {
		err := a.h.SetAIProviders(context.Background(), "ai-chat", c.names, root)
		if statusOf(err) != 400 || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%v = %v, want 400 %q", c.names, err, c.why)
		}
	}
	if err := a.h.SetAIProviders(context.Background(), "aiapp", []string{"ollama-gpu"}, root); statusOf(err) != 400 {
		t.Errorf("a non-AI page = %v, want 400", err)
	}
	if v, _ := a.h.InstanceAI("ai-chat"); !slices.Equal(v.Providers, []string{"ollama-gpu"}) {
		t.Errorf("selection after refusals = %v", v.Providers)
	}
	refused := 0
	for _, e := range a.audits("ai.providers") {
		if e.Result == "refused" {
			refused++
		}
	}
	if refused != 5 {
		t.Errorf("refused ai.providers audits = %d, want 5", refused)
	}
	// One of the kind is fine; via the PUT body too.
	res, err := a.h.UpdateInstanceAI(context.Background(), "ai-chat", InstanceAIUpdate{Providers: &[]string{"claude-a", "ollama-gpu"}}, root)
	if err != nil || !slices.Equal(res.Providers, []string{"claude-a", "ollama-gpu"}) {
		t.Fatalf("PUT providers = %+v %v", res, err)
	}
	if e := a.audits("ai.providers"); e[len(e)-1].Result != "ok" || e[len(e)-1].Detail != "ollama-gpu -> claude-a, ollama-gpu" {
		t.Errorf("audit = %+v", e[len(e)-1])
	}
}

// TestProviderChangeRestartsSelected (§15.11 update): updating ollama-gpu
// re-delivers and restarts ai-chat only, listed in the answer; the
// Settings → AI preview (used_by) lists it too. A secret change restarts
// it as well; one of a provider nobody selects restarts nothing.
func TestProviderChangeRestartsSelected(t *testing.T) {
	a := chatFixture23(t, nil)
	a.selectProviders(t, "ai-chat", "ollama-gpu", "litellm")
	a.selectProviders(t, "ai-research", "litellm")
	a.enable(t, "ai-chat")
	a.enable(t, "ai-research")
	// The preview: the enabled instances using it.
	for _, p := range a.h.ModelProviders(t.Context()) {
		if p.Name == "ollama-gpu" && (len(p.UsedBy) != 1 || p.UsedBy[0].Instance != "ai-chat" || !p.UsedBy[0].Restarts) {
			t.Errorf("ollama-gpu used_by = %+v", p.UsedBy)
		}
	}
	before := a.runner.Calls()
	_, restarts, err := a.h.UpdateModelProvider("ollama-gpu", withModels(ollamaGPU, "llama3.3:70b", "qwen3:32b", "gemma3"), root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(restarts, []string{"ai-chat"}) {
		t.Errorf("restarts = %v, want [ai-chat]", restarts)
	}
	a.h.Wait()
	after := a.runner.Calls()[len(before):]
	if aiRestartsOf(after, "ai-chat") != 1 || aiRestartsOf(after, "ai-research") != 0 {
		t.Errorf("compose calls after the update = %v", after)
	}
	if d := a.providersDoc(t, "ai-chat"); !slices.Contains(d.Providers[1].Models.List, "gemma3") {
		t.Errorf("not re-delivered: %+v", d.Providers)
	}
	// An unchanged update restarts nothing.
	if _, restarts, err := a.h.UpdateModelProvider("ollama-gpu", withModels(ollamaGPU, "llama3.3:70b", "qwen3:32b", "gemma3"), root); err != nil || len(restarts) != 0 {
		t.Errorf("unchanged update = %v %v", restarts, err)
	}
	// A secret replaced: ai-chat only, the env carries the new value.
	before = a.runner.Calls()
	_, restarts, err = a.h.SetProviderSecret("ollama-gpu", "key", []byte("sk-NEW-VALUE"), root)
	if err != nil || !slices.Equal(restarts, []string{"ai-chat"}) {
		t.Fatalf("secret set = %v %v", restarts, err)
	}
	a.h.Wait()
	after = a.runner.Calls()[len(before):]
	if aiRestartsOf(after, "ai-chat") != 1 || aiRestartsOf(after, "ai-research") != 0 {
		t.Errorf("compose calls after the secret = %v", after)
	}
	if !strings.Contains(a.envOf(t, "ai-chat"), ollamaVar+"='sk-NEW-VALUE'") {
		t.Error("the new key is not in ai-chat's env")
	}
	// Cleared: the variable and its env entry go.
	_, restarts, err = a.h.ClearProviderSecret("ollama-gpu", "key", root)
	a.h.Wait()
	if err != nil || !slices.Equal(restarts, []string{"ai-chat"}) || strings.Contains(a.envOf(t, "ai-chat"), ollamaVar) {
		t.Errorf("cleared = %v %v; env:\n%s", restarts, err, a.envOf(t, "ai-chat"))
	}
	if d := a.providersDoc(t, "ai-chat"); len(d.Providers[1].Env) != 0 {
		t.Errorf("env names after the clear = %v", d.Providers[1].Env)
	}
	// The litellm instance's hostname moves: both selecting instances
	// re-delivered with the new base_url.
	before = a.runner.Calls()
	if err := a.h.SetHosts("litellm-lab", map[string]string{"litellm": "llm2.example.com"}, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	after = a.runner.Calls()[len(before):]
	for _, id := range []string{"ai-chat", "ai-research"} {
		if d := a.providersDoc(t, id); d.Providers[0].BaseURL != "https://llm2.example.com" {
			t.Errorf("%s litellm base_url = %s", id, d.Providers[0].BaseURL)
		}
		if aiRestartsOf(after, id) != 1 {
			t.Errorf("%s not restarted after the litellm host move: %v", id, after)
		}
	}
}

// TestPerPersonCredentials: credentials per_person → no variable, the
// entry says per_person with env {}.
func TestPerPersonCredentials(t *testing.T) {
	a := chatFixture23(t, nil)
	p := cloneProvider(ollamaGPU)
	p.Credentials = ProviderCredentialsPerPerson
	if _, _, err := a.h.UpdateModelProvider("ollama-gpu", p, root); err != nil {
		t.Fatal(err)
	}
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	a.enable(t, "ai-chat")
	d := a.providersDoc(t, "ai-chat")
	if len(d.Providers) != 1 || d.Providers[0].Credentials != "per_person" || len(d.Providers[0].Env) != 0 {
		t.Errorf("doc = %+v", d)
	}
	if strings.Contains(a.envOf(t, "ai-chat"), ollamaVar) || strings.Contains(a.override(t, "ai-chat"), ollamaVar) {
		t.Error("a per_person provider's variable was written")
	}
}

// TestAIClientSemantics (§8, G9, G10): the ai_client entry is made by
// EnsureAIClient — confidential with its secret, consent, ACR hwk,
// basic + acr, offline_access + mcp:all only, the username mapper, owner
// the instance id — never RegisterClient; it keeps the access role
// (EnsureClientAccess); healthy → in the gate's clients (companions,
// people, aggregate; never admin); master off → kept, not listed; a
// failed ensure → unhealthy, not listed. A non-default instance's
// ai_client too.
func TestAIClientSemantics(t *testing.T) {
	kc, c := hubAIRealm(t)
	a := chatFixture23(t, nil)
	a.h.SetAIKeycloak(c)
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	a.enable(t, "ai-chat")
	for _, r := range a.idp.registered {
		if strings.HasPrefix(r, chatMCPID+":") {
			t.Errorf("the ai_client went through RegisterClient: %s", r)
		}
	}
	if !slices.ContainsFunc(a.idp.registered, func(r string) bool { return strings.HasPrefix(r, "ai-chat:ai-chat:") }) {
		t.Errorf("the ordinary client wasn't registered: %v", a.idp.registered)
	}
	if !slices.Contains(a.idp.accessCalls(), "+"+chatMCPID+":ai-chat:users_ai-chat") {
		t.Errorf("the ai_client lost its access role: %v", a.idp.accessCalls())
	}
	cl := kc.ClientByClientID(chatMCPID)
	if cl == nil {
		t.Fatal("ai_client not created")
	}
	secret := readEnvFile(a.h.envPath("ai-chat"))["CHAT_MCP_SECRET"]
	if cl.PublicClient == nil || *cl.PublicClient || cl.ConsentRequired == nil || !*cl.ConsentRequired || cl.Secret != secret || secret == "" ||
		cl.Attributes[keycloak.OwnerAttr] != "ai-chat" || cl.Attributes[keycloak.AIClientAttr] != "true" ||
		cl.Attributes["default.acr.values"] != "hwk" || !slices.Equal(cl.RedirectURIs, []string{"https://" + a.h.Template("ai-chat").Hosts["ai-chat"] + "/api/mcp/callback"}) {
		t.Errorf("ai_client = %+v", cl)
	}
	if got := kc.ClientScopes(cl.ID); !slices.Equal(slices.Sorted(slices.Values(got)), []string{"acr", "basic"}) {
		t.Errorf("default scopes = %v", got)
	}
	if got := kc.OptionalScopes(cl.ID); !slices.Equal(slices.Sorted(slices.Values(got)), []string{"mcp:all", "offline_access"}) {
		t.Errorf("optional scopes = %v", got)
	}
	if ms := kc.ClientMappers(cl.ID); len(ms) != 1 || ms[keycloak.AIUsernameMapper].Name == "" {
		t.Errorf("mappers = %v", ms)
	}
	if !a.h.aiClientHealth()[chatMCPID] {
		t.Errorf("health = %v", a.h.aiClientHealth())
	}
	g := a.gate(t)
	if !slices.Contains(g.Clients, chatMCPID) {
		t.Errorf("gate clients = %v", g.Clients)
	}
	for _, r := range g.Resources {
		if want := r.Kind != aigate.KindAdmin; slices.Contains(r.Clients, chatMCPID) != want {
			t.Errorf("resource %s clients = %v (want ai_client listed: %v)", r.URL, r.Clients, want)
		}
	}

	// The ACR push of a policy save skips it (UpdateClientACR refuses it).
	acrBefore := len(a.idp.updated)
	if _, err := a.h.SaveSettings("ai-chat", SettingsUpdate{Policy: &policy.AuthPolicy{Factors: []string{"webauthn"}, Op: "any"}}, root); err != nil {
		t.Fatal(err)
	}
	for _, u := range a.idp.updated[acrBefore:] {
		if strings.HasPrefix(u, chatMCPID) {
			t.Errorf("UpdateClientACR on the ai_client: %s", u)
		}
	}

	// Master off: kept, not listed.
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(false)})
	if kc.ClientByClientID(chatMCPID) == nil {
		t.Error("master off deleted the ai_client")
	}
	if g := a.gate(t); slices.Contains(g.Clients, chatMCPID) {
		t.Errorf("master off: gate clients = %v", g.Clients)
	}
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(true)})
	if g := a.gate(t); !slices.Contains(g.Clients, chatMCPID) {
		t.Errorf("master on again: gate clients = %v", g.Clients)
	}

	// A non-default instance: its own client id, owner and health.
	a.selectProviders(t, "ai-research", "ollama-gpu")
	a.enable(t, "ai-research")
	rid := a.h.Template("ai-research").Manifest.Clients[1].ClientID
	if rc := kc.ClientByClientID(rid); rc == nil || rc.Attributes[keycloak.OwnerAttr] != "ai-research" {
		t.Fatalf("ai-research's ai_client %s = %+v", rid, rc)
	}
	if g := a.gate(t); !slices.Contains(g.Clients, rid) {
		t.Errorf("gate clients = %v, want %s", g.Clients, rid)
	}
	if ids := a.h.aiClientIDs(); !slices.Contains(ids, rid) || !slices.Contains(ids, chatMCPID) {
		t.Errorf("aiClientIDs = %v", ids)
	}

	// A failed ensure: unhealthy, out of the gate's clients.
	fk := newFakeAIKC()
	fk.setFailClient(chatMCPID, errors.New("keycloak down"))
	a.h.SetAIKeycloak(fk)
	if _, err := a.h.aiClientPass(context.Background()); err == nil {
		t.Error("the pass hid the ai_client failure")
	}
	if a.h.aiClientHealth()[chatMCPID] {
		t.Error("a failed ensure left the ai_client healthy")
	}
	if g := a.gate(t); slices.Contains(g.Clients, chatMCPID) {
		t.Errorf("unhealthy ai_client listed: %v", g.Clients)
	}

	// Deleted: its health entry goes too.
	if _, err := a.h.DeleteInstance("ai-research", "ai-research", root); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.h.aiClientHealth()[rid]; ok {
		t.Error("the deleted instance's ai_client health kept")
	}
}

// TestAIClientSkipsSettingClaims (T10 carry): setting-claim mappers are
// never asked of the ai_client.
func TestAIClientSkipsSettingClaims(t *testing.T) {
	a := chatFixture23(t, nil)
	a.h.SetAttrStore(newFakeAttrStore())
	a.enable(t, "ai-chat")
	if _, err := a.h.Deliver(context.Background(), "ai-chat", TriggerRetry); err != nil {
		t.Fatal(err)
	}
	calls := a.idp.claimAllCalls()
	for _, c := range calls {
		if strings.HasPrefix(c, chatMCPID+":") {
			t.Errorf("EnsureSettingClaims on the ai_client: %s", c)
		}
	}
	if !slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "ai-chat:") }) {
		t.Errorf("the ordinary client got no setting claims: %v", calls)
	}
}

// TestUsedBy (§15.12): ModelProviders lists the selecting instance, its
// access group and population.
func TestUsedBy(t *testing.T) {
	a := chatFixture23(t, nil)
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	a.selectProviders(t, "ai-research", "litellm")
	for _, p := range a.h.ModelProviders(t.Context()) {
		if p.Name != "ollama-gpu" {
			continue
		}
		if len(p.UsedBy) != 1 || p.UsedBy[0].Instance != "ai-chat" || p.UsedBy[0].Group != "users_ai-chat" || p.UsedBy[0].People == nil || *p.UsedBy[0].People != 41 {
			t.Errorf("used_by = %+v", p.UsedBy)
		}
		return
	}
	t.Fatal("ollama-gpu not listed")
}

// TestDefaultProviderSelection (§15.12): an AI page that never chose gets
// every provider whose kind it supports (one per kind "one") at create
// and at its first enable; an emptied selection stays empty.
func TestDefaultProviderSelection(t *testing.T) {
	a := chatFixture23(t, nil)
	for _, p := range []state.ModelProvider{
		{Name: "claude-b", Label: "B", Kind: "anthropic"},
		{Name: "claude-a", Label: "A", Kind: "anthropic"},
	} {
		if _, err := a.h.AddModelProvider(p, root); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"claude-a", "litellm", "ollama-gpu"}
	if err := a.h.CreateInstance("ai-chat", "ai-new", nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := a.h.InstanceAI("ai-new"); !slices.Equal(v.Providers, want) {
		t.Errorf("created = %v, want %v", v.Providers, want)
	}
	// The default instance at its first enable.
	a.enable(t, "ai-chat")
	if v, _ := a.h.InstanceAI("ai-chat"); !slices.Equal(v.Providers, want) {
		t.Errorf("default instance = %v, want %v", v.Providers, want)
	}
	// Emptied stays empty across a disable / enable.
	a.selectProviders(t, "ai-new", []string{}...)
	a.enable(t, "ai-new")
	if err := a.h.Disable("ai-new"); err != nil {
		t.Fatal(err)
	}
	a.enable(t, "ai-new")
	if v, _ := a.h.InstanceAI("ai-new"); len(v.Providers) != 0 {
		t.Errorf("emptied selection re-seeded: %v", v.Providers)
	}
	// The delete 409 names the default-selected instance.
	if err := a.h.DeleteModelProvider("claude-a", root); statusOf(err) != 409 || !strings.Contains(err.Error(), "ai-chat") {
		t.Errorf("delete = %v", err)
	}
}

// TestDeleteLiteLLMInstanceInUse: an instance a litellm provider points
// at can't be deleted (409 naming the provider); deleting an AI page drops
// its selection.
func TestDeleteLiteLLMInstanceInUse(t *testing.T) {
	a := chatFixture23(t, nil)
	a.selectProviders(t, "ai-research", "litellm")
	_, err := a.h.DeleteInstance("litellm-lab", "litellm-lab", root)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "litellm") {
		t.Fatalf("delete = %v, want 409 naming the provider", err)
	}
	if a.h.Template("litellm-lab") == nil {
		t.Fatal("refused delete removed the instance")
	}
	if _, err := a.h.DeleteInstance("ai-research", "ai-research", root); err != nil {
		t.Fatal(err)
	}
	a.h.mu.RLock()
	_, kept := a.h.st.AIInstances["ai-research"]
	a.h.mu.RUnlock()
	if kept {
		t.Error("the deleted AI page's selection kept")
	}
	if a.h.selectingUnlocked("litellm") != nil && slices.Contains(a.h.selectingUnlocked("litellm"), "ai-research") {
		t.Error("the deleted instance still selects litellm")
	}
}

func (h *Hub) selectingUnlocked(name string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.selectingLocked(name)
}

// TestBackupRestoreProviderVars (G30(b)): the archive's env holds the
// provider variable blank; a same-instance restore and a restore-as
// write it from the store for that instance's own selection only; an
// archive selection naming a provider that's gone is dropped (warning).
func TestBackupRestoreProviderVars(t *testing.T) {
	a := chatFixture23(t, nil)
	a.selectProviders(t, "ai-chat", "ollama-gpu", "litellm")
	a.enable(t, "ai-chat")
	entry, err := a.h.BackupInstance("ai-chat", root)
	if err != nil {
		t.Fatal(err)
	}
	members, _ := archiveMembers(t, a, entry.Archive)
	arch := string(members["config/env"])
	if strings.Contains(arch, chatMarker) || !strings.Contains(arch, ollamaVar+"=\n") && !strings.HasSuffix(arch, ollamaVar+"=") {
		t.Errorf("archive env:\n%s", arch)
	}
	// Rotate the key: the restore writes the current one.
	if _, _, err := a.h.SetProviderSecret("ollama-gpu", "key", []byte("sk-ROTATED"), root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if _, err := a.h.RestoreInstance("ai-chat", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if env := a.envOf(t, "ai-chat"); !strings.Contains(env, ollamaVar+"='sk-ROTATED'") {
		t.Errorf("restored env:\n%s", env)
	}
	// A disabled instance's restore writes them too (no enable follows).
	if err := a.h.Disable("ai-chat"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.h.RestoreInstance("ai-chat", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	if env := a.envOf(t, "ai-chat"); !strings.Contains(env, ollamaVar+"='sk-ROTATED'") {
		t.Errorf("restored env of the disabled instance:\n%s", env)
	}
	a.enable(t, "ai-chat")
	// Restore-as with a provider deleted since: dropped with a warning,
	// and its variable not written.
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	a.h.mu.Lock()
	a.h.st.AI.Providers = slices.DeleteFunc(slices.Clone(a.h.st.AI.Providers), func(p state.ModelProvider) bool { return p.Name == "litellm" })
	a.h.mu.Unlock()
	res, err := a.h.RestoreInstanceAs(entry.Archive, "ai-copy", root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "litellm") }) {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if v, _ := a.h.InstanceAI("ai-copy"); !slices.Equal(v.Providers, []string{"ollama-gpu"}) {
		t.Errorf("copy selection = %v", v.Providers)
	}
	if env := a.envOf(t, "ai-copy"); !strings.Contains(env, ollamaVar+"='sk-ROTATED'") {
		t.Errorf("copy env:\n%s", env)
	}
}

var _ = directory.Human

// TestRestoredSelectionChecked (ruling 5): an archive's selection goes
// through the selection checks; what fails is dropped with a warning.
func TestRestoredSelectionChecked(t *testing.T) {
	a := chatFixture23(t, nil)
	for _, p := range []state.ModelProvider{{Name: "claude-a", Label: "A", Kind: "anthropic"}, {Name: "claude-b", Label: "B", Kind: "anthropic"}} {
		if _, err := a.h.AddModelProvider(p, root); err != nil {
			t.Fatal(err)
		}
	}
	a.h.mu.Lock()
	a.h.st.AI.Providers = append(a.h.st.AI.Providers, state.ModelProvider{Name: "gem", Label: "Gemini", Kind: "google", Credentials: "admin"})
	next, has, w := a.h.restoredAILocked(a.h.findLocked("ai-chat"), &aiArchive{Providers: []string{"claude-b", "claude-a", "ollama-gpu", "ghost", "gem"}}, nil, false, state.AIInstance{})
	a.h.mu.Unlock()
	if !has || !slices.Equal(next.Providers, []string{"claude-a", "ollama-gpu"}) {
		t.Errorf("restored selection = %v (has %v)", next.Providers, has)
	}
	if len(w) != 3 || !strings.Contains(strings.Join(w, "\n"), "at most one") || !strings.Contains(strings.Join(w, "\n"), "google") || !strings.Contains(strings.Join(w, "\n"), "ghost") {
		t.Errorf("warnings = %q", w)
	}
}
