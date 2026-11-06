package hub

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// chatFixture is the AI page test template (templates' testdata) with
// provider_kinds replaced by kinds.
func chatFixture(t *testing.T, kinds string) [2]string {
	t.Helper()
	dir := filepath.Join("..", "templates", "testdata", "ai", "chat")
	m, c := readFile(t, filepath.Join(dir, "manifest.yaml")), readFile(t, filepath.Join(dir, "compose.yml"))
	const orig = "provider_kinds: {openai_compatible: many, anthropic: one}"
	if !strings.Contains(m, orig) {
		t.Fatal("the chat fixture's provider_kinds changed")
	}
	return [2]string{strings.Replace(m, orig, "provider_kinds: "+kinds, 1), c}
}

const liteLLMManifest = `name: LiteLLM
category: ai
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_litellm
urls:
  - label: API
    url: "https://{{HOST_LITELLM}}"
`

const liteLLMCompose = "services:\n  proxy:\n    image: litellm\n    labels:\n" +
	"      traefik.http.routers.litellm.rule: Host(`${PORTCULLIS_HOST_LITELLM:-llm.portcullis.local}`)\n"

// aiFixture: the instance fixture plus ai-chat (kinds) and litellm, an
// instance litellm-lab and a grafana instance, audited.
func aiFixture(t *testing.T, kinds string, seed func(*state.AppState)) (*fixture, *fakeAudit) {
	t.Helper()
	f := newInstanceFixtureExtra(t, seed, nil, map[string][2]string{
		"ai-chat": chatFixture(t, kinds),
		"litellm": {liteLLMManifest, liteLLMCompose},
	})
	for _, id := range []string{"ai-chat", "litellm"} {
		if f.h.Template(id) == nil {
			t.Fatalf("%s not loaded (see the log)", id)
		}
	}
	if err := f.h.CreateInstance("litellm", "litellm-lab", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	return f, audit
}

var ollama = state.ModelProvider{Name: "ollama", Label: "Ollama on the GPU", Kind: "openai_compatible",
	BaseURL: "http://gpu.lan:11434/v1", Models: state.ProviderModels{List: []string{"llama3.3:70b"}}}

func TestProviderKindsMatchTemplates(t *testing.T) {
	if got := slices.Sorted(maps.Keys(ProviderKinds)); !slices.Equal(got, slices.Sorted(slices.Values(templates.ProviderKinds))) {
		t.Errorf("ProviderKinds = %v, templates.ProviderKinds = %v", got, templates.ProviderKinds)
	}
	if v := ProviderVar("ollama-gpu", "key"); v != "PORTCULLIS_AI_PROVIDER_OLLAMA_GPU_KEY" {
		t.Errorf("ProviderVar = %s", v)
	}
	if !templates.ReservedVar(ProviderVar("x", "key")) {
		t.Error("a provider variable is not reserved")
	}
}

// TestProviderValidation (contract §15.12).
func TestProviderValidation(t *testing.T) {
	f, audit := aiFixture(t, "{openai_compatible: many, litellm: many, anthropic: one, azure_openai: many}", nil)
	add := func(p state.ModelProvider) error {
		_, err := f.h.AddModelProvider(p, aiAdmin)
		return err
	}
	if err := add(ollama); err != nil {
		t.Fatal(err)
	}
	with := func(edit func(*state.ModelProvider)) state.ModelProvider {
		p := cloneProvider(ollama)
		p.Name = "other"
		edit(&p)
		return p
	}
	for _, c := range []struct {
		name   string
		p      state.ModelProvider
		status int
		why    string
	}{
		{"uppercase name", with(func(p *state.ModelProvider) { p.Name = "Ollama" }), 400, "name"},
		{"duplicate", ollama, 409, "exists already"},
		{"unknown kind", with(func(p *state.ModelProvider) { p.Kind = "mistral" }), 400, "kind"},
		{"no base_url", with(func(p *state.ModelProvider) { p.BaseURL = "" }), 400, "needs base_url"},
		{"litellm missing instance", with(func(p *state.ModelProvider) { p.Kind, p.BaseURL, p.Instance = "litellm", "", "nope" }), 400, "no such instance"},
		{"litellm non-litellm instance", with(func(p *state.ModelProvider) { p.Kind, p.BaseURL, p.Instance = "litellm", "", "grafana-b" }), 400, "not a LiteLLM instance"},
		{"litellm base_url", with(func(p *state.ModelProvider) { p.Kind, p.Instance = "litellm", "litellm-lab" }), 400, "base_url is not a field"},
		{"no chat template", with(func(p *state.ModelProvider) { p.Kind, p.BaseURL, p.Region = "bedrock", "", "us-east-1" }), 400, "no installed AI page supports kind bedrock"},
		{"no label", with(func(p *state.ModelProvider) { p.Label = " " }), 400, "label"},
		{"label two lines", with(func(p *state.ModelProvider) { p.Label = "a\nb" }), 400, "label"},
		{"credentials", with(func(p *state.ModelProvider) { p.Credentials = "shared" }), 400, "credentials"},
		{"user in base_url", with(func(p *state.ModelProvider) { p.BaseURL = "https://u:sk-1@gpu.lan/v1" }), 400, "base_url"},
		{"query in base_url", with(func(p *state.ModelProvider) { p.BaseURL = "https://gpu.lan/v1?key=sk-1" }), 400, "base_url"},
		{"ftp base_url", with(func(p *state.ModelProvider) { p.BaseURL = "ftp://gpu.lan/" }), 400, "base_url"},
		{"field of another kind", with(func(p *state.ModelProvider) { p.Region = "us-east-1" }), 400, "region is not a field"},
		{"fetch on anthropic", with(func(p *state.ModelProvider) { p.Kind, p.BaseURL, p.Models.Fetch = "anthropic", "", true }), 400, "models.fetch"},
		{"model twice", with(func(p *state.ModelProvider) { p.Models.List = []string{"a", "a"} }), 400, "twice"},
		{"azure without instance", with(func(p *state.ModelProvider) {
			p.Kind, p.BaseURL, p.APIVersion, p.Deployments = "azure_openai", "", "2024-10-21", map[string]string{"gpt4o": "gpt-4o"}
		}), 400, "instance_name or base_url"},
		{"azure bad api_version", with(func(p *state.ModelProvider) {
			p.Kind, p.BaseURL, p.InstanceName, p.APIVersion, p.Deployments = "azure_openai", "", "acme", "latest", map[string]string{"gpt4o": "gpt-4o"}
		}), 400, "api_version"},
	} {
		err := add(c.p)
		if statusOf(err) != c.status || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: err = %v, want %d %q", c.name, err, c.status, c.why)
		}
	}
	// Valid kinds with their own fields.
	lv, err := f.h.AddModelProvider(state.ModelProvider{Name: "lab", Label: "Lab LiteLLM", Kind: "litellm", Instance: "litellm-lab",
		Models: state.ProviderModels{Fetch: true}}, aiAdmin)
	if err != nil {
		t.Fatal(err)
	}
	host := f.h.Template("litellm-lab").Hosts["litellm"]
	if host == "" || lv.BaseURL != "https://"+host || lv.Credentials != "admin" {
		t.Errorf("litellm view = %+v (host %q)", lv.ModelProvider, host)
	}
	if _, ok := lv.Secrets["key"]; !ok || lv.Secrets["key"].Set || len(lv.UsedBy) != 0 {
		t.Errorf("litellm secrets / used_by = %+v %+v", lv.Secrets, lv.UsedBy)
	}
	if err := add(state.ModelProvider{Name: "azure", Label: "Azure", Kind: "azure_openai", InstanceName: "acme", APIVersion: "2024-10-01-preview",
		Deployments: map[string]string{"gpt4o": "gpt-4o"}}); err != nil {
		t.Fatal(err)
	}
	// Update: kept name, label changed; kind can't change; unknown 404.
	up := cloneProvider(ollama)
	up.Label = "Ollama (office)"
	if v, err := f.h.UpdateModelProvider("ollama", up, aiAdmin); err != nil || v.Label != "Ollama (office)" {
		t.Fatalf("update = %+v %v", v, err)
	}
	up.Kind, up.BaseURL = "anthropic", ""
	if _, err := f.h.UpdateModelProvider("ollama", up, aiAdmin); statusOf(err) != 400 {
		t.Errorf("kind change = %v, want 400", err)
	}
	if _, err := f.h.UpdateModelProvider("nope", ollama, aiAdmin); statusOf(err) != 404 && statusOf(err) != 400 {
		t.Errorf("unknown = %v, want 404", err)
	}
	if _, err := f.h.UpdateModelProvider("ghost", state.ModelProvider{Name: "ghost", Label: "G", Kind: "anthropic"}, aiAdmin); statusOf(err) != 404 {
		t.Errorf("unknown = %v, want 404", err)
	}
	if _, err := f.h.AddModelProvider(ollama, directory.Actor{}); statusOf(err) != 401 {
		t.Errorf("no actor = %v", err)
	}
	names := []string{}
	for _, p := range f.h.ModelProviders(t.Context()) {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "azure,lab,ollama" {
		t.Errorf("providers = %v", names)
	}
	var adds, updates, refusedAdds int
	for _, e := range audit.entries {
		switch {
		case e.Action == "ai.provider.add" && e.Result == "ok":
			adds++
		case e.Action == "ai.provider.add" && e.Result == "refused":
			refusedAdds++
		case e.Action == "ai.provider.update" && e.Result == "ok" && e.Target == "ollama":
			updates++
		}
		if e.Actor != "root" && e.Actor != "" {
			t.Errorf("audit actor = %+v", e)
		}
	}
	if adds != 3 || updates != 1 || refusedAdds < 20 {
		t.Errorf("audit: %d adds, %d updates, %d refused adds", adds, updates, refusedAdds)
	}
	// Persisted, never with a secret field.
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil || len(st.AI.Providers) != 3 || st.AI.Providers[2].Label != "Ollama (office)" {
		t.Fatalf("persisted = %+v %v", st.AI.Providers, err)
	}
}

// TestProviderVariableClash (G30(d)): x.secret_access_key and
// x-secret-access.key are both PORTCULLIS_AI_PROVIDER_X_SECRET_ACCESS_KEY:
// the second provider is a 409, whichever comes first.
func TestProviderVariableClash(t *testing.T) {
	x := state.ModelProvider{Name: "x", Label: "X", Kind: "bedrock", Region: "eu-west-1"}
	y := state.ModelProvider{Name: "x-secret-access", Label: "Y", Kind: "anthropic"}
	for _, order := range [][2]state.ModelProvider{{x, y}, {y, x}} {
		f, _ := aiFixture(t, "{bedrock: one, anthropic: one}", nil)
		if _, err := f.h.AddModelProvider(order[0], aiAdmin); err != nil {
			t.Fatal(err)
		}
		_, err := f.h.AddModelProvider(order[1], aiAdmin)
		if statusOf(err) != 409 || !strings.Contains(err.Error(), "PORTCULLIS_AI_PROVIDER_X_SECRET_ACCESS_KEY") {
			t.Errorf("%s after %s: %v, want 409 naming the variable", order[1].Name, order[0].Name, err)
		}
	}
}

// TestDeleteProviderInUse: selected by ai-chat → 409 naming it (and
// used_by lists it); deselected → deleted with its secrets, audited.
func TestDeleteProviderInUse(t *testing.T) {
	f, audit := aiFixture(t, "{openai_compatible: many}", func(st *state.AppState) {
		st.AIInstances = map[string]state.AIInstance{"ai-chat": {Providers: []string{"ollama"}}}
	})
	if _, err := f.h.AddModelProvider(ollama, aiAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetProviderSecret("ollama", "key", []byte("sk-DELETE-ME"), aiAdmin); err != nil {
		t.Fatal(err)
	}
	vs := f.h.ModelProviders(t.Context())
	if len(vs) != 1 || len(vs[0].UsedBy) != 1 || vs[0].UsedBy[0].Instance != "ai-chat" || vs[0].UsedBy[0].Group != "users_chat" {
		t.Fatalf("used_by = %+v", vs)
	}
	err := f.h.DeleteModelProvider("ollama", aiAdmin)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "ai-chat") {
		t.Fatalf("delete while selected = %v, want 409 naming ai-chat", err)
	}
	if e := audit.last(); e.Action != "ai.provider.delete" || e.Result != "refused" {
		t.Errorf("audit = %+v", e)
	}
	if vals, _ := f.h.providerSecrets(); vals["ollama.key"] != "sk-DELETE-ME" {
		t.Fatal("a refused delete removed the secret")
	}
	f.h.mu.Lock()
	delete(f.h.st.AIInstances, "ai-chat")
	f.h.mu.Unlock()
	if err := f.h.DeleteModelProvider("ollama", aiAdmin); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "ai.provider.delete" || e.Result != "ok" || e.Target != "ollama" || e.Actor != "root" {
		t.Errorf("audit = %+v", e)
	}
	if vals, err := f.h.providerSecrets(); err != nil || len(vals) != 0 {
		t.Errorf("store after delete = %d entries, %v", len(vals), err)
	}
	if _, err := os.Stat(f.h.providerSecretsPath()); !os.IsNotExist(err) {
		t.Errorf("empty store not removed: %v", err)
	}
	if len(f.h.ModelProviders(t.Context())) != 0 || len(f.h.st.AI.ProviderSecrets) != 0 {
		t.Error("provider or its secret metadata left")
	}
	// Re-adding the name starts without secrets.
	v, err := f.h.AddModelProvider(ollama, aiAdmin)
	if err != nil || v.Secrets["key"].Set {
		t.Errorf("re-added = %+v %v", v.Secrets, err)
	}
	if err := f.h.DeleteModelProvider("ghost", aiAdmin); statusOf(err) != 404 {
		t.Errorf("unknown = %v", err)
	}
}

// TestProviderSecretStore (G71): 0600 in a 0700 directory, set / clear
// with {set, updated_at}, audited "<field> replaced|cleared", the value
// buffer zeroed, refused values never quoted, unknown fields 400.
func TestProviderSecretStore(t *testing.T) {
	f, audit := aiFixture(t, "{openai_compatible: many, bedrock: one}", nil)
	if _, err := f.h.AddModelProvider(ollama, aiAdmin); err != nil {
		t.Fatal(err)
	}
	buf := []byte("sk-MARKER-123")
	v, err := f.h.SetProviderSecret("ollama", "key", buf, aiAdmin)
	if err != nil || !v.Set || v.UpdatedAt == nil {
		t.Fatalf("set = %+v %v", v, err)
	}
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Error("the value buffer was not zeroed")
	}
	if e := audit.last(); e.Action != "ai.provider.secret" || e.Detail != "key replaced" || e.Target != "ollama" || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	st, err := os.Stat(f.h.providerSecretsPath())
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("store mode = %v %v", st, err)
	}
	if d, _ := os.Stat(filepath.Dir(f.h.providerSecretsPath())); d == nil || d.Mode().Perm() != 0700 {
		t.Errorf("store dir mode = %v", d)
	}
	if vals, _ := f.h.providerSecrets(); vals["ollama.key"] != "sk-MARKER-123" {
		t.Error("value not stored")
	}
	for _, c := range []struct {
		field, value string
		status       int
	}{
		{"secret_access_key", "sk-MARKER-123", 400},
		{"key", "sk-MARKER-123'x", 400},
		{"key", "sk-MARKER-123\nx", 400},
		{"key", "", 400},
	} {
		_, err := f.h.SetProviderSecret("ollama", c.field, []byte(c.value), aiAdmin)
		if statusOf(err) != c.status || strings.Contains(err.Error(), "MARKER") {
			t.Errorf("%s=%q: %v, want %d without the value", c.field, c.value, err, c.status)
		}
	}
	if _, err := f.h.SetProviderSecret("ghost", "key", []byte("sk-MARKER-123"), aiAdmin); statusOf(err) != 404 {
		t.Errorf("unknown provider = %v", err)
	}
	v, err = f.h.ClearProviderSecret("ollama", "key", aiAdmin)
	if err != nil || v.Set {
		t.Fatalf("clear = %+v %v", v, err)
	}
	if e := audit.last(); e.Detail != "key cleared" || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	if vals, _ := f.h.providerSecrets(); len(vals) != 0 {
		t.Error("cleared value still stored")
	}
	for _, e := range audit.entries {
		if strings.Contains(e.Detail+e.Error, "MARKER") {
			t.Errorf("audit holds the value: %+v", e)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(f.data, "state.yaml")); bytes.Contains(data, []byte("MARKER")) {
		t.Error("state.yaml holds the value")
	}
}

// TestProviderSecretsMaskedAndRedacted (G30(a)/(c)): Expert Env shows
// PORTCULLIS_AI_PROVIDER_* (and any copy of a provider secret) as [set],
// SaveEnv takes [set] back unchanged and refuses a change, every
// instance's redaction set holds the provider secrets, and an unreadable
// store hides messages.
func TestProviderSecretsMaskedAndRedacted(t *testing.T) {
	f, _ := aiFixture(t, "{openai_compatible: many}", nil)
	if _, err := f.h.AddModelProvider(ollama, aiAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetProviderSecret("ollama", "key", []byte("sk-MARKER-123"), aiAdmin); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.h.envPath("grafana-b"), "PORTCULLIS_AI_PROVIDER_OLLAMA_KEY='sk-MARKER-123'\nCOPY=sk-MARKER-123\nPLAIN=hello\n")
	vars, _, err := f.h.Env("grafana-b")
	if err != nil {
		t.Fatal(err)
	}
	if vars["PORTCULLIS_AI_PROVIDER_OLLAMA_KEY"] != "[set]" || vars["COPY"] != "[set]" || vars["PLAIN"] != "hello" {
		t.Errorf("Env = %v", vars)
	}
	if err := f.h.SaveEnv("grafana-b", vars); err != nil {
		t.Errorf("SaveEnv of the masked values = %v", err)
	}
	vars["PORTCULLIS_AI_PROVIDER_OLLAMA_KEY"] = "sk-other"
	if err := f.h.SaveEnv("grafana-b", vars); statusOf(err) != 400 {
		t.Errorf("SaveEnv changing a provider variable = %v, want 400", err)
	}
	if !strings.Contains(readFile(t, f.h.envPath("grafana-b")), "PORTCULLIS_AI_PROVIDER_OLLAMA_KEY='sk-MARKER-123'") {
		t.Error("the provider variable was rewritten")
	}
	for _, id := range []string{"grafana-b", "litellm-lab"} {
		if got := f.h.secretRedactor(id)("boom sk-MARKER-123 boom"); strings.Contains(got, "MARKER") {
			t.Errorf("%s redactor = %q", id, got)
		}
	}
	writeFile(t, f.h.providerSecretsPath(), "not json")
	if got := f.h.secretRedactor("grafana-b")("boom"); !strings.Contains(got, "hidden") {
		t.Errorf("unreadable store: redactor = %q, want the message hidden", got)
	}
	if _, _, err := f.h.Env("grafana-b"); err == nil {
		t.Error("Env with an unreadable provider store must fail closed")
	}
}
