package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 17b: the admin tools of the Portcullis MCP, part 2 —
// catalog and sources, backups, domains, AI, Hub settings and their G15
// tools (contract §15.10–15.11; G15, G16, G30, G37).

// withDomains gives e's Hub a fake domains service (TestTokenNotEchoed's).
func withDomains(t *testing.T, e *toolEnv) *fakeDomainsService {
	t.Helper()
	secret := strings.Repeat("d", 40)
	fake, fsrv := newFakeDomainsService(t, secret)
	sf := filepath.Join(t.TempDir(), "api-secret")
	os.WriteFile(sf, []byte(secret+"\n"), 0600)
	e.s.Hub.SetDomainsAPI(domains.New(fsrv.URL, sf))
	return fake
}

// accept calls a U tool on 2026-07-28 with the person's accept reply.
func (e *toolEnv) accept(t *testing.T, tool string, args any) (string, bool) {
	t.Helper()
	return resultText(e.call(t, "/mcp/admin", "root", "2026-07-28", tool, args, urlElicit,
		map[string]any{"inputResponses": map[string]any{secretFormInputKey: map[string]any{"action": "accept"}}}))
}

// toolSchema is a listed tool's inputSchema.
func (e *toolEnv) toolSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2025-11-25", method: "tools/list", params: map[string]any{}})
	if code != 200 {
		t.Fatal(code)
	}
	res, _ := a["result"].(map[string]any)
	ts, _ := res["tools"].([]any)
	for _, x := range ts {
		tl := x.(map[string]any)
		if tl["name"] == name {
			s, _ := tl["inputSchema"].(map[string]any)
			return s
		}
	}
	t.Fatalf("tool %s isn't listed", name)
	return nil
}

// TestEnrollDomainNoToken (§15.10, U): enroll_domain's schema has no
// credential field (nor replace_domain_token's); its call answers the
// Domains form's URL (URL elicitation, or the link as text); a token
// argument is refused and never forwarded; after the person's accept it
// reports what the Hub knows — never the client's word, never the token.
func TestEnrollDomainNoToken(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	fake := withDomains(t, e)
	for _, n := range []string{"enroll_domain", "replace_domain_token"} {
		props, _ := e.toolSchema(t, n)["properties"].(map[string]any)
		for k := range props {
			if secretArgRe.MatchString(k) || strings.Contains(k, "cred") {
				t.Errorf("%s declares %q", n, k)
			}
		}
		if len(props) == 0 {
			t.Errorf("%s: no properties", n)
		}
	}
	args := map[string]any{"name": "Team-C.example.net"}
	el := elicitation(t, e.call(t, "/mcp/admin", "root", "2026-07-28", "enroll_domain", args, urlElicit), secretFormInputKey)
	if el["url"] != "https://hub.example.org/#settings/domains?enroll=team-c.example.net" {
		t.Errorf("form url %v", el["url"])
	}
	el = elicitation(t, e.call(t, "/mcp/admin", "root", "2026-07-28", "enroll_domain", map[string]any{"name": "team-c.example.net", "provider": "hetzner"}, urlElicit), secretFormInputKey)
	if el["url"] != "https://hub.example.org/#settings/domains?enroll=team-c.example.net&provider=hetzner" {
		t.Errorf("form url %v", el["url"])
	}
	// The text form on 2025-11-25.
	if txt, _ := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "enroll_domain", args, nil)); !strings.Contains(txt, "https://hub.example.org/#settings/domains?enroll=team-c.example.net") {
		t.Errorf("text form = %q", txt)
	}
	// A token in the arguments: refused, pointing at the form; never forwarded.
	for _, bad := range []map[string]any{
		{"name": "team-c.example.net", "api_token": dnsToken},
		{"name": "team-c.example.net", "credentials": map[string]string{"api_token": dnsToken}},
	} {
		txt, isErr := resultText(e.call(t, "/mcp/admin", "root", "2026-07-28", "enroll_domain", bad, urlElicit))
		if !isErr || !strings.HasPrefix(txt, textSecretArgs+"https://hub.example.org/#settings/domains?enroll=team-c.example.net") || strings.Contains(txt, dnsToken) {
			t.Errorf("token argument = %q %v", txt, isErr)
		}
	}
	if len(fake.bodies) != 0 {
		t.Fatalf("the tool reached the domains service: %v", fake.bodies)
	}
	// Accept before anything was submitted: not enrolled (the Hub's state).
	if txt, isErr := e.accept(t, "enroll_domain", args); isErr || !strings.Contains(txt, `"enrolled":false`) {
		t.Errorf("accept before = %q %v", txt, isErr)
	}
	// The form posts (the Hub page); then the same accept reports it.
	mustDo(t, e.hub, "root", "POST", "/api/domains", enrollBody("team-c.example.net", dnsToken), 202)
	txt, isErr := e.accept(t, "enroll_domain", args)
	if isErr || !strings.Contains(txt, `"enrolled":true`) || !strings.Contains(txt, `"provider":"cloudflare"`) || strings.Contains(txt, dnsToken) {
		t.Errorf("accept after = %q %v", txt, isErr)
	}
	// replace_domain_token: its form, then the last recorded replacement.
	el = elicitation(t, e.call(t, "/mcp/admin", "root", "2026-07-28", "replace_domain_token", map[string]any{"name": "team-c.example.net"}, urlElicit), secretFormInputKey)
	if el["url"] != "https://hub.example.org/#settings/domains?token=team-c.example.net" {
		t.Errorf("token form url %v", el["url"])
	}
	if txt, _ := e.accept(t, "replace_domain_token", map[string]any{"name": "team-c.example.net"}); strings.Contains(txt, "last_replaced") {
		t.Errorf("a replacement before any: %s", txt)
	}
	mustDo(t, e.hub, "root", "POST", "/api/domains/team-c.example.net/token", `{"provider":"cloudflare","credentials":{"api_token":"`+dnsToken+`2"}}`, 202)
	txt, isErr = e.accept(t, "replace_domain_token", map[string]any{"name": "team-c.example.net"})
	if isErr || !strings.Contains(txt, `"last_replaced":{"at":`) || !strings.Contains(txt, `"by":"root"`) || strings.Contains(txt, dnsToken) {
		t.Errorf("after replace = %q %v", txt, isErr)
	}
}

// TestSaveHubSettingsCantEnableAdminMCP (§15.10, the brief): the tool
// turns the Portcullis admin MCP off (W), never on — refused outright
// (no confirmation, nothing saved, audited refused via ai), whatever else
// the call holds; the Hub's page still can.
func TestSaveHubSettingsCantEnableAdminMCP(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	if !e.s.Hub.AISettings().PortcullisAdmin {
		t.Fatal("the admin MCP is off to begin with")
	}
	txt, isErr, conf := e.tool(t, "save_hub_settings", map[string]any{"portcullis_admin": false})
	if isErr || conf != "" || e.s.Hub.AISettings().PortcullisAdmin {
		t.Fatalf("off = %q %v (confirmation %q)", txt, isErr, conf)
	}
	for _, args := range []map[string]any{
		{"portcullis_admin": true},
		{"portcullis_admin": true, "enabled": false},
		{"portcullis_admin": true, "clients": map[string]any{"claude": map[string]any{"admin": true}}},
	} {
		n := len(readAudit(t, e.audit))
		txt, isErr, conf := e.tool(t, "save_hub_settings", args)
		if !isErr || conf != "" || !strings.HasPrefix(txt, "403: ") || !strings.Contains(txt, "can't be turned on through the AI") {
			t.Errorf("%v = %q %v (confirmation %q)", args, txt, isErr, conf)
		}
		if v := e.s.Hub.AISettings(); v.PortcullisAdmin || !v.Enabled || v.Clients.Claude.Admin {
			t.Errorf("%v changed the settings: %+v", args, v)
		}
		got := readAudit(t, e.audit)[n:]
		if len(got) != 1 || got[0].Action != "settings.ai" || got[0].Result != "refused" || got[0].Via != "ai" || got[0].Client != mcpClient {
			t.Errorf("%v audit = %+v", args, got)
		}
	}
	// A client's admin flag (no admin-MCP switch in the call) is D, not refused.
	txt, _ = resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "save_hub_settings", map[string]any{"clients": map[string]any{"claude": map[string]any{"admin": true}}}, nil))
	if !confirmTextRe.MatchString(txt) {
		t.Errorf("client admin flag = %q, want a confirmation", txt)
	}
	// The Hub's page turns it on.
	mustDo(t, e.hub, "root", "PUT", "/api/ai/settings", `{"portcullis_admin":true}`, 200)
	if !e.s.Hub.AISettings().PortcullisAdmin {
		t.Error("the page couldn't turn it on")
	}
}

// TestToolClassPerCall17b (G37 and the Task 17b rulings): each per-call
// tool is W only for its narrowing arguments, D (a confirmation) for
// anything that widens or doesn't decode; add_source and
// add_model_provider are always D, backup_instance and sync_sources W.
func TestToolClassPerCall17b(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	if _, err := e.s.Hub.AddModelProvider(ollamaModel(), directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tool    string
		args    map[string]any
		confirm bool
	}{
		{"set_ai_support", map[string]any{"id": "aiapp", "companion": "tok", "enabled": true}, true},
		{"set_ai_mode", map[string]any{"id": "aiapp", "companion": "tok", "mode": "read_write"}, true},
		{"set_ai_mode", map[string]any{"id": "aiapp", "companion": "tok", "mode": "bogus"}, true},
		{"set_ai_mode", map[string]any{"id": "aiapp", "companion": "tok", "mode": "read_only"}, false},
		{"set_ai_support", map[string]any{"id": "aiapp", "companion": "tok", "enabled": false}, false},
		// Providers: the stored one's label → W; its destination, or a new name → D.
		{"save_model_provider", ollamaArgs(map[string]any{"models": map[string]any{"fetch": false, "list": []string{"qwen3"}}}), false},
		{"save_model_provider", ollamaArgs(map[string]any{"credentials": "admin"}), false}, // "" stored = admin
		{"save_model_provider", ollamaArgs(map[string]any{"label": "Ollama 2"}), true},     // the egress note names it
		{"save_model_provider", ollamaArgs(map[string]any{"credentials": "bogus"}), true},
		{"save_model_provider", ollamaArgs(map[string]any{"credentials": "per_person"}), false}, // admin → per_person: runs
		{"save_model_provider", ollamaArgs(map[string]any{"credentials": "admin"}), true},       // per_person → admin
		{"save_model_provider", ollamaArgs(nil), true},                                          // "" = admin, from per_person
		{"save_model_provider", ollamaArgs(map[string]any{"base_url": "https://evil.example.com/v1"}), true},
		{"save_model_provider", ollamaArgs(map[string]any{"instance": "litellm"}), true},
		{"save_model_provider", ollamaArgs(map[string]any{"region": "us-east-1"}), true},
		{"save_model_provider", ollamaArgs(map[string]any{"name": "other"}), true},
		{"add_model_provider", ollamaArgs(map[string]any{"name": "other"}), true},
		// Hub settings: off and lower are W; on, clients, origins, higher D.
		{"save_hub_settings", map[string]any{"enabled": true}, true},
		{"save_hub_settings", map[string]any{"portcullis_people": true}, true},
		{"save_hub_settings", map[string]any{"clients": map[string]any{"generic": map[string]any{"offered": false}}}, true},
		{"save_hub_settings", map[string]any{"allowed_origins": []string{}}, true},
		{"save_hub_settings", map[string]any{"limits": map[string]any{"confirmations_per_hour": 50}}, true},
		{"save_hub_settings", map[string]any{"offline_max_days": 90}, true},
		{"save_hub_settings", map[string]any{"limits": map[string]any{"person_rpm": 300}, "offline_idle_days": 3}, false},
		{"save_hub_settings", map[string]any{"portcullis_people": false}, false},
		{"save_hub_settings", map[string]any{"enabled": false}, false},
		// Default policy: stricter W, equal or weaker D.
		{"set_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"webauthn", "mtls"}, "op": "any"}}, true},
		{"set_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"mtls", "webauthn"}, "op": "all"}}, false},
		{"set_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"webauthn"}, "op": "any"}}, true},
		// Always D / always W.
		{"add_source", map[string]any{"name": "more", "url": "https://example.org/more.git"}, true},
		{"backup_instance", map[string]any{"id": "nope"}, false},
		{"sync_sources", map[string]any{}, false},
	} {
		txt, _ := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", c.tool, c.args, nil))
		m := confirmTextRe.FindStringSubmatch(txt)
		if got := m != nil; got != c.confirm {
			t.Errorf("%s %v: confirmation %v, want %v (%s)", c.tool, c.args, got, c.confirm, txt)
		}
		if m != nil {
			e.decide(t, m[1], "", false) // declined: the pending ones stay few (G27)
		}
	}
	code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2025-11-25", method: "tools/list", params: map[string]any{}})
	if code != 200 {
		t.Fatal(code)
	}
	res, _ := a["result"].(map[string]any)
	ts, _ := res["tools"].([]any)
	want := map[string]bool{"set_ai_support": true, "set_ai_mode": true, "save_model_provider": true, "save_hub_settings": true,
		"set_default_policy": true, "add_source": true, "add_model_provider": true, "restore_as": true, "revoke_ai_access": true,
		"backup_instance": false, "sync_sources": false, "enroll_domain": false}
	for _, x := range ts {
		tl := x.(map[string]any)
		d, ok := want[tl["name"].(string)]
		if !ok {
			continue
		}
		delete(want, tl["name"].(string))
		ann, _ := tl["annotations"].(map[string]any)
		if (ann["destructiveHint"] == true) != d {
			t.Errorf("%s annotations %v, destructive want %v", tl["name"], ann, d)
		}
	}
	if len(want) != 0 {
		t.Errorf("not listed: %v", want)
	}
}

// TestAISupportConsequencesNameMode (fix round 1): switching a companion
// on names the mode it comes on in.
func TestAISupportConsequencesNameMode(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	for mode, want := range map[string]string{"read_only": "on in mode read_only:", "read_write": "on in mode read_write (AI clients may change things"} {
		if err := e.s.Hub.SetAIMode(context.Background(), "aiapp", "tok", mode, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
		got := strings.Join(e.s.aiSupportConsequences(json.RawMessage(`{"id":"aiapp","companion":"tok","enabled":true}`)), " ")
		if !strings.Contains(got, want) {
			t.Errorf("%s: consequences %q", mode, got)
		}
	}
	if got := strings.Join(e.s.aiSupportConsequences(json.RawMessage(`{"id":"nope","companion":"tok","enabled":true}`)), " "); !strings.Contains(got, "couldn't be read") {
		t.Errorf("unknown instance: %q", got)
	}
}

// ollamaModel is ollamaBody as a provider definition.
func ollamaModel() state.ModelProvider {
	var p state.ModelProvider
	json.Unmarshal([]byte(ollamaBody), &p)
	return p
}

// TestSourceToolsHideCredentials: add_source refuses a URL carrying
// credentials (after its confirmation, with the URL's credentials left
// out of the page), reaching no Hub call; list_sources shows URLs without
// user info or query.
func TestSourceToolsHideCredentials(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	rec := &callRec{}
	e.s.callHook = rec.hook
	const tok = "ghp_SOURCEMARKER123"
	args := map[string]any{"name": "more", "url": "https://bot:" + tok + "@example.org/more.git"}
	res := e.call(t, "/mcp/admin", "root", "2026-07-28", "add_source", args, urlElicit)
	m := confirmURLRe.FindStringSubmatch(elicitation(t, res, confirmInputKey)["url"].(string))
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, m[1], "root")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(v.Consequences, " "), tok) || v.Typed != "more" {
		t.Errorf("confirmation %q typed %q", v.Consequences, v.Typed)
	}
	e.decide(t, m[1], "more", true)
	txt, isErr := resultText(e.call(t, "/mcp/admin", "root", "2026-07-28", "add_source", args, urlElicit))
	if !isErr || !strings.HasPrefix(txt, "400: ") || strings.Contains(txt, tok) {
		t.Errorf("credentials in the URL = %q %v", txt, isErr)
	}
	if calls := rec.take(); len(calls) != 0 {
		t.Errorf("the refusal reached the Hub: %v", calls)
	}
	for u, want := range map[string]bool{
		"git@github.com:porelli/x.git": false, "https://example.org/x.git": false, "ssh://git@example.org/x.git": false,
		"https://example.org/x.git?token=1": true, "https://ghp_tok@example.org/x.git": true, "http://bot@example.org/x.git": true,
		"ssh://git:pw@example.org/x.git": true, "https://example.org/x.git#frag": true,
	} {
		if urlHasCredentials(u) != want {
			t.Errorf("urlHasCredentials(%s) = %v", u, !want)
		}
	}
	// The confirmation shows scp-style sources as host:path, URLs without
	// user info; the audit detail stays sourceURLDetail's.
	for u, want := range map[string]string{
		"git@github.com:porelli/x.git":  "github.com:porelli/x.git",
		"https://example.org/x.git?a=1": "https://example.org/x.git",
	} {
		if got := sourceDisplay(u); got != want {
			t.Errorf("sourceDisplay(%s) = %q, want %q", u, got, want)
		}
	}
	if got := sourceURLDetail("git@github.com:porelli/x.git"); got != "(scp-style source)" {
		t.Errorf("audit detail %q", got)
	}
	res = e.call(t, "/mcp/admin", "root", "2026-07-28", "add_source", map[string]any{"name": "scp", "url": "deploy@git.example.org:team/t.git"}, urlElicit)
	m = confirmURLRe.FindStringSubmatch(elicitation(t, res, confirmInputKey)["url"].(string))
	if v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, m[1], "root"); err != nil || !strings.Contains(v.Consequences[0], "(git.example.org:team/t.git)") || strings.Contains(v.Consequences[0], "deploy@") {
		t.Errorf("scp consequences %v %v", v, err)
	}
	txt, isErr, _ = e.tool(t, "list_sources", nil)
	if isErr || !strings.Contains(txt, `"name":"local"`) {
		t.Errorf("list_sources = %q %v", txt, isErr)
	}
}

// TestProviderSecretTool (G30, §15.12): set_model_provider_secret (U)
// answers the provider secret form, then what the Hub stores ({set,
// updated_at}); list_model_providers shows secrets the same way only.
func TestProviderSecretTool(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	if _, err := e.s.Hub.AddModelProvider(ollamaModel(), directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"name": "ollama", "field": "key"}
	el := elicitation(t, e.call(t, "/mcp/admin", "root", "2026-07-28", "set_model_provider_secret", args, urlElicit), secretFormInputKey)
	if el["url"] != "https://hub.example.org/#settings/ai?field=key&provider=ollama" {
		t.Errorf("form url %v", el["url"])
	}
	if txt, isErr := e.accept(t, "set_model_provider_secret", args); isErr || !strings.Contains(txt, `"secret":{"set":false}`) {
		t.Errorf("before = %q %v", txt, isErr)
	}
	const marker = "sk-PROVIDERMARKER-1"
	mustDo(t, e.hub, "root", "PUT", "/api/ai/providers/ollama/secrets/key", `{"value":"`+marker+`"}`, 200)
	txt, isErr := e.accept(t, "set_model_provider_secret", args)
	if isErr || !strings.Contains(txt, `"secret":{"set":true,"updated_at":`) || strings.Contains(txt, marker) {
		t.Errorf("after = %q %v", txt, isErr)
	}
	if txt, isErr := e.accept(t, "set_model_provider_secret", map[string]any{"name": "ollama", "field": "nope"}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("unknown field = %q %v", txt, isErr)
	}
	txt, isErr, _ = e.tool(t, "list_model_providers", nil)
	var l struct {
		Providers []map[string]any `json:"providers"`
	}
	if isErr || json.Unmarshal([]byte(txt), &l) != nil || len(l.Providers) != 1 {
		t.Fatalf("list = %q %v", txt, isErr)
	}
	sec, _ := l.Providers[0]["secrets"].(map[string]any)
	key, _ := sec["key"].(map[string]any)
	if len(key) != 2 || key["set"] != true || key["updated_at"] == nil || strings.Contains(txt, marker) {
		t.Errorf("secrets = %v", sec)
	}
}

// TestAIRevokeAndActivityRoutes (§15.11): POST /api/instances/{id}/ai/revoke
// (Task 17b, the twin of revoke_ai_access) and GET /api/ai/activity are
// admins only on the Hub listener; the revoke runs the companion's
// revoke_all and is audited ai.credential.revoke; the activity is the
// access log, newest first, filtered.
func TestAIRevokeAndActivityRoutes(t *testing.T) {
	gate := t.TempDir()
	e := newMCPEnvOpts(t, mcpEnvOpts{cfg: func(c *hub.Config) { c.MCPGateDataDir = gate }})
	now := time.Now().UTC().Truncate(time.Second)
	var log strings.Builder
	for i, l := range []map[string]any{
		{"user": "alice", "instance": "aiapp", "tool": "list_things"},
		{"user": "bob", "instance": "aiapp", "tool": "create_thing"},
		{"user": "alice", "instance": "other", "tool": "x"},
	} {
		line := map[string]any{"time": now.Add(time.Duration(i) * time.Second).Format(time.RFC3339), "user": l["user"], "client": mcpClient,
			"resource": aiappResource, "instance": l["instance"], "companion": "tok", "via": "direct", "method": "tools/call",
			"tool": l["tool"], "args_sha256": strings.Repeat("a", 64), "decision": "allow", "upstream_status": 200, "duration_ms": 3}
		b, _ := json.Marshal(line)
		log.Write(append(b, '\n'))
	}
	os.WriteFile(filepath.Join(gate, hub.AccessLogName), []byte(log.String()), 0o640)
	checkAdminOnly(t, e.instEnv, []route{
		{"POST", "/api/instances/aiapp/ai/revoke", `{"companion":"tok"}`},
		{"GET", "/api/ai/activity", ""},
	})
	if a := e.auditActions(t, "ai.credential.revoke"); len(a) != 0 {
		t.Fatalf("refused requests reached the Hub: %v", a)
	}
	b := mustDo(t, e.hub, "root", "POST", "/api/instances/aiapp/ai/revoke", `{"companion":"tok","user":"Alice"}`, 200)
	if !strings.Contains(b, `"user":"alice"`) {
		t.Errorf("revoke = %s", b)
	}
	mustDo(t, e.hub, "root", "POST", "/api/instances/aiapp/ai/revoke", `{"companion":"tok"}`, 200)
	mustDo(t, e.hub, "root", "POST", "/api/instances/aiapp/ai/revoke", `{"companion":"nope"}`, 404)
	mustDo(t, e.hub, "root", "POST", "/api/instances/aiapp/ai/revoke", `{"companion":"tok","extra":1}`, 400)
	if got := e.auditActions(t, "ai.credential.revoke"); !slices.Contains(got, "ai.credential.revoke:ok:root:aiapp/tok") {
		t.Errorf("audit %v", got)
	}
	var act struct {
		Lines []hub.AccessLine `json:"lines"`
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ai/activity?instance=aiapp", "", 200)), &act)
	if len(act.Lines) != 2 || act.Lines[0].User != "bob" || act.Lines[1].User != "alice" {
		t.Errorf("activity = %+v", act.Lines)
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ai/activity?user=ALICE&n=1", "", 200)), &act)
	if len(act.Lines) != 1 || act.Lines[0].Instance != "other" {
		t.Errorf("activity = %+v", act.Lines)
	}
	mustDo(t, e.hub, "root", "GET", "/api/ai/activity?n=201", "", 400)
	mustDo(t, e.hub, "root", "GET", "/api/ai/activity?n=x", "", 400)
}

// TestReadTools17bAnswer: the R tools of part 2 answer (a smoke test).
func TestReadTools17bAnswer(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	if _, err := e.s.Hub.BackupInstance("secretapp", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"list_templates", nil, `"id":"secretapp"`},
		{"get_template", map[string]any{"id": "secretapp"}, `"manifest"`},
		{"list_sources", nil, `"sources"`},
		{"list_backups", map[string]any{"id": "secretapp"}, `secretapp/`},
		{"list_backups_all", nil, `secretapp/`},
		{"list_domains", nil, `"domains"`},
		{"ai_status", map[string]any{"id": "aiapp"}, `"companions"`},
		{"ai_activity", nil, ""}, // no gate data dir here: 503 (TestAIRevokeAndActivityRoutes reads lines)
		{"list_model_providers", nil, `"providers"`},
		{"get_hub_settings", nil, `"default_policy"`},
		{"preview_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"mtls"}, "op": "any"}}, `"warnings"`},
		{"user_sweep_status", nil, `"paused"`},
	} {
		txt, isErr, _ := e.tool(t, c.tool, c.args)
		if (isErr && c.tool != "ai_activity") || !strings.Contains(txt, c.want) {
			t.Errorf("%s = %q %v", c.tool, txt, isErr)
		}
	}
	// Fix round 1: Hub-set instance variables aren't secrets by name —
	// secretapp's hostname shows (PORTCULLIS_HOST_SECRETAPP, written into
	// its env by the enable).
	if err := e.s.Hub.Enable("secretapp"); err != nil {
		t.Fatal(err)
	}
	if readEnvValue(t, filepath.Join(e.data, "env", "secretapp.env"), "PORTCULLIS_HOST_SECRETAPP") != "secretapp.example.org" {
		t.Fatal("secretapp's env has no hostname")
	}
	if txt, isErr, _ := e.tool(t, "get_template", map[string]any{"id": "secretapp"}); isErr || !strings.Contains(txt, `"hosts":{"secretapp":"secretapp.example.org"}`) {
		t.Errorf("get_template secretapp = %q %v", txt, isErr)
	}
	// get_env hides generated / secret-looking values from the AI (and
	// save_env refuses the mask written back); public instance variables show.
	sec := readEnvValue(t, filepath.Join(e.data, "env", "aiapp.env"), "HDR_SECRET")
	if txt, _, _ := e.tool(t, "get_env", map[string]any{"id": "aiapp"}); !strings.Contains(txt, `"HDR_SECRET":"[secret]"`) ||
		strings.Contains(txt, sec) || !strings.Contains(txt, `"PORTCULLIS_INSTANCE":"aiapp"`) {
		t.Errorf("get_env = %s", txt)
	}
	if txt, isErr, _ := e.tool(t, "save_env", map[string]any{"id": "aiapp", "variables": map[string]string{"HDR_SECRET": "[secret]"}}); !isErr || !strings.HasPrefix(txt, "400: ") {
		t.Errorf("save_env [secret] = %q %v", txt, isErr)
	}
	// get_template leaves secret defaults out; an unknown template is 404.
	if txt, isErr, _ := e.tool(t, "get_template", map[string]any{"id": "nope"}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("unknown template = %q %v", txt, isErr)
	}
	// preview_default_policy at mTLS lists aiapp's switch-off (G43).
	if txt, _, _ := e.tool(t, "preview_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"mtls"}, "op": "any"}}); !strings.Contains(txt, "aiapp") {
		t.Errorf("preview = %s", txt)
	}
}

// chatManifest: a multi native-oidc template whose Keycloak client has
// a secret (generated into CHAT_SECRET; TestTokenNotEchoed's marker).
const chatManifest = `name: Chat
category: misc
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_talk
keycloak_clients:
  - client_id: talk
    secret_env: CHAT_SECRET
    redirect_uri: https://{{HOST_TALK}}/cb
env:
  - key: CHAT_SECRET
    generate: random
`

const chatCompose = "services:\n  web:\n    image: x\n    environment:\n      SECRET: ${CHAT_SECRET}\n    labels:\n" +
	"      traefik.http.routers.talk.rule: Host(`${PORTCULLIS_HOST_TALK:-talk.portcullis.local}`)\n"

// archivePH in a fixture's arguments is replaced by secretapp's newest
// backup (backup_instance runs first).
const archivePH = "{{archive}}"

// adminToolFixtures are fixture arguments for every admin tool
// (TestTokenNotEchoed runs each once, in this order; real targets where
// the success path can run).
var adminToolFixtures = []struct {
	tool string
	args map[string]any
}{
	{"hub_status", map[string]any{"include_doctor": true}},
	{"explain_policy", map[string]any{"id": "secretapp"}},
	{"list_instances", nil},
	{"get_instance", map[string]any{"id": "talk-a"}},
	{"instance_defaults", map[string]any{"template": "grafana", "id": "grafana-z"}},
	{"create_instance", map[string]any{"template": "grafana", "id": "grafana-q"}},
	{"enable_instance", map[string]any{"id": "secretapp"}},
	{"restart_instance", map[string]any{"id": "secretapp"}},
	{"set_hosts", map[string]any{"id": "grafana-q", "hosts": map[string]string{"grafana": "grafana-r.example.org"}}},
	{"get_settings", map[string]any{"id": "secretapp"}},
	{"preview_settings", map[string]any{"id": "secretapp", "values": map[string]any{"api_url": "https://a.example.org"}}},
	{"save_settings", map[string]any{"id": "secretapp", "values": map[string]any{"api_url": "https://a.example.org"}, "plan_hash": strings.Repeat("0", 64)}},
	{"set_secret_setting", map[string]any{"id": "secretapp", "option": "api_key"}},
	{"set_policy", map[string]any{"id": "secretapp", "policy": map[string]any{"factors": []string{"webauthn"}, "op": "any"}}},
	{"set_sign_in_mode", map[string]any{"id": "nativeapp", "mode": "gateway"}},
	{"set_public_access", map[string]any{"id": "cloud", "access": "off"}},
	{"get_status", map[string]any{"id": "smbfixture"}},
	{"exec", map[string]any{"id": "smbfixture", "service": "smb", "command": "env"}},
	{"get_compose", map[string]any{"id": "talk-a"}},
	{"get_env", map[string]any{"id": "talk-a"}},
	{"save_env", map[string]any{"id": "secretapp", "variables": map[string]string{"FOO": "bar"}}},
	{"get_custom_override", map[string]any{"id": "secretapp"}},
	{"save_custom_override", map[string]any{"id": "secretapp", "content": ""}},
	{"list_drift", map[string]any{"recheck": true}},
	{"resolve_drift", map[string]any{"id": "nope-a", "action": "apply"}},
	{"set_person_value", map[string]any{"id": "secretapp", "key": "api_url", "user": "dana", "value": "x"}},
	{"clear_person_value", map[string]any{"id": "secretapp", "key": "api_url", "user": "dana"}},
	{"retry_deliveries", map[string]any{"id": "smbfixture"}},
	{"missing_groups", nil},
	{"create_missing_groups", map[string]any{"ids": []string{"secretapp"}}},
	{"list_credentials", map[string]any{"id": "smbfixture"}},
	{"get_local_networks", nil},
	{"set_local_networks", map[string]any{"use_defaults": true}},
	{"list_templates", nil},
	{"get_template", map[string]any{"id": "secretapp"}},
	{"list_sources", nil},
	{"sync_sources", nil},
	{"add_source", map[string]any{"name": "more", "url": "https://bot:pw@example.org/more.git"}},
	{"remove_source", map[string]any{"name": "nosuch"}},
	{"backup_instance", map[string]any{"id": "secretapp"}},
	{"list_backups", map[string]any{"id": "secretapp"}},
	{"list_backups_all", nil},
	{"restore_instance", map[string]any{"id": "secretapp", "archive": archivePH}},
	{"restore_as", map[string]any{"archive": archivePH, "id": "secretapp-b"}},
	{"delete_instance", map[string]any{"id": "secretapp-b"}},
	{"list_domains", nil},
	{"enroll_domain", map[string]any{"name": "team-c.example.net"}},
	{"replace_domain_token", map[string]any{"name": "team-c.example.net"}},
	{"ai_status", map[string]any{"id": "aiapp"}},
	{"set_ai_mode", map[string]any{"id": "aiapp", "companion": "tok", "mode": "read_only"}},
	{"set_ai_support", map[string]any{"id": "aiapp", "companion": "tok", "enabled": true}},
	{"revoke_ai_access", map[string]any{"id": "aiapp", "companion": "tok"}},
	{"ai_activity", nil},
	{"list_model_providers", nil},
	{"add_model_provider", map[string]any{"name": "other", "label": "Other", "kind": "anthropic"}},
	{"save_model_provider", map[string]any{"name": "ollama", "label": "Ollama", "kind": "openai_compatible", "base_url": "http://gpu.lan:11434/v1", "models": map[string]any{"fetch": false, "list": []string{"qwen3"}}}},
	{"set_model_provider_secret", map[string]any{"name": "ollama", "field": "key"}},
	{"delete_model_provider", map[string]any{"name": "other"}},
	{"get_hub_settings", nil},
	{"save_hub_settings", map[string]any{"limits": map[string]any{"resource_rpm": 100}}},
	{"set_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"webauthn", "mtls"}, "op": "any"}}},
	{"preview_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"mtls"}, "op": "any"}}},
	{"user_sweep_status", nil},
	{"resume_user_sweep", nil},
	{"remove_stale_keycloak_user", map[string]any{"username": "ghost"}},
	{"admin_revoke_credential", map[string]any{"id": "smbfixture", "key": "share_password", "user": "alice"}},
	{"delete_domain", map[string]any{"name": "team-c.example.net"}},
	{"disable_instance", map[string]any{"id": "secretapp"}},
	// At the end, over what the operations above left (fix round 1).
	{"get_op", map[string]any{"id": "secretapp"}},
	{"wait_for_op", map[string]any{"id": "secretapp"}},
	{"get_logs", map[string]any{"id": "smbfixture"}},
}

// redactedAllowed are the admin tools whose results may show
// "[redacted]" (the global redactor blanked something), each with why:
// any other "[redacted]" means a tool put a secret in its result and only
// the redactor caught it (TestTokenNotEchoed fails).
var redactedAllowed = map[string]string{}

// testToolsNotEchoed (TestTokenNotEchoed over every admin tool, Task 17b
// ruling 6 and fix round 1): the Hub's stores hold marker secrets — a
// domain token (sent to the domains service), a provider secret, a secret
// setting, a person_secret credential (its password and NT hash), a
// Keycloak client secret, the proxy, gate, invite and LLDAP secrets — and
// every admin tool runs with fixture arguments on real targets (D tools
// confirmed, U tools also accepted; a backup restored over its instance
// and into a new one): no marker is in any result or error, and no result
// shows "[redacted]" outside redactedAllowed — so the tools, not the
// redactor, keep the secrets out.
func testToolsNotEchoed(t *testing.T) {
	secrets := filepath.Join(t.TempDir(), "secrets")
	os.MkdirAll(secrets, 0o700)
	e := newToolEnvWith(t, mcpEnvOpts{
		extra: map[string][2]string{"smbfixture": settingsFixture(t, "smbfixture"), "talk": {chatManifest, chatCompose}},
		cfg:   func(c *hub.Config) { c.SecretsDir = secrets },
	})
	withDomains(t, e)
	const (
		dnsMarker      = "dns-TOOLMARKER-0123456789abcdef"
		providerMarker = "sk-TOOLMARKER-provider-0123"
		settingMarker  = "TOOLMARKER-setting-0123456"
	)
	for _, g := range []string{"users_secretapp", "admin_secretapp", "admin_smbfixture", "users_talk"} {
		e.ll.AddGroup(g)
	}
	e.ll.AddGroup("users_smbfixture", "alice", "bob")
	v := settingMarker
	if _, err := e.s.Hub.SaveSettings("secretapp", hub.SettingsUpdate{Secrets: map[string]hub.SecretChange{"api_key": {Value: &v}}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Hub.AddModelProvider(ollamaModel(), directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Hub.SetProviderSecret("ollama", "key", []byte(providerMarker), directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	mustDo(t, e.hub, "root", "POST", "/api/domains", enrollBody("team-c.example.net", dnsMarker), 202)
	mustDo(t, e.hub, "root", "POST", "/api/domains/team-c.example.net/token", `{"provider":"cloudflare","credentials":{"api_token":"`+dnsMarker+`"}}`, 202)
	// A person_secret credential: its password (shown once to alice) and its NT hash.
	if err := e.s.Hub.Enable("smbfixture"); err != nil {
		t.Fatal(err)
	}
	cred, err := e.s.Hub.CreateCredential(context.Background(), "smbfixture", "share_password", "alice",
		freshauth.Proof{Code: "good-code", CodeVerifier: strings.Repeat("v", 43), Nonce: "n0nce"})
	if err != nil {
		t.Fatal(err)
	}
	password := string(cred.Password)
	hash, err := os.ReadFile(filepath.Join(secrets, "smbfixture", "share_password", "alice.nt"))
	if err != nil || len(strings.TrimSpace(string(hash))) != 32 {
		t.Fatalf("hash file %q %v", hash, err)
	}
	// A Keycloak client secret (generated into the instance's env).
	if _, err := e.s.Hub.CreateInstanceAs("talk", "talk-a", nil, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Hub.Enable("talk-a"); err != nil {
		t.Fatal(err)
	}
	clientSecret := readEnvValue(t, filepath.Join(e.data, "env", "talk-a.env"), "CHAT_SECRET")
	if len(clientSecret) < 16 {
		t.Fatalf("talk-a's client secret %q", clientSecret)
	}
	h := strings.TrimSpace(string(hash))
	markers := []string{dnsMarker, providerMarker, settingMarker, password, h, strings.ToLower(h), clientSecret,
		testSecret, testMCPSecret, strings.Repeat("s", 40), "svc-password-0123456789"}
	covered := map[string]bool{}
	byName := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		byName[tl.Name] = tl
	}
	check := func(tool, txt string) {
		t.Helper()
		for _, m := range markers {
			if strings.Contains(txt, m) {
				t.Errorf("%s: the result holds a secret (%.6s…): %s", tool, m, txt)
			}
		}
		if strings.Contains(txt, "[redacted]") && redactedAllowed[tool] == "" {
			t.Errorf("%s: the redactor had to blank something: %s", tool, txt)
		}
	}
	archive := ""
	ok := map[string]bool{}
	for _, f := range adminToolFixtures {
		covered[f.tool] = true
		args := map[string]any{}
		for k, v := range f.args {
			if v == archivePH {
				v = archive
			}
			args[k] = v
		}
		txt, isErr, _ := e.tool(t, f.tool, args)
		check(f.tool, txt)
		ok[f.tool] = !isErr
		if byName[f.tool].Class == ClassSecret {
			txt, isErr := e.accept(t, f.tool, args)
			check(f.tool+" (accepted)", txt)
			ok[f.tool] = !isErr
		}
		switch f.tool {
		case "backup_instance", "restore_instance":
			waitIdle(t, e.s.Hub, "secretapp")
			list, err := e.s.Hub.ListBackups("secretapp")
			if err != nil || len(list) == 0 {
				t.Fatalf("backups %v %v", list, err)
			}
			if archive == "" {
				archive = list[0].Archive
			}
		case "restore_as", "delete_instance":
			waitIdle(t, e.s.Hub, "secretapp-b")
		}
	}
	for n := range byName {
		if !covered[n] {
			t.Errorf("admin tool %s has no fixture in adminToolFixtures", n)
		}
	}
	// The success paths ran (fix round 1: real targets).
	for _, n := range []string{"create_instance", "set_hosts", "backup_instance", "restore_instance", "restore_as", "delete_instance",
		"list_credentials", "admin_revoke_credential", "delete_domain", "enroll_domain", "replace_domain_token", "get_env", "get_instance",
		"set_model_provider_secret", "delete_model_provider", "get_op", "wait_for_op", "get_logs", "disable_instance"} {
		if !ok[n] {
			t.Errorf("%s didn't succeed: the fixture misses its success path", n)
		}
	}
	for _, id := range []string{"secretapp", "secretapp-b"} {
		if r := e.s.Hub.LastOp(id); r == nil || !r.OK {
			t.Errorf("%s's last op = %+v", id, r)
		}
	}
}

// keeperManifest: a native-oidc template whose Keycloak client secret
// lives in an innocuously named variable (no generate entry).
const keeperManifest = `name: Keeper
category: misc
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_keeper
keycloak_clients:
  - client_id: keeper
    secret_env: OIDC_CLIENT_VALUE
    redirect_uri: https://{{HOST_KEEPER}}/cb
`

const keeperCompose = "services:\n  web:\n    image: x\n    environment:\n      V: ${OIDC_CLIENT_VALUE}\n    labels:\n" +
	"      traefik.http.routers.keeper.rule: Host(`${PORTCULLIS_HOST_KEEPER:-keeper.portcullis.local}`)\n"

// TestClientSecretEnvAlwaysSecret (fix round 1, security review): a
// Keycloak client's secret_env, a secret option's env name and a
// generated entry are secrets whatever their name — get_env masks them,
// save_env refuses them on the tool path (even "[set]", which would be
// written literally), and the redaction set holds the value.
func TestClientSecretEnvAlwaysSecret(t *testing.T) {
	e := newToolEnv(t, map[string][2]string{"keeper": {keeperManifest, keeperCompose}}, nil)
	e.ll.AddGroup("users_keeper")
	if err := e.s.Hub.Enable("keeper"); err != nil {
		t.Fatal(err)
	}
	const val = "client-VALUE-0123456789"
	if err := e.s.Hub.SaveEnv("keeper", map[string]string{"OIDC_CLIENT_VALUE": val}); err != nil {
		t.Fatal(err)
	}
	txt, isErr, _ := e.tool(t, "get_env", map[string]any{"id": "keeper"})
	if isErr || !strings.Contains(txt, `"OIDC_CLIENT_VALUE":"[secret]"`) || strings.Contains(txt, val) {
		t.Errorf("get_env = %q %v", txt, isErr)
	}
	for _, v := range []string{"other-value-1", "[set]", "[secret]"} {
		txt, isErr, _ := e.tool(t, "save_env", map[string]any{"id": "keeper", "variables": map[string]string{"OIDC_CLIENT_VALUE": v}})
		if !isErr || !strings.HasPrefix(txt, "400: ") {
			t.Errorf("save_env %q = %q %v", v, txt, isErr)
		}
	}
	if got := readEnvValue(t, filepath.Join(e.data, "env", "keeper.env"), "OIDC_CLIENT_VALUE"); got != val {
		t.Errorf("the env changed: %q", got)
	}
	// The secret option's [set] is still taken back as unchanged.
	e.ll.AddGroup("users_secretapp")
	e.ll.AddGroup("admin_secretapp")
	sv := "s3cret-value-1"
	if _, err := e.s.Hub.SaveSettings("secretapp", hub.SettingsUpdate{Secrets: map[string]hub.SecretChange{"api_key": {Value: &sv}}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Hub.Enable("secretapp"); err != nil {
		t.Fatal(err)
	}
	if txt, isErr, _ := e.tool(t, "save_env", map[string]any{"id": "secretapp", "variables": map[string]string{"HEADSCALE_API_KEY": "[set]"}}); isErr {
		t.Errorf("secret option [set] = %q", txt)
	}
	// In the redaction set: a result quoting it is redacted.
	redact, err := e.s.toolRedactor()
	if err != nil || strings.Contains(redact("x "+val+" y"), val) {
		t.Errorf("redactor %v", err)
	}
	for _, n := range []string{"OIDC_CLIENT_VALUE"} {
		if !hub.SecretEnvNames(e.s.Hub.Template("keeper"))[n] {
			t.Errorf("%s isn't a secret env name", n)
		}
	}
	if sn := hub.SecretEnvNames(e.s.Hub.Template("secretapp")); !sn["HEADSCALE_API_KEY"] {
		t.Errorf("secretapp's secret option isn't listed: %v", sn)
	}
	if sn := hub.SecretEnvNames(e.s.Hub.Template("aiapp")); !sn["HDR_SECRET"] {
		t.Errorf("aiapp's generated entry isn't listed: %v", sn)
	}
}

// TestRedactionKeyFollowsSecretEnvNames (fix round 1, security review):
// the cached tool redaction set is rebuilt when a template change makes a
// variable secret (a new client secret_env): the next result redacts its
// value.
func TestRedactionKeyFollowsSecretEnvNames(t *testing.T) {
	plain := strings.Replace(keeperManifest, "    secret_env: OIDC_CLIENT_VALUE\n", "", 1)
	e := newToolEnv(t, map[string][2]string{"keeper": {plain, keeperCompose}}, nil)
	const val = "client-VALUE-0123456789"
	if err := e.s.Hub.SaveEnv("keeper", map[string]string{"OIDC_CLIENT_VALUE": val}); err != nil {
		t.Fatal(err)
	}
	redact, err := e.s.toolRedactor()
	if err != nil || !strings.Contains(redact(val), val) {
		t.Fatalf("before: a plain variable is redacted (%v)", err)
	}
	// The template update: its client now keeps its secret there.
	src := filepath.Join(filepath.Dir(e.data), "src", "keeper", "manifest.yaml")
	if err := os.WriteFile(src, []byte(keeperManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	e.s.Hub.Discover()
	if !hub.SecretEnvNames(e.s.Hub.Template("keeper"))["OIDC_CLIENT_VALUE"] {
		t.Fatal("the template change wasn't discovered")
	}
	redact, err = e.s.toolRedactor()
	if err != nil || strings.Contains(redact("x "+val+" y"), val) {
		t.Errorf("after: the new client secret isn't redacted (%v)", err)
	}
	if txt, _, _ := e.tool(t, "list_instances", nil); strings.Contains(txt, val) {
		t.Errorf("a result holds it: %s", txt)
	}
}
