package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
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
		{"save_model_provider", ollamaArgs(map[string]any{"label": "Ollama 2"}), false},
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
		if got := confirmTextRe.MatchString(txt); got != c.confirm {
			t.Errorf("%s %v: confirmation %v, want %v (%s)", c.tool, c.args, got, c.confirm, txt)
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
	if urlHasCredentials("git@github.com:porelli/x.git") || urlHasCredentials("https://example.org/x.git") ||
		!urlHasCredentials("https://example.org/x.git?token=1") {
		t.Error("urlHasCredentials")
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
	// get_template leaves secret defaults out; an unknown template is 404.
	if txt, isErr, _ := e.tool(t, "get_template", map[string]any{"id": "nope"}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("unknown template = %q %v", txt, isErr)
	}
	// preview_default_policy at mTLS lists aiapp's switch-off (G43).
	if txt, _, _ := e.tool(t, "preview_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"mtls"}, "op": "any"}}); !strings.Contains(txt, "aiapp") {
		t.Errorf("preview = %s", txt)
	}
}

// adminToolFixtures are fixture arguments for every admin tool
// (TestTokenNotEchoed runs each once, in this order).
var adminToolFixtures = []struct {
	tool string
	args map[string]any
}{
	{"hub_status", map[string]any{"include_doctor": true}},
	{"explain_policy", map[string]any{"id": "secretapp"}},
	{"list_instances", nil},
	{"get_instance", map[string]any{"id": "secretapp"}},
	{"instance_defaults", map[string]any{"template": "grafana", "id": "grafana-z"}},
	{"create_instance", map[string]any{"template": "nope", "id": "nope-a"}},
	{"enable_instance", map[string]any{"id": "secretapp"}},
	{"restart_instance", map[string]any{"id": "secretapp"}},
	{"set_hosts", map[string]any{"id": "nope-a", "hosts": map[string]string{}}},
	{"get_op", map[string]any{"id": "secretapp"}},
	{"wait_for_op", map[string]any{"id": "secretapp"}},
	{"delete_instance", map[string]any{"id": "nope-a"}},
	{"get_settings", map[string]any{"id": "secretapp"}},
	{"preview_settings", map[string]any{"id": "secretapp", "values": map[string]any{"api_url": "https://a.example.org"}}},
	{"save_settings", map[string]any{"id": "secretapp", "values": map[string]any{"api_url": "https://a.example.org"}, "plan_hash": strings.Repeat("0", 64)}},
	{"set_secret_setting", map[string]any{"id": "secretapp", "option": "api_key"}},
	{"set_policy", map[string]any{"id": "secretapp", "policy": map[string]any{"factors": []string{"webauthn"}, "op": "any"}}},
	{"set_sign_in_mode", map[string]any{"id": "nativeapp", "mode": "gateway"}},
	{"set_public_access", map[string]any{"id": "cloud", "access": "off"}},
	{"get_logs", map[string]any{"id": "secretapp"}},
	{"get_status", map[string]any{"id": "secretapp"}},
	{"exec", map[string]any{"id": "secretapp", "service": "server", "command": "env"}},
	{"get_compose", map[string]any{"id": "secretapp"}},
	{"get_env", map[string]any{"id": "secretapp"}},
	{"save_env", map[string]any{"id": "secretapp", "variables": map[string]string{"FOO": "bar"}}},
	{"get_custom_override", map[string]any{"id": "secretapp"}},
	{"save_custom_override", map[string]any{"id": "secretapp", "content": ""}},
	{"list_drift", map[string]any{"recheck": true}},
	{"resolve_drift", map[string]any{"id": "nope-a", "action": "apply"}},
	{"set_person_value", map[string]any{"id": "secretapp", "key": "api_url", "user": "dana", "value": "x"}},
	{"clear_person_value", map[string]any{"id": "secretapp", "key": "api_url", "user": "dana"}},
	{"retry_deliveries", map[string]any{"id": "secretapp"}},
	{"disable_instance", map[string]any{"id": "nope-a"}},
	{"missing_groups", nil},
	{"create_missing_groups", map[string]any{"ids": []string{"secretapp"}}},
	{"list_credentials", map[string]any{"id": "secretapp"}},
	{"admin_revoke_credential", map[string]any{"id": "secretapp", "key": "api_key", "user": "dana"}},
	{"get_local_networks", nil},
	{"set_local_networks", map[string]any{"use_defaults": true}},
	{"list_templates", nil},
	{"get_template", map[string]any{"id": "secretapp"}},
	{"list_sources", nil},
	{"sync_sources", nil},
	{"add_source", map[string]any{"name": "more", "url": "https://bot:pw@example.org/more.git"}},
	{"remove_source", map[string]any{"name": "nosuch"}},
	{"list_backups", map[string]any{"id": "secretapp"}},
	{"list_backups_all", nil},
	{"backup_instance", map[string]any{"id": "secretapp"}},
	{"restore_instance", map[string]any{"id": "secretapp", "archive": "secretapp/20990101T000000Z.tar"}},
	{"restore_as", map[string]any{"archive": "secretapp/20990101T000000Z.tar", "id": "notes-b"}},
	{"list_domains", nil},
	{"enroll_domain", map[string]any{"name": "team-c.example.net"}},
	{"replace_domain_token", map[string]any{"name": "team-c.example.net"}},
	{"delete_domain", map[string]any{"name": "nosuch.example.net"}},
	{"ai_status", map[string]any{"id": "aiapp"}},
	{"set_ai_mode", map[string]any{"id": "aiapp", "companion": "tok", "mode": "read_only"}},
	{"set_ai_support", map[string]any{"id": "aiapp", "companion": "tok", "enabled": true}},
	{"revoke_ai_access", map[string]any{"id": "aiapp", "companion": "tok"}},
	{"ai_activity", nil},
	{"list_model_providers", nil},
	{"add_model_provider", map[string]any{"name": "other", "label": "Other", "kind": "anthropic"}},
	{"save_model_provider", map[string]any{"name": "ollama", "label": "Ollama 2", "kind": "openai_compatible", "base_url": "http://gpu.lan:11434/v1"}},
	{"set_model_provider_secret", map[string]any{"name": "ollama", "field": "key"}},
	{"delete_model_provider", map[string]any{"name": "nosuch"}},
	{"get_hub_settings", nil},
	{"save_hub_settings", map[string]any{"limits": map[string]any{"resource_rpm": 100}}},
	{"set_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"webauthn", "mtls"}, "op": "any"}}},
	{"preview_default_policy", map[string]any{"policy": map[string]any{"factors": []string{"mtls"}, "op": "any"}}},
	{"user_sweep_status", nil},
	{"resume_user_sweep", nil},
	{"remove_stale_keycloak_user", map[string]any{"username": "ghost"}},
}

// testToolsNotEchoed (TestTokenNotEchoed over every admin tool, Task 17b
// ruling 6): the Hub's stores hold marker secrets — a domain token (sent
// to the domains service), a provider secret, a secret setting, the
// proxy, gate and invite secrets — and every admin tool runs once with
// fixture arguments (D tools confirmed, U tools also accepted): no marker
// is in any result or error.
func testToolsNotEchoed(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	withDomains(t, e)
	const (
		dnsMarker      = "dns-TOOLMARKER-0123456789abcdef"
		providerMarker = "sk-TOOLMARKER-provider-0123"
		settingMarker  = "TOOLMARKER-setting-0123456"
	)
	e.ll.AddGroup("users_secretapp")
	e.ll.AddGroup("admin_secretapp")
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
	markers := []string{dnsMarker, providerMarker, settingMarker, testSecret, testMCPSecret, strings.Repeat("s", 40), "svc-password-0123456789"}
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
	}
	for _, f := range adminToolFixtures {
		covered[f.tool] = true
		args := f.args
		if args == nil {
			args = map[string]any{}
		}
		txt, _, _ := e.tool(t, f.tool, args)
		check(f.tool, txt)
		if byName[f.tool].Class == ClassSecret {
			txt, _ := e.accept(t, f.tool, args)
			check(f.tool+" (accepted)", txt)
		}
		if f.tool == "backup_instance" {
			waitIdle(t, e.s.Hub, "secretapp")
		}
	}
	for n := range byName {
		if !covered[n] {
			t.Errorf("admin tool %s has no fixture in adminToolFixtures", n)
		}
	}
}
