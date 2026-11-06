package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// aiFixture reads testdata/ai/<name> (manifest, compose).
func aiFixture(t *testing.T, name string) (string, string) {
	t.Helper()
	m, err := os.ReadFile(filepath.Join("testdata", "ai", name, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join("testdata", "ai", name, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(m), string(c)
}

// aiEdit replaces old (which must occur) with new in s.
func aiEdit(t *testing.T, s, old, new string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("fixture has no %q", old)
	}
	return strings.Replace(s, old, new, 1)
}

// aiRow is one refusal: fixture, edits of the manifest and the compose
// file (old, new pairs), and a substring of the error.
type aiRow struct {
	name     string
	fixture  string
	manifest []string
	compose  []string
	want     string
}

func buildAI(t *testing.T, fixture string, medits, cedits []string) (Template, error) {
	t.Helper()
	m, c := aiFixture(t, fixture)
	for i := 0; i+1 < len(medits); i += 2 {
		m = aiEdit(t, m, medits[i], medits[i+1])
	}
	for i := 0; i+1 < len(cedits); i += 2 {
		c = aiEdit(t, c, cedits[i], cedits[i+1])
	}
	return build(fixture, "src", "", []byte(m), []byte(c), "example.org", nil)
}

func runAIRows(t *testing.T, rows []aiRow) {
	t.Helper()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := buildAI(t, r.fixture, r.manifest, r.compose)
			if err == nil || !strings.Contains(err.Error(), r.want) {
				t.Errorf("err = %v, want one containing %q", err, r.want)
			}
		})
	}
}

func TestAIFixturesLoad(t *testing.T) {
	for _, f := range []string{"companion", "headers", "oauth", "chat", "unsupported", "trust"} {
		tpl, err := buildAI(t, f, nil, nil)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if tpl.Manifest.AI == nil {
			t.Errorf("%s: no ai block", f)
		}
	}
	tpl, _ := buildAI(t, "companion", nil, nil)
	c := tpl.Manifest.AI.MCP[0]
	if c.EffectivePublicPath() != "/mcp" || c.EffectivePath() != "/mcp" || !c.Aggregated() {
		t.Errorf("companion defaults: public %q path %q aggregated %v", c.EffectivePublicPath(), c.EffectivePath(), c.Aggregated())
	}
	if tpl.InstanceEnv[VarAIEnabled] != "false" || tpl.InstanceEnv["PORTCULLIS_AI_READONLY_APP"] != "true" {
		t.Errorf("instance env %v: want the fail-closed AI defaults", tpl.InstanceEnv)
	}
	o, _ := buildAI(t, "oauth", nil, nil)
	if oc := o.Manifest.AI.MCP[0]; oc.Aggregated() || oc.EffectivePublicPath() != "/mcp" {
		t.Errorf("app_oauth: aggregated %v, endpoint path %q", oc.Aggregated(), oc.EffectivePublicPath())
	}
	h, _ := buildAI(t, "headers", nil, nil)
	if hc := h.Manifest.AI.MCP[0]; hc.Aggregated() || hc.EffectivePath() != "/api/mcp" {
		t.Errorf("headers: aggregated %v path %q", hc.Aggregated(), hc.EffectivePath())
	}
	u, _ := buildAI(t, "unsupported", nil, nil)
	if _, ok := u.InstanceEnv[VarAIEnabled]; ok {
		t.Error("an unsupported template gets PORTCULLIS_AI_ENABLED")
	}
	if got := ReadOnlyVar("my-app"); got != "PORTCULLIS_AI_READONLY_MY_APP" {
		t.Errorf("ReadOnlyVar = %s", got)
	}
}

func TestAIRequired(t *testing.T) {
	long := strings.Repeat("x", 201)
	unsup := `  unsupported: "No official MCP server; community servers are small and not vetted by Portcullis"`
	runAIRows(t, []aiRow{
		{"no block", "unsupported", []string{"ai:\n" + unsup + "\n", "", "  alternative:", "x-alt:"}, nil, "ai: required (ai.mcp or ai.unsupported)"},
		{"neither", "unsupported", []string{unsup + "\n", ""}, nil, "ai: required (ai.mcp or ai.unsupported)"},
		{"both", "companion", []string{"ai:\n", "ai:\n  unsupported: no\n"}, nil, "not both"},
		{"empty unsupported", "unsupported", []string{unsup, `  unsupported: ""`}, nil, "ai.unsupported"},
		{"201 chars", "unsupported", []string{unsup, "  unsupported: " + long}, nil, "ai.unsupported"},
		{"two lines", "unsupported", []string{unsup, `  unsupported: "a\nb"`}, nil, "ai.unsupported"},
		{"control char", "unsupported", []string{unsup, `  unsupported: "No MCP\x07 server"`}, nil, "ai.unsupported"},
		{"line separator", "unsupported", []string{unsup, `  unsupported: "No MCP\u2028server"`}, nil, "ai.unsupported"},
		{"empty mcp", "companion", []string{"ai:\n  mcp:\n", "ai:\n  mcp: []\nx-old:\n"}, nil, "ai.mcp"},
		{"unknown key", "unsupported", []string{"ai:\n", "ai:\n  bogus: 1\n"}, nil, "bogus"},
	})
	if _, err := buildAI(t, "unsupported", []string{unsup, "  unsupported: " + strings.Repeat("é", 200)}, nil); err != nil {
		t.Errorf("200 runes refused: %v", err)
	}
}

func TestAIAlternativeRules(t *testing.T) {
	runAIRows(t, []aiRow{
		{"alternative with mcp", "companion", []string{"ai:\n", "ai:\n  alternative: {name: x, source: \"https://example.org\", note: y}\n"}, nil, "ai.alternative"},
		{"alternative without source", "unsupported", []string{`source: "https://example.org/plain-mcp", `, ""}, nil, "ai.alternative.source"},
		{"alternative http source", "unsupported", []string{`"https://example.org/plain-mcp"`, `"http://example.org/plain-mcp"`}, nil, "ai.alternative.source"},
		{"alternative long name", "unsupported", []string{"name: plain-mcp", "name: " + strings.Repeat("n", 65)}, nil, "ai.alternative.name"},
		{"on_change with unsupported", "unsupported", []string{"ai:\n", "ai:\n  on_change: x\n"}, nil, "ai.on_change"},
		{"chat with mcp", "companion", []string{"ai:\n", "ai:\n  chat: {provider_kinds: {openai: one}, file: {service: app, mount: /x}, env: {service: app}}\n"}, nil, "ai.chat"},
	})
}

func TestCompanionRules(t *testing.T) {
	const comp = "companion"
	runAIRows(t, []aiRow{
		{"source missing", comp, []string{"      source: https://example.org/app-mcp\n", ""}, nil, "source"},
		{"source http", comp, []string{"https://example.org/app-mcp", "http://example.org/app-mcp"}, nil, "source"},
		{"name Gitea", comp, []string{"- name: app\n", "- name: Gitea\n"}, nil, "name"},
		{"name --", comp, []string{"- name: app\n", "- name: a--b\n"}, nil, "name"},
		{"name 32 chars", comp, []string{"- name: app\n", "- name: " + strings.Repeat("a", 32) + "\n"}, nil, "name"},
		{"duplicate name", "headers", []string{"  mcp:\n", "  mcp:\n    - {name: wiki, label: W, kind: builtin, service: web, port: 1, router: wiki, public_path: /other, upstream: official, source: \"https://example.org\", protocol: [\"2025-06-18\"], modes: [read_only], aggregate: false, identity: {mode: identity_headers, caller_secret: {env: MCP_SECRET}}}\n"}, nil, "twice"},
		{"label empty", comp, []string{"label: App", "label: \"\""}, nil, "label"},
		{"bad kind", comp, []string{"kind: companion", "kind: sidecar"}, nil, "kind"},
		{"service not in compose", comp, []string{"service: app-mcp", "service: nope"}, nil, "service nope"},
		{"service shape", comp, []string{"service: app-mcp", "service: app_mcp"}, []string{"  app-mcp:\n", "  app_mcp:\n"}, "service"},
		{"companion service twice", comp, []string{"  mcp:\n", "  mcp:\n    - {name: other, label: O, kind: companion, service: app-mcp, port: 8080, router: app, public_path: /other, upstream: official, source: \"https://example.org\", protocol: [\"2025-06-18\"], modes: [read_write], identity: {mode: app_token, format: \"Bearer {credential}\", mint: mcp-mint, revoke: mcp-revoke}}\n"}, nil, "app-mcp"},
		{"companion with traefik label", comp, nil, []string{"    image: app-mcp\n", "    image: app-mcp\n    labels:\n      traefik.enable: \"false\"\n"}, "traefik"},
		{"companion on portcullis-proxy", comp, nil, []string{"    networks: [default]\n", "    networks: [default, portcullis-proxy]\n"}, "portcullis-proxy"},
		{"companion with container_name", comp, nil, []string{"    image: app-mcp\n", "    image: app-mcp\n    container_name: mcpbox\n"}, "container_name"},
		{"companion with network_mode", comp, nil, []string{"    networks: [default]\n", "    network_mode: none\n"}, "network_mode"},
		{"port 0", comp, []string{"port: 8080", "port: 0"}, nil, "port"},
		{"path relative", comp, []string{"      router: app\n", "      router: app\n      path: mcp\n"}, nil, "path"},
		{"path query", comp, []string{"      router: app\n", "      router: app\n      path: /mcp?x\n"}, nil, "path"},
		{"router not a host router", comp, []string{"router: app", "router: nope"}, nil, "router"},
		{"public_path /", comp, []string{"      router: app\n", "      router: app\n      public_path: /\n"}, nil, "public_path"},
		{"public_path well-known", comp, []string{"      router: app\n", "      router: app\n      public_path: /.well-known/x\n"}, nil, "public_path"},
		{"public_path oauth2", comp, []string{"      router: app\n", "      router: app\n      public_path: /oauth2/x\n"}, nil, "public_path"},
		{"public_path unclean", comp, []string{"      router: app\n", "      router: app\n      public_path: /a/../mcp\n"}, nil, "public_path"},
		{"public_path under public access", comp, []string{
			"  access_group: users_companion\n", "  access_group: users_companion\n  public_access:\n    enabled_by_default: true\n    paths:\n      - {prefix: /s, description: Shares}\n",
			"      router: app\n", "      router: app\n      public_path: /s/mcp\n"}, nil, "public_access"},
		{"nested public_path", comp, []string{"  mcp:\n", "  mcp:\n    - {name: other, label: O, kind: builtin, service: app, port: 3000, router: app, public_path: /mcp/other, upstream: official, source: \"https://example.org\", protocol: [\"2025-06-18\"], modes: [read_write], identity: {mode: app_token, format: \"Bearer {credential}\", mint: mcp-mint, revoke: mcp-revoke}}\n"}, nil, "overlaps"},
		{"app_oauth path vs public_path", "oauth", []string{"  mcp:\n", "  mcp:\n    - {name: tok, label: T, kind: builtin, service: web, port: 8080, router: oauth, public_path: /mcp, upstream: official, source: \"https://example.org\", protocol: [\"2025-06-18\"], modes: [read_write], identity: {mode: app_token, format: \"Bearer {credential}\", mint: revoke-all, revoke: toggle}}\n", "  on_change: toggle\n", ""}, nil, "overlaps"},
		{"service in the companion's namespace", comp, nil, []string{"  app-mcp:\n", "  side:\n    image: side\n    network_mode: service:app-mcp\n  app-mcp:\n"}, "ai.mcp[app]: service side uses network_mode service:app-mcp"},
		{"companion publishes ports", comp, nil, []string{"    image: app-mcp\n", "    image: app-mcp\n    ports: [\"8080:8080\"]\n"}, "app-mcp may not publish ports"},
		{"on_change hook not ai", "oauth", []string{"{name: toggle, service: web, command: [/toggle], when: [ai]}", "{name: toggle, service: web, command: [/toggle], when: [settings_change]}"}, nil, "ai.on_change: hook toggle must have exactly when: [ai]"},
		{"same public_path twice", comp, []string{"  mcp:\n", "  mcp:\n    - {name: other, label: O, kind: builtin, service: app, port: 3000, router: app, upstream: official, source: \"https://example.org\", protocol: [\"2025-06-18\"], modes: [read_write], identity: {mode: app_token, format: \"Bearer {credential}\", mint: mcp-mint, revoke: mcp-revoke}}\n"}, nil, "public_path"},
		{"mint hook missing", comp, []string{"mint: mcp-mint", "mint: nope"}, nil, "hook nope"},
		{"mint hook not ai", comp, []string{"mint: mcp-mint", "mint: apply"}, nil, "when: [ai]"},
		{"hook ai plus another", comp, []string{"command: [/mint], when: [ai]", "command: [/mint], when: [ai, start]"}, nil, "ai"},
		{"ai hook nobody names", comp, []string{"  - {name: apply,", "  - {name: stray, service: app, command: [/s], when: [ai]}\n  - {name: apply,"}, nil, "stray"},
		{"app_oauth companion kind", "oauth", []string{"kind: builtin", "kind: companion"}, nil, "app_oauth"},
		{"app_oauth without revoke", "oauth", []string{"identity: {mode: app_oauth, revoke: revoke-all}", "identity: {mode: app_oauth}"}, nil, "revoke"},
		{"app_oauth read_only", "oauth", []string{"modes: [read_write]", "modes: [read_only, read_write]\n      default_mode: read_write"}, nil, "modes"},
		{"app_oauth aggregate", "oauth", []string{"modes: [read_write]", "modes: [read_write]\n      aggregate: true"}, nil, "aggregate"},
		{"app_oauth public_path", "oauth", []string{"      path: /mcp\n", "      path: /mcp\n      public_path: /x\n"}, nil, "public_path"},
		{"app_oauth extra key", "oauth", []string{"identity: {mode: app_oauth, revoke: revoke-all}", "identity: {mode: app_oauth, revoke: revoke-all, format: \"Bearer {credential}\"}"}, nil, "format"},
		{"identity_headers without caller_secret", "headers", []string{"        caller_secret: {env: MCP_SECRET, header: X-Mcp-Secret, format: \"{secret}\"}\n", ""}, nil, "caller_secret"},
		{"caller_secret env not random", "headers", []string{"env: MCP_SECRET,", "env: PLAIN,"}, nil, "generate: random"},
		{"caller_secret env undeclared", "headers", []string{"env: MCP_SECRET,", "env: NOPE,"}, nil, "generate: random"},
		{"caller_secret format", "headers", []string{`format: "{secret}"`, `format: "{secret} {secret}"`}, nil, "format"},
		{"caller_secret header Cookie", "headers", []string{"header: X-Mcp-Secret", "header: Cookie"}, nil, "header"},
		{"caller_secret header Content-Length", "headers", []string{"header: X-Mcp-Secret", "header: content-length"}, nil, "header"},
		{"caller_secret header Transfer-Encoding", "headers", []string{"header: X-Mcp-Secret", "header: Transfer-Encoding"}, nil, "header"},
		{"caller_secret header Connection", "headers", []string{"header: X-Mcp-Secret", "header: CONNECTION"}, nil, "header"},
		{"caller_secret header TE", "headers", []string{"header: X-Mcp-Secret", "header: te"}, nil, "header"},
		{"caller_secret header Upgrade", "headers", []string{"header: X-Mcp-Secret", "header: Upgrade"}, nil, "header"},
		{"caller_secret header Keep-Alive", "headers", []string{"header: X-Mcp-Secret", "header: Keep-Alive"}, nil, "header"},
		{"caller_secret header Trailer", "headers", []string{"header: X-Mcp-Secret", "header: Trailer"}, nil, "header"},
		{"caller_secret header Proxy-Connection", "headers", []string{"header: X-Mcp-Secret", "header: proxy-connection"}, nil, "header"},
		{"app_token header Upgrade", comp, []string{`format: "token {credential}"`, "header: Upgrade\n        format: \"token {credential}\""}, nil, "header"},
		{"caller_secret header X-Forwarded", "headers", []string{"header: X-Mcp-Secret", "header: x-forwarded-user"}, nil, "header"},
		{"app_token without mint", comp, []string{"        mint: mcp-mint\n", ""}, nil, "mint"},
		{"app_token without revoke", comp, []string{"        revoke: mcp-revoke\n", ""}, nil, "revoke"},
		{"app_token bad format", comp, []string{`format: "token {credential}"`, `format: "{credential}"`}, nil, "format"},
		{"app_token format and basic", comp, []string{`format: "token {credential}"`, "format: \"token {credential}\"\n        basic: {user: \"{username}\", password: \"{credential}\"}"}, nil, "basic"},
		{"app_token basic password", comp, []string{`format: "token {credential}"`, "basic: {user: \"{username}\", password: \"x\"}"}, nil, "basic"},
		{"app_token basic user colon", comp, []string{`format: "token {credential}"`, "basic: {user: \"a:b\", password: \"{credential}\"}"}, nil, "basic"},
		{"app_token caller_secret", comp, []string{"        mint: mcp-mint\n", "        mint: mcp-mint\n        caller_secret: {env: X}\n"}, nil, "caller_secret"},
		{"scopes key not a mode", comp, []string{"modes: [read_only, read_write]\n      default_mode: read_write", "modes: [read_write]"}, nil, "scopes"},
		{"bad identity mode", comp, []string{"mode: app_token", "mode: shared_admin"}, nil, "identity.mode"},
		{"modes empty", comp, []string{"modes: [read_only, read_write]\n      default_mode: read_write", "modes: []"}, nil, "modes"},
		{"modes repeat", comp, []string{"modes: [read_only, read_write]", "modes: [read_write, read_write]"}, nil, "modes"},
		{"modes unknown", comp, []string{"modes: [read_only, read_write]", "modes: [read_only, admin]"}, nil, "modes"},
		{"default_mode not in modes", comp, []string{"modes: [read_only, read_write]\n      default_mode: read_write", "modes: [read_only]\n      default_mode: read_write"}, nil, "default_mode"},
		{"default_mode missing with two", comp, []string{"      default_mode: read_write\n", ""}, nil, "default_mode"},
		{"community builtin", "headers", []string{"upstream: official", "upstream: community"}, nil, "community"},
		{"upstream missing", comp, []string{"      upstream: official\n", ""}, nil, "upstream"},
		{"protocol empty", comp, []string{`protocol: ["2026-07-28", "2025-11-25"]`, "protocol: []"}, nil, "protocol"},
		{"protocol unknown", comp, []string{`protocol: ["2026-07-28", "2025-11-25"]`, `protocol: ["2024-11-05"]`}, nil, "protocol"},
		{"tool pattern", comp, []string{`writes: ["create_*", "delete_*"]`, `writes: ["create *"]`}, nil, "tools"},
		{"admin_paths", comp, []string{"  access_group: users_companion\n", "  access_group: users_companion\n  admin_group: admin_companion\n  admin_paths: [/admin]\n"}, nil, "admin_paths"},
		{"method public", "headers", []string{"method: header-auth", "method: public"}, nil, "auth.method"},
		{"method mtls", "headers", []string{"method: header-auth", "method: mtls"}, nil, "auth.method"},
		{"readonly var other form", comp, nil, []string{"${PORTCULLIS_AI_READONLY_APP:-true}", "${PORTCULLIS_AI_READONLY_APP:-false}"}, "PORTCULLIS_AI_READONLY_APP"},
		{"readonly var foreign companion", comp, nil, []string{"${PORTCULLIS_AI_READONLY_APP:-true}", "${PORTCULLIS_AI_READONLY_OTHER:-true}"}, "PORTCULLIS_AI_READONLY_OTHER"},
		{"enabled var other form", comp, nil, []string{"${PORTCULLIS_AI_ENABLED:-false}", "$PORTCULLIS_AI_ENABLED"}, "PORTCULLIS_AI_ENABLED"},
		{"enabled var default true", comp, nil, []string{"${PORTCULLIS_AI_ENABLED:-false}", "${PORTCULLIS_AI_ENABLED:-true}"}, "PORTCULLIS_AI_ENABLED"},
		{"other ai var", comp, nil, []string{"${PORTCULLIS_AI_ENABLED:-false}", "${PORTCULLIS_AI_MODE}"}, "PORTCULLIS_AI_MODE"},
		{"enabled var without mcp", "unsupported", nil, []string{"    image: plain\n", "    image: plain\n    environment:\n      AI: ${PORTCULLIS_AI_ENABLED:-false}\n"}, "PORTCULLIS_AI_ENABLED"},
	})
}

func TestChatRules(t *testing.T) {
	const chat = "chat"
	runAIRows(t, []aiRow{
		{"no provider kinds", chat, []string{"provider_kinds: {openai_compatible: many, anthropic: one}", "provider_kinds: {}"}, nil, "provider_kinds"},
		{"unknown provider kind", chat, []string{"anthropic: one", "mistral: one"}, nil, "provider_kinds"},
		{"bad cardinality", chat, []string{"anthropic: one", "anthropic: two"}, nil, "provider_kinds"},
		{"file service missing", chat, []string{"file: {service: api,", "file: {service: nope,"}, nil, "ai.chat.file"},
		{"file mount relative", chat, []string{"mount: /portcullis/ai", "mount: portcullis"}, nil, "ai.chat.file"},
		{"env service missing", chat, []string{"env: {service: api}", "env: {service: nope}"}, nil, "ai.chat.env"},
		{"env missing", chat, []string{"    env: {service: api}\n", ""}, nil, "ai.chat.env"},
		{"chat without ai_client", chat, []string{"    ai_client: true\n", ""}, nil, "ai_client"},
		{"two ai_clients", chat, []string{"    redirect_uri: \"https://{{HOST_CHAT}}/oauth/openid/callback\"\n", "    redirect_uri: \"https://{{HOST_CHAT}}/oauth/openid/callback\"\n    ai_client: true\n"}, nil, "ai_client"},
		{"ai_client without secret", chat, []string{"    secret_env: CHAT_MCP_SECRET\n", ""}, nil, "secret_env"},
		{"provider var reference", chat, nil, []string{"OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "KEY: ${PORTCULLIS_AI_PROVIDER_X_KEY}"}, "PORTCULLIS_AI_PROVIDER_"},
		{"provider var bare", chat, nil, []string{"OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "KEY: $PORTCULLIS_AI_PROVIDER_X_KEY"}, "PORTCULLIS_AI_PROVIDER_"},
		// Fix round 1: a service may not set one either (map key, list item; any case).
		{"provider var map key", chat, nil, []string{"OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      PORTCULLIS_AI_PROVIDER_X_KEY: sk-literal"}, "sets PORTCULLIS_AI_PROVIDER_X_KEY"},
		{"provider var map key lowercase", chat, nil, []string{"OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      portcullis_ai_provider_x_key: sk-literal"}, "PORTCULLIS_AI_PROVIDER_"},
		{"provider var list bare", chat, nil, []string{"      OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "      - OPENID_CLIENT_ID=${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      - PORTCULLIS_AI_PROVIDER_X_KEY"}, "sets PORTCULLIS_AI_PROVIDER_X_KEY"},
		{"provider var list assignment", chat, nil, []string{"      OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "      - OPENID_CLIENT_ID=${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      - Portcullis_AI_Provider_X_KEY=sk-literal"}, "PORTCULLIS_AI_PROVIDER_"},
		// Security review: names built by interpolation, AI names in defaults.
		{"env name interpolated", chat, nil, []string{"OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      PORTCULLIS_AI_${X}: sk-literal"}, "built by interpolation"},
		{"env list name interpolated", chat, nil, []string{"      OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "      - OPENID_CLIENT_ID=${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      - PORTCULLIS_AI_${X}PROVIDER_X_KEY=sk"}, "built by interpolation"},
		{"AI name in a default", chat, nil, []string{"OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      KEY: ${FOO:-PORTCULLIS_AI_PROVIDER_X_KEY}"}, "a default or alternate value"},
		{"AI name in an alternate", chat, nil, []string{"OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}", "OPENID_CLIENT_ID: ${PORTCULLIS_OIDC_CLIENT_ID:-chat}\n      KEY: ${FOO:+portcullis_ai_x}"}, "a default or alternate value"},
		{"ai-providers file", "companion", []string{"hooks:\n", "files:\n  - {name: ai-providers, service: app, mount: /data}\nhooks:\n"}, nil, "ai-providers"},
	})
}

func TestAIClientFlag(t *testing.T) {
	runAIRows(t, []aiRow{
		{"ai_client without chat", "oauth", []string{"    redirect_uri: \"https://{{HOST_OAUTH}}/cb\"\n", "    redirect_uri: \"https://{{HOST_OAUTH}}/cb\"\n    secret_env: X\n    ai_client: true\n"}, nil, "ai_client"},
		{"portcullis-ai- client id", "oauth", []string{"client_id: oauthapp", "client_id: portcullis-ai-claude"}, nil, "portcullis-ai-"},
	})
	tpl, err := buildAI(t, "chat", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := tpl.Manifest.Clients; len(c) != 2 || c[0].AIClient || !c[1].AIClient {
		t.Errorf("clients = %+v: want only chat-mcp as ai_client", c)
	}
}

func TestHookAITrigger(t *testing.T) {
	if !HookTriggers[HookAI] || HookAI != "ai" {
		t.Errorf("HookTriggers lacks ai: %v", HookTriggers)
	}
	tpl, err := buildAI(t, "companion", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ai []string
	for _, h := range tpl.Manifest.Hooks {
		if h.IsAI() {
			ai = append(ai, h.Name)
		}
	}
	if strings.Join(ai, ",") != "mcp-mint,mcp-revoke" {
		t.Errorf("ai hooks = %v", ai)
	}
	all := "start, settings_change, membership_change, credential_change, ai"
	runAIRows(t, []aiRow{
		{"unknown trigger names all five", "companion", []string{"when: [start, settings_change]", "when: [boot]"}, nil, "start, settings_change, membership_change, credential_change or ai"},
		{"empty when names all five", "companion", []string{"when: [start, settings_change]", "when: []"}, nil, all},
		{"option delivers to an ai hook", "companion", []string{"delivery: [{hook: apply}]", "delivery: [{hook: mcp-mint}]"}, nil, "ai hook"},
		{"reload names an ai hook", "companion", []string{"settings:\n", "reload: {hook: mcp-mint}\nsettings:\n"}, nil, "ai hook"},
		{"mint hook on the companion service", "companion", []string{"{name: mcp-mint, service: app,", "{name: mcp-mint, service: app-mcp,"}, nil, "hooks[mcp-mint]: an ai hook may not run on service app-mcp"},
		{"revoke hook on the companion service", "companion", []string{"{name: mcp-revoke, service: app,", "{name: mcp-revoke, service: app-mcp,"}, nil, "hooks[mcp-revoke]: an ai hook may not run on service app-mcp"},
		{"on_change hook on the companion service", "companion", []string{"ai:\n  mcp:", "ai:\n  on_change: ai-toggle\n  mcp:", "hooks:\n", "hooks:\n  - {name: ai-toggle, service: app-mcp, command: [/t], when: [ai]}\n"}, nil, "hooks[ai-toggle]: an ai hook may not run on service app-mcp"},
	})
}

func TestReservedMCPNames(t *testing.T) {
	const comp = "companion"
	runAIRows(t, []aiRow{
		{"router name", comp, nil, []string{"      traefik.http.routers.app.entrypoints: websecure\n", "      traefik.http.routers.app.entrypoints: websecure\n      traefik.http.routers.portcullis-mcp-x.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`) && PathPrefix(`/x`)\n"}, "portcullis-mcp-"},
		{"middleware name", comp, nil, []string{"      traefik.http.routers.app.entrypoints: websecure\n", "      traefik.http.middlewares.Portcullis-MCP-x.headers.customrequestheaders.X: y\n      traefik.http.routers.app.entrypoints: websecure\n"}, "portcullis-mcp-"},
		{"service name", comp, nil, []string{"  app-mcp:\n", "  portcullis-mcp-app-app:\n"}, "portcullis-mcp-"},
		{"container_name", "unsupported", nil, []string{"    image: plain\n", "    image: plain\n    container_name: portcullis-mcp-plain--plain\n"}, "portcullis-mcp-"},
		{"hostname", "unsupported", nil, []string{"    image: plain\n", "    image: plain\n    hostname: portcullis-mcp-x\n"}, "portcullis-mcp-"},
		{"network alias", "unsupported", nil, []string{"    image: plain\n", "    image: plain\n    networks:\n      default:\n        aliases: [portcullis-mcp-plain--x]\n"}, "portcullis-mcp-"},
		{"split by a variable", "unsupported", nil, []string{"    image: plain\n", "    image: plain\n    environment:\n      X: portcullis-mcp${E}-x\n"}, "portcullis-mcp-"},
		{"declares PORTCULLIS_AI_ENABLED", "unsupported", []string{"auth:\n", "env:\n  - key: PORTCULLIS_AI_ENABLED\nauth:\n"}, nil, "PORTCULLIS_AI_ENABLED"},
		{"declares a provider variable", "unsupported", []string{"auth:\n", "env:\n  - key: PORTCULLIS_AI_PROVIDER_X\nauth:\n"}, nil, "PORTCULLIS_AI_PROVIDER_X"},
		{"declares the gate IP", "unsupported", []string{"auth:\n", "ports:\n  - {key: PORTCULLIS_MCP_GATE_IP, container: 1, default: 1, service: web}\nauth:\n"}, nil, "PORTCULLIS_MCP_GATE_IP"},
		{"mcp default subdomain", "unsupported", nil, []string{"plain.portcullis.local", "mcp.portcullis.local"}, "mcp"},
	})
	for _, k := range []string{"PORTCULLIS_AI_ENABLED", "PORTCULLIS_AI_READONLY_GITEA", "PORTCULLIS_AI_PROVIDER_X", "PORTCULLIS_AI_ANYTHING", "PORTCULLIS_MCP_GATE_IP"} {
		if !ReservedVar(k) {
			t.Errorf("%s is not reserved", k)
		}
	}
	// The alias portcullis-mcp-<id>--<companion> is one DNS label (≤ 63).
	m0, c0 := aiFixture(t, "companion")
	m31 := aiEdit(t, m0, "- name: app\n", "- name: "+strings.Repeat("a", 31)+"\n")
	c31 := aiEdit(t, c0, "PORTCULLIS_AI_READONLY_APP", "PORTCULLIS_AI_READONLY_"+strings.Repeat("A", 31))
	if _, err := build(strings.Repeat("b", 15), "src", "", []byte(m31), []byte(c31), "example.org", nil); err != nil {
		t.Errorf("alias of exactly 63: %v", err)
	}
	if _, err := build(strings.Repeat("b", 16), "src", "", []byte(m31), []byte(c31), "example.org", nil); err == nil || !strings.Contains(err.Error(), "63") {
		t.Errorf("alias of 64: err = %v", err)
	}
	// A router-less template has no host for a companion.
	m := "name: S\nauth:\n  method: custom\nai:\n  mcp:\n    - {name: s, label: S, kind: builtin, service: s, port: 1, router: s, upstream: official, source: \"https://example.org\", protocol: [\"2025-06-18\"], modes: [read_write], identity: {mode: app_token, format: \"Bearer {credential}\", mint: m, revoke: r}}\nhooks:\n  - {name: m, service: s, command: [/m], when: [ai]}\n  - {name: r, service: s, command: [/r], when: [ai]}\n"
	if _, err := build("s", "src", "", []byte(m), []byte("services:\n  s:\n    image: x\n"), "example.org", nil); err == nil || !strings.Contains(err.Error(), "router-less") {
		t.Errorf("router-less ai.mcp: err = %v", err)
	}
}

// TestTrustNetwork: an identity_headers companion's trust network
// (contract §3.2) holds exactly the companion and its router's service.
func TestTrustNetwork(t *testing.T) {
	const f = "trust"
	runAIRows(t, []aiRow{
		{"companion on default", f, nil, []string{"    networks: [mcp-trust]\n  db:", "  db:"}, "exactly one network"},
		{"companion on two networks", f, nil, []string{"    networks: [mcp-trust]\n  db:", "    networks: [mcp-trust, default]\n  db:"}, "exactly one network"},
		{"trust network not internal", f, nil, []string{"  mcp-trust:\n    internal: true\n", "  mcp-trust: {}\n"}, "internal: true"},
		{"trust network internal false", f, nil, []string{"    internal: true\n", "    internal: false\n"}, "internal: true"},
		{"a third member", f, nil, []string{"  db:\n    image: db\n", "  db:\n    image: db\n    networks: [default, mcp-trust]\n"}, "service db joins the trust network"},
		{"app not on it", f, nil, []string{"      mcp-trust:\n        aliases: [web-internal]\n", ""}, "must join the trust network"},
		{"sharing the app's namespace", f, nil, []string{"  db:\n    image: db\n", "  db:\n    image: db\n    network_mode: service:web\n"}, "share an address on the trust network"},
	})
	// The -internal alias of the app is allowed on the internal trust network
	// (the fixture loads), never on a plain project network.
	if _, err := buildAI(t, f, nil, []string{"  mcp-trust:\n    internal: true\n", "  mcp-trust: {}\n"}); err == nil || !strings.Contains(err.Error(), "-internal") {
		t.Errorf("an -internal alias on a non-internal network: err = %v", err)
	}
}
