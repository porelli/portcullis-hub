package httpapi

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/templates"
)

// Plan 4 Task 17a: the admin tools of the Portcullis MCP — overview,
// instances, settings, runtime, drift and their G15 tools (contract
// §15.10, spec call 25; G14–G17, G37, G46).

// notesManifest: a multi native-oidc template with one Keycloak client
// (TestDeleteInstanceTool's instance x).
const notesManifest = `name: Notes
category: tools
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_notes
  admin_group: admin_notes
keycloak_clients:
  - client_id: notes
    redirect_uri: https://{{HOST_NOTES}}/auth
urls:
  - label: Web
    url: "https://{{HOST_NOTES}}"
`

const notesCompose = "services:\n  web:\n    image: notes\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.notes.rule: Host(`${PORTCULLIS_HOST_NOTES:-notes.portcullis.local}`)\n" +
	"      traefik.http.services.notes.loadbalancer.server.port: \"80\"\n"

// teamManifest: users and list options (save_settings' allowlist rows).
const teamManifest = `name: Team
category: tools
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_teamapp
settings:
  options:
    - {key: owners, label: Owners, type: users, applies: restart, delivery: [{env: TEAM_OWNERS}]}
    - {key: title, label: Title, type: string, applies: restart, delivery: [{env: TEAM_TITLE}]}
`

const teamCompose = "services:\n  web:\n    image: team\n    environment:\n      OWNERS: ${TEAM_OWNERS}\n      TITLE: ${TEAM_TITLE}\n    labels:\n" +
	"      traefik.http.routers.teamapp.rule: Host(`${PORTCULLIS_HOST_TEAMAPP:-teamapp.portcullis.local}`)\n"

// aiChatFixture is the AI page test template (openai_compatible and
// anthropic providers).
func aiChatFixture(t *testing.T) [2]string {
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
	return [2]string{string(m), string(c)}
}

// ollamaArgs is ollamaBody as tool arguments, with over replacing fields.
func ollamaArgs(over map[string]any) map[string]any {
	var a map[string]any
	json.Unmarshal([]byte(ollamaBody), &a)
	for k, v := range over {
		a[k] = v
	}
	return a
}

// settingsFixture reads a template of the Hub's settings testdata.
func settingsFixture(t *testing.T, id string) [2]string {
	t.Helper()
	dir := filepath.Join("..", "hub", "testdata", "settings", id)
	m, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return [2]string{string(m), string(c)}
}

// toolEnv: the MCP listener with the real admin tools, confirmations
// decidable (newConfirmEnv), the fixtures notes, secretapp, nativeapp and
// cloud besides grafana, home and aiapp.
type toolEnv struct {
	*mcpTestEnv
}

func newToolEnv(t *testing.T, extra map[string][2]string, wrap func(hub.Engine) hub.Engine) *toolEnv {
	t.Helper()
	return newToolEnvWith(t, mcpEnvOpts{extra: extra, wrap: wrap})
}

// newToolEnvWith is newToolEnv with o's extra templates, engine wrapper
// and configuration.
func newToolEnvWith(t *testing.T, o mcpEnvOpts) *toolEnv {
	t.Helper()
	extra := o.extra
	all := map[string][2]string{
		"notes":     {notesManifest, notesCompose},
		"secretapp": settingsFixture(t, "secretapp"),
		"nativeapp": settingsFixture(t, "nativeapp"),
		"cloud":     {cloudManifest, cloudCompose},
		"privapp":   settingsFixture(t, "privapp"),
		"teamapp":   {teamManifest, teamCompose},
		"ai-chat":   aiChatFixture(t),
	}
	for k, v := range extra {
		all[k] = v
	}
	o.extra = all
	ce := newConfirmEnvOpts(t, o)
	// Many confirmations per test (the hourly limit is TestMCPDestructive…'s).
	ce.s.Hub.SetConfirmPerHourForTest(1000)
	return &toolEnv{&mcpTestEnv{confirmEnv: ce, runs: map[string]int{}}}
}

var confirmTextRe = regexp.MustCompile(`open https://hub\.example\.org/confirm/([A-Z2-7-]+), then ask me to try again\.$`)

// tool calls an admin tool as root (2025-11-25: the text forms); a
// confirmation it asks for is approved with its typed check and the call
// retried. → the text, isError, the confirmation id ("" = none asked).
func (e *toolEnv) tool(t *testing.T, name string, args any) (string, bool, string) {
	t.Helper()
	txt, isErr := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", name, args, nil))
	m := confirmTextRe.FindStringSubmatch(txt)
	if m == nil {
		return txt, isErr, ""
	}
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, m[1], "root")
	if err != nil {
		t.Fatalf("%s: confirmation page: %v", name, err)
	}
	e.decide(t, m[1], v.Typed, true)
	txt, isErr = resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", name, args, nil))
	return txt, isErr, v.ID
}

// waitIdle waits until instance id's op record isn't running.
func waitIdle(t *testing.T, h *hub.Hub, id string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if r := h.LastOp(id); r == nil || !r.Running {
			h.Wait()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: op still running", id)
}

// callRec records the Hub calls of the shared route/tool work (callHook).
type callRec struct {
	mu    sync.Mutex
	calls []string
}

func (c *callRec) hook(method string, args ...any) {
	b, _ := json.Marshal(args)
	c.mu.Lock()
	c.calls = append(c.calls, method+" "+string(b))
	c.mu.Unlock()
}

func (c *callRec) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.calls
	c.calls = nil
	return out
}

var archiveTS = regexp.MustCompile(`\d{8}T\d{6}Z`)

// auditKey is an entry as both paths must write it (the confirmation id
// and archive timestamps aside).
func auditKey(a directory.AuditEntry) string {
	d := a.Detail
	if i := strings.LastIndex(d, "confirmation "); i >= 0 {
		d = strings.TrimSuffix(strings.TrimSuffix(d[:i], "; "), " ")
	}
	return strings.Join([]string{a.Action, a.Target, archiveTS.ReplaceAllString(d, "TS"), a.Result, archiveTS.ReplaceAllString(a.Error, "TS")}, "|")
}

// sameAsHTTPCase: one W or D tool and its HTTP twin with the same input.
type sameAsHTTPCase struct {
	tool         string
	args         any
	method, path string
	body         string
	instance     string // an async op (or a background restart) to wait for ("" none)
	plan         bool   // the tool needs preview_settings' plan_hash first
}

// sameAsHTTPPending are the admin W and D tools whose same-as-HTTP case a
// later task adds with the tool: none is registered yet; each task drops
// its names when its tools land (T17b emptied it).
var sameAsHTTPPending = map[string]string{}

// TestAdminToolsSameAsHTTP: every registered admin W and D tool (but
// sameAsHTTPPending's) — and both classes of each per-call one — makes the
// same Hub call with the same arguments as its HTTP twin given the same
// input, on two Hubs in the same state, and writes the same audit
// entries — attributed via ai and the AI client (plus the consumed
// confirmation for D tools) only for the tool.
func TestAdminToolsSameAsHTTP(t *testing.T) {
	httpEnv := newToolEnv(t, nil, nil)
	toolE := newToolEnv(t, nil, nil)
	for _, e := range []*toolEnv{httpEnv, toolE} {
		// Groups exist (enable creates none: the details stay equal); the
		// secret is set (the save below needs it).
		e.ll.AddGroup("users_secretapp")
		e.ll.AddGroup("admin_secretapp")
		v := "s3cret-value-1"
		if _, err := e.s.Hub.SaveSettings("secretapp", hub.SettingsUpdate{Secrets: map[string]hub.SecretChange{"api_key": {Value: &v}}}, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
	}
	hr, tr := &callRec{}, &callRec{}
	httpEnv.s.callHook, toolE.s.callHook = hr.hook, tr.hook
	cases := []sameAsHTTPCase{
		{tool: "create_instance", args: map[string]any{"template": "grafana", "id": "grafana-a"},
			method: "POST", path: "/api/instances", body: `{"template":"grafana","id":"grafana-a"}`},
		{tool: "create_instance", args: map[string]any{"template": "nope", "id": "nope-a"},
			method: "POST", path: "/api/instances", body: `{"template":"nope","id":"nope-a"}`},
		{tool: "set_hosts", args: map[string]any{"id": "grafana-a", "hosts": map[string]string{"grafana": "grafana-b.example.org"}},
			method: "PUT", path: "/api/instances/grafana-a/hosts", body: `{"hosts":{"grafana":"grafana-b.example.org"}}`},
		{tool: "save_settings", args: map[string]any{"id": "secretapp", "values": map[string]any{"api_url": "https://api.example.org"}},
			method: "PUT", path: "/api/instances/secretapp/settings", body: `{"values":{"api_url":"https://api.example.org"}}`, plan: true},
		{tool: "save_settings", args: map[string]any{"id": "secretapp", "ports": map[string]string{}},
			method: "PUT", path: "/api/instances/secretapp/settings", body: `{"ports":{}}`, plan: true},
		{tool: "enable_instance", args: map[string]any{"id": "secretapp"},
			method: "POST", path: "/api/templates/enable", body: `{"id":"secretapp"}`},
		// cloud is public by default: enabling it is D.
		{tool: "enable_instance", args: map[string]any{"id": "cloud"},
			method: "POST", path: "/api/templates/enable", body: `{"id":"cloud"}`},
		{tool: "restart_instance", args: map[string]any{"id": "secretapp"},
			method: "POST", path: "/api/templates/restart/secretapp", body: ``},
		{tool: "set_policy", args: map[string]any{"id": "secretapp", "policy": map[string]any{"factors": []string{"webauthn"}, "op": "any"}},
			method: "PUT", path: "/api/instances/secretapp/settings", body: `{"auth_policy":{"factors":["webauthn"],"op":"any"}}`},
		{tool: "set_policy", args: map[string]any{"id": "secretapp", "policy": map[string]any{"factors": []string{"password"}, "op": "any"}},
			method: "PUT", path: "/api/instances/secretapp/settings", body: `{"auth_policy":{"factors":["password"],"op":"any"}}`},
		{tool: "set_policy", args: map[string]any{"id": "secretapp", "inherit": true},
			method: "PUT", path: "/api/instances/secretapp/settings", body: `{"auth_policy_inherit":true}`},
		{tool: "set_sign_in_mode", args: map[string]any{"id": "nativeapp", "mode": "native"},
			method: "PUT", path: "/api/instances/nativeapp/settings", body: `{"sign_in":"native"}`},
		{tool: "set_sign_in_mode", args: map[string]any{"id": "nativeapp", "mode": "gateway"},
			method: "PUT", path: "/api/instances/nativeapp/settings", body: `{"sign_in":"gateway"}`},
		{tool: "set_public_access", args: map[string]any{"id": "cloud", "access": "off"},
			method: "PUT", path: "/api/instances/cloud/settings", body: `{"public_access":false}`},
		{tool: "set_public_access", args: map[string]any{"id": "cloud", "access": "on"},
			method: "PUT", path: "/api/instances/cloud/settings", body: `{"public_access":true}`},
		{tool: "exec", args: map[string]any{"id": "secretapp", "service": "server", "command": "true"},
			method: "POST", path: "/api/templates/exec/secretapp", body: `{"service":"server","command":"true"}`},
		{tool: "save_env", args: map[string]any{"id": "secretapp", "variables": map[string]string{"FOO": "bar"}},
			method: "PUT", path: "/api/templates/env/secretapp", body: `{"FOO":"bar"}`},
		{tool: "save_custom_override", args: map[string]any{"id": "secretapp", "content": ""},
			method: "PUT", path: "/api/templates/compose/secretapp", body: `{"user_override":""}`},
		{tool: "resolve_drift", args: map[string]any{"id": "secretapp", "action": "apply"},
			method: "POST", path: "/api/drift/resolve", body: `{"id":"secretapp","action":"apply"}`},
		{tool: "retry_deliveries", args: map[string]any{"id": "secretapp"},
			method: "POST", path: "/api/instances/secretapp/settings/retry", body: `{}`},
		{tool: "set_person_value", args: map[string]any{"id": "secretapp", "key": "api_url", "user": "dana", "value": "x"},
			method: "PUT", path: "/api/instances/secretapp/settings/entries/api_url/dana", body: `{"value":"x"}`},
		{tool: "clear_person_value", args: map[string]any{"id": "secretapp", "key": "api_url", "user": "dana"},
			method: "DELETE", path: "/api/instances/secretapp/settings/entries/api_url/dana", body: ``},
		{tool: "create_missing_groups", args: map[string]any{"ids": []string{"secretapp"}},
			method: "POST", path: "/api/instances/missing-groups", body: `{"ids":["secretapp"]}`},
		{tool: "admin_revoke_credential", args: map[string]any{"id": "secretapp", "key": "api_key", "user": "dana"},
			method: "DELETE", path: "/api/instances/secretapp/credentials/api_key/dana", body: ``},
		{tool: "set_local_networks", args: map[string]any{"networks": []string{"10.0.0.0/8"}},
			method: "PUT", path: "/api/settings/local-networks", body: `{"networks":["10.0.0.0/8"]}`},
		{tool: "set_local_networks", args: map[string]any{"networks": []string{"10.0.0.0/8", "203.0.113.0/24"}},
			method: "PUT", path: "/api/settings/local-networks", body: `{"networks":["10.0.0.0/8","203.0.113.0/24"]}`},
		// ── Task 17b ──
		{tool: "sync_sources", args: map[string]any{},
			method: "POST", path: "/api/sources/sync", body: ``},
		{tool: "add_source", args: map[string]any{"name": "Bad Name", "url": "https://example.org/t.git"},
			method: "POST", path: "/api/sources/add", body: `{"name":"Bad Name","url":"https://example.org/t.git"}`},
		{tool: "remove_source", args: map[string]any{"name": "nosuch"},
			method: "POST", path: "/api/sources/remove", body: `{"name":"nosuch"}`},
		{tool: "backup_instance", args: map[string]any{"id": "secretapp"},
			method: "POST", path: "/api/instances/secretapp/backups", body: ``, instance: "secretapp"},
		{tool: "restore_instance", args: map[string]any{"id": "secretapp", "archive": "secretapp/20990101T000000Z.tar"},
			method: "POST", path: "/api/instances/secretapp/restore", body: `{"archive":"secretapp/20990101T000000Z.tar"}`},
		{tool: "restore_as", args: map[string]any{"archive": "secretapp/20990101T000000Z.tar", "id": "notes-b"},
			method: "POST", path: "/api/instances/restore", body: `{"archive":"secretapp/20990101T000000Z.tar","id":"notes-b"}`},
		{tool: "delete_domain", args: map[string]any{"name": "team-b.example.net"},
			method: "DELETE", path: "/api/domains/team-b.example.net", body: ``},
		{tool: "set_ai_mode", args: map[string]any{"id": "aiapp", "companion": "tok", "mode": "read_only"},
			method: "PUT", path: "/api/instances/aiapp/ai", body: `{"companions":{"tok":{"mode":"read_only"}}}`},
		{tool: "set_ai_mode", args: map[string]any{"id": "aiapp", "companion": "tok", "mode": "read_write"},
			method: "PUT", path: "/api/instances/aiapp/ai", body: `{"companions":{"tok":{"mode":"read_write"}}}`},
		{tool: "set_ai_support", args: map[string]any{"id": "aiapp", "companion": "tok", "enabled": false},
			method: "PUT", path: "/api/instances/aiapp/ai", body: `{"companions":{"tok":{"enabled":false}}}`},
		{tool: "set_ai_support", args: map[string]any{"id": "aiapp", "companion": "tok", "enabled": true},
			method: "PUT", path: "/api/instances/aiapp/ai", body: `{"companions":{"tok":{"enabled":true}}}`},
		{tool: "revoke_ai_access", args: map[string]any{"id": "aiapp", "companion": "tok"},
			method: "POST", path: "/api/instances/aiapp/ai/revoke", body: `{"companion":"tok"}`},
		{tool: "revoke_ai_access", args: map[string]any{"id": "aiapp", "companion": "hdr", "user": "alice"},
			method: "POST", path: "/api/instances/aiapp/ai/revoke", body: `{"companion":"hdr","user":"alice"}`},
		{tool: "add_model_provider", args: ollamaArgs(nil),
			method: "POST", path: "/api/ai/providers", body: ollamaBody},
		{tool: "save_model_provider", args: ollamaArgs(map[string]any{"label": "Ollama 2"}),
			method: "PUT", path: "/api/ai/providers/ollama", body: strings.Replace(ollamaBody, `"Ollama"`, `"Ollama 2"`, 1)},
		{tool: "save_model_provider", args: ollamaArgs(map[string]any{"base_url": "http://gpu2.lan:11434/v1"}),
			method: "PUT", path: "/api/ai/providers/ollama", body: strings.Replace(ollamaBody, "gpu.lan", "gpu2.lan", 1)},
		{tool: "delete_model_provider", args: map[string]any{"name": "ollama"},
			method: "DELETE", path: "/api/ai/providers/ollama", body: ``},
		{tool: "save_hub_settings", args: map[string]any{"limits": map[string]any{"resource_rpm": 100}},
			method: "PUT", path: "/api/ai/settings", body: `{"limits":{"resource_rpm":100}}`},
		{tool: "save_hub_settings", args: map[string]any{"allowed_origins": []string{"https://a.example.org"}},
			method: "PUT", path: "/api/ai/settings", body: `{"allowed_origins":["https://a.example.org"]}`},
		{tool: "resume_user_sweep", args: map[string]any{},
			method: "POST", path: "/api/keycloak/user-sweep/resume", body: `{"confirm":"resume"}`},
		{tool: "remove_stale_keycloak_user", args: map[string]any{"username": "ghost"},
			method: "DELETE", path: "/api/directory/keycloak-stale/ghost", body: `{"confirm":"ghost"}`},
		// Last of the AI cases: an mTLS default switches aiapp's companions off (G43).
		{tool: "set_default_policy", args: map[string]any{"policy": map[string]any{"factors": []string{"mtls", "webauthn"}, "op": "all"}},
			method: "PUT", path: "/api/settings", body: `{"default_auth_policy":{"factors":["mtls","webauthn"],"op":"all"}}`, instance: "secretapp"},
		{tool: "set_default_policy", args: map[string]any{"policy": map[string]any{"factors": []string{"webauthn", "mtls"}, "op": "any"}},
			method: "PUT", path: "/api/settings", body: `{"default_auth_policy":{"factors":["webauthn","mtls"],"op":"any"}}`, instance: "secretapp"},
		{tool: "disable_instance", args: map[string]any{"id": "secretapp"},
			method: "POST", path: "/api/templates/disable", body: `{"id":"secretapp"}`},
		{tool: "delete_instance", args: map[string]any{"id": "grafana-a"},
			method: "DELETE", path: "/api/instances/grafana-a", body: `{"confirm":"grafana-a"}`, instance: "grafana-a"},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.tool] = true
	}
	perCallTools := map[string]bool{}
	for _, tl := range toolE.s.tools(ScopeAdmin) {
		if tl.ClassFor != nil {
			perCallTools[tl.Name] = true
		}
		if (tl.Class == ClassWrite || tl.Class == ClassDestructive) && !covered[tl.Name] && sameAsHTTPPending[tl.Name] == "" {
			t.Errorf("tool %s (%s) has no same-as-HTTP case", tl.Name, tl.Class)
		}
		if sameAsHTTPPending[tl.Name] != "" {
			t.Errorf("tool %s is registered: move it from sameAsHTTPPending to a case", tl.Name)
		}
	}
	branches := map[string]map[bool]bool{} // per-call tool → confirmed? → seen
	run := func(c sameAsHTTPCase) {
		t.Helper()
		if c.plan {
			// The tool needs the preview's plan hash (the HTTP twin none).
			txt, isErr, _ := toolE.tool(t, "preview_settings", c.args)
			var p struct {
				PlanHash string `json:"plan_hash"`
			}
			if isErr || json.Unmarshal([]byte(txt), &p) != nil || len(p.PlanHash) != 64 {
				t.Fatalf("preview = %s %v", txt, isErr)
			}
			tr.take()
			args := maps.Clone(c.args.(map[string]any))
			args["plan_hash"] = p.PlanHash
			c.args = args
		}
		hn, tn := len(readAudit(t, httpEnv.audit)), len(readAudit(t, toolE.audit))
		code, body := httpEnv.do(t, "root", c.method, c.path, c.body)
		txt, isErr, conf := toolE.tool(t, c.tool, c.args)
		if perCallTools[c.tool] {
			if branches[c.tool] == nil {
				branches[c.tool] = map[bool]bool{}
			}
			branches[c.tool][conf != ""] = true
		}
		if c.instance != "" {
			waitIdle(t, httpEnv.s.Hub, c.instance)
			waitIdle(t, toolE.s.Hub, c.instance)
		}
		hc, tc := hr.take(), tr.take()
		if len(hc) == 0 || !slices.Equal(hc, tc) {
			t.Errorf("%s: Hub calls differ:\n http %q\n tool %q", c.tool, hc, tc)
		}
		if (code >= 400) != isErr {
			t.Errorf("%s: http %d %s, tool isError %v %s", c.tool, code, body, isErr, txt)
		}
		if isErr && !strings.HasPrefix(txt, strings.Split(body, "\n")[0]) && !strings.HasPrefix(txt, strconv.Itoa(code)+": ") {
			t.Errorf("%s: tool error %q, http %d %q", c.tool, txt, code, body)
		}
		ha, ta := readAudit(t, httpEnv.audit)[hn:], readAudit(t, toolE.audit)[tn:]
		var hk, tk []string
		for _, a := range ha {
			if a.Via != "" || a.Client != "" {
				t.Errorf("%s: http audit %+v attributed to AI", c.tool, a)
			}
			hk = append(hk, auditKey(a))
		}
		for _, a := range ta {
			if a.Action == "ai.confirm" {
				continue
			}
			if a.Actor == "root" && (a.Via != "ai" || a.Client != mcpClient) {
				t.Errorf("%s: tool audit %+v without via ai / client", c.tool, a)
			}
			if conf != "" && a.Actor == "root" && !strings.HasSuffix(a.Detail, "confirmation "+conf) {
				t.Errorf("%s: tool audit %+v without the confirmation %s", c.tool, a, conf)
			}
			tk = append(tk, auditKey(a))
		}
		if !slices.Equal(hk, tk) {
			t.Errorf("%s: audit differs:\n http %q\n tool %q", c.tool, hk, tk)
		}
	}
	for _, c := range cases {
		run(c)
	}
	for n := range perCallTools {
		if !branches[n][false] || !branches[n][true] {
			t.Errorf("per-call tool %s: cases cover W %v, D %v — want both", n, branches[n][false], branches[n][true])
		}
	}
}

// TestDeleteInstanceTool (§15.6, §15.10): delete_instance asks for a
// confirmation whose page shows the Hub's plan and the typed check x;
// approved, the retry answers the twin's 202 body; the delete is audited
// instance.delete via ai, the client and the consumed confirmation.
func TestDeleteInstanceTool(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	if _, err := e.s.Hub.CreateInstanceAs("notes", "x", nil, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if !e.ll.HasGroup("users_x") || !e.ll.HasGroup("admin_x") {
		t.Fatal("instance x has no groups")
	}
	res := e.call(t, "/mcp/admin", "root", "2026-07-28", "delete_instance", map[string]any{"id": "x"}, urlElicit)
	el := elicitation(t, res, confirmInputKey)
	m := confirmURLRe.FindStringSubmatch(el["url"].(string))
	if m == nil {
		t.Fatalf("elicitation %v", el)
	}
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, m[1], "root")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Takes a backup, then permanently removes its containers, volumes, Keycloak client and groups users_x, admin_x."}
	if v.Typed != "x" || v.Tool != "delete_instance" || !slices.Equal(v.Consequences, want) {
		t.Fatalf("confirmation typed %q tool %q consequences %q, want %q", v.Typed, v.Tool, v.Consequences, want)
	}
	if _, ok := e.s.Hub.InstanceView("x"); !ok {
		t.Fatal("deleted before the confirmation")
	}
	e.decide(t, m[1], "x", true)
	res = e.call(t, "/mcp/admin", "root", "2026-07-28", "delete_instance", map[string]any{"id": "x"}, urlElicit)
	txt, isErr := resultText(res)
	var op OpStarted
	if isErr || json.Unmarshal([]byte(txt), &op) != nil || op.OpID == "" || op.Op != "delete" || op.Instance != "x" || op.Poll != "/api/instances/x/op" {
		t.Fatalf("approved retry = %q %v", txt, isErr)
	}
	// wait_for_op shows the outcome.
	txt, isErr, _ = e.tool(t, "wait_for_op", map[string]any{"id": "x", "op_id": op.OpID})
	var w struct {
		Done   bool         `json:"done"`
		Record hub.OpRecord `json:"record"`
	}
	if isErr || json.Unmarshal([]byte(txt), &w) != nil || !w.Done || !w.Record.OK || w.Record.OpID != op.OpID {
		t.Fatalf("wait_for_op = %s %v", txt, isErr)
	}
	if _, ok := e.s.Hub.InstanceView("x"); ok {
		t.Error("instance x still listed")
	}
	var del []directory.AuditEntry
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "instance.delete" {
			del = append(del, a)
		}
	}
	if len(del) != 1 || del[0].Result != "ok" || del[0].Actor != "root" || del[0].Via != "ai" || del[0].Client != mcpClient ||
		!strings.Contains(del[0].Detail, "confirmation "+m[1]) {
		t.Errorf("instance.delete audit = %+v", del)
	}
}

// blockingEngine holds ListVolumes while armed (a backup mid-way).
type blockingEngine struct {
	hub.Engine
	mu      sync.Mutex
	gate    chan struct{}
	reached chan struct{}
}

func (b *blockingEngine) ListVolumes(ctx context.Context, f docker.Filters) ([]docker.Volume, error) {
	b.mu.Lock()
	gate, reached := b.gate, b.reached
	b.mu.Unlock()
	if gate != nil {
		select {
		case reached <- struct{}{}:
		default:
		}
		<-gate
	}
	return b.Engine.ListVolumes(ctx, f)
}

// TestBusyIsToolError (§15.10): an instance mid-backup → enable_instance
// is an isError result with the 409 reason, never a protocol error.
func TestBusyIsToolError(t *testing.T) {
	var be *blockingEngine
	e := newToolEnv(t, nil, func(eng hub.Engine) hub.Engine { be = &blockingEngine{Engine: eng}; return be })
	be.mu.Lock()
	be.gate, be.reached = make(chan struct{}), make(chan struct{}, 1)
	be.mu.Unlock()
	release := sync.OnceFunc(func() {
		be.mu.Lock()
		close(be.gate)
		be.gate = nil
		be.mu.Unlock()
	})
	defer release()
	if _, err := e.s.Hub.StartBackup("grafana", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	<-be.reached
	txt, isErr, _ := e.tool(t, "enable_instance", map[string]any{"id": "grafana"})
	if !isErr || !strings.HasPrefix(txt, "409: ") || !strings.Contains(txt, "in progress") {
		t.Errorf("enable while busy = %q %v", txt, isErr)
	}
	release()
	waitIdle(t, e.s.Hub, "grafana")
}

// TestToolClassPerCall (G37): set_policy, set_sign_in_mode and
// set_public_access are D (confirmation) only for the access-widening
// arguments, W otherwise; their annotations say destructive.
func TestToolClassPerCall(t *testing.T) {
	// smbfixture (person_id, groups, path): its person_secret makes every
	// result "hidden" here (no secrets volume), but the class is decided
	// before Run.
	e := newToolEnv(t, map[string][2]string{"smbfixture": settingsFixture(t, "smbfixture")}, nil)
	for _, c := range []struct {
		tool    string
		args    map[string]any
		confirm bool
	}{
		// enable_instance: D when it starts public (cloud is public by default) or with native sign-in.
		{"enable_instance", map[string]any{"id": "secretapp"}, false},
		{"enable_instance", map[string]any{"id": "cloud"}, true},
		{"enable_instance", map[string]any{"id": "nope"}, true},
		// The default is hwk-or-mtls (any); webauthn+mtls (all) is stricter.
		{"set_policy", map[string]any{"id": "secretapp", "policy": map[string]any{"factors": []string{"mtls", "webauthn"}, "op": "all"}}, false},
		{"set_policy", map[string]any{"id": "secretapp", "inherit": true}, true},
		{"set_sign_in_mode", map[string]any{"id": "nativeapp", "mode": "gateway"}, false},
		{"set_sign_in_mode", map[string]any{"id": "nativeapp", "mode": "native"}, true},
		{"set_public_access", map[string]any{"id": "cloud", "access": "off"}, false},
		{"set_public_access", map[string]any{"id": "cloud", "access": "on"}, true},
		// Security review: local networks within the current ones (the
		// defaults include 10/8), or the defaults while they are current
		// → W; wider → D.
		{"set_local_networks", map[string]any{"use_defaults": true}, false},
		{"set_local_networks", map[string]any{"networks": []string{"10.1.0.0/16"}}, false},
		{"set_local_networks", map[string]any{"networks": []string{}}, false},

		// save_settings with ports → D, settings only → W (the hash
		// mismatch answers after the class decided).
		{"save_settings", map[string]any{"id": "secretapp", "values": map[string]any{"api_url": "https://a.example.org"}, "plan_hash": "x"}, false},
		{"save_settings", map[string]any{"id": "secretapp", "ports": map[string]string{}, "plan_hash": "x"}, true},
		// Fix round 1: a privileged option's rows (privapp's role, as
		// Grafana's role) → D; a plain value or a plain person option → W.
		{"save_settings", map[string]any{"id": "privapp", "person": map[string]any{"role": map[string]any{"default": "user", "rows": []any{map[string]any{"group": "helpers", "value": "admin"}}}}, "plan_hash": "x"}, true},
		{"save_settings", map[string]any{"id": "privapp", "values": map[string]any{"motd": "hello"}, "plan_hash": "x"}, false},
		{"save_settings", map[string]any{"id": "privapp", "person": map[string]any{"tier": map[string]any{"default": "pro"}}, "plan_hash": "x"}, false},
		{"save_settings", map[string]any{"id": "nope", "values": map[string]any{"motd": "hello"}, "plan_hash": "x"}, true},
		// The allowlist by type (security review): users, person_id,
		// groups, an unknown key → D; an inert string → W.
		{"save_settings", map[string]any{"id": "teamapp", "values": map[string]any{"owners": []string{"dana"}}, "plan_hash": "x"}, true},
		{"save_settings", map[string]any{"id": "teamapp", "values": map[string]any{"title": "Ops"}, "plan_hash": "x"}, false},
		{"save_settings", map[string]any{"id": "teamapp", "values": map[string]any{"nosuch": "x"}, "plan_hash": "x"}, true},
		{"save_settings", map[string]any{"id": "smbfixture", "person": map[string]any{"uid": map[string]any{"default": 1, "rows": []any{}}}, "plan_hash": "x"}, true},
		{"save_settings", map[string]any{"id": "smbfixture", "values": map[string]any{"share1_readers": []string{"helpers"}}, "plan_hash": "x"}, true},
		{"save_settings", map[string]any{"id": "smbfixture", "values": map[string]any{"share1_name": "Docs"}, "plan_hash": "x"}, false},
		// Fail closed: only gateway / off / a closed default are W.
		{"set_sign_in_mode", map[string]any{"id": "nativeapp", "mode": "bogus"}, true},
		{"set_public_access", map[string]any{"id": "cloud", "access": "default"}, true},
		{"set_public_access", map[string]any{"id": "cloud", "access": "off", "mode": "all"}, true},
		{"set_public_access", map[string]any{"id": "cloud", "access": "off", "mode": "listed"}, false},
	} {
		res := e.call(t, "/mcp/admin", "root", "2025-11-25", c.tool, c.args, nil)
		txt, _ := resultText(res)
		if got := confirmTextRe.MatchString(txt); got != c.confirm {
			t.Errorf("%s %v: confirmation %v, want %v (%s)", c.tool, c.args, got, c.confirm, txt)
		}
	}
	// Current narrower than the defaults: going back to them is a
	// widening (D); within the narrowed list still W.
	if err := e.s.Hub.SetLocalNetworks([]string{"10.1.0.0/16"}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args    map[string]any
		confirm bool
	}{
		{map[string]any{"use_defaults": true}, true},
		{map[string]any{"networks": []string{"10.0.0.0/8"}}, true},
		{map[string]any{"networks": []string{"10.1.2.0/24"}}, false},
		{map[string]any{"networks": []string{"10.1.0.0/16", "203.0.113.0/24"}}, true},
		{map[string]any{"networks": []string{"0.0.0.0/1"}}, true},
	} {
		txt, _ := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "set_local_networks", c.args, nil))
		if got := confirmTextRe.MatchString(txt); got != c.confirm {
			t.Errorf("narrowed: set_local_networks %v: confirmation %v, want %v (%s)", c.args, got, c.confirm, txt)
		}
	}
	// enable_instance of an app set to its own login only: D.
	native := hub.SignInNative
	if _, err := e.s.Hub.SaveSettings("nativeapp", hub.SettingsUpdate{SignIn: &native}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if txt, _ := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "enable_instance", map[string]any{"id": "nativeapp"}, nil)); !confirmTextRe.MatchString(txt) {
		t.Errorf("enable_instance of a native-sign-in app = %q, want a confirmation", txt)
	}
	// The consequences name what the defaults are, and an empty list.
	if got := strings.Join(localNetsConsequences(json.RawMessage(`{"use_defaults":true}`)), " "); !strings.Contains(got, strings.Join(hub.DefaultLocalNetworks, ", ")) {
		t.Errorf("use_defaults consequences = %q", got)
	}
	if got := strings.Join(localNetsConsequences(json.RawMessage(`{"networks":[]}`)), " "); !strings.Contains(got, "loopback only") {
		t.Errorf("[] consequences = %q", got)
	}
	code, a := e.rpc(t, rpcCall{path: "/mcp/admin", user: "root", version: "2025-11-25", method: "tools/list", params: map[string]any{}})
	if code != 200 {
		t.Fatal(code)
	}
	res, _ := a["result"].(map[string]any)
	ts, _ := res["tools"].([]any)
	seen := 0
	for _, x := range ts {
		tl := x.(map[string]any)
		ann, _ := tl["annotations"].(map[string]any)
		switch tl["name"] {
		case "set_policy", "set_sign_in_mode", "set_public_access", "save_settings", "set_local_networks", "delete_instance", "exec":
			seen++
			if ann["destructiveHint"] != true {
				t.Errorf("%s annotations %v", tl["name"], ann)
			}
		case "get_settings":
			if ann["readOnlyHint"] != true {
				t.Errorf("get_settings annotations %v", ann)
			}
		}
	}
	if seen != 7 {
		t.Errorf("listed %d of the D tools", seen)
	}
}

// TestInertOptionAllowlist: save_settings is W only for the inert types;
// every other built-in type, and a type this Hub doesn't know, is D.
func TestInertOptionAllowlist(t *testing.T) {
	inert := []string{"string", "int", "size", "duration", "bool", "enum", "multi_enum"}
	for typ := range templates.BuiltinTypes {
		if got := inertOption(&templates.Option{Key: "k", Type: typ}); got != slices.Contains(inert, typ) {
			t.Errorf("type %s: inert %v", typ, got)
		}
	}
	for _, o := range []*templates.Option{nil, {Key: "k", Type: "hologram"}, {Key: "k", Type: "string", Privileged: true},
		{Key: "k", Type: "users"}, {Key: "k", Type: "person_id"}} {
		if inertOption(o) {
			t.Errorf("%+v counts as inert", o)
		}
	}
}

// TestSaveSettingsPlanHash (G46): save_settings needs the preview's
// plan_hash — another one, or a change since the preview, is a 409 — and
// never takes a secret's value (secrets go through set_secret_setting).
func TestSaveSettingsPlanHash(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	v := "s3cret-value-1"
	if _, err := e.s.Hub.SaveSettings("secretapp", hub.SettingsUpdate{Secrets: map[string]hub.SecretChange{"api_key": {Value: &v}}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"id": "secretapp", "values": map[string]any{"api_url": "https://a.example.org"}}
	preview := func() string {
		txt, isErr, _ := e.tool(t, "preview_settings", args)
		var p struct {
			PlanHash string `json:"plan_hash"`
		}
		if isErr || json.Unmarshal([]byte(txt), &p) != nil || len(p.PlanHash) != 64 {
			t.Fatalf("preview = %s %v", txt, isErr)
		}
		return p.PlanHash
	}
	h1 := preview()
	if h2 := preview(); h2 != h1 {
		t.Fatalf("the plan hash isn't stable: %s %s", h1, h2)
	}
	save := func(hash string) (string, bool) {
		a := map[string]any{"id": "secretapp", "values": args["values"], "plan_hash": hash}
		txt, isErr, _ := e.tool(t, "save_settings", a)
		return txt, isErr
	}
	if txt, isErr := save(strings.Repeat("0", 64)); !isErr || !strings.HasPrefix(txt, "409: ") {
		t.Errorf("wrong hash = %q %v", txt, isErr)
	}
	// Something changed since the preview (another value saved): 409.
	mustDo(t, e.hub, "root", "PUT", "/api/instances/secretapp/settings", `{"values":{"api_url":"https://b.example.org"}}`, 200)
	if txt, isErr := save(h1); !isErr || !strings.HasPrefix(txt, "409: ") {
		t.Errorf("stale hash = %q %v", txt, isErr)
	}
	if txt, isErr := save(preview()); isErr || !strings.Contains(txt, `"changed"`) {
		t.Errorf("save = %q %v", txt, isErr)
	}
	panel, _ := e.s.Hub.SettingsPanel(context.Background(), "secretapp")
	if panel.Instance["api_url"] != "https://a.example.org" {
		t.Errorf("api_url = %v", panel.Instance["api_url"])
	}
	// A secret's value is refused by the Hub, a secrets field by the schema.
	bad := map[string]any{"id": "secretapp", "values": map[string]any{"api_key": "leak-me-123"}}
	if txt, isErr, _ := e.tool(t, "preview_settings", bad); !isErr || !strings.HasPrefix(txt, "400: ") || strings.Contains(txt, "leak-me") {
		t.Errorf("secret value = %q %v", txt, isErr)
	}
	sec := map[string]any{"id": "secretapp", "secrets": map[string]any{"api_key": map[string]any{"value": "x"}}, "plan_hash": h1}
	if txt, isErr, _ := e.tool(t, "save_settings", sec); !isErr || !strings.HasPrefix(txt, textSecretArgs) {
		t.Errorf("secrets field = %q %v", txt, isErr)
	}
}

// TestSecretSettingForm: set_secret_setting (U) takes no value: it
// answers the settings form's URL; after the person's accept it reports
// what the Hub stores ({set, updated_at}), never a value.
func TestSecretSettingForm(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	args := map[string]any{"id": "secretapp", "option": "api_key"}
	res := e.call(t, "/mcp/admin", "root", "2026-07-28", "set_secret_setting", args, urlElicit)
	el := elicitation(t, res, secretFormInputKey)
	if el["url"] != "https://hub.example.org/#app/secretapp/settings/api_key" {
		t.Errorf("form url %v", el["url"])
	}
	v := "s3cret-value-1"
	if _, err := e.s.Hub.SaveSettings("secretapp", hub.SettingsUpdate{Secrets: map[string]hub.SecretChange{"api_key": {Value: &v}}}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	res = e.call(t, "/mcp/admin", "root", "2026-07-28", "set_secret_setting", args, urlElicit,
		map[string]any{"inputResponses": map[string]any{secretFormInputKey: map[string]any{"action": "accept"}}})
	txt, isErr := resultText(res)
	if isErr || !strings.Contains(txt, `"set":true`) || strings.Contains(txt, v) {
		t.Errorf("after accept = %q %v", txt, isErr)
	}
	// get_env shows it as [set]; get_settings has no value.
	for _, tool := range []string{"get_env", "get_settings"} {
		txt, isErr, _ := e.tool(t, tool, map[string]any{"id": "secretapp"})
		if isErr || strings.Contains(txt, v) {
			t.Errorf("%s = %q %v", tool, txt, isErr)
		}
	}
}

// TestReadToolsAnswer: the R tools answer (a smoke test over each), get_logs
// keeps to 500 lines.
func TestReadToolsAnswer(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	for _, c := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"hub_status", nil, `"enabled"`},
		{"hub_status", map[string]any{"include_doctor": true}, `"doctor"`},
		{"explain_policy", map[string]any{"id": "secretapp"}, `"effective_policy"`},
		{"list_instances", nil, `"aiapp"`},
		{"get_instance", map[string]any{"id": "aiapp"}, `"state"`},
		{"instance_defaults", map[string]any{"template": "grafana", "id": "grafana-z"}, `grafana-z.example.org`},
		{"get_op", map[string]any{"id": "aiapp"}, `"op"`},
		{"get_settings", map[string]any{"id": "secretapp"}, `"options"`},
		{"get_logs", map[string]any{"id": "aiapp", "lines": 10}, `"logs"`},
		{"get_status", map[string]any{"id": "aiapp"}, `[`},
		{"get_compose", map[string]any{"id": "aiapp"}, `"compose"`},
		{"get_env", map[string]any{"id": "aiapp"}, `"variables"`},
		{"get_custom_override", map[string]any{"id": "aiapp"}, `"user_override"`},
		{"list_drift", nil, `"items"`},
		{"missing_groups", nil, `{`},
		{"get_local_networks", nil, `"networks"`},
	} {
		txt, isErr, _ := e.tool(t, c.tool, c.args)
		if isErr || !strings.Contains(txt, c.want) {
			t.Errorf("%s = %q %v", c.tool, txt, isErr)
		}
	}
	if txt, _, _ := e.tool(t, "hub_status", nil); strings.Contains(txt, `"doctor"`) {
		t.Errorf("hub_status ran the doctor without include_doctor: %s", txt)
	}
	if txt, isErr, _ := e.tool(t, "get_logs", map[string]any{"id": "aiapp", "lines": 501}); !isErr || !strings.HasPrefix(txt, "400: ") {
		t.Errorf("501 lines = %q %v", txt, isErr)
	}
	// aiapp's generated HDR_SECRET never shows (secret-looking: redacted).
	sec := readEnvValue(t, filepath.Join(e.data, "env", "aiapp.env"), "HDR_SECRET")
	if txt, _, _ := e.tool(t, "get_env", map[string]any{"id": "aiapp"}); sec == "" || strings.Contains(txt, sec) {
		t.Errorf("get_env shows HDR_SECRET (%q): %s", sec, txt)
	}
}
