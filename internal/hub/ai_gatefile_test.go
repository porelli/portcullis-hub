package hub

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Plan 4 Task 11: the gate files (contract §15.4). The test templates use
// pilot ids (gitea, wiki) on purpose: only non-test code must be free of
// template ids (TestGateFileHasNoTemplateIDs).

const gateGiteaManifest = `name: Gitea
category: dev
instances: multi
auth:
  method: forward-auth
  group_access: true
  access_group: users_gitea
urls:
  - label: Web
    url: "https://{{HOST_GITEA}}"
hooks:
  - {name: mcp-mint, service: gitea, command: [/mint], when: [ai]}
  - {name: mcp-revoke, service: gitea, command: [/revoke], when: [ai]}
  - {name: oauth-revoke, service: gitea, command: [/oauth-revoke], when: [ai]}
ai:
  mcp:
    - name: gitea
      label: Gitea
      kind: companion
      service: gitea-mcp
      port: 8080
      router: gitea
      upstream: official
      source: https://gitea.com/gitea/gitea-mcp
      protocol: ["2026-07-28", "2025-11-25"]
      modes: [read_only, read_write]
      default_mode: read_write
      identity:
        mode: app_token
        format: "token {credential}"
        mint: mcp-mint
        revoke: mcp-revoke
      tools:
        writes: ["*_write", "create_*", "update_*", "merge_*", "delete_*"]
        confirm: ["delete_*", "repo_write:delete"]
        never: []
    - name: oauth
      label: Gitea OAuth
      kind: builtin
      service: gitea
      path: /api/mcp
      router: gitea
      upstream: official
      source: https://gitea.com/gitea/gitea
      protocol: ["2025-11-25"]
      modes: [read_write]
      identity: {mode: app_oauth, revoke: oauth-revoke}
`

const gateGiteaCompose = "services:\n  gitea:\n    image: gitea\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.gitea.rule: Host(`${PORTCULLIS_HOST_GITEA:-gitea.portcullis.local}`)\n      traefik.http.routers.gitea.entrypoints: websecure\n      traefik.http.routers.gitea.middlewares: portcullis-auth@docker,portcullis-groups@docker\n      traefik.http.services.gitea.loadbalancer.server.port: \"3000\"\n    networks: [default, portcullis-proxy]\n  gitea-mcp:\n    image: gitea-mcp\n    networks: [default]\nnetworks:\n  portcullis-proxy:\n    external: true\n"

const gateNativeManifest = `name: Native
category: tools
auth:
  method: custom
  sso: false
  group_access: true
  access_group: users_native
  native_login:
    supported: true
    allow_without_gateway: true
    note: its own accounts
urls:
  - label: Web
    url: "https://{{HOST_NATIVE}}"
hooks:
  - {name: mcp-mint, service: native-mcp, command: [/mint], when: [ai]}
  - {name: mcp-revoke, service: native-mcp, command: [/revoke], when: [ai]}
ai:
  mcp:
    - name: native
      label: Native
      kind: companion
      service: native-mcp
      port: 9000
      router: native
      upstream: official
      source: https://example.org/native
      protocol: ["2025-11-25"]
      modes: [read_only]
      identity:
        mode: app_token
        basic: {user: "{username}", password: "{credential}"}
        mint: mcp-mint
        revoke: mcp-revoke
      tools: {writes: [], confirm: [], never: []}
`

const gateNativeCompose = "services:\n  app:\n    image: native\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.native.rule: Host(`${PORTCULLIS_HOST_NATIVE:-native.portcullis.local}`)\n      traefik.http.routers.native.entrypoints: websecure\n      traefik.http.services.native.loadbalancer.server.port: \"8080\"\n  native-mcp:\n    image: native-mcp\n"

const gateUnsupManifest = `name: Unsup
category: tools
ai: {unsupported: "no MCP server"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_unsup
`

const gateUnsupCompose = "services:\n  web:\n    image: x\n    labels:\n      traefik.http.routers.unsup.rule: Host(`unsup.${PORTCULLIS_DOMAIN}`)\n"

type gateFixture struct {
	*fixture
	people *fakePeople
	id     *age.X25519Identity
	recip  string
	// chatClient is the ai_client id of the AI page instance.
	chatClient string
}

// allAIClientsHealthy: the three Hub clients and the AI page's client.
func (g *gateFixture) allHealthy() map[string]bool {
	return map[string]bool{keycloak.AIClientIDs.Claude: true, keycloak.AIClientIDs.ClaudeCode: true,
		keycloak.AIClientIDs.Generic: true, g.chatClient: true}
}

func readFixture(t *testing.T, dir string) [2]string {
	t.Helper()
	return [2]string{string(mustRead(t, filepath.Join(dir, "manifest.yaml"))), string(mustRead(t, filepath.Join(dir, "compose.yml")))}
}

// newGateFixture: domain example.com, a gate recipient, AI on with every
// test companion switched on (seed adjusts the state first), and a
// directory: alice, bob in users_gitea; alice in users_headers (wiki) and
// users_native; root in lldap_admin; carol in nothing.
func newGateFixture(t *testing.T, seed func(*state.AppState)) *gateFixture {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	g := &gateFixture{id: id}
	tdir := filepath.Join("..", "templates", "testdata", "ai")
	extra := map[string][2]string{
		"gitea":  {gateGiteaManifest, gateGiteaCompose},
		"wiki":   readFixture(t, filepath.Join(tdir, "headers")),
		"aichat": readFixture(t, filepath.Join(tdir, "chat")),
		"native": {gateNativeManifest, gateNativeCompose},
		"unsup":  {gateUnsupManifest, gateUnsupCompose},
	}
	g.fixture = newInstanceFixtureCfg(t, func(st *state.AppState) {
		st.Enabled = []string{"aichat", "gitea", "native", "unsup", "wiki"}
		st.AI.Enabled = true
		st.AI.Clients.Claude.Admin = true
		st.AI.Clients.ClaudeCode.Admin = true
		st.SignIn = map[string]string{"native": state.SignInNative}
		st.AIInstances = map[string]state.AIInstance{
			"gitea":  {Companions: map[string]state.AICompanion{"gitea": {Enabled: true, Mode: "read_write"}, "oauth": {Enabled: true, Mode: "read_write"}}},
			"wiki":   {Companions: map[string]state.AICompanion{"wiki": {Enabled: true, Mode: "read_only"}}},
			"native": {Companions: map[string]state.AICompanion{"native": {Enabled: true, Mode: "read_only"}}},
			"unsup":  {Companions: map[string]state.AICompanion{"unsup": {Enabled: true, Mode: "read_write"}}},
		}
		if seed != nil {
			seed(st)
		}
	}, nil, extra, func(root string, c *Config) {
		c.Domain = "example.com"
		g.recip = filepath.Join(root, "age.pub")
		if err := os.WriteFile(g.recip, []byte(id.Recipient().String()+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		c.MCPGateRecipientFile = g.recip
	})
	for _, tid := range []string{"gitea", "wiki", "aichat", "native", "unsup"} {
		if g.h.Template(tid) == nil {
			t.Fatalf("template %s not loaded (see the log)", tid)
		}
	}
	g.chatClient = g.h.Template("aichat").InstanceClientID("chat-mcp")
	p := newFakePeople("carol")
	p.addGroup("users_gitea", "alice", "bob")
	p.addGroup("users_headers", "alice") // the wiki fixture's access group
	p.addGroup("users_native", "alice")
	p.addGroup("design", "alice")
	p.addGroup("lldap_admin", "root")
	p.emails = map[string]string{"alice": "alice@example.org", "bob": "bob@example.org", "root": "root@example.org"}
	g.people = p
	g.h.SetPeople(p)
	g.h.SetAIClientHealth(g.allHealthy())
	return g
}

func (g *gateFixture) build(t *testing.T) *aigate.File {
	t.Helper()
	m, err := g.h.membership(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := g.h.gateFile(m, g.h.aiClientHealth(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("the gate would refuse the file: %v", err)
	}
	return f
}

func resourceByURL(f *aigate.File, url string) *aigate.Resource {
	for i := range f.Resources {
		if f.Resources[i].URL == url {
			return &f.Resources[i]
		}
	}
	return nil
}

func urls(f *aigate.File) []string {
	var out []string
	for _, r := range f.Resources {
		out = append(out, r.URL)
	}
	return out
}

func TestGateFileResources(t *testing.T) {
	g := newGateFixture(t, nil)
	f := g.build(t)
	if !f.Enabled || f.Issuer != "https://auth.example.com/realms/portcullis" || f.MainDomain != "example.com" {
		t.Fatalf("header = %v %q %q", f.Enabled, f.Issuer, f.MainDomain)
	}
	r := resourceByURL(f, "https://gitea.example.com/mcp")
	if r == nil {
		t.Fatalf("no gitea resource: %v", urls(f))
	}
	g.h.mu.RLock()
	wantLoA := policy.LoA(g.h.effectivePolicyLocked(g.h.findLocked("gitea")))
	g.h.mu.RUnlock()
	if r.Scope != "mcp:gitea.gitea" || r.Kind != aigate.KindCompanion || r.Instance != "gitea" || r.Companion != "gitea" ||
		r.Label != "Gitea" || r.Host != "gitea.example.com" || !slices.Equal(r.Hosts, []string{"gitea.example.com"}) ||
		r.AppURL != "https://gitea.example.com" || r.Upstream != "http://portcullis-mcp-gitea--gitea:8080/mcp" ||
		r.MinLoA != wantLoA || r.Mode != "read_write" || !r.Aggregate ||
		!slices.Equal(r.Protocol, []string{"2026-07-28", "2025-11-25"}) {
		t.Errorf("gitea resource = %+v", *r)
	}
	if r.Identity != (aigate.Identity{Mode: "app_token", Header: "Authorization", Format: "token {credential}"}) {
		t.Errorf("identity = %+v", r.Identity)
	}
	if !slices.Equal(r.Tools.Writes, []string{"*_write", "create_*", "update_*", "merge_*", "delete_*"}) ||
		!slices.Equal(r.Tools.Confirm, []string{"delete_*", "repo_write:delete"}) || r.Tools.Never == nil {
		t.Errorf("tools = %+v", r.Tools)
	}
	if !slices.Equal(r.Population, []string{"alice", "bob"}) || len(r.Expiring) != 0 || r.People != nil {
		t.Errorf("population = %v expiring %v people %v", r.Population, r.Expiring, r.People)
	}
	all := resourceByURL(f, "https://mcp.example.com/mcp")
	if all == nil || all.Scope != "mcp:all" || all.Kind != aigate.KindAggregate || all.Aggregate ||
		!slices.Equal(all.Population, []string{"admin", "alice", "bob", "carol", "root"}) {
		t.Errorf("aggregate = %+v", all)
	}
	adm := resourceByURL(f, "https://hub.example.com/mcp")
	if adm == nil || adm.Scope != "mcp:portcullis.admin" || adm.Kind != aigate.KindAdmin || !slices.Equal(adm.Population, []string{"root"}) || adm.MinLoA != 2 {
		t.Errorf("admin = %+v", adm)
	}
	ppl := resourceByURL(f, "https://people.example.com/mcp")
	if ppl == nil || ppl.Scope != "mcp:portcullis.people" || ppl.Kind != aigate.KindPeople || !ppl.Aggregate || ppl.MinLoA != 2 ||
		!slices.Equal(ppl.Population, all.Population) {
		t.Errorf("people = %+v", ppl)
	}
	if !slices.IsSorted(urls(f)) {
		t.Errorf("resources not sorted: %v", urls(f))
	}
	// Written by WritePolicy: decodes with the gate's rules.
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(g.data, aigate.GateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if df, err := aigate.DecodeFile(b); err != nil || resourceByURL(df, r.URL) == nil {
		t.Fatalf("written file: %v", err)
	}
	if st, _ := os.Stat(filepath.Join(g.data, aigate.GateFileName)); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %o", st.Mode().Perm())
	}

	// Portcullis MCP for admins off: no admin resource.
	g.h.mu.Lock()
	g.h.st.AI.PortcullisAdmin = false
	g.h.mu.Unlock()
	if f := g.build(t); resourceByURL(f, "https://hub.example.com/mcp") != nil {
		t.Error("admin resource with Portcullis MCP for admins off")
	}
	// ... for people off: no people resource.
	g.h.mu.Lock()
	g.h.st.AI.PortcullisPeople = false
	g.h.mu.Unlock()
	if f := g.build(t); resourceByURL(f, "https://people.example.com/mcp") != nil {
		t.Error("people resource with Portcullis MCP for people off")
	}
	// An instance policy reaching LoA 3 (mTLS): the companion is excluded.
	g.h.mu.Lock()
	g.h.st.AuthPolicies = map[string]policy.AuthPolicy{"gitea": {Factors: []string{"mtls"}}}
	g.h.mu.Unlock()
	if f := g.build(t); resourceByURL(f, "https://gitea.example.com/mcp") != nil {
		t.Error("LoA 3 companion listed")
	}
	// The master switch off: enabled false, nothing listed.
	g.h.mu.Lock()
	g.h.st.AI.Enabled = false
	g.h.mu.Unlock()
	off := g.build(t)
	if off.Enabled || len(off.Resources) != 0 || len(off.Clients) != 0 {
		t.Errorf("master switch off = enabled %v resources %v clients %v", off.Enabled, urls(off), off.Clients)
	}
}

// Without a (readable, parseable) recipient file: enabled false, and the
// directory isn't needed for it.
func TestGateFileNoRecipient(t *testing.T) {
	for name, content := range map[string]*string{"missing": nil, "garbage": ptr("age1stale\n")} {
		t.Run(name, func(t *testing.T) {
			g := newGateFixture(t, nil)
			if content == nil {
				os.Remove(g.recip)
			} else if err := os.WriteFile(g.recip, []byte(*content), 0o640); err != nil {
				t.Fatal(err)
			}
			g.people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 503, Msg: "down"} })
			if err := g.h.WritePolicy(); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(g.data, aigate.GateFileName))
			if err != nil {
				t.Fatal(err)
			}
			f, err := aigate.DecodeFile(b)
			if err != nil || f.Enabled || len(f.Resources) != 0 {
				t.Fatalf("file = %+v %v", f, err)
			}
		})
	}
}

func TestGateFilePopulationRules(t *testing.T) {
	soon := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
	g := newGateFixture(t, func(st *state.AppState) {
		// wiki's switch on in state, but the instance disabled.
		st.Enabled = []string{"aichat", "gitea", "native", "unsup"}
	})
	g.people.set(func(p *fakePeople) {
		p.expired = map[string]map[string]bool{"bob": {"users_gitea": true}}
		p.pending = map[string]map[string]time.Time{"alice": {"users_gitea": soon, "design": soon.Add(-time.Hour)}}
	})
	f := g.build(t)
	if r := resourceByURL(f, "https://wiki.example.com/mcp"); r != nil {
		t.Error("disabled instance's companion listed")
	}
	r := resourceByURL(f, "https://gitea.example.com/mcp")
	if r == nil {
		t.Fatalf("no gitea: %v", urls(f))
	}
	if !slices.Equal(r.Population, []string{"alice"}) {
		t.Errorf("population %v: an expired-but-not-removed member must be absent", r.Population)
	}
	// The access group's pending expiry, not another group's.
	if len(r.Expiring) != 1 || !r.Expiring["alice"].Equal(soon) {
		t.Errorf("expiring = %v, want alice at %v", r.Expiring, soon)
	}
	// sign_in native: the resource with nobody in it.
	if n := resourceByURL(f, "https://native.example.com/mcp"); n == nil || len(n.Population) != 0 {
		t.Errorf("native sign-in = %+v, want listed with an empty population", n)
	} else if n.Identity != (aigate.Identity{Mode: "app_token", Header: "Authorization", BasicUser: "{username}"}) {
		t.Errorf("basic identity = %+v", n.Identity)
	}
	for _, u := range urls(f) {
		if strings.Contains(u, "/api/mcp") || strings.Contains(u, "unsup") {
			t.Errorf("app_oauth or unsupported companion listed: %s", u)
		}
	}
	for _, r := range f.Resources {
		if r.Companion == "oauth" || r.Instance == "unsup" {
			t.Errorf("listed %s/%s", r.Instance, r.Companion)
		}
	}

	// Input doubts exclude: a stored mode the companion doesn't offer, a
	// companion switched off, an instance being deleted.
	g.h.mu.Lock()
	g.h.st.Enabled = append(g.h.st.Enabled, "wiki")
	g.h.st.AIInstances["wiki"] = state.AIInstance{Companions: map[string]state.AICompanion{"wiki": {Enabled: true, Mode: "read_write"}}}
	g.h.mu.Unlock()
	g.h.Discover()
	if r := resourceByURL(g.build(t), "https://wiki.example.com/mcp"); r != nil {
		t.Error("a mode outside the companion's modes listed")
	}
	g.h.mu.Lock()
	g.h.st.AIInstances["gitea"] = state.AIInstance{Companions: map[string]state.AICompanion{"gitea": {Enabled: false, Mode: "read_write"}}}
	g.h.mu.Unlock()
	if r := resourceByURL(g.build(t), "https://gitea.example.com/mcp"); r != nil {
		t.Error("a switched-off companion listed")
	}
	g.h.mu.Lock()
	g.h.st.AIInstances["gitea"] = state.AIInstance{Companions: map[string]state.AICompanion{"gitea": {Enabled: true, Mode: "read_write"}}}
	g.h.st.Instances = map[string]state.Instance{"gitea": {State: state.InstanceDeleting}}
	g.h.mu.Unlock()
	if r := resourceByURL(g.build(t), "https://gitea.example.com/mcp"); r != nil {
		t.Error("a deleting instance's companion listed")
	}
}

func TestGateFileIdentityPeople(t *testing.T) {
	g := newGateFixture(t, nil)
	g.people.set(func(p *fakePeople) {
		p.expired = map[string]map[string]bool{"alice": {"design": true}}
	})
	envFile := filepath.Join(g.data, "env", "wiki.env")
	if err := os.WriteFile(envFile, []byte("MCP_SECRET='wiki-caller-secret-value'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := g.build(t)
	w := resourceByURL(f, "https://wiki.example.com/mcp")
	if w == nil {
		t.Fatalf("no wiki: %v", urls(f))
	}
	if w.Upstream != "http://portcullis-mcp-wiki--wiki:8080/api/mcp" || w.Aggregate || w.Mode != "read_only" {
		t.Errorf("wiki = %+v", *w)
	}
	if w.Identity != (aigate.Identity{Mode: "identity_headers", Header: "X-Mcp-Secret", Format: "{secret}", SecretRef: "wiki/wiki"}) {
		t.Errorf("identity = %+v", w.Identity)
	}
	// The groups group-gate forwards: LLDAP groups minus expired ones.
	p, ok := w.People["alice"]
	if !ok || len(w.People) != 1 || p.Email != "alice@example.org" ||
		!slices.Equal(p.Groups, []string{"users_gitea", "users_headers", "users_native"}) {
		t.Errorf("people = %+v (population %v)", w.People, w.Population)
	}
	// app_token: no people.
	if r := resourceByURL(f, "https://gitea.example.com/mcp"); r == nil || r.People != nil {
		t.Errorf("gitea people = %+v", r)
	}
	// A member without an email: no entry (never a stale or empty value).
	g.people.set(func(p *fakePeople) { delete(p.emails, "alice") })
	if w := resourceByURL(g.build(t), "https://wiki.example.com/mcp"); w == nil || len(w.People) != 0 {
		t.Errorf("people without an email = %+v", w)
	}
}

func TestGateFileFollowsSettings(t *testing.T) {
	g := newGateFixture(t, func(st *state.AppState) {
		st.AI.Clients.Generic.Offered = false
		st.AI.Limits.ToolCallsRPM = 33
		st.AI.Limits.Fanout = 2
		st.AI.AllowedOrigins = []string{"https://a.example.org", "https://b.example.org:8443"}
	})
	f := g.build(t)
	claude, code := keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode
	offered := []string{claude, code}
	withChat := append([]string{g.chatClient}, offered...)
	slices.Sort(withChat)
	if !slices.Equal(f.Clients, withChat) {
		t.Errorf("clients = %v, want %v", f.Clients, withChat)
	}
	for _, r := range f.Resources {
		want := withChat
		if r.Kind == aigate.KindAdmin {
			want = offered // only the admin-flagged clients, never an ai_client
		}
		if !slices.Equal(r.Clients, want) {
			t.Errorf("%s clients = %v, want %v", r.URL, r.Clients, want)
		}
	}
	if f.Limits.ToolCallsRPM != 33 || f.Limits.Fanout != 2 || f.Limits.ResourceRPM != 120 ||
		f.Limits.MaxRequestBytes != aigate.FixedMaxRequestBytes || f.Limits.UpstreamTimeoutS != 120 {
		t.Errorf("limits = %+v", f.Limits)
	}
	if !slices.Equal(f.AllowedOrigins, []string{"https://a.example.org", "https://b.example.org:8443"}) {
		t.Errorf("origins = %v", f.AllowedOrigins)
	}
	if f.ACRLoA["public"] != 0 || f.ACRLoA["pwd"] != 1 || f.ACRLoA["hwk"] != 2 || f.ACRLoA["mtls"] != 3 || len(f.ACRLoA) != 4 {
		t.Errorf("acr_loa = %v", f.ACRLoA)
	}
	if !slices.Contains(f.CoreHosts, "mcp.example.com") || !slices.Contains(f.CoreHosts, "example.com") {
		t.Errorf("core hosts = %v", f.CoreHosts)
	}

	// Admin flag only on Claude Code: the admin resource lists it alone.
	g.h.mu.Lock()
	g.h.st.AI.Clients.Claude.Admin = false
	g.h.mu.Unlock()
	if adm := resourceByURL(g.build(t), "https://hub.example.com/mcp"); adm == nil || !slices.Equal(adm.Clients, []string{code}) {
		t.Errorf("admin = %+v", adm)
	}
	// No admin-flagged client: no admin resource.
	g.h.mu.Lock()
	g.h.st.AI.Clients.ClaudeCode.Admin = false
	g.h.mu.Unlock()
	if adm := resourceByURL(g.build(t), "https://hub.example.com/mcp"); adm != nil {
		t.Errorf("admin resource without an admin-flagged client: %+v", adm)
	}

	// T10 carry: a client whose last EnsureAIClient failed is in no list.
	health := g.allHealthy()
	health[claude] = false
	delete(health, g.chatClient)
	g.h.SetAIClientHealth(health)
	f = g.build(t)
	if !slices.Equal(f.Clients, []string{code}) {
		t.Errorf("unhealthy clients listed: %v", f.Clients)
	}
	for _, r := range f.Resources {
		if slices.Contains(r.Clients, claude) || slices.Contains(r.Clients, g.chatClient) {
			t.Errorf("%s lists an unhealthy client: %v", r.URL, r.Clients)
		}
	}
	// Health unknown (the sync loop hasn't run): no client at all.
	g.h.SetAIClientHealth(nil)
	f = g.build(t)
	if len(f.Clients) != 0 {
		t.Errorf("clients with health unknown: %v", f.Clients)
	}
	for _, r := range f.Resources {
		if len(r.Clients) != 0 || r.Kind == aigate.KindAdmin {
			t.Errorf("%s with health unknown: clients %v", r.URL, r.Clients)
		}
	}
}

// A membership change through the directory sync loop rewrites the
// policy file and the gate file in the same WritePolicy, from one read; a
// failing directory keeps the last gate file's populations (fail closed,
// like expiring) — with no state change the file is byte-identical.
func TestGateFileWrittenWithPolicy(t *testing.T) {
	g := newGateFixture(t, nil)
	var dirCalls atomic.Int32
	carolIn := atomic.Bool{}
	far := time.Now().UTC().Add(240 * time.Hour).Format(time.RFC3339)
	// ONE directory read per WritePolicy feeds both files (fix round 1,
	// item 4): the snapshot carries the membership.
	g.h.SetDirectory(func(ctx context.Context) (DirectorySnapshot, error) {
		dirCalls.Add(1)
		m, err := g.people.Membership(ctx, time.Now().UTC())
		if err != nil {
			return DirectorySnapshot{}, err
		}
		var exp []policy.Expiring
		if carolIn.Load() {
			exp = []policy.Expiring{{User: "carol", Group: "users_gitea", At: far}}
		}
		return DirectorySnapshot{Expiring: exp, Membership: m}, nil
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.h.RunDirectorySync(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	gatePath := filepath.Join(g.data, aigate.GateFileName)
	readGate := func() *aigate.File {
		b, err := os.ReadFile(gatePath)
		if err != nil {
			return nil
		}
		f, err := aigate.DecodeFile(b)
		if err != nil {
			t.Fatalf("gate file: %v", err)
		}
		return f
	}
	waitUntil := func(what string, ok func() bool) {
		t.Helper()
		for i := 0; i < 500 && !ok(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if !ok() {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
	giteaPop := func() []string {
		if f := readGate(); f != nil {
			if r := resourceByURL(f, "https://gitea.example.com/mcp"); r != nil {
				return r.Population
			}
		}
		return nil
	}
	waitUntil("the first gate file", func() bool { return slices.Equal(giteaPop(), []string{"alice", "bob"}) })

	g.people.addGroup("users_gitea", "carol")
	carolIn.Store(true)
	g.h.TriggerDirectorySync()
	waitUntil("carol in the gate file", func() bool { return slices.Contains(giteaPop(), "carol") })
	pol, err := os.ReadFile(g.h.policyPath())
	if err != nil || !strings.Contains(string(pol), `"carol"`) {
		t.Fatalf("the policy file of the same write lacks carol's expiry: %v", err)
	}

	before, _ := os.ReadFile(gatePath)
	g.people.removeMember("users_gitea", "carol")
	g.people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 502, Msg: "unreachable"} })
	n := dirCalls.Load()
	g.h.TriggerDirectorySync()
	waitUntil("a policy write", func() bool { return dirCalls.Load() > n })
	g.h.policyWriteMu.Lock() // the write in flight has finished
	g.h.policyWriteMu.Unlock()
	after, _ := os.ReadFile(gatePath)
	if !bytes.Equal(before, after) {
		t.Error("the gate file changed while the directory failed")
	}
	if !g.h.gateStale.Load() {
		t.Error("a failed gate write isn't marked for retry")
	}
	if err := g.h.WritePolicy(); err == nil {
		t.Error("WritePolicy hid the kept gate file")
	}
	g.people.set(func(p *fakePeople) { p.err = nil })
	var calls0, calls1 int
	g.people.set(func(p *fakePeople) { calls0 = p.calls })
	if err := g.h.WritePolicy(); err != nil || slices.Contains(giteaPop(), "carol") || g.h.gateStale.Load() {
		t.Errorf("after recovery: %v %v", err, giteaPop())
	}
	g.people.set(func(p *fakePeople) { calls1 = p.calls })
	if n := calls1 - calls0; n != 1 {
		t.Errorf("one WritePolicy read the directory %d times, want 1 (one snapshot for both files)", n)
	}
}

func TestCredentialsEncryptedHubCantRead(t *testing.T) {
	g := newGateFixture(t, nil)
	envFile := filepath.Join(g.data, "env", "wiki.env")
	if err := os.WriteFile(envFile, []byte("MCP_SECRET='wiki-caller-secret-value'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := []byte("s3cr3t")
	minted := time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC)
	if err := g.h.creds().Put(aigate.Credential{Instance: "gitea", Companion: "gitea", User: "alice", ID: "7", MintedAt: aigate.At(minted)}, plain); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, make([]byte, len(plain))) {
		t.Error("plaintext not zeroed")
	}
	if err := g.h.WritePolicy(); err != nil { // the caller secret
		t.Fatal(err)
	}
	path := filepath.Join(g.data, aigate.CredsFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	cf, err := aigate.DecodeCredFile(b)
	if err != nil {
		t.Fatal(err)
	}
	open := func(ct string, id age.Identity) string {
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(ct)), id)
		if err != nil {
			return "<" + err.Error() + ">"
		}
		out, _ := io.ReadAll(r)
		return string(out)
	}
	if len(cf.Credentials) != 1 || cf.Credentials[0].State != aigate.StateActive || open(cf.Credentials[0].Age, g.id) != "s3cr3t" {
		t.Fatalf("credentials = %+v", cf.Credentials)
	}
	other, _ := age.GenerateX25519Identity()
	if open(cf.Credentials[0].Age, other) == "s3cr3t" {
		t.Fatal("another identity decrypted it")
	}
	if len(cf.CallerSecrets) != 1 || cf.CallerSecrets[0].Ref != "wiki/wiki" || open(cf.CallerSecrets[0].Age, g.id) != "wiki-caller-secret-value" {
		t.Fatalf("caller secrets = %+v", cf.CallerSecrets)
	}
	// The plaintext is nowhere under the data directory, and no Hub view
	// carries the ciphertext.
	filepath.WalkDir(g.data, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if c, _ := os.ReadFile(p); bytes.Contains(c, []byte("s3cr3t")) {
				t.Errorf("%s holds the plaintext", p)
			}
		}
		return nil
	})
	for _, e := range g.h.creds().Entries() {
		if e.Age != "" {
			t.Errorf("Entries carries the ciphertext: %+v", e)
		}
	}
	// Revoking drops the ciphertext; remove drops the entry.
	if err := g.h.creds().MarkRevoking("gitea", "gitea", "alice"); err != nil {
		t.Fatal(err)
	}
	cf, _ = aigate.DecodeCredFile(mustRead(t, path))
	if cf.Credentials[0].State != aigate.StateRevoking || cf.Credentials[0].Age != "" {
		t.Errorf("revoking = %+v", cf.Credentials[0])
	}
	if err := g.h.creds().Remove("gitea", "gitea", "alice"); err != nil {
		t.Fatal(err)
	}
	cf, _ = aigate.DecodeCredFile(mustRead(t, path))
	if len(cf.Credentials) != 0 {
		t.Errorf("after remove = %+v", cf.Credentials)
	}
	// A companion that leaves the gate file loses its caller secret.
	g.h.mu.Lock()
	g.h.st.AIInstances["wiki"] = state.AIInstance{}
	g.h.mu.Unlock()
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	cf, _ = aigate.DecodeCredFile(mustRead(t, path))
	if len(cf.CallerSecrets) != 0 {
		t.Errorf("caller secret kept for a companion that left: %+v", cf.CallerSecrets)
	}
	// Bad inputs are refused before anything is written.
	if err := g.h.creds().Put(aigate.Credential{Instance: "gitea", Companion: "gitea", User: "Alice", ID: "7", MintedAt: aigate.At(minted)}, []byte("x")); err == nil {
		t.Error("an invalid username accepted")
	}
}

// The Hub holds no age identity (fix round 1, item 7): every non-test Go
// file of every package of the module (go list ./...) is parsed; imports
// of filippo.io/age and filippo.io/age/armor are resolved under whatever
// name they get, and every selector on that name must be in the
// allowlist (encrypting only). Any other filippo.io/age/... package and
// dot or blank imports of these are refused.
func TestHubHoldsNoAgeIdentity(t *testing.T) {
	allowed := map[string]map[string]bool{
		"filippo.io/age":       {"ParseX25519Recipient": true, "Encrypt": true, "X25519Recipient": true, "Recipient": true},
		"filippo.io/age/armor": {"NewWriter": true},
	}
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "github.com/portcullis/hub/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	dirs := strings.Fields(string(out))
	if len(dirs) < 10 {
		t.Fatalf("go list found only %d packages", len(dirs))
	}
	users := 0
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, p := range files {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			names := map[string]string{} // local name → import path
			for _, imp := range file.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if path != "filippo.io/age" && !strings.HasPrefix(path, "filippo.io/age/") {
					continue
				}
				if allowed[path] == nil {
					t.Errorf("%s imports %s", p, path)
					continue
				}
				name := filepath.Base(path)
				if imp.Name != nil {
					name = imp.Name.Name
				}
				if name == "." || name == "_" {
					t.Errorf("%s: %s imported as %q", p, path, name)
					continue
				}
				names[name] = path
			}
			if len(names) == 0 {
				continue
			}
			users++
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if path, ok := names[id.Name]; ok && !allowed[path][sel.Sel.Name] {
					t.Errorf("%s: %s.%s (%s) — the Hub must hold no age identity", fset.Position(sel.Pos()), id.Name, sel.Sel.Name, path)
				}
				return true
			})
		}
	}
	if users == 0 {
		t.Fatal("no file imports age: the walk found nothing to check")
	}
}

// Global Constraints: no template id in the Hub's AI code. The kind name
// litellm in ai_providers.go (Task 9: a litellm provider names an
// installed instance of the template whose id is the kind name) is a
// known exception and deliberately not in the list.
func TestGateFileHasNoTemplateIDs(t *testing.T) {
	ids := regexp.MustCompile(`(?i)gitea|grafana|homeassistant|librechat`)
	files, _ := filepath.Glob("ai*.go")
	more, _ := filepath.Glob(filepath.Join("..", "aigate", "*.go"))
	files = append(files, more...)
	n := 0
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		n++
		if loc := ids.FindString(string(mustRead(t, p))); loc != "" {
			t.Errorf("%s names template id %q", p, loc)
		}
	}
	if n < 4 {
		t.Fatalf("only %d files checked", n)
	}
}

// G74: the only group-readable files in the data directory are the five
// the readers need; any other is chmodded 0600 at Init (template
// checkouts under repos/ are left alone: apps bind-mount them).
func TestDataDirGroupReadable(t *testing.T) {
	g := newGateFixture(t, nil)
	write := func(rel string, mode os.FileMode) string {
		p := filepath.Join(g.data, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	files := map[string][2]os.FileMode{ // rel → {before, after}
		"state.yaml":               {0o644, 0o600},
		"env/wiki.env":             {0o640, 0o600},
		"audit.jsonl":              {0o604, 0o600},
		"ai/provider-secrets.json": {0o640, 0o600},
		"group-gate-policy.json":   {0o644, 0o644},
		"portal-apps.json":         {0o644, 0o644},
		"user-attributes.json":     {0o644, 0o644},
		"mcp-gate.json":            {0o644, 0o640},
		"mcp-credentials.json":     {0o600, 0o640},
		"overrides/mcp-gate.json":  {0o644, 0o600}, // a gate file's name elsewhere
		"repos/src/compose.yml":    {0o644, 0o644},
		"repos/src/conf/app.ini":   {0o644, 0o644},
		"settings/x/secrets.json":  {0o600, 0o600},
		"ops/gitea.json":           {0o620, 0o600},
	}
	for rel, m := range files {
		write(rel, m[0])
	}
	g.h.checkDataDirModes()
	for rel, m := range files {
		st, err := os.Stat(filepath.Join(g.data, rel))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != m[1] {
			t.Errorf("%s: mode %o, want %o", rel, st.Mode().Perm(), m[1])
		}
	}
	// Init runs it.
	p := write("state-copy.yaml", 0o644)
	g.h.Init()
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("Init left %o", st.Mode().Perm())
	}
}

// A Settings → AI save rewrites mcp-gate.json at once (master switch,
// clients, limits, origins).
func TestGateFileRewrittenOnAISettingsSave(t *testing.T) {
	g := newGateFixture(t, nil)
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	read := func() *aigate.File {
		f, err := aigate.DecodeFile(mustRead(t, filepath.Join(g.data, aigate.GateFileName)))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if !read().Enabled {
		t.Fatal("not enabled")
	}
	rpm := 77
	if err := g.h.SaveAISettings(AISettingsUpdate{Limits: &AILimitsUpdate{ToolCallsRPM: &rpm}}, aiAdmin); err != nil {
		t.Fatal(err)
	}
	if read().Limits.ToolCallsRPM != 77 {
		t.Error("limits not rewritten")
	}
	off := false
	if err := g.h.SaveAISettings(AISettingsUpdate{Enabled: &off}, aiAdmin); err != nil {
		t.Fatal(err)
	}
	if f := read(); f.Enabled || len(f.Resources) != 0 {
		t.Errorf("master switch off not written: %v %v", f.Enabled, urls(f))
	}
}

// ── fix round 1 ──────────────────────────────────────────

// Item 1: a credential or caller secret the gate would refuse once
// decrypted is refused before encryption, zeroed, never quoted, and
// nothing is written.
func TestCredentialValueRefused(t *testing.T) {
	g := newGateFixture(t, nil)
	c := aigate.Credential{Instance: "gitea", Companion: "gitea", User: "alice", ID: "7", MintedAt: aigate.At(time.Now())}
	for name, v := range map[string][]byte{
		"empty":   {},
		"64KiB+1": bytes.Repeat([]byte("a"), 64<<10+1),
		"newline": []byte("abc\ndef"),
		"NUL":     []byte("abc\x00def"),
		"DEL":     []byte("abc\x7fdef"),
		"tab":     []byte("abc\tdef"),
		"bad UTF": []byte("abc\xffdef"),
	} {
		buf := append([]byte(nil), v...)
		err := g.h.creds().Put(c, buf)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if len(v) > 3 && strings.Contains(err.Error(), string(v[:3])) {
			t.Errorf("%s: the error quotes the value: %v", name, err)
		}
		if !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Errorf("%s: not zeroed", name)
		}
		if err := g.h.creds().PutCallerSecret("wiki/wiki", append([]byte(nil), v...)); err == nil {
			t.Errorf("%s: caller secret accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(g.data, aigate.CredsFileName)); err == nil {
		t.Error("a refused value wrote the credentials file")
	}
	// The bounds themselves are accepted.
	if err := g.h.creds().Put(c, bytes.Repeat([]byte("a"), 64<<10)); err != nil {
		t.Errorf("64 KiB: %v", err)
	}
	if err := g.h.creds().Put(c, []byte("ünïcode-tøken")); err != nil {
		t.Errorf("UTF-8: %v", err)
	}
}

// Item 2 (ruling): with the directory down the file is rebuilt from state;
// populations come from the last file's resource of the same URL, a
// resource the last file lacks is left out, and every state change still
// reaches the gate.
func TestGateFileDirectoryDownFollowsState(t *testing.T) {
	g := newGateFixture(t, func(st *state.AppState) {
		st.AIInstances["wiki"] = state.AIInstance{} // off at first
	})
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	read := func() *aigate.File {
		f, err := aigate.DecodeFile(mustRead(t, filepath.Join(g.data, aigate.GateFileName)))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	first := read()
	gitea0 := resourceByURL(first, "https://gitea.example.com/mcp")
	if gitea0 == nil || resourceByURL(first, "https://wiki.example.com/mcp") != nil {
		t.Fatalf("first file: %v", urls(first))
	}
	// The directory goes down, and the people change meanwhile (unseen).
	g.people.addGroup("users_gitea", "carol")
	g.people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 502, Msg: "unreachable"} })
	// State changes: gitea's companion off, native's instance disabled,
	// wiki switched on (no previous entry), Claude unticked, Claude Code's
	// admin flag off (Claude's was the other one), Generic unhealthy.
	g.h.mu.Lock()
	g.h.st.AIInstances["gitea"] = state.AIInstance{Companions: map[string]state.AICompanion{"gitea": {Enabled: false, Mode: "read_write"}}}
	g.h.st.AIInstances["wiki"] = state.AIInstance{Companions: map[string]state.AICompanion{"wiki": {Enabled: true, Mode: "read_only"}}}
	g.h.st.Enabled = slices.DeleteFunc(slices.Clone(g.h.st.Enabled), func(s string) bool { return s == "native" })
	g.h.st.AI.Clients.Claude.Offered = false
	g.h.st.AI.Clients.ClaudeCode.Admin = false
	g.h.mu.Unlock()
	g.h.Discover()
	health := g.allHealthy()
	health[keycloak.AIClientIDs.Generic] = false
	g.h.SetAIClientHealth(health)
	if err := g.h.WritePolicy(); err == nil || !g.h.gateStale.Load() {
		t.Errorf("WritePolicy = %v, stale %v: want the directory error and a retry", err, g.h.gateStale.Load())
	}
	f := read()
	if !f.Enabled {
		t.Fatal("disabled")
	}
	for _, u := range []string{"https://gitea.example.com/mcp", "https://native.example.com/mcp", "https://wiki.example.com/mcp", "https://hub.example.com/mcp"} {
		if resourceByURL(f, u) != nil {
			t.Errorf("%s still listed with the directory down", u)
		}
	}
	code := keycloak.AIClientIDs.ClaudeCode
	want := sortedSet([]string{code, g.chatClient})
	if !slices.Equal(f.Clients, want) {
		t.Errorf("clients = %v, want %v", f.Clients, want)
	}
	all, all0 := resourceByURL(f, "https://mcp.example.com/mcp"), resourceByURL(first, "https://mcp.example.com/mcp")
	if all == nil || !slices.Equal(all.Population, all0.Population) || slices.Contains(all.Population, "carol") && !slices.Contains(all0.Population, "carol") || !slices.Equal(all.Clients, want) {
		t.Errorf("aggregate = %+v, want the last population %v and clients %v", all, all0.Population, want)
	}
	// Back: the directory's populations again.
	g.people.set(func(p *fakePeople) { p.err = nil })
	g.h.mu.Lock()
	g.h.st.AIInstances["gitea"] = state.AIInstance{Companions: map[string]state.AICompanion{"gitea": {Enabled: true, Mode: "read_write"}}}
	g.h.mu.Unlock()
	if err := g.h.WritePolicy(); err != nil || g.h.gateStale.Load() {
		t.Fatal(err)
	}
	if r := resourceByURL(read(), "https://gitea.example.com/mcp"); r == nil || !slices.Contains(r.Population, "carol") {
		t.Errorf("after recovery: %+v", r)
	}
}

// Item 2: a built file the gate's rules refuse is never written; the
// Hub writes enabled: false (no origins, clients or resources) instead
// of keeping the old file.
func TestGateFileRefusedWritesDisabled(t *testing.T) {
	g := newGateFixture(t, nil)
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	g.h.mu.Lock()
	g.h.st.AI.AllowedOrigins = []string{"http://not-https.example.org"} // the gate refuses it
	g.h.mu.Unlock()
	if err := g.h.WritePolicy(); err == nil {
		t.Error("WritePolicy hid the refused file")
	}
	f, err := aigate.DecodeFile(mustRead(t, filepath.Join(g.data, aigate.GateFileName)))
	if err != nil {
		t.Fatal(err)
	}
	if f.Enabled || len(f.Resources) != 0 || len(f.Clients) != 0 || len(f.AllowedOrigins) != 0 {
		t.Errorf("file = enabled %v resources %v clients %v origins %v", f.Enabled, urls(f), f.Clients, f.AllowedOrigins)
	}
}

// Item 3: a new gate recipient re-encrypts the caller secrets, though the
// value is unchanged.
func TestCallerSecretFollowsRecipient(t *testing.T) {
	g := newGateFixture(t, nil)
	envFile := filepath.Join(g.data, "env", "wiki.env")
	if err := os.WriteFile(envFile, []byte("MCP_SECRET='wiki-caller-secret-value'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	open := func(id age.Identity) string {
		cf, err := aigate.DecodeCredFile(mustRead(t, filepath.Join(g.data, aigate.CredsFileName)))
		if err != nil || len(cf.CallerSecrets) != 1 {
			t.Fatalf("creds: %v %+v", err, cf)
		}
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(cf.CallerSecrets[0].Age)), id)
		if err != nil {
			return ""
		}
		b, _ := io.ReadAll(r)
		return string(b)
	}
	if open(g.id) != "wiki-caller-secret-value" {
		t.Fatal("not encrypted to the first recipient")
	}
	if err := g.h.WritePolicy(); err != nil { // unchanged: not rewritten
		t.Fatal(err)
	}
	next, _ := age.GenerateX25519Identity()
	if err := os.WriteFile(g.recip, []byte(next.Recipient().String()+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if open(next) != "wiki-caller-secret-value" {
		t.Error("the caller secret wasn't re-encrypted to the new recipient")
	}
}

// Item 6: the three world-readable files keep 0644: group or other write
// bits are cleared.
func TestDataDirSharedFilesNotWritable(t *testing.T) {
	g := newGateFixture(t, nil)
	for _, name := range []string{"group-gate-policy.json", "portal-apps.json", "user-attributes.json"} {
		p := filepath.Join(g.data, name)
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	g.h.checkDataDirModes()
	for _, name := range []string{"group-gate-policy.json", "portal-apps.json", "user-attributes.json"} {
		if st, _ := os.Stat(filepath.Join(g.data, name)); st.Mode().Perm() != 0o644 {
			t.Errorf("%s: %o, want 0644", name, st.Mode().Perm())
		}
	}
}

// Item 9: the gate's username rule is exactly the Hub's, and every
// hostname the Hub accepts the gate accepts (the Hub is stricter only on
// single-label names).
func TestGateRulesMatchHub(t *testing.T) {
	long := strings.Repeat("a", 63)
	for _, s := range []string{"", "a", "alice", "Alice", "a.b", "a_b", "a-b", "-a", ".a", "_a", "a@b", "a+b", "a b", "bök", "Kim",
		strings.Repeat("a", 64), strings.Repeat("a", 65), "a\n", "1abc", "a..b", "a."} {
		if aigate.ValidUsername(s) != lldap.ValidUsername(s) {
			t.Errorf("username %q: gate %v, Hub %v", s, aigate.ValidUsername(s), lldap.ValidUsername(s))
		}
	}
	for _, s := range []string{"", "a", "example.com", "Example.com", "a.b.c", "a-b.c", "-a.b", "a-.b", "a..b", "a.", ".a", "a_b.c",
		long + ".com", long + "a.com", strings.Repeat(long+".", 4) + "com", "xn--bcher-kva.example", "1.2.3.4", "a b.c", "bück.de"} {
		// Every hostname the Hub accepts, the gate accepts; the only
		// difference is that the Hub also needs two labels (a dotless
		// name never reaches the file).
		gate, hub := aigate.ValidHostname(s), templates.ValidHostname(s)
		if hub && !gate || gate != hub && strings.Contains(s, ".") {
			t.Errorf("hostname %q: gate %v, Hub %v", s, gate, hub)
		}
	}
}

// ── fix round 2 ──────────────────────────────────────────

// Item 1: with the directory down, a switch to native sign-in still
// empties the population — nothing is carried over for an instance whose
// routes now give nobody Portcullis identity.
func TestGateFileDirectoryDownNativeSignIn(t *testing.T) {
	g := newGateFixture(t, func(st *state.AppState) { st.SignIn = map[string]string{} })
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	read := func() *aigate.File {
		f, err := aigate.DecodeFile(mustRead(t, filepath.Join(g.data, aigate.GateFileName)))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if r := resourceByURL(read(), "https://native.example.com/mcp"); r == nil || !slices.Equal(r.Population, []string{"alice"}) {
		t.Fatalf("gateway sign-in: %+v", r)
	}
	g.people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 502, Msg: "unreachable"} })
	g.h.mu.Lock()
	g.h.st.SignIn = map[string]string{"native": state.SignInNative}
	g.h.mu.Unlock()
	if err := g.h.WritePolicy(); err == nil {
		t.Error("the directory error was hidden")
	}
	r := resourceByURL(read(), "https://native.example.com/mcp")
	if r == nil || len(r.Population) != 0 || len(r.Expiring) != 0 || r.People != nil {
		t.Errorf("native sign-in with the directory down = %+v, want listed with nobody", r)
	}
}

// Item 2: a previous entry is carried over only when it is the same
// resource (kind, scope, instance, companion), not merely the same URL.
func TestGateFileDirectoryDownURLReassigned(t *testing.T) {
	g := newGateFixture(t, nil)
	if err := g.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(g.data, aigate.GateFileName)
	f, err := aigate.DecodeFile(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	// The last file had https://gitea.example.com/mcp as another
	// instance's companion (a hostname moved meanwhile).
	r := resourceByURL(f, "https://gitea.example.com/mcp")
	r.Instance, r.Scope, r.Upstream = "gitea-b", "mcp:gitea-b.gitea", "http://portcullis-mcp-gitea-b--gitea:8080/mcp"
	r.Population = []string{"alice", "bob", "carol"}
	if err := aigate.WriteFile(path, f); err != nil {
		t.Fatal(err)
	}
	g.people.set(func(p *fakePeople) { p.err = &directory.Error{Status: 502, Msg: "unreachable"} })
	if err := g.h.WritePolicy(); err == nil {
		t.Error("the directory error was hidden")
	}
	nf, err := aigate.DecodeFile(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if r := resourceByURL(nf, "https://gitea.example.com/mcp"); r != nil {
		t.Errorf("another instance's population carried over: %+v", r)
	}
	if resourceByURL(nf, "https://mcp.example.com/mcp") == nil {
		t.Error("the aggregate (same kind) wasn't carried over")
	}
}
