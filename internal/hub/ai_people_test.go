package hub

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 21: My apps' AI parts (contract §5.1): each app's
// companions for the caller and the top-level "ai" (the aggregate, the
// offered clients, the admin URL).

// newMyAIFixture: aiapp (tok app_token read_write, hdr identity_headers
// read_only) and oauthapp (oauth app_oauth) enabled with every companion
// on (oauthapp with the access group users_oauthapp); alice in both,
// root in lldap_admin, carol in nothing; Claude has the admin flag.
func newMyAIFixture(t *testing.T, seed func(*state.AppState)) *instAIFixture {
	t.Helper()
	a := newInstAIFixture(t, func(st *state.AppState) {
		st.AIInstances = map[string]state.AIInstance{
			"aiapp":    {Companions: map[string]state.AICompanion{"tok": {Enabled: true, Mode: "read_write"}, "hdr": {Enabled: true, Mode: "read_only"}}},
			"oauthapp": {Companions: map[string]state.AICompanion{"oauth": {Enabled: true, Mode: "read_write"}}},
		}
		if seed != nil {
			seed(st)
		}
	}, func(extra map[string][2]string) {
		m := extra["oauthapp"]
		m[0] = strings.Replace(m[0], "  group_access: true\n", "  group_access: true\n  access_group: users_oauthapp\n", 1)
		extra["oauthapp"] = m
	})
	a.setMintAnswer(nil)
	a.enable(t, "aiapp")
	a.enable(t, "oauthapp")
	return a
}

func myAIApps(t *testing.T, a *instAIFixture, user string) (*MyAppsView, string) {
	t.Helper()
	v, err := a.h.MyApps(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return v, string(b)
}

func appOf(v *MyAppsView, id string) *MyApp {
	for i := range v.Apps {
		if v.Apps[i].ID == id {
			return &v.Apps[i]
		}
	}
	return nil
}

func TestMyAppsAI(t *testing.T) {
	a := newMyAIFixture(t, nil)
	oauthHost := NormalizeHost(a.h.Template("oauthapp").Hosts["oauth"])
	if oauthHost == "" {
		t.Fatal("oauthapp has no host for its oauth router")
	}

	v, raw := myAIApps(t, a, "alice")
	// G13: both apps are listed for their AI parts alone (no per-person
	// values, entries or credentials).
	ai := appOf(v, "aiapp")
	if ai == nil || ai.AI == nil {
		t.Fatalf("alice's aiapp = %+v (%s)", ai, raw)
	}
	want := []MyCompanion{
		{Name: "tok", Label: "Tokens", URL: tokResource, IdentityMode: "app_token", Mode: "read_write", Official: true},
		{Name: "hdr", Label: "Headers", URL: "https://aiapp.example.com/hdr/mcp", IdentityMode: "identity_headers", Mode: "read_only", Official: true},
	}
	if !slices.Equal(ai.AI.Companions, want) {
		t.Errorf("aiapp companions = %+v, want %+v", ai.AI.Companions, want)
	}
	oa := appOf(v, "oauthapp")
	if oa == nil || oa.AI == nil || !slices.Equal(oa.AI.Companions, []MyCompanion{
		{Name: "oauth", Label: "OAuth App", URL: "https://" + oauthHost + "/mcp", IdentityMode: "app_oauth", Mode: "read_write", Official: true}}) {
		t.Errorf("alice's oauthapp = %+v", oa)
	}
	top := v.AI
	if top == nil {
		t.Fatalf("no top-level ai: %s", raw)
	}
	if top.AggregateURL != "https://mcp.example.com/mcp" || top.AdminURL != "" {
		t.Errorf("top = %+v", top)
	}
	c := top.Clients
	if c.Claude == nil || c.Claude.ClientID != keycloak.AIClientIDs.Claude || !c.Claude.Admin {
		t.Errorf("claude = %+v", c.Claude)
	}
	if c.ClaudeCode == nil || c.ClaudeCode.ClientID != keycloak.AIClientIDs.ClaudeCode || c.ClaudeCode.CallbackPort != 33418 || c.ClaudeCode.Admin {
		t.Errorf("claude_code = %+v", c.ClaudeCode)
	}
	if c.Generic == nil || c.Generic.ClientID != keycloak.AIClientIDs.Generic ||
		!slices.Equal(c.Generic.RedirectURIs, []string{"http://localhost:33418/callback", "http://127.0.0.1:33418/callback"}) || c.Generic.Admin {
		t.Errorf("generic = %+v", c.Generic)
	}
	// The wire form is the contract's.
	for _, s := range []string{`"ai":{"aggregate_url":"https://mcp.example.com/mcp","clients":{"claude":{"client_id":"portcullis-ai-claude","admin":true},` +
		`"claude_code":{"client_id":"portcullis-ai-claude-code","callback_port":33418,"admin":false},` +
		`"generic":{"client_id":"portcullis-ai-generic","redirect_uris":["http://localhost:33418/callback","http://127.0.0.1:33418/callback"],"admin":false}}}`,
		`"ai":{"companions":[{"name":"tok","label":"Tokens","url":"https://aiapp.example.com/mcp","identity_mode":"app_token","mode":"read_write","official":true},`} {
		if !strings.Contains(raw, s) {
			t.Errorf("alice's answer lacks %s:\n%s", s, raw)
		}
	}

	// root: an admin, in no app population — the people MCP is the AI
	// resource; admin_url because Claude has the admin flag.
	v, raw = myAIApps(t, a, "ROOT")
	if v.AI == nil || v.AI.AdminURL != "https://hub.example.com/mcp" || len(v.Apps) != 0 {
		t.Errorf("root = %s", raw)
	}
	// carol (in nothing): the aggregate only.
	if v, raw = myAIApps(t, a, "carol"); v.AI == nil || v.AI.AdminURL != "" || len(v.Apps) != 0 {
		t.Errorf("carol = %s", raw)
	}
	// Someone not in LLDAP gets nothing.
	if _, raw = myAIApps(t, a, "mallory"); strings.Contains(raw, `"ai"`) {
		t.Errorf("mallory = %s", raw)
	}

	// The admin MCP off, or no offered client with the admin flag: no
	// admin_url.
	setAI := func(f func(*state.AISettings)) {
		a.h.mu.Lock()
		f(&a.h.st.AI)
		a.h.mu.Unlock()
	}
	setAI(func(s *state.AISettings) { s.PortcullisAdmin = false })
	if v, _ := myAIApps(t, a, "root"); v.AI == nil || v.AI.AdminURL != "" {
		t.Errorf("admin MCP off: root's ai = %+v", v.AI)
	}
	setAI(func(s *state.AISettings) { s.PortcullisAdmin = true; s.Clients.Claude.Offered = false })
	if v, _ := myAIApps(t, a, "root"); v.AI == nil || v.AI.AdminURL != "" || v.AI.Clients.Claude != nil || v.AI.Clients.ClaudeCode == nil {
		t.Errorf("Claude not offered: root's ai = %+v", v.AI)
	}
	setAI(func(s *state.AISettings) { s.Clients.Claude.Offered = true })

	// An unhealthy client (Keycloak) is left out.
	a.h.SetAIClientHealth(map[string]bool{keycloak.AIClientIDs.Claude: true, keycloak.AIClientIDs.ClaudeCode: false, keycloak.AIClientIDs.Generic: true})
	if v, _ := myAIApps(t, a, "alice"); v.AI == nil || v.AI.Clients.ClaudeCode != nil || v.AI.Clients.Claude == nil || v.AI.Clients.Generic == nil {
		t.Errorf("claude_code unhealthy: %+v", v.AI)
	}
	a.h.SetAIClientHealth(map[string]bool{keycloak.AIClientIDs.Claude: true, keycloak.AIClientIDs.ClaudeCode: true, keycloak.AIClientIDs.Generic: true})

	// The people MCP off: carol has no AI resource → no ai key; alice
	// keeps hers (companions).
	setAI(func(s *state.AISettings) { s.PortcullisPeople = false })
	if _, raw := myAIApps(t, a, "carol"); strings.Contains(raw, `"ai"`) {
		t.Errorf("people MCP off: carol = %s", raw)
	}
	if v, _ := myAIApps(t, a, "alice"); v.AI == nil {
		t.Error("people MCP off: alice lost the aggregate")
	}
	setAI(func(s *state.AISettings) { s.PortcullisPeople = true })

	// A companion pending its revoke_all, or switched off, is not shown;
	// an app left with no AI part (and nothing else) is not listed.
	a.h.mu.Lock()
	a.h.st.AIInstances["aiapp"].Companions["hdr"] = state.AICompanion{Enabled: true, Mode: "read_only", RevokePending: true}
	a.h.st.AIInstances["oauthapp"].Companions["oauth"] = state.AICompanion{Enabled: false, Mode: "read_write"}
	a.h.mu.Unlock()
	v, raw = myAIApps(t, a, "alice")
	if ai := appOf(v, "aiapp"); ai == nil || ai.AI == nil || len(ai.AI.Companions) != 1 || ai.AI.Companions[0].Name != "tok" {
		t.Errorf("hdr revoke pending: %s", raw)
	}
	if appOf(v, "oauthapp") != nil {
		t.Errorf("oauthapp with AI off is still listed: %s", raw)
	}

	// The master switch off: no ai anywhere.
	setAI(func(s *state.AISettings) { s.Enabled = false })
	for _, u := range []string{"alice", "root", "carol"} {
		if _, raw := myAIApps(t, a, u); strings.Contains(raw, `"ai"`) {
			t.Errorf("master off: %s = %s", u, raw)
		}
	}
	setAI(func(s *state.AISettings) { s.Enabled = true })

	// No gate (its recipient file gone): no ai anywhere.
	if err := os.Remove(a.h.cfg.MCPGateRecipientFile); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "root"} {
		if _, raw := myAIApps(t, a, u); strings.Contains(raw, `"ai"`) {
			t.Errorf("no gate: %s = %s", u, raw)
		}
	}
}

// TestMyAppsAIPopulation: an app's AI part is only for its population;
// someone else sees neither the app nor its companions.
func TestMyAppsAIPopulation(t *testing.T) {
	a := newMyAIFixture(t, nil)
	a.people.addGroup("users_aiapp", "alice", "bob")
	v, raw := myAIApps(t, a, "bob")
	if ai := appOf(v, "aiapp"); ai == nil || ai.AI == nil || len(ai.AI.Companions) != 2 {
		t.Errorf("bob's aiapp: %s", raw)
	}
	if appOf(v, "oauthapp") != nil || strings.Contains(raw, "OAuth App") {
		t.Errorf("bob (not in users_oauthapp) sees oauthapp: %s", raw)
	}
}
