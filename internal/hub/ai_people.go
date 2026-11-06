package hub

import (
	"slices"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// My apps' AI parts (contract §5.1, plan 4 Task 21): per app, the
// caller's switched-on companions; at the top, the "all my apps"
// aggregate, the AI clients the admin offers and, for administrators,
// the Portcullis admin MCP. Everything comes from the current state
// (hosts included, so a hostname change moves the URLs); the whole ai
// key is absent while the master switch is off, the gate isn't present,
// or the caller has no AI resource (no companion, people MCP off).

// MyAppAI is an app's AI part for the caller.
type MyAppAI struct {
	Companions []MyCompanion `json:"companions"`
}

// MyCompanion is one switched-on companion the caller may use: URL the
// resource URL (§15.1; for app_oauth the app's own MCP route), Official
// = upstream official.
type MyCompanion struct {
	Name         string `json:"name"`
	Label        string `json:"label"`
	URL          string `json:"url"`
	IdentityMode string `json:"identity_mode"`
	Mode         string `json:"mode"`
	Official     bool   `json:"official"`
}

// MyAITop is the top-level ai of GET /api/me/apps.
type MyAITop struct {
	AggregateURL string      `json:"aggregate_url"`
	Clients      MyAIClients `json:"clients"`
	// AdminURL: lldap_admin members only, while the Portcullis admin MCP
	// is on and some listed client has the admin flag.
	AdminURL string `json:"admin_url,omitempty"`
}

// MyAIClients are the offered (and healthy) AI clients; nil = not
// offered.
type MyAIClients struct {
	Claude     *MyAIClient     `json:"claude,omitempty"`
	ClaudeCode *MyAIClaudeCode `json:"claude_code,omitempty"`
	Generic    *MyAIGeneric    `json:"generic,omitempty"`
}

// MyAIClient is the hosted Claude client.
type MyAIClient struct {
	ClientID string `json:"client_id"`
	Admin    bool   `json:"admin"`
}

// MyAIClaudeCode is the Claude Code client (fixed callback port).
type MyAIClaudeCode struct {
	ClientID     string `json:"client_id"`
	CallbackPort int    `json:"callback_port"`
	Admin        bool   `json:"admin"`
}

// MyAIGeneric is the client for other MCP clients.
type MyAIGeneric struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	Admin        bool     `json:"admin"`
}

// ClaudeCodeCallbackPort is the loopback port of portcullis-ai-claude-code's
// redirect URIs (§8).
const ClaudeCodeCallbackPort = 33418

// myAIOn: the ai key may appear at all — the master switch is on and the
// gate is present. gate is h.gatePresent() (read before mu). Caller holds
// mu.
func (h *Hub) myAIOnLocked(gate bool) bool {
	return gate && h.st.AI.Enabled
}

// myAppAILocked is t's AI part for a caller in its population (nil: no
// companion to show). A companion is shown only while it is on, its
// revoke_all isn't owed, it isn't pruned, its mode is one of its modes,
// the instance's policy allows AI (LoA ≤ 2) and its router has a
// hostname — any doubt leaves it out, as the gate file does. Caller
// holds mu.
func (h *Hub) myAppAILocked(t *templates.Template) *MyAppAI {
	if !t.Enabled || !t.HasAIMCP() || t.Manifest.Routerless() || h.instanceBusyLocked(t.ID) {
		return nil
	}
	switches := h.st.AIInstances[t.ID].Companions
	if len(switches) == 0 {
		return nil
	}
	if loa := policy.LoA(h.effectivePolicyLocked(t)); loa < 0 || loa > 2 {
		return nil
	}
	var out []MyCompanion
	for i := range t.Manifest.AI.MCP {
		c := &t.Manifest.AI.MCP[i]
		sw, ok := switches[c.Name]
		if !ok || !sw.Enabled || sw.RevokePending || sw.Pruned || !slices.Contains(c.Modes, sw.Mode) {
			continue
		}
		if c.Identity.Mode != templates.IdentityAppOAuth && !templates.AliasFits(t.ID, c.Name) {
			continue
		}
		host := NormalizeHost(t.Hosts[c.Router])
		if host == "" || !templates.ValidHostname(host) {
			continue
		}
		out = append(out, MyCompanion{Name: c.Name, Label: c.Label, URL: aigate.CompanionURL(host, c.EffectivePublicPath()),
			IdentityMode: c.Identity.Mode, Mode: sw.Mode, Official: c.Upstream == templates.UpstreamOfficial})
	}
	if len(out) == 0 {
		return nil
	}
	return &MyAppAI{Companions: out}
}

// myAITopLocked is the top-level ai for user (lowercase) given whether
// they have a companion: nil without an AI resource (no companion and the
// people MCP off) or outside LLDAP. Clients: offered and healthy
// (healthy: the last Keycloak pass, nil = none). Caller holds mu.
func (h *Hub) myAITopLocked(m *directory.Membership, user string, companion bool, healthy map[string]bool) *MyAITop {
	ai := h.st.AI
	if _, ok := m.Users[user]; !ok || !aigate.ValidUsername(user) {
		return nil
	}
	if !companion && !ai.PortcullisPeople {
		return nil
	}
	domain := NormalizeHost(h.cfg.Domain)
	if !templates.ValidHostname(domain) {
		return nil
	}
	top := &MyAITop{AggregateURL: aigate.AggregateURL(domain)}
	listed := func(id string, c state.AIClient) bool { return c.Offered && healthy[id] }
	admin := false
	if c := ai.Clients.Claude; listed(keycloak.AIClientIDs.Claude, c) {
		top.Clients.Claude = &MyAIClient{ClientID: keycloak.AIClientIDs.Claude, Admin: c.Admin}
		admin = admin || c.Admin
	}
	if c := ai.Clients.ClaudeCode; listed(keycloak.AIClientIDs.ClaudeCode, c) {
		top.Clients.ClaudeCode = &MyAIClaudeCode{ClientID: keycloak.AIClientIDs.ClaudeCode, CallbackPort: ClaudeCodeCallbackPort, Admin: c.Admin}
		admin = admin || c.Admin
	}
	if c := ai.Clients.Generic; listed(keycloak.AIClientIDs.Generic, c) {
		top.Clients.Generic = &MyAIGeneric{ClientID: keycloak.AIClientIDs.Generic, RedirectURIs: slices.Clone(keycloak.LoopbackRedirectURIs), Admin: c.Admin}
		admin = admin || c.Admin
	}
	if admin && ai.PortcullisAdmin && slices.Contains(groupMembers(m, lldap.AdminGroup), user) {
		top.AdminURL = aigate.AdminURL(domain)
	}
	return top
}
