package hub

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Settings → AI (contract §15.11): the master switch, the offered AI
// clients and their admin flag, the Portcullis MCPs, the connection
// length, the gate's limits and the allowed origins. Stored in
// state.yaml ai (never a secret). Plan 4 Task 9 stores and validates
// them; the Keycloak clients, scopes and gate files that follow them are
// later tasks' (T10, T11).

// MaxAIOrigins is the most allowed origins.
const MaxAIOrigins = 64

// AISettingsView is GET /api/ai/settings.
type AISettingsView struct {
	Enabled          bool            `json:"enabled"`
	GatePresent      bool            `json:"gate_present"`
	Clients          state.AIClients `json:"clients"`
	PortcullisAdmin  bool            `json:"portcullis_admin"`
	PortcullisPeople bool            `json:"portcullis_people"`
	OfflineIdleDays  int             `json:"offline_idle_days"`
	OfflineMaxDays   int             `json:"offline_max_days"`
	Limits           state.AILimits  `json:"limits"`
	AllowedOrigins   []string        `json:"allowed_origins"`
}

// AISettingsUpdate is PUT /api/ai/settings: only what changed (nil =
// unchanged).
type AISettingsUpdate struct {
	Enabled          *bool            `json:"enabled"`
	Clients          *AIClientsUpdate `json:"clients"`
	PortcullisAdmin  *bool            `json:"portcullis_admin"`
	PortcullisPeople *bool            `json:"portcullis_people"`
	OfflineIdleDays  *int             `json:"offline_idle_days"`
	OfflineMaxDays   *int             `json:"offline_max_days"`
	Limits           *AILimitsUpdate  `json:"limits"`
	AllowedOrigins   *[]string        `json:"allowed_origins"`
}

// AIClientsUpdate: per client kind, what changed.
type AIClientsUpdate struct {
	Claude     *AIClientUpdate `json:"claude"`
	ClaudeCode *AIClientUpdate `json:"claude_code"`
	Generic    *AIClientUpdate `json:"generic"`
}

// AIClientUpdate: a client kind's offered / admin flags.
type AIClientUpdate struct {
	Offered *bool `json:"offered"`
	Admin   *bool `json:"admin"`
}

// AILimitsUpdate: the limits that changed.
type AILimitsUpdate struct {
	ResourceRPM          *int `json:"resource_rpm"`
	ResourceBurst        *int `json:"resource_burst"`
	PersonRPM            *int `json:"person_rpm"`
	ToolCallsRPM         *int `json:"tool_calls_rpm"`
	ConfirmationsPerHour *int `json:"confirmations_per_hour"`
	MintsPerMinute       *int `json:"mints_per_minute"`
	Fanout               *int `json:"fanout"`
}

// AISettings is Settings → AI as stored (a new install: the defaults).
func (h *Hub) AISettings() AISettingsView {
	h.mu.RLock()
	a := h.st.AI
	h.mu.RUnlock()
	return AISettingsView{
		Enabled: a.Enabled, GatePresent: h.gatePresent(), Clients: a.Clients,
		PortcullisAdmin: a.PortcullisAdmin, PortcullisPeople: a.PortcullisPeople,
		OfflineIdleDays: a.OfflineIdleDays, OfflineMaxDays: a.OfflineMaxDays,
		Limits: a.Limits, AllowedOrigins: append([]string{}, a.AllowedOrigins...),
	}
}

// gatePresent: the gate's age recipient file is readable and not empty
// (§15.4 "Without the gate").
func (h *Hub) gatePresent() bool {
	if h.cfg.MCPGateRecipientFile == "" {
		return false
	}
	st, err := os.Stat(h.cfg.MCPGateRecipientFile)
	if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return false
	}
	f, err := os.Open(h.cfg.MCPGateRecipientFile)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// SaveAISettings applies u (400 outside the bounds: idle 1–30, max 1–90
// days, idle ≤ max, limits positive (fanout ≤ 4), origins
// https://<host>[:port]); no actor 401. Audited settings.ai with the
// changed keys ("key: before -> after", refusals "refused"), after mu;
// nothing changed = no entry.
func (h *Hub) SaveAISettings(u AISettingsUpdate, actor directory.Actor) error {
	changes, err := h.saveAISettings(u, actor)
	if err != nil || len(changes) > 0 {
		h.auditAI(actor, "settings.ai", "ai", strings.Join(changes, ", "), err)
	}
	if err == nil && len(changes) > 0 {
		// The gate file follows at once (contract §15.4); its failure is
		// logged and retried by the directory sync loop.
		h.writePolicyLogged()
	}
	return err
}

func (h *Hub) saveAISettings(u AISettingsUpdate, actor directory.Actor) ([]string, error) {
	if err := checkAIActor(actor); err != nil {
		return nil, err
	}
	var origins []string
	if u.AllowedOrigins != nil {
		var err error
		if origins, err = normalizeOrigins(*u.AllowedOrigins); err != nil {
			return nil, statusErr(http.StatusBadRequest, "allowed_origins: %v", err)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	before := h.st.AI
	next := before
	setBool(&next.Enabled, u.Enabled)
	setBool(&next.PortcullisAdmin, u.PortcullisAdmin)
	setBool(&next.PortcullisPeople, u.PortcullisPeople)
	if c := u.Clients; c != nil {
		setClient(&next.Clients.Claude, c.Claude)
		setClient(&next.Clients.ClaudeCode, c.ClaudeCode)
		setClient(&next.Clients.Generic, c.Generic)
	}
	setInt(&next.OfflineIdleDays, u.OfflineIdleDays)
	setInt(&next.OfflineMaxDays, u.OfflineMaxDays)
	if l := u.Limits; l != nil {
		setInt(&next.Limits.ResourceRPM, l.ResourceRPM)
		setInt(&next.Limits.ResourceBurst, l.ResourceBurst)
		setInt(&next.Limits.PersonRPM, l.PersonRPM)
		setInt(&next.Limits.ToolCallsRPM, l.ToolCallsRPM)
		setInt(&next.Limits.ConfirmationsPerHour, l.ConfirmationsPerHour)
		setInt(&next.Limits.MintsPerMinute, l.MintsPerMinute)
		setInt(&next.Limits.Fanout, l.Fanout)
	}
	if u.AllowedOrigins != nil {
		next.AllowedOrigins = origins
	}
	if err := next.CheckDays(); err != nil {
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}
	if err := next.Limits.CheckLimits(); err != nil {
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}
	changes := aiSettingChanges(before, next)
	if len(changes) == 0 {
		return nil, nil
	}
	h.st.AI = next
	if err := h.saveStateLocked(); err != nil {
		h.st.AI = before
		return nil, err
	}
	return changes, nil
}

// checkAIActor: a signed-in, well-attributed actor (401 / 403).
func checkAIActor(actor directory.Actor) error {
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusUnauthorized, "changing AI settings needs a signed-in admin")
	}
	if err := actor.Check(); err != nil {
		return statusErr(http.StatusForbidden, "%v", err)
	}
	return nil
}

func setBool(dst *bool, v *bool) {
	if v != nil {
		*dst = *v
	}
}

func setInt(dst *int, v *int) {
	if v != nil {
		*dst = *v
	}
}

func setClient(dst *state.AIClient, u *AIClientUpdate) {
	if u != nil {
		setBool(&dst.Offered, u.Offered)
		setBool(&dst.Admin, u.Admin)
	}
}

// aiSettingKeys flattens the settings to "key" → value text, in the
// API's key names.
func aiSettingKeys(a state.AISettings) [][2]string {
	b := strconv.FormatBool
	n := strconv.Itoa
	return [][2]string{
		{"enabled", b(a.Enabled)},
		{"clients.claude.offered", b(a.Clients.Claude.Offered)},
		{"clients.claude.admin", b(a.Clients.Claude.Admin)},
		{"clients.claude_code.offered", b(a.Clients.ClaudeCode.Offered)},
		{"clients.claude_code.admin", b(a.Clients.ClaudeCode.Admin)},
		{"clients.generic.offered", b(a.Clients.Generic.Offered)},
		{"clients.generic.admin", b(a.Clients.Generic.Admin)},
		{"portcullis_admin", b(a.PortcullisAdmin)},
		{"portcullis_people", b(a.PortcullisPeople)},
		{"offline_idle_days", n(a.OfflineIdleDays)},
		{"offline_max_days", n(a.OfflineMaxDays)},
		{"limits.resource_rpm", n(a.Limits.ResourceRPM)},
		{"limits.resource_burst", n(a.Limits.ResourceBurst)},
		{"limits.person_rpm", n(a.Limits.PersonRPM)},
		{"limits.tool_calls_rpm", n(a.Limits.ToolCallsRPM)},
		{"limits.confirmations_per_hour", n(a.Limits.ConfirmationsPerHour)},
		{"limits.mints_per_minute", n(a.Limits.MintsPerMinute)},
		{"limits.fanout", n(a.Limits.Fanout)},
		{"allowed_origins", "[" + strings.Join(a.AllowedOrigins, " ") + "]"},
	}
}

// aiSettingChanges are the keys whose value differs, "key: a -> b".
func aiSettingChanges(before, after state.AISettings) []string {
	bk, ak := aiSettingKeys(before), aiSettingKeys(after)
	var out []string
	for i := range bk {
		if bk[i][1] != ak[i][1] {
			out = append(out, fmt.Sprintf("%s: %s -> %s", bk[i][0], bk[i][1], ak[i][1]))
		}
	}
	return out
}

// normalizeOrigins checks each origin (https://<host>[:port]: no user,
// path, query or fragment; a valid hostname; port 1–65535), lowercases
// it and sorts the list; duplicates and more than MaxAIOrigins refused.
func normalizeOrigins(list []string) ([]string, error) {
	if len(list) > MaxAIOrigins {
		return nil, fmt.Errorf("at most %d origins (got %d)", MaxAIOrigins, len(list))
	}
	out := make([]string, 0, len(list))
	for _, o := range list {
		n, ok := normalizeOrigin(o)
		if !ok {
			return nil, fmt.Errorf("%s is not an origin of the form https://<host>[:port]", clipQuoted(o))
		}
		if slices.Contains(out, n) {
			return nil, fmt.Errorf("%s is listed twice", clipQuoted(o))
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

func normalizeOrigin(s string) (string, bool) {
	if templates.HasControlChars(s) || strings.ContainsAny(s, " \t") {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if !templates.ValidHostname(host) {
		return "", false
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return "", false
		}
		return "https://" + host + ":" + p, true
	}
	return "https://" + host, true
}

// clipQuoted is s quoted, at most 64 bytes of it.
func clipQuoted(s string) string {
	if len(s) > 64 {
		s = s[:64] + "…"
	}
	return strconv.Quote(s)
}
