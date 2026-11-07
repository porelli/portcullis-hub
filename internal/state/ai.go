package state

import (
	"fmt"
	"time"
)

// AI support (contract §15.11, §15.12): Settings → AI and the model
// provider definitions. Never a secret: provider secret values live only
// in <data>/ai/provider-secrets.json (ProviderSecrets holds when each was
// set).

// AISettings is state.yaml's ai.
type AISettings struct {
	// Enabled is the master switch "AI support".
	Enabled bool      `json:"enabled" yaml:"enabled"`
	Clients AIClients `json:"clients" yaml:"clients"`
	// PortcullisAdmin / PortcullisPeople: the Portcullis MCPs on
	// hub.<d>/mcp and people.<d>/mcp.
	PortcullisAdmin  bool `json:"portcullis_admin" yaml:"portcullis_admin"`
	PortcullisPeople bool `json:"portcullis_people" yaml:"portcullis_people"`
	// Connection length (§8): the AI clients' offline session idle and
	// max, in days.
	OfflineIdleDays int      `json:"offline_idle_days" yaml:"offline_idle_days"`
	OfflineMaxDays  int      `json:"offline_max_days" yaml:"offline_max_days"`
	Limits          AILimits `json:"limits" yaml:"limits"`
	// AllowedOrigins: https://<host>[:port] each, sorted.
	AllowedOrigins []string        `json:"allowed_origins" yaml:"allowed_origins"`
	Providers      []ModelProvider `json:"providers,omitempty" yaml:"providers,omitempty"`
	// ProviderSecrets: "<provider>.<field>" → when it was set. Never the
	// value.
	ProviderSecrets map[string]SecretMeta `json:"provider_secrets,omitempty" yaml:"provider_secrets,omitempty"`
}

// AIClients are the three AI client kinds of §8.
type AIClients struct {
	Claude     AIClient `json:"claude" yaml:"claude"`
	ClaudeCode AIClient `json:"claude_code" yaml:"claude_code"`
	Generic    AIClient `json:"generic" yaml:"generic"`
}

// AIClient: Offered = the Keycloak client exists while AI support is on;
// Admin = mcp:portcullis.admin is attached to it (default off: the admin
// enables it client by client).
type AIClient struct {
	Offered bool `json:"offered" yaml:"offered"`
	Admin   bool `json:"admin" yaml:"admin"`
}

// AILimits are the gate's per-person limits (§15.9).
type AILimits struct {
	ResourceRPM          int `json:"resource_rpm" yaml:"resource_rpm"`
	ResourceBurst        int `json:"resource_burst" yaml:"resource_burst"`
	PersonRPM            int `json:"person_rpm" yaml:"person_rpm"`
	ToolCallsRPM         int `json:"tool_calls_rpm" yaml:"tool_calls_rpm"`
	ConfirmationsPerHour int `json:"confirmations_per_hour" yaml:"confirmations_per_hour"`
	MintsPerMinute       int `json:"mints_per_minute" yaml:"mints_per_minute"`
	Fanout               int `json:"fanout" yaml:"fanout"`
}

// ModelProvider is one model provider of Settings → AI (§15.12). The
// fields a kind doesn't take are empty.
type ModelProvider struct {
	Name         string            `json:"name" yaml:"name"`
	Label        string            `json:"label" yaml:"label"`
	Kind         string            `json:"kind" yaml:"kind"`
	Instance     string            `json:"instance,omitempty" yaml:"instance,omitempty"`
	BaseURL      string            `json:"base_url,omitempty" yaml:"base_url,omitempty"`
	Region       string            `json:"region,omitempty" yaml:"region,omitempty"`
	InstanceName string            `json:"instance_name,omitempty" yaml:"instance_name,omitempty"`
	APIVersion   string            `json:"api_version,omitempty" yaml:"api_version,omitempty"`
	Deployments  map[string]string `json:"deployments,omitempty" yaml:"deployments,omitempty"`
	Models       ProviderModels    `json:"models" yaml:"models"`
	// Credentials: "admin" (the stored secrets) or "per_person".
	Credentials string `json:"credentials" yaml:"credentials"`
}

// ProviderModels: fetch the list from the provider (only kinds that
// allow it) and/or the admin's list.
type ProviderModels struct {
	Fetch bool     `json:"fetch" yaml:"fetch"`
	List  []string `json:"list,omitempty" yaml:"list,omitempty"`
}

// AIInstance is one instance's AI state (state.yaml ai_instances, §15.11).
// Companions: companion name → its switch and mode (Task 12's PUT
// /api/instances/{id}/ai writes it; Task 11's gate file reads it).
// Providers: an ai.chat instance's provider selection (§15.12; Task 23).
type AIInstance struct {
	Companions map[string]AICompanion `json:"companions,omitempty" yaml:"companions,omitempty"`
	Providers  []string               `json:"providers,omitempty" yaml:"providers,omitempty"`
}

// AICompanion is one companion's AI switch and the admin's mode
// (read_only or read_write; one of the companion's modes).
type AICompanion struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Mode    string `json:"mode" yaml:"mode"`
	// RevokePending: the companion's app-side credentials still need a
	// revoke_all (a switch or mode change while the instance was stopped,
	// a failed revoke_all at switch-off; Task 13b: a restore). While set
	// the companion is never rendered (alias, router, scale 1) nor listed
	// in mcp-gate.json; the next start runs revoke_all and clears it.
	RevokePending bool `json:"revoke_pending,omitempty" yaml:"revoke_pending,omitempty"`
	// OnChangePending: the template's ai.on_change is owed for the
	// current state (a switch or mode change while the instance was
	// stopped); the next start runs it, after an owed revoke_all.
	OnChangePending bool `json:"on_change_pending,omitempty" yaml:"on_change_pending,omitempty"`
	// IdentityMode and RevokeHook: the companion's identity mode and
	// revoke hook when it was last switched on (Task 13b, G33: a template
	// update that drops the companion or changes its mode is detected,
	// and the app-side credentials are revoked with the hook that minted
	// them).
	IdentityMode string `json:"identity_mode,omitempty" yaml:"identity_mode,omitempty"`
	RevokeHook   string `json:"revoke_hook,omitempty" yaml:"revoke_hook,omitempty"`
	// Pruned: switched off by a template update (pruneAI, G33); a
	// revoke_all with RevokeHook is still owed (its entries are revoking).
	// Cleared once it succeeded; while the template lacks that hook it
	// stays (AIRevokeProblems, the doctor's ai_credentials_revoking).
	Pruned bool `json:"pruned,omitempty" yaml:"pruned,omitempty"`
}

// Connection length bounds and defaults (§15.11), in days.
const (
	AIOfflineIdleMin     = 1
	AIOfflineIdleMax     = 30
	AIOfflineIdleDefault = 7
	AIOfflineMaxMin      = 1
	AIOfflineMaxMax      = 90
	AIOfflineMaxDefault  = 30
	// AIFanoutMax: the aggregate calls at most 4 upstreams in parallel
	// (§15.9; the gate refuses more).
	AIFanoutMax = 4
	// AILimitMax bounds every other limit (a positive integer, §15.4).
	AILimitMax = 1_000_000
)

// DefaultAISettings are a new install's (§15.11): AI support off, the
// three clients offered with the admin scope off, both Portcullis MCPs
// on, 7 / 30 days, the limits of §15.9, no origins, no providers.
func DefaultAISettings() AISettings {
	return AISettings{
		Clients: AIClients{
			Claude:     AIClient{Offered: true},
			ClaudeCode: AIClient{Offered: true},
			Generic:    AIClient{Offered: true},
		},
		PortcullisAdmin:  true,
		PortcullisPeople: true,
		OfflineIdleDays:  AIOfflineIdleDefault,
		OfflineMaxDays:   AIOfflineMaxDefault,
		Limits: AILimits{ResourceRPM: 120, ResourceBurst: 30, PersonRPM: 600, ToolCallsRPM: 60,
			ConfirmationsPerHour: 10, MintsPerMinute: 10, Fanout: AIFanoutMax},
		AllowedOrigins: []string{},
	}
}

// CheckDays refuses a connection length outside the bounds (idle 1–30,
// max 1–90, idle ≤ max).
func (a *AISettings) CheckDays() error {
	switch {
	case a.OfflineIdleDays < AIOfflineIdleMin || a.OfflineIdleDays > AIOfflineIdleMax:
		return fmt.Errorf("offline_idle_days must be %d–%d days (got %d)", AIOfflineIdleMin, AIOfflineIdleMax, a.OfflineIdleDays)
	case a.OfflineMaxDays < AIOfflineMaxMin || a.OfflineMaxDays > AIOfflineMaxMax:
		return fmt.Errorf("offline_max_days must be %d–%d days (got %d)", AIOfflineMaxMin, AIOfflineMaxMax, a.OfflineMaxDays)
	case a.OfflineIdleDays > a.OfflineMaxDays:
		return fmt.Errorf("offline_idle_days (%d) can't be longer than offline_max_days (%d)", a.OfflineIdleDays, a.OfflineMaxDays)
	}
	return nil
}

// CheckLimits refuses a limit that isn't a positive integer (fanout at
// most 4, the others at most AILimitMax).
func (l AILimits) CheckLimits() error {
	for _, c := range []struct {
		name string
		v    int
	}{
		{"resource_rpm", l.ResourceRPM}, {"resource_burst", l.ResourceBurst}, {"person_rpm", l.PersonRPM},
		{"tool_calls_rpm", l.ToolCallsRPM}, {"confirmations_per_hour", l.ConfirmationsPerHour},
		{"mints_per_minute", l.MintsPerMinute},
	} {
		if c.v < 1 || c.v > AILimitMax {
			return fmt.Errorf("limits.%s must be 1–%d (got %d)", c.name, AILimitMax, c.v)
		}
	}
	if l.Fanout < 1 || l.Fanout > AIFanoutMax {
		return fmt.Errorf("limits.fanout must be 1–%d (got %d)", AIFanoutMax, l.Fanout)
	}
	return nil
}

// ProviderSecretKey is ProviderSecrets' key of a provider's secret field.
func ProviderSecretKey(provider, field string) string { return provider + "." + field }

// providerSecretAt is when a provider secret was set (zero = not set).
func (a *AISettings) providerSecretAt(provider, field string) time.Time {
	return a.ProviderSecrets[ProviderSecretKey(provider, field)].UpdatedAt
}

// ProviderSecretSet reports whether a provider secret is set.
func (a *AISettings) ProviderSecretSet(provider, field string) bool {
	return !a.providerSecretAt(provider, field).IsZero()
}
