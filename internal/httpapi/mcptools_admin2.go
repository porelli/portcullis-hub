package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

// The Portcullis MCP's admin tools, part 2 (plan 4 Task 17b; contract
// §15.10–15.11, spec call 25): catalog and sources, backups, domains, AI,
// Hub settings and their G15 tools. As in part 1, each tool's Run calls
// the Server work its HTTP twin's handler calls (addSource, startRestore,
// updateInstanceAI, …: the same Hub method with the same checks and
// audit, attributed via ai and the AI client, the consumed confirmation
// in the detail). Secrets never pass through the AI: domain tokens and
// provider secrets are U tools (the Hub's form, then a check of what the
// Hub stores now), results show provider secrets as {set, updated_at}.

func init() {
	for k, why := range map[string]string{
		"restore_as.hosts":                "host router → hostname (the routers the archived template declares)",
		"add_model_provider.deployments":  "Azure deployment → model name (names the admin chose; never a secret: the provider has no secret field)",
		"save_model_provider.deployments": "Azure deployment → model name (names the admin chose; never a secret: the provider has no secret field)",
	} {
		mcpFreeFormAllow[k] = why
	}
}

// Argument types (part 2).
type (
	templateArgs struct {
		ID string `json:"id" jsonschema:"the template id"`
	}
	sourceArgs struct {
		Name string `json:"name" jsonschema:"the source's name (lowercase letters, digits, - and _)"`
		URL  string `json:"url" jsonschema:"the git repository (https://, http://, ssh:// or user@host:path; no credentials in it)"`
	}
	sourceRefArgs struct {
		Name string `json:"name" jsonschema:"the source's name"`
	}
	restoreArgs struct {
		ID      string `json:"id" jsonschema:"the instance id"`
		Archive string `json:"archive" jsonschema:"the archive, <instance-id>/<YYYYMMDDTHHMMSSZ>.tar (list_backups)"`
	}
	restoreAsArgs struct {
		Archive string            `json:"archive" jsonschema:"the archive, <instance-id>/<YYYYMMDDTHHMMSSZ>.tar (list_backups_all)"`
		ID      string            `json:"id" jsonschema:"the new instance id"`
		Hosts   map[string]string `json:"hosts,omitempty" jsonschema:"host router → hostname (default: the new id's hostnames)"`
	}
	enrollArgs struct {
		Name     string `json:"name" jsonschema:"the domain or subdomain to enroll"`
		Provider string `json:"provider,omitempty" jsonschema:"the DNS provider to pre-select on the form (cloudflare, porkbun, route53, digitalocean, hetzner)"`
	}
	domainArgs struct {
		Name string `json:"name" jsonschema:"the enrolled domain"`
	}
	aiSupportArgs struct {
		ID        string `json:"id" jsonschema:"the instance id"`
		Companion string `json:"companion" jsonschema:"the companion's name (ai_status lists them)"`
		Enabled   bool   `json:"enabled" jsonschema:"true switches it on (needs your confirmation in the browser), false off"`
	}
	aiProvidersArgs struct {
		ID        string   `json:"id" jsonschema:"the AI page instance id"`
		Providers []string `json:"providers" jsonschema:"the model provider names to select (list_model_providers lists them); the whole selection, [] for none"`
	}
	aiModeArgs struct {
		ID        string `json:"id" jsonschema:"the instance id"`
		Companion string `json:"companion" jsonschema:"the companion's name"`
		Mode      string `json:"mode" jsonschema:"read_only, or read_write (needs your confirmation in the browser)"`
	}
	revokeAIArgs struct {
		ID        string `json:"id" jsonschema:"the instance id"`
		Companion string `json:"companion" jsonschema:"the companion's name"`
		User      string `json:"user,omitempty" jsonschema:"one person's username (default: everyone)"`
	}
	activityArgs struct {
		Instance string `json:"instance,omitempty" jsonschema:"only this instance's lines"`
		User     string `json:"user,omitempty" jsonschema:"only this person's lines"`
		N        int    `json:"n,omitempty" jsonschema:"how many lines, newest first, 1-200 (default 50)"`
	}
	providerArgs struct {
		Name         string               `json:"name" jsonschema:"the provider's name (^[a-z][a-z0-9-]{0,30}$)"`
		Label        string               `json:"label" jsonschema:"what people see (one line, at most 64 characters)"`
		Kind         string               `json:"kind" jsonschema:"litellm, openai_compatible, anthropic, openai, google, bedrock or azure_openai"`
		Instance     string               `json:"instance,omitempty" jsonschema:"litellm: the installed LiteLLM instance"`
		BaseURL      string               `json:"base_url,omitempty" jsonschema:"the API's base URL (where model traffic goes)"`
		Region       string               `json:"region,omitempty" jsonschema:"bedrock: the AWS region"`
		InstanceName string               `json:"instance_name,omitempty" jsonschema:"azure_openai: the resource name"`
		APIVersion   string               `json:"api_version,omitempty" jsonschema:"azure_openai: the API version"`
		Deployments  map[string]string    `json:"deployments,omitempty" jsonschema:"azure_openai: deployment → model"`
		Models       state.ProviderModels `json:"models,omitempty" jsonschema:"{fetch, list}: fetch the model list (litellm, openai_compatible, openai) and/or list them"`
		Credentials  string               `json:"credentials,omitempty" jsonschema:"admin (the secrets set on the Hub, default) or per_person"`
	}
	providerRefArgs struct {
		Name string `json:"name" jsonschema:"the provider's name"`
	}
	providerFieldArgs struct {
		Name  string `json:"name" jsonschema:"the provider's name"`
		Field string `json:"field" jsonschema:"the secret field (list_model_providers shows each provider's)"`
	}
	defaultPolicyArgs struct {
		Policy policy.AuthPolicy `json:"policy" jsonschema:"the Hub default sign-in policy {factors, op}"`
	}
	// hubSettingsArgs is hub.AISettingsUpdate's schema (every field
	// optional: only what changes); Run decodes the arguments into
	// hub.AISettingsUpdate itself (the same JSON names).
	hubSettingsArgs struct {
		Enabled          *bool          `json:"enabled,omitempty" jsonschema:"the master switch (turning it on needs your confirmation)"`
		Clients          *aiClientsArgs `json:"clients,omitempty" jsonschema:"per AI client kind {offered, admin} (any change needs your confirmation)"`
		PortcullisAdmin  *bool          `json:"portcullis_admin,omitempty" jsonschema:"false turns the Portcullis admin MCP off; true is refused (only on the Hub's page)"`
		PortcullisPeople *bool          `json:"portcullis_people,omitempty" jsonschema:"the Portcullis people MCP (turning it on needs your confirmation)"`
		OfflineIdleDays  *int           `json:"offline_idle_days,omitempty" jsonschema:"days an unused AI connection lasts, 1-30"`
		OfflineMaxDays   *int           `json:"offline_max_days,omitempty" jsonschema:"days an AI connection lasts at most, 1-90"`
		Limits           *aiLimitsArgs  `json:"limits,omitempty" jsonschema:"the gate's per-person limits (only what changes)"`
		AllowedOrigins   *[]string      `json:"allowed_origins,omitempty" jsonschema:"browser origins https://<host>[:port] AI requests may come from (any change needs your confirmation)"`
	}
	aiClientsArgs struct {
		Claude     *aiClientArgs `json:"claude,omitempty"`
		ClaudeCode *aiClientArgs `json:"claude_code,omitempty"`
		Generic    *aiClientArgs `json:"generic,omitempty"`
	}
	aiClientArgs struct {
		Offered *bool `json:"offered,omitempty" jsonschema:"offered to people"`
		Admin   *bool `json:"admin,omitempty" jsonschema:"may use the Portcullis admin MCP"`
	}
	aiLimitsArgs struct {
		ResourceRPM          *int `json:"resource_rpm,omitempty"`
		ResourceBurst        *int `json:"resource_burst,omitempty"`
		PersonRPM            *int `json:"person_rpm,omitempty"`
		ToolCallsRPM         *int `json:"tool_calls_rpm,omitempty"`
		ConfirmationsPerHour *int `json:"confirmations_per_hour,omitempty"`
		MintsPerMinute       *int `json:"mints_per_minute,omitempty"`
		Fanout               *int `json:"fanout,omitempty"`
	}
	staleArgs struct {
		Username string `json:"username" jsonschema:"the username of the stale Keycloak record"`
	}
)

// model is the provider definition the arguments stand for.
func (a providerArgs) model() state.ModelProvider {
	return state.ModelProvider{Name: a.Name, Label: a.Label, Kind: a.Kind, Instance: a.Instance, BaseURL: a.BaseURL,
		Region: a.Region, InstanceName: a.InstanceName, APIVersion: a.APIVersion, Deployments: a.Deployments,
		Models: a.Models, Credentials: a.Credentials}
}

// registerAdminTools2 registers part 2 of the admin tools.
func (s *Server) registerAdminTools2() {
	for _, t := range []Tool{
		// ── Catalog and sources ──
		admin("list_templates", "Every template in the catalog: id, name, category, single or multi instance, its source, whether its default instance is enabled and its instances.",
			ClassRead, "/api/templates", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				out := []map[string]any{}
				for _, t := range s.Hub.Templates() {
					out = append(out, map[string]any{"id": t.ID, "name": t.Manifest.Name, "category": t.Manifest.Category,
						"instances_mode": t.Manifest.Instances, "source": t.Source, "enabled": t.Enabled, "instances": t.Instances,
						"hosts": t.Hosts})
				}
				return out, nil
			}),
		admin("get_template", "One template: its manifest (secret defaults left out), hostnames, host routers and instances.",
			ClassRead, "/api/templates", "", func(_ context.Context, _ directory.Actor, in templateArgs) (any, error) {
				for _, t := range s.Hub.Templates() {
					if t.ID == in.ID {
						m, err := manifestView(t.Manifest)
						if err != nil {
							return nil, err
						}
						return map[string]any{"id": t.ID, "source": t.Source, "enabled": t.Enabled, "manifest": m,
							"host_routers": t.HostRouters, "hosts": t.Hosts, "instances": t.Instances}, nil
					}
				}
				return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("template not found: " + in.ID)}
			}),
		admin("list_sources", "The template sources (git repositories; URLs without user info or query) and the last sync's outcome.",
			ClassRead, "/api/sources", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				out := []map[string]string{}
				for _, src := range s.Hub.Sources() {
					u := ""
					if src.URL != "" {
						u = sourceURLDetail(src.URL)
					}
					out = append(out, map[string]string{"name": src.Name, "url": u})
				}
				return map[string]any{"sources": out, "last_sync": s.Hub.SourceSync()}, nil
			}),
		admin("sync_sources", "Pull every template source now (fast-forward only; a version that would leave an enabled app without its template is rolled back) and rediscover the templates.",
			ClassWrite, "/api/sources/sync", "source.sync", func(_ context.Context, a directory.Actor, _ noArgs) (any, error) {
				return s.syncSources(a)
			}),
		{Name: "add_source", Description: "Add a template source (a git repository): its templates join the catalog. Always needs your confirmation in the browser: a source decides what apps can run. A URL carrying credentials is refused (add it on the Hub's page).",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "/api/sources/add", Audit: "source.add", In: sourceArgs{},
			Typed: nameOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[sourceArgs](args)
				return []string{"Adds the template source " + a.Name + " (" + sourceDisplay(a.URL) + "): its templates join the catalog and can be installed; a later sync pulls whatever the repository then holds."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[sourceArgs](args)
				if urlHasCredentials(a.URL) {
					return nil, badArg("the URL carries credentials: secrets never pass through the AI; add the source on the Hub's page (" + s.mcpScope(ScopeAdmin).home + "#sources)")
				}
				return s.addSource(toolActor(ctx, c), a.Name, a.URL)
			}},
		{Name: "remove_source", Description: "Remove a template source: its enabled apps are disabled first, then its templates leave the catalog (needs your confirmation in the browser).",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "/api/sources/remove", Audit: "source.remove", In: sourceRefArgs{},
			Typed: nameOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				n := nameOf(args)
				return []string{"Removes the template source " + n + ": every enabled app from it is disabled (stopped) first, and its templates leave the catalog."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				return s.removeSource(toolActor(ctx, c), nameOf(args))
			}},
		// ── Backups ──
		admin("list_backups", "An instance's backups, newest first.",
			ClassRead, "GET /api/instances/{id}/backups", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.listBackups(in.ID)
			}),
		admin("list_backups_all", "Every backup, deleted instances' included, newest first.",
			ClassRead, "GET /api/backups", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.listBackups("")
			}),
		admin("backup_instance", "Back up an instance now (a running one is stopped while its volumes are copied, then started again). Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			ClassWrite, "POST /api/instances/{id}/backups", "instance.backup", func(_ context.Context, a directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				op, err := s.startBackup(a, in.ID)
				if err != nil {
					return nil, err
				}
				return acceptedBody(op), nil
			}),
		{Name: "restore_instance", Description: "Restore an instance from one of its backups (a backup of its current state is taken first; its volumes, env, custom override and settings are replaced; hostnames kept). Needs your confirmation in the browser. Runs in the background: see wait_for_op.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/instances/{id}/restore", Audit: "instance.restore", In: restoreArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[restoreArgs](args)
				return []string{"Takes a backup of " + a.ID + ", then replaces its volumes, env, custom override and settings with the archive " + a.Archive + " (its hostnames are kept); an enabled instance restarts.",
					"Whatever changed since that archive — data and settings, access settings included — is replaced (the pre-restore backup keeps it)."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[restoreArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				op, err := s.startRestore(toolActor(ctx, c), a.ID, a.Archive)
				if err != nil {
					return nil, err
				}
				return acceptedBody(op), nil
			}},
		{Name: "restore_as", Description: "Restore a backup into a new instance (created stopped; its groups are created, its data and settings — access settings included — come from the archive). Needs your confirmation in the browser. Runs in the background: see wait_for_op on the new id.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/instances/restore", Audit: "instance.restore", In: restoreAsArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[restoreAsArgs](args)
				return []string{"Creates the instance " + a.ID + " from the archive " + a.Archive + ": its data, settings, sign-in policy, public access and per-person values come from the archive; its groups users_" + a.ID + " / admin_" + a.ID + " are created.",
					"It is created stopped; enabling it later starts it with what the archive held (path settings share the archived host folders)."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[restoreAsArgs](args)
				hosts := a.Hosts
				if len(hosts) == 0 {
					hosts = nil
				}
				op, err := s.startRestoreAs(toolActor(ctx, c), a.Archive, a.ID, hosts)
				if err != nil {
					return nil, err
				}
				return acceptedBody(op), nil
			}},
		// ── Domains ──
		admin("list_domains", "The enrolled domains: provider, records OK, certificate validity, state and last error (the last known list, with the reason, while the domains service can't be reached).",
			ClassRead, "GET /api/domains", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return s.domainsView(ctx), nil
			}),
		{Name: "enroll_domain", Description: "Enroll a domain for app hostnames: the DNS provider's API token is entered on the Hub's Domains page, never in the chat. After you submitted the form, this reports whether the domain is enrolled.",
			Class: ClassSecret, Scope: ScopeAdmin, Twin: "POST /api/domains", In: enrollArgs{},
			SecretForm: func(args json.RawMessage) string {
				a, _ := decode[enrollArgs](args)
				return s.domainForm(url.Values{"enroll": {hub.NormalizeHost(a.Name)}, "provider": {a.Provider}})
			},
			Run: func(ctx context.Context, _ *directory.Caller, args json.RawMessage) (any, error) {
				// The accept is the client's word: what the Hub knows now.
				a, _ := decode[enrollArgs](args)
				return s.domainCheck(ctx, hub.NormalizeHost(a.Name), "")
			}},
		{Name: "replace_domain_token", Description: "Replace an enrolled domain's DNS provider token: the new token is entered on the Hub's Domains page, never in the chat. After you submitted it, this reports the domain's state and the last recorded replacement.",
			Class: ClassSecret, Scope: ScopeAdmin, Twin: "POST /api/domains/{name}/token", In: domainArgs{},
			SecretForm: func(args json.RawMessage) string {
				return s.domainForm(url.Values{"token": {hub.NormalizeHost(nameOf(args))}})
			},
			Run: func(ctx context.Context, _ *directory.Caller, args json.RawMessage) (any, error) {
				return s.domainCheck(ctx, hub.NormalizeHost(nameOf(args)), "domain.token")
			}},
		{Name: "delete_domain", Description: "Remove an enrolled domain (its records and certificate go; refused while any instance has a hostname on it). Needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/domains/{name}", Audit: "domain.delete", In: domainArgs{},
			Typed: func(args json.RawMessage) string { return hub.NormalizeHost(nameOf(args)) },
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				return []string{"Removes the domain " + hub.NormalizeHost(nameOf(args)) + ": its DNS records and certificate are removed and no new hostname can go on it."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				warning, err := s.deleteDomain(ctx, toolActor(ctx, c), nameOf(args))
				if err != nil {
					return nil, err
				}
				out := map[string]string{"status": "removed", "name": hub.NormalizeHost(nameOf(args))}
				if warning != "" {
					out["warning"] = warning
				}
				return out, nil
			}},
		// ── AI ──
		admin("ai_status", "An instance's AI support: whether it is supported or refused (and why), the master switch, and each companion (mode, status, population, credentials, last error).",
			ClassRead, "GET /api/instances/{id}/ai", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.Hub.InstanceAI(in.ID)
			}),
		perCall(admin("set_ai_support", "Switch a companion (an app's MCP server) on or off for an instance. Switching on needs your confirmation in the browser: AI clients can then act in the app as the people who use it. An enabled instance restarts.",
			ClassWrite, "PUT /api/instances/{id}/ai", "ai.enable", func(ctx context.Context, a directory.Actor, in aiSupportArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				on := in.Enabled
				return s.updateInstanceAI(ctx, a, in.ID, hub.InstanceAIUpdate{Companions: map[string]hub.CompanionUpdate{in.Companion: {Enabled: &on}}})
			}), aiSupportClass, idOf, s.aiSupportConsequences),
		perCall(admin("set_ai_mode", "Change a companion's mode: read_only, or read_write (needs your confirmation in the browser). Existing AI credentials are revoked first.",
			ClassWrite, "PUT /api/instances/{id}/ai", "ai.mode", func(ctx context.Context, a directory.Actor, in aiModeArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				mode := in.Mode
				return s.updateInstanceAI(ctx, a, in.ID, hub.InstanceAIUpdate{Companions: map[string]hub.CompanionUpdate{in.Companion: {Mode: &mode}}})
			}), aiModeClass, idOf, func(args json.RawMessage) []string {
			a, _ := decode[aiModeArgs](args)
			return []string{"Sets the companion " + a.Companion + " of " + a.ID + " to mode " + a.Mode + ": AI clients may then change things in the app, not only read; existing AI credentials are revoked first."}
		}),
		perCall(admin("set_ai_providers", "Set which model providers an AI page (an instance of a template with an AI page, e.g. LibreChat) offers: the whole selection. Adding a provider needs your confirmation in the browser: what people send on the AI page then goes to it. A running AI page restarts.",
			ClassWrite, "PUT /api/instances/{id}/ai", "ai.providers", func(ctx context.Context, a directory.Actor, in aiProvidersArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				names := append([]string{}, in.Providers...)
				return s.updateInstanceAI(ctx, a, in.ID, hub.InstanceAIUpdate{Providers: &names})
			}), s.aiProvidersClass, idOf, s.aiProvidersConsequences),
		{Name: "revoke_ai_access", Description: "Revoke one person's (or everyone's) AI credentials for a companion now; their AI clients lose access to it until a new credential is minted. Needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/instances/{id}/ai/revoke", Audit: "ai.credential.revoke", In: revokeAIArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[revokeAIArgs](args)
				who := "everyone's"
				if a.User != "" {
					who = strings.ToLower(a.User) + "'s"
				}
				return []string{"Revokes " + who + " AI credentials for the companion " + a.Companion + " of " + a.ID + " now, in the app itself."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[revokeAIArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				return s.revokeAI(ctx, toolActor(ctx, c), a.ID, a.Companion, a.User)
			}},
		admin("ai_activity", "The gate's access log, newest first (who used which AI resource and tool, the decision; never arguments or results), filtered by instance and person.",
			ClassRead, "GET /api/ai/activity", "", func(_ context.Context, _ directory.Actor, in activityArgs) (any, error) {
				lines, err := s.aiActivity(in.Instance, in.User, in.N)
				if err != nil {
					return nil, err
				}
				return map[string]any{"lines": lines}, nil
			}),
		admin("list_model_providers", "The model providers of the AI page: definition, each secret field only as {set, updated_at}, and the instances using it.",
			ClassRead, "GET /api/ai/providers", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return map[string]any{"providers": providersOut(s.Hub.ModelProviders(ctx))}, nil
			}),
		{Name: "add_model_provider", Description: "Add a model provider for the AI page (no secret: set its key with set_model_provider_secret). Always needs your confirmation in the browser: what people send on the AI page goes to it.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/ai/providers", Audit: "ai.provider.add", In: providerArgs{},
			Typed:        nameOf,
			Consequences: noCtx(providerConsequences),
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[providerArgs](args)
				v, err := s.addModelProvider(toolActor(ctx, c), a.model())
				if err != nil {
					return nil, err
				}
				return map[string]any{"provider": providerOut(v)}, nil
			}},
		perCall(admin("save_model_provider", "Update a model provider's definition (its kind can't change; its secrets are kept). Changing where model traffic goes (base_url, instance, instance_name, region), its label or its credentials mode (but admin → per_person) needs your confirmation in the browser.",
			ClassWrite, "PUT /api/ai/providers/{name}", "ai.provider.update", func(_ context.Context, a directory.Actor, in providerArgs) (any, error) {
				v, restarts, err := s.updateModelProvider(a, in.Name, in.model())
				if err != nil {
					return nil, err
				}
				return map[string]any{"provider": providerOut(v), "restarts": restarts}, nil
			}), s.providerClass, nameOf, providerConsequences),
		{Name: "set_model_provider_secret", Description: "Set a model provider's secret (an API key): it is entered on the Hub's AI settings, never in the chat. After you saved it, this reports whether it is set and when.",
			Class: ClassSecret, Scope: ScopeAdmin, Twin: "PUT /api/ai/providers/{name}/secrets/{field}", In: providerFieldArgs{},
			SecretForm: func(args json.RawMessage) string {
				a, _ := decode[providerFieldArgs](args)
				return s.mcpScope(ScopeAdmin).home + "#settings/ai?" + url.Values{"provider": {a.Name}, "field": {a.Field}}.Encode()
			},
			Run: func(ctx context.Context, _ *directory.Caller, args json.RawMessage) (any, error) {
				// The accept is the client's word: what the Hub stores now.
				a, _ := decode[providerFieldArgs](args)
				for _, p := range s.Hub.ModelProviders(ctx) {
					if p.Name != a.Name {
						continue
					}
					sv, ok := p.Secrets[a.Field]
					if !ok {
						return nil, &hub.StatusError{Status: http.StatusNotFound, Err: fmt.Errorf("provider %s has no secret field %q", a.Name, a.Field)}
					}
					return map[string]any{"provider": a.Name, "field": a.Field, "secret": secretOut(sv),
						"note": "what the Hub stores now; it doesn't show who set it or whether it was just now"}, nil
				}
				return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no model provider " + a.Name)}
			}},
		{Name: "delete_model_provider", Description: "Delete a model provider and its secrets (refused while an AI page uses it). Needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/ai/providers/{name}", Audit: "ai.provider.delete", In: providerRefArgs{},
			Typed: nameOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				return []string{"Deletes the model provider " + nameOf(args) + " and its stored secrets."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				if err := s.deleteModelProvider(toolActor(ctx, c), nameOf(args)); err != nil {
					return nil, err
				}
				return map[string]string{"status": "deleted", "name": nameOf(args)}, nil
			}},
		// ── Hub settings ──
		admin("get_hub_settings", "The Hub's settings: Settings → AI (master switch, gate, AI clients, Portcullis MCPs, connection length, limits, allowed origins) and the default sign-in policy.",
			ClassRead, "GET /api/ai/settings", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return map[string]any{"ai": s.Hub.AISettings(), "default_policy": s.defaultPolicyView()}, nil
			}),
		perCall(Tool{Name: "save_hub_settings", Description: "Save Settings → AI (only what changes). It may turn the Portcullis admin MCP off, never on (on the Hub's page only). Turning AI or the people MCP on, changing the AI clients or the allowed origins, or raising a limit or the connection length needs your confirmation in the browser.",
			Class: ClassWrite, Scope: ScopeAdmin, Twin: "PUT /api/ai/settings", Audit: "settings.ai", In: hubSettingsArgs{},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[hub.AISettingsUpdate](args)
				if err != nil {
					return nil, badArg("invalid arguments")
				}
				a := toolActor(ctx, c)
				if in.PortcullisAdmin != nil && *in.PortcullisAdmin {
					// §15.10 / the brief: off, never on (the Hub's page only).
					err := &hub.StatusError{Status: http.StatusForbidden, Err: errors.New("the Portcullis admin MCP can't be turned on through the AI: turn it on in Settings → AI on the Hub's page (" + s.mcpScope(ScopeAdmin).home + "#settings)")}
					s.auditAs(a, directory.AuditEntry{Action: "settings.ai", Target: "ai", Detail: "portcullis_admin: on (through the AI)"}, err)
					return nil, err
				}
				return s.saveAISettings(a, in)
			}}, s.hubSettingsClass, func(json.RawMessage) string { return "settings" }, hubSettingsConsequences),
		perCall(admin("set_default_policy", "Set the Hub default sign-in policy ({factors, op}) every instance without its own uses. One that isn't stricter than the current default needs your confirmation in the browser. Inheriting instances the new default puts at mTLS only get AI support switched off first.",
			ClassWrite, "/api/settings", "settings.default_policy", func(_ context.Context, a directory.Actor, in defaultPolicyArgs) (any, error) {
				return s.setDefaultPolicy(a, in.Policy)
			}), s.defaultPolicyClass, func(json.RawMessage) string { return "default-policy" }, func(args json.RawMessage) []string {
			a, _ := decode[defaultPolicyArgs](args)
			return []string{"Sets the Hub default sign-in policy to " + hub.ShowPolicy(policy.Normalize(a.Policy)) + ", which isn't stricter than the current one: every instance without its own policy follows it."}
		}),
		admin("preview_default_policy", "What saving this default sign-in policy would switch off first (AI support of inheriting instances it puts at mTLS only); nothing is stored.",
			ClassRead, "POST /api/settings/preview", "", func(_ context.Context, _ directory.Actor, in defaultPolicyArgs) (any, error) {
				return map[string]any{"warnings": append([]string{}, s.Hub.DefaultPolicyAIWarnings(in.Policy)...)}, nil
			}),
		// ── G15: the Keycloak user sweep ──
		admin("user_sweep_status", "The guarded clean-up of Keycloak records of people deleted in LLDAP: paused (and why), skipped, the last successful run and its user count.",
			ClassRead, "GET /api/keycloak/user-sweep", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.Hub.UserSweep(), nil
			}),
		{Name: "resume_user_sweep", Description: "Resume the paused Keycloak record clean-up: LLDAP's current user count becomes its new baseline (check LLDAP first: a broken LLDAP makes the clean-up remove real people's Keycloak records). Needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/keycloak/user-sweep/resume", Audit: "keycloak.sweep_resume", In: noArgs{},
			Typed: func(json.RawMessage) string { return hub.SweepResumeConfirm },
			Consequences: func(context.Context, json.RawMessage) []string {
				st := s.Hub.UserSweep()
				lines := []string{"Resumes the Keycloak record clean-up: LLDAP's current user count becomes the baseline, and Keycloak removes the records of anyone LLDAP no longer lists."}
				if st.Reason != "" {
					lines = append(lines, "It paused because: "+st.Reason)
				}
				return lines
			},
			Run: func(ctx context.Context, c *directory.Caller, _ json.RawMessage) (any, error) {
				return s.resumeUserSweep(ctx, toolActor(ctx, c), hub.SweepResumeConfirm)
			}},
		{Name: "remove_stale_keycloak_user", Description: "Delete the Keycloak record of a person LLDAP no longer has (refused for anyone LLDAP still lists). Needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/directory/keycloak-stale/{username}", Audit: "keycloak.remove_stale", In: staleArgs{},
			Typed: argReader("username"),
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				return []string{"Deletes Keycloak's record of " + argField(args, "username") + " (passkeys, sessions, consents): LLDAP no longer has this person."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				username := argField(args, "username")
				if s.Directory == nil {
					return nil, &hub.StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("user management not configured")}
				}
				dc, err := s.Directory.CallerAs(ctx, toolActor(ctx, c))
				if err != nil {
					return nil, err
				}
				if err := s.removeStale(ctx, dc, username, username); err != nil {
					return nil, err
				}
				return map[string]string{"status": "removed", "username": username}, nil
			}},
	} {
		s.registerTool(t)
	}
}

// urlHasCredentials: a source URL the tool path refuses — on http(s) any
// user info (a user name alone can be a token: https://<token>@host/…),
// elsewhere a password; and on any URL a query string or fragment
// (either may carry a token). scp-style user@host:path names a login
// user, no secret.
func urlHasCredentials(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return false
	}
	_, pw := u.User.Password()
	web := u.Scheme == "http" || u.Scheme == "https"
	return pw || (web && u.User != nil) || u.RawQuery != "" || u.Fragment != ""
}

// scpSourceRe is an scp-style source: user@host:path.
var scpSourceRe = regexp.MustCompile(`^[^@/:\s]+@([^@/:\s]+):(\S+)$`)

// sourceDisplay is a source URL as add_source's confirmation shows it:
// a URL as sourceURLDetail (user info, query and fragment dropped), an
// scp-style one as host:path (the user@ dropped). The audit detail stays
// sourceURLDetail's.
func sourceDisplay(raw string) string {
	if m := scpSourceRe.FindStringSubmatch(raw); m != nil {
		return clipMessage(m[1]+":"+m[2], 300)
	}
	return sourceURLDetail(raw)
}

// domainForm is the Domains section's deep link with q
// (#settings/domains?enroll=<name>[&provider=<p>] or ?token=<name>).
func (s *Server) domainForm(q url.Values) string {
	for k, v := range q {
		if len(v) == 0 || v[0] == "" {
			delete(q, k)
		}
	}
	return s.mcpScope(ScopeAdmin).home + "#settings/domains?" + q.Encode()
}

// domainCheck is the U domain tools' report: whether name is enrolled
// now (the service's list when it answers, else the last known one) and,
// for action, the last such audit entry the Hub recorded for it — what
// the Hub knows, never the client's accept.
func (s *Server) domainCheck(ctx context.Context, name, action string) (any, error) {
	v := s.domainsView(ctx)
	var found any
	if list, ok := v["domains"].([]domains.Domain); ok {
		for _, d := range list {
			if d.Name == name {
				found = d
			}
		}
	}
	out := map[string]any{"name": name, "enrolled": found != nil, "domain": found,
		"note": "what the Hub knows now; it doesn't show who submitted the form"}
	if e, ok := v["error"]; ok {
		out["error"] = e
	}
	if action != "" && found != nil {
		if a := s.lastAudit(action, name); a != nil {
			out["last_replaced"] = map[string]any{"at": a.Time, "by": a.Actor, "result": a.Result}
		}
	}
	return out, nil
}

// auditLog is the Hub's audit log (nil: none).
func (s *Server) auditLog() *directory.AuditLog {
	if s.Audit != nil {
		return s.Audit
	}
	if s.Directory != nil {
		return s.Directory.Audit
	}
	return nil
}

// lastAudit is the newest ok-or-not entry of action on target (any case)
// in the Hub's audit log (nil: none in the recent entries or no log).
func (s *Server) lastAudit(action, target string) *directory.AuditEntry {
	l := s.auditLog()
	if l == nil {
		return nil
	}
	list, err := l.Recent(1000)
	if err != nil {
		return nil
	}
	// Recent is newest first.
	for i := range list {
		if list[i].Action == action && strings.EqualFold(list[i].Target, target) {
			return &list[i]
		}
	}
	return nil
}

// secretOut is a secret as the AI sees it: {set, updated_at} only.
func secretOut(v hub.SecretView) map[string]any {
	out := map[string]any{"set": v.Set}
	if v.UpdatedAt != nil {
		out["updated_at"] = v.UpdatedAt
	}
	return out
}

// providerOut is a provider view with its secrets as {set, updated_at}.
func providerOut(v hub.ProviderView) map[string]any {
	b, _ := json.Marshal(v.ModelProvider)
	out := map[string]any{}
	json.Unmarshal(b, &out)
	sec := map[string]any{}
	for f, sv := range v.Secrets {
		sec[f] = secretOut(sv)
	}
	out["secrets"], out["used_by"] = sec, v.UsedBy
	return out
}

func providersOut(list []hub.ProviderView) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, v := range list {
		out = append(out, providerOut(v))
	}
	return out
}

func providerConsequences(args json.RawMessage) []string {
	a, _ := decode[providerArgs](args)
	dest := a.BaseURL
	switch {
	case a.Instance != "":
		dest = "the instance " + a.Instance
	case a.InstanceName != "":
		dest = "the Azure resource " + a.InstanceName
	case a.Region != "":
		dest = "AWS region " + a.Region
	case dest == "":
		dest = "the " + a.Kind + " default endpoint"
	}
	return []string{"Model provider " + a.Name + " (" + a.Kind + ") sends what people type on the AI page, and what their apps return to it, to " + dest + "; its secrets go there too."}
}

// aiSupportConsequences names the mode the companion switches on in (fix
// round 1): its stored mode — what UpdateInstanceAI keeps — or, unknown,
// says so.
func (s *Server) aiSupportConsequences(args json.RawMessage) []string {
	a, _ := decode[aiSupportArgs](args)
	mode := "its stored mode (it couldn't be read)"
	if v, err := s.Hub.InstanceAI(a.ID); err == nil {
		for _, c := range v.Companions {
			if c.Name == a.Companion && c.Mode != "" {
				mode = "mode " + c.Mode
				if c.Mode == "read_write" {
					mode += " (AI clients may change things in the app, not only read)"
				}
			}
		}
	}
	return []string{"Switches the companion " + a.Companion + " of " + a.ID + " on in " + mode + ": AI clients of the people who can use " + a.ID + " get its tools, acting in the app as them; an enabled instance restarts."}
}

// aiSupportClass (Task 17b ruling, fail closed): switching off is W;
// switching on (AI clients act in the app as its people) or anything
// that doesn't decode, D.
func aiSupportClass(args json.RawMessage) ToolClass {
	if a, err := decode[aiSupportArgs](args); err == nil && !a.Enabled {
		return ClassWrite
	}
	return ClassDestructive
}

// aiProvidersClass (Task 23): W only when every provider of the new
// selection is one the AI page renders now (Hub.AIPageSelection: a stored
// one a template update stopped rendering — a kind gone, many → one —
// counts as new; people's data goes nowhere new); anything else — an
// added provider, an instance that isn't an AI page or can't be read,
// arguments that don't decode — D.
func (s *Server) aiProvidersClass(args json.RawMessage) ToolClass {
	a, err := decode[aiProvidersArgs](args)
	if err != nil || instanceIDOK(a.ID) != nil {
		return ClassDestructive
	}
	cur, ok := s.Hub.AIPageSelection(a.ID)
	if !ok {
		return ClassDestructive
	}
	for _, p := range a.Providers {
		if !slices.Contains(cur, p) {
			return ClassDestructive
		}
	}
	return ClassWrite
}

// aiProvidersConsequences names the providers the selection adds (with
// their labels: the data-egress note).
func (s *Server) aiProvidersConsequences(args json.RawMessage) []string {
	a, _ := decode[aiProvidersArgs](args)
	cur, _ := s.Hub.AIPageSelection(a.ID)
	var out []string
	for _, p := range a.Providers {
		if slices.Contains(cur, p) {
			continue
		}
		label := p
		if m, ok := s.Hub.ModelProvider(p); ok {
			label = m.Label + " (" + p + ")"
		}
		out = append(out, "Adds the model provider "+label+" to the AI page "+a.ID+": what people send on it, and what their apps return to it, goes to "+label+".")
	}
	if len(a.Providers) == 0 {
		out = append(out, "Leaves the AI page "+a.ID+" without model providers.")
	}
	return append(out, "A running "+a.ID+" restarts.")
}

// aiModeClass (G37: read_write is D): W only for exactly read_only.
func aiModeClass(args json.RawMessage) ToolClass {
	if a, err := decode[aiModeArgs](args); err == nil && a.Mode == "read_only" {
		return ClassWrite
	}
	return ClassDestructive
}

// providerClass is save_model_provider's class (Task 17b ruling, fix
// round 1): W only for a provider that exists whose kind, destination
// (base_url, instance, instance_name, region — where model traffic and
// its secrets go), label (the data-egress note people read names it) and
// credentials mode stay as stored — credentials may only go from admin
// to per_person (the Hub's key no longer goes out); "" counts as admin,
// the Hub's default. A new name, any other change of those, or arguments
// that don't decode, D.
func (s *Server) providerClass(args json.RawMessage) ToolClass {
	a, err := decode[providerArgs](args)
	if err != nil {
		return ClassDestructive
	}
	cur, ok := s.Hub.ModelProvider(a.Name)
	if !ok || cur.Kind != a.Kind || cur.BaseURL != a.BaseURL || cur.Instance != a.Instance ||
		cur.InstanceName != a.InstanceName || cur.Region != a.Region || cur.Label != a.Label {
		return ClassDestructive
	}
	if from, to := credentialsMode(cur.Credentials), credentialsMode(a.Credentials); from != to && (from != "admin" || to != "per_person") {
		return ClassDestructive
	}
	return ClassWrite
}

// credentialsMode is a provider's credentials with "" as the Hub's
// default, admin.
func credentialsMode(c string) string {
	if c == "" {
		return "admin"
	}
	return c
}

// hubSettingsClass is save_hub_settings' class (G37 + Task 17b ruling,
// fail closed): W only for switching things off (the master switch, the
// people MCP) and for limits and connection lengths that don't rise above
// the stored ones; turning AI or the people MCP on, any client change,
// any origins change, a higher limit or a longer connection, or
// arguments that don't decode, D. portcullis_admin true is refused by
// Run outright (no confirmation for a refusal: nothing runs).
func (s *Server) hubSettingsClass(args json.RawMessage) ToolClass {
	u, err := decode[hub.AISettingsUpdate](args)
	if err != nil {
		return ClassDestructive
	}
	if u.PortcullisAdmin != nil && *u.PortcullisAdmin {
		return ClassWrite // refused by Run before any Hub call
	}
	if (u.Enabled != nil && *u.Enabled) || (u.PortcullisPeople != nil && *u.PortcullisPeople) ||
		u.Clients != nil || u.AllowedOrigins != nil {
		return ClassDestructive
	}
	// The stored values are read now, not at the commit. A concurrent save
	// lowering a value between this decision and Run lets this W call put
	// back at most what was stored when it was judged — a value an admin
	// had in force a moment earlier, within SaveAISettings' bounds (idle
	// 1–30, max 1–90 days, limits 1–1,000,000, fanout ≤ 4) — and the call
	// still can't turn anything on, change a client or an origin. That is
	// harmless (Task 17b fix round 1: the race is accepted).
	cur := s.Hub.AISettings()
	raises := func(next *int, now int) bool { return next != nil && *next > now }
	if raises(u.OfflineIdleDays, cur.OfflineIdleDays) || raises(u.OfflineMaxDays, cur.OfflineMaxDays) {
		return ClassDestructive
	}
	if l := u.Limits; l != nil {
		c := cur.Limits
		if raises(l.ResourceRPM, c.ResourceRPM) || raises(l.ResourceBurst, c.ResourceBurst) || raises(l.PersonRPM, c.PersonRPM) ||
			raises(l.ToolCallsRPM, c.ToolCallsRPM) || raises(l.ConfirmationsPerHour, c.ConfirmationsPerHour) ||
			raises(l.MintsPerMinute, c.MintsPerMinute) || raises(l.Fanout, c.Fanout) {
			return ClassDestructive
		}
	}
	return ClassWrite
}

func hubSettingsConsequences(args json.RawMessage) []string {
	u, _ := decode[hub.AISettingsUpdate](args)
	var lines []string
	if u.Enabled != nil && *u.Enabled {
		lines = append(lines, "Turns AI support on for this Portcullis: AI clients can connect to the apps whose companions are on.")
	}
	if u.PortcullisPeople != nil && *u.PortcullisPeople {
		lines = append(lines, "Turns the Portcullis people MCP on: everyone's AI client can use their Portcullis account.")
	}
	if c := u.Clients; c != nil {
		for _, x := range []struct {
			name string
			u    *hub.AIClientUpdate
		}{{"claude", c.Claude}, {"claude_code", c.ClaudeCode}, {"generic", c.Generic}} {
			if x.u == nil {
				continue
			}
			if x.u.Offered != nil {
				lines = append(lines, fmt.Sprintf("AI client %s: offered %v.", x.name, *x.u.Offered))
			}
			if x.u.Admin != nil {
				l := fmt.Sprintf("AI client %s: admin %v", x.name, *x.u.Admin)
				if *x.u.Admin {
					l += " (it may then use the Portcullis admin MCP: manage Portcullis as an administrator)"
				}
				lines = append(lines, l+".")
			}
		}
	}
	if u.AllowedOrigins != nil {
		o := strings.Join(*u.AllowedOrigins, ", ")
		if o == "" {
			o = "none"
		}
		lines = append(lines, "Sets the allowed browser origins of AI requests to "+o+".")
	}
	if u.OfflineIdleDays != nil || u.OfflineMaxDays != nil || u.Limits != nil {
		lines = append(lines, "Changes the connection length or the limits (see the arguments below): a higher value lets AI clients stay connected longer or do more.")
	}
	return append(lines, "The arguments below are saved as shown.")
}

// defaultPolicyClass is set_default_policy's class (G37, like set_policy):
// W only for a policy policy.Stricter than the current default.
func (s *Server) defaultPolicyClass(args json.RawMessage) ToolClass {
	a, err := decode[defaultPolicyArgs](args)
	if err != nil {
		return ClassDestructive
	}
	if policy.Stricter(policy.Normalize(a.Policy), policy.Normalize(s.Hub.DefaultPolicy())) {
		return ClassWrite
	}
	return ClassDestructive
}
