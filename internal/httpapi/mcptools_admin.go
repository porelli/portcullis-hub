package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

// The Portcullis MCP's admin tools, part 1 (plan 4 Task 17a; contract
// §15.10, spec call 25): overview, instances, settings, runtime, drift
// and their G15 tools. Each tool's Run calls the same Server work its
// HTTP twin's handler calls (enableInstance, saveSettings, …: the same
// Hub method with the same checks and the same audit, attributed to the
// caller via ai and the AI client, with the consumed confirmation of a
// D tool in the detail) — never an HTTP loopback, never logic of its own
// beyond decoding its arguments. Credential create and revoke are never
// tools; admin_revoke_credential revokes an existing credential through
// its existing audited path (G15).

// Tool-path knobs (tests shorten them).
var (
	waitOpEvery = 2 * time.Second  // wait_for_op's poll interval
	waitOpMax   = 60 * time.Second // wait_for_op's longest wait
)

// maxLogLines is get_logs' bound (spec call 25).
const maxLogLines = 500

func init() {
	// Free-form arguments (fix round 1): maps whose keys are names the
	// manifest or the admin chose (option keys, host routers, variable
	// names) and values that are setting values, hostnames or env values
	// — never judged by name (G16). Secrets can't pass through any of
	// them: the Hub refuses a secret option's value as a plain value
	// (400), the schemas have no secrets field, and save_env refuses
	// secret-looking variables on the tool path.
	for k, why := range map[string]string{
		"create_instance.hosts":            "host router → hostname (the routers the template declares)",
		"set_hosts.hosts":                  "host router → hostname (the routers the template declares)",
		"preview_settings.values":          "option key → its JSON value (a secret option's value is refused by the Hub)",
		"save_settings.values":             "option key → its JSON value (a secret option's value is refused by the Hub)",
		"preview_settings.value_group_ids": "option key → group name → the LLDAP group id the panel showed",
		"save_settings.value_group_ids":    "option key → group name → the LLDAP group id the panel showed",
		"preview_settings.person":          "per-person option key → its default and group rows (values of non-secret options)",
		"save_settings.person":             "per-person option key → its default and group rows (values of non-secret options)",
		"preview_settings.groups":          "group-scope option key → its group records (secret options take none)",
		"save_settings.groups":             "group-scope option key → its group records (secret options take none)",
		"preview_settings.ports":           "port key or <KEY>_BIND → port / bind address",
		"save_settings.ports":              "port key or <KEY>_BIND → port / bind address",
		"save_env.variables":               "variable name → value; secret-looking names are refused on the tool path",
		"set_person_value.value":           "a person-entered option's JSON value (never a secret: person_entered options aren't secrets)",
	} {
		mcpFreeFormAllow[k] = why
	}
}

// toolActor is the caller's attribution for the Hub call: the person via
// ai and the AI client, plus the confirmation a D call consumed.
func toolActor(ctx context.Context, c *directory.Caller) directory.Actor {
	a := c.Actor()
	a.Confirmation = confirmationID(ctx)
	return a
}

// decode is the tool's arguments (already checked against the schema
// and decoded strictly by callTool).
func decode[T any](args json.RawMessage) (T, error) {
	var v T
	err := json.Unmarshal(args, &v)
	return v, err
}

// admin is an admin-scope tool whose Run decodes its arguments into T.
func admin[T any](name, desc string, class ToolClass, twin, audit string,
	run func(ctx context.Context, a directory.Actor, in T) (any, error)) Tool {
	var zero T
	return Tool{Name: name, Description: desc, Class: class, Scope: ScopeAdmin, Twin: twin, Audit: audit, In: zero,
		Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
			in, err := decode[T](args)
			if err != nil {
				return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("invalid arguments")}
			}
			return run(ctx, toolActor(ctx, c), in)
		}}
}

// idOf is a tool's "id" argument (its typed check).
func idOf(args json.RawMessage) string {
	var a struct {
		ID string `json:"id"`
	}
	json.Unmarshal(args, &a)
	return a.ID
}

func badArg(msg string) error {
	return &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New(msg)}
}

// appIDOK is the {id} rule of the /api/templates/<verb>/{id} routes
// (appID: 404 for anything but a valid id).
func appIDOK(id string) error {
	if !templates.ValidID(id) {
		return &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("404 page not found")}
	}
	return nil
}

// instanceIDOK is the {id} rule of the instance routes (instanceID).
func instanceIDOK(id string) error {
	if !templates.InstanceIDRe.MatchString(id) && !templates.ValidID(id) {
		return badArg("invalid instance id")
	}
	return nil
}

// Argument types.
type (
	noArgs     struct{}
	statusArgs struct {
		IncludeDoctor bool `json:"include_doctor,omitempty" jsonschema:"also run the doctor and show its counts (default false)"`
	}
	idArgs struct {
		ID string `json:"id" jsonschema:"the instance id (a template id names its default instance)"`
	}
	createArgs struct {
		Template string            `json:"template" jsonschema:"the template id"`
		ID       string            `json:"id" jsonschema:"the new instance id"`
		Hosts    map[string]string `json:"hosts,omitempty" jsonschema:"host router → hostname (default: the instance's hostnames on the main domain)"`
	}
	hostsArgs struct {
		ID    string            `json:"id" jsonschema:"the instance id"`
		Hosts map[string]string `json:"hosts" jsonschema:"host router → hostname"`
	}
	defaultsArgs struct {
		Template string `json:"template" jsonschema:"the template id"`
		ID       string `json:"id,omitempty" jsonschema:"the instance id the hostnames are for"`
		Domain   string `json:"domain,omitempty" jsonschema:"an enrolled domain (default: the main domain)"`
	}
	waitArgs struct {
		ID   string `json:"id" jsonschema:"the instance id"`
		OpID string `json:"op_id,omitempty" jsonschema:"the operation to wait for (default: whatever runs now)"`
	}
	settingsArgs struct {
		ID            string                           `json:"id" jsonschema:"the instance id"`
		Values        map[string]json.RawMessage       `json:"values,omitempty" jsonschema:"instance option key → JSON value (null = back to the default); never a secret"`
		ValueGroupIDs map[string]map[string]int        `json:"value_group_ids,omitempty" jsonschema:"for group / groups values: option key → group → the id get_settings showed"`
		Person        map[string]hub.PersonChange      `json:"person,omitempty" jsonschema:"per-person option key → {default, resolve, rows: [{group, value, group_id}]}"`
		Groups        map[string][]hub.GroupValueInput `json:"groups,omitempty" jsonschema:"group-scope option key → [{group, value, group_id}]"`
		Ports         map[string]string                `json:"ports,omitempty" jsonschema:"the whole port configuration: port key / <KEY>_BIND → value"`
	}
	saveSettingsArgs struct {
		settingsArgs
		PlanHash string `json:"plan_hash" jsonschema:"the plan_hash preview_settings answered for exactly these arguments"`
	}
	secretSettingArgs struct {
		ID     string `json:"id" jsonschema:"the instance id"`
		Option string `json:"option" jsonschema:"the secret option's key"`
	}
	policyArgs struct {
		ID      string             `json:"id" jsonschema:"the instance id"`
		Policy  *policy.AuthPolicy `json:"policy,omitempty" jsonschema:"the instance's own policy {factors, op}"`
		Inherit bool               `json:"inherit,omitempty" jsonschema:"drop the instance's own policy: the Hub default applies"`
	}
	signInArgs struct {
		ID   string `json:"id" jsonschema:"the instance id"`
		Mode string `json:"mode" jsonschema:"gateway (Portcullis sign-in) or native (the app's own login only)"`
	}
	publicArgs struct {
		ID     string `json:"id" jsonschema:"the instance id"`
		Access string `json:"access" jsonschema:"on, off or default (the template's default)"`
		Mode   string `json:"mode,omitempty" jsonschema:"all or listed (listed shares are added on the Hub's page)"`
	}
	logsArgs struct {
		ID      string `json:"id" jsonschema:"the instance id"`
		Service string `json:"service,omitempty" jsonschema:"one service (default: all)"`
		Lines   int    `json:"lines,omitempty" jsonschema:"lines from the end, 1-500 (default 200)"`
	}
	execArgs struct {
		ID      string `json:"id" jsonschema:"the instance id"`
		Service string `json:"service" jsonschema:"the compose service"`
		Command string `json:"command" jsonschema:"run as /bin/sh -c <command> in its running container"`
	}
	envArgs struct {
		ID        string            `json:"id" jsonschema:"the instance id"`
		Variables map[string]string `json:"variables" jsonschema:"the variables to write (name → value); secret-looking names are refused"`
	}
	overrideArgs struct {
		ID      string `json:"id" jsonschema:"the instance id"`
		Content string `json:"content" jsonschema:"the custom compose override (empty removes it)"`
	}
	driftArgs struct {
		Recheck bool `json:"recheck,omitempty" jsonschema:"re-check now instead of the last result"`
	}
	resolveArgs struct {
		ID     string `json:"id" jsonschema:"the instance or project id"`
		Action string `json:"action" jsonschema:"one of the drift's actions: start, apply, adopt, disable"`
	}
	entryArgs struct {
		ID    string          `json:"id" jsonschema:"the instance id"`
		Key   string          `json:"key" jsonschema:"the person-entered option's key"`
		User  string          `json:"user" jsonschema:"the person's username"`
		Value json.RawMessage `json:"value" jsonschema:"the JSON value"`
	}
	entryRefArgs struct {
		ID   string `json:"id" jsonschema:"the instance id"`
		Key  string `json:"key" jsonschema:"the person-entered option's key"`
		User string `json:"user" jsonschema:"the person's username"`
	}
	idsArgs struct {
		IDs []string `json:"ids,omitempty" jsonschema:"instance ids (default: every enabled instance)"`
	}
	credArgs struct {
		ID   string `json:"id" jsonschema:"the instance id"`
		Key  string `json:"key" jsonschema:"the person_secret option's key"`
		User string `json:"user" jsonschema:"the person's username"`
	}
	localNetsArgs struct {
		Networks    []string `json:"networks,omitempty" jsonschema:"CIDR prefixes ([] = loopback only)"`
		UseDefaults bool     `json:"use_defaults,omitempty" jsonschema:"back to the built-in local networks (networks must be empty)"`
	}
)

// registerAdminTools registers part 1 of the admin tools.
func (s *Server) registerAdminTools() {
	for _, t := range []Tool{
		// ── Overview ──
		admin("hub_status", "The Hub at a glance: domain, template / enabled / source counts, the last drift check and the instances whose last operation failed; with include_doctor, the doctor's counts too (it runs the doctor's checks).",
			ClassRead, "/api/status", "", func(ctx context.Context, _ directory.Actor, in statusArgs) (any, error) {
				return s.hubStatus(ctx, in.IncludeDoctor), nil
			}),
		admin("explain_policy", "An instance's sign-in policy: what applies (its own or the Hub default, intersected with what the app can enforce), the safety score and level, why (notes), the TLS tier, the sign-in mode and public access.",
			ClassRead, "GET /api/instances/{id}/settings", "", func(ctx context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				p, err := s.Hub.SettingsPanel(ctx, in.ID)
				if err != nil {
					return nil, err
				}
				return policyPart(in.ID, p.AppSettingsView), nil
			}),
		// ── Instances ──
		admin("list_instances", "Every app instance: id, template, state, hostnames, groups, Keycloak clients.",
			ClassRead, "GET /api/instances", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.Hub.Instances(), nil
			}),
		admin("get_instance", "One instance: state, hostnames, groups, clients, policy, sign-in mode, public access, its last operation, newest backup and AI support.",
			ClassRead, "/api/templates/lastop/", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				return s.getInstance(in.ID)
			}),
		admin("instance_defaults", "What creating an instance of a template needs: its host routers (immutable ones flagged), the domains hostnames may go on, and the pre-filled hostnames of an instance id.",
			ClassRead, "GET /api/instances/defaults", "", func(_ context.Context, _ directory.Actor, in defaultsArgs) (any, error) {
				return s.instanceDefaults(in.Template, in.ID, in.Domain)
			}),
		admin("create_instance", "Create an instance of a multi-instance template (created stopped: review its settings, then enable it). Its users_<id> / admin_<id> groups are created.",
			ClassWrite, "POST /api/instances", "instance.create", func(_ context.Context, a directory.Actor, in createArgs) (any, error) {
				return s.createInstance(a, in.Template, in.ID, in.Hosts)
			}),
		perCall(admin("enable_instance", "Enable (start) an instance; its missing groups are created first. Starting one whose public access is on or whose sign-in is the app's own login needs your confirmation in the browser.",
			ClassWrite, "/api/templates/enable", "instance.enable", func(_ context.Context, a directory.Actor, in idArgs) (any, error) {
				return s.enableInstance(a, in.ID)
			}), s.enableClass, idOf, s.enableConsequences),
		admin("disable_instance", "Disable (stop) an instance; its data is kept.",
			ClassWrite, "/api/templates/disable", "instance.disable", func(_ context.Context, a directory.Actor, in idArgs) (any, error) {
				return s.disableInstance(a, in.ID)
			}),
		admin("restart_instance", "Restart an enabled instance.",
			ClassWrite, "/api/templates/restart/", "instance.restart", func(_ context.Context, a directory.Actor, in idArgs) (any, error) {
				if err := appIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.restartInstance(a, in.ID)
			}),
		admin("set_hosts", "Change an instance's hostnames (every host router; immutable ones can't change).",
			ClassWrite, "PUT /api/instances/{id}/hosts", "instance.update", func(_ context.Context, a directory.Actor, in hostsArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.setHosts(a, in.ID, in.Hosts)
			}),
		admin("get_op", "An instance's last operation record (running, then ok / error with the result and warnings).",
			ClassRead, "GET /api/instances/{id}/op", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				return s.getOp(in.ID)
			}),
		admin("wait_for_op", "Wait (polling every 2 s, at most 60 s) until an instance's operation is done; answers {done, record}.",
			ClassRead, "GET /api/instances/{id}/op", "", func(ctx context.Context, _ directory.Actor, in waitArgs) (any, error) {
				return s.waitForOp(ctx, in.ID, in.OpID)
			}),
		{Name: "delete_instance", Description: "Delete an instance for good: a backup is taken first, then its containers, volumes, Keycloak clients and own groups go. Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/instances/{id}", Audit: "instance.delete", In: idArgs{},
			Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				lines, err := s.Hub.DeletePlan(idOf(args))
				if err != nil {
					return []string{"Deletes instance " + idOf(args) + " (" + err.Error() + ")."}
				}
				return lines
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, _ := decode[idArgs](args)
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				// The typed check was the confirmation page's (the id).
				op, err := s.startDelete(toolActor(ctx, c), in.ID, in.ID)
				if err != nil {
					return nil, err
				}
				return acceptedBody(op), nil
			}},
		// ── Settings ──
		admin("get_settings", "An instance's settings panel: options with their definitions and values (secrets only as {set, updated_at}), per-person and group rows, ports, the population, deliveries and person-entered values.",
			ClassRead, "GET /api/instances/{id}/settings", "", func(ctx context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				p, err := s.Hub.SettingsPanel(ctx, in.ID)
				if err != nil {
					return nil, err
				}
				p.PublicAccess = maskPublic(p.PublicAccess)
				return p, nil
			}),
		admin("preview_settings", "What saving these settings would do (nothing is stored): who gets what, the effect (reload / restart) and warnings, and the plan_hash save_settings needs.",
			ClassRead, "POST /api/instances/{id}/settings/preview", "", func(ctx context.Context, _ directory.Actor, in settingsArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.Hub.PreviewSettings(ctx, in.ID, in.update())
			}),
		perCall(admin("save_settings", "Save settings previewed with preview_settings (the same arguments and its plan_hash; a change since the preview is refused). Secrets are set with set_secret_setting; policy, sign-in and public access with their own tools. A save with ports needs your confirmation in the browser.",
			ClassWrite, "PUT /api/instances/{id}/settings", "settings.change", func(ctx context.Context, a directory.Actor, in saveSettingsArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				if in.PlanHash == "" {
					return nil, badArg("plan_hash is required: preview_settings answers it")
				}
				// G46: SaveSettings recomputes the plan (409 when it
				// differs) and re-checks its stored inputs at the commit.
				u := in.update()
				u.ExpectPlanHash = in.PlanHash
				return s.saveSettings(a, in.ID, u)
			}), s.settingsClass, idOf, settingsConsequences),
		{Name: "set_secret_setting", Description: "Set a secret setting: the value is entered on the Hub's settings page, never in the chat. After you entered it, this reports whether it is set and when.",
			Class: ClassSecret, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/settings", In: secretSettingArgs{},
			SecretForm: func(args json.RawMessage) string {
				var a secretSettingArgs
				json.Unmarshal(args, &a)
				return s.secretSettingForm(a.ID, a.Option)
			},
			Run: func(_ context.Context, _ *directory.Caller, args json.RawMessage) (any, error) {
				// The accept is the client's word: what the Hub stores now.
				a, _ := decode[secretSettingArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				v, err := s.Hub.AppSettings(a.ID)
				if err != nil {
					return nil, err
				}
				sv, ok := v.Secrets[a.Option]
				if !ok {
					return nil, &hub.StatusError{Status: http.StatusNotFound, Err: fmt.Errorf("%s has no secret option %q", a.ID, a.Option)}
				}
				return map[string]any{"instance": a.ID, "option": a.Option, "secret": sv,
					"note": "what the Hub stores now; it doesn't show who set it or whether it was just now"}, nil
			}},
		{Name: "set_policy", Description: "Set an instance's sign-in policy ({factors, op}), or inherit the Hub default. A policy that isn't stricter than the current one needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/settings", Audit: "settings.change", In: policyArgs{},
			ClassFor: s.policyClass, Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[policyArgs](args)
				if a.Inherit {
					return []string{"Drops " + a.ID + "'s own sign-in policy: the Hub default applies, which isn't stricter."}
				}
				p := "?"
				if a.Policy != nil {
					p = hub.ShowPolicy(policy.Normalize(*a.Policy))
				}
				return []string{"Sets " + a.ID + "'s sign-in policy to " + p + ", which isn't stricter than the current one."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[policyArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				if (a.Policy == nil) == !a.Inherit {
					return nil, badArg("give exactly one of policy and inherit: true")
				}
				return s.saveSettings(toolActor(ctx, c), a.ID, hub.SettingsUpdate{Policy: a.Policy, Inherit: a.Inherit})
			}},
		{Name: "set_sign_in_mode", Description: "Set the sign-in mode of an app with its own login: gateway (Portcullis sign-in in front) or native (the app's own login only, needs your confirmation in the browser).",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/settings", Audit: "app.sign_in", In: signInArgs{},
			ClassFor: func(args json.RawMessage) ToolClass {
				if a, err := decode[signInArgs](args); err == nil && a.Mode == hub.SignInGateway {
					return ClassWrite
				}
				return ClassDestructive
			},
			Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[signInArgs](args)
				return []string{"Removes Portcullis sign-in from in front of " + a.ID + ": only the app's own login protects it."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[signInArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				return s.saveSettings(toolActor(ctx, c), a.ID, hub.SettingsUpdate{SignIn: &a.Mode})
			}},
		{Name: "set_public_access", Description: "Switch an app's public exception (its share paths without sign-in) on, off or back to the template default, and its mode (all / listed). Turning it on needs your confirmation in the browser; listed shares are added on the Hub's page.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/settings", Audit: "settings.change", In: publicArgs{},
			ClassFor: s.publicClass, Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[publicArgs](args)
				line := "Opens " + a.ID + "'s public paths to anyone on the internet, without sign-in"
				if a.Mode != "" {
					line += " (mode " + a.Mode + ")"
				}
				return []string{line + "."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[publicArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				var u hub.SettingsUpdate
				switch a.Access {
				case "on", "off":
					on := a.Access == "on"
					u.PublicAccess = &on
				case "default":
					u.PublicAccessDefault = true
				default:
					return nil, badArg(`access must be "on", "off" or "default"`)
				}
				if a.Mode != "" {
					u.PublicMode = &a.Mode
				}
				return s.saveSettings(toolActor(ctx, c), a.ID, u)
			}},
		// ── Logs and runtime ──
		admin("get_logs", "The last lines (at most 500) of an instance's containers, interleaved by time; secrets redacted.",
			ClassRead, "/api/templates/logs/", "", func(ctx context.Context, _ directory.Actor, in logsArgs) (any, error) {
				return s.getLogs(ctx, in)
			}),
		admin("get_status", "An instance's containers and their state.",
			ClassRead, "/api/templates/status/", "", func(ctx context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := appIDOK(in.ID); err != nil {
					return nil, err
				}
				st, err := s.Hub.Status(ctx, in.ID)
				return st, defaultStatus(err, http.StatusBadGateway)
			}),
		{Name: "exec", Description: "Run a shell command in a running container of an instance (needs your confirmation in the browser). The output comes back redacted.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "/api/templates/exec/", Audit: "instance.exec", In: execArgs{},
			Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[execArgs](args)
				return []string{"Runs /bin/sh -c in service " + a.Service + " of " + a.ID + ", as the container's user: " + a.Command,
					"Its output goes back to the AI (secrets redacted)."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[execArgs](args)
				if err := appIDOK(a.ID); err != nil {
					return nil, err
				}
				return s.execInstance(ctx, toolActor(ctx, c), a.ID, a.Service, a.Command)
			}},
		admin("get_compose", "An instance's compose layers: the template's compose.yml, the Hub override (both read-only) and the custom override.",
			ClassRead, "/api/templates/compose/", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := appIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.Hub.ComposeFiles(in.ID)
			}),
		admin("get_env", "An instance's .env variables (secret options and secret-looking values hidden) and its compose services.",
			ClassRead, "/api/templates/env/", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := appIDOK(in.ID); err != nil {
					return nil, err
				}
				vars, services, err := s.Hub.Env(in.ID)
				if err != nil {
					return nil, err
				}
				return map[string]any{"variables": vars, "services": services}, nil
			}),
		{Name: "save_env", Description: "Write variables to an instance's .env (Expert; applies on the next restart; needs your confirmation in the browser). Variables a setting or the Hub owns are refused, and so are secret-looking ones: secrets never pass through the AI.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "/api/templates/env/", Audit: "app.env", In: envArgs{},
			Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[envArgs](args)
				names := make([]string, 0, len(a.Variables))
				for k := range a.Variables {
					names = append(names, k)
				}
				slices.Sort(names)
				return []string{"Writes " + strings.Join(names, ", ") + " to " + a.ID + "'s .env; the app reads it at its next restart."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[envArgs](args)
				if err := appIDOK(a.ID); err != nil {
					return nil, err
				}
				for _, k := range slices.Sorted(maps.Keys(a.Variables)) {
					if hub.SecretLookingEnvName(k) && a.Variables[k] != "[set]" {
						return nil, badArg(k + " looks like a secret: secrets never pass through the AI; set it on the Hub's page (" + s.mcpScope(ScopeAdmin).home + "#app/" + a.ID + "/settings)")
					}
				}
				return s.saveEnv(toolActor(ctx, c), a.ID, a.Variables)
			}},
		admin("get_custom_override", "An instance's custom compose override (Expert; \"\" = none).",
			ClassRead, "/api/templates/compose/", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := appIDOK(in.ID); err != nil {
					return nil, err
				}
				v, err := s.Hub.ComposeFiles(in.ID)
				if err != nil {
					return nil, err
				}
				return map[string]any{"user_override": v.UserOverride, "enabled": v.Enabled}, nil
			}),
		{Name: "save_custom_override", Description: "Replace an instance's custom compose override (\"\" removes it; validated; applies on the next restart; needs your confirmation in the browser).",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "/api/templates/compose/", Audit: "app.compose_override", In: overrideArgs{},
			Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[overrideArgs](args)
				if a.Content == "" {
					return []string{"Removes " + a.ID + "'s custom compose override; the change applies at its next restart."}
				}
				return []string{"Replaces " + a.ID + "'s custom compose override with the content below; it decides what runs from the next restart."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[overrideArgs](args)
				if err := appIDOK(a.ID); err != nil {
					return nil, err
				}
				return s.saveUserOverride(toolActor(ctx, c), a.ID, a.Content)
			}},
		// ── Drift ──
		admin("list_drift", "Drift between what the Hub configured and what runs (the last check, or a new one with recheck), with each item's possible actions.",
			ClassRead, "/api/drift", "", func(ctx context.Context, _ directory.Actor, in driftArgs) (any, error) {
				if in.Recheck {
					return s.Hub.Reconcile(ctx), nil
				}
				return s.Hub.Drift(), nil
			}),
		{Name: "resolve_drift", Description: "Resolve a drift item with one of its actions: start or apply (compose up with the Hub's configuration), adopt (enable running containers), disable (stop and disable). Needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "/api/drift/resolve", Audit: "drift.resolve", In: resolveArgs{},
			Typed: idOf,
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[resolveArgs](args)
				switch a.Action {
				case hub.ActionDisable:
					return []string{"Stops " + a.ID + "'s project and marks it disabled."}
				case hub.ActionAdopt:
					return []string{"Enables " + a.ID + ", adopting the containers that run."}
				default:
					return []string{"Runs compose up for " + a.ID + " with the Hub's configuration (action " + a.Action + "): containers may be recreated."}
				}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[resolveArgs](args)
				return s.resolveDrift(toolActor(ctx, c), a.ID, a.Action)
			}},
		// ── G15: settings entries, deliveries, groups, credentials, local networks ──
		admin("set_person_value", "Set a person's value of a person-entered option as the admin (the option must allow admin_override).",
			ClassWrite, "PUT /api/instances/{id}/settings/entries/{key}/{user}", "settings.person_value", func(ctx context.Context, a directory.Actor, in entryArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				if len(in.Value) == 0 {
					return nil, badArg(`value is required`)
				}
				return s.setEntry(ctx, a, in.ID, in.Key, in.User, in.Value)
			}),
		admin("clear_person_value", "Clear a person's value of a person-entered option.",
			ClassWrite, "DELETE /api/instances/{id}/settings/entries/{key}/{user}", "settings.person_value", func(ctx context.Context, a directory.Actor, in entryRefArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				if err := s.clearEntry(ctx, a, in.ID, in.Key, in.User); err != nil {
					return nil, err
				}
				return map[string]string{"status": "cleared"}, nil
			}),
		admin("retry_deliveries", "Run an instance's settings deliveries again now (every hook) and report each unit.",
			ClassWrite, "POST /api/instances/{id}/settings/retry", "settings.retry", func(ctx context.Context, a directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.retryDeliveries(ctx, a, in.ID)
			}),
		admin("missing_groups", "Enabled instances whose access or admin groups are missing in Users & Groups.",
			ClassRead, "GET /api/instances/missing-groups", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return s.Hub.MissingGroups(ctx), nil
			}),
		admin("create_missing_groups", "Create the missing users_<id> / admin_<id> groups of the given (default: every) enabled instance.",
			ClassWrite, "POST /api/instances/missing-groups", "group.create", func(ctx context.Context, a directory.Actor, in idsArgs) (any, error) {
				res, err := s.createMissingGroups(ctx, a, in.IDs)
				if err != nil {
					return nil, err
				}
				return map[string]any{"results": res}, nil
			}),
		admin("list_credentials", "An instance's per-person file-sharing credentials: who has one (metadata only, never a password or hash).",
			ClassRead, "GET /api/instances/{id}/credentials", "", func(ctx context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				v, err := s.Hub.Credentials(ctx, in.ID)
				return v, credentialsErr("credentials of "+in.ID, err)
			}),
		{Name: "admin_revoke_credential", Description: "Revoke a person's file-sharing credential for an instance now (needs your confirmation in the browser). Creating one is never a tool: the person does it on the People page.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/instances/{id}/credentials/{key}/{user}", Audit: "credential.revoke", In: credArgs{},
			Typed: func(args json.RawMessage) string { a, _ := decode[credArgs](args); return strings.ToLower(a.User) },
			Consequences: func(args json.RawMessage) []string {
				a, _ := decode[credArgs](args)
				return []string{"Revokes " + strings.ToLower(a.User) + "'s " + a.Key + " credential for " + a.ID + " now: the app stops accepting it."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[credArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				if err := credentialsErr("revoke credential", s.adminRevokeCredential(ctx, toolActor(ctx, c), a.ID, a.Key, a.User)); err != nil {
					return nil, err
				}
				return map[string]string{"status": "revoked"}, nil
			}},
		admin("get_local_networks", "The local networks (CIDRs) LAN-only ports and file sharing accept, and whether they are the defaults.",
			ClassRead, "GET /api/settings/local-networks", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.localNetworks(), nil
			}),
		perCall(admin("set_local_networks", "Set the local networks (CIDR prefixes; [] = loopback only), or go back to the defaults with use_defaults. A list that isn't within the current one needs your confirmation in the browser.",
			ClassWrite, "PUT /api/settings/local-networks", "settings.local_networks", func(_ context.Context, a directory.Actor, in localNetsArgs) (any, error) {
				cidrs := in.Networks
				switch {
				case in.UseDefaults && len(cidrs) > 0:
					return nil, badArg("give networks or use_defaults, not both")
				case in.UseDefaults:
					cidrs = nil
				case cidrs == nil:
					cidrs = []string{}
				}
				if err := s.setLocalNetworks(a, cidrs); err != nil {
					return nil, err
				}
				return s.localNetworks(), nil
			}), s.localNetsClass, func(json.RawMessage) string { return "local-networks" }, localNetsConsequences),
	} {
		s.registerTool(t)
	}
}

// perCall makes t a tool whose class is decided per call (G37): it
// registers D with its typed check and consequences, and classFor says
// W or D for each call's arguments.
func perCall(t Tool, classFor func(json.RawMessage) ToolClass, typed func(json.RawMessage) string, consequences func(json.RawMessage) []string) Tool {
	t.Class, t.ClassFor, t.Typed, t.Consequences = ClassDestructive, classFor, typed, consequences
	return t
}

// settingsClass is save_settings' class (security review of T17a, fix
// round 1): D when the call sets ports (host ports published, <KEY>_BIND
// changed), per-person rows / a default or group records of a privileged
// option (who gets elevated values; this covers raising its default), a
// group, groups or path value (who has access, what the app mounts), or
// names an option the template doesn't declare; D when the arguments or
// the template can't be read (fail closed); else W.
func (s *Server) settingsClass(args json.RawMessage) ToolClass {
	a, err := decode[saveSettingsArgs](args)
	if err != nil {
		return ClassDestructive
	}
	var raw struct {
		Ports *json.RawMessage `json:"ports"`
	}
	if json.Unmarshal(args, &raw) != nil || raw.Ports != nil || len(a.ValueGroupIDs) > 0 {
		return ClassDestructive
	}
	t := s.Hub.Template(a.ID)
	if t == nil {
		return ClassDestructive
	}
	opts := map[string]*templates.Option{}
	all := t.Manifest.Options()
	for i := range all {
		opts[all[i].Key] = &all[i]
	}
	for _, keys := range []iterKeys{maps.Keys(a.Person), maps.Keys(a.Groups)} {
		for k := range keys {
			if o := opts[k]; o == nil || o.Privileged {
				return ClassDestructive
			}
		}
	}
	for k := range a.Values {
		if o := opts[k]; o == nil || o.Privileged || o.Type == templates.TypeGroup || o.Type == templates.TypeGroups || o.Type == templates.TypePath {
			return ClassDestructive
		}
	}
	return ClassWrite
}

// iterKeys is a maps.Keys sequence.
type iterKeys = func(func(string) bool)

func settingsConsequences(args json.RawMessage) []string {
	a, _ := decode[saveSettingsArgs](args)
	keys := slices.Sorted(maps.Keys(a.Ports))
	var lines []string
	if a.Ports != nil {
		lines = append(lines, "Replaces "+a.ID+"'s port configuration ("+strings.Join(keys, ", ")+"): host ports may be published or bound to other addresses.")
	}
	var named []string
	for _, m := range []iterKeys{maps.Keys(a.Person), maps.Keys(a.Groups), maps.Keys(a.Values)} {
		for k := range m {
			named = append(named, k)
		}
	}
	slices.Sort(named)
	if len(named) > 0 {
		lines = append(lines, "Changes "+a.ID+"'s settings "+strings.Join(slices.Compact(named), ", ")+": they may decide who gets elevated values or access, or what the app mounts.")
	}
	return append(lines, "The arguments below are saved as previewed.")
}

// localNetsClass is set_local_networks' class (security review of T17a):
// W only for a list within the current one (every new prefix inside a
// current prefix of its family) — use_defaults judged as the default
// list (DefaultLocalNetworks); anything wider, or a list that doesn't
// parse, D.
func (s *Server) localNetsClass(args json.RawMessage) ToolClass {
	a, err := decode[localNetsArgs](args)
	if err != nil {
		return ClassDestructive
	}
	list := a.Networks
	switch {
	case a.UseDefaults && len(a.Networks) > 0:
		return ClassDestructive // refused anyway
	case a.UseDefaults:
		// Back to the defaults widens a narrower list: judged like one.
		list = hub.DefaultLocalNetworks
	}
	var next []netip.Prefix
	for _, n := range list {
		p, err := netip.ParsePrefix(strings.TrimSpace(n))
		if err != nil {
			return ClassDestructive
		}
		next = append(next, p.Masked())
	}
	cur := s.Hub.LocalNetworks()
	for _, p := range next {
		if !slices.ContainsFunc(cur, func(c netip.Prefix) bool {
			return c.Addr().Is4() == p.Addr().Is4() && c.Bits() <= p.Bits() && c.Contains(p.Addr())
		}) {
			return ClassDestructive
		}
	}
	return ClassWrite
}

func localNetsConsequences(args json.RawMessage) []string {
	a, _ := decode[localNetsArgs](args)
	list := strings.Join(a.Networks, ", ")
	switch {
	case a.UseDefaults:
		list = strings.Join(hub.DefaultLocalNetworks, ", ") + " (the defaults)"
	case len(a.Networks) == 0:
		list = "loopback only"
	}
	return []string{"Sets the local networks to " + list + ": LAN-only ports and file sharing accept connections from them, and the apps using them restart."}
}

// enableClass is enable_instance's class (fix round 1 ruling): D when the
// instance starts reachable without Portcullis sign-in — its public
// access is on, or its sign-in mode is the app's own login — or either
// can't be read; else W.
func (s *Server) enableClass(args json.RawMessage) ToolClass {
	id := idOf(args)
	v, err := s.Hub.AppSettings(id)
	if err != nil || v == nil {
		return ClassDestructive
	}
	if (v.PublicAccess != nil && (v.PublicAccess.Enabled || v.PublicAccess.Active)) || s.Hub.SignInMode(id) == hub.SignInNative {
		return ClassDestructive
	}
	return ClassWrite
}

func (s *Server) enableConsequences(args json.RawMessage) []string {
	id := idOf(args)
	var lines []string
	if v, err := s.Hub.AppSettings(id); err == nil && v.PublicAccess != nil && (v.PublicAccess.Enabled || v.PublicAccess.Active) {
		lines = append(lines, "Starts "+id+" with its public paths open to anyone on the internet, without sign-in.")
	}
	if s.Hub.SignInMode(id) == hub.SignInNative {
		lines = append(lines, "Starts "+id+" with only the app's own login in front of it: no Portcullis sign-in.")
	}
	if len(lines) == 0 {
		lines = append(lines, "Starts "+id+" (its access settings couldn't be read).")
	}
	return lines
}

// update is the SettingsUpdate the arguments stand for (no secrets, no
// policy, sign-in or public access: those have their own tools).
func (a settingsArgs) update() hub.SettingsUpdate {
	return hub.SettingsUpdate{Values: a.Values, ValueGroupIDs: a.ValueGroupIDs, Person: a.Person, Groups: a.Groups, Ports: a.Ports}
}

// hubStatus is hub_status: GET /api/status's counts, the last drift
// check, the doctor's counts (when it can run) and failed operations.
func (s *Server) hubStatus(ctx context.Context, withDoctor bool) map[string]any {
	nt, ne, ns := s.Hub.Counts()
	d := s.Hub.Drift()
	out := map[string]any{
		"domain": s.Hub.Domain(), "templates": nt, "enabled": ne, "sources": ns,
		"drift":      map[string]any{"checked_at": d.CheckedAt, "items": len(d.Items), "error": d.Error},
		"failed_ops": s.Hub.FailedOps(),
	}
	if !withDoctor {
		return out
	}
	if rep, err := s.Hub.Doctor(ctx); err != nil {
		out["doctor"] = map[string]any{"error": err.Error()}
	} else {
		out["doctor"] = map[string]any{"counts": rep.Counts, "muted": rep.Muted}
	}
	return out
}

// policyPart is explain_policy's answer: the policy part of the settings
// panel.
func policyPart(id string, v hub.AppSettingsView) map[string]any {
	return map[string]any{
		"instance": id, "effective_policy": v.EffectivePolicy, "default_policy": v.DefaultPolicy, "own_policy": v.AuthPolicy,
		"inherits": v.AuthPolicy == nil, "safety_score": v.SafetyScore, "level": policy.LoA(v.EffectivePolicy),
		"method": v.Method, "capability": v.Capability, "resolution": v.Resolution, "notes": v.PolicyNotes, "tier": v.Tier,
		"sign_in": v.SignIn, "public_access": maskPublic(v.PublicAccess),
	}
}

// maskPublic hides listed share tokens (§15.10: "•••", their paths stay
// in the view's paths).
func maskPublic(p *hub.PublicAccessView) *hub.PublicAccessView {
	if p == nil {
		return nil
	}
	c := *p
	mask := func(in []string) []string {
		if in == nil {
			return nil
		}
		out := make([]string, len(in))
		for i := range in {
			out[i] = "•••"
		}
		return out
	}
	c.Tokens, c.InvalidTokens = mask(p.Tokens), mask(p.InvalidTokens)
	return &c
}

// getInstance is get_instance: the instance view plus its policy, last
// operation (the lastop route's answer), newest backup and AI support.
func (s *Server) getInstance(id string) (any, error) {
	if !templates.ValidID(id) && !templates.InstanceIDRe.MatchString(id) {
		return nil, badArg("invalid instance id")
	}
	v, ok := s.Hub.InstanceView(id)
	if !ok || s.Hub.Template(id) == nil {
		return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("instance not found: " + id)}
	}
	out := map[string]any{"instance": v, "last_op": s.Hub.LastOp(id)}
	if p, err := s.Hub.AppSettings(id); err == nil {
		out["policy"] = policyPart(id, *p)
	}
	if list, err := s.Hub.ListBackups(id); err == nil && len(list) > 0 {
		out["newest_backup"] = list[0]
	}
	if ai, err := s.Hub.InstanceAI(id); err == nil {
		out["ai"] = ai
	} else {
		out["ai"] = map[string]string{"error": err.Error()}
	}
	return out, nil
}

// getOp is GET /api/instances/{id}/op's answer.
func (s *Server) getOp(id string) (*hub.OpRecord, error) {
	if err := instanceIDOK(id); err != nil {
		return nil, err
	}
	rec := s.Hub.LastOp(id)
	if rec == nil {
		return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no operation recorded for " + id)}
	}
	return rec, nil
}

// waitForOp polls id's op record every waitOpEvery until it isn't
// running (and is opID's, when given) or waitOpMax passed.
func (s *Server) waitForOp(ctx context.Context, id, opID string) (any, error) {
	if err := instanceIDOK(id); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(waitOpMax)
	for {
		rec := s.Hub.LastOp(id)
		done := rec != nil && !rec.Running && (opID == "" || rec.OpID == opID)
		if done || !time.Now().Before(deadline) {
			if rec == nil {
				return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no operation recorded for " + id)}
			}
			return map[string]any{"done": done, "record": rec}, nil
		}
		select {
		case <-ctx.Done():
			return map[string]any{"done": false, "record": rec}, nil
		case <-time.After(min(waitOpEvery, time.Until(deadline))):
		}
	}
}

// getLogs is get_logs: the logs route's call, at most maxLogLines, then
// the op-record redaction of the instance.
func (s *Server) getLogs(ctx context.Context, in logsArgs) (any, error) {
	if err := appIDOK(in.ID); err != nil {
		return nil, err
	}
	lines := in.Lines
	if lines == 0 {
		lines = 200
	}
	if lines < 1 || lines > maxLogLines {
		return nil, badArg(fmt.Sprintf("lines must be 1-%d", maxLogLines))
	}
	out, err := s.Hub.Logs(ctx, in.ID, in.Service, lines)
	if err != nil {
		return nil, defaultStatus(err, http.StatusBadGateway)
	}
	return map[string]any{"instance": in.ID, "logs": s.Hub.RedactText(in.ID, string(out))}, nil
}

// localNetworks is the local networks routes' answer.
func (s *Server) localNetworks() map[string]any {
	cidrs, isDefault := s.Hub.LocalNetworksView()
	if cidrs == nil {
		cidrs = []string{}
	}
	return map[string]any{"networks": cidrs, "default": isDefault}
}

// credentialsErr maps a credentials error as the routes answer it: a
// StatusError as is, anything else logged and 503 with the generic text.
func credentialsErr(what string, err error) error {
	if err == nil {
		return nil
	}
	var se *hub.StatusError
	if errors.As(err, &se) {
		return err
	}
	log.Printf("admin: %s: %v", what, err)
	return &hub.StatusError{Status: http.StatusServiceUnavailable, Err: errors.New(directory.GenericUnavailable)}
}

// secretSettingForm is the settings page of instance id at option (the
// Hub page's deep link #app/<id>/settings[/<option>]).
func (s *Server) secretSettingForm(id, option string) string {
	u := s.mcpScope(ScopeAdmin).home + "#app/" + id + "/settings"
	if option != "" {
		u += "/" + option
	}
	return u
}

// policyClass is set_policy's class (G37): W only for a policy
// policy.Stricter than the instance's current one (its own, else the
// default); anything else — inherit, an equal or weaker policy, an
// instance that can't be read — D.
func (s *Server) policyClass(args json.RawMessage) ToolClass {
	a, err := decode[policyArgs](args)
	if err != nil || a.Inherit || a.Policy == nil {
		return ClassDestructive
	}
	v, err := s.Hub.AppSettings(a.ID)
	if err != nil {
		return ClassDestructive
	}
	cur := v.DefaultPolicy
	if v.AuthPolicy != nil {
		cur = *v.AuthPolicy
	}
	if policy.Stricter(policy.Normalize(*a.Policy), policy.Normalize(cur)) {
		return ClassWrite
	}
	return ClassDestructive
}

// publicClass is set_public_access's class (G37, fix round 1: fail
// closed): W only for "off", or "default" on a template known to be
// closed by default, with the mode empty or listed; anything else — "on",
// the mode "all", a template that can't be read, arguments that don't
// decode — D.
func (s *Server) publicClass(args json.RawMessage) ToolClass {
	a, err := decode[publicArgs](args)
	if err != nil || (a.Mode != "" && a.Mode != "listed") {
		return ClassDestructive
	}
	switch a.Access {
	case "off":
		return ClassWrite
	case "default":
		v, err := s.Hub.AppSettings(a.ID)
		if err == nil && v.PublicAccess != nil && !v.PublicAccess.EnabledByDefault {
			return ClassWrite
		}
	}
	return ClassDestructive
}
