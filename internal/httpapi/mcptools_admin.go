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
	"strconv"
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
	// (400), the schemas have no secrets field, and set_env_override's
	// twin refuses secret and secret-looking variables (§11.9).
	for k, why := range map[string]string{
		"create_instance.hosts":            "host router → hostname (the routers the template declares)",
		"create_instance.setup":            "setup option key → its JSON value (setup options are never secrets)",
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

// argField reads one string argument of a tool's (canonical) arguments
// ("" when absent or not a string): the typed checks and consequences of
// the tools that name their target by it.
func argField(args json.RawMessage, key string) string {
	var m map[string]json.RawMessage
	var v string
	if json.Unmarshal(args, &m) == nil {
		json.Unmarshal(m[key], &v)
	}
	return v
}

// q is how a consequence line shows an argument value that isn't a
// validated name (checkNameArgs: usernames, group, field and instance
// ids): quoted (Go syntax, so a quote inside can't end it), with every
// invisible, bidi or control character as \uXXXX — never as the Hub's
// own words (security review of the final fix).
func q(v string) string { return hub.VisibleText(strconv.Quote(v)) }

// quoteAll is q over a list.
func quoteAll(vs []string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = q(v)
	}
	return out
}

// argReader is argField(·, key) as a function (a Typed check).
func argReader(key string) func(json.RawMessage) string {
	return func(args json.RawMessage) string { return argField(args, key) }
}

// idOf / nameOf are the "id" / "name" arguments (typed checks).
var (
	idOf   = argReader("id")
	nameOf = argReader("name")
)

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
		Template string                     `json:"template" jsonschema:"the template id"`
		ID       string                     `json:"id" jsonschema:"the new instance id (the template id for its first instance)"`
		Label    string                     `json:"label" jsonschema:"the instance's label: the portal shows it as <App> · <label> (1–64 characters, one line)"`
		Hosts    map[string]string          `json:"hosts,omitempty" jsonschema:"host router → hostname (default: the instance's hostnames on the main domain)"`
		Groups   *groupsBody                `json:"groups,omitempty" jsonschema:"who can use it: {mode: new} (default: empty users_<id> / admin_<id> are created) or {mode: existing, users, admins} (bound to existing groups)"`
		Setup    map[string]json.RawMessage `json:"setup,omitempty" jsonschema:"the template's setup choices: setup option key → its JSON value (an omitted one takes its default; a fixed_after_start choice can't change once the instance has started)"`
	}
	labelArgs struct {
		ID    string `json:"id" jsonschema:"the instance id"`
		Label string `json:"label" jsonschema:"the new label (1–64 characters, one line)"`
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
		OpID string `json:"op_id,omitempty" jsonschema:"the operation to wait for: the op_id its start answered (default: the instance's current operation)"`
	}
	opArgs struct {
		ID   string `json:"id" jsonschema:"the instance id"`
		OpID string `json:"op_id,omitempty" jsonschema:"the operation to show: the op_id its start answered (default: the instance's current record)"`
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
	envVarArgs struct {
		ID   string `json:"id" jsonschema:"the instance id"`
		Name string `json:"name" jsonschema:"the variable's name ([A-Za-z_][A-Za-z0-9_]*)"`
	}
	envOverrideArgs struct {
		ID    string `json:"id" jsonschema:"the instance id"`
		Name  string `json:"name" jsonschema:"the variable's name ([A-Za-z_][A-Za-z0-9_]*): a variable of the instance, or a new one of your own"`
		Value string `json:"value" jsonschema:"its value (written single-quoted: no ', \\, line breaks or control characters; never a secret)"`
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
		Action string `json:"action" jsonschema:"one of the drift's actions: start, apply, restart, adopt, disable"`
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
		perCallCtx(admin("create_instance", "Create an instance of a template with a label (created stopped: review its settings, then enable it); the template's first instance takes the template id. Its users_<id> / admin_<id> groups are created, or with groups {mode: existing, users, admins} it is bound to existing groups. If one of its groups already exists with people, it needs your confirmation in the browser. Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			ClassWrite, "POST /api/instances", "instance.create", func(_ context.Context, a directory.Actor, in createArgs) (any, error) {
				return started(s.createInstance(a, in.request()))
			}), s.createClass, idOf, s.createConsequences),
		perCallCtx(admin("enable_instance", "Enable (start) an instance; its missing groups are created first. Starting one whose public access is on, whose sign-in is the app's own login, or whose access / admin group already has members needs your confirmation in the browser. Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			ClassWrite, "/api/templates/enable", "instance.enable", func(_ context.Context, a directory.Actor, in idArgs) (any, error) {
				return started(s.enableInstance(a, in.ID))
			}), s.enableClass, idOf, s.enableConsequences),
		admin("disable_instance", "Disable (stop) an instance; its data is kept. Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			ClassWrite, "/api/templates/disable", "instance.disable", func(_ context.Context, a directory.Actor, in idArgs) (any, error) {
				return started(s.disableInstance(a, in.ID))
			}),
		admin("restart_instance", "Restart an enabled instance. Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			ClassWrite, "/api/templates/restart/", "instance.restart", func(_ context.Context, a directory.Actor, in idArgs) (any, error) {
				if err := appIDOK(in.ID); err != nil {
					return nil, err
				}
				return started(s.restartInstance(a, in.ID))
			}),
		admin("set_instance_label", "Change an instance's label (display only: the portal and My apps show <App> · <label>). Answers the instance.",
			ClassWrite, "PUT /api/instances/{id}/label", "instance.update", func(ctx context.Context, a directory.Actor, in labelArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.setLabel(ctx, a, in.ID, in.Label)
			}),
		admin("set_hosts", "Change an instance's hostnames (every host router; immutable ones can't change).",
			ClassWrite, "PUT /api/instances/{id}/hosts", "instance.update", func(_ context.Context, a directory.Actor, in hostsArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.setHosts(a, in.ID, in.Hosts)
			}),
		admin("get_op", "An instance's operation record — with op_id that operation's (kept for its last 20), else the instance's current one: its steps (state, percent, detail, times), what it created, whether it can be stopped, then ok / error with the result and warnings.",
			ClassRead, "GET /api/instances/{id}/op", "", func(_ context.Context, _ directory.Actor, in opArgs) (any, error) {
				return s.getOp(in.ID, in.OpID)
			}),
		admin("list_ops", "Every instance's current operation in short: {<instance>: {op, op_id, running, stopping, stoppable, ok, at}}.",
			ClassRead, "GET /api/instances/ops", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.Hub.OpSummaries(), nil
			}),
		admin("wait_for_op", "Wait (polling every 2 s, at most 60 s) until an instance's operation is done — with op_id that operation, whatever ran after it; answers {done, record} (the record with its steps and what it created).",
			ClassRead, "GET /api/instances/{id}/op", "", func(ctx context.Context, _ directory.Actor, in waitArgs) (any, error) {
				return s.waitForOp(ctx, in.ID, in.OpID)
			}),
		// D or W per call (security review of Task 7): a Stop reverses
		// what the running operation did, and some undos turn things back
		// on — stopping a disable enables the app again, stopping an AI
		// switch-off switches the companion back on, stopping a delete of
		// an enabled instance enables it again. Those take the class the
		// direct tool would (enable_instance, set_ai_support / set_ai_mode);
		// every other undo is W (stopClass).
		s.stopOpTool(),
		{Name: "delete_instance", Description: "Delete an instance for good: a backup is taken first, then its containers, volumes, Keycloak clients and own groups go. Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/instances/{id}", Audit: "instance.delete", In: idArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
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
			ClassFor: noCtxClass(s.policyClass), Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
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
			ClassFor: func(_ context.Context, args json.RawMessage) ToolClass {
				if a, err := decode[signInArgs](args); err == nil && a.Mode == hub.SignInGateway {
					return ClassWrite
				}
				return ClassDestructive
			},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
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
			ClassFor: noCtxClass(s.publicClass), Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[publicArgs](args)
				line := "Opens " + a.ID + "'s public paths to anyone on the internet, without sign-in"
				if a.Mode != "" {
					line += " (mode " + q(a.Mode) + ")"
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
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[execArgs](args)
				return []string{"Runs /bin/sh -c in service " + q(a.Service) + " of " + a.ID + ", as the container's user, the command " + q(a.Command) + ".",
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
		admin("get_env", "An instance's environment rows: per variable its default (secrets only as [set]), source (template, hub, option or custom), your override, and whether it is Hub-set (can't be overridden).",
			ClassRead, "GET /api/instances/{id}/env", "", func(_ context.Context, _ directory.Actor, in idArgs) (any, error) {
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.envRows(in.ID)
			}),
		{Name: "set_env_override", Description: "Override one variable of an instance's .env, or add one of your own (needs your confirmation in the browser). Variables the Hub or a setting sets, and secrets, are refused. An enabled instance restarts. Answers {row, effect}.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/env/{name}", Audit: "settings.env", In: envOverrideArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[envOverrideArgs](args)
				return []string{"Sets " + q(a.Name) + " to " + q(a.Value) + " in " + a.ID + "'s environment, after every value the template, the Hub and the settings write; an enabled instance restarts."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[envOverrideArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				return s.setEnvOverride(toolActor(ctx, c), a.ID, a.Name, a.Value)
			}},
		{Name: "clear_env_override", Description: "Put one variable of an instance's .env back to its default (a variable you added is removed; needs your confirmation in the browser). An enabled instance restarts. Answers {row, effect}.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/instances/{id}/env/{name}", Audit: "settings.env", In: envVarArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[envVarArgs](args)
				return []string{"Resets " + q(a.Name) + " in " + a.ID + "'s environment to its default (a variable you added is removed); an enabled instance restarts."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				a, _ := decode[envVarArgs](args)
				if err := instanceIDOK(a.ID); err != nil {
					return nil, err
				}
				return s.clearEnvOverride(toolActor(ctx, c), a.ID, a.Name)
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
			Consequences: func(_ context.Context, args json.RawMessage) []string {
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
		{Name: "resolve_drift", Description: "Resolve a drift item with one of its actions: start or apply (compose up with the Hub's configuration), restart (compose down with every profile, then up), adopt (enable running containers), disable (stop and disable). Needs your confirmation in the browser.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "/api/drift/resolve", Audit: "drift.resolve", In: resolveArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[resolveArgs](args)
				switch a.Action {
				case hub.ActionDisable:
					return []string{"Stops " + a.ID + "'s project and marks it disabled."}
				case hub.ActionAdopt:
					return []string{"Enables " + a.ID + ", adopting the containers that run."}
				case hub.ActionRestart:
					return []string{"Restarts " + a.ID + ": every container of its project is stopped, then the ones its setup choices select are started."}
				default:
					return []string{"Runs compose up for " + a.ID + " with the Hub's configuration (action " + q(a.Action) + "): containers may be recreated."}
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
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				a, _ := decode[credArgs](args)
				return []string{"Revokes " + strings.ToLower(a.User) + "'s " + q(a.Key) + " credential for " + a.ID + " now: the app stops accepting it."}
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
	return perCallCtx(t, noCtxClass(classFor), typed, noCtx(consequences))
}

// noCtxClass adapts a class function that needs no call state.
func noCtxClass(f func(json.RawMessage) ToolClass) func(context.Context, json.RawMessage) ToolClass {
	return func(_ context.Context, a json.RawMessage) ToolClass { return f(a) }
}

// perCallCtx is perCall with class and consequences that read the call's
// state (the memoised directory read, the caller: callMemo).
func perCallCtx(t Tool, classFor func(context.Context, json.RawMessage) ToolClass, typed func(json.RawMessage) string, consequences func(context.Context, json.RawMessage) []string) Tool {
	t.Class, t.ClassFor, t.Typed, t.Consequences = ClassDestructive, classFor, typed, consequences
	return t
}

// inertSettingTypes are the option types save_settings may change as W
// (fix round 1, security review: an allowlist, failing closed by type):
// scalars that grant nobody anything and mount nothing.
// Every other type — user, users, group, groups, path, secret,
// person_secret, person_id, list, table, a type added later — is D.
var inertSettingTypes = map[string]bool{
	templates.TypeString: true, templates.TypeInt: true, templates.TypeSize: true, templates.TypeDuration: true,
	templates.TypeBool: true, templates.TypeEnum: true, templates.TypeMultiEnum: true,
}

// inertOption: o exists, isn't privileged and has an inert type.
func inertOption(o *templates.Option) bool {
	return o != nil && !o.Privileged && inertSettingTypes[o.Type]
}

// settingsClass is save_settings' class (security review of T17a, fix
// round 1): W only when every values / person / groups key is a
// non-privileged option of the template whose type is in
// inertSettingTypes, and the call sets no ports (host ports published,
// <KEY>_BIND changed) and no value_group_ids; anything else — a
// privileged option (raising its default included), another type, an
// unknown key, arguments or a template that can't be read — D.
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
	for _, keys := range []iterKeys{maps.Keys(a.Person), maps.Keys(a.Groups), maps.Keys(a.Values)} {
		for k := range keys {
			if !inertOption(opts[k]) {
				return ClassDestructive
			}
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
		lines = append(lines, "Replaces "+a.ID+"'s port configuration ("+strings.Join(quoteAll(keys), ", ")+"): host ports may be published or bound to other addresses.")
	}
	var named []string
	for _, m := range []iterKeys{maps.Keys(a.Person), maps.Keys(a.Groups), maps.Keys(a.Values)} {
		for k := range m {
			named = append(named, k)
		}
	}
	slices.Sort(named)
	if len(named) > 0 {
		lines = append(lines, "Changes "+a.ID+"'s settings "+strings.Join(quoteAll(slices.Compact(named)), ", ")+": they may decide who gets elevated values or access, or what the app mounts.")
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
	list := strings.Join(quoteAll(a.Networks), ", ")
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
// can't be read; D when its access / admin group already has members
// (pre-staged groups, T18 fix round 1: prestaged); else W.
func (s *Server) enableClass(ctx context.Context, args json.RawMessage) ToolClass {
	id := idOf(args)
	v, err := s.Hub.AppSettings(id)
	if err != nil || v == nil {
		return ClassDestructive
	}
	if (v.PublicAccess != nil && (v.PublicAccess.Enabled || v.PublicAccess.Active)) || s.Hub.SignInMode(id) == hub.SignInNative {
		return ClassDestructive
	}
	if pre, ok := s.prestaged(ctx, s.instanceGroupList(id)); !ok || len(pre) > 0 {
		return ClassDestructive
	}
	return ClassWrite
}

func (s *Server) enableConsequences(ctx context.Context, args json.RawMessage) []string {
	id := idOf(args)
	var lines []string
	if v, err := s.Hub.AppSettings(id); err == nil && v.PublicAccess != nil && (v.PublicAccess.Enabled || v.PublicAccess.Active) {
		lines = append(lines, "Starts "+id+" with its public paths open to anyone on the internet, without sign-in.")
	}
	if s.Hub.SignInMode(id) == hub.SignInNative {
		lines = append(lines, "Starts "+id+" with only the app's own login in front of it: no Portcullis sign-in.")
	}
	lines = append(lines, s.prestagedLines(ctx, s.instanceGroupList(id), id)...)
	if len(lines) == 0 {
		lines = append(lines, "Starts "+id+" (its access settings couldn't be read).")
	}
	return lines
}

// createClass is create_instance's class (T18 fix round 1): D when one of
// the new instance's groups already exists with members, or that can't
// be read (unknown template, directory down); else W.
func (s *Server) createClass(ctx context.Context, args json.RawMessage) ToolClass {
	a, err := decode[createArgs](args)
	if err != nil {
		return ClassDestructive
	}
	if pre, ok := s.prestaged(ctx, s.plannedGroups(ctx, a)); !ok || len(pre) > 0 {
		return ClassDestructive
	}
	return ClassWrite
}

// plannedGroups are the groups the create would use (bound ones for
// mode existing, §11.9); nil: unknown template (fail closed).
func (s *Server) plannedGroups(ctx context.Context, a createArgs) []string {
	req := a.request()
	users, admins, ok := s.Hub.PlannedGroups(ctx, req.Template, req.ID, req.Groups)
	if !ok {
		return nil
	}
	return []string{users, admins}
}

// request is the create the arguments stand for (the route's body).
func (a createArgs) request() hub.CreateRequest {
	return instanceCreateBody{Template: a.Template, ID: a.ID, Label: a.Label, Hosts: a.Hosts, Groups: a.Groups, Setup: a.Setup}.request()
}

func (s *Server) createConsequences(ctx context.Context, args json.RawMessage) []string {
	a, _ := decode[createArgs](args)
	lines := []string{"Creates instance " + a.ID + " of " + a.Template + " (label " + q(a.Label) + ")."}
	if a.Groups != nil && a.Groups.Mode == hub.GroupsExisting {
		lines = append(lines, "Binds it to the existing groups "+q(a.Groups.Users)+" (users) and "+q(a.Groups.Admins)+" (admins): their people get it at once.")
	}
	if len(a.Setup) > 0 {
		lines = append(lines, "Setup choices: "+s.setupChoicesText(a.Template, a.Setup)+".")
	}
	return append(lines, s.prestagedLines(ctx, s.plannedGroups(ctx, a), a.ID)...)
}

// setupChoicesText is a create's setup values for its confirmation:
// every key and value quoted once (q: strconv.Quote, then VisibleText),
// so no key or value can read as another choice; a key that isn't one of
// the template's setup options is named as refused; a value that
// decodes to a JSON string shows that string quoted, another scalar its
// JSON text, anything else the raw JSON — each quoted.
func (s *Server) setupChoicesText(templateID string, setup map[string]json.RawMessage) string {
	isSetup := map[string]bool{}
	if t := s.Hub.Template(templateID); t != nil && t.Manifest.Settings != nil {
		for _, o := range t.Manifest.Settings.Options {
			if o.Setup {
				isSetup[o.Key] = true
			}
		}
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(setup)) {
		if !isSetup[k] {
			parts = append(parts, q(k)+" (not a setup option of the template: refused)")
			continue
		}
		raw := setup[k]
		val := q(string(raw))
		var v any
		if json.Unmarshal(raw, &v) == nil {
			switch x := v.(type) {
			case string:
				val = q(x)
			case float64, bool, nil:
				val = q(strings.TrimSpace(string(raw)))
			}
		}
		parts = append(parts, q(k)+" = "+val)
	}
	return strings.Join(parts, ", ")
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

// stopArgs are stop_op's arguments: op_id (optional) binds the call
// (and its confirmation) to that operation.
type stopArgs struct {
	ID   string `json:"id" jsonschema:"the instance id"`
	OpID string `json:"op_id,omitempty" jsonschema:"the operation to stop (get_op's op_id): refused when another one is the instance's now"`
}

// stopOpTool is stop_op, D or W per call (security review of Task 7):
// a Stop reverses what the running operation did, and some undos turn
// things back on — stopping a disable enables the app again, stopping a
// delete or a same-instance restore of an enabled instance brings it back
// as it was, stopping an AI switch-off switches the companion back on.
// Those take the class the direct tool would (stopClass) and need op_id:
// the confirmation's arguments name the operation, and the Hub stops only
// that one (StopOpExpect). Every other undo is W, bound to the operation
// its class was judged on.
func (s *Server) stopOpTool() Tool {
	t := perCallCtx(admin("stop_op", "Stop an instance's running operation and undo what it did (an enable's containers, volumes, sign-in clients and groups it created; a disable turns the app back on; …). Answers the record (stopping: true); poll with wait_for_op. op_id (from get_op) stops only that operation; it is required when the undo turns something back on (a disable, a delete or restore of an enabled instance, an AI switch-off), which needs your confirmation in the browser. Refused (409, with the record) when nothing runs, the operation is already stopping or changed, or a delete is past its point of no return.",
		ClassWrite, "POST /api/instances/{id}/op/stop", "op.stop", func(ctx context.Context, a directory.Actor, in stopArgs) (any, error) {
			if err := instanceIDOK(in.ID); err != nil {
				return nil, s.refuseStop(a, in.ID, err)
			}
			expected, err := s.stopExpected(ctx, in)
			if err != nil {
				return nil, s.refuseStop(a, in.ID, err)
			}
			return s.stopOp(a, in.ID, expected)
		}), s.stopClass, idOf, s.stopConsequences)
	t.Precheck = func(ctx context.Context, _ *directory.Caller, args json.RawMessage) error {
		a, err := decode[stopArgs](args)
		if err == nil && a.OpID == "" && s.stopClass(ctx, args) == ClassDestructive {
			return badArg("stopping this operation turns something back on: pass its op_id (from get_op), so the confirmation names that operation")
		}
		return nil
	}
	return t
}

// opNone is an expected op id no operation has: the class judged "no
// record", so any operation found by then is another.
const opNone = "-"

// stopClass is stop_op's class: the class of what the undo of the
// instance's current operation turns on (undoClass). Arguments that
// don't decode, or an op_id that isn't the current operation's, D (fail
// closed: the Hub refuses the latter). The operation it judged is kept
// in the call memo: Run stops only that one (stopExpected).
func (s *Server) stopClass(ctx context.Context, args json.RawMessage) ToolClass {
	a, err := decode[stopArgs](args)
	if err != nil || instanceIDOK(a.ID) != nil {
		return ClassDestructive
	}
	rec := s.Hub.LastOp(a.ID)
	opID := opNone
	if rec != nil && rec.OpID != "" {
		// A record without an op id (finishOp's: hook, hosts, reload,
		// credentials, drift) is opNone too, never "" (= any).
		opID = rec.OpID
	}
	if m := memoOf(ctx); m != nil {
		m.stopOnce.Do(func() { m.stopOpID = opID })
	}
	if a.OpID != "" && a.OpID != opID {
		return ClassDestructive
	}
	return s.undoClass(ctx, a.ID, rec)
}

// undoClass is the class of what a Stop of rec would turn back on (nil:
// no record, nothing to undo: W):
//   - disable: the app enabled again — enable_instance's class;
//   - delete: cancelled, the app as before — enable_instance's class
//     unless Before says it wasn't enabled;
//   - restore into the same instance: rolled back from the pre-restore
//     backup — enabled app, AI companions, policy and public access as
//     they were — D when it was (or may have been) enabled or the
//     rollback is armed (restoring); a restore into a new id only removes
//     it: W;
//   - AI switch: each companion back to its Before {enabled, mode} — D
//     when one goes back on (set_ai_support on), W when all go back off;
//   - everything else W: an enable's, a create's and a restore-as's undo
//     remove what they made, a restart's and a backup's start only what
//     was running.
func (s *Server) undoClass(ctx context.Context, id string, rec *hub.OpRecord) ToolClass {
	if rec == nil {
		return ClassWrite
	}
	switch rec.Op {
	case hub.OpDisable:
		return s.enableClass(ctx, idArgsJSON(id))
	case hub.OpDelete:
		if rec.Before[hub.BeforeEnabled] == "false" {
			return ClassWrite
		}
		return s.enableClass(ctx, idArgsJSON(id))
	case hub.OpRestore:
		switch {
		case rec.Before[hub.BeforeNewID] == "true":
			return ClassWrite
		case rec.Before[hub.BeforeEnabled] == "false" && rec.Before[hub.BeforeRestoring] == "":
			return ClassWrite
		}
		return ClassDestructive
	case hub.OpAI:
		seen := false
		for k, v := range rec.Before {
			if strings.HasPrefix(k, hub.BeforeCompanion) {
				seen = true
				if !strings.HasPrefix(v, "off ") {
					return ClassDestructive // back on (or unreadable): set_ai_support on
				}
			}
		}
		if !seen {
			return ClassDestructive // Before not written: unknown, fail closed
		}
	}
	return ClassWrite
}

// stopExpected (Run) is the op id stop_op stops: op_id when given, else
// the one its class judged (opNone: none) — the Hub refuses any other
// (ErrOpChanged). A D undo the call has no confirmation for is refused
// at once.
func (s *Server) stopExpected(ctx context.Context, a stopArgs) (string, error) {
	m := memoOf(ctx)
	if m == nil {
		return "", hub.ErrOpChanged
	}
	m.stopOnce.Do(func() { m.stopOpID = opNone })
	expected := a.OpID
	if expected == "" {
		expected = m.stopOpID
	}
	if s.undoClass(ctx, a.ID, s.Hub.LastOp(a.ID)) == ClassDestructive && confirmationID(ctx) == "" {
		return "", hub.ErrOpChanged
	}
	return expected, nil
}

// refuseStop is a stop_op refusal of Run's own (refusal: an invalid id,
// an undo needing a confirmation the call didn't get), through the Hub:
// audited <op>.stop refused, a 409 answered with the current record
// (recordError), anything else as it is.
func (s *Server) refuseStop(a directory.Actor, id string, refusal error) error {
	s.rec("RefuseStop", id)
	rec, err := s.Hub.RefuseStop(id, a, refusal)
	if rec != nil && errStatus(err, http.StatusInternalServerError) == http.StatusConflict {
		return &recordError{err: err, rec: rec}
	}
	return err
}

func idArgsJSON(id string) json.RawMessage {
	b, _ := json.Marshal(idArgs{ID: id})
	return b
}

// stopConsequences says which operation is stopped and what its undo
// turns back on.
func (s *Server) stopConsequences(ctx context.Context, args json.RawMessage) []string {
	a, _ := decode[stopArgs](args)
	rec := s.Hub.LastOp(a.ID)
	if rec == nil {
		return []string{"Stops the operation of " + a.ID + " (none is recorded)."}
	}
	head := "Stops the " + rec.Op + " of " + a.ID + " (operation " + rec.OpID + ") and undoes it"
	switch rec.Op {
	case hub.OpDisable:
		return append([]string{head + ": " + a.ID + " is turned back on."}, s.enableConsequences(ctx, idArgsJSON(a.ID))...)
	case hub.OpDelete:
		if rec.Before[hub.BeforeEnabled] != "false" {
			return append([]string{head + ": the delete is cancelled and " + a.ID + " is turned back on."}, s.enableConsequences(ctx, idArgsJSON(a.ID))...)
		}
	case hub.OpRestore:
		if rec.Before[hub.BeforeNewID] != "true" {
			return []string{head + ": " + a.ID + " is rolled back from its pre-restore backup — its data, settings, sign-in and public access, AI support and, if it was running, the app itself come back as they were before the restore."}
		}
	case hub.OpAI:
		var lines []string
		for _, k := range slices.Sorted(maps.Keys(rec.Before)) {
			name, ok := strings.CutPrefix(k, hub.BeforeCompanion)
			if !ok {
				continue
			}
			if mode, on := strings.CutPrefix(rec.Before[k], "on "); on {
				line := "Switches the companion " + q(name) + " of " + a.ID + " back on in mode " + q(mode)
				if mode == "read_write" {
					line += " (AI clients may change things in the app, not only read)"
				}
				lines = append(lines, line+": AI clients of the people who can use "+a.ID+" get its tools, acting in the app as them; an enabled instance restarts.")
			}
		}
		return append([]string{head + "."}, lines...)
	}
	return []string{head + "."}
}

// started is a long operation's tool answer: the twin's 202 body.
func started(op *hub.AsyncOp, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return acceptedBody(op), nil
}

// getOp is GET /api/instances/{id}/op's answer.
func (s *Server) getOp(id, opID string) (*hub.OpRecord, error) {
	if err := instanceIDOK(id); err != nil {
		return nil, err
	}
	if opID != "" {
		return s.opByID(id, opID)
	}
	rec := s.Hub.LastOp(id)
	if rec == nil {
		return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no operation recorded for " + id)}
	}
	return rec, nil
}

// opByID is the ?op_id= route's answer: 400 malformed, 404 unknown or
// pruned.
func (s *Server) opByID(id, opID string) (*hub.OpRecord, error) {
	if !hub.OpIDRe.MatchString(opID) {
		return nil, badArg("op_id must be 16 lowercase hex digits")
	}
	rec := s.Hub.OpByID(id, opID)
	if rec == nil {
		return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no operation " + opID + " recorded for " + id)}
	}
	return rec, nil
}

// waitForOp polls every waitOpEvery until the operation isn't running or
// waitOpMax passed: opID's record when given (the op history: it ends on
// that operation's own outcome), else id's current record.
func (s *Server) waitForOp(ctx context.Context, id, opID string) (any, error) {
	if err := instanceIDOK(id); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(waitOpMax)
	for {
		var rec *hub.OpRecord
		if opID != "" {
			var err error
			if rec, err = s.opByID(id, opID); err != nil {
				return nil, err
			}
		} else {
			rec = s.Hub.LastOp(id)
		}
		done := rec != nil && !rec.Running
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
