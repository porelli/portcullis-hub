package httpapi

import (
	"slices"
	"strings"
	"testing"
)

// Plan 4 Task 17a: twins and routes (contract §15.10, G14, G15, G37).
// Every Hub-listener route (hubMux().patterns, G14: no other recorder) is
// some admin tool's Twin, in noToolRoutes (G15's list, each with its
// reason) or — until its task lands — in pendingToolRoutes; every admin
// tool's Twin is a recorded route; every class-D tool's twin deletes,
// restores, revokes, runs code or has a typed confirmation today — or the
// tool is one of the access-widening calls whose class is decided per
// call (ClassFor).

// noToolRoutes are the Hub-listener routes no tool mirrors (exactly G15's
// list), each with why.
var noToolRoutes = map[string]string{
	"/":                     "the Hub's page: a browser UI, not an operation",
	"/static/":              "the page's scripts and styles",
	"/healthz":              "the liveness probe",
	"GET /api/portal/apps":  "core's portal page list (what list_instances / get_instance already show the admin)",
	"GET /api/directory/me": "the people page's who-am-I: a tool's caller is the token's person",
	importReviewPath:        "the multipart CSV upload; import_review takes the CSV as JSON instead",
}

// confirmationRoutes are the Hub listener's confirmation page and its
// decision (§15.6): a confirmation is given only by the person in a
// browser with a fresh passkey touch, never by a tool — they can't be in
// noToolRoutes (G15's list predates them) nor pending (no task will add a
// tool for them). Deviation of T17a, reported.
var confirmationRoutes = map[string]string{
	"GET /confirm/{id}":               "the confirmation page itself: only the person, in a browser",
	"POST /api/me/confirmations/{id}": "approving or declining a confirmation: never through the AI",
}

// pendingToolRoutes are the routes whose tools later tasks add: route →
// the task. Each task removed its entries (T17b, T18, T20): it is empty
// now, and TestToolParity requires it to stay so — a new route gets its
// tool (or a noToolRoutes reason) in the change that adds it.
var pendingToolRoutes = map[string]string{}

// helpNoToolRoutes are the person's Sign-in routes (both listeners) with
// no tool (contract §15.10, D33): person_sign_in carries the last 20
// history entries.
var helpNoToolRoutes = map[string]string{
	"GET /api/directory/users/{username}/signin/history": "a person's history pages: person_sign_in carries the last 20 entries",
}

// impersonationNoToolRoutes are the routes of signing in as someone
// else with no tool (contract §15.10, D46), each with D46's reason: the
// start (both listeners), the impersonating browser's routes and the
// Stop page (people listener; TestPeopleToolParity reads them through
// peopleNoToolRoutes).
var impersonationNoToolRoutes = map[string]string{
	"POST /api/directory/users/{username}/impersonation": "needs the admin's fresh YubiKey touch and a typed reason; never by an AI",
	"GET /api/me/impersonation":                          "the impersonating browser only",
	"POST /api/me/impersonation/stop":                    "the impersonating browser only",
	"GET /impersonation/stop":                            "the impersonating browser only (the Stop page)",
}

// vpnNoToolRoutes are the VPN admin routes no tool mirrors (V9): Settings
// → VPN and the manual DNS acknowledgement are the admin UI's only.
var vpnNoToolRoutes = map[string]string{
	"PUT /api/vpn/settings":                "admin UI only (Settings → VPN)",
	"POST /api/instances/{id}/vpn-dns/ack": "admin UI only (the instance's VPN tab, after configuring the records by hand)",
}

// adminVPN are the VPN tools (§15.10).
var adminVPN = []string{"get_vpn", "list_vpn_devices", "remove_vpn_device", "set_vpn_provider", "assign_vpn_address", "set_instance_reach"}

// impersonationPartialTwins are the routes a tool mirrors for some
// bodies only, listed once with the reason for the rest (F27):
// turn_off_impersonation covers {"allowed": false}.
var impersonationPartialTwins = map[string]string{
	"PUT /api/signin/impersonation": "switched on in Hub Settings only",
}

// signInNoToolRoutes are the Sign-in page's people-listener routes with
// no people tool (contract §15.10, D33; TestPeopleToolParity reads them
// through peopleNoToolRoutes).
var signInNoToolRoutes = map[string]string{
	"GET /signin": "the Sign-in page itself: a browser UI",
	"POST /api/me/signin/yubikey-certificate/renew":    "the YubiKey renewal needs the certificate the browser presents (TLS), which an AI client never has",
	"GET /api/me/signin/history":                       "the history pages: my_sign_in carries the last 20 entries",
	"DELETE /api/me/signin/password":                   "removing your password: on the Sign-in page, where my_password hands off (D33 lists no tool for it)",
	"PUT /api/me/signin/passkeys/{credentialId}/label": "naming your passkeys: on the Sign-in page, where you can see which key is which (my_sign_in lists names and models)",
}

// destructiveTwins are the routes whose handler deletes, restores over,
// revokes or runs code, or has a typed confirmation today (spec call 25,
// §15.10): a class-D tool's twin must be one of them — unless the tool is
// in accessWidening.
var destructiveTwins = map[string]string{
	"DELETE /api/instances/{id}":                          "deletes the instance (typed id)",
	"/api/templates/exec/":                                "runs a command in a container",
	"PUT /api/instances/{id}/env/{name}":                  "writes a variable the app's code reads (set_env_override)",
	"DELETE /api/instances/{id}/env/{name}":               "switches an app's variable back to its default (clear_env_override)",
	"/api/templates/compose/":                             "writes the compose override that decides what runs (save_custom_override)",
	"/api/drift/resolve":                                  "stops, adopts or recreates a project",
	"DELETE /api/instances/{id}/credentials/{key}/{user}": "revokes a person's credential",
	// Task 17b.
	"/api/sources/remove":              "removes a source; its enabled apps are disabled",
	"POST /api/instances/{id}/restore": "restores over the instance",
	"POST /api/instances/restore":      "restores an archive into a new instance (data and access settings from the archive)",
	"DELETE /api/domains/{name}":       "deletes a domain (records, certificate)",
	// DNS hardening (§15.10, F1).
	"POST /api/domains/{name}/dnssec":                 "turns on DNSSEC signing for the whole zone; not undoable from Portcullis",
	"POST /api/instances/{id}/ai/revoke":              "revokes AI credentials in the app",
	"POST /api/instances/{id}/ai/dismiss":             "hides a leaver whose app tokens the Hub couldn't revoke (T27)",
	"DELETE /api/ai/providers/{name}":                 "deletes a model provider and its secrets",
	"POST /api/keycloak/user-sweep/resume":            "typed confirmation (resume): Keycloak then removes records LLDAP lacks",
	"DELETE /api/directory/keycloak-stale/{username}": "deletes a Keycloak record (typed username)",
	// Task 18 (§15.10's D list).
	"DELETE /api/directory/users/{username}":                       "deletes a person (typed username)",
	"POST /api/directory/users/{username}/remove-passkeys":         "removes a person's passkeys (typed username)",
	"DELETE /api/directory/users/{username}/certificates/{serial}": "revokes a person's certificate (sign-in part 2, D32)",
	"POST /api/directory/users/{username}/require-passkey":         "forces a passkey registration: on another administrator it hands over their sign-in (§15.10 lists require_passkey as D)",
	"DELETE /api/directory/groups/{group}":                         "deletes a group (typed name)",
	"DELETE /api/directory/fields/{name}":                          "deletes a field and every value of it (typed name)",
	// Task 20 (§15.10's D list, G45).
	"DELETE /api/folders/{id}":             "deletes a shared folder's definition",
	"POST /api/folders/{id}/undo/apply":    "restores a permissions snapshot over the folder's files",
	"POST /api/doctor/findings/{fp}/apply": "a one-click fix: D when its plan touches data (a folder apply or undo, an ownership change, a revocation; G45)",
	// VPN (§15.10).
	"DELETE /api/vpn/devices/{id}": "revokes a person's VPN device",
}

// accessWidening are the tools that are D only for some arguments (G37,
// ClassFor): their twin is a plain save.
var accessWidening = map[string]string{
	"set_sign_in_mode":   "D for native (the app's own login, no Portcullis sign-in)",
	"set_public_access":  "D when it turns public access on (or widens it to all)",
	"save_settings":      "D when it sets ports (host ports published, <KEY>_BIND changed)",
	"set_local_networks": "D unless use_defaults or a list within the current one",
	"enable_instance":    "D when the instance starts with public access on or the app's own login only (fix round 1), or its groups already have members (T18 fix round 1)",
	// Task 17b.
	"set_ai_support": "D when it switches a companion on",
	"set_ai_mode":    "D unless read_only",
	// Task 23.
	"set_ai_providers":    "D when it adds a model provider to an AI page (people's data goes to it)",
	"save_model_provider": "D when it changes where model traffic goes (base_url, instance, instance_name, region) or names no stored provider",
	"save_hub_settings":   "D when it turns AI or the people MCP on, changes clients or origins, or raises a limit or connection length",
	// Sign-in methods (Task 6).
	"set_sign_in_method":    "D when on; off W only when nobody is newly blocked and nobody is unknown (item-9 ruling)",
	"save_sign_in_template": "D unless creating, or the new rule Implies the old (switched-on and all available methods) and nobody is newly blocked or unknown",
	"set_default_template":  "D unless the new template Implies the current one (both switch states) and nobody is newly blocked or unknown",
	"set_core_template":     "D unless the new template Implies the current one (both switch states) and nobody is newly blocked or unknown",
	"set_sign_in_template":  "D unless the app's new template Implies its current one (both switch states) and nobody is newly blocked or unknown",
	"set_add_stronger":      "D when on, W when off",
	// Sign-in part 2 (Task 3).
	"set_sign_in_limits": "D when browser_cert_days or browser_cert_max_active go up or history_days goes down, else W",
	// Task 18 (G37 ruling 2; the directory's Membership.Guarding).
	"create_instance":   "D when one of its groups already exists with members, or the template / directory can't be read (T18 fix round 1)",
	"remove_member":     "D from an administrator, permission or guarding group (T18 fix round 1 ruling)",
	"update_field":      "D on a guarded field when it changes kind, values, multi or turns admin-only off (T18 fix round 1)",
	"add_member":        "D into an administrator, permission or guarding group (or one the directory can't place); on a rule-based group classed as add_exception{include:true} (ruleClass: D on an instance's access or admin group too)",
	"set_member_expiry": "D on an administrator, permission or guarding group",
	"set_group_rule":    "D on a guarding group",
	"convert_group":     "D on a guarding group",
	"add_exception":     "D on a guarding group (deviation: an included exception is a membership)",
	"remove_exception":  "D on a guarding group (deviation: dropping a kept-out exception lets the rule add them)",
	"set_details":       "D when it sets a field a guarding group's rule uses (deviation)",
	"import_apply":      "D when a row creates or deletes a person, or sets a field a guarding group's rule uses",
	// Task 20.
	"folder_apply":         "D unless the plan only removes uses and leaves the disk alone (AssignPlan.WidensAccess)",
	"folder_recheck_apply": "D when it accepts a different directory (confirm_different_directory)",
	"doctor_mute":          "D for a Problem, an ai_credentials_revoking finding or one the report doesn't have (fix round 1 ruling)",
	// Operation progress (Task 7 security review).
	// VPN (§15.10).
	"set_vpn_provider":   "D when it wires a provider (its devices become a way into VPN-only apps), W when it unwires",
	"assign_vpn_address": "D when it assigns an address to a person, W when it removes the assignment",
	"set_instance_reach": "D unless it narrows an instance to VPN-only through every provider without public links",
	"stop_op":            "D when the undo turns something back on: a disable's (enable_instance's class), a delete's of an enabled instance, a same-instance restore's of an enabled instance or once its rollback is armed, an AI switch-off's (set_ai_support on)",
}

// widensAlways are the D tools whose every call widens access (G37
// add_source; Task 17b: adding a model provider sends people's data to a
// new place): their twin is a plain add, and they have no ClassFor.
var widensAlways = map[string]string{
	"add_source":         "a source decides what apps can run (G37)",
	"add_model_provider": "what people send on the AI page goes to it, and its secrets (Task 17b ruling)",
	"set_permission":     "a delegated permission lets a group manage people (G37)",
}

func TestToolParity(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	routes := e.s.hubMux().patterns
	routeSet := map[string]bool{}
	for _, r := range routes {
		if routeSet[r] {
			t.Errorf("route %s registered twice", r)
		}
		routeSet[r] = true
	}
	tools := e.s.tools(ScopeAdmin)
	twins := map[string][]string{}
	for _, tl := range tools {
		// Every twin a tool mirrors (save_sign_in_template: two).
		for _, r := range append([]string{tl.Twin}, tl.AlsoTwins...) {
			twins[r] = append(twins[r], tl.Name)
		}
	}
	// Every route: a twin, no tool (with a reason), or pending.
	for _, r := range routes {
		_, none := noToolRoutes[r]
		_, conf := confirmationRoutes[r]
		_, help := helpNoToolRoutes[r]
		_, imp := impersonationNoToolRoutes[r]
		_, vpnNo := vpnNoToolRoutes[r]
		conf = conf || help || imp || vpnNo
		task, pending := pendingToolRoutes[r]
		n := 0
		for _, b := range []bool{len(twins[r]) > 0, none, conf, pending} {
			if b {
				n++
			}
		}
		switch {
		case n == 0:
			t.Errorf("route %s: no tool has it as Twin, and it isn't in noToolRoutes or pendingToolRoutes", r)
		case pending && len(twins[r]) > 0:
			t.Errorf("route %s is pending (%s) but %v already mirror it: remove it from pendingToolRoutes", r, task, twins[r])
		case n > 1:
			t.Errorf("route %s is listed twice (twin %v, noTool %v, confirmation %v, pending %v)", r, twins[r], none, conf, pending)
		}
	}
	// T20 emptied it: every route has its tool or a reason.
	if len(pendingToolRoutes) != 0 {
		t.Errorf("pendingToolRoutes = %v, want empty", pendingToolRoutes)
	}
	// noToolRoutes is exactly G15's list, each with a reason.
	g15 := []string{"/", "/static/", "/healthz", "GET /api/portal/apps", "GET /api/directory/me", importReviewPath}
	if len(noToolRoutes) != len(g15) {
		t.Errorf("noToolRoutes has %d entries, G15 lists %d", len(noToolRoutes), len(g15))
	}
	for _, r := range g15 {
		if strings.TrimSpace(noToolRoutes[r]) == "" {
			t.Errorf("noToolRoutes %s: missing or no reason", r)
		}
	}
	for _, m := range []map[string]string{noToolRoutes, confirmationRoutes, pendingToolRoutes, helpNoToolRoutes, impersonationPartialTwins, vpnNoToolRoutes} {
		for r := range m {
			if !routeSet[r] {
				t.Errorf("listed route %s isn't a Hub-listener route", r)
			}
		}
	}
	for r, why := range confirmationRoutes {
		if strings.TrimSpace(why) == "" {
			t.Errorf("confirmationRoutes %s: no reason", r)
		}
	}
	// Every admin tool's twin is a route.
	for _, tl := range tools {
		for _, r := range append([]string{tl.Twin}, tl.AlsoTwins...) {
			if !routeSet[r] {
				t.Errorf("tool %s: twin %q is no Hub-listener route", tl.Name, r)
			}
		}
	}
	// Class D: a destructive twin, or an access-widening call with ClassFor.
	byName := map[string]Tool{}
	for _, tl := range tools {
		byName[tl.Name] = tl
		if tl.Class != ClassDestructive {
			if tl.ClassFor != nil {
				t.Errorf("tool %s has ClassFor but class %s", tl.Name, tl.Class)
			}
			continue
		}
		_, widening := accessWidening[tl.Name]
		_, always := widensAlways[tl.Name]
		switch {
		case widening && tl.ClassFor == nil:
			t.Errorf("tool %s is access-widening but has no ClassFor", tl.Name)
		case always && tl.ClassFor != nil:
			t.Errorf("tool %s widens on every call but has a ClassFor", tl.Name)
		case always:
		case !widening && destructiveTwins[tl.Twin] == "":
			t.Errorf("D tool %s: twin %s neither deletes, restores, revokes, runs code nor has a typed check", tl.Name, tl.Twin)
		}
	}
	for _, n := range []string{"exec", "set_env_override", "clear_env_override", "save_custom_override", "resolve_drift", "delete_instance", "admin_revoke_credential",
		"set_sign_in_mode", "set_public_access", "save_settings", "set_local_networks", "enable_instance",
		// Task 17b (§15.10's D list, G37 and its rulings).
		"add_source", "remove_source", "restore_instance", "restore_as", "delete_domain", "revoke_ai_access", "dismiss_ai_revoke_problem",
		"add_model_provider", "delete_model_provider", "resume_user_sweep", "remove_stale_keycloak_user",
		"set_ai_support", "set_ai_mode", "save_model_provider", "save_hub_settings",
		// Task 23.
		"set_ai_providers",
		// Task 18 (§15.10, G37).
		"delete_person", "delete_group", "delete_field", "require_passkey", "remove_passkeys", "set_permission",
		// Sign-in part 2 (Task 7).
		"revoke_person_certificate",
		"create_instance", "remove_member", "update_field", "add_member", "set_member_expiry", "set_group_rule", "convert_group", "add_exception",
		"remove_exception", "set_details", "import_apply",
		// Task 20 (§15.10, G15, G45).
		"delete_folder", "folder_undo_apply", "doctor_apply_fix", "folder_apply", "folder_recheck_apply", "doctor_mute",
		// Task 7 security review.
		"stop_op",
		// Sign-in methods (Task 6).
		"set_sign_in_method", "save_sign_in_template", "set_default_template", "set_core_template", "set_sign_in_template", "set_add_stronger", "set_sign_in_limits",
		// DNS hardening (F1).
		"enable_domain_dnssec",
		// VPN (§15.10).
		"remove_vpn_device", "set_vpn_provider", "assign_vpn_address", "set_instance_reach"} {
		if byName[n].Class != ClassDestructive {
			t.Errorf("tool %s: class %q, want D", n, byName[n].Class)
		}
	}
	// U tools (Task 17b): domain tokens and provider secrets.
	for _, n := range []string{"set_secret_setting", "add_domain", "replace_domain_token", "set_model_provider_secret", "set_password",
		"create_person", "send_invite"} {
		if byName[n].Class != ClassSecret {
			t.Errorf("tool %s: class %q, want U", n, byName[n].Class)
		}
	}
	// W (Task 17b): a backup can't widen access (the archive stays in the
	// Hub's data; the instance comes back as it was); a sync pulls the
	// sources the admin added.
	for _, n := range []string{"backup_instance", "sync_sources", "update_person", "clear_actions", "create_group", "create_field",
		"doctor_scan", "doctor_unmute", "create_folder", "update_folder",
		// Operation progress (§15.10): a Stop only reverses what the
		// running operation did; the long operations' tools stay W / per call.
		"disable_instance", "restart_instance",
		// Sign-in methods (Task 6).
		"set_sign_in_template_enabled", "delete_sign_in_template",
		// DNS hardening (F1).
		"apply_domain_dns"} {
		if byName[n].Class != ClassWrite {
			t.Errorf("tool %s: class %q, want W", n, byName[n].Class)
		}
	}
	// doctor_apply_fix and folder_apply decide per call (G45; Task 20).
	for _, n := range []string{"doctor_apply_fix", "folder_apply", "folder_recheck_apply", "doctor_mute"} {
		if byName[n].ClassFor == nil {
			t.Errorf("tool %s has no ClassFor", n)
		}
	}
	// R (Task 20): reads and previews only.
	for _, n := range []string{"doctor_findings", "doctor_op", "doctor_preview_fix", "list_folders", "check_folder_path", "folder_preview",
		"folder_undo_preview", "folder_recheck_preview", "folder_op"} {
		if byName[n].Class != ClassRead {
			t.Errorf("tool %s: class %q, want R", n, byName[n].Class)
		}
	}
	// R (sign-in Task 6).
	for _, n := range []string{"get_sign_in", "get_instance_sign_in", "preview_sign_in_template", "sign_in_impact", "person_sign_in", "issue_yubikey_certificate",
		// DNS hardening (F1).
		"get_domain_dns", "get_main_dns", "domain_op",
		// Rootless Podman (P3).
		"get_runtime",
		// VPN (§15.10).
		"get_vpn", "list_vpn_devices"} {
		if byName[n].Class != ClassRead {
			t.Errorf("tool %s: class %q, want R", n, byName[n].Class)
		}
	}
	// The tools of every part are all there.
	for _, n := range append(append(append(append(append(slices.Clone(admin17a), admin17b...), admin18...), admin20...), adminSignIn...), adminVPN...) {
		if _, ok := byName[n]; !ok {
			t.Errorf("tool %s is not registered", n)
		}
	}
}

// adminSignIn are the sign-in tools (sign-in Task 6, §15.10).
var adminSignIn = []string{
	"get_sign_in", "get_instance_sign_in", "preview_sign_in_template", "set_sign_in_method", "save_sign_in_template",
	"set_sign_in_template_enabled", "delete_sign_in_template", "set_default_template", "set_core_template",
	"set_sign_in_template", "set_add_stronger", "sign_in_impact", "set_sign_in_limits",
	// Sign-in part 2 (Task 7).
	"person_sign_in", "revoke_person_certificate", "issue_yubikey_certificate",
}

// admin20 are the doctor and shared-folder tools of T20.
var admin20 = []string{
	"doctor_findings", "doctor_scan", "doctor_op", "doctor_preview_fix", "doctor_apply_fix", "doctor_mute", "doctor_unmute",
	"list_folders", "create_folder", "update_folder", "delete_folder", "check_folder_path",
	"folder_preview", "folder_apply", "folder_undo_preview", "folder_undo_apply", "folder_recheck_preview", "folder_recheck_apply", "folder_op",
}

// admin18 are the users and groups tools of T18.
var admin18 = []string{
	"directory_overview", "get_person", "preview_rule", "convert_group_preview", "import_review", "audit_recent", "get_person_apps", "get_group_uses",
	"create_person", "update_person", "set_details", "require_passkey", "remove_passkeys", "set_password", "send_invite",
	"clear_actions", "delete_person", "create_group", "delete_group", "add_member", "remove_member", "set_member_expiry",
	"set_group_rule", "convert_group", "add_exception", "remove_exception", "set_permission",
	"create_field", "update_field", "delete_field", "import_apply",
}

// admin17b are the admin tools of T17b (catalog and sources, backups,
// domains, AI, Hub settings and their G15 tools).
var admin17b = []string{
	"list_templates", "get_template", "list_sources", "sync_sources", "add_source", "remove_source",
	"list_backups", "list_backups_all", "backup_instance", "restore_instance", "restore_as",
	"list_domains", "add_domain", "replace_domain_token", "delete_domain",
	"ai_status", "set_ai_support", "set_ai_mode", "set_ai_providers", "revoke_ai_access", "dismiss_ai_revoke_problem", "ai_activity",
	"list_model_providers", "add_model_provider", "save_model_provider", "set_model_provider_secret", "delete_model_provider",
	"get_hub_settings", "save_hub_settings",
	"user_sweep_status", "resume_user_sweep", "remove_stale_keycloak_user",
}

// admin17a are the admin tools of T17a (overview, instances, settings,
// runtime, drift and their G15 tools).
var admin17a = []string{
	"hub_status", "explain_policy",
	"list_instances", "get_instance", "instance_defaults", "create_instance", "enable_instance", "disable_instance",
	"restart_instance", "set_hosts", "set_instance_label", "get_op", "list_ops", "wait_for_op", "stop_op", "delete_instance",
	"get_settings", "preview_settings", "save_settings", "set_secret_setting", "set_sign_in_mode", "set_public_access",
	"get_logs", "get_status", "exec", "get_compose", "get_env", "set_env_override", "clear_env_override", "get_custom_override", "save_custom_override",
	"list_drift", "resolve_drift",
	"set_person_value", "clear_person_value", "retry_deliveries", "missing_groups", "create_missing_groups",
	"list_credentials", "admin_revoke_credential", "get_local_networks", "set_local_networks",
	"get_runtime",
}

// TestParityImpersonation (D46, F27): the routes of signing in as
// someone else without a tool carry D46's reasons; PUT
// /api/signin/impersonation is listed once, with its reason, and
// turn_off_impersonation covers {"allowed": false}; the start has no
// tool on either listener.
func TestParityImpersonation(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	const start = "POST /api/directory/users/{username}/impersonation"
	want := map[string]string{
		start:                             "needs the admin's fresh YubiKey touch and a typed reason; never by an AI",
		"GET /api/me/impersonation":       "the impersonating browser only",
		"POST /api/me/impersonation/stop": "the impersonating browser only",
	}
	for r, why := range want {
		if impersonationNoToolRoutes[r] != why {
			t.Errorf("%s: reason %q, want %q", r, impersonationNoToolRoutes[r], why)
		}
		if peopleNoToolRoutes[r] != why {
			t.Errorf("people %s: reason %q, want %q", r, peopleNoToolRoutes[r], why)
		}
	}
	if !strings.HasPrefix(impersonationNoToolRoutes["GET /impersonation/stop"], "the impersonating browser only") {
		t.Errorf("the Stop page's reason = %q", impersonationNoToolRoutes["GET /impersonation/stop"])
	}
	const put = "PUT /api/signin/impersonation"
	if len(impersonationPartialTwins) != 1 || impersonationPartialTwins[put] != "switched on in Hub Settings only" {
		t.Errorf("impersonationPartialTwins = %v", impersonationPartialTwins)
	}
	if _, dup := impersonationNoToolRoutes[put]; dup || noToolRoutes[put] != "" {
		t.Errorf("%s listed more than once", put)
	}
	var putTwins []string
	for _, tl := range e.s.tools(ScopeAdmin) {
		if tl.Twin == put || slices.Contains(tl.AlsoTwins, put) {
			putTwins = append(putTwins, tl.Name)
		}
		if tl.Twin == start || slices.Contains(tl.AlsoTwins, start) {
			t.Errorf("tool %s mirrors the start", tl.Name)
		}
	}
	if !slices.Equal(putTwins, []string{"turn_off_impersonation"}) {
		t.Errorf("%s twins = %v, want [turn_off_impersonation]", put, putTwins)
	}
	hub := map[string]bool{}
	for _, p := range e.s.hubMux().patterns {
		hub[p] = true
	}
	for _, r := range []string{start, put, "GET /api/impersonations", "POST /api/directory/users/{username}/impersonation/stop"} {
		if !hub[r] {
			t.Errorf("the Hub listener lacks %s", r)
		}
	}
	for _, r := range []string{"GET /api/me/impersonation", "POST /api/me/impersonation/stop", "GET /impersonation/stop"} {
		if hub[r] {
			t.Errorf("the Hub listener registers %s (people only)", r)
		}
	}
}
