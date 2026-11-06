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
// the task ("T17b", "T18", "T20"). Each task removes its entries; T20
// leaves it empty.
var pendingToolRoutes = map[string]string{
	// T17b: catalog and sources.
	"/api/templates":      "T17b",
	"/api/sources":        "T17b",
	"/api/sources/add":    "T17b",
	"/api/sources/remove": "T17b",
	"/api/sources/sync":   "T17b",
	// T17b: backups.
	"GET /api/backups":                 "T17b",
	"GET /api/instances/{id}/backups":  "T17b",
	"POST /api/instances/{id}/backups": "T17b",
	"POST /api/instances/{id}/restore": "T17b",
	"POST /api/instances/restore":      "T17b",
	// T17b: domains.
	"GET /api/domains":               "T17b",
	"POST /api/domains":              "T17b",
	"POST /api/domains/{name}/token": "T17b",
	"DELETE /api/domains/{name}":     "T17b",
	// T17b: AI and Hub settings.
	"GET /api/ai/settings":                         "T17b",
	"PUT /api/ai/settings":                         "T17b",
	"GET /api/ai/providers":                        "T17b",
	"POST /api/ai/providers":                       "T17b",
	"PUT /api/ai/providers/{name}":                 "T17b",
	"DELETE /api/ai/providers/{name}":              "T17b",
	"PUT /api/ai/providers/{name}/secrets/{field}": "T17b",
	"GET /api/instances/{id}/ai":                   "T17b",
	"PUT /api/instances/{id}/ai":                   "T17b",
	"/api/settings":                                "T17b",
	"POST /api/settings/preview":                   "T17b",
	// T18: users and groups, the Keycloak user sweep.
	"GET /api/directory":                                          "T18",
	"GET /api/directory/audit":                                    "T18",
	"POST /api/directory/users":                                   "T18",
	"PUT /api/directory/users/{username}":                         "T18",
	"DELETE /api/directory/users/{username}":                      "T18",
	"POST /api/directory/users/{username}/password":               "T18",
	"POST /api/directory/users/{username}/invite":                 "T18",
	"POST /api/directory/users/{username}/require-passkey":        "T18",
	"POST /api/directory/users/{username}/clear-actions":          "T18",
	"POST /api/directory/users/{username}/remove-passkeys":        "T18",
	"DELETE /api/directory/keycloak-stale/{username}":             "T18",
	"POST /api/directory/groups":                                  "T18",
	"DELETE /api/directory/groups/{group}":                        "T18",
	"POST /api/directory/groups/{group}/members":                  "T18",
	"DELETE /api/directory/groups/{group}/members/{username}":     "T18",
	"POST /api/directory/fields":                                  "T18",
	"PUT /api/directory/fields/{name}":                            "T18",
	"DELETE /api/directory/fields/{name}":                         "T18",
	"PUT /api/directory/users/{username}/details":                 "T18",
	"POST /api/directory/rules/preview":                           "T18",
	"PUT /api/directory/groups/{group}/rule":                      "T18",
	"POST /api/directory/groups/{group}/convert-preview":          "T18",
	"POST /api/directory/groups/{group}/convert":                  "T18",
	"POST /api/directory/groups/{group}/exceptions":               "T18",
	"DELETE /api/directory/groups/{group}/exceptions/{username}":  "T18",
	"PUT /api/directory/groups/{group}/members/{username}/expiry": "T18",
	"PUT /api/directory/permissions/{perm}":                       "T18",
	"POST /api/directory/import/apply":                            "T18",
	"GET /api/keycloak/user-sweep":                                "T18",
	"POST /api/keycloak/user-sweep/resume":                        "T18",
	// T20: doctor and shared folders.
	"GET /api/doctor":                        "T20",
	"POST /api/doctor/scan":                  "T20",
	"GET /api/doctor/op":                     "T20",
	"POST /api/doctor/findings/{fp}/preview": "T20",
	"POST /api/doctor/findings/{fp}/apply":   "T20",
	"POST /api/doctor/findings/{fp}/mute":    "T20",
	"DELETE /api/doctor/findings/{fp}/mute":  "T20",
	"GET /api/folders":                       "T20",
	"POST /api/folders":                      "T20",
	"PUT /api/folders/{id}":                  "T20",
	"DELETE /api/folders/{id}":               "T20",
	"POST /api/folders/check":                "T20",
	"POST /api/folders/{id}/assign/preview":  "T20",
	"POST /api/folders/{id}/assign/apply":    "T20",
	"POST /api/folders/{id}/undo/preview":    "T20",
	"POST /api/folders/{id}/undo/apply":      "T20",
	"POST /api/folders/{id}/recheck/preview": "T20",
	"POST /api/folders/{id}/recheck/apply":   "T20",
	"GET /api/folders/{id}/op":               "T20",
}

// destructiveTwins are the routes whose handler deletes, restores over,
// revokes or runs code, or has a typed confirmation today (spec call 25,
// §15.10): a class-D tool's twin must be one of them — unless the tool is
// in accessWidening.
var destructiveTwins = map[string]string{
	"DELETE /api/instances/{id}":                          "deletes the instance (typed id)",
	"/api/templates/exec/":                                "runs a command in a container",
	"/api/templates/env/":                                 "writes the env the app's code reads (save_env)",
	"/api/templates/compose/":                             "writes the compose override that decides what runs (save_custom_override)",
	"/api/drift/resolve":                                  "stops, adopts or recreates a project",
	"DELETE /api/instances/{id}/credentials/{key}/{user}": "revokes a person's credential",
}

// accessWidening are the tools that are D only for some arguments (G37,
// ClassFor): their twin is a plain save.
var accessWidening = map[string]string{
	"set_policy":        "D unless the new policy is policy.Stricter than the current one",
	"set_sign_in_mode":  "D for native (the app's own login, no Portcullis sign-in)",
	"set_public_access": "D when it turns public access on (or widens it to all)",
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
		twins[tl.Twin] = append(twins[tl.Twin], tl.Name)
	}
	// Every route: a twin, no tool (with a reason), or pending.
	for _, r := range routes {
		_, none := noToolRoutes[r]
		_, conf := confirmationRoutes[r]
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
		if pending && !slices.Contains([]string{"T17b", "T18", "T20"}, task) {
			t.Errorf("pending route %s: task %q", r, task)
		}
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
	for _, m := range []map[string]string{noToolRoutes, confirmationRoutes, pendingToolRoutes} {
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
		if !routeSet[tl.Twin] {
			t.Errorf("tool %s: twin %q is no Hub-listener route", tl.Name, tl.Twin)
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
		switch {
		case widening && tl.ClassFor == nil:
			t.Errorf("tool %s is access-widening but has no ClassFor", tl.Name)
		case !widening && destructiveTwins[tl.Twin] == "":
			t.Errorf("D tool %s: twin %s neither deletes, restores, revokes, runs code nor has a typed check", tl.Name, tl.Twin)
		}
	}
	for _, n := range []string{"exec", "save_env", "save_custom_override", "resolve_drift", "delete_instance", "admin_revoke_credential",
		"set_policy", "set_sign_in_mode", "set_public_access"} {
		if byName[n].Class != ClassDestructive {
			t.Errorf("tool %s: class %q, want D", n, byName[n].Class)
		}
	}
	// The tools of this part (17a) are all there.
	for _, n := range admin17a {
		if _, ok := byName[n]; !ok {
			t.Errorf("tool %s is not registered", n)
		}
	}
}

// admin17a are the admin tools of T17a (overview, instances, settings,
// runtime, drift and their G15 tools).
var admin17a = []string{
	"hub_status", "explain_policy",
	"list_instances", "get_instance", "instance_defaults", "create_instance", "enable_instance", "disable_instance",
	"restart_instance", "set_hosts", "get_op", "wait_for_op", "delete_instance",
	"get_settings", "preview_settings", "save_settings", "set_secret_setting", "set_policy", "set_sign_in_mode", "set_public_access",
	"get_logs", "get_status", "exec", "get_compose", "get_env", "save_env", "get_custom_override", "save_custom_override",
	"list_drift", "resolve_drift",
	"set_person_value", "clear_person_value", "retry_deliveries", "missing_groups", "create_missing_groups",
	"list_credentials", "admin_revoke_credential", "get_local_networks", "set_local_networks",
}
