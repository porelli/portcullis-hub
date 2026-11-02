package templates

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Settings fixtures (contract §13). Each case is a whole template run
// through Discover's pipeline (build); want "" = accepted, otherwise the
// error must contain "setting <key>" (when key is set) and want.

// hdrHead is a header-auth app behind Portcullis (group-gate on its router).
const hdrHead = `name: App
auth:
  method: header-auth
  group_access: true
  access_group: users_app
  admin_group: admin_app
`

const hdrCompose = "services:\n  web:\n    image: x\n    environment:\n      TRASH_DAYS: ${TRASH_DAYS:-30}\n      THEME: ${THEME:-dark}\n      HARD: literal\n      DISK_1: ${DISK_1:-}\n      DISK_2: ${DISK_2:-}\n    labels:\n" +
	"      traefik.http.routers.app.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`)\n" +
	"      traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"  init:\n    image: x\n"

// oidcHead is a native-oidc app with one Keycloak client "app".
const oidcHead = `name: App
auth:
  method: native-oidc
  group_access: true
  access_group: users_app
  admin_group: admin_app
keycloak_clients:
  - {client_id: app, secret_env: APP_SECRET, redirect_uri: "https://{{HOST_APP}}/cb"}
env:
  - {key: APP_SECRET, generate: random}
`

const oidcCompose = "services:\n  web:\n    image: x\n    environment:\n      APP_SECRET: ${APP_SECRET}\n      TRASH_DAYS: ${TRASH_DAYS:-30}\n    labels:\n" +
	"      traefik.http.routers.app.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`)\n"

// The spec's Firefox Sync block (call 32), as a whole template.
const firefoxHead = `name: Firefox Sync
auth:
  method: custom
  group_access: false
  access_group: users_firefox-sync
`

const firefoxSettings = `settings:
  sections: [Accounts]
  options:
    - key: mozilla_uid
      label: Mozilla account ID
      description: >
        The uid of the Mozilla account you sign in to Firefox with
        (32 lowercase hexadecimal characters). Only accounts listed here
        can sync with this server.
      type: string
      pattern: '^[0-9a-f]{32}$'
      min_len: 32
      max_len: 32
      scope: person_entered
      unique: true
      admin_override: true
      section: Accounts
      applies: restart
      delivery: [{file: {name: allowlist}}]
    - key: extra_accounts
      label: Other allowed accounts
      type: list
      items: {type: string, pattern: '^[0-9a-f]{32}$'}
      unique: true
      scope: instance
      section: Accounts
      applies: restart
      delivery: [{file: {name: allowlist}}]
files:
  - name: allowlist
    service: firefox-sync-init
    mount: /portcullis
    on_membership_change: restart
`

const firefoxCompose = "services:\n  firefox-sync:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.sync.rule: Host(`${PORTCULLIS_HOST_SYNC:-sync.portcullis.local}`)\n" +
	"  firefox-sync-init:\n    image: x\n"

type settingsCase struct {
	name     string
	manifest string
	compose  string
	key      string // the option the refusal must name
	want     string // "" = accepted
}

// opts wraps flow-style option lines into a settings block.
func opts(lines ...string) string {
	return "settings:\n  options:\n    - " + strings.Join(lines, "\n    - ") + "\n"
}

func runSettingsCases(t *testing.T, cases []settingsCase) {
	t.Helper()
	for _, c := range cases {
		_, err := build("app", "src", "", []byte(c.manifest), []byte(c.compose), "example.org", nil)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted, want %q", c.name, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || (c.key != "" && !strings.Contains(err.Error(), "setting "+c.key)) {
			t.Errorf("%s: error %q, want %q naming setting %q", c.name, err, c.want, c.key)
		}
	}
}

func TestOptionKeyRule(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"upper", hdrHead + opts("{key: IMMICH_X, label: X, type: string}"), hdrCompose, "IMMICH_X", "must match"},
		{"digit", hdrHead + opts("{key: 1a, label: X, type: string}"), hdrCompose, "1a", "must match"},
		{"long", hdrHead + opts("{key: "+strings.Repeat("a", 41)+", label: X, type: string}"), hdrCompose, "", "must match"},
		{"duplicate", hdrHead + opts("{key: trash_days, label: X, type: int}", "{key: trash_days, label: Y, type: int, delivery: [{env: THEME}]}"), hdrCompose, "trash_days", "declared twice"},
		{"no label", hdrHead + opts("{key: trash_days, type: int}"), hdrCompose, "trash_days", "label"},
		{"unknown field", hdrHead + opts("{key: trash_days, label: X, type: int, priviledged: true}"), hdrCompose, "", "priviledged"},
		{"unknown section", hdrHead + opts("{key: trash_days, label: X, type: int, section: Nope}"), hdrCompose, "trash_days", "section"},
		{"ok", hdrHead + opts("{key: trash_days, label: Keep deleted items for, type: int, unit: days, min: 0, max: 3650, default: 30}"), hdrCompose, "", ""},
	})
}

func TestOldTypesRefused(t *testing.T) {
	for old, repl := range map[string]string{"text": "string", "boolean": "bool", "select": "enum", "paths": "path"} {
		runSettingsCases(t, []settingsCase{
			{old, hdrHead + opts("{key: theme, label: X, type: "+old+"}"), hdrCompose, "theme", "use " + repl},
		})
	}
	runSettingsCases(t, []settingsCase{
		{"v2 list", hdrHead + "settings:\n  - key: THEME\n    type: text\n", hdrCompose, "", "contract v3"},
		{"unknown type", hdrHead + opts("{key: theme, label: X, type: colour}"), hdrCompose, "theme", "unknown type"},
	})
}

func TestReservedTypesRefused(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"folder", hdrHead + opts("{key: media, label: X, type: folder}"), hdrCompose, "media", "type folder needs shared folders (project 2)"},
		{"person_secret", hdrHead + opts("{key: smb, label: X, type: person_secret}"), hdrCompose, "smb", "type person_secret needs file sharing (project 3)"},
		{"person_id", hdrHead + opts("{key: uid, label: X, type: person_id}"), hdrCompose, "uid", "type person_id needs file sharing (project 3)"},
		{"folder block", hdrHead + opts("{key: media, label: X, type: path, target: {service: web, mount: /media}, folder: {access: read}}"), hdrCompose, "media", "shared folders (project 2)"},
		{"checks", hdrHead + opts("{key: media, label: X, type: path, target: {service: web, mount: /media}, checks: [{kind: exclusive}]}"), hdrCompose, "media", "shared folders (project 2)"},
		{"hash", hdrHead + opts("{key: theme, label: X, type: string, hash: nt}"), hdrCompose, "theme", "file sharing (project 3)"},
		{"bare delivery", hdrHead + opts("{key: theme, label: X, type: string, delivery: file}"), hdrCompose, "theme", "file sharing (project 3)"},
	})
	if f := ReservedFeature(&Option{Type: TypeString}); f != "" {
		t.Errorf("ReservedFeature(string) = %q", f)
	}
	for typ := range BuiltinTypes {
		if f := ReservedFeature(&Option{Type: typ}); f != "" {
			t.Errorf("builtin %s is reserved: %q", typ, f)
		}
	}
	if len(BuiltinTypes) != 15 || BuiltinTypes[TypeFolder] || BuiltinTypes[TypePersonSecret] || BuiltinTypes[TypePersonID] {
		t.Errorf("BuiltinTypes = %v", BuiltinTypes)
	}
	// A Hub whose registry knows the type still refuses a reserved one
	// until its project lands; an unknown type is refused by known.
	only := func(typ string) bool { return typ == TypeString }
	if _, err := build("app", "src", "", []byte(hdrHead+opts("{key: n, label: N, type: int, delivery: [{env: THEME}]}")), []byte(hdrCompose), "example.org", only); err == nil || !strings.Contains(err.Error(), "setting n") {
		t.Errorf("type unknown to known() accepted: %v", err)
	}
}

const personClaim = "delivery: [{claim: {client: app, name: app_quota, json_type: int}}]"

func TestPersonScopeNeedsDefaultAndPersonDelivery(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"no default", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, resolve: max, "+personClaim+"}"), oidcCompose, "quota", "default"},
		{"env only", hdrHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{env: TRASH_DAYS}]}"), hdrCompose, "quota", "per-person env is not allowed"},
		{"no delivery", hdrHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1}"), hdrCompose, "quota", "per-person delivery"},
		{"claim", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 10, resolve: max, "+personClaim+"}"), oidcCompose, "", ""},
		{"bad scope", hdrHead + opts("{key: quota, label: Q, type: int, scope: everyone}"), hdrCompose, "quota", "scope"},
		{"group default", hdrHead + opts("{key: quota, label: Q, type: int, scope: group, default: 1, delivery: [{env: THEME, render: {format: json}}]}"), hdrCompose, "quota", "default"},
		{"group env not json", hdrHead + opts("{key: quota, label: Q, type: int, scope: group, delivery: [{env: THEME}]}"), hdrCompose, "quota", "format: json"},
		{"group claim", oidcHead + opts("{key: quota, label: Q, type: int, scope: group, "+personClaim+"}"), oidcCompose, "quota", "claim"},
		{"instance header", hdrHead + opts("{key: quota, label: Q, type: int, delivery: [{header: {name: X-Forwarded-Attr-Quota}}]}"), hdrCompose, "quota", "header"},
		{"instance resolve", hdrHead + opts("{key: trash_days, label: Q, type: int, resolve: max}"), hdrCompose, "trash_days", "resolve"},
		{"instance privileged", hdrHead + opts("{key: trash_days, label: Q, type: bool, privileged: true}"), hdrCompose, "trash_days", "privileged"},
		{"instance self_visible", hdrHead + opts("{key: trash_days, label: Q, type: int, self_visible: false}"), hdrCompose, "trash_days", "self_visible"},
		{"two kinds in one delivery", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{env: TRASH_DAYS, hook: x}]}"), oidcCompose, "quota", "exactly one"},
	})
}

func TestResolveFitsType(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"max on string", oidcHead + opts("{key: quota, label: Q, type: string, scope: person, default: a, resolve: max, "+personClaim+"}"), oidcCompose, "quota", "resolve max"},
		{"union on list", oidcHead + opts("{key: langs, label: L, type: list, items: {type: string}, scope: person, default: [en], resolve: union, delivery: [{claim: {client: app, name: app_langs, json_type: json}}]}"), oidcCompose, "", ""},
		{"any on bool", oidcHead + opts("{key: beta, label: B, type: bool, scope: person, default: false, resolve: any, delivery: [{claim: {client: app, name: app_beta, json_type: bool}}]}"), oidcCompose, "", ""},
		{"priority on string", oidcHead + opts("{key: quota, label: Q, type: string, scope: person, default: a, resolve: priority, "+personClaim+"}"), oidcCompose, "", ""},
		{"unknown rule", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, resolve: avg, "+personClaim+"}"), oidcCompose, "quota", "resolve avg"},
		{"choice does not fit", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, resolve: max, resolve_choices: [max, min, union], "+personClaim+"}"), oidcCompose, "quota", "resolve_choices: union"},
		{"choices fit", oidcHead + opts("{key: quota, label: Q, type: size, step: 1GiB, allow_unlimited: true, scope: person, default: 100GiB, resolve: max, resolve_choices: [max, min, priority], "+personClaim+"}"), oidcCompose, "", ""},
	})
}

func TestEnvNames(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"default env", hdrHead + opts("{key: trash_days, label: X, type: int}"), hdrCompose, "", ""},
		{"reserved prefix", hdrHead + opts("{key: x, label: X, type: string, delivery: [{env: PORTCULLIS_X}]}"), hdrCompose, "x", "reserved"},
		{"instance variable", hdrHead + opts("{key: x, label: X, type: string, delivery: [{env: PORTCULLIS_INSTANCE}]}"), hdrCompose, "", "PORTCULLIS_INSTANCE"},
		{"bad name", hdrHead + opts("{key: x, label: X, type: string, delivery: [{env: A-B}]}"), hdrCompose, "x", "env name"},
		{"two options", hdrHead + opts("{key: a, label: A, type: string, delivery: [{env: THEME}]}", "{key: b, label: B, type: string, delivery: [{env: THEME}]}"), hdrCompose, "b", "THEME"},
		{"with env[]", hdrHead + "env:\n  - {key: THEME}\n" + opts("{key: theme, label: T, type: string}"), hdrCompose, "theme", "THEME"},
		{"with ports[]", hdrHead + "ports:\n  - {key: THEME, container: 80, service: web}\n" + opts("{key: theme, label: T, type: string}"), hdrCompose, "theme", "THEME"},
		{"with port bind", hdrHead + "ports:\n  - {key: TRASH, container: 80, service: web}\n" + opts("{key: x, label: T, type: string, delivery: [{env: TRASH_BIND}]}"), hdrCompose, "x", "TRASH_BIND"},
		{"not referenced", hdrHead + opts("{key: missing, label: M, type: string}"), hdrCompose, "missing", "not referenced"},
		{"hard-coded", hdrHead + opts("{key: hard, label: H, type: string}"), hdrCompose, "hard", "hard-codes"},
		{"indexed", hdrHead + opts("{key: disks, label: D, type: list, items: {type: string, pattern: '^/dev/'}, max_items: 2, delivery: [{env: 'DISK_{n}'}]}"), hdrCompose, "", ""},
		{"indexed no max_items", hdrHead + opts("{key: disks, label: D, type: list, items: {type: string}, delivery: [{env: 'DISK_{n}'}]}"), hdrCompose, "disks", "max_items"},
		{"indexed unreferenced", hdrHead + opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 3, delivery: [{env: 'DISK_{n}'}]}"), hdrCompose, "disks", "DISK_3"},
		{"indexed beyond max_items", hdrHead + opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 1, delivery: [{env: 'DISK_{n}'}]}"), hdrCompose, "disks", "DISK_2"},
		{"indexed on string", hdrHead + opts("{key: disks, label: D, type: string, max_items: 2, delivery: [{env: 'DISK_{n}'}]}"), hdrCompose, "disks", "list"},
		{"indexed dup", hdrHead + opts("{key: disks, label: D, type: list, items: {type: string}, max_items: 2, delivery: [{env: 'DISK_{n}'}]}", "{key: d1, label: D, type: string, delivery: [{env: DISK_1}]}"), hdrCompose, "d1", "DISK_1"},
	})
	// The list form: "- THEME=dark" hard-codes THEME.
	c := strings.Replace(hdrCompose, "      THEME: ${THEME:-dark}\n", "", 1)
	c = strings.Replace(c, "    environment:\n", "    environment:\n      - THEME=dark\n      - X=${THEME}\n", 1)
	c = strings.Replace(c, "      TRASH_DAYS: ${TRASH_DAYS:-30}\n      HARD: literal\n      DISK_1: ${DISK_1:-}\n      DISK_2: ${DISK_2:-}\n", "", 1)
	runSettingsCases(t, []settingsCase{{"list hard-coded", hdrHead + opts("{key: theme, label: T, type: string}"), c, "theme", "hard-codes"}})
	o := &Option{Key: "trash_days"}
	if o.EnvName() != "TRASH_DAYS" || o.EffectiveScope() != ScopeInstance {
		t.Errorf("EnvName = %q, scope %q", o.EnvName(), o.EffectiveScope())
	}
	if (&Option{Key: "m", Type: TypePath}).EnvName() != "" || (&Option{Key: "q", Scope: ScopePerson}).EnvName() != "" {
		t.Error("path / person options deliver no env by default")
	}
	n := 2
	l := &Option{Key: "disks", Type: TypeList, MaxItems: &n, Delivery: Deliveries{{Env: "DISK_{n}"}}}
	if strings.Join(l.EnvNames(), ",") != "DISK_1,DISK_2" {
		t.Errorf("EnvNames = %v", l.EnvNames())
	}
}

func TestClaimDeliveryNeedsNativeOIDCClient(t *testing.T) {
	cases := []settingsCase{
		{"forward-auth", hdrHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, "+personClaim+"}"), hdrCompose, "quota", "native-oidc"},
		{"unknown client", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{claim: {client: other, name: app_quota, json_type: int}}]}"), oidcCompose, "quota", "client other"},
		{"bad json_type", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{claim: {client: app, name: app_quota, json_type: float}}]}"), oidcCompose, "quota", "json_type"},
		{"duplicate claim", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, "+personClaim+"}", "{key: q2, label: Q, type: int, scope: person, default: 1, "+personClaim+"}"), oidcCompose, "q2", "app_quota"},
	}
	for _, n := range []string{"sub", "email", "groups", "acr", "amr", "preferred_username", "attr_x", "portcullis_x"} {
		cases = append(cases, settingsCase{"claim " + n, oidcHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{claim: {client: app, name: "+n+", json_type: int}}]}"), oidcCompose, "quota", "claim " + n})
	}
	runSettingsCases(t, cases)
}

const personHeader = "{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Forwarded-Attr-Quota}}]}"

func TestHeaderDeliveryRules(t *testing.T) {
	noGroups := strings.Replace(hdrCompose, "portcullis-auth@docker,portcullis-groups@docker", "portcullis-auth@docker", 1)
	// A second router on the delivering service, without forward-auth.
	public := strings.Replace(hdrCompose, "  init:\n", "      traefik.http.routers.share.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`) && PathPrefix(`/share`)\n  init:\n", 1)
	runSettingsCases(t, []settingsCase{
		{"ok", hdrHead + opts(personHeader), hdrCompose, "", ""},
		{"bad name", hdrHead + opts("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{header: {name: X-Quota}}]}"), hdrCompose, "quota", "X-Forwarded-Attr-"},
		{"no group-gate", hdrHead + opts(personHeader), noGroups, "quota", "portcullis-groups"},
		{"public router", hdrHead + opts(personHeader), public, "quota", "router share"},
		{"sign_in native", "name: App\nauth:\n  method: custom\n  sso: false\n  native_login: {supported: true, allow_without_gateway: true}\n" + opts(personHeader), hdrCompose, "quota", "own login"},
		{"duplicate", hdrHead + opts(personHeader, strings.Replace(personHeader, "key: quota", "key: q2", 1)), hdrCompose, "q2", "X-Forwarded-Attr-Quota"},
		{"duplicate case-insensitive", hdrHead + opts(personHeader, strings.Replace(strings.Replace(personHeader, "key: quota", "key: q2", 1), "Attr-Quota", "Attr-QUOTA", 1)), hdrCompose, "q2", "QUOTA"},
	})
}

const filesBlock = `files:
  - {name: people, service: init, mount: /portcullis, on_membership_change: restart}
hooks:
  - {name: apply, service: web, command: [php, /portcullis/apply.php], when: [start, settings_change], timeout: 60s}
`

func TestFileAndHookRefs(t *testing.T) {
	pf := func(o string) string { return hdrHead + opts(o) + filesBlock }
	runSettingsCases(t, []settingsCase{
		{"ok", pf("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{file: {name: people, field: quota}}, {hook: apply}]}"), hdrCompose, "", ""},
		{"undeclared file", pf("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{file: {name: nope}}]}"), hdrCompose, "quota", "file nope"},
		{"undeclared hook", pf("{key: quota, label: Q, type: int, scope: person, default: 1, delivery: [{hook: nope}]}"), hdrCompose, "quota", "hook nope"},
		{"field on instance", pf("{key: trash_days, label: Q, type: int, delivery: [{file: {name: people, field: x}}]}"), hdrCompose, "trash_days", "field"},
		{"file service", hdrHead + "files:\n  - {name: people, service: nope, mount: /portcullis}\n", hdrCompose, "", "files[people]: service nope"},
		{"file name", hdrHead + "files:\n  - {name: People, service: init, mount: /portcullis}\n", hdrCompose, "", "People"},
		{"file mount relative", hdrHead + "files:\n  - {name: people, service: init, mount: portcullis}\n", hdrCompose, "", "absolute"},
		{"file twice", hdrHead + "files:\n  - {name: people, service: init, mount: /a}\n  - {name: people, service: init, mount: /b}\n", hdrCompose, "", "twice"},
		{"two files one mount", hdrHead + "files:\n  - {name: a, service: init, mount: /p}\n  - {name: b, service: init, mount: /p}\n", hdrCompose, "", "/p"},
		{"file on_membership_change", hdrHead + "files:\n  - {name: people, service: init, mount: /p, on_membership_change: sometimes}\n", hdrCompose, "", "on_membership_change"},
		{"mount collides with path", hdrHead + opts("{key: media, label: M, type: path, target: {service: init, mount: /portcullis}}") + "files:\n  - {name: people, service: init, mount: /portcullis}\n", hdrCompose, "", "media"},
		{"mount inside a path", hdrHead + opts("{key: media, label: M, type: path, target: {service: init, mount: /data}}") + "files:\n  - {name: people, service: init, mount: /data/portcullis}\n", hdrCompose, "", "media"},
		{"path on another service", hdrHead + opts("{key: media, label: M, type: path, target: {service: web, mount: /portcullis}}") + "files:\n  - {name: people, service: init, mount: /portcullis}\n", hdrCompose, "", ""},
		{"hook empty command", hdrHead + "hooks:\n  - {name: apply, service: web, command: [], when: [start]}\n", hdrCompose, "", "hooks[apply]: command"},
		{"hook empty arg", hdrHead + "hooks:\n  - {name: apply, service: web, command: [php, ''], when: [start]}\n", hdrCompose, "", "hooks[apply]: command"},
		{"hook when", hdrHead + "hooks:\n  - {name: apply, service: web, command: [x], when: [start, boot]}\n", hdrCompose, "", "boot"},
		{"hook no when", hdrHead + "hooks:\n  - {name: apply, service: web, command: [x]}\n", hdrCompose, "", "when"},
		{"hook service", hdrHead + "hooks:\n  - {name: apply, service: nope, command: [x], when: [start]}\n", hdrCompose, "", "service nope"},
		{"hook timeout", hdrHead + "hooks:\n  - {name: apply, service: web, command: [x], when: [start], timeout: 11m}\n", hdrCompose, "", "timeout"},
		{"hook timeout unparsable", hdrHead + "hooks:\n  - {name: apply, service: web, command: [x], when: [start], timeout: soon}\n", hdrCompose, "", "soon"},
		{"path delivery", hdrHead + opts("{key: media, label: M, type: path, target: {service: web, mount: /media}, delivery: [{env: THEME}]}"), hdrCompose, "media", "target"},
		{"path no target", hdrHead + opts("{key: media, label: M, type: path}"), hdrCompose, "media", "target"},
		{"path target service", hdrHead + opts("{key: media, label: M, type: path, target: {service: nope, mount: /media}}"), hdrCompose, "media", "nope"},
		{"path person", hdrHead + opts("{key: media, label: M, type: path, scope: person, default: /x, target: {service: web, mount: /media}}"), hdrCompose, "media", "instance"},
	})
}

func TestReloadRules(t *testing.T) {
	o := opts("{key: theme, label: T, type: string, applies: reload}")
	runSettingsCases(t, []settingsCase{
		{"applies reload", hdrHead + o, hdrCompose, "theme", "reload"},
		{"on_membership_change reload", hdrHead + "files:\n  - {name: people, service: init, mount: /p, on_membership_change: reload}\n", hdrCompose, "", "files[people]: on_membership_change: reload"},
		{"signal", hdrHead + o + "reload: {service: web, signal: KILL}\n", hdrCompose, "", "KILL"},
		{"signal service", hdrHead + o + "reload: {service: nope, signal: HUP}\n", hdrCompose, "", "nope"},
		{"hook", hdrHead + o + "reload: {hook: nope}\n", hdrCompose, "", "reload: hook nope"},
		{"both forms", hdrHead + o + filesBlock + "reload: {service: web, signal: HUP, hook: apply}\n", hdrCompose, "", "reload"},
		{"ok signal", hdrHead + o + "reload: {service: web, signal: HUP}\n", hdrCompose, "", ""},
		{"ok hook", hdrHead + o + filesBlock + "reload: {hook: apply}\n", hdrCompose, "", ""},
		{"applies unknown", hdrHead + opts("{key: theme, label: T, type: string, applies: soon}"), hdrCompose, "theme", "applies"},
		{"live without hook", hdrHead + opts("{key: theme, label: T, type: string, applies: live}"), hdrCompose, "theme", "live"},
	})
}

const role = "{key: role, label: Role, type: enum, options: [{value: user, label: User}, {value: admin, label: Administrator}], scope: person, privileged: true, resolve: max, delivery: [{claim: {client: app, name: app_role, json_type: string}}], "

func TestGroupValuesPlaceholdersOnly(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"literal", oidcHead + opts(role+"default: user, group_values: {admins: admin}}"), oidcCompose, "role", "admins"},
		{"admin placeholder", oidcHead + opts(role+`default: user, group_values: {"{{ADMIN_GROUP}}": admin}}`), oidcCompose, "", ""},
		{"access placeholder", oidcHead + opts(role+`default: user, group_values: {"{{ACCESS_GROUP}}": admin}}`), oidcCompose, "", ""},
		{"no admin group", strings.Replace(oidcHead, "  admin_group: admin_app\n", "", 1) + opts(role+`default: user, group_values: {"{{ADMIN_GROUP}}": admin}}`), oidcCompose, "role", "admin_group"},
		{"instance scope", hdrHead + opts(`{key: theme, label: T, type: string, group_values: {"{{ADMIN_GROUP}}": x}}`), hdrCompose, "theme", "group_values"},
	})
}

func TestPrivilegedDefaultLowest(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"admin default", oidcHead + opts(role+"default: admin}"), oidcCompose, "role", "lowest"},
		{"user default", oidcHead + opts(role+"default: user}"), oidcCompose, "", ""},
		{"bool true", oidcHead + opts("{key: admin, label: A, type: bool, scope: person, privileged: true, default: true, resolve: any, delivery: [{claim: {client: app, name: app_admin, json_type: bool}}]}"), oidcCompose, "admin", "lowest"},
		{"privileged int", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, privileged: true, default: 1, resolve: max, "+personClaim+"}"), oidcCompose, "quota", "privileged"},
	})
}

func TestRequires(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"unknown", hdrHead + opts("{key: theme, label: T, type: string, requires: [nope]}"), hdrCompose, "theme", "nope"},
		{"self", hdrHead + opts("{key: theme, label: T, type: string, requires: [theme]}"), hdrCompose, "theme", "itself"},
		{"person target", hdrHead + opts("{key: theme, label: T, type: string, requires: [quota]}", personHeader), hdrCompose, "theme", "quota"},
		{"ok", hdrHead + opts("{key: theme, label: T, type: string, requires: [trash_days]}", "{key: trash_days, label: D, type: int}"), hdrCompose, "", ""},
	})
}

func TestWritesAs(t *testing.T) {
	path := "{key: media, label: M, type: path, target: {service: web, mount: /media}, mode: ro, needs: read, writes_as: "
	ids := "{key: puid, label: U, type: int, delivery: [{env: TRASH_DAYS}]}"
	runSettingsCases(t, []settingsCase{
		{"numbers", hdrHead + opts(path+"{uid: 0, gid: 0}}"), hdrCompose, "", ""},
		{"keys", hdrHead + opts(path+"{uid: puid, gid: 100}}", ids), hdrCompose, "", ""},
		{"string key", hdrHead + opts(path+"{uid: theme, gid: 0}}", "{key: theme, label: T, type: string}"), hdrCompose, "", ""},
		{"unknown key", hdrHead + opts(path+"{uid: nope, gid: 0}}"), hdrCompose, "media", "nope"},
		{"bool key", hdrHead + opts(path+"{uid: theme, gid: 0}}", "{key: theme, label: T, type: bool}"), hdrCompose, "media", "theme"},
		{"person key", hdrHead + opts(path+"{uid: quota, gid: 0}}", personHeader), hdrCompose, "media", "quota"},
		{"negative", hdrHead + opts(path+"{uid: -1, gid: 0}}"), hdrCompose, "media", "uid"},
		{"not a path", hdrHead + opts("{key: theme, label: T, type: string, writes_as: {uid: 0, gid: 0}}"), hdrCompose, "theme", "writes_as"},
	})
	var w Owner
	if err := yaml.Unmarshal([]byte("{uid: 1000, gid: pgid}"), &w); err != nil || w.UID.Num == nil || *w.UID.Num != 1000 || w.GID.Key != "pgid" {
		t.Fatalf("Owner = %+v, %v", w, err)
	}
	b, _ := json.Marshal(w)
	if string(b) != `{"uid":1000,"gid":"pgid"}` {
		t.Errorf("Owner JSON = %s", b)
	}
}

func TestGenerateNoneRefused(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"none", hdrHead + "env:\n  - {key: THEME, generate: none}\n", hdrCompose, "", "declare a setting"},
		{"other", hdrHead + "env:\n  - {key: THEME, generate: always}\n", hdrCompose, "", "generate"},
		{"random", hdrHead + "env:\n  - {key: THEME, generate: random}\n", hdrCompose, "", ""},
		{"secret generate", hdrHead + opts("{key: theme, label: T, type: secret, generate: {length: 32, charset: alphanumeric}}"), hdrCompose, "", ""},
		{"secret generate short", hdrHead + opts("{key: theme, label: T, type: secret, generate: {length: 4, charset: hex}}"), hdrCompose, "theme", "length"},
		{"secret generate charset", hdrHead + opts("{key: theme, label: T, type: secret, generate: {length: 32, charset: emoji}}"), hdrCompose, "theme", "charset"},
		{"generate on string", hdrHead + opts("{key: theme, label: T, type: string, generate: {length: 32, charset: hex}}"), hdrCompose, "theme", "generate"},
	})
}

func TestPersonEnteredRules(t *testing.T) {
	ff := firefoxHead + firefoxSettings
	uid := func(old, repl string) string {
		if !strings.Contains(ff, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(ff, old, repl, 1)
	}
	add := func(field string) string {
		return uid("      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra", field+"\n      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra")
	}
	pe := func(o string) string {
		return "{key: mozilla_uid, label: U, type: string, max_len: 32, scope: person_entered, " + o + "}"
	}
	runSettingsCases(t, []settingsCase{
		{"firefox sync", ff, firefoxCompose, "", ""},
		{"secret", uid("type: string\n      pattern", "type: secret\n      pattern"), firefoxCompose, "mozilla_uid", "a per-person credential is person_secret (project 3)"},
		{"list", uid("type: string\n      pattern", "type: list\n      pattern"), firefoxCompose, "mozilla_uid", "person_entered"},
		{"default", add("      default: x"), firefoxCompose, "mozilla_uid", "default"},
		{"required", add("      required: true"), firefoxCompose, "mozilla_uid", "required"},
		{"resolve", add("      resolve: priority"), firefoxCompose, "mozilla_uid", "resolve"},
		{"resolve_choices", add("      resolve_choices: [priority]"), firefoxCompose, "mozilla_uid", "resolve_choices"},
		{"group_values", add(`      group_values: {"{{ACCESS_GROUP}}": x}`), firefoxCompose, "mozilla_uid", "group_values"},
		{"privileged", add("      privileged: true"), firefoxCompose, "mozilla_uid", "privileged"},
		{"requires on it", add("      requires: [extra_accounts]"), firefoxCompose, "mozilla_uid", "requires"},
		{"requires naming it", uid("      scope: instance\n", "      scope: instance\n      requires: [mozilla_uid]\n"), firefoxCompose, "extra_accounts", "mozilla_uid"},
		{"self_visible false", add("      self_visible: false"), firefoxCompose, "mozilla_uid", "self_visible"},
		{"account_creation", uid("      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra", "      applies: account_creation\n      delivery: [{file: {name: allowlist}}]\n    - key: extra"), firefoxCompose, "mozilla_uid", "account_creation"},
		{"unbounded string", uid("      pattern: '^[0-9a-f]{32}$'\n      min_len: 32\n      max_len: 32\n", ""), firefoxCompose, "mozilla_uid", "max_len"},
		{"max_len too big", uid("      max_len: 32\n", "      max_len: 300\n"), firefoxCompose, "mozilla_uid", "256"},
		{"format bounds", uid("      pattern: '^[0-9a-f]{32}$'\n      min_len: 32\n      max_len: 32\n", "      format: email\n"), firefoxCompose, "", ""},
		{"unique bool", firefoxHead + opts("{key: opt_in, label: O, type: bool, scope: person_entered, unique: true, applies: restart, delivery: [{file: {name: allowlist}}]}") + "files:\n  - {name: allowlist, service: firefox-sync-init, mount: /p, on_membership_change: restart}\n", firefoxCompose, "opt_in", "unique"},
		{"unique enum", firefoxHead + opts("{key: tier, label: O, type: enum, options: [{value: a, label: A}], scope: person_entered, unique: true, applies: restart, delivery: [{file: {name: allowlist}}]}") + "files:\n  - {name: allowlist, service: firefox-sync-init, mount: /p, on_membership_change: restart}\n", firefoxCompose, "tier", "unique"},
		{"admin_override elsewhere", uid("      scope: instance\n", "      scope: instance\n      admin_override: true\n"), firefoxCompose, "extra_accounts", "admin_override"},
		{"env without join", hdrHead + opts(pe("applies: restart, delivery: [{env: THEME}]")), hdrCompose, "mozilla_uid", "render.join"},
		{"env joined", hdrHead + opts(pe("applies: restart, delivery: [{env: THEME, render: {join: ' '}}]")), hdrCompose, "", ""},
		{"env json", hdrHead + opts(pe("applies: restart, delivery: [{env: THEME, render: {format: json}}]")), hdrCompose, "", ""},
		{"env not restart", hdrHead + opts(pe("applies: next_request, delivery: [{env: THEME, render: {join: ' '}}]")), hdrCompose, "mozilla_uid", "restart"},
		{"file applies live", uid("      applies: restart\n      delivery: [{file: {name: allowlist}}]\n    - key: extra", "      applies: live\n      delivery: [{file: {name: allowlist}}]\n    - key: extra"), firefoxCompose, "mozilla_uid", "on_membership_change"},
		{"hook not live", hdrHead + opts(pe("applies: restart, delivery: [{hook: h}]")) + "hooks:\n  - {name: h, service: web, command: [x], when: [membership_change]}\n", hdrCompose, "mozilla_uid", "live"},
		{"hook without membership_change", hdrHead + opts(pe("applies: live, delivery: [{hook: h}]")) + "hooks:\n  - {name: h, service: web, command: [x], when: [start]}\n", hdrCompose, "mozilla_uid", "membership_change"},
		{"file via hook live", hdrHead + opts(pe("applies: live, delivery: [{file: {name: people}}]")) + "files:\n  - {name: people, service: init, mount: /p, on_membership_change: hook}\nhooks:\n  - {name: h, service: web, command: [x], when: [membership_change]}\n", hdrCompose, "", ""},
		{"hook ok", hdrHead + opts(pe("applies: live, delivery: [{hook: h}]")) + "hooks:\n  - {name: h, service: web, command: [x], when: [membership_change]}\n", hdrCompose, "", ""},
		{"claim not next_sign_in", oidcHead + opts(pe("applies: restart, delivery: [{claim: {client: app, name: app_uid}}]")), oidcCompose, "mozilla_uid", "next_sign_in"},
		{"claim ok", oidcHead + opts(pe("delivery: [{claim: {client: app, name: app_uid}}]")), oidcCompose, "", ""},
		{"header not next_request", hdrHead + opts(pe("applies: restart, delivery: [{header: {name: X-Forwarded-Attr-Uid}}]")), hdrCompose, "mozilla_uid", "next_request"},
		{"header ok", hdrHead + opts(pe("applies: next_request, delivery: [{header: {name: X-Forwarded-Attr-Uid}}]")), hdrCompose, "", ""},
		{"custom without access_group", strings.Replace(ff, "  access_group: users_firefox-sync\n", "", 1), firefoxCompose, "mozilla_uid", "access_group"},
		{"public without access_group", "name: App\nauth:\n  method: public\n" + strings.TrimPrefix(ff, firefoxHead), firefoxCompose, "mozilla_uid", "access_group"},
		{"forward-auth needs none", hdrHead + opts(pe("applies: next_request, delivery: [{header: {name: X-Forwarded-Attr-Uid}}]")), hdrCompose, "", ""},
	})
}

func TestSettingsJSON(t *testing.T) {
	var s SettingsSpec
	if err := yaml.Unmarshal([]byte(strings.TrimPrefix(firefoxSettings[:strings.Index(firefoxSettings, "files:")], "settings:\n")), &s); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(s.Options[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"key":"mozilla_uid"`, `"max_len":32`, `"admin_override":true`, `"scope":"person_entered"`, `"delivery":[{"file":{"name":"allowlist"}}]`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("JSON lacks %s: %s", k, b)
		}
	}
	for _, k := range []string{"MinLen", "minlen", "Choices"} {
		if strings.Contains(string(b), k) {
			t.Errorf("JSON has %s: %s", k, b)
		}
	}
}

// TestSpecExamples: the spec's Immich and Nextcloud blocks pass as written.
func TestSpecExamples(t *testing.T) {
	immich := strings.ReplaceAll(oidcHead, "client_id: app", "client_id: immich") + `settings:
  sections: [Storage, Accounts, Library]
  options:
    - key: trash_days
      label: Keep deleted items for
      type: int
      unit: days
      min: 0
      max: 3650
      default: 30
      scope: instance
      section: Library
      applies: restart
      delivery: [{env: IMMICH_TRASH_DAYS}]
    - key: storage_quota
      label: Storage quota
      type: size
      step: 1GiB
      allow_unlimited: true
      scope: person
      default: 100GiB
      resolve: max
      resolve_choices: [max, min, priority]
      section: Storage
      applies: next_sign_in
      delivery:
        - claim: {client: immich, name: immich_quota, json_type: int,
                  render: {unit: GiB, unlimited: "-1"}}
    - key: role
      label: Role
      type: enum
      options: [{value: user, label: User}, {value: admin, label: Administrator}]
      scope: person
      privileged: true
      default: user
      group_values: {"{{ADMIN_GROUP}}": admin}
      resolve: max
      section: Accounts
      applies: next_sign_in
      delivery: [{claim: {client: immich, name: immich_role, json_type: string}}]
    - key: external_library
      label: External photo library
      type: path
      mode: ro
      needs: read
      writes_as: {uid: 0, gid: 0}
      target: {service: web, mount: /usr/src/app/external}
      scope: instance
      applies: restart
`
	nextcloud := hdrHead + `hooks:
  - name: apply-settings
    service: web
    command: [php, /portcullis/apply-settings.php]
    when: [start, settings_change]
    timeout: 60s
settings:
  options:
    - key: default_quota
      label: Default storage quota
      type: size
      step: 1GiB
      allow_unlimited: true
      scope: instance
      default: 10GiB
      applies: live
      delivery: [{hook: apply-settings, render: {unit: GiB, integer: true, unlimited: none}}]
`
	runSettingsCases(t, []settingsCase{
		{"immich", immich, strings.Replace(oidcCompose, "TRASH_DAYS: ${TRASH_DAYS:-30}", "IMMICH_TRASH_DAYS: ${IMMICH_TRASH_DAYS:-30}", 1), "", ""},
		{"nextcloud", nextcloud, hdrCompose, "", ""},
	})
}
