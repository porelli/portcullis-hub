package templates

import (
	"strings"
	"testing"
)

// File sharing (contract §13.2 person_secret / person_id, §13.7 tsv,
// §13.8 credential_change, §13.9 requires_any, §13.15 uid_from /
// gid_from, §3 router-less custom). Every refusal names the option.

// smbHead is a router-less custom template (§3): the access group decides
// the population; a tsv people file and a sync hook on service smb.
const smbHead = `name: Files
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: custom
  group_access: true
  access_group: users_files
ports:
  - {key: SMB, label: SMB, container: 445, default: 445, protocol: tcp, service: smb, lan_only: true}
files:
  - {name: people, service: smb, mount: /portcullis/data, format: tsv}
hooks:
  - {name: sync, service: smb, command: [/portcullis/portcullis-sync], when: [start, settings_change, membership_change, credential_change], timeout: 60s}
`

// smbCompose has no Traefik router at all.
const smbCompose = "services:\n  smb:\n    image: x\n  other:\n    image: x\n"

// smbRouted adds a service with an HTTP router.
const smbRouted = smbCompose + "  web:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.files.rule: Host(`${PORTCULLIS_HOST_FILES:-files.portcullis.local}`)\n" +
	"      traefik.http.routers.files.middlewares: portcullis-auth@docker,portcullis-groups@docker\n"

const (
	psOpt = `{key: share_password, label: File-share password, type: person_secret, hash: nt, length: 24, delivery: file, ` +
		`mount: {service: smb, path: /portcullis/secrets}, revoke_on_leave: true, on_restore: void, applies: live, ` +
		`username: {pattern: '^[a-z_][a-z0-9_.-]{0,31}$', reserved: [root, nobody], reason: "isn't a valid Samba and Unix name"}, ` +
		`info: [{label: Address, value: 'smb://{value:connect_address}{port_suffix:SMB:445}/Home'}, {label: Username, value: '{user}'}, {label: Port, value: '{port:SMB}'}]}`
	uidOpt     = `{key: uid, label: File owner id, type: person_id, pool: posix_uid, self_visible: false, delivery: [{file: {name: people, field: uid}}]}`
	connectOpt = `{key: connect_address, label: Address people connect to, type: string, format: hostname, required: true, self_visible: true, delivery: [{file: {name: people}}]}`
	thePattern = `'^[a-z_][a-z0-9_.-]{0,31}$'`
)

// edit replaces each old/new pair in o once; an old of "}" appends new
// as extra fields of the flow mapping.
func edit(o string, pairs ...string) string {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i] == "}" {
			o = o[:len(o)-1] + ", " + pairs[i+1] + "}"
			continue
		}
		if !strings.Contains(o, pairs[i]) {
			panic("edit: no " + pairs[i] + " in " + o)
		}
		o = strings.Replace(o, pairs[i], pairs[i+1], 1)
	}
	return o
}

func ps(pairs ...string) string  { return edit(psOpt, pairs...) }
func uid(pairs ...string) string { return edit(uidOpt, pairs...) }

// smb is smbHead with connect_address, uid and the given options.
func smb(lines ...string) string {
	return smbHead + opts(append([]string{connectOpt, uidOpt}, lines...)...)
}

func TestPersonSecretRules(t *testing.T) {
	noAccess := strings.Replace(smbHead, "  access_group: users_files\n", "", 1)
	noGroupAccess := strings.Replace(smbHead, "group_access: true", "group_access: false", 1)
	noCredHook := strings.Replace(smbHead, ", credential_change]", "]", 1)
	otherHook := strings.Replace(smbHead, "{name: sync, service: smb,", "{name: sync, service: other,", 1)
	headerAuth := strings.Replace(smbHead, "method: custom", "method: header-auth", 1)
	jsonFile := strings.Replace(smbHead, "hooks:\n", "  - {name: json, service: other, mount: /json}\nhooks:\n", 1)
	pathOpt := "{key: data, label: Data, type: path, target: {service: smb, mount: /portcullis/secrets/x}}"
	secretOpt := "{key: api, label: API, type: secret, delivery: [{file: {name: json}}]}"
	plainOpt := "{key: motd, label: Motd, type: string, delivery: [{file: {name: people}}]}"
	listOpt := "{key: names, label: Names, type: list, items: {type: string}, self_visible: true, delivery: [{file: {name: people}}]}"
	patEnv := func(v string) string {
		return "services:\n  smb:\n    image: x\n    environment:\n      PORTCULLIS_USERNAME_PATTERN: '" + v + "'\n  other:\n    image: x\n"
	}
	pat := func(p string) string { return ps(thePattern, p) }
	runSettingsCases(t, []settingsCase{
		{"ok", smb(ps()), smbCompose, "", ""},
		{"hash", smb(ps("hash: nt", "hash: md5")), smbCompose, "share_password", "hash must be nt"},
		{"no hash", smb(ps("hash: nt, ", "")), smbCompose, "share_password", "hash must be nt"},
		{"short", smb(ps("length: 24", "length: 20")), smbCompose, "share_password", "length 20 must be at least 24"},
		{"not groups of 4", smb(ps("length: 24", "length: 26")), smbCompose, "share_password", "multiple of 4"},
		{"long ok", smb(ps("length: 24", "length: 32")), smbCompose, "", ""},
		{"delivery list", smb(ps("delivery: file", "delivery: [{file: {name: people}}]")), smbCompose, "share_password", "delivery: file"},
		{"delivery hook", smb(ps("delivery: file", "delivery: hook")), smbCompose, "share_password", "delivery: file"},
		{"delivery env", smb(ps("delivery: file", "delivery: [{env: X}]")), smbCompose, "share_password", "delivery: file"},
		{"no delivery", smb(ps("delivery: file, ", "")), smbCompose, "share_password", "delivery: file"},
		{"no mount", smb(ps("mount: {service: smb, path: /portcullis/secrets}, ", "")), smbCompose, "share_password", "needs mount"},
		{"mount service", smb(ps("service: smb, path", "service: nope, path")), smbCompose, "share_password", "mount.service nope is not in compose.yml"},
		{"mount relative", smb(ps("path: /portcullis/secrets", "path: portcullis/secrets")), smbCompose, "share_password", "mount.path"},
		{"mount colon", smb(ps("path: /portcullis/secrets", "path: '/a:b'")), smbCompose, "share_password", "mount.path"},
		{"mount unclean", smb(ps("path: /portcullis/secrets", "path: /portcullis//secrets")), smbCompose, "share_password", "mount.path"},
		{"mount on the data file", smb(ps("path: /portcullis/secrets", "path: /portcullis")), smbCompose, "share_password", "collides with files[people]"},
		{"mount on a path option", smb(pathOpt, ps()), smbCompose, "share_password", "collides with setting data"},
		{"two on one mount", smb(ps(), ps("key: share_password", "key: other_password")), smbCompose, "other_password", "collides with setting share_password"},
		{"mount elsewhere, hook not there", smb(ps("service: smb, path: /portcullis/secrets", "service: other, path: /portcullis/data")), smbCompose, "share_password", "credential_change"},
		{"revoke_on_leave false", smb(ps("revoke_on_leave: true", "revoke_on_leave: false")), smbCompose, "share_password", "revoke_on_leave must be true"},
		{"revoke_on_leave missing", smb(ps("revoke_on_leave: true, ", "")), smbCompose, "share_password", "revoke_on_leave must be true"},
		{"on_restore", smb(ps("on_restore: void", "on_restore: keep")), smbCompose, "share_password", "on_restore must be void"},
		{"on_restore missing", smb(ps("on_restore: void, ", "")), smbCompose, "share_password", "on_restore must be void"},
		{"applies", smb(ps("applies: live", "applies: restart")), smbCompose, "share_password", "applies"},
		{"applies omitted", smb(ps("applies: live, ", "")), smbCompose, "", ""},
		{"scope", smb(ps("}", "scope: person")), smbCompose, "share_password", "takes no scope"},
		{"default", smb(ps("}", "default: x")), smbCompose, "share_password", "takes no default"},
		{"required", smb(ps("}", "required: true")), smbCompose, "share_password", "takes no required"},
		{"resolve", smb(ps("}", "resolve: priority")), smbCompose, "share_password", "takes no resolve"},
		{"resolve_choices", smb(ps("}", "resolve_choices: [priority]")), smbCompose, "share_password", "takes no resolve_choices"},
		{"group_values", smb(ps("}", "group_values: {'{{ACCESS_GROUP}}': x}")), smbCompose, "share_password", "takes no group_values"},
		{"privileged", smb(ps("}", "privileged: true")), smbCompose, "share_password", "takes no privileged"},
		{"requires", smb(ps("}", "requires: [connect_address]")), smbCompose, "share_password", "takes no requires"},
		{"requires_any", smb(ps("}", "requires_any: [connect_address]")), smbCompose, "share_password", "takes no requires_any"},
		{"self_visible", smb(ps("}", "self_visible: false")), smbCompose, "share_password", "takes no self_visible"},
		{"checks", smb(ps("}", "checks: [{kind: requires_group_value, reason: x}]")), smbCompose, "share_password", "takes no checks"},
		{"pool", smb(ps("}", "pool: posix_uid")), smbCompose, "share_password", "pool is for person_id"},
		{"constraint", smb(ps("}", "max_len: 3")), smbCompose, "share_password", "max_len is not a constraint of type person_secret"},
		{"no access group", noAccess + opts(connectOpt, ps()), smbCompose, "share_password", "router-less"},
		{"no group access", noGroupAccess + opts(connectOpt, ps()), smbCompose, "share_password", "router-less"},
		{"with a router", smbHead + opts(connectOpt, ps()), smbRouted, "share_password", "router-less"},
		{"header-auth", headerAuth + opts(connectOpt, ps()), smbRouted, "share_password", "router-less"},
		{"no credential hook", noCredHook + opts(connectOpt, ps()), smbCompose, "share_password", "credential_change"},
		{"hook on another service", otherHook + opts(connectOpt, ps()), smbCompose, "share_password", "credential_change"},
		{"bad pattern", smb(pat(`'^[a-z$'`)), smbCompose, "share_password", "username.pattern"},
		{"unanchored pattern", smb(pat(`'[a-z]{1,8}'`)), smbCompose, "share_password", "username.pattern"},
		{"perl class", smb(pat(`'^\w{1,8}$'`)), smbCompose, "share_password", "username.pattern"},
		{"escape", smb(pat(`'^a\.b$'`)), smbCompose, "share_password", "username.pattern"},
		{"dot", smb(pat(`'^a.b$'`)), smbCompose, "share_password", "username.pattern"},
		{"alternation", smb(pat(`'^(a|b)$'`)), smbCompose, "share_password", "username.pattern"},
		{"star", smb(pat(`'^a*$'`)), smbCompose, "share_password", "username.pattern"},
		{"flags", smb(pat(`'(?i)^a$'`)), smbCompose, "share_password", "username.pattern"},
		{"literals and repeats", smb(pat(`'^u-[a-z]{2}[0-9]{1,3}$'`)), smbCompose, "", ""},
		// Only what RE2 and busybox ERE read alike (fix round 1).
		{"collating element", smb(pat(`'^[[.a.]]$'`)), smbCompose, "share_password", "username.pattern"},
		{"equivalence class", smb(pat(`'^[[=a=]]$'`)), smbCompose, "share_password", "username.pattern"},
		{"interval without m", smb(pat(`'^a{,3}$'`)), smbCompose, "share_password", "username.pattern"},
		{"interval not digits", smb(pat(`'^a{x}$'`)), smbCompose, "share_password", "username.pattern"},
		{"open interval", smb(pat(`'^a{1,}$'`)), smbCompose, "share_password", "username.pattern"},
		{"interval m > n", smb(pat(`'^a{3,2}$'`)), smbCompose, "share_password", "username.pattern"},
		{"interval over 1000", smb(pat(`'^a{1,1001}$'`)), smbCompose, "share_password", "username.pattern"},
		{"literal brace", smb(pat(`'^a}$'`)), smbCompose, "share_password", "username.pattern"},
		{"lone open brace", smb(pat(`'^{$'`)), smbCompose, "share_password", "username.pattern"},
		{"literal close bracket", smb(pat(`'^a]$'`)), smbCompose, "share_password", "username.pattern"},
		{"bracket in class", smb(pat(`'^[a[b]$'`)), smbCompose, "share_password", "username.pattern"},
		{"word class", smb(pat(`'^[[:word:]]{1,3}$'`)), smbCompose, "share_password", "username.pattern"},
		{"non-ASCII", smb(pat(`'^[é]{1,2}$'`)), smbCompose, "share_password", "username.pattern"},
		{"non-ASCII literal", smb(pat(`'^é$'`)), smbCompose, "share_password", "username.pattern"},
		{"empty class", smb(pat(`'^[]$'`)), smbCompose, "share_password", "username.pattern"},
		{"repeated interval", smb(pat(`'^a{1,2}{1,2}$'`)), smbCompose, "share_password", "username.pattern"},
		{"interval on the anchor", smb(pat(`'^{1,2}a$'`)), smbCompose, "share_password", "username.pattern"},
		{"space", smb(pat(`'^a b$'`)), smbCompose, "share_password", "username.pattern"},
		{"samba rule", smb(pat(`'^[a-z][a-z0-9._-]{0,31}$'`)), smbCompose, "", ""},
		{"posix lower", smb(pat(`'^[[:lower:]]{1,8}$'`)), smbCompose, "", ""},
		{"posix classes", smb(pat(`'^[[:alpha:]_][[:alnum:][:digit:][:upper:][:xdigit:].-]{0,31}$'`)), smbCompose, "", ""},
		{"negated class", smb(pat(`'^[^A-Z]{1,8}$'`)), smbCompose, "", ""},
		{"exact interval", smb(pat(`'^x[0-9]{4}$'`)), smbCompose, "", ""},
		{"reserved upper", smb(ps("reserved: [root, nobody]", "reserved: [Root]")), smbCompose, "share_password", "username.reserved"},
		{"reserved empty name", smb(ps("reserved: [root, nobody]", "reserved: ['']")), smbCompose, "share_password", "username.reserved"},
		{"reason too long", smb(ps(`"isn't a valid Samba and Unix name"`, strings.Repeat("x", 201))), smbCompose, "share_password", "username.reason"},
		{"reason 200", smb(ps(`"isn't a valid Samba and Unix name"`, strings.Repeat("x", 200))), smbCompose, "", ""},
		{"reason missing", smb(ps(`, reason: "isn't a valid Samba and Unix name"`, "")), smbCompose, "share_password", "username.reason"},
		{"username unknown key", smb(ps("reserved: [root, nobody]", "reserved: [root], max: 3")), smbCompose, "", "max"},
		{"info unknown option", smb(ps("{value:connect_address}", "{value:nope}")), smbCompose, "share_password", "info[0]"},
		{"info unknown port", smb(ps("{port:SMB}", "{port:NOPE}")), smbCompose, "share_password", "info[2]"},
		{"info unknown suffix port", smb(ps("{port_suffix:SMB:445}", "{port_suffix:NOPE:445}")), smbCompose, "share_password", "info[0]"},
		{"info bad default", smb(ps("{port_suffix:SMB:445}", "{port_suffix:SMB:70000}")), smbCompose, "share_password", "info[0]"},
		{"info rows", smb(ps("{port:SMB}", "{rows:shares}")), smbCompose, "share_password", "info[2]"},
		{"info stray brace", smb(ps("/Home", "/{Home")), smbCompose, "share_password", "info[0]"},
		{"info stray close", smb(ps("/Home", "/Home}")), smbCompose, "share_password", "info[0]"},
		{"info secret", jsonFile + opts(connectOpt, uidOpt, secretOpt, ps("{value:connect_address}", "{value:api}")), smbCompose, "share_password", "info[0]"},
		{"info path option", smb("{key: data, label: Data, type: path, self_visible: true, target: {service: other, mount: /data}}", ps("{value:connect_address}", "{value:data}")), smbCompose, "share_password", "info[0]"},
		{"info not self_visible", smb(plainOpt, ps("{value:connect_address}", "{value:motd}")), smbCompose, "share_password", "self_visible: true"},
		{"info list", smb(listOpt, ps("{value:connect_address}", "{value:names}")), smbCompose, "share_password", "info[0]"},
		{"info person option", smb(ps("{value:connect_address}", "{value:uid}")), smbCompose, "share_password", "info[0]"},
		{"info empty label", smb(ps("{label: Username,", "{label: '',")), smbCompose, "share_password", "info[1]"},
		{"info empty value", smb(ps("value: '{user}'", "value: ''")), smbCompose, "share_password", "info[1]"},
		{"pattern env matches", smb(ps()), patEnv("^[a-z_][a-z0-9_.-]{0,31}$$"), "", ""},
		{"pattern env differs", smb(ps()), patEnv("^[a-z]{0,31}$$"), "", "PORTCULLIS_USERNAME_PATTERN"},
		{"pattern env not escaped", smb(ps()), patEnv("^[a-z_][a-z0-9_.-]{0,31}$"), "", "PORTCULLIS_USERNAME_PATTERN"},
		{"pattern env without a rule", smb(ps("username: {pattern: '^[a-z_][a-z0-9_.-]{0,31}$', reserved: [root, nobody], reason: \"isn't a valid Samba and Unix name\"}, ", "")), patEnv("^a$$"), "", "PORTCULLIS_USERNAME_PATTERN"},
		// Fields of the two types on other types.
		{"hash on string", smbHead + opts(edit(connectOpt, "}", "hash: nt")), smbCompose, "connect_address", "hash is for person_secret"},
		{"mount on string", smbHead + opts(edit(connectOpt, "}", "mount: {service: smb, path: /x}")), smbCompose, "connect_address", "mount is for person_secret"},
		{"info on string", smbHead + opts(edit(connectOpt, "}", "info: [{label: a, value: b}]")), smbCompose, "connect_address", "info is for person_secret"},
		{"bare delivery on string", smbHead + opts(edit(connectOpt, "delivery: [{file: {name: people}}]", "delivery: file")), smbCompose, "connect_address", "delivery: file is for person_secret"},
		{"pool on string", smbHead + opts(edit(connectOpt, "}", "pool: posix_uid")), smbCompose, "connect_address", "pool is for person_id"},
	})
}

// TestTimeMachineBlock: the spec's Time Machine declaration (as the
// contract and the rulings amend it: group_access with an access group,
// a tsv people file, info lines) passes.
func TestTimeMachineBlock(t *testing.T) {
	const m = `name: Time Machine
description: Mac backups over SMB, one share per person
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: custom
  group_access: true
  access_group: users_timemachine
  notes: "No web page. SMB with per-person file-share passwords; LAN/VPN only."
ports:
  - {key: TM_SMB, label: SMB, container: 445, default: 445, protocol: tcp, service: timemachine, lan_only: true}
files:
  - {name: people, service: timemachine, mount: /portcullis/data, format: tsv, on_membership_change: hook}
hooks:
  - name: sync
    service: timemachine
    command: [/portcullis/portcullis-sync]
    when: [start, settings_change, membership_change, credential_change]
    timeout: 60s
settings:
  sections: [Access, Backups, Network]
  options:
    - key: share_password
      label: File-share password
      type: person_secret
      hash: nt
      length: 24
      delivery: file
      mount: {service: timemachine, path: /portcullis/secrets}
      revoke_on_leave: true
      on_restore: void
      username: {pattern: "^[a-z_][a-z0-9_.-]{0,31}$",
                 reserved: [root, nobody, timemachine],
                 reason: "isn't a valid Samba and Unix name"}
      info:
        - {label: Server, value: "smb://{value:connect_address}{port_suffix:TM_SMB:445}/{value:share_prefix}-{user}"}
        - {label: Username, value: "{user}"}
      applies: live
      section: Access
    - key: uid
      label: File owner id
      type: person_id
      pool: posix_uid
      self_visible: false
      delivery: [{file: {name: people, field: uid}}]
    - key: size_limit
      label: Backup size limit
      type: size
      step: 1GiB
      allow_unlimited: true
      scope: person
      default: 500GiB
      resolve: max
      section: Backups
      applies: live
      delivery: [{file: {name: people, field: size_limit, render: {unit: MiB, integer: true, unlimited: none}}}]
      checks: [{kind: requires_group_value, reason: "Most people should get a deliberate limit"}]
    - key: storage
      label: Backup storage
      type: path
      target: {service: timemachine, mount: /opt}
      folder:
        access: write
        runs_as: {uid_from: uid, gid_from: uid}
        joins_group: template
      checks:
        - {kind: filesystem, needs: [xattr], not: [nfs, cifs, fuse], reason: "Time Machine stores metadata in extended attributes"}
        - {kind: exclusive, reason: "Backup bundles must not be written by other apps"}
    - key: share_prefix
      label: Share name prefix
      type: string
      pattern: "^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$"
      default: TimeMachine
      applies: live
      self_visible: true
      delivery: [{file: {name: people}}]
    - key: connect_address
      label: Address people connect to
      type: string
      format: hostname
      required: true
      section: Network
      self_visible: true
      delivery: [{file: {name: people}}]
    - key: avahi_services_dir
      label: Host Avahi services directory (Bonjour advertising)
      description: "Empty = off. Advertising shows every share name, which contains usernames, to everyone on the local network."
      type: path
      target: {service: timemachine, mount: /portcullis/avahi}
      section: Network
      applies: restart
    - key: model
      label: Shown in Finder as
      type: enum
      options: [{value: "TimeCapsule8,119", label: Time Capsule}, {value: "MacPro7,1", label: Mac Pro}]
      default: "TimeCapsule8,119"
      delivery: [{env: MIMIC_MODEL}]
      applies: restart
      section: Network
`
	const c = "services:\n  timemachine:\n    image: x\n    environment:\n      MIMIC_MODEL: ${MIMIC_MODEL}\n      PORTCULLIS_USERNAME_PATTERN: '^[a-z_][a-z0-9_.-]{0,31}$$'\n"
	tm, err := build("timemachine", "src", "", []byte(m), []byte(c), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !tm.Manifest.Routerless() {
		t.Error("Routerless() = false")
	}
	o := tm.Manifest.Settings.Options[0]
	if o.Username == nil || o.Username.Pattern != "^[a-z_][a-z0-9_.-]{0,31}$" || len(o.Username.Reserved) != 3 || o.Username.Reason == "" {
		t.Errorf("username = %+v", o.Username)
	}
	if len(o.Info) != 2 || o.Info[1] != (InfoLine{Label: "Username", Value: "{user}"}) {
		t.Errorf("info = %+v", o.Info)
	}
	for _, k := range []string{"share_password", "uid"} {
		for i := range tm.Manifest.Settings.Options {
			if p := &tm.Manifest.Settings.Options[i]; p.Key == k && (p.EffectiveScope() != ScopePerson || p.EnvName() != "" || len(p.EnvNames()) != 0) {
				t.Errorf("%s: scope %s, env %q %v", k, p.EffectiveScope(), p.EnvName(), p.EnvNames())
			}
		}
	}
	if tm.Manifest.Files[0].Format != FormatTSV {
		t.Errorf("format = %q", tm.Manifest.Files[0].Format)
	}
}

func TestPersonIDRules(t *testing.T) {
	noAccess := strings.Replace(smbHead, "  access_group: users_files\n", "", 1)
	hookFile := strings.Replace(smbHead, "format: tsv}", "format: tsv, on_membership_change: hook}", 1)
	one := func(o string) string { return hookFile + opts(connectOpt, psOpt, o) }
	jsonHead := strings.Replace(hookFile, "hooks:\n", "  - {name: json, service: other, mount: /json}\nhooks:\n", 1)
	runSettingsCases(t, []settingsCase{
		{"ok", one(uidOpt), smbCompose, "", ""},
		{"two ok", one(uidOpt)[:len(one(uidOpt))-1] + "\n    - " + uid("key: uid", "key: gid", "field: uid", "field: gid") + "\n", smbCompose, "", ""},
		{"unknown pool", one(uid("pool: posix_uid", "pool: posix_gid")), smbCompose, "uid", "pool must be posix_uid"},
		{"no pool", one(uid("pool: posix_uid, ", "")), smbCompose, "uid", "pool must be posix_uid"},
		{"self_visible missing", one(uid("self_visible: false, ", "")), smbCompose, "uid", "self_visible: false"},
		{"self_visible true", one(uid("self_visible: false", "self_visible: true")), smbCompose, "uid", "self_visible: false"},
		{"hook delivery", one(uid("delivery: [{file: {name: people, field: uid}}]", "delivery: [{hook: sync}]")), smbCompose, "uid", "only file deliveries"},
		{"env delivery", one(uid("delivery: [{file: {name: people, field: uid}}]", "delivery: [{env: UID}]")), smbCompose, "uid", "only file deliveries"},
		{"file and hook", one(uid("{file: {name: people, field: uid}}", "{file: {name: people, field: uid}}, {hook: sync}")), smbCompose, "uid", "only file deliveries"},
		{"bare file", one(uid("delivery: [{file: {name: people, field: uid}}]", "delivery: file")), smbCompose, "uid", "only file deliveries"},
		{"no delivery", one(uid(", delivery: [{file: {name: people, field: uid}}]", "")), smbCompose, "uid", "file delivery"},
		{"default", one(uid("}", "default: 20000")), smbCompose, "uid", "takes no default"},
		{"scope", one(uid("}", "scope: person")), smbCompose, "uid", "takes no scope"},
		{"required", one(uid("}", "required: true")), smbCompose, "uid", "takes no required"},
		{"resolve", one(uid("}", "resolve: max")), smbCompose, "uid", "takes no resolve"},
		{"requires", one(uid("}", "requires: [connect_address]")), smbCompose, "uid", "takes no requires"},
		{"hash", one(uid("}", "hash: nt")), smbCompose, "uid", "hash is for person_secret"},
		{"constraint", one(uid("}", "min: 1")), smbCompose, "uid", "min is not a constraint of type person_id"},
		{"applies live, hook file", one(uid("}", "applies: live")), smbCompose, "", ""},
		{"applies live, second file not hook", jsonHead + opts(connectOpt, psOpt, uid("{file: {name: people, field: uid}}", "{file: {name: people, field: uid}}, {file: {name: json}}", "}", "applies: live")), smbCompose, "uid", "applies: live"},
		{"applies live, first file not hook", jsonHead + opts(connectOpt, psOpt, uid("{file: {name: people, field: uid}}", "{file: {name: json}}, {file: {name: people, field: uid}}", "}", "applies: live")), smbCompose, "uid", "applies: live"},
		{"field twice", one(uidOpt)[:len(one(uidOpt))-1] + "\n    - " + uid("key: uid", "key: gid") + "\n", smbCompose, "gid", "field uid is already written by setting uid"},
		{"no access group", noAccess + opts(connectOpt, uidOpt), smbCompose, "uid", "router-less"},
		{"with a router", smbHead + opts(connectOpt, uidOpt), smbRouted, "uid", "router-less"},
	})
}

func TestCredentialChangeTrigger(t *testing.T) {
	only := strings.Replace(smbHead, "when: [start, settings_change, membership_change, credential_change]", "when: [credential_change]", 1)
	bad := strings.Replace(smbHead, "when: [start, settings_change, membership_change, credential_change]", "when: [credential]", 1)
	if !HookTriggers[HookCredentialChange] || HookCredentialChange != "credential_change" {
		t.Errorf("HookTriggers = %v", HookTriggers)
	}
	runSettingsCases(t, []settingsCase{
		{"credential_change only", only + opts(connectOpt, uidOpt, psOpt), smbCompose, "", ""},
		{"unknown trigger", bad + opts(connectOpt), smbCompose, "", `when "credential" must be start, settings_change, membership_change, credential_change or ai`},
	})
}

func TestDataFileFormat(t *testing.T) {
	format := func(f string) string { return strings.Replace(smbHead, ", format: tsv}", f+"}", 1) }
	secretOpt := "{key: api, label: API, type: secret, delivery: [{file: {name: people}}]}"
	tableOpt := "{key: shares, label: Shares, type: table, columns: [{name: name, label: Name, type: string}], delivery: [{file: {name: people}}]}"
	runSettingsCases(t, []settingsCase{
		{"tsv", format(", format: tsv") + opts(connectOpt), smbCompose, "", ""},
		{"json", format(", format: json") + opts(connectOpt), smbCompose, "", ""},
		{"default json", format("") + opts(connectOpt), smbCompose, "", ""},
		{"xml", format(", format: xml") + opts(connectOpt), smbCompose, "", `files[people]: format "xml" must be json or tsv`},
		{"secret into tsv", smbHead + opts(connectOpt, secretOpt), smbCompose, "api", "tsv"},
		{"secret into json", format(", format: json") + opts(connectOpt, secretOpt), smbCompose, "", ""},
		{"table into tsv", smbHead + opts(connectOpt, tableOpt), smbCompose, "shares", "tsv"},
		{"table into json", format("") + opts(connectOpt, tableOpt), smbCompose, "", ""},
	})
}

// H10 (B-M4): a tsv file takes only the default text: every render.format
// is refused on a tsv delivery (json files keep them).
func TestTSVRefusesRenderFormat(t *testing.T) {
	list := func(f string) string {
		return "{key: tags, label: Tags, type: groups, delivery: [{file: {name: people, render: {format: " + f + "}}}]}"
	}
	scalar := "{key: motd, label: MOTD, type: string, delivery: [{file: {name: people, render: {format: json}}}]}"
	json := strings.Replace(smbHead, ", format: tsv}", "}", 1)
	runSettingsCases(t, []settingsCase{
		{"yaml list into tsv", smbHead + opts(connectOpt, list("yaml")), smbCompose, "tags", "file people is tsv: render.format yaml can't be written to a tsv file"},
		{"csv list into tsv", smbHead + opts(connectOpt, list("csv")), smbCompose, "tags", "file people is tsv: render.format csv can't be written to a tsv file"},
		{"json list into tsv", smbHead + opts(connectOpt, list("json")), smbCompose, "tags", "file people is tsv: render.format json can't be written to a tsv file"},
		{"json scalar into tsv", smbHead + opts(connectOpt, scalar), smbCompose, "motd", "file people is tsv: render.format json can't be written to a tsv file"},
		{"yaml list into json", json + opts(connectOpt, list("yaml")), smbCompose, "", ""},
		{"default list into tsv", smbHead + opts(connectOpt, "{key: tags, label: Tags, type: groups, delivery: [{file: {name: people}}]}"), smbCompose, "", ""},
	})
}

func TestRequiresAny(t *testing.T) {
	r := "{key: readers, label: R, type: groups, delivery: [{file: {name: people}}]}"
	w := "{key: writers, label: W, type: groups, delivery: [{file: {name: people}}]}"
	folder := func(extra string) string {
		return "{key: share1_folder, label: Folder, type: path, target: {service: smb, mount: /shares/1}" + extra + "}"
	}
	person := "{key: quota, label: Q, type: int, scope: person, default: 1, resolve: max, delivery: [{file: {name: people}}]}"
	runSettingsCases(t, []settingsCase{
		{"ok", smbHead + opts(r, w, folder(", requires_any: [readers, writers]")), smbCompose, "", ""},
		{"unknown", smbHead + opts(r, folder(", requires_any: [readers, writers]")), smbCompose, "share1_folder", "requires_any writers: no such option"},
		{"self", smbHead + opts(r, folder(", requires_any: [share1_folder]")), smbCompose, "share1_folder", "requires_any names itself"},
		{"person listed", smbHead + opts(r, person, folder(", requires_any: [readers, quota]")), smbCompose, "share1_folder", "requires_any quota: not an instance option"},
		{"on a person option", smbHead + opts(r, edit(person, "}", "requires_any: [readers]")), smbCompose, "quota", "requires_any is for instance options"},
		{"empty", smbHead + opts(r, folder(", requires_any: []")), smbCompose, "", ""},
	})
	m := mustBuild(t, smbHead+opts(r, w, folder(", requires_any: [readers, writers]")), smbCompose)
	if got := m.Manifest.Settings.Options[2].RequiresAny; len(got) != 2 || got[0] != "readers" {
		t.Errorf("RequiresAny = %v", got)
	}
}

func TestRunsAsFrom(t *testing.T) {
	fo := func(ra, join string) string {
		return "{key: storage, label: S, type: path, target: {service: smb, mount: /opt}, folder: {access: write, runs_as: " + ra + join + "}}"
	}
	tmpl := ", joins_group: template"
	notID := "{key: num, label: N, type: int, default: 1000, delivery: [{file: {name: people}}]}"
	runSettingsCases(t, []settingsCase{
		{"per-person tree", smb(psOpt, fo("{uid_from: uid, gid_from: uid}", tmpl)), smbCompose, "", ""},
		{"shared folder slot", smb(psOpt, fo("{uid_from: uid}", tmpl)), smbCompose, "", ""},
		{"uid_from with a gid", smb(psOpt, fo("{uid_from: uid, gid: 1000}", "")), smbCompose, "", ""},
		{"uid_from, group_add, no gid", smb(psOpt, fo("{uid_from: uid}", "")), smbCompose, "storage", "folder.runs_as.gid"},
		{"uid_from not a person_id", smb(psOpt, notID, fo("{uid_from: num}", tmpl)), smbCompose, "storage", "uid_from num is not a person_id option"},
		{"uid_from unknown", smb(psOpt, fo("{uid_from: nope}", tmpl)), smbCompose, "storage", "uid_from nope is not a person_id option"},
		{"gid_from not a person_id", smb(psOpt, notID, fo("{uid_from: uid, gid_from: num}", tmpl)), smbCompose, "storage", "gid_from num is not a person_id option"},
		{"gid_from without uid_from", smb(psOpt, fo("{uid: 0, gid_from: uid}", tmpl)), smbCompose, "storage", "gid_from needs uid_from"},
		{"gid_from with group_add", smb(psOpt, fo("{uid_from: uid, gid_from: uid}", "")), smbCompose, "storage", "gid_from needs joins_group: template"},
		{"gid_from with gid_env", smb(psOpt, fo("{uid_from: uid, gid_from: uid}", ", joins_group: gid_env")), smbCompose, "storage", "joins_group"},
		{"uid and uid_from", smb(psOpt, fo("{uid: 0, uid_from: uid}", tmpl)), smbCompose, "storage", "folder.runs_as.uid: exactly one of"},
		{"uid_env and uid_from", smb(psOpt, notID, fo("{uid_env: NUM, uid_from: uid}", tmpl)), smbCompose, "storage", "folder.runs_as.uid: exactly one of"},
		{"gid and gid_from", smb(psOpt, fo("{uid_from: uid, gid: 0, gid_from: uid}", tmpl)), smbCompose, "storage", "folder.runs_as.gid: exactly one of"},
	})
}

func mustBuild(t *testing.T, manifest, compose string) Template {
	t.Helper()
	tm, err := build("app", "src", "", []byte(manifest), []byte(compose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// TestHasPersonSecret: the Hub UI shows an app's File sharing tab when its
// template has a person_secret option (plan 3 Task 14).
func TestHasPersonSecret(t *testing.T) {
	var none Manifest
	if none.HasPersonSecret() {
		t.Error("a manifest without settings has no person_secret option")
	}
	m := Manifest{Settings: &SettingsSpec{Options: []Option{{Key: "uid", Type: TypePersonID}}}}
	if m.HasPersonSecret() {
		t.Error("person_id alone is not a person_secret option")
	}
	m.Settings.Options = append(m.Settings.Options, Option{Key: "pw", Type: TypePersonSecret})
	if !m.HasPersonSecret() {
		t.Error("HasPersonSecret = false with a person_secret option")
	}
}
