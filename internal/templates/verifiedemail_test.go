package templates

import (
	"strings"
	"testing"
)

// veHead is a forward-auth app (with a router) whose access group is the
// population, and a JSON data file "access".
const veHead = `name: Accounts
ai: {unsupported: "test fixture"}
auth:
  method: header-auth
  group_access: true
  access_group: users_app
  admin_group: admin_app
files:
  - {name: access, service: web, mount: /portcullis, on_membership_change: hook}
  - {name: other, service: init, mount: /other}
hooks:
  - {name: sync, service: web, command: [/sync], when: [membership_change]}
`

const veOpt = `{key: email, label: Account email, type: verified_email, self_visible: false, delivery: [{file: {name: access, field: email}}]}`

func ve(pairs ...string) string { return edit(veOpt, pairs...) }

func TestVerifiedEmailValidation(t *testing.T) {
	one := func(o string) string { return veHead + opts(o) }
	noAccess := strings.Replace(veHead, "  access_group: users_app\n", "", 1)
	noGroupAccess := strings.Replace(veHead, "group_access: true", "group_access: false", 1)
	tsv := strings.Replace(veHead, "mount: /portcullis, on_membership_change: hook}", "mount: /portcullis, format: tsv, on_membership_change: hook}", 1)
	file := "delivery: [{file: {name: access, field: email}}]"
	runSettingsCases(t, []settingsCase{
		{"ok", one(veOpt), hdrCompose, "", ""},
		{"ok tsv", tsv + opts(veOpt), hdrCompose, "", ""},
		{"ok default field", one(ve("{file: {name: access, field: email}}", "{file: {name: access}}")), hdrCompose, "", ""},
		{"ok two files", one(ve("{file: {name: access, field: email}}", "{file: {name: access, field: email}}, {file: {name: other, field: mail}}")), hdrCompose, "", ""},
		{"ok applies live", one(ve("}", "applies: live")), hdrCompose, "", ""},
		{"ok router-less", smbHead + opts(connectOpt, edit(veOpt, "name: access", "name: people")), smbCompose, "", ""},
		{"scope", one(ve("}", "scope: person")), hdrCompose, "email", "takes no scope"},
		{"scope instance", one(ve("}", "scope: instance")), hdrCompose, "email", "takes no scope"},
		{"default", one(ve("}", "default: a@example.org")), hdrCompose, "email", "takes no default"},
		{"required", one(ve("}", "required: true")), hdrCompose, "email", "takes no required"},
		{"resolve", one(ve("}", "resolve: priority")), hdrCompose, "email", "takes no resolve"},
		{"group_values", one(ve("}", "group_values: {x: a@example.org}")), hdrCompose, "email", "takes no group_values"},
		{"privileged", one(ve("}", "privileged: true")), hdrCompose, "email", "takes no privileged"},
		{"requires", one(ve("}", "requires: [x]")), hdrCompose, "email", "takes no requires"},
		{"env delivery", one(ve(file, "delivery: [{env: EMAIL}]")), hdrCompose, "email", "only file deliveries"},
		{"env and file", one(ve("{file: {name: access, field: email}}", "{file: {name: access, field: email}}, {env: EMAIL}")), hdrCompose, "email", "only file deliveries"},
		{"claim delivery", one(ve(file, "delivery: [{claim: {client: app, name: email}}]")), hdrCompose, "email", "only file deliveries"},
		{"header delivery", one(ve(file, "delivery: [{header: {name: Email}}]")), hdrCompose, "email", "only file deliveries"},
		{"hook delivery", one(ve(file, "delivery: [{hook: sync}]")), hdrCompose, "email", "only file deliveries"},
		{"render", one(ve("{file: {name: access, field: email}}", "{file: {name: access, field: email}, render: {format: json}}")), hdrCompose, "email", "only file deliveries"},
		{"bare file", one(ve(file, "delivery: file")), hdrCompose, "email", "person_secret"},
		{"no delivery", one(ve(", "+file, "")), hdrCompose, "email", "file delivery"},
		{"unknown file", one(ve("name: access", "name: nope")), hdrCompose, "email", "file nope is not declared"},
		{"self_visible true", one(ve("self_visible: false", "self_visible: true")), hdrCompose, "email", "self_visible: false"},
		{"self_visible missing", one(ve("self_visible: false, ", "")), hdrCompose, "email", "self_visible: false"},
		{"no access group", noAccess + opts(veOpt), hdrCompose, "email", "group_access: true and an auth.access_group"},
		{"no group access", noGroupAccess + opts(veOpt), hdrCompose, "email", "group_access: true and an auth.access_group"},
		{"applies live, file not hook", one(ve("name: access", "name: other", "}", "applies: live")), hdrCompose, "email", "applies: live"},
		{"pool", one(ve("}", "pool: posix_uid")), hdrCompose, "email", "pool is for person_id"},
		{"constraint", one(ve("}", "format: email")), hdrCompose, "email", "format is not a constraint of type verified_email"},
		{"field twice", veHead + opts(veOpt, edit(veOpt, "key: email", "key: email2")), hdrCompose, "email2", "field email is already written by setting email"},
	})
}

// The structural rules alone (no compose): validateVerifiedEmail.
func TestValidateVerifiedEmailDirect(t *testing.T) {
	no := false
	m := &Manifest{Auth: Auth{Method: "header-auth", GroupAccess: true, AccessGroup: "users_app"}}
	ok := &Option{Key: "email", Label: "E", Type: TypeVerifiedEmail, SelfVisible: &no,
		Delivery: []Delivery{{File: &FileDelivery{Name: "access", Field: "email"}}}}
	if err := validateVerifiedEmail(ok, m); err != nil {
		t.Errorf("ok: %v", err)
	}
	if got := ok.EffectiveScope(); got != ScopePerson {
		t.Errorf("EffectiveScope = %q, want person", got)
	}
	if ok.EnvName() != "" {
		t.Errorf("EnvName = %q, want none", ok.EnvName())
	}
	if !BuiltinTypes[TypeVerifiedEmail] || TypeVerifiedEmail != "verified_email" {
		t.Errorf("TypeVerifiedEmail = %q builtin %v", TypeVerifiedEmail, BuiltinTypes[TypeVerifiedEmail])
	}
	off := *m
	off.Auth.AccessGroup = ""
	if err := validateVerifiedEmail(ok, &off); err == nil {
		t.Error("no access group: accepted")
	}
}
