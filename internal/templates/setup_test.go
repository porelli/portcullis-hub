package templates

import (
	"reflect"
	"strings"
	"testing"
)

// guacamoleCompose is guacamole's shape: guacamole-init writes the schema
// once and exits; the database and the web app wait for it.
const guacamoleCompose = `services:
  guacamole-init:
    image: x
    restart: "no"
  postgres:
    image: x
    depends_on:
      guacamole-init:
        condition: service_completed_successfully
  guacd:
    image: x
  guacamole:
    image: x
    depends_on:
      postgres:
        condition: service_healthy
      guacd:
        condition: service_started
      guacamole-init: {condition: service_completed_successfully}
    labels:
      traefik.http.routers.app.rule: Host(` + "`${PORTCULLIS_HOST_APP:-app.portcullis.local}`" + `)
      traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker
  short:
    image: x
    depends_on: [guacd]
`

func TestJobServicesFromDependsOn(t *testing.T) {
	got := JobServices(&Manifest{}, []byte(guacamoleCompose))
	if want := map[string]bool{"guacamole-init": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("JobServices = %v, want %v", got, want)
	}
	if got := JobServices(&Manifest{}, []byte("services: [")); got == nil || len(got) != 0 {
		t.Errorf("unparsable compose = %v, want an empty map", got)
	}
}

func TestJobsListed(t *testing.T) {
	got := JobServices(&Manifest{Jobs: []string{"migrate"}}, []byte(guacamoleCompose))
	if want := map[string]bool{"guacamole-init": true, "migrate": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("JobServices = %v, want %v", got, want)
	}
	head := hdrHead
	compose := hdrCompose + "  migrate:\n    image: x\n"
	runSettingsCases(t, []settingsCase{
		{"listed job", head + "jobs: [migrate]\n", compose, "", ""},
		{"init too", head + "jobs: [migrate, init]\n", compose, "", ""},
		{"unknown service", head + "jobs: [nope]\n", compose, "", "jobs: nope is not a compose service"},
		{"twice", head + "jobs: [migrate, migrate]\n", compose, "", "jobs: migrate is listed twice"},
		{"routed", head + "jobs: [web]\n", compose, "", "jobs: web has a Traefik router: a one-off job serves nothing"},
	})
	tpl, err := build("app", "src", "", []byte(head+"jobs: [migrate]\n"), []byte(compose), "example.org", nil)
	if err != nil || !reflect.DeepEqual(tpl.Manifest.Jobs, []string{"migrate"}) {
		t.Errorf("Jobs = %v, %v", tpl.Manifest.Jobs, err)
	}
}

// dbCompose: the web app plus one database service per engine, each
// behind its profile.
// setupCompose: hdrCompose's web app also reading the setup options.
var setupCompose = strings.Replace(hdrCompose, "      HARD: literal\n", "      HARD: literal\n      DATABASE: ${DATABASE:-mysql}\n      CACHE: ${CACHE:-none}\n", 1)

var dbCompose = setupCompose +
	"  db-mysql:\n    image: x\n    profiles: [db-mysql]\n" +
	"  db-postgres:\n    image: x\n    profiles: [db-postgres]\n"

const dbChoice = "{key: database, label: Database, type: enum, options: [{value: mysql, label: MySQL}, {value: postgres, label: PostgreSQL}], default: mysql, setup: true, fixed_after_start: true, %s}"

func dbOpt(extra string) string {
	return strings.Replace(dbChoice, "%s", extra, 1)
}

func TestSetupOptionValidation(t *testing.T) {
	profiles := "profiles: {mysql: [db-mysql], postgres: [db-postgres]}"
	runSettingsCases(t, []settingsCase{
		{"ok", hdrHead + opts(dbOpt(profiles)), dbCompose, "", ""},
		{"empty list for a value", hdrHead + opts(dbOpt("profiles: {mysql: [], postgres: [db-postgres, db-mysql]}")), dbCompose, "", ""},
		{"setup string", hdrHead + opts("{key: theme, label: T, type: string, default: dark, setup: true}"), hdrCompose, "", ""},
		{"setup not fixed", hdrHead + opts("{key: theme, label: T, type: string, default: dark, setup: true, fixed_after_start: false}"), hdrCompose, "", ""},
		{"profiles on a string", hdrHead + opts("{key: theme, label: T, type: string, default: mysql, setup: true, profiles: {mysql: [db-mysql]}}"), dbCompose, "theme", "profiles is for setup enum options of scope instance"},
		{"profiles without setup", hdrHead + opts(strings.Replace(dbOpt(profiles), "setup: true, fixed_after_start: true, ", "", 1)), dbCompose, "database", "profiles is for setup enum options of scope instance"},
		{"profiles without default", hdrHead + opts(strings.Replace(dbOpt(profiles), "default: mysql, ", "", 1)), dbCompose, "database", "profiles needs a default"},
		{"unknown value key", hdrHead + opts(dbOpt("profiles: {mysql: [db-mysql], postgres: [db-postgres], sqlite: []}")), dbCompose, "database", "profiles: sqlite is not one of the option's values"},
		{"value without entry", hdrHead + opts(dbOpt("profiles: {mysql: [db-mysql]}")), dbCompose, "database", "profiles: value postgres has no entry"},
		{"unknown profile", hdrHead + opts(dbOpt("profiles: {mysql: [db-mysql], postgres: [db-pg]}")), dbCompose, "database", "profiles.postgres: profile db-pg is on no compose service"},
		{"uncovered profiled service", hdrHead + opts(dbOpt("profiles: {mysql: [db-mysql], postgres: []}")), dbCompose, "", "service db-postgres: no setup option's profiles start it (its profiles db-postgres)"},
		{"profiled service, no settings", hdrHead, dbCompose, "", "service db-mysql: no setup option's profiles start it"},
		{"profiles not a list", hdrHead + opts(dbOpt(profiles)), setupCompose + "  db-mysql:\n    image: x\n    profiles: db-mysql\n", "", "service db-mysql: profiles must be a list of literal profile names"},
		{"profile interpolated", hdrHead + opts(dbOpt(profiles)), dbCompose + "  extra:\n    image: x\n    profiles: [\"${P}\"]\n", "", "service extra: profiles must be a list of literal profile names"},
		{"fixed without setup", hdrHead + opts("{key: theme, label: T, type: string, default: dark, fixed_after_start: true}"), hdrCompose, "theme", "fixed_after_start needs setup: true"},
		{"setup secret", hdrHead + opts("{key: theme, label: T, type: secret, setup: true, delivery: [{env: THEME}]}"), hdrCompose, "theme", "setup needs scope instance and a type other than secret"},
		{"setup person", oidcHead + opts("{key: quota, label: Q, type: int, scope: person, resolve: max, default: 1, setup: true, delivery: [{claim: {client: app, name: app_quota, json_type: int}}]}"), oidcCompose, "quota", "setup needs scope instance and a type other than secret"},
		{"compose profiles reserved", hdrHead + "env:\n  - {key: COMPOSE_PROFILES}\n", hdrCompose, "", "COMPOSE_PROFILES is an instance variable the Hub sets"},
	})
}

func TestProfilesFor(t *testing.T) {
	m := hdrHead + opts(dbOpt("profiles: {mysql: [db-mysql], postgres: [db-postgres]}"),
		"{key: cache, label: Cache, type: enum, options: [{value: none, label: None}, {value: redis, label: Redis}], default: none, setup: true, profiles: {none: [], redis: [cache, db-mysql]}}")
	compose := dbCompose + "  redis:\n    image: x\n    profiles: [cache]\n"
	tpl, err := build("app", "src", "", []byte(m), []byte(compose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		values map[string]any
		want   []string
	}{
		{"defaults", nil, []string{"db-mysql"}},
		{"postgres", map[string]any{"database": "postgres"}, []string{"db-postgres"}},
		{"merged and sorted", map[string]any{"database": "mysql", "cache": "redis"}, []string{"cache", "db-mysql"}},
		{"postgres and redis", map[string]any{"database": "postgres", "cache": "redis"}, []string{"cache", "db-mysql", "db-postgres"}},
		{"unknown value = default", map[string]any{"database": "oracle"}, []string{"db-mysql"}},
		{"not a string = default", map[string]any{"database": 3}, []string{"db-mysql"}},
	} {
		if got := ProfilesFor(&tpl, c.values); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ProfilesFor = %v, want %v", c.name, got, c.want)
		}
	}
	plain, err := build("app", "src", "", []byte(hdrHead), []byte(hdrCompose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ProfilesFor(&plain, nil); got != nil {
		t.Errorf("no profiles = %v, want nil", got)
	}
	o := tpl.Manifest.Settings.Options[0]
	if !o.Setup || !o.FixedAfterStart || len(o.Profiles) != 2 {
		t.Errorf("decoded option = %+v", o)
	}
}

// TestJobsFoundRefusedWithRouter: a job found through depends_on gets the
// same router refusal as a listed one.
func TestJobsFoundRefusedWithRouter(t *testing.T) {
	compose := hdrCompose + "  late:\n    image: x\n    depends_on:\n      web: {condition: service_completed_successfully}\n"
	runSettingsCases(t, []settingsCase{
		{"routed dependency", hdrHead, compose, "", "jobs: web has a Traefik router: a one-off job serves nothing"},
		{"unrouted dependency", hdrHead, hdrCompose + "  late:\n    image: x\n    depends_on:\n      init: {condition: service_completed_successfully}\n", "", ""},
	})
}

// TestSetupYAMLAnchors: anchors and merge keys in depends_on and
// profiles: are read as compose reads them.
func TestSetupYAMLAnchors(t *testing.T) {
	compose := "x-wait: &wait\n  init: {condition: service_completed_successfully}\nx-p: &p [db-mysql]\n" + setupCompose +
		"  late:\n    image: x\n    depends_on:\n      <<: *wait\n      other: {condition: service_started}\n" +
		"  other:\n    image: x\n    depends_on: *wait\n" +
		"  db-mysql:\n    image: x\n    profiles: *p\n" +
		"  db-postgres:\n    image: x\n    profiles: [db-postgres]\n"
	if got, want := JobServices(&Manifest{}, []byte(compose)), map[string]bool{"init": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("JobServices = %v, want %v", got, want)
	}
	runSettingsCases(t, []settingsCase{
		{"anchored profiles", hdrHead + opts(dbOpt("profiles: {mysql: [db-mysql], postgres: [db-postgres]}")), compose, "", ""},
		{"anchored profiles uncovered", hdrHead + opts(dbOpt("profiles: {mysql: [], postgres: [db-postgres]}")), compose, "", "service db-mysql: no setup option's profiles start it"},
		{"merged dependency on a routed service", hdrHead, "x-wait: &wait\n  web: {condition: service_completed_successfully}\n" + hdrCompose +
			"  late:\n    image: x\n    depends_on:\n      <<: *wait\n", "", "jobs: web has a Traefik router"},
	})
}

func TestNullProfilesRefused(t *testing.T) {
	runSettingsCases(t, []settingsCase{
		{"null profiles", hdrHead + opts(dbOpt("profiles: ~")), setupCompose, "database", "profiles: value mysql has no entry"},
		{"null profiles on a string", hdrHead + opts("{key: theme, label: T, type: string, default: dark, profiles: null}"), hdrCompose, "theme", "profiles is for setup enum options of scope instance"},
	})
}

// TestUnprofiledDependsOnProfiled: a service without profiles may not
// need a profiled one (depends_on, network_mode, volumes_from).
func TestUnprofiledDependsOnProfiled(t *testing.T) {
	m := hdrHead + opts(dbOpt("profiles: {mysql: [db-mysql], postgres: [db-postgres]}"))
	runSettingsCases(t, []settingsCase{
		{"depends_on list", m, dbCompose + "  app:\n    image: x\n    depends_on: [db-mysql]\n", "", "service app: depends_on names profiled service db-mysql"},
		{"depends_on map", m, dbCompose + "  app:\n    image: x\n    depends_on:\n      db-postgres: {condition: service_healthy}\n", "", "service app: depends_on names profiled service db-postgres"},
		{"network_mode", m, dbCompose + "  app:\n    image: x\n    network_mode: service:db-mysql\n", "", "service app: network_mode names profiled service db-mysql"},
		{"volumes_from", m, dbCompose + "  app:\n    image: x\n    volumes_from: [\"db-mysql:ro\"]\n", "", "service app: volumes_from names profiled service db-mysql"},
		{"profiled may depend on profiled", m, dbCompose + "  admin:\n    image: x\n    profiles: [db-mysql]\n    depends_on: [db-mysql]\n", "", ""},
		{"unprofiled dependency ok", m, dbCompose + "  app:\n    image: x\n    depends_on: [init]\n", "", ""},
	})
}
