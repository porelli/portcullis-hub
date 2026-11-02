package hub

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Contract v2 templates (instances: multi), shaped like the real ones.
const v2GrafanaManifest = `name: Grafana
category: monitoring
instances: multi
auth:
  method: header-auth
  group_access: true
  access_group: users_grafana
  admin_group: admin_grafana
  admin_paths: [/admin/]
urls:
  - label: Dashboards
    url: "https://{{HOST_GRAFANA}}"
env:
  - key: GF_SECRET
    generate: random
ports:
  - key: GRAFANA_PORT
    container: 3000
    default: 3300
    service: web
`

const v2GrafanaCompose = "services:\n" +
	"  web:\n" +
	"    image: grafana\n" +
	"    environment:\n" +
	"      GF_SERVER_ROOT_URL: https://${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}\n" +
	"      GF_ROLE_GROUP: ${PORTCULLIS_ADMIN_GROUP:-admin_grafana}\n" +
	"    volumes:\n" +
	"      - grafana-data:/var/lib/grafana\n" +
	"    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.grafana.rule: Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`)\n" +
	"      traefik.http.routers.grafana.entrypoints: websecure\n" +
	"      traefik.http.routers.grafana.middlewares: portcullis-auth@docker,portcullis-groups@docker,grafana-headers@docker,security-headers@file\n" +
	"      traefik.http.routers.grafana-api.rule: Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`) && PathPrefix(`/api`)\n" +
	"      traefik.http.routers.grafana-api.service: grafana\n" +
	"      traefik.http.middlewares.grafana-headers.headers.customresponseheaders.X-App: grafana\n" +
	"      traefik.http.services.grafana.loadbalancer.server.port: \"3000\"\n" +
	"volumes:\n" +
	"  grafana-data: {}\n"

const v2ChatManifest = `name: Chat
category: misc
instances: multi
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_chat
keycloak_clients:
  - client_id: chat
    secret_env: CHAT_SECRET
    redirect_uri: https://{{HOST_CHAT}}/cb
  - client_id: chat-admin
    redirect_uri: https://{{HOST_CHAT}}/admin/cb
env:
  - key: CHAT_SECRET
    generate: random
`

const v2ChatCompose = "services:\n  web:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.chat.rule: Host(`${PORTCULLIS_HOST_CHAT:-chat.portcullis.local}`)\n"

// v2Relay is netbird-like: host-network ports and a range.
const v2RelayManifest = `name: Relay
category: network
instances: multi
auth:
  method: forward-auth
ports:
  - key: RELAY_PORT
    container: 3478
    protocol: udp
    default: 3478
    required: true
    service: relay
    network_mode_host: true
  - key: RELAY_RANGE
    protocol: udp
    range: "49152-65535"
    required: true
    service: relay
    network_mode_host: true
`

const v2RelayCompose = "services:\n  relay:\n    image: coturn\n    network_mode: host\n" +
	"    environment:\n      RELAY_PORT: ${RELAY_PORT:-3478}\n      RELAY_RANGE: ${RELAY_RANGE:-49152-65535}\n" +
	"  dash:\n    image: dash\n    labels:\n" +
	"      traefik.http.routers.relay.rule: Host(`${PORTCULLIS_HOST_RELAY:-relay.portcullis.local}`)\n"

const singleManifest = `name: Disks
category: monitoring
instances: single
auth:
  method: forward-auth
  notes: privileged, monitors the host's own disks
`

const singleCompose = "services:\n  disks:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.disks.rule: Host(`${PORTCULLIS_HOST_DISKS:-disks.portcullis.local}`)\n" +
	"volumes:\n  disks-data:\n    name: portcullis_disks-data\n"

// newInstanceFixture is newFixture with the v2 templates above; seed, if
// set, prepares state.yaml before the Hub starts.
func newInstanceFixture(t *testing.T, seed func(*state.AppState)) *fixture {
	t.Helper()
	return newInstanceFixtureWith(t, seed, nil)
}

// newInstanceFixtureWith is newInstanceFixture with idp as the Hub's IdP
// (nil: the fakeIdP in f.idp).
func newInstanceFixtureWith(t *testing.T, seed func(*state.AppState), idp IdP) *fixture {
	t.Helper()
	return newInstanceFixtureExtra(t, seed, idp, nil)
}

// newInstanceFixtureExtra is newInstanceFixtureWith with extra templates
// (id → manifest, compose) in the source.
func newInstanceFixtureExtra(t *testing.T, seed func(*state.AppState), idp IdP, extra map[string][2]string) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		runner:  newFakeRunner(),
		engine:  &fakeEngine{logs: map[string]string{}},
		idp:     &fakeIdP{},
		project: filepath.Join(root, "project"),
		data:    filepath.Join(root, "data"),
		src:     filepath.Join(root, "src"),
	}
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\n")
	for id, files := range map[string][2]string{
		"grafana": {v2GrafanaManifest, v2GrafanaCompose},
		"chat":    {v2ChatManifest, v2ChatCompose},
		"relay":   {v2RelayManifest, v2RelayCompose},
		"disks":   {singleManifest, singleCompose},
	} {
		writeFile(t, filepath.Join(f.src, id, "manifest.yaml"), files[0])
		writeFile(t, filepath.Join(f.src, id, "compose.yml"), files[1])
		writeFile(t, filepath.Join(f.src, id, "conf", "app.ini"), "[v1]\n")
	}
	for id, files := range extra {
		writeFile(t, filepath.Join(f.src, id, "manifest.yaml"), files[0])
		writeFile(t, filepath.Join(f.src, id, "compose.yml"), files[1])
	}
	st := state.New()
	st.Sources = []state.Source{{Name: "local", Path: f.src}}
	if seed != nil {
		seed(st)
	}
	os.MkdirAll(f.data, 0755)
	if err := st.Save(filepath.Join(f.data, "state.yaml")); err != nil {
		t.Fatal(err)
	}
	if idp == nil {
		idp = f.idp
	}
	h, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "example.org"}, f.runner, f.engine, idp)
	if err != nil {
		t.Fatal(err)
	}
	h.lockPoll = 5 * time.Millisecond
	h.Init()
	t.Cleanup(h.Wait)
	f.h = h
	return f
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDefaultInstanceUnchanged(t *testing.T) {
	// Byte for byte what the base commit (before instances) generated from
	// an existing state.yaml with grafana and disks enabled. The env only
	// gains the instance variables.
	check := func(name string, got map[string]string, extraOverride string) {
		t.Helper()
		for _, n := range []string{"grafana.override.yml", "disks.override.yml", "policy.json"} {
			want := golden(t, n)
			if n == "grafana.override.yml" {
				want += extraOverride
			}
			if got[n] != want {
				t.Errorf("%s: %s differs from the base commit's:\n got:\n%s\nwant:\n%s", name, n, got[n], want)
			}
		}
		for _, n := range []string{"grafana.env", "disks.env"} {
			if g := instanceVarLineRe.ReplaceAllString(got[n], ""); g != golden(t, n) {
				t.Errorf("%s: %s differs from the base commit's (instance variables aside):\n got:\n%s\nwant:\n%s", name, n, g, golden(t, n))
			}
		}
		for k, want := range map[string]string{
			"PORTCULLIS_INSTANCE=": "grafana", "PORTCULLIS_HOST_GRAFANA=": "grafana.example.org",
			"PORTCULLIS_ACCESS_GROUP=": "users_grafana", "PORTCULLIS_ADMIN_GROUP=": "admin_grafana", "PORTCULLIS_OIDC_CLIENT_ID=": "",
		} {
			if !strings.Contains(got["grafana.env"], "\n"+k+want+"\n") {
				t.Errorf("%s: grafana.env lacks %s%s", name, k, want)
			}
		}
		if !strings.Contains(got["disks.env"], "\nPORTCULLIS_INSTANCE=disks\n") || !strings.Contains(got["disks.env"], "\nPORTCULLIS_HOST_DISKS=disks.example.org\n") {
			t.Errorf("%s: disks.env = %s", name, got["disks.env"])
		}
	}
	// The templates as they were: identical.
	_, legacy := goldenRun(t, false)
	check("legacy", legacy, "")
	// grafana converted to contract v2: identical, plus the volume name
	// the template no longer declares itself (today's name).
	f, v2 := goldenRun(t, true)
	check("v2", v2, "volumes:\n  \"grafana-data\":\n    name: \"portcullis_grafana-data\"\n")

	tpl := f.h.Template("grafana")
	if tpl == nil || !tpl.Enabled || !tpl.IsDefault() || tpl.TemplateID != "grafana" || tpl.Hosts["grafana"] != "grafana.example.org" {
		t.Fatalf("default instance = %+v", tpl)
	}
	ps := f.runner.Projects()
	if p := ps[len(ps)-1]; p.Name != "portcullis-disks" {
		t.Errorf("project = %+v", p)
	}
	iv := f.h.Instances()
	if len(iv) != 2 || iv[1].ID != "grafana" || !iv[1].Default || iv[1].State != StateEnabled || iv[1].Project != "portcullis-grafana" ||
		iv[1].AccessGroup != "users_grafana" {
		t.Errorf("instances = %+v", iv)
	}
	// Nothing about instances was written to state.yaml.
	if s := readFile(t, filepath.Join(f.data, "state.yaml")); strings.Contains(s, "instances:") {
		t.Errorf("state.yaml gained an instances section:\n%s", s)
	}
}

func TestTwoInstancesSeparate(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("grafana", "grafana-team-a", nil); err != nil {
		t.Fatal(err)
	}
	iv := f.h.Instances()
	if len(iv) != 1 || iv[0].ID != "grafana-team-a" || iv[0].State != StateCreated || iv[0].Default ||
		iv[0].Hosts["grafana"] != "grafana-team-a.example.org" || iv[0].AccessGroup != "users_grafana-team-a" ||
		iv[0].AdminGroup != "admin_grafana-team-a" || iv[0].Project != "portcullis-grafana-team-a" {
		t.Fatalf("instances = %+v", iv)
	}
	// The second instance needs a free host port before it can start.
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-team-a"); statusOf(err) != 409 || !strings.Contains(err.Error(), "3300") {
		t.Fatalf("port clash: %v", err)
	}
	if err := f.h.SaveSettings("grafana-team-a", SettingsUpdate{Values: map[string]string{"GRAFANA_PORT": "3310"}}); err != nil {
		t.Fatal(err)
	}
	callsBefore := len(f.runner.Calls())
	if err := f.h.Enable("grafana-team-a"); err != nil {
		t.Fatal(err)
	}
	// Enabling one doesn't touch the other.
	calls := f.runner.Calls()[callsBefore:]
	if len(calls) != 1 || calls[0] != "up:portcullis-grafana-team-a" {
		t.Errorf("calls = %v", calls)
	}
	if !f.h.IsEnabled("grafana") || !f.h.IsEnabled("grafana-team-a") {
		t.Error("both should be enabled")
	}

	// Env: separate files, instance variables, separate secrets.
	envA := readEnvFile(filepath.Join(f.data, "env", "grafana.env"))
	envB := readEnvFile(filepath.Join(f.data, "env", "grafana-team-a.env"))
	if envB["PORTCULLIS_INSTANCE"] != "grafana-team-a" || envB["PORTCULLIS_HOST_GRAFANA"] != "grafana-team-a.example.org" ||
		envB["PORTCULLIS_ACCESS_GROUP"] != "users_grafana-team-a" || envB["PORTCULLIS_ADMIN_GROUP"] != "admin_grafana-team-a" {
		t.Errorf("env B = %v", envB)
	}
	if envA["GF_SECRET"] == "" || envA["GF_SECRET"] == envB["GF_SECRET"] {
		t.Errorf("secrets shared: %q / %q", envA["GF_SECRET"], envB["GF_SECRET"])
	}

	// Override: renamed Traefik names, replaced labels, own volume.
	ov := readFile(t, filepath.Join(f.data, "overrides", "grafana-team-a.override.yml"))
	for _, want := range []string{
		"    labels: !override\n",
		`"traefik.http.routers.grafana-team-a_grafana.rule": "Host(` + "`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`" + `)"`,
		`"traefik.http.routers.grafana-team-a_grafana.tls.options": "authaware@file"`,
		`"traefik.http.routers.grafana-team-a_grafana.middlewares": "portcullis-auth@docker,portcullis-groups@docker,grafana-team-a_grafana-headers@docker,security-headers@file"`,
		`"traefik.http.routers.grafana-team-a_grafana-api.service": "grafana-team-a_grafana"`,
		`"traefik.http.middlewares.grafana-team-a_grafana-headers.headers.customresponseheaders.X-App": "grafana"`,
		`"traefik.http.services.grafana-team-a_grafana.loadbalancer.server.port": "3000"`,
		`"traefik.enable": "true"`,
		`"0.0.0.0:3310:3000/tcp"`,
		"  \"grafana-data\":\n    name: \"portcullis_grafana-team-a-grafana-data\"\n",
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("override lacks %q:\n%s", want, ov)
		}
	}
	if strings.Contains(ov, "routers.grafana.") || strings.Contains(ov, "services.grafana.") {
		t.Errorf("an original Traefik name survived:\n%s", ov)
	}

	// Policy: one entry per instance, each with its own groups.
	doc := readPolicy(t, f)
	if doc.Groups["grafana.example.org"] != "users_grafana" || doc.Groups["grafana-team-a.example.org"] != "users_grafana-team-a" {
		t.Errorf("groups = %v", doc.Groups)
	}
	if pg := doc.PathGroups["grafana-team-a.example.org"]; len(pg) != 1 || pg[0].Group != "admin_grafana-team-a" {
		t.Errorf("path_groups = %v", doc.PathGroups)
	}
	// Portal: one entry per instance.
	portal := f.h.Portal()
	if len(portal.Apps) != 2 || portal.Apps[1].ID != "grafana-team-a" || portal.Apps[1].Template != "grafana" ||
		portal.Apps[1].Name != "Grafana (grafana-team-a)" || portal.Apps[1].URLs[0].URL != "https://grafana-team-a.example.org" ||
		portal.Apps[0].Name != "Grafana" {
		t.Errorf("portal = %+v", portal.Apps)
	}
	// Catalog: one template with both instance ids.
	for _, tpl := range f.h.Templates() {
		if tpl.ID == "grafana" && strings.Join(tpl.Instances, ",") != "grafana,grafana-team-a" {
			t.Errorf("catalog instances = %v", tpl.Instances)
		}
	}

	// Settings and policies stay per instance.
	if err := f.h.Disable("grafana-team-a"); err != nil {
		t.Fatal(err)
	}
	if !f.h.IsEnabled("grafana") {
		t.Error("disabling B disabled A")
	}
	if g := readPolicy(t, f).Groups; g["grafana-team-a.example.org"] != "" || g["grafana.example.org"] != "users_grafana" {
		t.Errorf("after disable: groups = %v", g)
	}
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if e := st.Instances["grafana-team-a"]; e.Template != "grafana" || e.State != "" || e.Hosts["grafana"] != "grafana-team-a.example.org" {
		t.Errorf("state entry = %+v", e)
	}
	if got := f.h.Instances(); len(got) != 2 || got[1].State != StateDisabled {
		t.Errorf("instances = %+v", got)
	}
}

func TestInstanceKeycloakClients(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	if len(f.idp.specs) != 2 {
		t.Fatalf("specs = %+v", f.idp.specs)
	}
	s0, s1 := f.idp.specs[0], f.idp.specs[1]
	if s0.ClientID != "chat-b" || s0.TemplateID != "chat-b" || s0.RedirectURIs[0] != "https://chat-b.example.org/cb" ||
		strings.Join(s0.AllowedHosts, ",") != "chat-b.example.org" {
		t.Errorf("first client = %+v", s0)
	}
	if s1.ClientID != "chat-b-chat-admin" || s1.RedirectURIs[0] != "https://chat-b.example.org/admin/cb" {
		t.Errorf("second client = %+v", s1)
	}
	env := readEnvFile(filepath.Join(f.data, "env", "chat-b.env"))
	if env["PORTCULLIS_OIDC_CLIENT_ID"] != "chat-b" || env["PORTCULLIS_OIDC_CLIENT_ID_CHAT"] != "chat-b" ||
		env["PORTCULLIS_OIDC_CLIENT_ID_CHAT_ADMIN"] != "chat-b-chat-admin" || env["PORTCULLIS_ADMIN_GROUP"] != "" {
		t.Errorf("env = %v", env)
	}
}

func TestInstanceIDRules(t *testing.T) {
	f := newInstanceFixture(t, nil)
	for _, c := range []struct {
		id     string
		status int
		why    string
	}{
		{"Grafana-b", 400, "must match"},
		{"1grafana", 400, "must match"},
		{"grafana_b", 400, "must match"},
		{"g" + strings.Repeat("a", 31), 400, "must match"},
		{"portcullis-x", 400, "reserved"},
		{"portcullisx", 400, "reserved"},
		{"a-portcullis-b", 400, "portcullis may not be a segment"},
		{"team-portcullis", 400, "portcullis may not be a segment"},
		{"team--b", 400, "single -"},
		{"team-", 400, "single -"},
		{"portcullisx-b", 400, "reserved"},
		{"chat", 409, "template id"},
		{"disks", 409, "template id"},
	} {
		err := f.h.CreateInstance("grafana", c.id, nil)
		if statusOf(err) != c.status || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: got %v, want %d (%s)", c.id, err, c.status, c.why)
		}
	}
	// Derived names that equal another template's default names (§11.1).
	// Volume: template store's default volume portcullis_team-grafana-data
	// is what grafana instance "team" would derive.
	writeFile(t, filepath.Join(f.src, "store", "manifest.yaml"), "name: Store\ninstances: multi\nauth:\n  method: forward-auth\n")
	writeFile(t, filepath.Join(f.src, "store", "compose.yml"), "services:\n  s:\n    image: x\n    volumes: [team-grafana-data:/d]\nvolumes:\n  team-grafana-data: {}\n")
	f.h.Discover()
	if err := f.h.CreateInstance("grafana", "team", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "volume portcullis_team-grafana-data") {
		t.Errorf("volume collision: %v", err)
	}
	// A group collision (case-insensitive) with a template's default group.
	writeFile(t, filepath.Join(f.src, "teams", "manifest.yaml"), "name: Teams\ninstances: multi\nauth:\n  method: forward-auth\n  group_access: true\n  access_group: Users_Ops\n")
	writeFile(t, filepath.Join(f.src, "teams", "compose.yml"), "services:\n  s:\n    image: x\n")
	f.h.Discover()
	if err := f.h.CreateInstance("grafana", "ops", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "group users_ops") {
		t.Errorf("group collision: %v", err)
	}
	// Keycloak client: chat's default clients are chat and chat-admin; a
	// chat instance "chat-admin" would use chat-admin as its first client.
	if err := f.h.CreateInstance("chat", "chat-admin", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "Keycloak client chat-admin") {
		t.Errorf("client collision: %v", err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); statusOf(err) != 409 {
		t.Errorf("duplicate id: %v", err)
	}
	// Two chat instances whose client ids would meet: "a" → a, a-chat-admin;
	// "a-chat-admin" → a-chat-admin. Refused.
	if err := f.h.CreateInstance("chat", "a", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.CreateInstance("chat", "a-chat-admin", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "instance a") {
		t.Errorf("cross-instance client collision: %v", err)
	}
	// An existing compose project of that name is refused.
	f.engine.containers = append(f.engine.containers, container("c1", "portcullis-grafana-c", "grafana", "exited"))
	f.engine.containers[len(f.engine.containers)-1].Labels[docker.LabelProject] = "portcullis-grafana-c"
	if err := f.h.CreateInstance("grafana", "grafana-c", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "compose project") {
		t.Errorf("leftover project: %v", err)
	}
	// Hostnames: in use by another instance, core, or not on the domain.
	for hosts, why := range map[string]string{
		"grafana-b.example.org": "already used by instance grafana-b",
		"grafana.example.org":   "already used by instance grafana",
		"auth.example.org":      "core hostname",
		"grafana.other.org":     "neither <label>.example.org nor on an enrolled domain",
		"a.b.example.org":       "deeper names need an enrolled domain",
	} {
		err := f.h.CreateInstance("grafana", "grafana-d", map[string]string{"grafana": hosts})
		if err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("host %s: %v, want %q", hosts, err, why)
		}
	}
	if err := f.h.CreateInstance("grafana", "grafana-d", map[string]string{"grafana": "dash.example.org", "nope": "x.example.org"}); statusOf(err) != 400 {
		t.Errorf("unknown host router: %v", err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-d", map[string]string{"grafana": "Dash.Example.org."}); err != nil {
		t.Errorf("explicit host: %v", err)
	}
	if h := f.h.Template("grafana-d").Hosts["grafana"]; h != "dash.example.org" {
		t.Errorf("normalised host = %s", h)
	}
	// A template that later appears with an existing instance's id loses.
	writeFile(t, filepath.Join(f.src, "grafana-b", "manifest.yaml"), "name: GB\nauth:\n  method: forward-auth\n")
	writeFile(t, filepath.Join(f.src, "grafana-b", "compose.yml"), "services:\n  s:\n    image: x\n")
	f.h.Discover()
	if tpl := f.h.Template("grafana-b"); tpl == nil || tpl.TemplateID != "grafana" {
		t.Errorf("grafana-b = %+v", tpl)
	}
}

func TestDefaultHostsTruncated(t *testing.T) {
	f := newInstanceFixture(t, nil)
	id := "grafana-" + strings.Repeat("x", 23) // 31 chars
	if err := f.h.CreateInstance("grafana", id, nil); err != nil {
		t.Fatal(err)
	}
	if h := f.h.Template(id).Hosts["grafana"]; h != "grafana-"+strings.Repeat("x", 23)+".example.org" {
		t.Errorf("host = %s", h)
	}
	if got := instanceSuffix("litellm", "litellm-lab"); got != "lab" {
		t.Errorf("suffix = %s", got)
	}
	if got := instanceSuffix("litellm", "lab"); got != "lab" {
		t.Errorf("suffix = %s", got)
	}
}

func TestSingleTemplateRefusesSecondInstance(t *testing.T) {
	f := newInstanceFixture(t, nil)
	err := f.h.CreateInstance("disks", "disks-b", nil)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "single") {
		t.Fatalf("got %v", err)
	}
	if len(f.h.Instances()) != 0 {
		t.Errorf("instances = %+v", f.h.Instances())
	}
	if err := f.h.CreateInstance("nope", "nope-b", nil); statusOf(err) != 404 {
		t.Errorf("unknown template: %v", err)
	}
	// The single template still runs as its default instance; the Hub
	// never names a single template's volumes (they keep what compose
	// names them: the declared name, else <project>_<key>).
	if err := f.h.Enable("disks"); err != nil {
		t.Fatal(err)
	}
	ov := readFile(t, filepath.Join(f.data, "overrides", "disks.override.yml"))
	if strings.Contains(ov, "volumes:") || strings.Contains(ov, "name:") {
		t.Errorf("override names a single template's volume:\n%s", ov)
	}
	if n := f.h.Template("disks").NamesFor("disks"); n.Volumes["disks-data"] != "portcullis_disks-data" {
		t.Errorf("names = %+v", n)
	}
	// A legacy single template with an unnamed volume (golden fixture).
	g, out := goldenRun(t, false)
	if ov := out["disks.override.yml"]; strings.Contains(ov, "volumes:") {
		t.Errorf("legacy override:\n%s", ov)
	}
	if n := g.h.Template("disks").NamesFor("disks"); n.Volumes["data"] != "portcullis-disks_data" {
		t.Errorf("legacy names = %+v", n)
	}
}

// TestHostNetworkPortsPerInstance: a netbird-like template binds host
// ports itself (network_mode: host, a range); they are per-instance
// settings, reach the app through the env and count in the collision
// check, so a second instance must pick free ones.
func TestHostNetworkPortsPerInstance(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.Enable("relay"); err != nil {
		t.Fatal(err)
	}
	env := readEnvFile(filepath.Join(f.data, "env", "relay.env"))
	if env["RELAY_PORT"] != "3478" || env["RELAY_RANGE"] != "49152-65535" {
		t.Errorf("default env = %v", env)
	}
	if err := f.h.CreateInstance("relay", "relay-b", nil); err != nil {
		t.Fatal(err)
	}
	err := f.h.Enable("relay-b")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "3478") {
		t.Fatalf("same host-network port: %v", err)
	}
	// A free port but an overlapping range is still refused.
	if err := f.h.SaveSettings("relay-b", SettingsUpdate{Values: map[string]string{"RELAY_PORT": "3479", "RELAY_RANGE": "40000-49152"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("relay-b"); statusOf(err) != 409 || !strings.Contains(err.Error(), "RELAY_RANGE") {
		t.Fatalf("overlapping range: %v", err)
	}
	if err := f.h.SaveSettings("relay-b", SettingsUpdate{Values: map[string]string{"RELAY_PORT": "3479", "RELAY_RANGE": "40000-40100"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("relay-b"); err != nil {
		t.Fatal(err)
	}
	env = readEnvFile(filepath.Join(f.data, "env", "relay-b.env"))
	if env["RELAY_PORT"] != "3479" || env["RELAY_RANGE"] != "40000-40100" {
		t.Errorf("instance env = %v", env)
	}
	// Changing a running instance's ports into a clash is refused.
	err = f.h.SaveSettings("relay-b", SettingsUpdate{Values: map[string]string{"RELAY_PORT": "3478", "RELAY_RANGE": "40000-40100"}})
	if statusOf(err) != 409 {
		t.Errorf("clash on save: %v", err)
	}
	// Bad ranges are refused.
	for _, r := range []string{"40100-40000", "0-10", "1-70000", "abc", "40000"} {
		if err := f.h.SaveSettings("relay-b", SettingsUpdate{Values: map[string]string{"RELAY_RANGE": r}}); statusOf(err) != 400 {
			t.Errorf("range %q: %v", r, err)
		}
	}
	// Neither range nor host-network port is published by compose.
	ov := readFile(t, filepath.Join(f.data, "overrides", "relay-b.override.yml"))
	if strings.Contains(ov, "ports:") {
		t.Errorf("override publishes host-network ports:\n%s", ov)
	}
}

func TestInstanceDriftRenamedLabels(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	want, err := f.h.desiredRouteLabelsLocked(f.h.findLocked("grafana-b"))
	f.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range want["web"] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "traefik.http.routers.grafana-b_grafana-api.tls.options,traefik.http.routers.grafana-b_grafana.tls.options" {
		t.Errorf("desired keys = %v", keys)
	}
	// A running container carrying exactly those labels is not drift.
	c := container("c1", "portcullis-grafana-b", "web", "running")
	for k, v := range want["web"] {
		c.Labels[k] = v
	}
	c.Labels["traefik.http.routers.grafana-b_grafana.rule"] = "Host(`grafana-b.example.org`)"
	f.engine.containers = []docker.Container{c}
	rep := f.h.Reconcile(t.Context())
	if len(rep.Items) != 0 {
		t.Errorf("drift = %+v", rep.Items)
	}
	// One with the template's original (unrenamed) names is.
	c.Labels["traefik.http.routers.grafana.tls.options"] = "public@file"
	f.engine.containers = []docker.Container{c}
	if rep := f.h.Reconcile(t.Context()); len(rep.Items) != 1 || rep.Items[0].Kind != DriftPublicAccess {
		t.Errorf("drift = %+v", rep.Items)
	}
}

func TestExpandComposeValue(t *testing.T) {
	env := map[string]string{"PORTCULLIS_HOST_GRAFANA": "g.team.example.org"}
	got := expandComposeValue("Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`) && PathRegexp(`^/x$$`) && ${PORTCULLIS_DOMAIN:-d} ${OTHER}", "example.org", env)
	if got != "Host(`g.team.example.org`) && PathRegexp(`^/x$`) && example.org ${OTHER}" {
		t.Errorf("got %s", got)
	}
	if got := expandComposeValue("$${PORTCULLIS_DOMAIN}", "example.org", nil); got != "${PORTCULLIS_DOMAIN}" {
		t.Errorf("escaped: %s", got)
	}
}

func TestInstanceEnvIsTheHubs(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"PORTCULLIS_HOST_GRAFANA", "PORTCULLIS_INSTANCE", "PORTCULLIS_DOMAIN", "PORTCULLIS_OIDC_CLIENT_ID_X"} {
		if err := f.h.SaveEnv("grafana", map[string]string{k: "evil.example.com"}); statusOf(err) != 400 {
			t.Errorf("SaveEnv %s: %v", k, err)
		}
	}
	// A hand-edited file is put right before the next compose up.
	path := filepath.Join(f.data, "env", "grafana.env")
	if err := setEnvVar(path, "PORTCULLIS_HOST_GRAFANA", "evil.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.RestartApp("grafana"); err != nil {
		t.Fatal(err)
	}
	if v := readEnvFile(path)["PORTCULLIS_HOST_GRAFANA"]; v != "grafana.example.org" {
		t.Errorf("after restart: %s", v)
	}
}

// TestSiblingsShareSupportFiles: instances of one template share
// <core>/templates/<template-id>/. An unchanged tree is never swapped
// under a running sibling; concurrent syncs of siblings are serialised.
func TestSiblingsShareSupportFiles(t *testing.T) {
	f := newInstanceFixture(t, nil)
	dest := filepath.Join(f.project, "templates", "grafana")
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"grafana-b", "grafana-c"} {
		if err := f.h.CreateInstance("grafana", id, nil); err != nil {
			t.Fatal(err)
		}
		if err := f.h.SaveSettings(id, SettingsUpdate{Values: map[string]string{"GRAFANA_PORT": fmt.Sprint(3311 + i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(dest)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the running sibling's support dir was swapped although nothing changed (%v)", err)
	}
	// The published hash is recorded in the Hub's data dir, not in dest,
	// and survives a restart of the Hub.
	if rec := readFile(t, filepath.Join(f.data, "template-sync.json")); !strings.Contains(rec, `"grafana"`) {
		t.Errorf("sync record = %s", rec)
	}
	h2, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	if h2.syncHashes["grafana"] == "" || h2.syncHashes["grafana"] != f.h.syncHashes["grafana"] {
		t.Errorf("reloaded record = %v", h2.syncHashes)
	}
	// A file edited in the shared dir is put back on the next up.
	writeFile(t, filepath.Join(dest, "conf", "app.ini"), "tampered\n")
	if err := f.h.RestartApp("grafana"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dest, "conf", "app.ini")); got != "[v1]\n" {
		t.Errorf("tampered support file kept: %q", got)
	}
	// Changed content: two siblings sync concurrently, both succeed and the
	// result is the new tree.
	writeFile(t, filepath.Join(f.src, "grafana", "conf", "app.ini"), "[v2]\n")
	if err := f.h.Disable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []string{"grafana-b", "grafana-c"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f.h.Enable(id)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("enable %d: %v", i, err)
		}
	}
	if got := readFile(t, filepath.Join(dest, "conf", "app.ini")); got != "[v2]\n" {
		t.Errorf("support file = %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(f.project, "templates"))
	for _, e := range entries {
		if e.Name() != "grafana" {
			t.Errorf("leftover %s in templates/", e.Name())
		}
	}
}

// TestDiscoverSkipsTemplateCollidingWithInstance: a template discovered
// after an instance whose derived names its default instance would use is
// skipped; the instance was there first.
func TestDiscoverSkipsTemplateCollidingWithInstance(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	for id, c := range map[string][2]string{
		// its access group is grafana-b's.
		"teamb": {"name: T\nauth:\n  method: forward-auth\n  group_access: true\n  access_group: USERS_grafana-b\n",
			"services:\n  s:\n    image: x\n"},
		// its volume portcullis_grafana-b-grafana-data is grafana-b's.
		"store": {"name: S\ninstances: multi\nauth:\n  method: forward-auth\n",
			"services:\n  s:\n    image: x\nvolumes:\n  grafana-b-grafana-data: {}\n"},
		// no collision.
		"fine": {"name: F\nauth:\n  method: forward-auth\n", "services:\n  s:\n    image: x\n"},
	} {
		writeFile(t, filepath.Join(f.src, id, "manifest.yaml"), c[0])
		writeFile(t, filepath.Join(f.src, id, "compose.yml"), c[1])
	}
	f.h.Discover()
	if f.h.Template("teamb") != nil || f.h.Template("store") != nil {
		t.Error("a colliding template was loaded")
	}
	if f.h.Template("fine") == nil || f.h.Template("grafana-b") == nil {
		t.Error("lost a template or the instance")
	}
}

func TestBrokenInstanceListedAsError(t *testing.T) {
	f := newInstanceFixture(t, nil)
	for _, c := range [][2]string{{"chat", "chat-b"}, {"grafana", "grafana-b"}} {
		if err := f.h.CreateInstance(c[0], c[1], nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	// chat's template disappears; grafana's host router is renamed, so
	// grafana-b's stored hostnames no longer fit.
	os.RemoveAll(filepath.Join(f.src, "chat"))
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), strings.ReplaceAll(strings.ReplaceAll(v2GrafanaCompose,
		"routers.grafana.", "routers.dash."), "PORTCULLIS_HOST_GRAFANA", "PORTCULLIS_HOST_DASH"))
	writeFile(t, filepath.Join(f.src, "grafana", "manifest.yaml"), strings.ReplaceAll(v2GrafanaManifest, "HOST_GRAFANA", "HOST_DASH"))
	f.h.Discover()
	got := map[string]InstanceView{}
	for _, v := range f.h.Instances() {
		got[v.ID] = v
	}
	if v := got["chat-b"]; v.State != StateError || !strings.Contains(v.Error, "template chat is missing") || v.Template != "chat" {
		t.Errorf("chat-b = %+v", v)
	}
	if v := got["grafana-b"]; v.State != StateError || !strings.Contains(v.Error, "dash") || v.Hosts["grafana"] != "grafana-b.example.org" {
		t.Errorf("grafana-b = %+v", v)
	}
	// Still fail-closed: chat-b is enabled, its published snapshot holds.
	if g := readPolicy(t, f).Groups["chat-b.example.org"]; g != "users_chat-b" {
		t.Errorf("policy groups = %v", readPolicy(t, f).Groups)
	}
	if err := f.h.Enable("grafana-b"); err == nil {
		t.Error("enabled a broken instance")
	}
}

func TestInstanceHostsVsOtherSources(t *testing.T) {
	f := newInstanceFixture(t, nil)
	other := filepath.Join(filepath.Dir(f.src), "other-src")
	// A duplicate id (skipped: the first source wins) routing "talk".
	writeFile(t, filepath.Join(other, "chat", "manifest.yaml"), "name: C2\nauth:\n  method: forward-auth\n")
	writeFile(t, filepath.Join(other, "chat", "compose.yml"), "services:\n  s:\n    labels:\n      traefik.http.routers.talk.rule: Host(`${PORTCULLIS_HOST_TALK:-talk.portcullis.local}`)\n")
	f.h.mu.Lock()
	f.h.st.Sources = append(f.h.st.Sources, state.Source{Name: "other", Path: other})
	f.h.mu.Unlock()
	f.h.Discover()
	err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "talk.example.org"})
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "template chat (source other)") {
		t.Errorf("got %v", err)
	}
}

// TestMissingTemplateKeepsReservations: an instance whose template
// disappears keeps its names; a new template can't take them.
func TestMissingTemplateKeepsReservations(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(f.src, "grafana"))
	for id, c := range map[string][2]string{
		"teamb": {"name: T\nauth:\n  method: forward-auth\n  group_access: true\n  access_group: users_grafana-b\n", "services:\n  s:\n    image: x\n"},
		"store": {"name: S\ninstances: multi\nauth:\n  method: forward-auth\n", "services:\n  s:\n    image: x\nvolumes:\n  grafana-b-data: {}\n"},
		"kc":    {"name: K\nauth:\n  method: native-oidc\n  group_access: true\nkeycloak_clients:\n  - client_id: grafana-b-x\n", "services:\n  s:\n    image: x\n"},
		// The missing default instance's published groups too.
		"ga":   {"name: G\nauth:\n  method: forward-auth\n  group_access: true\n  access_group: users_grafana\n", "services:\n  s:\n    image: x\n"},
		"fine": {"name: F\nauth:\n  method: forward-auth\n", "services:\n  s:\n    image: x\n"},
	} {
		writeFile(t, filepath.Join(f.src, id, "manifest.yaml"), c[0])
		writeFile(t, filepath.Join(f.src, id, "compose.yml"), c[1])
	}
	f.h.Discover()
	for _, id := range []string{"teamb", "store", "kc", "ga"} {
		if f.h.Template(id) != nil {
			t.Errorf("%s took a name of grafana-b / grafana (template missing)", id)
		}
	}
	if f.h.Template("fine") == nil {
		t.Error("fine was skipped")
	}
	// New instances can't take them either: with its template gone,
	// grafana-b's client pattern grafana-b-* stays reserved.
	if err := f.h.CreateInstance("chat", "grafana-b-chat", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "template grafana missing") {
		t.Errorf("grafana-b-chat: %v", err)
	}
	if err := f.h.CreateInstance("chat", "chat-c", nil); err != nil {
		t.Errorf("unrelated id refused: %v", err)
	}
	f.h.mu.Lock()
	r := f.h.reservationsLocked(func(tid string) *templates.Template { return f.h.catalogLocked(tid) }, "")
	f.h.mu.Unlock()
	for _, c := range []string{"project\x00portcullis-grafana-b", "group\x00users_grafana-b", "group\x00admin_grafana-b",
		"Keycloak client\x00grafana-b", "volume\x00portcullis_grafana-b-anything", "project\x00portcullis-grafana", "group\x00users_grafana",
		"Traefik name\x00grafana-b_anything"} {
		if _, who := r.match([]string{c}); who == "" {
			t.Errorf("%q not reserved", c)
		}
	}
}

// TestTraefikNameClaims (fix round 5, I2): Traefik merges same-name
// routers, services and middlewares across containers, so a template
// defining another app's name would receive its traffic (forward-auth
// identity headers included). Every template-defined name, renamed per
// instance, is a claim: Discover refuses a second default instance with
// it (enabled ones first), CreateInstance an instance deriving it.
func TestTraefikNameClaims(t *testing.T) {
	route := func(r string) string {
		return "      traefik.http.routers." + r + ".rule: Host(`${PORTCULLIS_HOST_" + strings.ToUpper(r) + ":-" + r + ".portcullis.local}`)\n"
	}
	m := "name: X\ninstances: multi\nauth:\n  method: forward-auth\n"
	extra := map[string][2]string{
		// aaa sorts before grafana and defines grafana's service and
		// middleware: Traefik would merge them with grafana's.
		"aaa": {m, "services:\n  s:\n    image: x\n    labels:\n" + route("aaa") +
			"      traefik.http.services.grafana.loadbalancer.server.port: \"80\"\n" +
			"      traefik.http.middlewares.grafana-headers.headers.customresponseheaders.X-User: admin\n"},
		// Two templates, neither enabled, sharing a router name: the
		// first (source order) keeps it.
		"pair-a": {m, "services:\n  s:\n    image: x\n    labels:\n" + route("pair") + "      traefik.http.services.pair-a.loadbalancer.server.port: \"80\"\n"},
		"pair-b": {m, "services:\n  s:\n    image: x\n    labels:\n" + route("pair") + "      traefik.http.services.pair-b.loadbalancer.server.port: \"80\"\n"},
		"fine":   {m, "services:\n  s:\n    image: x\n    labels:\n" + route("fine")},
	}
	f := newInstanceFixtureExtra(t, func(st *state.AppState) { st.SetEnabled("grafana", true) }, nil, extra)
	if f.h.Template("aaa") != nil {
		t.Error("aaa (grafana's Traefik service and middleware) was loaded")
	}
	if f.h.Template("grafana") == nil {
		t.Error("grafana (enabled, claims first) was skipped")
	}
	if f.h.Template("pair-a") == nil || f.h.Template("pair-b") != nil {
		t.Errorf("pair: a loaded %v, b loaded %v; want only a", f.h.Template("pair-a") != nil, f.h.Template("pair-b") != nil)
	}
	if f.h.Template("fine") == nil {
		t.Error("fine was skipped")
	}
	// Not enabled, grafana has no precedence: aaa sorts first and wins.
	g := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"aaa": extra["aaa"]})
	if g.h.Template("aaa") == nil || g.h.Template("grafana") != nil {
		t.Errorf("unenabled: aaa loaded %v, grafana loaded %v; want aaa only", g.h.Template("aaa") != nil, g.h.Template("grafana") != nil)
	}
	// An instance's names are its own (<id>_<name>), so it may run beside
	// the default instance; its claims are the renamed names.
	if err := f.h.CreateInstance("grafana", "gb", nil); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	r := f.h.reservationsLocked(func(tid string) *templates.Template { return f.h.catalogLocked(tid) }, "")
	f.h.mu.Unlock()
	for _, c := range []string{"Traefik name\x00gb_grafana", "Traefik name\x00gb_grafana-api", "Traefik name\x00gb_grafana-headers"} {
		if _, who := r.match([]string{c}); who != "instance gb" {
			t.Errorf("%q: owner %q, want instance gb", c, who)
		}
	}
	n := f.h.Template("grafana").NamesFor("gb")
	if strings.Join(n.Traefik, ",") != "gb_grafana,gb_grafana-api,gb_grafana-headers" {
		t.Errorf("NamesFor(gb).Traefik = %v", n.Traefik)
	}
	// CreateInstance compares the same claims (checkInstanceNamesLocked):
	// a template-defined name an instance would derive is refused.
	f.h.mu.Lock()
	f.h.allTemplates = append(f.h.allTemplates, templates.Template{ID: "evil", TemplateID: "evil", Names: map[string]bool{"gc_grafana": true}})
	f.h.mu.Unlock()
	if err := f.h.CreateInstance("grafana", "gc", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "Traefik name gc_grafana") {
		t.Errorf("gc: %v", err)
	}
}

// TestSingleVolumeNameClaims (fix round 5, I3): a single template names
// its volumes inside portcullis_<template-id>[-_…]; a name in that
// namespace another template's (or instance's) volume derives is a claim.
func TestSingleVolumeNameClaims(t *testing.T) {
	single := "name: S\ninstances: single\nauth:\n  method: forward-auth\n"
	multi := "name: M\ninstances: multi\nauth:\n  method: forward-auth\n"
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{
		// op's own namespace holds portcullis_op-s-grafana-data, which
		// grafana instance "op-s" would derive.
		"op": {single, "services:\n  s:\n    image: x\n    volumes: [d:/d]\nvolumes:\n  d:\n    name: portcullis_op-s-grafana-data\n"},
		// st names portcullis_st-data; multi template "store" (default
		// instance: portcullis_<key>) has the key st-data.
		"st":    {single, "services:\n  s:\n    image: x\n    volumes: [d:/d]\nvolumes:\n  d:\n    name: portcullis_st-data\n"},
		"store": {multi, "services:\n  s:\n    image: x\n    volumes: [st-data:/d]\nvolumes:\n  st-data: {}\n"},
		// Not its own namespace.
		"thief": {single, "services:\n  s:\n    image: x\n    volumes: [d:/d]\nvolumes:\n  d:\n    name: portcullis_disks-data\n"},
	})
	if f.h.Template("thief") != nil {
		t.Error("thief (disks' volume portcullis_disks-data) was loaded")
	}
	if f.h.Template("st") == nil || f.h.Template("store") != nil {
		t.Errorf("st loaded %v, store loaded %v; want st only (source order)", f.h.Template("st") != nil, f.h.Template("store") != nil)
	}
	if got := f.h.Template("op").NamesFor("op").Volumes["d"]; got != "portcullis_op-s-grafana-data" {
		t.Errorf("op's volume = %q", got)
	}
	if err := f.h.CreateInstance("grafana", "op-s", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "volume portcullis_op-s-grafana-data") {
		t.Errorf("op-s: %v", err)
	}
}

// TestInstanceCoreContainerName (fix round 5, M6): project
// portcullis-<id> names its containers portcullis-<id>-<service>-<n>;
// one that is a core service's container name is refused.
func TestInstanceCoreContainerName(t *testing.T) {
	m := "name: A\ninstances: multi\nauth:\n  method: forward-auth\n"
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{
		"authy": {m, "services:\n  auth:\n    image: x\n  proxy-hub:\n    image: x\n    labels:\n" +
			"      traefik.http.routers.authy.rule: Host(`${PORTCULLIS_HOST_AUTHY:-authy.portcullis.local}`)\n"},
		// The default instance: project portcullis-forward, service auth.
		"forward": {m, "services:\n  auth:\n    image: x\n"},
	})
	if f.h.Template("forward") != nil {
		t.Error("forward (container portcullis-forward-auth-1) was loaded")
	}
	for id, c := range map[string]string{"forward": "portcullis-forward-auth-1", "socket": "portcullis-socket-proxy-hub-1"} {
		if err := f.h.CreateInstance("authy", id, nil); statusOf(err) != 409 || !strings.Contains(err.Error(), c) {
			t.Errorf("%s: %v", id, err)
		}
	}
	if err := f.h.CreateInstance("authy", "authy-b", nil); err != nil {
		t.Errorf("authy-b: %v", err)
	}
}

// TestInstanceMixedCaseReference (fix round 5, I4): a multi template
// whose non-default instance would carry a mixed-case reference (the
// validator folds, RenameLabels used to match raw case, so "Hdr" stayed
// the default instance's middleware) is refused at discover; the
// lowercase form loads and its instance gets every reference renamed.
func TestInstanceMixedCaseReference(t *testing.T) {
	m := "name: C\ninstances: multi\nauth:\n  method: forward-auth\n"
	body := func(p, ref string) string {
		return "services:\n  s:\n    image: x\n    labels:\n" +
			"      traefik.http.routers." + p + ".rule: Host(`${PORTCULLIS_HOST_" + strings.ToUpper(p) + ":-" + p + ".portcullis.local}`)\n" +
			"      traefik.http.routers." + p + ".middlewares: portcullis-auth@docker,portcullis-groups@docker," + p + "-cc\n" +
			"      traefik.http.middlewares." + p + "-cc.chain.middlewares: " + ref + "\n" +
			"      traefik.http.middlewares." + p + "-hdr.headers.customrequestheaders.X-A: b\n"
	}
	logs := &lockedBuf{}
	log.SetOutput(logs)
	defer log.SetOutput(os.Stderr)
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{
		"mixed": {m, body("mixed", "Mixed-Hdr@docker")},
		"lower": {m, body("lower", "lower-hdr@docker")},
	})
	if !strings.Contains(logs.String(), `Skipping template mixed: service s: label traefik.http.middlewares.mixed-cc.chain.middlewares: "Mixed-Hdr@docker" must be lowercase`) {
		t.Errorf("mixed not refused for its case:\n%s", logs.String())
	}
	if f.h.Template("mixed") != nil {
		t.Fatal("mixed-case reference loaded")
	}
	if err := f.h.CreateInstance("mixed", "mixed-b", nil); statusOf(err) != 404 {
		t.Errorf("mixed-b: %v", err)
	}
	if err := f.h.CreateInstance("lower", "lower-b", nil); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	it := f.h.findLocked("lower-b")
	rl, err := f.h.routeLabelsLocked(it)
	var labels map[string]map[string]string
	if err == nil {
		labels, err = f.h.instanceLabelsLocked(it, rl)
	}
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	l := labels["s"]
	if l["traefik.http.middlewares.lower-b_lower-cc.chain.middlewares"] != "lower-b_lower-hdr@docker" ||
		!strings.Contains(l["traefik.http.routers.lower-b_lower.middlewares"], "lower-b_lower-cc") {
		t.Errorf("instance labels = %v", l)
	}
}

// lockedBuf is a log sink safe for the Hub's background goroutines.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestDiscoverClaimsAfterSort: Discover sorts enabled templates first;
// the template lookup used for existing instances' claims must follow the
// sort. Here grafana (enabled) moves ahead of chat and disks, and a new
// single template "team" names the volume grafana's instance team-x
// derives (portcullis_team-x-grafana-data): it must be skipped.
func TestDiscoverClaimsAfterSort(t *testing.T) {
	team := [2]string{
		"name: Team\ninstances: single\nauth:\n  method: forward-auth\n",
		"services:\n  team:\n    image: x\n    labels:\n" +
			"      traefik.http.routers.team.rule: Host(`${PORTCULLIS_HOST_TEAM:-team.portcullis.local}`)\n" +
			"    volumes:\n      - d:/d\n" +
			"volumes:\n  d:\n    name: portcullis_team-x-grafana-data\n",
	}
	f := newInstanceFixtureExtra(t, func(st *state.AppState) {
		st.SetEnabled("grafana", true)
		st.Instances["team-x"] = state.Instance{ID: "team-x", Template: "grafana", Hosts: map[string]string{"grafana": "grafana-team-x.example.org"}}
	}, nil, map[string][2]string{"team": team})
	if f.h.Template("grafana") == nil {
		t.Fatal("grafana was skipped")
	}
	if f.h.Template("team") != nil {
		t.Error("team loaded although it names instance team-x's volume portcullis_team-x-grafana-data")
	}
}
