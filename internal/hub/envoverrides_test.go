package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/dotenv"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// envAppManifest has a variable of every source (§11.9): manifest env
// entries (LOG_LEVEL plain, GEN_VALUE generated), a Keycloak client's
// secret_env, an option's env delivery (TRASH_DAYS), a secret option's
// (OPT_VALUE) and compose defaults (PHP_MEMORY_LIMIT, UPLOAD_MAX).
const envAppManifest = `name: Env App
category: misc
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: true
  group_access: true
  access_group: users_envapp
keycloak_clients:
  - client_id: envapp
    secret_env: CLIENT_VALUE
    redirect_uri: https://{{HOST_ENVAPP}}/cb
env:
  - key: GEN_VALUE
    generate: random
  - key: LOG_LEVEL
settings:
  options:
    - key: trash_days
      label: Trash days
      type: int
      min: 1
      default: 30
      applies: restart
      delivery: [{env: TRASH_DAYS}]
    - key: api_key
      label: API key
      type: secret
      applies: restart
      delivery: [{env: OPT_VALUE}]
`

const envAppCompose = "services:\n  web:\n    image: x\n    environment:\n      C: ${CLIENT_VALUE}\n      G: ${GEN_VALUE}\n      O: ${OPT_VALUE}\n" +
	"      T: ${TRASH_DAYS}\n      L: ${LOG_LEVEL}\n      P: ${PHP_MEMORY_LIMIT:-512M}\n      U: ${UPLOAD_MAX-10M}\n" +
	"    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.envapp.rule: Host(`${PORTCULLIS_HOST_ENVAPP:-envapp.portcullis.local}`)\n      traefik.http.services.envapp.loadbalancer.server.port: \"80\"\n"

// envFixture: envapp enabled (compose simulated), audits recorded.
func envFixture(t *testing.T) (*fixture, *fakeAudit) {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"envapp": {envAppManifest, envAppCompose}})
	if f.h.Template("envapp") == nil {
		t.Fatal("envapp fixture not loaded (see the log)")
	}
	a := &fakeAudit{}
	f.h.SetAudit(a)
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 0)
	if err := f.h.Enable("envapp"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	return f, a
}

var envAdmin = directory.Human("admin")

func rowOf(t *testing.T, f *fixture, id, name string) *EnvRow {
	t.Helper()
	rows, err := f.h.EnvRows(id)
	if err != nil {
		t.Fatal(err)
	}
	return envRowOf(rows, name)
}

// composeEnv is the .env as compose reads it (compose-go's dotenv).
func composeEnv(t *testing.T, f *fixture, id string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(f.h.envPath(id))
	if err != nil {
		t.Fatal(err)
	}
	m, err := dotenv.UnmarshalBytesWithLookup(b, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("compose can't read the .env: %v\n%s", err, b)
	}
	return m
}

func envAudits(a *fakeAudit) []directory.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []directory.AuditEntry
	for _, e := range a.entries {
		if e.Action == "settings.env" {
			out = append(out, e)
		}
	}
	return out
}

func TestEnvRowsSources(t *testing.T) {
	f, _ := envFixture(t)
	rows, err := f.h.EnvRows("envapp")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSortedFunc(rows, func(a, b EnvRow) int { return strings.Compare(a.Name, b.Name) }) {
		t.Error("rows not sorted by name")
	}
	want := map[string]struct {
		source        string
		hubSet, secet bool
		def           string
	}{
		"LOG_LEVEL":           {EnvSourceTemplate, false, false, ""},
		"PHP_MEMORY_LIMIT":    {EnvSourceTemplate, false, false, "512M"},
		"UPLOAD_MAX":          {EnvSourceTemplate, false, false, "10M"},
		"GEN_VALUE":           {EnvSourceTemplate, true, true, settings.SecretShown},
		"CLIENT_VALUE":        {EnvSourceHub, true, true, ""},
		"TRASH_DAYS":          {EnvSourceOption, true, false, "30"},
		"OPT_VALUE":           {EnvSourceOption, true, true, ""},
		"PORTCULLIS_INSTANCE": {EnvSourceHub, true, false, "envapp"},
		"PORTCULLIS_DOMAIN":   {EnvSourceHub, true, false, "example.org"},
	}
	for n, w := range want {
		r := envRowOf(rows, n)
		if r == nil {
			t.Errorf("no row %s", n)
			continue
		}
		if r.Source != w.source || r.HubSet != w.hubSet || r.Secret != w.secet || r.Default != w.def || r.Overridden || r.Value != "" {
			t.Errorf("%s = %+v, want %+v", n, *r, w)
		}
	}
}

func TestEnvOverrideWins(t *testing.T) {
	f, a := envFixture(t)
	before := len(f.runner.Calls())
	res, err := f.h.SetEnvOverride("envapp", "PHP_MEMORY_LIMIT", "1G $HOME #x", envAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if res.Effect != settings.EffectRestart || res.Row == nil || res.Row.Value != "1G $HOME #x" || !res.Row.Overridden || res.Row.Default != "512M" || res.Row.Source != EnvSourceTemplate {
		t.Fatalf("answer = %+v %+v", res, res.Row)
	}
	// Written last, single-quoted: compose reads it literally, and it
	// wins over the template's line.
	if _, err := f.h.SetEnvOverride("envapp", "LOG_LEVEL", "debug", envAdmin); err != nil {
		t.Fatal(err)
	}
	env := composeEnv(t, f, "envapp")
	if env["PHP_MEMORY_LIMIT"] != "1G $HOME #x" || env["LOG_LEVEL"] != "debug" {
		t.Errorf("compose reads %q / %q", env["PHP_MEMORY_LIMIT"], env["LOG_LEVEL"])
	}
	raw := readFile(t, f.h.envPath("envapp"))
	if !strings.HasSuffix(raw, envOverrideMarker+"\nLOG_LEVEL='debug'\nPHP_MEMORY_LIMIT='1G $HOME #x'\n") {
		t.Errorf("the overrides aren't last:\n%s", raw)
	}
	// The readers see the default (the overrides' block isn't theirs).
	if readEnvFile(f.h.envPath("envapp"))["LOG_LEVEL"] != "" {
		t.Error("readEnvFile reads the override")
	}
	// Every .env writer keeps them last: a settings save, an engine
	// write, a restart's refresh, a whole-file generate.
	if _, err := f.h.SaveSettings("envapp", SettingsUpdate{Values: map[string]json.RawMessage{"trash_days": json.RawMessage("7")}}, envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	tpl := f.h.findLocked("envapp")
	if err := f.h.refreshInstanceEnvLocked(tpl, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.generateAppEnvLocked(tpl, nil); err != nil {
		t.Fatal(err)
	}
	if err := setEnvVars(f.h.envPath("envapp"), map[string]string{"NEW_ONE": "x"}, false); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Unlock()
	raw = readFile(t, f.h.envPath("envapp"))
	if !strings.HasSuffix(raw, envOverrideMarker+"\nLOG_LEVEL='debug'\nPHP_MEMORY_LIMIT='1G $HOME #x'\n") || strings.Count(raw, envOverrideMarker) != 1 {
		t.Errorf("after the writers:\n%s", raw)
	}
	if env := composeEnv(t, f, "envapp"); env["TRASH_DAYS"] != "7" || env["LOG_LEVEL"] != "debug" {
		t.Errorf("compose reads %v", env)
	}
	// The enabled instance restarts through the delivery engine.
	deadline := time.Now().Add(5 * time.Second)
	for !slices.ContainsFunc(f.runner.Calls()[before:], func(c string) bool { return strings.HasPrefix(c, "down:portcullis-envapp") }) {
		if time.Now().After(deadline) {
			t.Fatalf("no restart: %v", f.runner.Calls()[before:])
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.h.Wait()
	// The same value again: nothing, not audited.
	n := len(envAudits(a))
	if res, err := f.h.SetEnvOverride("envapp", "LOG_LEVEL", "debug", envAdmin); err != nil || res.Effect != settings.EffectNone {
		t.Errorf("unchanged = %+v %v", res, err)
	}
	got := envAudits(a)
	if len(got) != n {
		t.Errorf("an unchanged value was audited: %+v", got[n:])
	}
	if got[0].Target != "envapp/PHP_MEMORY_LIMIT" || got[0].Detail != "overridden" || got[0].Result != "ok" || got[0].Actor != "admin" {
		t.Errorf("audit = %+v", got[0])
	}
	for _, e := range got {
		if strings.Contains(e.Detail+e.Error, "1G") || strings.Contains(e.Detail+e.Error, "debug") {
			t.Errorf("the audit holds a value: %+v", e)
		}
	}
	// Stored on the state entry, and carried by a backup's instance.yaml.
	f.h.mu.RLock()
	ov := f.h.st.Instances["envapp"].EnvOverrides
	tg, _ := f.h.targetLocked("envapp")
	cfg := f.h.instanceConfigLocked(tg)
	f.h.mu.RUnlock()
	if ov["LOG_LEVEL"] != "debug" || cfg.EnvOverrides["PHP_MEMORY_LIMIT"] != "1G $HOME #x" {
		t.Errorf("stored %v, archived %v", ov, cfg.EnvOverrides)
	}
}

func TestEnvOverrideHubSetRefused(t *testing.T) {
	f, a := envFixture(t)
	path := f.h.envPath("envapp")
	before := readFile(t, path)
	for name, want := range map[string]string{
		"PORTCULLIS_DOMAIN":         "is set by the Hub",
		"PORTCULLIS_HOST_ENVAPP":    "is set by the Hub",
		"PORTCULLIS_AI_PROVIDER_X":  "is set by the Hub",
		"PORTCULLIS_ANYTHING":       "is set by the Hub",
		"COMPOSE_PROFILES":          "is set by the Hub",
		"COMPOSE_PROJECT_NAME":      "is set by the Hub",
		"TRASH_DAYS":                "is set by setting trash_days: change it under Settings",
		"1BAD":                      "invalid variable name",
		"A-B":                       "invalid variable name",
		strings.Repeat("A", 129):    "invalid variable name",
		"PORTCULLIS_LOCAL_NETWORKS": "is set by the Hub",
	} {
		_, err := f.h.SetEnvOverride("envapp", name, "x", envAdmin)
		if statusOf(err) != 400 || !strings.Contains(err.Error(), want) {
			t.Errorf("%s = %v, want 400 %q", name, err, want)
		}
	}
	// Values that can't be single-quoted, masks, too long.
	for _, v := range []string{"a'b", `a\`, "a\nB=2", "a\rb", "a\tb", "a\x00b", "[set]", "[secret]", strings.Repeat("x", 4097), "\xff"} {
		if _, err := f.h.SetEnvOverride("envapp", "LOG_LEVEL", v, envAdmin); statusOf(err) != 400 {
			t.Errorf("value %q = %v, want 400", v, err)
		}
	}
	if got := readFile(t, path); got != before {
		t.Errorf("a refusal changed the .env:\n%s", got)
	}
	f.h.mu.RLock()
	stored := f.h.st.Instances["envapp"].EnvOverrides
	f.h.mu.RUnlock()
	if len(stored) != 0 {
		t.Errorf("a refusal stored %v", stored)
	}
	got := envAudits(a)
	if len(got) == 0 || got[0].Result != "refused" || got[0].Detail != "refused" {
		t.Errorf("refusals audited %+v", got)
	}
	for _, e := range got {
		if e.Result != "refused" {
			t.Errorf("audit %+v", e)
		}
	}
	// An implicit default instance (never created, not enabled): 404.
	if _, err := f.h.SetEnvOverride("grafana", "LOG_LEVEL", "x", envAdmin); statusOf(err) != 404 {
		t.Errorf("implicit default instance = %v", err)
	}
	// No actor: 400.
	if _, err := f.h.SetEnvOverride("envapp", "LOG_LEVEL", "x", directory.Actor{}); statusOf(err) != 400 {
		t.Errorf("no actor = %v", err)
	}
}

func TestEnvOverrideSecretRefused(t *testing.T) {
	f, _ := envFixture(t)
	saveSecret(t, f, "envapp", "api_key", setSecret("opt-VALUE-0123456789"))
	for _, n := range []string{"GEN_VALUE", "CLIENT_VALUE", "OPT_VALUE", "MY_PASSWORD", "SOME_TOKEN", "APP_SECRET"} {
		_, err := f.h.SetEnvOverride("envapp", n, "x", envAdmin)
		if statusOf(err) != 400 || !strings.Contains(err.Error(), "secrets aren't overridden here: use Settings") {
			t.Errorf("%s = %v", n, err)
		}
	}
	// A stored secret's value in a variable the template doesn't declare.
	if _, err := f.h.SetEnvOverride("envapp", "MY_COPY", "opt-VALUE-0123456789", envAdmin); statusOf(err) != 400 {
		t.Errorf("a secret's value = %v", err)
	}
	// Reset is refused alike for an invalid name.
	if _, err := f.h.ClearEnvOverride("envapp", "BAD NAME", envAdmin); statusOf(err) != 400 {
		t.Errorf("reset of an invalid name = %v", err)
	}
}

func TestEnvRowsMaskSecrets(t *testing.T) {
	f, _ := envFixture(t)
	const secret = "opt-VALUE-0123456789"
	saveSecret(t, f, "envapp", "api_key", setSecret(secret))
	// A line an old Expert save left: a stored secret's copy, and a
	// secret-looking name.
	if err := setEnvVars(f.h.envPath("envapp"), map[string]string{"OLD_COPY": secret, "LEGACY_TOKEN": "tok-0123456789", "LEFT_OVER": "plain"}, false); err != nil {
		t.Fatal(err)
	}
	gen := readEnvFile(f.h.envPath("envapp"))["GEN_VALUE"]
	rows, err := f.h.EnvRows("envapp")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"OPT_VALUE", "GEN_VALUE", "OLD_COPY", "LEGACY_TOKEN"} {
		r := envRowOf(rows, n)
		if r == nil || !r.Secret || !r.HubSet || r.Default != settings.SecretShown || r.Value != "" {
			t.Errorf("%s = %+v", n, r)
		}
	}
	if r := envRowOf(rows, "LEFT_OVER"); r == nil || r.Source != EnvSourceCustom || r.Default != "plain" || r.Secret || r.HubSet {
		t.Errorf("LEFT_OVER = %+v", r)
	}
	for _, r := range rows {
		if r.Default == secret || r.Value == secret || r.Default == gen || r.Value == gen {
			t.Errorf("row %s carries a secret: %+v", r.Name, r)
		}
	}
}

func TestEnvReset(t *testing.T) {
	f, a := envFixture(t)
	if _, err := f.h.SetEnvOverride("envapp", "PHP_MEMORY_LIMIT", "1G", envAdmin); err != nil {
		t.Fatal(err)
	}
	res, err := f.h.ClearEnvOverride("envapp", "PHP_MEMORY_LIMIT", envAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if res.Effect != settings.EffectRestart || res.Row == nil || res.Row.Overridden || res.Row.Value != "" || res.Row.Default != "512M" {
		t.Errorf("reset = %+v %+v", res, res.Row)
	}
	raw := readFile(t, f.h.envPath("envapp"))
	if strings.Contains(raw, envOverrideMarker) || strings.Contains(raw, "1G") {
		t.Errorf("the override is still written:\n%s", raw)
	}
	if env := composeEnv(t, f, "envapp"); env["PHP_MEMORY_LIMIT"] != "" {
		t.Errorf("compose reads %q", env["PHP_MEMORY_LIMIT"])
	}
	// Nothing stored: effect none, not audited.
	n := len(envAudits(a))
	if res, err := f.h.ClearEnvOverride("envapp", "PHP_MEMORY_LIMIT", envAdmin); err != nil || res.Effect != settings.EffectNone {
		t.Errorf("second reset = %+v %v", res, err)
	}
	got := envAudits(a)
	if len(got) != n || got[n-1].Detail != "reset" || got[n-1].Target != "envapp/PHP_MEMORY_LIMIT" {
		t.Errorf("audits %+v", got)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["envapp"]
	f.h.mu.RUnlock()
	if e.EnvOverrides != nil {
		t.Errorf("stored %v", e.EnvOverrides)
	}
}

func TestEnvAddOwnVariable(t *testing.T) {
	f, a := envFixture(t)
	res, err := f.h.SetEnvOverride("envapp", "MY_FLAG", "on", envAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if res.Row == nil || res.Row.Source != EnvSourceCustom || res.Row.Value != "on" || !res.Row.Overridden || res.Row.Default != "" || res.Row.HubSet {
		t.Errorf("added = %+v", res.Row)
	}
	if env := composeEnv(t, f, "envapp"); env["MY_FLAG"] != "on" {
		t.Errorf("compose reads %q", env["MY_FLAG"])
	}
	// A disabled instance: stored, no restart.
	if err := f.h.Disable("envapp"); err != nil {
		t.Fatal(err)
	}
	if res, err := f.h.SetEnvOverride("envapp", "MY_FLAG", "off", envAdmin); err != nil || res.Effect != settings.EffectNone {
		t.Errorf("disabled = %+v %v", res, err)
	}
	// Removed by a reset: no row left.
	res, err = f.h.ClearEnvOverride("envapp", "MY_FLAG", envAdmin)
	if err != nil || res.Row != nil {
		t.Errorf("reset of an added variable = %+v %v", res, err)
	}
	got := envAudits(a)
	details := []string{}
	for _, e := range got {
		details = append(details, e.Detail)
	}
	if strings.Join(details, ",") != "added,overridden,reset" {
		t.Errorf("audit details %v", details)
	}
}

// A stored override the template now refuses is skipped at every write
// (warning, the panel's env:values unit), removed at the prune after a
// source sync (audited dropped), and dropped by a restore.
func TestEnvOverrideRecheckedOnWrite(t *testing.T) {
	f, a := envFixture(t)
	if _, err := f.h.SetEnvOverride("envapp", "SITE_NAME", "Team A", envAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetEnvOverride("envapp", "LOG_LEVEL", "debug", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	// The template now generates SITE_NAME (a secret).
	m := strings.Replace(envAppManifest, "  - key: LOG_LEVEL\n", "  - key: LOG_LEVEL\n  - key: SITE_NAME\n    generate: random\n", 1)
	writeFile(t, f.src+"/envapp/manifest.yaml", m)
	f.h.Discover()
	f.h.mu.Lock()
	tpl := f.h.findLocked("envapp")
	if err := f.h.writeOptionEnvLocked(tpl, nil); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Unlock()
	raw := readFile(t, f.h.envPath("envapp"))
	if strings.Contains(raw, "Team A") || !strings.Contains(raw, "LOG_LEVEL='debug'") {
		t.Errorf("the refused override is written (or the allowed one isn't):\n%s", raw)
	}
	if d := f.h.envOverrideDrops("envapp"); len(d) != 1 || !strings.HasPrefix(d[0], "env override SITE_NAME dropped: ") {
		t.Errorf("drops = %v", d)
	}
	if u, ok := f.h.envProblemsUnit("envapp"); !ok || !strings.Contains(u.Error, "env override SITE_NAME dropped") {
		t.Errorf("panel unit = %+v %v", u, ok)
	}
	// The prune removes it and audits it.
	f.h.pruneSettings()
	f.h.mu.RLock()
	ov := f.h.st.Instances["envapp"].EnvOverrides
	f.h.mu.RUnlock()
	if _, still := ov["SITE_NAME"]; still || ov["LOG_LEVEL"] != "debug" {
		t.Errorf("after the prune %v", ov)
	}
	last := envAudits(a)[len(envAudits(a))-1]
	if last.Target != "envapp/SITE_NAME" || last.Detail != "dropped" || last.Actor != purgeActor {
		t.Errorf("prune audit %+v", last)
	}
	// A restore checks the archive's overrides against the template.
	f.h.mu.Lock()
	tg, _ := f.h.targetLocked("envapp")
	cfg := f.h.instanceConfigLocked(tg)
	cfg.EnvOverrides = map[string]string{"SITE_NAME": "x", "LOG_LEVEL": "info", "PORTCULLIS_INSTANCE": "evil"}
	f.h.applyConfigLocked("envapp", cfg)
	w := f.h.restoredEnvOverridesLocked(f.h.findLocked("envapp"))
	ov = f.h.st.Instances["envapp"].EnvOverrides
	f.h.mu.Unlock()
	if len(w) != 2 || !strings.HasPrefix(w[0], "env override PORTCULLIS_INSTANCE dropped: ") || !strings.HasPrefix(w[1], "env override SITE_NAME dropped: ") {
		t.Errorf("restore warnings %v", w)
	}
	if len(ov) != 1 || ov["LOG_LEVEL"] != "info" {
		t.Errorf("restored %v", ov)
	}
}

// The compose defaults parser.
func TestComposeEnvDefaults(t *testing.T) {
	d := composeEnvDefaults("a: ${A:-x y}\nb: ${B-}\nc: ${C}\nd: $${D:-no}\ne: ${E:-${F}}\ng: ${G:?err}\n")
	if d["A"] != (composeDefault{"x y", true, true}) || d["B"] != (composeDefault{"", false, true}) || d["C"].hasDefault || d["G"].hasDefault {
		t.Errorf("defaults %+v", d)
	}
	if _, ok := d["D"]; ok {
		t.Errorf("$$ read as a reference: %+v", d)
	}
	if d["E"].text != "${F}" {
		t.Errorf("nested default %+v", d["E"])
	}
}

// envView is instance id's env rows as name → default (secrets masked):
// the view the old Expert Env showed.
func envView(h *Hub, id string) (map[string]string, error) {
	rows, err := h.EnvRows(id)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Name] = r.Default
	}
	return out, nil
}

// plantEnv writes raw lines into id's .env (what an old Expert save or a
// template update left behind).
func plantEnv(t *testing.T, h *Hub, id string, vars map[string]string) {
	t.Helper()
	if err := setEnvVars(h.envPath(id), vars, false); err != nil {
		t.Fatal(err)
	}
}

// envOverrideErr is SetEnvOverride's error (as the admin).
func envOverrideErr(h *Hub, id, name, value string) error {
	_, err := h.SetEnvOverride(id, name, value, envAdmin)
	return err
}

// Backups carry the overrides in config/instance.yaml; a restore into a
// new id copies them (written last into its .env), a same-instance
// restore puts the archived ones back.
func TestEnvOverridesTravelWithBackups(t *testing.T) {
	f, _, _ := grafanaB(t)
	if _, err := f.h.SetEnvOverride("grafana-b", "GF_LOG_LEVEL", "debug", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	waitIdle(t, f, "grafana-b")
	entry, err := f.h.BackupInstance("grafana-b", envAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	if !strings.Contains(string(data["config/instance.yaml"]), "env_overrides:\n    GF_LOG_LEVEL: debug") {
		t.Errorf("instance.yaml:\n%s", data["config/instance.yaml"])
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", envAdmin); err != nil {
		t.Fatal(err)
	}
	if r := rowOf(t, f, "grafana-c", "GF_LOG_LEVEL"); r == nil || r.Value != "debug" || !r.Overridden {
		t.Errorf("restore-as row %+v", r)
	}
	if env := composeEnv(t, f, "grafana-c"); env["GF_LOG_LEVEL"] != "debug" {
		t.Errorf("restore-as .env reads %q", env["GF_LOG_LEVEL"])
	}
	// Changed after the backup, then restored: the archive's again.
	if _, err := f.h.ClearEnvOverride("grafana-b", "GF_LOG_LEVEL", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	waitIdle(t, f, "grafana-b")
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, envAdmin); err != nil {
		t.Fatal(err)
	}
	if r := rowOf(t, f, "grafana-b", "GF_LOG_LEVEL"); r == nil || r.Value != "debug" {
		t.Errorf("same-instance restore row %+v", r)
	}
}

// Fix round 1, item 1: an override whose value later equals a set
// secret is never shown (its row is a secret's) and no longer written.
func TestEnvRowsNeverShowSecretOverride(t *testing.T) {
	f, _ := envFixture(t)
	const val = "opt-VALUE-0123456789"
	if _, err := f.h.SetEnvOverride("envapp", "MY_COPY", val, envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	saveSecret(t, f, "envapp", "api_key", setSecret(val))
	f.h.Wait()
	rows, err := f.h.EnvRows("envapp")
	if err != nil {
		t.Fatal(err)
	}
	r := envRowOf(rows, "MY_COPY")
	if r == nil || !r.Secret || r.Value != "" || !r.HubSet || !r.Overridden {
		t.Errorf("MY_COPY = %+v", r)
	}
	for _, r := range rows {
		if r.Value == val || r.Default == val {
			t.Errorf("row %s carries the secret", r.Name)
		}
	}
	if raw := readFile(t, f.h.envPath("envapp")); strings.Contains(raw, "MY_COPY='") {
		t.Errorf("the override equal to a secret is still written:\n%s", raw)
	}
}

// Fix round 1, item 1: a restore-as archive whose override equals one of
// its secrets: checked after the secrets are copied, so it is dropped.
func TestEnvRestoreAsDropsSecretOverride(t *testing.T) {
	f, _ := envFixture(t)
	const val = "opt-VALUE-0123456789"
	saveSecret(t, f, "envapp", "api_key", setSecret(val))
	f.h.Wait()
	waitIdle(t, f, "envapp")
	if _, err := f.h.SetEnvOverride("envapp", "MY_FLAG", "on", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	waitIdle(t, f, "envapp")
	entry, err := f.h.BackupInstance("envapp", envAdmin)
	if err != nil {
		t.Fatal(err)
	}
	p := archivePath(f, entry.Archive)
	_, data, _ := readArchive(t, p)
	cfg := strings.Replace(string(data["config/instance.yaml"]), "env_overrides:\n", "env_overrides:\n    MY_COPY: "+val+"\n", 1)
	if cfg == string(data["config/instance.yaml"]) {
		t.Fatalf("instance.yaml has no env_overrides:\n%s", cfg)
	}
	rewriteMember(t, p, "config/instance.yaml", []byte(cfg))
	res, err := f.h.RestoreInstanceAs(entry.Archive, "envapp-c", envAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.HasPrefix(w, "env override MY_COPY dropped: ") }) {
		t.Errorf("warnings %v", res.Warnings)
	}
	f.h.mu.RLock()
	ov := f.h.st.Instances["envapp-c"].EnvOverrides
	f.h.mu.RUnlock()
	if _, kept := ov["MY_COPY"]; kept || ov["MY_FLAG"] != "on" {
		t.Errorf("restored overrides %v", ov)
	}
	if raw := readFile(t, f.h.envPath("envapp-c")); strings.Contains(raw, "MY_COPY") {
		t.Errorf("the copy's .env holds it:\n%s", raw)
	}
}

// Fix round 1, item 2: a short value is never judged a secret's by
// value (as the redactor's), so it is no oracle and not refused.
func TestEnvShortValueNotJudgedSecret(t *testing.T) {
	f, _ := envFixture(t)
	saveSecret(t, f, "envapp", "api_key", setSecret("true"))
	f.h.Wait()
	waitIdle(t, f, "envapp")
	if _, err := f.h.SetEnvOverride("envapp", "MY_FLAG", "true", envAdmin); err != nil {
		t.Errorf("a short value equal to a secret = %v", err)
	}
	saveSecret(t, f, "envapp", "api_key", setSecret("sixsix"))
	f.h.Wait()
	waitIdle(t, f, "envapp")
	if _, err := f.h.SetEnvOverride("envapp", "MY_OTHER", "sixsix", envAdmin); statusOf(err) != 400 {
		t.Errorf("a six-byte secret's value = %v, want 400", err)
	}
}

// Fix round 1, item 4: resetting the last override of a default
// instance's entry that holds nothing else removes the entry.
func TestEnvResetDropsEmptyEntry(t *testing.T) {
	f, _ := envFixture(t)
	f.h.mu.RLock()
	_, had := f.h.st.Instances["envapp"]
	f.h.mu.RUnlock()
	if had {
		t.Skip("the enabled default instance already has an entry")
	}
	if _, err := f.h.SetEnvOverride("envapp", "MY_FLAG", "on", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	_, has := f.h.st.Instances["envapp"]
	f.h.mu.RUnlock()
	if !has {
		t.Fatal("no entry holds the override")
	}
	if _, err := f.h.ClearEnvOverride("envapp", "MY_FLAG", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	e, still := f.h.st.Instances["envapp"]
	f.h.mu.RUnlock()
	if still {
		t.Errorf("the empty entry stays: %+v", e)
	}
	// A labelled entry is kept.
	f.h.mu.Lock()
	f.h.st.Instances["envapp"] = state.Instance{ID: "envapp", Template: "envapp", Label: "Mine"}
	f.h.mu.Unlock()
	if _, err := f.h.SetEnvOverride("envapp", "MY_FLAG", "on", envAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.ClearEnvOverride("envapp", "MY_FLAG", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	e, still = f.h.st.Instances["envapp"]
	f.h.mu.RUnlock()
	if !still || e.Label != "Mine" || e.EnvOverrides != nil {
		t.Errorf("the labelled entry = %+v %v", e, still)
	}
}

// mountAppCompose references variables in environment: only
// (LOG_LEVEL), in environment: and volumes (BOTH_VAR) and outside it
// (labels, image, privileged, a volume source; user: and a top-level
// secrets: block — whose variables Discover limits anyway — are
// TestComposeVars').
const mountAppCompose = "services:\n  web:\n    image: \"x:${IMAGE_TAG:-1}\"\n    privileged: ${PRIV:-false}\n" +
	"    volumes:\n      - ${DATA_DIR:-./data}:/data\n      - \"${BOTH_VAR:-./both}:/both\"\n" +
	"    environment:\n      L: ${LOG_LEVEL}\n      B: ${BOTH_VAR}\n" +
	"    labels:\n      com.example.note: \"${NOTE_LABEL:-x}\"\n      traefik.http.routers.mountapp.rule: Host(`mountapp.${PORTCULLIS_DOMAIN}`)\n"

const mountAppManifest = `name: Mount App
category: misc
ai: {unsupported: "test fixture"}
auth:
  method: native-oidc
  sso: false
  group_access: false
  access_group: users_mountapp
env:
  - key: LOG_LEVEL
`

// Security fix (allowlist): only a variable compose references nowhere
// but in environment: values, or not at all, may be overridden;
// DOCKER_* is Hub-set. The rows say so (hub_set).
func TestEnvOverrideOutsideEnvironmentRefused(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"mountapp": {mountAppManifest, mountAppCompose}})
	tpl := f.h.Template("mountapp")
	if tpl == nil {
		t.Fatal("mountapp not loaded (see the log)")
	}
	if cv := tpl.ComposeVars; cv == nil || !cv.EnvOnly["LOG_LEVEL"] || cv.EnvOnly["BOTH_VAR"] || !cv.Outside["BOTH_VAR"] {
		t.Errorf("ComposeVars = %+v", cv)
	}
	const outside = "is used outside environment: in the template's compose file; change it through Settings or the custom compose override"
	for name, want := range map[string]string{
		"NOTE_LABEL":  outside,
		"IMAGE_TAG":   outside,
		"PRIV":        outside,
		"DATA_DIR":    outside,
		"BOTH_VAR":    outside,
		"DOCKER_HOST": "is set by the Hub",
	} {
		if err := envOverrideErr(f.h, "mountapp", name, "x"); statusOf(err) != 400 || !strings.Contains(err.Error(), want) {
			t.Errorf("%s = %v", name, err)
		}
	}
	// Environment-only and unreferenced variables pass the rules (the
	// instance itself was never started: 404 after the checks).
	for _, name := range []string{"LOG_LEVEL", "MY_OWN_VAR"} {
		if err := envOverrideErr(f.h, "mountapp", name, "x"); statusOf(err) != 404 {
			t.Errorf("%s = %v, want the rules passed (404: not created)", name, err)
		}
	}
	rows, err := f.h.EnvRows("mountapp")
	if err != nil {
		t.Fatal(err)
	}
	if r := envRowOf(rows, "DATA_DIR"); r == nil || !r.HubSet || r.Default != "./data" {
		t.Errorf("DATA_DIR row %+v", r)
	}
	if r := envRowOf(rows, "LOG_LEVEL"); r == nil || r.HubSet {
		t.Errorf("LOG_LEVEL row %+v", r)
	}
	// A view whose compose can't be checked refuses every override.
	rules := &envRules{t: tpl, composeVars: &templates.ComposeVarUse{Err: "compose.yml: broken"}, masked: func(string, string) bool { return false }}
	if why := rules.nameRefusal("MY_OWN_VAR"); !strings.Contains(why, "can't be checked") {
		t.Errorf("unparsable compose = %q", why)
	}
	// A view without discovery data whose compose.yml can't be read:
	// every override refused too.
	c := *tpl
	c.ComposeVars, c.Path = nil, filepath.Join(t.TempDir(), "gone")
	fr, err := f.h.envRulesFor(&c)
	if err != nil {
		t.Fatal(err)
	}
	if why := fr.nameRefusal("MY_OWN_VAR"); !strings.Contains(why, "can't be checked") {
		t.Errorf("unreadable compose = %q", why)
	}
}

// Fix round 1, item 7: ports, <KEY>_BIND, a gid_env join variable, a
// person-entered and a group-scope env delivery are refused.
func TestEnvOverrideOwnedVariablesRefused(t *testing.T) {
	check := func(h *Hub, id, name, want string) {
		t.Helper()
		if err := envOverrideErr(h, id, name, "1"); statusOf(err) != 400 || !strings.Contains(err.Error(), want) {
			t.Errorf("%s/%s = %v, want 400 %q", id, name, err, want)
		}
	}
	smb := smbFixture(t)
	check(smb.h, smbID, "SMB", "is set by setting SMB: change it under Settings")
	check(smb.h, smbID, "SMB_BIND", "is set by setting SMB: change it under Settings")
	jf, _ := jellyfinFixture(t)
	check(jf.h, "jellyfin", "PGID", "is set by setting library: change it under Settings")
	pf, _, _ := privFixture(t)
	check(pf.h, "privapp", "PRIVAPP_LIBRARIES", "is set by setting")
	ef, _, _, _ := entryFixture(t)
	check(ef.h, entryEnv, "EXT_IDS", "is set by setting ext_id: change it under Settings")
}

// Fix round 1, item 7: a skipped override lands in the running
// operation's record (a restart's).
func TestEnvOverrideDropInOpRecord(t *testing.T) {
	f, _ := envFixture(t)
	if _, err := f.h.SetEnvOverride("envapp", "SITE_NAME", "Team A", envAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	waitIdle(t, f, "envapp")
	m := strings.Replace(envAppManifest, "  - key: LOG_LEVEL\n", "  - key: LOG_LEVEL\n  - key: SITE_NAME\n    generate: random\n", 1)
	writeFile(t, f.src+"/envapp/manifest.yaml", m)
	f.h.Discover()
	if err := f.h.RestartApp("envapp"); err != nil {
		t.Fatal(err)
	}
	r := f.h.LastOp("envapp")
	if r == nil || !slices.ContainsFunc(r.Warnings, func(w string) bool { return strings.HasPrefix(w, "env override SITE_NAME dropped: ") }) {
		t.Errorf("op record %+v", r)
	}
}
