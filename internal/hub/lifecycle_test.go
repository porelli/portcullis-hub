package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

func readPolicy(t *testing.T, f *fixture) policy.Document {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.data, "group-gate-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc policy.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func statusOf(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

func TestInitWritesPolicy(t *testing.T) {
	f := newFixture(t)
	doc := readPolicy(t, f)
	if doc.Version != policy.FileVersion || len(doc.Groups) != 0 || len(doc.PathGroups) != 0 {
		t.Errorf("initial policy = %+v", doc)
	}
	if n := len(f.h.Templates()); n != 2 {
		t.Errorf("templates = %d", n)
	}
}

func TestEnable(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if got := f.runner.Calls(); len(got) != 1 || got[0] != "up:portcullis-grafana" {
		t.Fatalf("calls = %v", got)
	}
	p := f.runner.projects[0]
	if p.ProjectDir != "/host/project" || p.EnvFile != filepath.Join(f.data, "env", "grafana.env") ||
		len(p.Files) != 2 || p.Files[0] != filepath.Join(f.src, "grafana", "compose.yml") || p.Files[1] != filepath.Join(f.data, "overrides", "grafana.override.yml") {
		t.Errorf("project = %+v", p)
	}

	// Env: domain, generated secret, core var referenced by compose only.
	envPath := filepath.Join(f.data, "env", "grafana.env")
	env := readEnvFile(envPath)
	if env["PORTCULLIS_DOMAIN"] != "example.org" || env["CORE_VAR"] != "core-value" {
		t.Errorf("env = %v", env)
	}
	if _, leaked := env["UNUSED"]; leaked {
		t.Error("unreferenced core var copied")
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(env["GF_SECRET"]) {
		t.Errorf("generated secret = %q", env["GF_SECRET"])
	}
	if fi, _ := os.Stat(envPath); fi.Mode().Perm() != 0600 {
		t.Errorf("env mode = %v", fi.Mode().Perm())
	}

	// Override: port binding + TLS tier label.
	ov, _ := os.ReadFile(filepath.Join(f.data, "overrides", "grafana.override.yml"))
	if !strings.Contains(string(ov), `"0.0.0.0:3300:3000/tcp"`) || !strings.Contains(string(ov), "traefik.http.routers.grafana.tls.options: authaware@file") {
		t.Errorf("override =\n%s", ov)
	}

	// Template files published for host bind mounts.
	if _, err := os.Stat(filepath.Join(f.project, "templates", "grafana", "conf", "grafana.ini")); err != nil {
		t.Errorf("template files not synced: %v", err)
	}

	// State persisted.
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil || !st.IsEnabled("grafana") {
		t.Errorf("state = %+v, %v", st, err)
	}

	// Policy file: groups + path_groups for the routed subdomain.
	doc := readPolicy(t, f)
	if doc.Groups["grafana"] != "users_grafana" {
		t.Errorf("groups = %v", doc.Groups)
	}
	pg := doc.PathGroups["grafana"]
	if len(pg) != 2 || pg[0] != (policy.PathGroup{Prefix: "/admin", Group: "admin_grafana"}) || pg[1].Prefix != "/api/admin" {
		t.Errorf("path_groups = %+v", doc.PathGroups)
	}

	// Enabling again is a no-op.
	if err := f.h.Enable("grafana"); err != nil || len(f.runner.Calls()) != 1 {
		t.Errorf("re-enable: %v, calls %v", err, f.runner.Calls())
	}
}

func TestEnableRegistersClients(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Enable("other"); err != nil {
		t.Fatal(err)
	}
	secret := readEnvFile(filepath.Join(f.data, "env", "other.env"))["OTHER_SECRET"]
	if len(f.idp.registered) != 1 || f.idp.registered[0] != "other:other:hwk:"+secret+":other.example.org" || secret == "" {
		t.Errorf("registered = %v (secret %q)", f.idp.registered, secret)
	}
	// email_verified_claim: false reaches Keycloak as OmitEmailVerified.
	if len(f.idp.specs) != 1 || !f.idp.specs[0].OmitEmailVerified {
		t.Errorf("specs = %+v, want OmitEmailVerified", f.idp.specs)
	}
}

func TestEnableClientConflict(t *testing.T) {
	f := newFixture(t)
	f.idp.registerErr = &keycloak.ConflictError{ClientID: "other", TemplateID: "other", Owner: "someone"}
	err := f.h.Enable("other")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), `client "other"`) {
		t.Fatalf("err = %v", err)
	}
	if f.h.IsEnabled("other") || len(f.runner.Calls()) != 0 {
		t.Errorf("app started despite the conflict: %v", f.runner.Calls())
	}
	// Other Keycloak errors (e.g. outage) still only warn.
	f.idp.registerErr = errors.New("connection refused")
	if err := f.h.Enable("other"); err != nil {
		t.Errorf("transient keycloak error blocked enable: %v", err)
	}
}

func TestEnableUnknown(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Enable("nope"); statusOf(err) != 400 {
		t.Errorf("err = %v", err)
	}
}

func TestEnableComposeFailureNotRecorded(t *testing.T) {
	f := newFixture(t)
	f.runner.upErr = errors.New("pull failed")
	if err := f.h.Enable("grafana"); err == nil {
		t.Fatal("expected error")
	}
	if f.h.IsEnabled("grafana") {
		t.Error("app recorded as enabled after failed compose up")
	}
	if doc := readPolicy(t, f); len(doc.Groups) != 0 {
		t.Errorf("groups published for failed app: %v", doc.Groups)
	}
}

func TestEnablePreservesEnv(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.data, "env", "grafana.env"), "GF_SECRET=keepme\nCUSTOM=1\n")
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	env := readEnvFile(filepath.Join(f.data, "env", "grafana.env"))
	if env["GF_SECRET"] != "keepme" || env["CUSTOM"] != "1" {
		t.Errorf("env = %v", env)
	}
}

func TestPortCollision(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	err := f.h.Enable("other")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "3300/tcp") {
		t.Fatalf("err = %v", err)
	}
	// Rebinding to a specific IP still overlaps 0.0.0.0; another port is fine.
	if err := f.h.SaveSettings("other", SettingsUpdate{Values: map[string]string{"OTHER_PORT": "3300", "OTHER_PORT_BIND": "127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("other"); statusOf(err) != 409 {
		t.Errorf("err = %v", err)
	}
	if err := f.h.SaveSettings("other", SettingsUpdate{Values: map[string]string{"OTHER_PORT": "3301"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("other"); err != nil {
		t.Errorf("err = %v", err)
	}
	// Changing an enabled app onto a claimed port is refused and rolled back.
	err = f.h.SaveSettings("other", SettingsUpdate{Values: map[string]string{"OTHER_PORT": "3300"}})
	if statusOf(err) != 409 {
		t.Errorf("err = %v", err)
	}
	if v, _ := f.h.AppSettings("other"); v.Values["OTHER_PORT"] != "3301" {
		t.Errorf("settings not rolled back: %v", v.Values)
	}
}

func TestDisable(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Disable("grafana"); statusOf(err) != 400 {
		t.Errorf("disable of disabled app: %v", err)
	}
	f.h.Enable("grafana")
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	if f.h.IsEnabled("grafana") {
		t.Error("still enabled")
	}
	if c := f.runner.Calls(); c[len(c)-1] != "down:portcullis-grafana" {
		t.Errorf("calls = %v", c)
	}
	if doc := readPolicy(t, f); len(doc.Groups) != 0 || len(doc.PathGroups) != 0 {
		t.Errorf("disabled app still published: %+v", doc)
	}
}

func TestDisableFallbacks(t *testing.T) {
	f := newFixture(t)
	f.h.Enable("grafana")
	f.runner.downErr = errors.New("broken compose")
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	c := f.runner.Calls()
	if c[len(c)-2] != "down:portcullis-grafana" || c[len(c)-1] != "downbyname:portcullis-grafana" {
		t.Errorf("calls = %v", c)
	}

	// Both fail → app stays enabled so the user can retry.
	f.runner.downErr = nil
	f.h.Enable("grafana")
	f.runner.downErr = errors.New("x")
	f.runner.byNameErr = errors.New("daemon down")
	if err := f.h.Disable("grafana"); err == nil || !f.h.IsEnabled("grafana") {
		t.Errorf("err = %v, enabled = %v", err, f.h.IsEnabled("grafana"))
	}
}

func TestDisableMissingTemplate(t *testing.T) {
	f := newFixture(t)
	f.h.Enable("grafana")
	os.RemoveAll(filepath.Join(f.src, "grafana"))
	f.h.Discover()
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	if c := f.runner.Calls(); c[len(c)-1] != "downbyname:portcullis-grafana" {
		t.Errorf("calls = %v", c)
	}
}

func TestLockBusy(t *testing.T) {
	f := newFixture(t)
	f.runner.gate = make(chan struct{})
	f.runner.entered = make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- f.h.Enable("grafana") }()
	<-f.runner.entered

	var busy ErrBusy
	if err := f.h.Enable("grafana"); !errors.As(err, &busy) {
		t.Errorf("concurrent enable: %v", err)
	}
	if err := f.h.Disable("grafana"); !errors.As(err, &busy) {
		t.Errorf("concurrent disable: %v", err)
	}
	if err := f.h.ResolveDrift("grafana", ActionStop); !errors.As(err, &busy) {
		t.Errorf("concurrent drift stop: %v", err)
	}
	// Other apps are not blocked.
	f.runner.entered = nil
	otherDone := make(chan error, 1)
	go func() { otherDone <- f.h.Enable("other") }()

	close(f.runner.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-otherDone // collides on port 3300 or succeeds — either way it ran
	if !f.h.IsEnabled("grafana") {
		t.Error("not enabled")
	}
}

func TestRestartWaitsForLock(t *testing.T) {
	f := newFixture(t)
	f.h.Enable("grafana")
	tmpl := *f.h.Template("grafana")

	unlock, err := f.h.lockApp("grafana")
	if err != nil {
		t.Fatal(err)
	}
	restarted := make(chan struct{})
	go func() { f.h.Restart(tmpl); close(restarted) }()
	time.Sleep(50 * time.Millisecond)
	before := len(f.runner.Calls())
	if before != 1 {
		t.Fatalf("restart ran while locked: %v", f.runner.Calls())
	}
	unlock()
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("restart never ran")
	}
	c := f.runner.Calls()
	if len(c) != 3 || c[1] != "down:portcullis-grafana" || c[2] != "up:portcullis-grafana" {
		t.Errorf("calls = %v", c)
	}

	// A restart queued for an app that gets disabled meanwhile is dropped.
	f.h.Disable("grafana")
	n := len(f.runner.Calls())
	f.h.Restart(tmpl)
	if len(f.runner.Calls()) != n {
		t.Errorf("restart of disabled app ran: %v", f.runner.Calls()[n:])
	}
	if err := f.h.RestartApp("grafana"); statusOf(err) != 400 {
		t.Errorf("RestartApp(disabled) = %v", err)
	}
	if err := f.h.RestartApp("nope"); statusOf(err) != http.StatusNotFound {
		t.Errorf("RestartApp(unknown) = %v", err)
	}
}

// TestConcurrentLifecycle hammers enable/disable/restart/settings on two
// apps from many goroutines: compose must never run two operations on the
// same project at once (and -race must stay quiet).
func TestConcurrentLifecycle(t *testing.T) {
	f := newFixture(t)
	f.runner.delay = time.Millisecond
	// Avoid the port collision so both apps can be enabled.
	f.h.SaveSettings("other", SettingsUpdate{Values: map[string]string{"OTHER_PORT": "3301"}})
	ids := []string{"grafana", "other"}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for i := 0; i < 25; i++ {
				id := ids[r.Intn(len(ids))]
				switch r.Intn(5) {
				case 0, 1:
					f.h.Enable(id)
				case 2:
					f.h.Disable(id)
				case 3:
					if t := f.h.Template(id); t != nil && t.Enabled {
						f.h.Restart(*t)
					}
				case 4:
					f.h.Reconcile(t.Context())
					f.h.Templates()
					f.h.WritePolicy()
				}
			}
		}(int64(g))
	}
	wg.Wait()
	if o := f.runner.Overlaps(); len(o) > 0 {
		t.Errorf("overlapping compose operations: %v", o)
	}
	// State and catalog agree.
	for _, id := range ids {
		if f.h.IsEnabled(id) != f.h.Template(id).Enabled {
			t.Errorf("%s: state and catalog disagree", id)
		}
	}
}

func TestNewCorruptState(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "state.yaml"), "enabled: [oops\n")
	if _, err := New(Config{ProjectDir: dir, DataDir: dir}, newFakeRunner(), nil, nil); err == nil {
		t.Fatal("corrupt state accepted")
	}
	writeFile(t, filepath.Join(dir, "state.yaml"), "")
	if _, err := New(Config{ProjectDir: dir, DataDir: dir}, newFakeRunner(), nil, nil); err == nil {
		t.Fatal("empty state accepted")
	}
}

func TestConfigFilesConfined(t *testing.T) {
	f := newFixture(t)
	tmpl := *f.h.Template("grafana")
	tmpl.Manifest.ConfigFiles = nil
	for _, cf := range [][2]string{
		{"conf/grafana.ini", "config/grafana/grafana.ini"}, // allowed
		{"conf/grafana.ini", ".env"},                       // top-level core file
		{"conf/grafana.ini", "docker-compose.yml"},
		{"conf/grafana.ini", "../escape.ini"},
		{"../../etc/passwd", "config/passwd"},
	} {
		tmpl.Manifest.ConfigFiles = append(tmpl.Manifest.ConfigFiles, templates.ConfigFile{Src: cf[0], Dest: cf[1]})
	}
	f.h.copyConfigFiles(&tmpl)
	if _, err := os.Stat(filepath.Join(f.project, "config", "grafana", "grafana.ini")); err != nil {
		t.Errorf("allowed copy missing: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(f.project, ".env")); !strings.HasPrefix(string(b), "CORE_VAR=") {
		t.Errorf("core .env overwritten: %q", b)
	}
	for _, p := range []string{filepath.Join(f.project, "docker-compose.yml"), filepath.Join(filepath.Dir(f.project), "escape.ini"), filepath.Join(f.project, "config", "passwd")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s written", p)
		}
	}
}

func TestSaveSettingsValidation(t *testing.T) {
	f := newFixture(t)
	bad := []map[string]string{
		{"bad-key": "x"},
		{"GF_THEME": "dark\nEVIL=1"},
		{"MEDIA": "/a:/etc"},
		{"GRAFANA_PORT": "70000"},
		{"GRAFANA_PORT": "abc"},
		{"GRAFANA_PORT_BIND": "localhost"},
	}
	for _, v := range bad {
		if err := f.h.SaveSettings("grafana", SettingsUpdate{Values: v}); statusOf(err) != 400 {
			t.Errorf("SaveSettings(%v) = %v, want 400", v, err)
		}
	}
	if err := f.h.SaveSettings("nope", SettingsUpdate{}); statusOf(err) != 404 {
		t.Errorf("unknown app: %v", err)
	}

	err := f.h.SaveSettings("grafana", SettingsUpdate{
		Values: map[string]string{"GF_THEME": "light", "MEDIA": "/mnt/My Media", "GRAFANA_PORT": ""},
		Policy: &policy.AuthPolicy{Factors: []string{"WEBAUTHN", "mtls"}, Op: "all"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := f.h.AppSettings("grafana")
	if v.AuthPolicy == nil || strings.Join(v.AuthPolicy.Factors, ",") != "mtls,webauthn" || v.AuthPolicy.Op != "all" || v.SafetyScore != 3.5 {
		t.Errorf("policy = %+v score %v", v.AuthPolicy, v.SafetyScore)
	}
	if env := readEnvFile(filepath.Join(f.data, "env", "grafana.env")); env["GF_THEME"] != "light" {
		t.Errorf("select setting not written to env: %v", env)
	}
	ov, _ := os.ReadFile(filepath.Join(f.data, "overrides", "grafana.override.yml"))
	if !strings.Contains(string(ov), `- "/mnt/My Media:/media"`) || strings.Contains(string(ov), "3300") ||
		!strings.Contains(string(ov), "tls.options: protected@file") {
		t.Errorf("override =\n%s", ov)
	}
	// Not enabled: nothing is published (group-gate keys by subdomain).
	if doc := readPolicy(t, f); len(doc.Policies) != 0 {
		t.Errorf("policy file = %+v", doc.Policies)
	}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	doc := readPolicy(t, f)
	if p := doc.Policies["grafana"]; p.Op != "all" || len(doc.Policies) != 1 {
		t.Errorf("policy file = %+v", doc.Policies)
	}
	// Inherit drops the override.
	if err := f.h.SaveSettings("grafana", SettingsUpdate{Values: map[string]string{}, Inherit: true}); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.h.AppSettings("grafana"); v.AuthPolicy != nil {
		t.Errorf("override not dropped: %+v", v.AuthPolicy)
	}
	if _, ok := readPolicy(t, f).Policies["grafana"]; ok {
		t.Error("policy file still has the override")
	}
}

func TestSubdomainCollision(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.src, "clash", "manifest.yaml"), "name: Clash\nauth:\n  method: forward-auth\n")
	writeFile(t, filepath.Join(f.src, "clash", "compose.yml"), "services:\n  c:\n    labels:\n      traefik.http.routers.c.rule: Host(`GRAFANA.${PORTCULLIS_DOMAIN}`) && PathPrefix(`/x`)\n")
	f.h.Discover()
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	err := f.h.Enable("clash")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "grafana.example.org") {
		t.Errorf("err = %v", err)
	}
	// A template update can't introduce a collision either.
	writeFile(t, filepath.Join(f.src, "other", "compose.yml"), "services:\n  web:\n    labels:\n      traefik.http.routers.o.rule: Host(`grafana.${PORTCULLIS_DOMAIN}`)\n")
	f.h.Discover()
	if err := f.h.Enable("other"); statusOf(err) != 409 {
		t.Errorf("enable after edit: %v", err)
	}
}

func TestRoutingValidation(t *testing.T) {
	f := newFixture(t)
	// Templates routing core subdomains or unresolvable hosts are skipped.
	writeFile(t, filepath.Join(f.src, "evil", "manifest.yaml"), "name: Evil\n")
	writeFile(t, filepath.Join(f.src, "evil", "compose.yml"), "services:\n  e:\n    labels:\n      traefik.http.routers.e.rule: Host(`hub.${PORTCULLIS_DOMAIN}`)\n")
	writeFile(t, filepath.Join(f.src, "sneaky", "manifest.yaml"), "name: Sneaky\n")
	writeFile(t, filepath.Join(f.src, "sneaky", "compose.yml"), "services:\n  e:\n    labels:\n      traefik.http.routers.e.rule: Host(`s.${PORTCULLIS_DOMAIN}`) || Host(`s.example.com`)\n")
	f.h.Discover()
	if f.h.Template("evil") != nil || f.h.Template("sneaky") != nil {
		t.Error("unsafe templates loaded")
	}
	for name, c := range map[string]string{
		"regexp":  "services:\n  g:\n    labels:\n      traefik.http.routers.g.rule: HostRegexp(`.+`)\n",
		"core":    "services:\n  g:\n    labels:\n      traefik.http.routers.g.rule: Host(`auth.${PORTCULLIS_DOMAIN}`)\n",
		"metrics": "services:\n  g:\n    labels:\n      traefik.http.routers.g.rule: Host(`metrics.${PORTCULLIS_DOMAIN}`)\n",
		"any":     "services:\n  g:\n    labels:\n      traefik.http.routers.g.rule: PathPrefix(`/`)\n",
	} {
		writeFile(t, filepath.Join(f.src, "bad", "manifest.yaml"), "name: Bad\n")
		writeFile(t, filepath.Join(f.src, "bad", "compose.yml"), c)
		f.h.Discover()
		if f.h.Template("bad") != nil {
			t.Errorf("%s: template loaded", name)
		}
	}
	// A template update changes the routed subdomains used for the policy file.
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), "services:\n  grafana:\n    labels:\n      traefik.http.routers.g.rule: Host(`dash.${PORTCULLIS_DOMAIN}`)\n")
	f.h.Discover()
	f.h.Enable("grafana")
	if doc := readPolicy(t, f); doc.Groups["dash"] != "users_grafana" || doc.Groups["grafana"] != "" {
		t.Errorf("groups = %v", doc.Groups)
	}
}

// Fresh installs default to a YubiKey by either method (client cert or
// passkey); an explicitly chosen public default is honoured (and differs
// from "never set").
func TestInitialDefaultPolicy(t *testing.T) {
	f := newFixture(t)
	doc := readPolicy(t, f)
	if strings.Join(doc.Default.Factors, ",") != "mtls,webauthn" || doc.Default.Op != "any" {
		t.Errorf("fresh default = %+v", doc.Default)
	}
	if d := f.h.DefaultPolicy(); strings.Join(d.Factors, ",") != "mtls,webauthn" || d.Op != "any" {
		t.Errorf("DefaultPolicy() = %+v", d)
	}
	// Apps that inherit it: cert optional at the handshake, Keycloak
	// steps up to hwk (the lower of the two LoAs).
	if err := f.h.Enable("other"); err != nil {
		t.Fatal(err)
	}
	if ov, _ := os.ReadFile(filepath.Join(f.data, "overrides", "other.override.yml")); !strings.Contains(string(ov), "tls.options: authaware@file") {
		t.Errorf("inherited default tier:\n%s", ov)
	}
	f.idp.mu.Lock()
	acr := f.idp.specs[len(f.idp.specs)-1].ACR
	f.idp.mu.Unlock()
	if acr != "hwk" {
		t.Errorf("inherited default acr = %q, want hwk", acr)
	}
	if err := f.h.Disable("other"); err != nil {
		t.Fatal(err)
	}
	if ch, err := f.h.SetDefaultPolicy(policy.AuthPolicy{}); err != nil || !ch {
		t.Fatal("public default not detected as a change")
	}
	f.h.Wait()
	raw, _ := os.ReadFile(filepath.Join(f.data, "group-gate-policy.json"))
	if !strings.Contains(string(raw), `"factors": []`) {
		t.Errorf("explicit public default not published as []:\n%s", raw)
	}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	ov, _ := os.ReadFile(filepath.Join(f.data, "overrides", "grafana.override.yml"))
	if !strings.Contains(string(ov), "tls.options: public@file") {
		t.Errorf("explicit public default not applied:\n%s", ov)
	}
	// Survives a restart.
	h2, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	if d := h2.DefaultPolicy(); len(d.Factors) != 0 {
		t.Errorf("after restart default = %+v", d)
	}
}

func TestDefaultPolicy(t *testing.T) {
	f := newFixture(t)
	f.h.Enable("other")
	if ch, err := f.h.SetDefaultPolicy(policy.AuthPolicy{Factors: []string{"mtls"}}); err != nil || !ch {
		t.Fatal("change not detected", err)
	}
	if ch, _ := f.h.SetDefaultPolicy(policy.AuthPolicy{Factors: []string{" MTLS "}}); ch {
		t.Error("same policy reported as changed")
	}
	for _, bad := range [][]string{{"password"}, {"mtls", "sms"}} {
		if _, err := f.h.SetDefaultPolicy(policy.AuthPolicy{Factors: bad}); statusOf(err) != 400 {
			t.Errorf("default %v: err = %v", bad, err)
		}
	}
	if d := readPolicy(t, f).Default; strings.Join(d.Factors, ",") != "mtls" {
		t.Errorf("default = %+v", d)
	}
	// Propagation runs in the background: wait for the restart.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.idp.mu.Lock()
		n := len(f.idp.updated)
		f.idp.mu.Unlock()
		if n > 0 && len(f.runner.Calls()) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.idp.mu.Lock()
	defer f.idp.mu.Unlock()
	if len(f.idp.updated) == 0 || f.idp.updated[0] != "other:mtls" {
		t.Errorf("acr not pushed: %v", f.idp.updated)
	}
	ov, _ := os.ReadFile(filepath.Join(f.data, "overrides", "other.override.yml"))
	if !strings.Contains(string(ov), "protected@file") {
		t.Errorf("override not regenerated:\n%s", ov)
	}
}

func TestExpertFiles(t *testing.T) {
	f := newFixture(t)
	if err := f.h.SaveEnv("grafana", map[string]string{"A": "1\nB=2"}); statusOf(err) != 400 {
		t.Errorf("newline in env accepted: %v", err)
	}
	if err := f.h.SaveEnv("grafana", map[string]string{"A B": "1"}); statusOf(err) != 400 {
		t.Errorf("bad key accepted: %v", err)
	}
	if err := f.h.SaveEnv("grafana", map[string]string{"FOO": "bar"}); err != nil {
		t.Fatal(err)
	}
	vars, services, err := f.h.Env("grafana")
	if err != nil || vars["FOO"] != "bar" || fmt.Sprint(services) != "[grafana]" {
		t.Errorf("env = %v %v %v", vars, services, err)
	}
}
