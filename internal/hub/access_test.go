package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

const plexManifest = `name: Plex
category: media
auth:
  method: custom
  sso: false
  group_access: true
  access_group: users_plex
  native_login:
    supported: true
    allow_without_gateway: true
    note: Plex accounts (plex.tv)
`

const plexCompose = "services:\n  plex:\n    image: x\n    labels:\n      traefik.http.routers.plex.rule: Host(`plex.${PORTCULLIS_DOMAIN:-x}`)\n      traefik.http.routers.plex.entrypoints: websecure\n      traefik.http.routers.plex.tls.options: public@file\n      traefik.http.routers.plex.middlewares: security-headers@file\n"

const vaultManifest = "name: Vault\ncategory: security\nauth:\n  method: mtls\n  sso: false\n"

const vaultCompose = "services:\n  v:\n    image: x\n    labels:\n      traefik.http.routers.vault.rule: Host(`vault.${PORTCULLIS_DOMAIN}`)\n      traefik.http.routers.vault.tls.options: protected@file\n"

const docsManifest = "name: Docs\ncategory: public\nauth:\n  method: public\n  sso: false\n"

const docsCompose = "services:\n  d:\n    image: x\n    labels:\n      traefik.http.routers.docs.rule: Host(`docs.${PORTCULLIS_DOMAIN}`)\n"

func newAccessFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	writeFile(t, filepath.Join(f.src, "plex", "manifest.yaml"), plexManifest)
	writeFile(t, filepath.Join(f.src, "plex", "compose.yml"), plexCompose)
	writeFile(t, filepath.Join(f.src, "vault", "manifest.yaml"), vaultManifest)
	writeFile(t, filepath.Join(f.src, "vault", "compose.yml"), vaultCompose)
	writeFile(t, filepath.Join(f.src, "docs", "manifest.yaml"), docsManifest)
	writeFile(t, filepath.Join(f.src, "docs", "compose.yml"), docsCompose)
	f.h.Discover()
	return f
}

func saveApp(t *testing.T, f *fixture, id string, u SettingsUpdate) error {
	t.Helper()
	if u.Values == nil {
		u.Values = map[string]string{}
	}
	err := f.h.SaveSettings(id, u)
	f.h.Wait()
	return err
}

func view(t *testing.T, f *fixture, id string) *AppSettingsView {
	t.Helper()
	v, err := f.h.AppSettings(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func factors(p policy.AuthPolicy) string { return strings.Join(p.Factors, ",") + "/" + p.Op }

// Every app inherits by default and shows the EFFECTIVE policy: the global
// default intersected with what its auth method can enforce.
func TestEffectivePolicyPerMethod(t *testing.T) {
	f := newAccessFixture(t)
	cases := []struct {
		id, method, enforcement, effective, tier, note string
	}{
		{"grafana", "header-auth", policy.EnforcePerRequest, "mtls,webauthn/any", "authaware@file", "every request"},
		{"other", "native-oidc", policy.EnforceAtLogin, "mtls,webauthn/any", "authaware@file", "mTLS is checked at login only"},
		{"vault", "mtls", policy.EnforceTLS, "mtls/", "protected@file", "can't enforce WebAuthn, so it enforces mTLS"},
		{"docs", "public", policy.EnforceNone, "/", "public@file", "handles its own sign-in"},
		{"plex", "forward-auth", policy.EnforcePerRequest, "mtls,webauthn/any", "authaware@file", "every request"},
	}
	for _, c := range cases {
		v := view(t, f, c.id)
		if v.AuthPolicy != nil || v.Method != c.method || v.Capability.Enforcement != c.enforcement ||
			factors(v.EffectivePolicy) != c.effective || v.Tier != c.tier || !strings.Contains(strings.Join(v.PolicyNotes, " "), c.note) {
			t.Errorf("%s: method=%s cap=%+v effective=%s tier=%s notes=%q", c.id, v.Method, v.Capability, factors(v.EffectivePolicy), v.Tier, v.PolicyNotes)
		}
	}
	// The overrides follow the effective policy, not the raw default: the
	// mTLS-only app keeps the protected tier, the public app public@file.
	for id, tier := range map[string]string{"vault": "protected@file", "docs": "public@file", "grafana": "authaware@file"} {
		if err := f.h.Enable(id); err != nil {
			t.Fatal(err)
		}
		if ov := readOverride(t, f, id); !strings.Contains(ov, "tls.options: "+tier) {
			t.Errorf("%s override:\n%s", id, ov)
		}
	}

	// A default the mTLS app can't enforce at all: say so, keep the cert.
	if _, err := f.h.SetDefaultPolicy(policy.AuthPolicy{Factors: []string{"webauthn"}}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	v := view(t, f, "vault")
	if factors(v.EffectivePolicy) != "mtls/" || !v.Resolution.Fallback || !strings.Contains(strings.Join(v.PolicyNotes, " "), "which this app can't enforce: mTLS applies instead") {
		t.Errorf("vault under webauthn default: %+v %q", v.EffectivePolicy, v.PolicyNotes)
	}
	if ov := readOverride(t, f, "vault"); !strings.Contains(ov, "protected@file") {
		t.Errorf("vault lost its protected tier:\n%s", ov)
	}
	// Native OIDC with an mTLS-only policy: per connection too.
	if err := saveApp(t, f, "other", SettingsUpdate{Policy: &policy.AuthPolicy{Factors: []string{"mtls"}}}); err != nil {
		t.Fatal(err)
	}
	if v := view(t, f, "other"); v.Tier != "protected@file" || !strings.Contains(strings.Join(v.PolicyNotes, " "), "every connection") {
		t.Errorf("other mtls override: %s %q", v.Tier, v.PolicyNotes)
	}
}

// Overrides may only name factors the app can enforce.
func TestOverrideValidation(t *testing.T) {
	f := newAccessFixture(t)
	bad := []struct {
		id   string
		p    policy.AuthPolicy
		want string
	}{
		{"vault", policy.AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}, `can't enforce "webauthn"`},
		{"vault", policy.AuthPolicy{}, "can't be public"},
		{"docs", policy.AuthPolicy{Factors: []string{"mtls"}}, "handles its own sign-in"},
		{"grafana", policy.AuthPolicy{Factors: []string{"password"}}, "not a sign-in method"},
		{"grafana", policy.AuthPolicy{Factors: []string{"sms"}}, "unknown factor"},
	}
	for _, c := range bad {
		err := saveApp(t, f, c.id, SettingsUpdate{Policy: &c.p})
		if statusOf(err) != 400 || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %+v: err = %v", c.id, c.p, err)
		}
		if v := view(t, f, c.id); v.AuthPolicy != nil {
			t.Errorf("%s: rejected override stored: %+v", c.id, v.AuthPolicy)
		}
	}
	// Refused before anything is stored, settings included.
	if err := saveApp(t, f, "grafana", SettingsUpdate{Values: map[string]string{"GF_THEME": "light"}, Policy: &policy.AuthPolicy{Factors: []string{"password"}}}); statusOf(err) != 400 {
		t.Fatal(err)
	}
	if v := view(t, f, "grafana"); v.Values["GF_THEME"] != "" {
		t.Errorf("settings stored despite a refused policy: %v", v.Values)
	}
	for id, p := range map[string]policy.AuthPolicy{
		"vault":   {Factors: []string{"mtls"}},
		"grafana": {Factors: []string{"mtls", "webauthn"}, Op: "all"},
		"plex":    {Factors: []string{"webauthn"}},
	} {
		if err := saveApp(t, f, id, SettingsUpdate{Policy: &p}); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	// Inheriting is always allowed, also for apps without a policy.
	if err := saveApp(t, f, "docs", SettingsUpdate{Inherit: true}); err != nil {
		t.Error(err)
	}
}

// A stored policy naming "password" is normalised and the view says so.
func TestLegacyPasswordNote(t *testing.T) {
	f := newAccessFixture(t)
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	st.AuthPolicies["grafana"] = policy.AuthPolicy{Factors: []string{"password", "webauthn"}, Op: "all"}
	st.DefaultPolicy = &policy.AuthPolicy{Factors: []string{"password"}}
	if err := st.Save(filepath.Join(f.data, "state.yaml")); err != nil {
		t.Fatal(err)
	}
	h, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h.Init()
	f.h = h
	v := view(t, f, "grafana")
	if factors(*v.AuthPolicy) != "webauthn/" || !strings.Contains(strings.Join(v.PolicyNotes, " "), `named "password"`) {
		t.Errorf("grafana: %+v %q", v.AuthPolicy, v.PolicyNotes)
	}
	if v := view(t, f, "vault"); !strings.Contains(strings.Join(v.PolicyNotes, " "), `global default named "password"`) || !h.DefaultPolicyLegacy() {
		t.Errorf("vault (inherits): %q", v.PolicyNotes)
	}
	if d := readPolicy(t, f).Default; factors(d) != "mtls,webauthn/any" {
		t.Errorf("published default = %+v", d)
	}
	raw, _ := os.ReadFile(filepath.Join(f.data, "group-gate-policy.json"))
	if strings.Contains(string(raw), "password") {
		t.Errorf("policy file names password:\n%s", raw)
	}
	if err := saveApp(t, f, "grafana", SettingsUpdate{Policy: &policy.AuthPolicy{Factors: []string{"webauthn"}}}); err != nil {
		t.Fatal(err)
	}
	if v := view(t, f, "grafana"); strings.Contains(strings.Join(v.PolicyNotes, " "), "password") {
		t.Errorf("note survives a save: %q", v.PolicyNotes)
	}
}

func plexLabels(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	want, err := f.h.desiredRouteLabelsLocked(f.h.findLocked("plex"))
	if err != nil {
		t.Fatal(err)
	}
	return want["plex"]
}

// Apps with their own login: Portcullis sign-in in front by default (the
// override adds forward-auth + group-gate), or the app's own login only.
func TestNativeLoginSignIn(t *testing.T) {
	f := newAccessFixture(t)
	if err := f.h.Enable("plex"); err != nil {
		t.Fatal(err)
	}
	mw, tls := "traefik.http.routers.plex.middlewares", "traefik.http.routers.plex.tls.options"
	ov := readOverride(t, f, "plex")
	if !strings.Contains(ov, mw+": portcullis-auth@docker,portcullis-groups@docker,security-headers@file") || !strings.Contains(ov, tls+": authaware@file") {
		t.Errorf("gateway override:\n%s", ov)
	}
	if v := view(t, f, "plex"); v.SignIn == nil || v.SignIn.Mode != SignInGateway || v.SignIn.AccessGroup != "users_plex" || !v.SignIn.AllowWithoutGateway {
		t.Errorf("sign-in view = %+v", v.SignIn)
	}
	if g := readPolicy(t, f).Groups["plex"]; g != "users_plex" {
		t.Errorf("gateway group = %q", g)
	}
	if p := portalApp(t, f, "plex"); p.AccessGroup != "users_plex" {
		t.Errorf("portal = %+v", p)
	}
	// Running as rendered: no drift.
	gw := container("c1", "portcullis-plex", "plex", "running")
	for k, v := range plexLabels(t, f) {
		gw.Labels[k] = v
	}
	f.engine.containers = []docker.Container{gw}
	if d := driftFor(f.h.Reconcile(context.Background()), "plex"); d != nil {
		t.Errorf("drift for identical labels: %+v", d)
	}

	// Switch to the app's own login only.
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	ov = readOverride(t, f, "plex")
	if strings.Contains(ov, "portcullis-auth") || !strings.Contains(ov, mw+": security-headers@file") || !strings.Contains(ov, tls+": public@file") {
		t.Errorf("native override:\n%s", ov)
	}
	if _, ok := readPolicy(t, f).Groups["plex"]; ok {
		t.Error("native-only app still publishes a group")
	}
	if p := portalApp(t, f, "plex"); p.AccessGroup != "" {
		t.Errorf("portal = %+v", p)
	}
	v := view(t, f, "plex")
	if v.SignIn.Mode != SignInNative || v.Capability.Enforcement != policy.EnforceNone || v.Tier != "public@file" {
		t.Errorf("native view = %+v %+v", v.SignIn, v.Capability)
	}
	f.h.mu.RLock()
	snap := f.h.st.Published["plex"]
	f.h.mu.RUnlock()
	if !snap.NativeLoginOnly || snap.GroupAccess {
		t.Errorf("snapshot = %+v", snap)
	}
	// The containers still run the gateway labels: exposure drift, and the
	// message says what the settings want.
	d := driftFor(f.h.Reconcile(context.Background()), "plex")
	if d == nil || d.Kind != DriftPublicAccess || !strings.Contains(d.Message, "changed routers.plex.middlewares") || !strings.Contains(d.Message, "own login only") {
		t.Errorf("drift after switching = %+v", d)
	}
	// An override naming a factor is refused while nothing is enforced.
	if err := saveApp(t, f, "plex", SettingsUpdate{Policy: &policy.AuthPolicy{Factors: []string{"mtls"}}}); statusOf(err) != 400 {
		t.Errorf("override on native-only app: %v", err)
	}
	// ...but accepted when switching back in the same request.
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInGateway), Policy: &policy.AuthPolicy{Factors: []string{"mtls"}}}); err != nil {
		t.Fatal(err)
	}
	if ov := readOverride(t, f, "plex"); !strings.Contains(ov, mw+": portcullis-auth@docker,portcullis-groups@docker,security-headers@file") || !strings.Contains(ov, tls+": protected@file") {
		t.Errorf("back to gateway:\n%s", ov)
	}
	if p := readPolicy(t, f).Policies["plex"]; factors(p) != "mtls/" {
		t.Errorf("published policy = %+v", p)
	}
	if d := driftFor(f.h.Reconcile(context.Background()), "plex"); d == nil || !strings.Contains(d.Message, "tls.options") {
		t.Errorf("tier drift = %+v", d)
	}

	// Sign-in choices the template doesn't offer are refused.
	for id, mode := range map[string]string{"grafana": SignInNative, "docs": SignInGateway, "plex": "both"} {
		if err := saveApp(t, f, id, SettingsUpdate{SignIn: strp(mode)}); statusOf(err) != 400 {
			t.Errorf("%s %s: %v", id, mode, err)
		}
	}
}

// A stored "own login only" the template stops allowing falls back to
// Portcullis sign-in (fail closed) and says why.
func TestNativeLoginNoLongerAllowed(t *testing.T) {
	f := newAccessFixture(t)
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.src, "plex", "manifest.yaml"), strings.Replace(plexManifest, "allow_without_gateway: true", "allow_without_gateway: false", 1))
	f.h.Discover()
	if err := f.h.Enable("plex"); err != nil {
		t.Fatal(err)
	}
	v := view(t, f, "plex")
	if v.SignIn.Mode != SignInGateway || !strings.Contains(v.SignIn.Blocked, "no longer allows") {
		t.Errorf("view = %+v", v.SignIn)
	}
	if ov := readOverride(t, f, "plex"); !strings.Contains(ov, "portcullis-auth@docker,portcullis-groups@docker") {
		t.Errorf("override:\n%s", ov)
	}
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInNative)}); statusOf(err) != 400 {
		t.Errorf("native allowed: %v", err)
	}
}

// Template gone while running with its own login only: the snapshot keeps
// publishing no group, and drift says how the containers run.
func TestNativeLoginSnapshot(t *testing.T) {
	f := newAccessFixture(t)
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("plex"); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(f.src, "plex"))
	f.h.Discover()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPolicy(t, f).Groups["plex"]; ok {
		t.Error("snapshot publishes a group for a native-only app")
	}
	f.engine.containers = []docker.Container{container("c1", "portcullis-plex", "plex", "running")}
	if d := driftFor(f.h.Reconcile(context.Background()), "plex"); d == nil || d.Kind != DriftTemplateMissing || !strings.Contains(d.Message, "own login only") {
		t.Errorf("drift = %+v", d)
	}
}

func portalApp(t *testing.T, f *fixture, id string) PortalApp {
	t.Helper()
	for _, a := range f.h.Portal().Apps {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("%s not in the portal", id)
	return PortalApp{}
}
