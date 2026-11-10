package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/signin"
)

const plexManifest = `name: Plex
category: media
ai: {unsupported: "test fixture"}
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

const vaultManifest = "name: Vault\ncategory: security\nai: {unsupported: test fixture}\nauth:\n  method: mtls\n  sso: false\n"

const vaultCompose = "services:\n  v:\n    image: x\n    labels:\n      traefik.http.routers.vault.rule: Host(`vault.${PORTCULLIS_DOMAIN}`)\n      traefik.http.routers.vault.tls.options: protected@file\n"

const docsManifest = "name: Docs\ncategory: public\nai: {unsupported: test fixture}\nauth:\n  method: public\n  sso: false\n"

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
	err := f.h.save(id, u)
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

// enableTemplate enables built-in or stored template id (test helper).
func enableTemplate(t *testing.T, f *fixture, id string) {
	t.Helper()
	if _, err := f.h.SetTemplateEnabled(context.Background(), id, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
}

func pickTemplate(id string) *string { return &id }

// Every app inherits by default and shows the template that applies and
// what its auth method makes of it: the TLS tier and the notes.
func TestSignInPerMethod(t *testing.T) {
	f := newAccessFixture(t)
	cases := []struct {
		id, method, enforcement, template, tier, note string
	}{
		{"grafana", "header-auth", policy.EnforcePerRequest, "standard", "authaware@file", "every request"},
		{"other", "native-oidc", policy.EnforceAtLogin, "standard", "authaware@file", "Keycloak checks the template"},
		{"vault", "mtls", policy.EnforceTLS, "", "protected@file", "takes no sign-in template"},
		{"docs", "public", policy.EnforceNone, "", "public@file", "handles its own sign-in"},
		{"plex", "forward-auth", policy.EnforcePerRequest, "standard", "authaware@file", "every request"},
	}
	for _, c := range cases {
		v := view(t, f, c.id)
		if v.SignInTemplate != "" || v.Method != c.method || v.Capability.Enforcement != c.enforcement ||
			v.Template != c.template || v.Tier != c.tier || !strings.Contains(strings.Join(v.SignInNotes, " "), c.note) {
			t.Errorf("%s: method=%s cap=%+v template=%s tier=%s notes=%q", c.id, v.Method, v.Capability, v.Template, v.Tier, v.SignInNotes)
		}
		if c.template != "" && (v.Sentence == "" || v.Score.Tenths == 0) {
			t.Errorf("%s: sentence %q score %+v", c.id, v.Sentence, v.Score)
		}
	}
	// The overrides follow the template: the mTLS-only app keeps the
	// protected tier, the public app public@file.
	for id, tier := range map[string]string{"vault": "protected@file", "docs": "public@file", "grafana": "authaware@file"} {
		if err := f.h.Enable(id); err != nil {
			t.Fatal(err)
		}
		if ov := readOverride(t, f, id); !strings.Contains(ov, "tls.options: "+tier) {
			t.Errorf("%s override:\n%s", id, ov)
		}
	}
	// Native OIDC on a certificate-only template: per connection too.
	enableTemplate(t, f, "yubikey-and-certificate")
	if err := saveApp(t, f, "other", SettingsUpdate{SignInTemplate: pickTemplate("yubikey-and-certificate")}); err != nil {
		t.Fatal(err)
	}
	if v := view(t, f, "other"); v.Tier != "protected@file" || v.SignInTemplate != "yubikey-and-certificate" {
		t.Errorf("other on yubikey-and-certificate: %s %q", v.Tier, v.SignInTemplate)
	}
}

// Controller ruling: an mtls app takes no template and is always on
// protected@file, whatever the switches and the default.
func TestMTLSAppAlwaysProtected(t *testing.T) {
	f := newAccessFixture(t)
	ctx := context.Background()
	ableAdmin(f.h)
	if err := f.h.Enable("vault"); err != nil {
		t.Fatal(err)
	}
	// Default on passkeys only, the certificate method off: still protected.
	if _, err := f.h.SaveTemplate(ctx, "standard", TemplateInput{Name: "Standard", Rule: siLeaves("any", "family:passkey")}, false, siAdmin); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"hub", "people"} {
		if _, err := f.h.SetCoreTemplate(ctx, k, "standard", siAdmin); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "strong", false, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetMethod(ctx, signin.YubiKeyCert, false, siAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if v := view(t, f, "vault"); v.Tier != "protected@file" || v.Template != "" {
		t.Errorf("vault: %s %q", v.Tier, v.Template)
	}
	if ov := readOverride(t, f, "vault"); !strings.Contains(ov, "tls.options: protected@file") {
		t.Errorf("vault override:\n%s", ov)
	}
	if err := saveApp(t, f, "vault", SettingsUpdate{SignInTemplate: pickTemplate("standard")}); statusOf(err) != 400 || !strings.Contains(err.Error(), "takes none") {
		t.Errorf("mtls pick: %v", err)
	}
	if _, ok := readPolicy(t, f).Hosts["vault.example.org"]; ok {
		t.Error("mtls app published a template")
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
	if g := readPolicy(t, f).Groups["plex.example.org"]; g != "users_plex" {
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
	if _, ok := readPolicy(t, f).Groups["plex.example.org"]; ok {
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
	// A template pick is refused while nothing is enforced.
	enableTemplate(t, f, "yubikey-and-certificate")
	if err := saveApp(t, f, "plex", SettingsUpdate{SignInTemplate: pickTemplate("yubikey-and-certificate")}); statusOf(err) != 400 {
		t.Errorf("template on native-only app: %v", err)
	}
	// ...but accepted when switching back in the same request.
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInGateway), SignInTemplate: pickTemplate("yubikey-and-certificate")}); err != nil {
		t.Fatal(err)
	}
	if ov := readOverride(t, f, "plex"); !strings.Contains(ov, mw+": portcullis-auth@docker,portcullis-groups@docker,security-headers@file") || !strings.Contains(ov, tls+": protected@file") {
		t.Errorf("back to gateway:\n%s", ov)
	}
	if p := readPolicy(t, f).Hosts["plex.example.org"]; p != "yubikey-and-certificate" {
		t.Errorf("published template = %q", p)
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
	if _, ok := readPolicy(t, f).Groups["plex.example.org"]; ok {
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
