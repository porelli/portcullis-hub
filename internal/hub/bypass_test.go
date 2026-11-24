package hub

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/policy"
)

// syncManifest / syncCompose: a Firefox Sync-like app — custom, no
// Portcullis sign-in, group_access false but an access group.
const syncManifest = `name: Sync
category: productivity
ai: {unsupported: "test fixture"}
auth:
  method: custom
  sso: false
  group_access: false
  access_group: users_sync
  notes: |
    A sync server; the host is open to the internet, with no Portcullis sign-in, because the client can't pass one.

    More details for operators.
`

const syncCompose = "services:\n  sync:\n    image: x\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.sync.rule: Host(`${PORTCULLIS_HOST_SYNC:-sync.portcullis.local}`)\n" +
	"      traefik.http.routers.sync.tls.options: public@file\n" +
	"      traefik.http.routers.sync.middlewares: rate-limit@file\n" +
	"      traefik.http.routers.sync-token.rule: Host(`${PORTCULLIS_HOST_SYNC:-sync.portcullis.local}`) && PathPrefix(`/1.0/`)\n" +
	"      traefik.http.routers.sync-token.tls.options: public@file\n" +
	"      traefik.http.routers.sync-token.service: sync\n" +
	"      traefik.http.services.sync.loadbalancer.server.port: \"8000\"\n"

func bypassOf(t *testing.T, f *fixture, id string) []Bypass {
	t.Helper()
	v, ok := f.h.InstanceView(id)
	if !ok {
		t.Fatalf("no instance %s", id)
	}
	if v.Bypass == nil {
		t.Fatalf("%s: bypass is nil, want an array", id)
	}
	return v.Bypass
}

func bypassKinds(bs []Bypass) string {
	var k []string
	for _, b := range bs {
		k = append(k, b.Kind)
	}
	return strings.Join(k, ",")
}

func newBypassFixture(t *testing.T) *fixture {
	t.Helper()
	f := newAccessFixture(t)
	writeFile(t, filepath.Join(f.src, "sync", "manifest.yaml"), syncManifest)
	writeFile(t, filepath.Join(f.src, "sync", "compose.yml"), syncCompose)
	writeFile(t, filepath.Join(f.src, "cloud", "manifest.yaml"), cloudManifest)
	writeFile(t, filepath.Join(f.src, "cloud", "compose.yml"), cloudCompose)
	f.h.Discover()
	return f
}

// An app without Portcullis sign-in: one open_host entry covering every
// host, the tier it gets and the template's first notes paragraph.
func TestBypassOpenHost(t *testing.T) {
	f := newBypassFixture(t)
	bs := bypassOf(t, f, "sync")
	if len(bs) != 1 || bs[0].Kind != BypassOpenHost {
		t.Fatalf("sync bypass = %+v", bs)
	}
	b := bs[0]
	if strings.Join(b.Hosts, ",") != "sync.example.org" || len(b.Paths) != 0 || b.Tier != policy.TierPublic || b.VPNOnly {
		t.Errorf("open host = %+v", b)
	}
	if !strings.Contains(b.Reason, "auth method is custom") || !strings.HasPrefix(b.Note, "A sync server") || strings.Contains(b.Note, "operators") {
		t.Errorf("reason %q note %q", b.Reason, b.Note)
	}
	// A public app and an app on its own login only are open too.
	if bs := bypassOf(t, f, "docs"); bypassKinds(bs) != BypassOpenHost || !strings.Contains(bs[0].Reason, "public app") {
		t.Errorf("docs bypass = %+v", bs)
	}
	if bs := bypassOf(t, f, "plex"); len(bs) != 0 {
		t.Errorf("plex behind the gateway: %+v", bs)
	}
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	if bs := bypassOf(t, f, "plex"); bypassKinds(bs) != BypassOpenHost || !strings.Contains(bs[0].Reason, "own login only") {
		t.Errorf("plex on its own login = %+v", bs)
	}
	// mtls (the certificate is the sign-in) and native-oidc (the app's
	// OIDC login) skip nothing.
	for _, id := range []string{"vault", "other"} {
		if bs := bypassOf(t, f, id); len(bs) != 0 {
			t.Errorf("%s bypass = %+v", id, bs)
		}
	}
}

// A signed-in app: an ungated router is listed with its paths, and the
// public exception (on by default here, all shares) with its published paths and the
// exception's description; switching the exception off drops it.
func TestBypassOpenRouterAndPublicPaths(t *testing.T) {
	f := newBypassFixture(t)
	// Listed mode without tokens opens nothing.
	if bs := bypassOf(t, f, "cloud"); bypassKinds(bs) != BypassOpenRouter {
		t.Fatalf("cloud, no listed share = %+v", bs)
	}
	save(t, f, SettingsUpdate{PublicMode: strp("all")})
	bs := bypassOf(t, f, "cloud")
	if bypassKinds(bs) != BypassOpenRouter+","+BypassPublicPaths {
		t.Fatalf("cloud bypass = %+v", bs)
	}
	r := bs[0]
	if r.Router != "cloud-login" || strings.Join(r.Hosts, ",") != "cloud.example.org" || len(r.Paths) != 1 || r.Paths[0] != (BypassPath{Path: "/login", Match: "prefix"}) {
		t.Errorf("open router = %+v", r)
	}
	p := bs[1]
	var paths []string
	for _, x := range p.Paths {
		paths = append(paths, x.Match+":"+x.Path)
	}
	if strings.Join(p.Hosts, ",") != "cloud.example.org" || p.Note != "Public share links" || p.Tier != policy.TierDefault ||
		!strings.Contains(strings.Join(paths, " "), "prefix:/s") || !strings.Contains(strings.Join(paths, " "), "static:/dist") {
		t.Errorf("public paths = %+v (%v)", p, paths)
	}
	save(t, f, SettingsUpdate{PublicAccess: boolp(false)})
	if bs := bypassOf(t, f, "cloud"); bypassKinds(bs) != BypassOpenRouter {
		t.Errorf("exception off: %+v", bs)
	}
}

// A weaker TLS tier: only public@file on a signed-in app, only while the
// default template asks for a certificate; stricter tiers never.
func TestBypassWeakTLS(t *testing.T) {
	f := newBypassFixture(t)
	ctx := context.Background()
	ableAdmin(f.h)
	if bs := bypassOf(t, f, "plex"); len(bs) != 0 {
		t.Fatalf("plex on the default (tier default) = %+v", bs)
	}
	if _, err := f.h.SaveTemplate(ctx, "passkeys", TemplateInput{Name: "Passkeys only", Rule: siLeaves("any", "family:passkey")}, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if err := saveApp(t, f, "plex", SettingsUpdate{SignInTemplate: pickTemplate("passkeys")}); err != nil {
		t.Fatal(err)
	}
	bs := bypassOf(t, f, "plex")
	if bypassKinds(bs) != BypassWeakTLS || bs[0].Tier != policy.TierPublic || strings.Join(bs[0].Hosts, ",") != "plex.example.org" ||
		!strings.Contains(bs[0].Reason, `"Passkeys only"`) || !strings.Contains(bs[0].Reason, "default (") {
		t.Errorf("plex on passkeys = %+v", bs)
	}
	// A stricter pick: no badge.
	enableTemplate(t, f, "yubikey-and-certificate")
	if err := saveApp(t, f, "plex", SettingsUpdate{SignInTemplate: pickTemplate("yubikey-and-certificate")}); err != nil {
		t.Fatal(err)
	}
	if bs := bypassOf(t, f, "plex"); len(bs) != 0 {
		t.Errorf("plex on a protected template = %+v", bs)
	}
	// The default itself asks for no certificate: public is the norm.
	if err := saveApp(t, f, "plex", SettingsUpdate{SignInTemplate: pickTemplate("passkeys")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveTemplate(ctx, "standard", TemplateInput{Name: "Standard", Rule: siLeaves("any", "family:passkey")}, false, siAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if bs := bypassOf(t, f, "plex"); len(bs) != 0 {
		t.Errorf("public is the norm: %+v", bs)
	}
}

// The portal follows the access group even when group-gate doesn't
// enforce it (group_access false, the app's own login only): only members
// see the tile, administrators included; My apps likewise.
func TestPortalUsesAccessGroupWithoutGroupAccess(t *testing.T) {
	f := newBypassFixture(t)
	if err := f.h.Enable("sync"); err != nil {
		t.Fatal(err)
	}
	if p := portalApp(t, f, "sync"); p.AccessGroup != "users_sync" {
		t.Errorf("sync portal access_group = %q, want users_sync", p.AccessGroup)
	}
	if g, ok := readPolicy(t, f).Groups["sync.example.org"]; ok && g != "" {
		t.Errorf("policy group changed: %q", g)
	}
	if err := f.h.Enable("plex"); err != nil {
		t.Fatal(err)
	}
	if err := saveApp(t, f, "plex", SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	if p := portalApp(t, f, "plex"); p.AccessGroup != "users_plex" {
		t.Errorf("plex (own login) portal access_group = %q", p.AccessGroup)
	}
}
