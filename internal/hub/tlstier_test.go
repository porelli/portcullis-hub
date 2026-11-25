package hub

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/runtime/kube"
	"github.com/portcullis/hub/internal/templates"
)

// fxaManifest / fxaCompose: shaped like firefox-sync-fxa — Portcullis
// sign-in on the accounts and admin hosts, the API, profile, Sync and
// pairing hosts open (Firefox presents no certificate), and open exact
// paths on the accounts host.
const fxaManifest = `name: FxA
category: productivity
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_fxa
`

const fxaGated = "portcullis-auth@docker,portcullis-groups@docker,security-headers@file"

func fxaRouter(name, sub, extra, mws string) string {
	rule := "Host(`" + sub + ".${PORTCULLIS_DOMAIN:-portcullis.local}`)" + extra
	return "      traefik.http.routers." + name + ".rule: " + rule + "\n" +
		"      traefik.http.routers." + name + ".middlewares: " + mws + "\n"
}

var fxaCompose = "services:\n  fxa:\n    image: x\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	fxaRouter("fxa", "fxa-sync", "", "rate-limit@file") +
	fxaRouter("fxa-accounts", "fxa-accounts", "", fxaGated) +
	fxaRouter("fxa-accounts-open", "fxa-accounts", " && (Path(`/.well-known/fxa-client-configuration`) || Path(`/__heartbeat__`))", "rate-limit@file") +
	"      traefik.http.routers.fxa-accounts-open.priority: \"100\"\n" +
	fxaRouter("fxa-api", "fxa-api", "", "rate-limit@file") +
	fxaRouter("fxa-api-create", "fxa-api", " && Path(`/v1/account/create`)", "rate-limit@file") +
	"      traefik.http.routers.fxa-api-create.priority: \"100\"\n" +
	fxaRouter("fxa-profile", "fxa-profile", "", "rate-limit@file") +
	fxaRouter("fxa-pairing", "fxa-pairing", "", "rate-limit@file") +
	fxaRouter("fxa-admin", "fxa-admin", "", fxaGated) +
	"      traefik.http.services.fxa.loadbalancer.server.port: \"80\"\n"

// newFxaFixture: the fxa app on a sign-in template that requires
// yubikey_cert, so its instance tier is protected@file.
func newFxaFixture(t *testing.T) *fixture {
	t.Helper()
	f := newBypassFixture(t)
	writeFile(t, filepath.Join(f.src, "fxa", "manifest.yaml"), fxaManifest)
	writeFile(t, filepath.Join(f.src, "fxa", "compose.yml"), fxaCompose)
	f.h.Discover()
	ableAdmin(f.h)
	enableTemplate(t, f, "yubikey-and-certificate")
	if err := saveApp(t, f, "fxa", SettingsUpdate{SignInTemplate: pickTemplate("yubikey-and-certificate")}); err != nil {
		t.Fatal(err)
	}
	return f
}

// routerTiers is routerTiersLocked of id, with its instance tier.
func routerTiers(t *testing.T, f *fixture, id string) (map[string]string, string) {
	t.Helper()
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	tmpl := f.h.findLocked(id)
	if tmpl == nil {
		t.Fatalf("no template %s", id)
	}
	rl, err := f.h.routeLabelsLocked(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	return f.h.routerTiersLocked(tmpl, rl), rl.tier
}

// overrideTier is the tls.options the override gives router r.
func overrideTier(t *testing.T, ov, r string) string {
	t.Helper()
	for _, l := range strings.Split(ov, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ": "); ok && k == "traefik.http.routers."+r+".tls.options" {
			return v
		}
	}
	t.Fatalf("no tls.options for %s in:\n%s", r, ov)
	return ""
}

func TestOpenOnlyHostGetsPublicTier(t *testing.T) {
	f := newFxaFixture(t)
	tiers, inst := routerTiers(t, f, "fxa")
	if inst != policy.TierProtected {
		t.Fatalf("instance tier = %s, want protected@file", inst)
	}
	ov := readOverride(t, f, "fxa")
	for _, r := range []string{"fxa", "fxa-api", "fxa-api-create", "fxa-profile", "fxa-pairing"} {
		if tiers[r] != policy.TierPublic {
			t.Errorf("router %s: tier %q, want public@file", r, tiers[r])
		}
		if got := overrideTier(t, ov, r); got != policy.TierPublic {
			t.Errorf("override %s: tls.options %q, want public@file", r, got)
		}
	}
}

func TestMixedHostDowngradedToDefault(t *testing.T) {
	f := newFxaFixture(t)
	tiers, _ := routerTiers(t, f, "fxa")
	ov := readOverride(t, f, "fxa")
	for _, r := range []string{"fxa-accounts", "fxa-accounts-open"} {
		if tiers[r] != policy.TierDefault {
			t.Errorf("router %s: tier %q, want default", r, tiers[r])
		}
		if got := overrideTier(t, ov, r); got != policy.TierDefault {
			t.Errorf("override %s: tls.options %q, want default", r, got)
		}
	}
}

// Never weaken a gated host: one whose routers all sign in keeps the
// instance tier, and its open_router badges show each host's tier.
func TestGatedOnlyHostKeepsTier(t *testing.T) {
	f := newFxaFixture(t)
	tiers, _ := routerTiers(t, f, "fxa")
	if tiers["fxa-admin"] != policy.TierProtected {
		t.Errorf("fxa-admin: tier %q, want protected@file", tiers["fxa-admin"])
	}
	if got := overrideTier(t, readOverride(t, f, "fxa"), "fxa-admin"); got != policy.TierProtected {
		t.Errorf("override fxa-admin: tls.options %q, want protected@file", got)
	}
	want := map[string]string{"fxa": policy.TierPublic, "fxa-accounts-open": policy.TierDefault, "fxa-api": policy.TierPublic}
	for _, b := range bypassOf(t, f, "fxa") {
		if w, ok := want[b.Router]; ok && b.Kind == BypassOpenRouter && b.Tier != w {
			t.Errorf("badge %s: tier %q, want %q", b.Router, b.Tier, w)
		}
		if b.Kind == BypassWeakTLS {
			t.Errorf("weak_tls on a protected instance: %+v", b)
		}
	}
}

// A custom app without Portcullis sign-in: every router public@file, as
// before.
func TestCustomAppUnchanged(t *testing.T) {
	f := newFxaFixture(t)
	tiers, inst := routerTiers(t, f, "sync")
	if inst != policy.TierPublic || len(tiers) != 2 {
		t.Fatalf("sync: instance tier %s, tiers %v", inst, tiers)
	}
	for r, tier := range tiers {
		if tier != policy.TierPublic {
			t.Errorf("router %s: tier %q, want public@file", r, tier)
		}
	}
}

// Kubernetes: the translator reads the same rendered labels, so each
// IngressRoute carries its host's tier (default: no options at all).
func TestPerHostTierOnKubernetes(t *testing.T) {
	f := newFxaFixture(t)
	f.h.mu.RLock()
	tmpl := f.h.findLocked("fxa")
	rl, err := f.h.routeLabelsLocked(tmpl)
	var mine map[string]map[string]string
	if err == nil {
		mine, err = hubLabels(rl)
	}
	f.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	base, err := templates.ServiceLabels(tmpl.ReadCompose())
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]map[string]string{}
	for svc, l := range base {
		m := map[string]string{}
		for k, v := range l {
			m[k] = strings.ReplaceAll(v, "${PORTCULLIS_DOMAIN:-portcullis.local}", "example.org")
		}
		maps.Copy(m, mine[svc])
		labels[svc] = m
	}
	objs, err := kube.IngressObjects("fxa", kube.EdgeNamespace, "portcullis-apps", labels)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range objs {
		if o.GetKind() != "IngressRoute" {
			continue
		}
		j, _ := json.Marshal(o.Object["spec"])
		var spec struct {
			Routes []struct {
				Match string `json:"match"`
			} `json:"routes"`
			TLS struct {
				Options struct {
					Name string `json:"name"`
				} `json:"options"`
			} `json:"tls"`
		}
		json.Unmarshal(j, &spec)
		opt := spec.TLS.Options.Name
		if opt == "" {
			opt = policy.TierDefault
		}
		for _, r := range spec.Routes {
			got[r.Match] = opt
		}
	}
	want := map[string]string{
		"Host(`fxa-sync.example.org`)":     policy.TierPublic,
		"Host(`fxa-api.example.org`)":      policy.TierPublic,
		"Host(`fxa-accounts.example.org`)": policy.TierDefault,
		"Host(`fxa-admin.example.org`)":    policy.TierProtected,
	}
	for match, w := range want {
		if got[match] != w {
			t.Errorf("%s: options %q, want %q (all: %v)", match, got[match], w, got)
		}
	}
}

// A router spanning two hosts pins the host grouping (both hosts get the same
// tier, the instance tier).
func TestTierTwoHostRouter(t *testing.T) {
	f := newBypassFixture(t)
	ableAdmin(f.h)
	enableTemplate(t, f, "yubikey-and-certificate")
	const manifest = `name: Test
category: productivity
ai: {unsupported: "test"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_test
`
	const compose = `services:
  web:
    image: x
    labels:
      traefik.enable: "true"
      traefik.http.routers.test-web.rule: Host(` + "`web-a.${PORTCULLIS_DOMAIN:-portcullis.local}`) || Host(`web-b.${PORTCULLIS_DOMAIN:-portcullis.local}`)" + `
      traefik.http.routers.test-web.middlewares: portcullis-auth@docker,portcullis-groups@docker
      traefik.http.services.test-web.loadbalancer.server.port: "8000"
`
	writeFile(t, filepath.Join(f.src, "test", "manifest.yaml"), manifest)
	writeFile(t, filepath.Join(f.src, "test", "compose.yml"), compose)
	f.h.Discover()
	if err := saveApp(t, f, "test", SettingsUpdate{SignInTemplate: pickTemplate("yubikey-and-certificate")}); err != nil {
		t.Fatal(err)
	}

	tiers, inst := routerTiers(t, f, "test")
	if inst != policy.TierProtected {
		t.Fatalf("instance tier = %s, want protected@file", inst)
	}
	// Both hosts get the instance tier.
	if tiers["test-web"] != policy.TierProtected {
		t.Errorf("router test-web: tier %q, want %q (the instance tier)", tiers["test-web"], policy.TierProtected)
	}
}

// A router gated only through a template chain middleware keeps the instance tier.
func TestTierChainMiddleware(t *testing.T) {
	f := newBypassFixture(t)
	ableAdmin(f.h)
	enableTemplate(t, f, "yubikey-and-certificate")
	const manifest = `name: Test
category: productivity
ai: {unsupported: "test"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_test
`
	const compose = `services:
  web:
    image: x
    labels:
      traefik.enable: "true"
      traefik.http.routers.test-web.rule: Host(` + "`web.${PORTCULLIS_DOMAIN:-portcullis.local}`)" + `
      traefik.http.routers.test-web.middlewares: test-chain@docker
      traefik.http.middlewares.test-chain.chain.middlewares: portcullis-auth@docker,portcullis-groups@docker
      traefik.http.services.test-web.loadbalancer.server.port: "8000"
`
	writeFile(t, filepath.Join(f.src, "test", "manifest.yaml"), manifest)
	writeFile(t, filepath.Join(f.src, "test", "compose.yml"), compose)
	f.h.Discover()
	if err := saveApp(t, f, "test", SettingsUpdate{SignInTemplate: pickTemplate("yubikey-and-certificate")}); err != nil {
		t.Fatal(err)
	}

	tiers, inst := routerTiers(t, f, "test")
	if inst != policy.TierProtected {
		t.Fatalf("instance tier = %s, want protected@file", inst)
	}
	// The router is gated through a chain middleware, so it keeps the instance tier.
	if tiers["test-web"] != policy.TierProtected {
		t.Errorf("router test-web: tier %q, want %q (the instance tier)", tiers["test-web"], policy.TierProtected)
	}
}
