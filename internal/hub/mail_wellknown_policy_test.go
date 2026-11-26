package hub

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

// policyGroups writes the policy file and answers its groups.
func policyGroups(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups map[string]string `json:"groups"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(f.data, "group-gate-policy.json"))), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Groups
}

// wkService is the stalwart-shaped fixture's mail.wellknown.service.
func wkService(t *testing.T, f *fixture) string {
	t.Helper()
	v := f.h.Template(mailProviderID)
	if v == nil || v.Manifest.Mail == nil || v.Manifest.Mail.Wellknown.Service == "" {
		t.Fatal("no wellknown service in the fixture")
	}
	return v.Manifest.Mail.Wellknown.Service
}

// setRoutes sets what Reconcile last saw.
func setRoutes(f *fixture, hosts map[string][]string, wk map[string]mailWKRoutes) {
	f.h.driftMu.Lock()
	f.h.runtimeHosts, f.h.runtimeMailWK = hosts, wk
	f.h.driftMu.Unlock()
}

var wkHosts = []string{"mta-sts.example.org", "autoconfig.example.org", "autodiscover.example.org"}

// TestPolicyKeepsMailWellknownHosts (issue 5, review N8): the wired mail
// provider's portcullis-mail-wellknown router, on its manifest's
// wellknown service, in normal mode, routes mta-sts / autoconfig /
// autodiscover of every mail domain (contract §5): the policy file
// publishes no deny entry for exactly those hosts. Any other host the
// project routes stays denied.
func TestPolicyKeepsMailWellknownHosts(t *testing.T) {
	f := mailOverrideFixture(t)
	svc := wkService(t, f)
	setRoutes(f, map[string][]string{mailProviderID: append(append([]string{}, wkHosts...), "rogue.example.org")},
		map[string]mailWKRoutes{mailProviderID: {byService: map[string][]string{svc: {"mta-sts.example.org", "Autoconfig.example.org", "autodiscover.example.org"}},
			other: map[string]bool{"rogue.example.org": true}}})
	g := policyGroups(t, f)
	for _, h := range wkHosts {
		if g[h] == policy.DenyGroup {
			t.Errorf("%s is denied: the Hub's own well-known router counted as unknown config", h)
		}
	}
	if g["rogue.example.org"] != policy.DenyGroup {
		t.Errorf("rogue.example.org = %q, want denied", g["rogue.example.org"])
	}
}

// TestPolicyDeniesOtherWellknownRoutes (review N8, R4): a well-known host
// on any other router, on another service's copy of the Hub's router
// name, in another project, or in void mode keeps its deny entry, and so
// does a host that isn't a mail well-known name on the Hub's own rule.
func TestPolicyDeniesOtherWellknownRoutes(t *testing.T) {
	cases := []struct {
		name string
		set  func(f *fixture, svc string)
	}{
		{"another router of the provider project", func(f *fixture, svc string) {
			setRoutes(f, map[string][]string{mailProviderID: wkHosts},
				map[string]mailWKRoutes{mailProviderID: {byService: map[string][]string{svc: wkHosts}, other: map[string]bool{"mta-sts.example.org": true, "autoconfig.example.org": true, "autodiscover.example.org": true}}})
		}},
		{"the router name on another service", func(f *fixture, svc string) {
			setRoutes(f, map[string][]string{mailProviderID: wkHosts},
				map[string]mailWKRoutes{mailProviderID: {byService: map[string][]string{svc + "-other": wkHosts}, other: map[string]bool{}}})
		}},
		{"another project", func(f *fixture, svc string) {
			setRoutes(f, map[string][]string{"other": wkHosts},
				map[string]mailWKRoutes{"other": {byService: map[string][]string{svc: wkHosts}, other: map[string]bool{}}})
		}},
		{"a non-well-known host on the Hub's router", func(f *fixture, svc string) {
			hosts := append(append([]string{}, wkHosts...), "rogue.example.org")
			setRoutes(f, map[string][]string{mailProviderID: hosts},
				map[string]mailWKRoutes{mailProviderID: {byService: map[string][]string{svc: {"rogue.example.org"}}, other: map[string]bool{}}})
		}},
		{"void mode", func(f *fixture, svc string) {
			setRoutes(f, map[string][]string{mailProviderID: wkHosts},
				map[string]mailWKRoutes{mailProviderID: {byService: map[string][]string{svc: wkHosts}, other: map[string]bool{}}})
			f.h.mu.Lock()
			if err := f.h.markVoidOwedLocked(state.MailVoidRestore); err != nil {
				t.Fatal(err)
			}
			f.h.mu.Unlock()
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := mailOverrideFixture(t)
			c.set(f, wkService(t, f))
			g := policyGroups(t, f)
			check := wkHosts
			if c.name == "a non-well-known host on the Hub's router" {
				// Review R4: only mailWellknownHostsLocked's names are
				// exempt, even on the Hub's own rule.
				check = []string{"rogue.example.org"}
			}
			for _, h := range check {
				if g[h] != policy.DenyGroup {
					t.Errorf("%s = %q, want denied", h, g[h])
				}
			}
		})
	}
}

// TestReconcileRecordsMailWellknownRouter (review N8): Reconcile records
// the Hub's router's hosts per compose service, and every other router's
// hosts apart, from the containers' labels (any key case).
func TestReconcileRecordsMailWellknownRouter(t *testing.T) {
	f := mailOverrideFixture(t)
	svc := wkService(t, f)
	project := ProjectPrefix + mailProviderID
	wk := container("wk", project, svc, "running")
	wk.Labels["Traefik.HTTP.Routers."+MailWellknownRouter+".Rule"] = "Host(`mta-sts.example.org`) || Host(`autoconfig.example.org`)"
	wk.Labels["traefik.http.routers.extra.rule"] = "Host(`autoconfig.example.org`)"
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers, wk)
	f.engine.mu.Unlock()
	f.h.Reconcile(context.Background())
	f.h.driftMu.Lock()
	r := f.h.runtimeMailWK[mailProviderID]
	f.h.driftMu.Unlock()
	if got := r.byService[svc]; len(got) != 2 {
		t.Errorf("byService[%s] = %v", svc, got)
	}
	if !r.other["autoconfig.example.org"] || r.other["mta-sts.example.org"] {
		t.Errorf("other = %v", r.other)
	}
	// mta-sts only on the Hub's router: exempt; autoconfig also on
	// "extra": denied.
	g := policyGroups(t, f)
	if g["mta-sts.example.org"] == policy.DenyGroup || g["autoconfig.example.org"] != policy.DenyGroup {
		t.Errorf("mta-sts = %q, autoconfig = %q", g["mta-sts.example.org"], g["autoconfig.example.org"])
	}
}
