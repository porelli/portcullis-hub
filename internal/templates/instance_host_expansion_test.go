package templates

import (
	"strings"
	"testing"
)

// TestHostVariableExpansionInKeycloakClients verifies {{HOST_<ROUTER>}}
// placeholders are expanded with the instance's hostnames in Keycloak client
// redirect URIs (contract §3.1).
func TestHostVariableExpansionInKeycloakClients(t *testing.T) {
	domain := "portcullis.example.com"
	extraDomain := "team-b.example.org"

	// Template with Keycloak clients using {{HOST_*}} placeholders
	rawManifest := &Manifest{
		Instances: "multi",
		URLs: []AppURL{
			{Label: "App", URL: "https://{{HOST_GRAFANA}}"},
		},
		Clients: []KeycloakClient{
			{
				ClientID:    "grafana",
				RedirectURI: "https://{{HOST_GRAFANA}}/oauth/callback",
				RedirectURIs: []string{
					"https://{{HOST_GRAFANA}}/oauth/callback",
					"https://{{HOST_GRAFANA}}/login/generic_oauth",
				},
				BackchannelLogoutURL: "https://{{HOST_GRAFANA}}/logout",
			},
		},
	}

	// Template with one host router
	tpl := &Template{
		ID:          "grafana",
		TemplateID:  "grafana",
		HostRouters: map[string]string{"grafana": "grafana"},
		raw:         rawManifest,
	}

	// Test 1: Default instance on main domain
	defaultInstance, err := tpl.Instance("grafana", nil, domain)
	if err != nil {
		t.Fatalf("default instance: %v", err)
	}

	// Verify URLs expanded
	if len(defaultInstance.Manifest.URLs) != 1 {
		t.Fatalf("URLs length = %d", len(defaultInstance.Manifest.URLs))
	}
	wantURL := "https://grafana." + domain
	if defaultInstance.Manifest.URLs[0].URL != wantURL {
		t.Errorf("URL = %s, want %s", defaultInstance.Manifest.URLs[0].URL, wantURL)
	}

	// Verify Keycloak client URIs expanded
	if len(defaultInstance.Manifest.Clients) != 1 {
		t.Fatalf("clients length = %d", len(defaultInstance.Manifest.Clients))
	}
	c := defaultInstance.Manifest.Clients[0]
	wantRedirect := "https://grafana." + domain + "/oauth/callback"
	if c.RedirectURI != wantRedirect {
		t.Errorf("RedirectURI = %s, want %s", c.RedirectURI, wantRedirect)
	}
	if len(c.RedirectURIs) != 2 {
		t.Fatalf("RedirectURIs length = %d", len(c.RedirectURIs))
	}
	if c.RedirectURIs[0] != wantRedirect {
		t.Errorf("RedirectURIs[0] = %s, want %s", c.RedirectURIs[0], wantRedirect)
	}
	wantGeneric := "https://grafana." + domain + "/login/generic_oauth"
	if c.RedirectURIs[1] != wantGeneric {
		t.Errorf("RedirectURIs[1] = %s, want %s", c.RedirectURIs[1], wantGeneric)
	}
	wantLogout := "https://grafana." + domain + "/logout"
	if c.BackchannelLogoutURL != wantLogout {
		t.Errorf("BackchannelLogoutURL = %s, want %s", c.BackchannelLogoutURL, wantLogout)
	}

	// Test 2: Instance on extra domain
	extra := func(h string) bool { return strings.HasSuffix(h, "."+extraDomain) }
	instanceHosts := map[string]string{"grafana": "grafana." + extraDomain}
	extraInstance, err := tpl.InstanceOn("grafana-team-b", instanceHosts, domain, extra)
	if err != nil {
		t.Fatalf("extra-domain instance: %v", err)
	}

	// Verify URLs expanded with extra-domain hostname
	if len(extraInstance.Manifest.URLs) != 1 {
		t.Fatalf("extra URLs length = %d", len(extraInstance.Manifest.URLs))
	}
	wantExtraURL := "https://grafana." + extraDomain
	if extraInstance.Manifest.URLs[0].URL != wantExtraURL {
		t.Errorf("extra URL = %s, want %s", extraInstance.Manifest.URLs[0].URL, wantExtraURL)
	}

	// Verify Keycloak client URIs expanded with extra-domain hostname
	if len(extraInstance.Manifest.Clients) != 1 {
		t.Fatalf("extra clients length = %d", len(extraInstance.Manifest.Clients))
	}
	ec := extraInstance.Manifest.Clients[0]
	wantExtraRedirect := "https://grafana." + extraDomain + "/oauth/callback"
	if ec.RedirectURI != wantExtraRedirect {
		t.Errorf("extra RedirectURI = %s, want %s", ec.RedirectURI, wantExtraRedirect)
	}
	if len(ec.RedirectURIs) != 2 {
		t.Fatalf("extra RedirectURIs length = %d", len(ec.RedirectURIs))
	}
	if ec.RedirectURIs[0] != wantExtraRedirect {
		t.Errorf("extra RedirectURIs[0] = %s, want %s", ec.RedirectURIs[0], wantExtraRedirect)
	}
	wantExtraGeneric := "https://grafana." + extraDomain + "/login/generic_oauth"
	if ec.RedirectURIs[1] != wantExtraGeneric {
		t.Errorf("extra RedirectURIs[1] = %s, want %s", ec.RedirectURIs[1], wantExtraGeneric)
	}
	wantExtraLogout := "https://grafana." + extraDomain + "/logout"
	if ec.BackchannelLogoutURL != wantExtraLogout {
		t.Errorf("extra BackchannelLogoutURL = %s, want %s", ec.BackchannelLogoutURL, wantExtraLogout)
	}
}

// Only the hosts of the routers the template marks public carry the public
// exception — never every host of the instance — and an extra-domain host
// of a public router is included (full hostname, no subdomain).
func TestPublicHostsOnlyPublicRouters(t *testing.T) {
	domain := "portcullis.example.com"
	tpl := &Template{
		ID:          "cloud",
		TemplateID:  "cloud",
		HostRouters: map[string]string{"web": "cloud", "admin": "cloud-admin"},
		Subdomains:  []string{"cloud", "cloud-admin"},
		Public:      &PublicPlan{Service: "web", Subdomains: []string{"cloud"}},
		raw:         &Manifest{Instances: "multi"},
	}
	main, err := tpl.Instance("cloud-b", map[string]string{"web": "cloud-b." + domain, "admin": "cloud-b-admin." + domain}, domain)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(main.Public.Hosts, ","); got != "cloud-b."+domain {
		t.Errorf("main domain: public hosts = %s, want only the public router's host", got)
	}
	if got := strings.Join(main.Public.Subdomains, ","); got != "cloud-b" {
		t.Errorf("main domain: public subdomains = %s", got)
	}
	extra := func(h string) bool { return strings.HasSuffix(h, ".team-b.example.org") }
	ex, err := tpl.InstanceOn("cloud-c", map[string]string{"web": "files.team-b.example.org", "admin": "cloud-c-admin." + domain}, domain, extra)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ex.Public.Hosts, ","); got != "files.team-b.example.org" {
		t.Errorf("extra domain: public hosts = %s, want the extra-domain host only", got)
	}
	if len(ex.Public.Subdomains) != 0 {
		t.Errorf("extra domain: public subdomains = %v", ex.Public.Subdomains)
	}
	// The admin router is public instead: only its host.
	tpl.Public = &PublicPlan{Service: "admin", Subdomains: []string{"cloud-admin"}}
	adm, err := tpl.InstanceOn("cloud-c", map[string]string{"web": "files.team-b.example.org", "admin": "cloud-c-admin." + domain}, domain, extra)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(adm.Public.Hosts, ","); got != "cloud-c-admin."+domain {
		t.Errorf("admin public: public hosts = %s", got)
	}
}
