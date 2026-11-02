package policy

import (
	"reflect"
	"testing"
)

// TestPolicyFileV5KeyedByHost verifies version 5 keys by full hostname, not
// subdomain, for instances on the main domain and on enrolled domains.
func TestPolicyFileV5KeyedByHost(t *testing.T) {
	extraDomain := "team-b.example.org"

	webauthn := AuthPolicy{Factors: []string{"webauthn"}}
	mtls := AuthPolicy{Factors: []string{"mtls"}}

	apps := []App{
		// Default instance on main domain: subdomain grafana-team-a
		{ID: "grafana-team-a", Enabled: true,
			Hosts:       map[string]string{"grafana-team-a.portcullis.example.com": "grafana-team-a.portcullis.example.com"},
			GroupAccess: true, AccessGroup: "users_grafana-team-a"},
		// Instance on extra domain
		{ID: "grafana-team-b", Enabled: true,
			Hosts:       map[string]string{"grafana.team-b.example.org": "grafana.team-b.example.org"},
			GroupAccess: true, AccessGroup: "users_grafana-team-b"},
		// Vaultwarden on main domain with admin paths
		{ID: "vaultwarden", Enabled: true,
			Hosts:       map[string]string{"passwords.portcullis.example.com": "passwords.portcullis.example.com"},
			GroupAccess: true, AccessGroup: "users_vaultwarden",
			AdminGroup: "admin_vaultwarden", AdminPaths: []string{"/admin"}},
	}

	perApp := map[string]AuthPolicy{
		"grafana-team-a": {Factors: []string{"webauthn"}},
		"grafana-team-b": mtls,
	}

	doc := Build(apps, perApp, webauthn, []string{extraDomain})

	if doc.Version != 5 {
		t.Errorf("version = %d, want 5", doc.Version)
	}

	// Keys must be full hostnames, not subdomains
	wantPolicies := map[string]AuthPolicy{
		"grafana-team-a.portcullis.example.com": {Factors: []string{"webauthn"}},
		"grafana.team-b.example.org":            mtls,
	}
	if !reflect.DeepEqual(doc.Policies, wantPolicies) {
		t.Errorf("policies = %+v\nwant %+v", doc.Policies, wantPolicies)
	}

	wantGroups := map[string]string{
		"grafana-team-a.portcullis.example.com": "users_grafana-team-a",
		"grafana.team-b.example.org":            "users_grafana-team-b",
		"passwords.portcullis.example.com":      "users_vaultwarden",
	}
	if !reflect.DeepEqual(doc.Groups, wantGroups) {
		t.Errorf("groups = %v\nwant %v", doc.Groups, wantGroups)
	}

	wantPG := map[string][]PathGroup{
		"passwords.portcullis.example.com": {{"/admin", "admin_vaultwarden"}},
	}
	if !reflect.DeepEqual(doc.PathGroups, wantPG) {
		t.Errorf("path_groups = %+v\nwant %+v", doc.PathGroups, wantPG)
	}

	// extra_domains must list the enrolled domain
	if len(doc.ExtraDomains) != 1 || doc.ExtraDomains[0] != extraDomain {
		t.Errorf("extra_domains = %v, want [%s]", doc.ExtraDomains, extraDomain)
	}
}

// TestCoreHostsNeverPublished verifies Build doesn't publish core hosts (the
// Hub filters them before calling Build).
func TestCoreHostsNeverPublished(t *testing.T) {
	mainDomain := "portcullis.example.com"

	apps := []App{
		// A normal app
		{ID: "grafana", Enabled: true,
			Hosts:       map[string]string{"grafana." + mainDomain: "grafana." + mainDomain},
			GroupAccess: true, AccessGroup: "users_grafana"},
	}

	doc := Build(apps, nil, AuthPolicy{}, []string{})

	// Core hosts must never appear in any map
	coreHosts := CoreHosts(mainDomain)
	for host := range coreHosts {
		if _, ok := doc.Policies[host]; ok {
			t.Errorf("core host %s in policies", host)
		}
		if _, ok := doc.Groups[host]; ok {
			t.Errorf("core host %s in groups", host)
		}
		if _, ok := doc.PathGroups[host]; ok {
			t.Errorf("core host %s in path_groups", host)
		}
	}

	// The normal app should be there
	if doc.Groups["grafana."+mainDomain] != "users_grafana" {
		t.Errorf("normal app not in groups")
	}
}

// TestDenyGroupForUnknownRunningHosts verifies running apps with no config
// get DenyGroup keyed by their full hostname.
func TestDenyGroupForUnknownRunningHosts(t *testing.T) {
	apps := []App{
		// Known app with config
		{ID: "known", Enabled: true,
			Hosts:       map[string]string{"known.portcullis.example.com": "known.portcullis.example.com"},
			GroupAccess: true, AccessGroup: "users_known"},
		// Running app with no config (Deny = true, keyed by host)
		{ID: "ghost", Enabled: true, Deny: true,
			Hosts: map[string]string{"ghost.portcullis.example.com": "ghost.portcullis.example.com"}},
	}

	doc := Build(apps, nil, AuthPolicy{}, nil)

	if doc.Groups["ghost.portcullis.example.com"] != DenyGroup {
		t.Errorf("ghost host = %q, want %q", doc.Groups["ghost.portcullis.example.com"], DenyGroup)
	}

	// Known app must not be affected
	if doc.Groups["known.portcullis.example.com"] != "users_known" {
		t.Errorf("known host = %q", doc.Groups["known.portcullis.example.com"])
	}
}
