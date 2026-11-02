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

	doc := Build(apps, perApp, webauthn, "portcullis.example.com", []string{extraDomain})

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

// TestCoreHostsNeverPublished feeds every core host to Build — as app
// hosts, public hosts and deny hosts — and checks none is published (they
// come from group-gate-map.conf, contract §4).
func TestCoreHostsNeverPublished(t *testing.T) {
	mainDomain := "portcullis.example.com"
	core := CoreHosts(mainDomain)
	if len(core) != 8 || !core[mainDomain] || !core["people."+mainDomain] || !core["metrics."+mainDomain] {
		t.Fatalf("CoreHosts = %v", core)
	}
	all := map[string]string{"grafana." + mainDomain: "grafana." + mainDomain}
	for h := range core {
		all[h] = h
	}
	pub := &PublicEntry{Paths: []PublicPath{{"/s", "prefix"}}}
	apps := []App{
		{ID: "grafana", Enabled: true, Hosts: all, PublicHosts: all, Public: pub,
			GroupAccess: true, AccessGroup: "users_grafana", AdminGroup: "admin_grafana", AdminPaths: []string{"/admin"}},
		{ID: "ghost", Enabled: true, Deny: true, Hosts: all},
	}
	doc := Build(apps, map[string]AuthPolicy{"grafana": {}}, AuthPolicy{}, mainDomain, nil)
	for host := range core {
		if _, ok := doc.Policies[host]; ok {
			t.Errorf("core host %s in policies", host)
		}
		if _, ok := doc.Groups[host]; ok {
			t.Errorf("core host %s in groups", host)
		}
		if _, ok := doc.PathGroups[host]; ok {
			t.Errorf("core host %s in path_groups", host)
		}
		if _, ok := doc.PublicPaths[host]; ok {
			t.Errorf("core host %s in public_paths", host)
		}
	}
	g := "grafana." + mainDomain
	if doc.Groups[g] != "users_grafana" || len(doc.PathGroups[g]) != 1 || len(doc.PublicPaths) != 1 || len(doc.Groups) != 1 {
		t.Errorf("normal host: groups %v path_groups %v public %v", doc.Groups, doc.PathGroups, doc.PublicPaths)
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

	doc := Build(apps, nil, AuthPolicy{}, "portcullis.example.com", nil)

	if doc.Groups["ghost.portcullis.example.com"] != DenyGroup {
		t.Errorf("ghost host = %q, want %q", doc.Groups["ghost.portcullis.example.com"], DenyGroup)
	}

	// Known app must not be affected
	if doc.Groups["known.portcullis.example.com"] != "users_known" {
		t.Errorf("known host = %q", doc.Groups["known.portcullis.example.com"])
	}
}
