package cliapi

import (
	"sort"
	"strings"
)

// ClientGroup is one host group of the person's SSH client config: its
// names (managed hosts' names and addresses, plus the group's patterns
// for unmanaged hosts).
type ClientGroup struct {
	HostGroup string
	Hosts     []string
}

// ClientDir is the CLI's directory for a domain, as ssh_config writes it.
func ClientDir(domain string) string { return "~/.ssh/portcullis/" + domain }

// IncludeLine is the one line `ssh-config --install` adds to ~/.ssh/config.
const IncludeLine = "Include ~/.ssh/portcullis/*/config"

// ClientConfig is ~/.ssh/portcullis/<domain>/config (spec §6): one Match
// block per host group with names, sorted by host group. A group without
// names gets no block (ssh still tries every agent identity).
func ClientConfig(domain string, groups []ClientGroup) string {
	gs := append([]ClientGroup(nil), groups...)
	sort.Slice(gs, func(i, j int) bool { return gs[i].HostGroup < gs[j].HostGroup })
	dir := ClientDir(domain)
	var b strings.Builder
	b.WriteString("# Written by portcullis login for " + domain + ". Do not edit.\n")
	for _, g := range gs {
		if len(g.Hosts) == 0 {
			continue
		}
		b.WriteString("Match host " + strings.Join(g.Hosts, ",") + "\n")
		b.WriteString("  IdentityFile " + dir + "/id.pub\n")
		b.WriteString("  CertificateFile " + dir + "/" + g.HostGroup + "-cert.pub\n")
		b.WriteString("  IdentitiesOnly yes\n")
		b.WriteString("  UserKnownHostsFile ~/.ssh/known_hosts " + dir + "/known_hosts\n")
	}
	return b.String()
}

// KnownHosts is ~/.ssh/portcullis/<domain>/known_hosts (spec §8.10): an
// @cert-authority line per host group scoped to its names, and an
// @revoked line per revoked host key.
func KnownHosts(groups []ClientGroup, hostCAs, revokedHostKeys []string) string {
	gs := append([]ClientGroup(nil), groups...)
	sort.Slice(gs, func(i, j int) bool { return gs[i].HostGroup < gs[j].HostGroup })
	var b strings.Builder
	for _, g := range gs {
		if len(g.Hosts) == 0 {
			continue
		}
		for _, ca := range hostCAs {
			b.WriteString("@cert-authority " + strings.Join(g.Hosts, ",") + " " + ca + "\n")
		}
	}
	for _, k := range revokedHostKeys {
		b.WriteString("@revoked * " + k + "\n")
	}
	return b.String()
}
