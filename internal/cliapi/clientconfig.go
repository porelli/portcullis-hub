package cliapi

import (
	"errors"
	"fmt"
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

// checkGroups refuses any value that isn't in its strict grammar: the
// renderers never write one (the Hub's answer is untrusted on the CLI).
func checkGroups(domain string, groups []ClientGroup) error {
	if !ValidDomain(domain) {
		return errors.New("the domain is not a valid DNS name")
	}
	for _, g := range groups {
		if !ValidHostGroupID(g.HostGroup) {
			return fmt.Errorf("host group %q is not a valid id", clipQ(g.HostGroup))
		}
		for _, h := range g.Hosts {
			if !ValidHostPattern(h) {
				return fmt.Errorf("host group %s: %q is not a host name, address or pattern", g.HostGroup, clipQ(h))
			}
		}
	}
	return nil
}

func clipQ(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// ClientConfig is ~/.ssh/portcullis/<domain>/config (spec §6): one Match
// block per host group with names, sorted by host group. A group without
// names gets no block (ssh still tries every agent identity). Any value
// outside its grammar is an error and nothing is rendered.
func ClientConfig(domain string, groups []ClientGroup) (string, error) {
	if err := checkGroups(domain, groups); err != nil {
		return "", err
	}
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
	return b.String(), nil
}

// KnownHosts is ~/.ssh/portcullis/<domain>/known_hosts (spec §8.10): an
// @cert-authority line per host group scoped to its names, and an
// @revoked line per revoked host key. Names must pass ValidHostPattern and
// keys must be single public keys (ParseAuthorizedKey); they are written
// in their normal form. Anything else is an error, nothing is rendered.
func KnownHosts(domain string, groups []ClientGroup, hostCAs, revokedHostKeys []string) (string, error) {
	if err := checkGroups(domain, groups); err != nil {
		return "", err
	}
	norm := func(keys []string) ([]string, error) {
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			_, n, err := ParseAuthorizedKey(k)
			if err != nil {
				return nil, errors.New("a host CA or revoked host key is not a public key")
			}
			out = append(out, n)
		}
		return out, nil
	}
	cas, err := norm(hostCAs)
	if err != nil {
		return "", err
	}
	revoked, err := norm(revokedHostKeys)
	if err != nil {
		return "", err
	}
	hostCAs, revokedHostKeys = cas, revoked
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
	return b.String(), nil
}
