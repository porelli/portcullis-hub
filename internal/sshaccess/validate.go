package sshaccess

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/state"
)

var (
	dnsNameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	patternRE = regexp.MustCompile(`^(?i)(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	grantIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ValidHostName is a DNS name or an IP address (a host's names, a host
// certificate's principals).
func ValidHostName(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return len(s) <= 253 && dnsNameRE.MatchString(s)
}

// ValidPattern is an unmanaged host name pattern: a DNS name, optionally
// starting with "*." (ssh_config Match host syntax).
func ValidPattern(s string) bool { return len(s) <= 253 && patternRE.MatchString(s) }

// ValidGrantAccount is "{username}" or a local account name.
func ValidGrantAccount(a string) bool {
	return a == cliapi.UsernamePlaceholder || cliapi.ValidAccount(a)
}

// Validate checks s's shape (contract §18.12). The messages name the
// offending id, never anything else.
func Validate(s state.SSHState) error {
	if s.Settings.DefaultTTLHours < 0 || s.Settings.DefaultTTLHours > 12 {
		return fmt.Errorf("the default certificate lifetime must be 1–12 hours")
	}
	if len(s.HostGroups) > cliapi.MaxHostGroups {
		return fmt.Errorf("at most %d host groups", cliapi.MaxHostGroups)
	}
	if _, ok := s.HostGroups[cliapi.BuiltinAllHostGroup]; !ok {
		return fmt.Errorf("the built-in host group %q is missing", cliapi.BuiltinAllHostGroup)
	}
	for id, g := range s.HostGroups {
		if !cliapi.ValidHostGroupID(id) {
			return fmt.Errorf("host group %q: an id is a lowercase letter, then up to 30 lowercase letters, digits or dashes", id)
		}
		if cliapi.ReservedHostGroupID(id) {
			return fmt.Errorf("host group %q: portcullis-* ids are reserved", id)
		}
		if len(g.SourceCIDRs) > cliapi.MaxSourceCIDRs {
			return fmt.Errorf("host group %q: at most %d source addresses", id, cliapi.MaxSourceCIDRs)
		}
		for _, c := range g.SourceCIDRs {
			if _, err := netip.ParsePrefix(c); err != nil {
				return fmt.Errorf("host group %q: %q is not a CIDR", id, c)
			}
		}
		if len(g.Patterns) > 64 {
			return fmt.Errorf("host group %q: at most 64 patterns", id)
		}
		for _, p := range g.Patterns {
			if !ValidPattern(p) {
				return fmt.Errorf("host group %q: %q is not a host name pattern", id, p)
			}
		}
		if len(g.Label) > 64 || len(g.Description) > 512 {
			return fmt.Errorf("host group %q: label or description too long", id)
		}
	}
	for id, h := range s.Hosts {
		if !cliapi.ValidHostID(id) {
			return fmt.Errorf("host %q: a host id is lowercase letters, digits and dashes", id)
		}
		if len(h.Names)+len(h.Addrs) == 0 || len(h.Names)+len(h.Addrs) > 32 {
			return fmt.Errorf("host %q: 1–32 names and addresses", id)
		}
		for _, n := range h.Names {
			if !ValidHostName(n) {
				return fmt.Errorf("host %q: %q is not a host name", id, n)
			}
		}
		for _, a := range h.Addrs {
			if _, err := netip.ParseAddr(a); err != nil {
				return fmt.Errorf("host %q: %q is not an IP address", id, a)
			}
		}
		for _, g := range h.HostGroups {
			if _, ok := s.HostGroups[g]; !ok {
				return fmt.Errorf("host %q: no host group %q", id, g)
			}
		}
	}
	if len(s.Grants) > cliapi.MaxGrants {
		return fmt.Errorf("at most %d grants", cliapi.MaxGrants)
	}
	seen := map[string]bool{}
	for _, g := range s.Grants {
		if err := ValidateGrant(s, g); err != nil {
			return err
		}
		if seen[g.ID] {
			return fmt.Errorf("grant %q: the id is used twice", g.ID)
		}
		seen[g.ID] = true
	}
	return nil
}

// ValidateGrant checks one grant against s's host groups.
func ValidateGrant(s state.SSHState, g state.SSHGrant) error {
	if !grantIDRE.MatchString(g.ID) {
		return fmt.Errorf("grant %q: bad id", g.ID)
	}
	if g.Group == "" || len(g.Group) > 128 || strings.ContainsAny(g.Group, "\n\r\x00") {
		return fmt.Errorf("grant %q: no group", g.ID)
	}
	if _, ok := s.HostGroups[g.HostGroup]; !ok {
		return fmt.Errorf("grant %q: no host group %q", g.ID, g.HostGroup)
	}
	if len(g.Accounts) == 0 || len(g.Accounts) > 16 {
		return fmt.Errorf("grant %q: 1–16 accounts", g.ID)
	}
	seen := map[string]bool{}
	for _, a := range g.Accounts {
		if !ValidGrantAccount(a) {
			return fmt.Errorf("grant %q: %q is neither {username} nor an account name", g.ID, a)
		}
		if seen[a] {
			return fmt.Errorf("grant %q: account %q listed twice", g.ID, a)
		}
		seen[a] = true
	}
	if g.Sudo != state.SudoNone && g.Sudo != state.SudoFull {
		return fmt.Errorf("grant %q: sudo is none or full", g.ID)
	}
	if g.TTLHours < 0 || g.TTLHours > 12 {
		return fmt.Errorf("grant %q: the lifetime must be 1–12 hours", g.ID)
	}
	return nil
}
