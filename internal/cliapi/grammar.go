package cliapi

import (
	"golang.org/x/net/publicsuffix"
	"net/netip"
	"regexp"
	"strings"
)

var (
	principalRE  = regexp.MustCompile(`^([us])(p?):([a-z_][a-z0-9._-]{0,31})@([a-z][a-z0-9-]{0,30})$`)
	hostGroupRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	usernameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	accountRE    = regexp.MustCompile(`^[a-z_][a-z0-9._-]{0,31}$`)
	hostIDRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	keyIDReqRE   = regexp.MustCompile(`^[0-9a-f]{16}$`)
	breakglassRE = regexp.MustCompile(`^pc-breakglass:[A-Za-z0-9 ._:@/-]{1,128}$`)
	// hostLabelRE is one host name label, with the ssh_config pattern
	// characters * and ? allowed (contract §18.15).
	hostLabelRE = regexp.MustCompile(`^[A-Za-z0-9*?]([A-Za-z0-9*?-]{0,61}[A-Za-z0-9*?])?$`)
)

// UsernamePlaceholder is the grant account that means "the person's own
// account" (spec §8.4).
const UsernamePlaceholder = "{username}"

// ReservedHostGroupPrefix is reserved for Portcullis's own host groups.
const ReservedHostGroupPrefix = "portcullis-"

// BuiltinAllHostGroup is the built-in host group of every managed host.
const BuiltinAllHostGroup = "all"

// Principal kinds: a person's own account and a shared account live in
// separate namespaces, so a certificate for one can never be accepted for
// the other even when the names collide (contract §18.12).
const (
	PrincipalPersonal = "u"
	PrincipalShared   = "s"
)

// Principal is `<kind>:<account>@<host group>`.
func Principal(kind, account, hostGroup string) string {
	return kind + ":" + account + "@" + hostGroup
}

// ApprovedPrincipal is `<kind>p:<account>@<host group>` (Ruling RR3): the
// principal a grant that went through the privileged path issues. A
// host lists only these for an account that has sudo by any means, so a
// certificate from a plain grant — outstanding or new — never matches.
func ApprovedPrincipal(kind, account, hostGroup string) string {
	return kind + "p:" + account + "@" + hostGroup
}

// ParsePrincipal reports whether s is `<u|s>[p]:<account>@<host group>`
// (contract §18.12); kind is the base kind (u or s) for both namespaces.
// Reservation of `portcullis-*` host groups is sshaccess's check.
func ParsePrincipal(s string) (kind, account, hostGroup string, ok bool) {
	m := principalRE.FindStringSubmatch(s)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[3], m[4], true
}

// IsApprovedPrincipal: s is an up: / sp: principal (a privileged grant's).
func IsApprovedPrincipal(s string) bool {
	m := principalRE.FindStringSubmatch(s)
	return m != nil && m[2] == "p"
}

// ValidHostGroupID is the host group id grammar (without the reservation).
func ValidHostGroupID(s string) bool { return hostGroupRE.MatchString(s) }

// ReservedHostGroupID reports a `portcullis-*` id.
func ReservedHostGroupID(s string) bool { return strings.HasPrefix(s, ReservedHostGroupPrefix) }

// ValidUsername is LLDAP's username grammar.
func ValidUsername(s string) bool { return usernameRE.MatchString(s) }

// ValidAccount is the local account part of a principal (≤ 32 characters,
// no leading digit): what a host can create.
func ValidAccount(s string) bool { return accountRE.MatchString(s) }

// ValidHostID is the managed host id grammar.
func ValidHostID(s string) bool { return hostIDRE.MatchString(s) }

// KeyID is the certificate key id `pc:<user>:<hg>:<16 hex>`.
func KeyID(user, hg, reqHex string) string { return "pc:" + user + ":" + hg + ":" + reqHex }

// ParseKeyID parses and validates a key id made by KeyID.
func ParseKeyID(s string) (user, hg, req string, ok bool) {
	p := strings.Split(s, ":")
	if len(p) != 4 || p[0] != "pc" {
		return "", "", "", false
	}
	if !ValidUsername(p[1]) || !ValidHostGroupID(p[2]) || !keyIDReqRE.MatchString(p[3]) {
		return "", "", "", false
	}
	return p[1], p[2], p[3], true
}

// ValidBreakglassKeyID reports `pc-breakglass:<operator note>`.
func ValidBreakglassKeyID(s string) bool { return breakglassRE.MatchString(s) }

// Extension names (contract §18.7). The order is the canonical one.
const (
	ExtPTY             = "permit-pty"
	ExtPortForwarding  = "permit-port-forwarding"
	ExtAgentForwarding = "permit-agent-forwarding"
)

// ExtensionSets are the only four allowed_extensions strings.
var ExtensionSets = []string{
	ExtPTY,
	ExtPTY + "," + ExtPortForwarding,
	ExtPTY + "," + ExtAgentForwarding,
	ExtPTY + "," + ExtPortForwarding + "," + ExtAgentForwarding,
}

// CanonicalExtensions is the canonical comma string for a grant ceiling.
func CanonicalExtensions(portForwarding, agentForwarding bool) string {
	return strings.Join(ExtensionList(portForwarding, agentForwarding), ",")
}

// ExtensionList is CanonicalExtensions as a list.
func ExtensionList(portForwarding, agentForwarding bool) []string {
	out := []string{ExtPTY}
	if portForwarding {
		out = append(out, ExtPortForwarding)
	}
	if agentForwarding {
		out = append(out, ExtAgentForwarding)
	}
	return out
}

// ValidExtensionSet reports one of the four canonical strings.
func ValidExtensionSet(s string) bool {
	for _, e := range ExtensionSets {
		if s == e {
			return true
		}
	}
	return false
}

// Role TTL bounds (contract §18.7: whole hours, at most 12 h).
const (
	MinRoleTTLSeconds = 3600
	MaxRoleTTLSeconds = 43200
	MinCertSeconds    = 300
	MaxCertSeconds    = 43200
)

// RoundRoleTTL rounds seconds up to a whole hour and reports whether the
// result is one of the twelve allowed role TTLs.
func RoundRoleTTL(seconds int) (int, bool) {
	if seconds <= 0 {
		return 0, false
	}
	h := (seconds + 3599) / 3600 * 3600
	return h, h >= MinRoleTTLSeconds && h <= MaxRoleTTLSeconds
}

// ValidHostPattern is a name clients may match a host by (ssh_config
// `Match host`, known_hosts): an IPv4 or IPv6 address without a zone, or
// dot-separated host name labels where * and ? are the only pattern
// characters, optionally preceded by one ! (negation). No whitespace,
// commas, quotes or control characters can pass, so a value can never
// add an ssh_config keyword or a known_hosts field.
func ValidHostPattern(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == ""
	}
	s = strings.TrimPrefix(s, "!")
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !hostLabelRE.MatchString(l) {
			return false
		}
	}
	return narrowPattern(labels)
}

// narrowPattern (final review M9): a pattern with * or ? must keep a
// literal suffix longer than its public suffix — at least a registrable
// domain like lab.example.org in *.lab.example.org. `*`, `*.org`,
// `web-?.org` or `*.lab` (an unlisted TLD counts as one public suffix)
// would point every member's ssh (IdentitiesOnly) and the Portcullis host
// CA (@cert-authority) at hosts far beyond the operator's own. A name
// without pattern characters is one host and always fine.
func narrowPattern(labels []string) bool {
	i := len(labels)
	for i > 0 && !strings.ContainsAny(labels[i-1], "*?") {
		i--
	}
	if i == 0 {
		return true
	}
	lit := strings.ToLower(strings.Join(labels[i:], "."))
	if lit == "" {
		return false
	}
	ps, _ := publicsuffix.PublicSuffix(lit)
	return len(lit) > len(ps)
}

// ValidHostName is ValidHostPattern without pattern characters: a host's
// own name or address (an admin entry, a host certificate principal).
func ValidHostName(s string) bool {
	return ValidHostPattern(s) && !strings.ContainsAny(s, "*?!")
}

// ValidDomain is a DNS name with at least two labels and no pattern
// characters.
func ValidDomain(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	return ValidHostName(s) && strings.Contains(s, ".")
}
