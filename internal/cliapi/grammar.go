package cliapi

import (
	"regexp"
	"strings"
)

var (
	principalRE  = regexp.MustCompile(`^([a-z_][a-z0-9._-]{0,31})@([a-z][a-z0-9-]{0,30})$`)
	hostGroupRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	usernameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	accountRE    = regexp.MustCompile(`^[a-z_][a-z0-9._-]{0,31}$`)
	hostIDRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	keyIDReqRE   = regexp.MustCompile(`^[0-9a-f]{16}$`)
	breakglassRE = regexp.MustCompile(`^pc-breakglass:[A-Za-z0-9 ._:@/-]{1,128}$`)
)

// UsernamePlaceholder is the grant account that means "the person's own
// account" (spec §8.4).
const UsernamePlaceholder = "{username}"

// ReservedHostGroupPrefix is reserved for Portcullis's own host groups.
const ReservedHostGroupPrefix = "portcullis-"

// BuiltinAllHostGroup is the built-in host group of every managed host.
const BuiltinAllHostGroup = "all"

// ValidPrincipal reports whether s is `<account>@<host group>` (contract
// §18.12). Reservation of `portcullis-*` host groups is sshaccess's check.
func ValidPrincipal(s string) (account, hostGroup string, ok bool) {
	m := principalRE.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
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
