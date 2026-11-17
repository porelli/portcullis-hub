package state

import (
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

// SSHState is Hub → SSH access (contract §18.12): the mapping from LLDAP
// groups to grants, host groups, hosts and accounts. The source of truth;
// Vault roles and host bundles are compiled from it (internal/sshaccess).
type SSHState struct {
	Settings   SSHSettings             `json:"settings" yaml:"settings"`
	HostGroups map[string]SSHHostGroup `json:"host_groups,omitempty" yaml:"host_groups,omitempty"`
	Hosts      map[string]SSHHost      `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	Grants     []SSHGrant              `json:"grants,omitempty" yaml:"grants,omitempty"`
	// UIDs: username → uid (20000–59999, plan C19).
	UIDs map[string]int `json:"uids,omitempty" yaml:"uids,omitempty"`
	// UIDsUsed: every uid ever allocated, sorted; never shrinks.
	UIDsUsed []int `json:"uids_used,omitempty" yaml:"uids_used,omitempty"`
	// Serial: the Hub-wide bundle counter (plan C22).
	Serial int64 `json:"serial,omitempty" yaml:"serial,omitempty"`
}

// SSHSettings are Settings → SSH.
type SSHSettings struct {
	// Enabled starts false: SSH access is off (plan C29).
	Enabled bool `json:"enabled" yaml:"enabled"`
	// DefaultTTLHours is the certificate maximum, 1–12; 0 = 8.
	DefaultTTLHours int `json:"default_ttl_hours,omitempty" yaml:"default_ttl_hours,omitempty"`
}

// DefaultSSHTTLHours is the default certificate lifetime.
const DefaultSSHTTLHours = 8

// TTLHours is the effective setting (0 = 8).
func (s SSHSettings) TTLHours() int {
	if s.DefaultTTLHours == 0 {
		return DefaultSSHTTLHours
	}
	return s.DefaultTTLHours
}

// SSHHostGroup is one host group (id = the map key).
type SSHHostGroup struct {
	Label       string `json:"label,omitempty" yaml:"label,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Template is the governing sign-in template ("" = strong).
	Template string `json:"template,omitempty" yaml:"template,omitempty"`
	// Patterns are the names of unmanaged hosts (`*.lab.example.com`).
	Patterns []string `json:"patterns,omitempty" yaml:"patterns,omitempty"`
	// SourceCIDRs is the certificates' source-address (≤ 16).
	SourceCIDRs []string `json:"source_cidrs,omitempty" yaml:"source_cidrs,omitempty"`
	// VPNOnly: "Only through the Portcullis VPN": the built-in subnet plus
	// the VPNVia marketplace providers' ranges, added to SourceCIDRs.
	VPNOnly bool     `json:"vpn_only,omitempty" yaml:"vpn_only,omitempty"`
	VPNVia  []string `json:"vpn_via,omitempty" yaml:"vpn_via,omitempty"`
	// HostCerts: managed hosts get host certificates (default on: the
	// field is "no host certificates").
	NoHostCerts bool `json:"no_host_certs,omitempty" yaml:"no_host_certs,omitempty"`
	// Delegable: ssh_access holders may grant on it.
	Delegable bool `json:"delegable,omitempty" yaml:"delegable,omitempty"`
	// CreateShared: "Portcullis creates shared accounts".
	CreateShared bool `json:"create_shared,omitempty" yaml:"create_shared,omitempty"`
}

// DefaultSSHTemplate is a host group's default governing template.
const DefaultSSHTemplate = "strong"

// GoverningTemplate is Template, or strong.
func (g SSHHostGroup) GoverningTemplate() string {
	if g.Template == "" {
		return DefaultSSHTemplate
	}
	return g.Template
}

// HostCerts reports whether managed hosts get host certificates.
func (g SSHHostGroup) HostCerts() bool { return !g.NoHostCerts }

// SSHHost is one host (id = the map key).
type SSHHost struct {
	// Names and Addrs are what the admin entered (also the host
	// certificate's principals).
	Names      []string `json:"names,omitempty" yaml:"names,omitempty"`
	Addrs      []string `json:"addrs,omitempty" yaml:"addrs,omitempty"`
	HostGroups []string `json:"host_groups,omitempty" yaml:"host_groups,omitempty"`
	// Managed: enrolled with `host enroll` (else an unmanaged entry).
	Managed bool `json:"managed,omitempty" yaml:"managed,omitempty"`
	// HostKey is the pinned ed25519 host key ("<type> <base64>") and
	// KeyFP its fingerprint; empty until enrolled.
	KeyFP   string `json:"key_fp,omitempty" yaml:"key_fp,omitempty"`
	HostKey string `json:"host_key,omitempty" yaml:"host_key,omitempty"`
	// EnrolHash is hex SHA-256 of the enrolment secret (single use; ""
	// once used), valid until EnrolExpires.
	EnrolHash    string    `json:"enrol_hash,omitempty" yaml:"enrol_hash,omitempty"`
	EnrolExpires time.Time `json:"enrol_expires,omitempty" yaml:"enrol_expires,omitempty"`
	// Serial is the bundle serial of the host's last change.
	Serial int64 `json:"serial,omitempty" yaml:"serial,omitempty"`
	// HostCert is the current host certificate (public), valid until
	// HostCertUntil; HostCertFrom is when it was issued.
	HostCert      string    `json:"host_cert,omitempty" yaml:"host_cert,omitempty"`
	HostCertFrom  time.Time `json:"host_cert_from,omitempty" yaml:"host_cert_from,omitempty"`
	HostCertUntil time.Time `json:"host_cert_until,omitempty" yaml:"host_cert_until,omitempty"`
	// Ceiling is the host's local ceiling as it reported at enrolment.
	Ceiling *cliapi.Ceiling `json:"ceiling,omitempty" yaml:"ceiling,omitempty"`
	// Removed: *Remove host* ran; requests get 403 removed.
	Removed bool `json:"removed,omitempty" yaml:"removed,omitempty"`
	// RemoveAccounts: *Remove account* asked for these (bundle `remove`).
	RemoveAccounts []string `json:"remove_accounts,omitempty" yaml:"remove_accounts,omitempty"`
	// LastSync is the last signed request.
	LastSync time.Time `json:"last_sync,omitempty" yaml:"last_sync,omitempty"`
}

// SSHGrant is one grant (contract §18.12).
type SSHGrant struct {
	ID string `json:"id" yaml:"id"`
	// Group is the LLDAP group, GroupID its id at creation (a group
	// re-created with a new id grants nothing).
	Group     string `json:"group" yaml:"group"`
	GroupID   int    `json:"group_id" yaml:"group_id"`
	HostGroup string `json:"host_group" yaml:"host_group"`
	// Accounts: "{username}" and/or shared account names.
	Accounts []string `json:"accounts" yaml:"accounts"`
	// Sudo: "none" or "full".
	Sudo string `json:"sudo" yaml:"sudo"`
	// TTLHours: 1–12; 0 = the default (8, or 4 for a privileged grant).
	TTLHours        int  `json:"ttl_hours,omitempty" yaml:"ttl_hours,omitempty"`
	PortForwarding  bool `json:"port_forwarding,omitempty" yaml:"port_forwarding,omitempty"`
	AgentForwarding bool `json:"agent_forwarding,omitempty" yaml:"agent_forwarding,omitempty"`
}

// Sudo levels.
const (
	SudoNone = "none"
	SudoFull = "full"
)

// EnsureBuiltins adds the built-in host group all (every managed host).
func (s *SSHState) EnsureBuiltins() {
	if s.HostGroups == nil {
		s.HostGroups = map[string]SSHHostGroup{}
	}
	if _, ok := s.HostGroups[cliapi.BuiltinAllHostGroup]; !ok {
		s.HostGroups[cliapi.BuiltinAllHostGroup] = SSHHostGroup{Label: "All managed hosts"}
	}
}
