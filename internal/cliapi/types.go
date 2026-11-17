package cliapi

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the CLI API version (`api=1`).
const APIVersion = 1

// HeaderCLI carries `<version>; api=<n>` on every CLI request.
const HeaderCLI = "Portcullis-CLI"

// ClientID is the Hub-owned Keycloak client of the loopback sign-in.
const ClientID = "portcullis-cli"

// RedirectPorts are the three loopback ports, tried in order.
var RedirectPorts = [3]int{38917, 38918, 38919}

// RedirectURI is the loopback redirect URI for a port.
func RedirectURI(port int) string { return fmt.Sprintf("http://127.0.0.1:%d/callback", port) }

// RedirectURIs are the three loopback redirect URIs.
func RedirectURIs() []string {
	out := make([]string, 0, len(RedirectPorts))
	for _, p := range RedirectPorts {
		out = append(out, RedirectURI(p))
	}
	return out
}

// CLIHeaderValue is the header value a CLI of this version sends.
func CLIHeaderValue(version string) string {
	return version + "; api=" + strconv.Itoa(APIVersion)
}

// ParseCLIHeader splits `<version>; api=<n>`.
func ParseCLIHeader(h string) (version string, api int, ok bool) {
	v, rest, found := strings.Cut(h, ";")
	if !found {
		return "", 0, false
	}
	rest = strings.TrimSpace(rest)
	n, found := strings.CutPrefix(rest, "api=")
	if !found {
		return "", 0, false
	}
	a, err := strconv.Atoi(n)
	if err != nil {
		return "", 0, false
	}
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 64 {
		return "", 0, false
	}
	return v, a, true
}

// Limits (contract §18.5, §18.12).
const (
	MaxCertsPerLogin  = 16
	MaxHostGroups     = 64
	MaxGrants         = 256
	MaxRolePrincipals = 4096
	MaxSourceCIDRs    = 16
)

// Config is GET config (contract §18.4).
type Config struct {
	API           int    `json:"api"`
	Domain        string `json:"domain"`
	Issuer        string `json:"issuer"`
	AuthorizeURL  string `json:"authorize_url"`
	ClientID      string `json:"client_id"`
	RedirectPorts []int  `json:"redirect_ports"`
	Device        bool   `json:"device"`
	MinCLI        string `json:"min_cli"`
}

// ErrorAnswer is every error body.
type ErrorAnswer struct {
	Error string `json:"error"`
}

// Proof is the fresh sign-in part every proven request carries.
type Proof struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
	RedirectURI  string `json:"redirect_uri"`
}

// CertRequest is POST ssh/certificates.
type CertRequest struct {
	Code         string   `json:"code"`
	CodeVerifier string   `json:"code_verifier"`
	Nonce        string   `json:"nonce"`
	RedirectURI  string   `json:"redirect_uri"`
	PublicKey    string   `json:"public_key"`
	KeyProof     string   `json:"key_proof"`
	HostGroups   []string `json:"host_groups"`
	// OwnKey: the key is the person's own (`login --key`), not this
	// login's ephemeral key: its revocation never expires (contract §18.10).
	OwnKey bool `json:"own_key,omitempty"`
}

// IssuedCert is one certificate of a CertAnswer.
type IssuedCert struct {
	HostGroup   string    `json:"host_group"`
	Certificate string    `json:"certificate"`
	Principals  []string  `json:"principals"`
	Serial      string    `json:"serial"`
	ValidBefore time.Time `json:"valid_before"`
	Hosts       []string  `json:"hosts"`
}

// Refusal is one refused host group.
type Refusal struct {
	HostGroup string `json:"host_group"`
	Reason    string `json:"reason"`
}

// CertAnswer is the answer of POST ssh/certificates.
type CertAnswer struct {
	User            string       `json:"user"`
	Certificates    []IssuedCert `json:"certificates"`
	Refused         []Refusal    `json:"refused"`
	HostCAs         []string     `json:"host_cas"`
	RevokedHostKeys []string     `json:"revoked_host_keys"`
}

// RevocationRequest is POST ssh/revocations (plan C30).
type RevocationRequest struct {
	Code         string   `json:"code"`
	CodeVerifier string   `json:"code_verifier"`
	Nonce        string   `json:"nonce"`
	RedirectURI  string   `json:"redirect_uri"`
	PublicKeys   []string `json:"public_keys"`
}

// RevocationAnswer is its answer.
type RevocationAnswer struct {
	Revoked int `json:"revoked"`
}

// HostCertRequest is POST ssh/host-certificates (plan C31).
type HostCertRequest struct {
	Code         string   `json:"code"`
	CodeVerifier string   `json:"code_verifier"`
	Nonce        string   `json:"nonce"`
	RedirectURI  string   `json:"redirect_uri"`
	HostGroup    string   `json:"host_group"`
	PublicKey    string   `json:"public_key"`
	Names        []string `json:"names"`
}

// HostCertAnswer is its answer.
type HostCertAnswer struct {
	Certificate string    `json:"certificate"`
	ValidBefore time.Time `json:"valid_before"`
}

// CAAnswer is GET ssh/ca.
type CAAnswer struct {
	UserCAs []string `json:"user_cas"`
	HostCAs []string `json:"host_cas"`
}

// EnrolChallengeRequest is POST hosts/enrol/challenge.
type EnrolChallengeRequest struct {
	HostID string `json:"host_id"`
}

// EnrolChallenge is its answer.
type EnrolChallenge struct {
	Challenge string `json:"challenge"`
}

// EnrolRequest is POST hosts/enrol (plan C4). Secret is a secret.
type EnrolRequest struct {
	HostID      string  `json:"host_id"`
	Secret      string  `json:"secret"`
	HostKey     string  `json:"host_key"`
	Proof       string  `json:"proof"`
	SSHDVersion string  `json:"sshd_version"`
	Ceiling     Ceiling `json:"ceiling"`
}

// Ceiling is the host's local ceiling, /etc/portcullis/host.json.
type Ceiling struct {
	AllowSudo         bool     `json:"allow_sudo"`
	AllowRootLogin    bool     `json:"allow_root_login"`
	UIDRange          [2]int   `json:"uid_range"`
	ProtectedAccounts []string `json:"protected_accounts"`
	BreakglassAccount string   `json:"breakglass_account"`
	MaxAccounts       int      `json:"max_accounts"`
}

// Ceiling defaults (spec §8.9).
const (
	DefaultBreakglassAccount = "breakglass"
	DefaultMaxAccounts       = 500
	UIDMin                   = 20000
	UIDMax                   = 59999
	ProtectedBelowUID        = 1000
)

// DefaultCeiling is the ceiling with the spec's defaults.
func DefaultCeiling() Ceiling {
	return Ceiling{
		AllowSudo:         true,
		UIDRange:          [2]int{UIDMin, UIDMax},
		ProtectedAccounts: []string{DefaultBreakglassAccount},
		BreakglassAccount: DefaultBreakglassAccount,
		MaxAccounts:       DefaultMaxAccounts,
	}
}

// Validate checks a ceiling's shape.
func (c Ceiling) Validate() error {
	if c.UIDRange[0] < ProtectedBelowUID || c.UIDRange[1] < c.UIDRange[0] || c.UIDRange[1] > 2147483646 {
		return fmt.Errorf("uid_range must be within %d-2147483646 and ordered", ProtectedBelowUID)
	}
	if c.MaxAccounts < 0 || c.MaxAccounts > 100000 {
		return fmt.Errorf("max_accounts must be 0-100000")
	}
	if c.BreakglassAccount != "" && !ValidAccount(c.BreakglassAccount) {
		return fmt.Errorf("breakglass_account is not a valid account name")
	}
	if len(c.ProtectedAccounts) > 1024 {
		return fmt.Errorf("too many protected_accounts")
	}
	for _, a := range c.ProtectedAccounts {
		if !ValidAccount(a) && a != "root" {
			return fmt.Errorf("protected_accounts holds an invalid account name")
		}
	}
	return nil
}

// Account kinds in a bundle.
const (
	AccountPerson = "person"
	AccountShared = "shared"
)

// Account is one bundle account.
type Account struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	UID        int      `json:"uid,omitempty"`
	Principals []string `json:"principals"`
	Sudo       bool     `json:"sudo"`
}

// BundleOptions are the host group switches a host needs.
type BundleOptions struct {
	CreateSharedAccounts bool `json:"create_shared_accounts"`
}

// BundleVersion is the only bundle version.
const BundleVersion = 1

// Bundle is a managed host's desired state (contract §18.11).
type Bundle struct {
	Version         int           `json:"version"`
	HostID          string        `json:"host_id"`
	Serial          int64         `json:"serial"`
	Generated       time.Time     `json:"generated"`
	UserCAs         []string      `json:"user_cas"`
	HostCertificate string        `json:"host_certificate"`
	Accounts        []Account     `json:"accounts"`
	Locked          []string      `json:"locked"`
	Remove          []string      `json:"remove"`
	RevokedKeys     []string      `json:"revoked_keys"`
	Options         BundleOptions `json:"options"`
}

// Finding severities.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityProblem = "problem"
)

// Host finding kinds (contract §18.11).
const (
	FindingDrift                = "ssh_host_drift"
	FindingAccountConflict      = "ssh_host_account_conflict"
	FindingAccountMissing       = "ssh_host_account_missing"
	FindingAccountInvalid       = "ssh_host_account_invalid"
	FindingCeiling              = "ssh_host_ceiling"
	FindingAuthorizedKeysShared = "ssh_host_authorized_keys_shared"
	FindingBreakglassUsed       = "ssh_breakglass_used"
)

// Finding is one host-side finding. Every string is opaque to the Hub.
type Finding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Subject  string `json:"subject"`
	Detail   string `json:"detail"`
}

// ReportAccounts lists the Portcullis accounts a host sees.
type ReportAccounts struct {
	Present []string `json:"present"`
	Missing []string `json:"missing"`
	Locked  []string `json:"locked"`
	Removed []string `json:"removed"`
	// SudoCapable: every local account (uid ≥ 1000) that can reach root
	// on the host (RR-H1: sudo -l, id -Gn incl. root-equivalent groups,
	// doas), whatever the ceiling; SudoChecked false = unknown (too many
	// accounts, the accounts unreadable), which the Hub reads as "every
	// account may".
	SudoCapable []string `json:"sudo_capable"`
	SudoChecked bool     `json:"sudo_checked"`
}

// MaxSudoChecked is how many local accounts a report checks for sudo; a
// host with more reports SudoChecked false.
const MaxSudoChecked = 256

// LoginEvent is the last break-glass login.
type LoginEvent struct {
	Time string `json:"time"`
	From string `json:"from"`
}

// ReportLogins are counts since the last report, never log lines.
type ReportLogins struct {
	Portcullis     int        `json:"portcullis"`
	Breakglass     int        `json:"breakglass"`
	BreakglassLast LoginEvent `json:"breakglass_last"`
}

// ReportVersion is the only report version.
const ReportVersion = 1

// Report is POST hosts/report (contract §18.11). Untrusted.
type Report struct {
	Version              int                          `json:"version"`
	HostID               string                       `json:"host_id"`
	Serial               int64                        `json:"serial"`
	Time                 time.Time                    `json:"time"`
	SSHDVersion          string                       `json:"sshd_version"`
	Applied              bool                         `json:"applied"`
	Error                string                       `json:"error"`
	Files                map[string]string            `json:"files"`
	Effective            map[string]map[string]string `json:"effective"`
	Accounts             ReportAccounts               `json:"accounts"`
	Findings             []Finding                    `json:"findings"`
	AuthorizedKeysShared int                          `json:"authorized_keys_shared"`
	Logins               ReportLogins                 `json:"logins"`
}

// RoleSpec is a host group's Vault role as the Hub compiles it and as
// enroll's PUT /internal/ssh-roles/{hg} takes and answers it.
type RoleSpec struct {
	Principals    []string `json:"principals"`
	Extensions    string   `json:"extensions"`
	SourceAddress []string `json:"source_address"`
	MaxTTLSeconds int      `json:"max_ttl_s"`
}

// Equal compares two specs exactly (order included: both sides are sorted).
func (r RoleSpec) Equal(o RoleSpec) bool {
	return r.Extensions == o.Extensions && r.MaxTTLSeconds == o.MaxTTLSeconds &&
		equalStrings(r.Principals, o.Principals) && equalStrings(r.SourceAddress, o.SourceAddress)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
