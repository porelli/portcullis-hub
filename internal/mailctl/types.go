package mailctl

import (
	"errors"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// The types mirror the mailctl API of contract §19.5 exactly (snake_case
// JSON, every key always present): TestTypesMatchContractVector decodes
// the contract's MailState vector strictly and encodes it back.

// MailState is the desired-state document (PUT /v1/state, version 1).
type MailState struct {
	Version            int       `json:"version"`
	Generation         int       `json:"generation"`
	PrimaryDomain      string    `json:"primary_domain"`
	ConfirmMassRemoval bool      `json:"confirm_mass_removal"`
	Domains            []Domain  `json:"domains"`
	Accounts           []Account `json:"accounts"`
	Aliases            []Alias   `json:"aliases"`
	Lists              []List    `json:"lists"`
	Postmaster         []string  `json:"postmaster"`
	Limits             Limits    `json:"limits"`
	Spam               Spam      `json:"spam"`
	LocalNetworks      []string  `json:"local_networks"`
}

// StateVersion is the only MailState version.
const StateVersion = 1

// Domain is one mail domain of the document.
type Domain struct {
	Name       string `json:"name"`
	DMARCStart string `json:"dmarc_start"` // reject | none
	Mail       string `json:"mail"`        // on | off | draining
	DNSSEC     string `json:"dnssec"`      // secure, unsigned, …, unknown
}

// Domain mail states (Domain.Mail, contract §19.5).
const (
	MailOn       = "on"
	MailOff      = "off"
	MailDraining = "draining"
)

// Account is one mailbox (a member of mail_users).
type Account struct {
	Username    string   `json:"username"`
	UUID        string   `json:"uuid"`
	DisplayName string   `json:"display_name"`
	Addresses   []string `json:"addresses"`
	QuotaBytes  int64    `json:"quota_bytes"`
}

// Alias delivers Address to one account.
type Alias struct {
	Address  string `json:"address"`
	Username string `json:"username"`
}

// List is a group list.
type List struct {
	Address string   `json:"address"`
	Members []string `json:"members"`
	Posting string   `json:"posting"` // members | anyone
}

// Limits are the per-account outbound limits.
type Limits struct {
	RecipientsPerHour int `json:"recipients_per_hour"`
	RecipientsPerDay  int `json:"recipients_per_day"`
}

// Spam is the spam filter's settings.
type Spam struct {
	RejectScore int      `json:"reject_score"`
	JunkScore   int      `json:"junk_score"`
	DNSBL       DNSBL    `json:"dnsbl"`
	Allow       []string `json:"allow"`
	Block       []string `json:"block"`
}

// DNSBL switches the three blocklists.
type DNSBL struct {
	Spamhaus  bool `json:"spamhaus"`
	Spamcop   bool `json:"spamcop"`
	Barracuda bool `json:"barracuda"`
}

// StateStatus is GET /v1/state.
type StateStatus struct {
	Generation        int      `json:"generation"`
	AppliedGeneration int      `json:"applied_generation"`
	Bootstrap         bool     `json:"bootstrap"`
	Errors            []string `json:"errors"`
}

// Record is one wanted DNS record.
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

// DNSSet is GET /v1/dns/{domain}: the domain's wanted mail set.
type DNSSet struct {
	Domain  string   `json:"domain"`
	Records []Record `json:"records"`
	DKIM    string   `json:"dkim"` // auto | manual
	TLSA    string   `json:"tlsa"` // published | withheld: <why>
}

// Check is one check result.
type Check struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"` // ok | info | warning | problem
	Detail   string   `json:"detail"`
	Steps    []string `json:"steps"`
	// Reason (fcrdns_v4 / fcrdns_v6 only): "missing" (no PTR) or
	// "mismatch" (the PTR's name doesn't resolve back); absent elsewhere.
	Reason string `json:"reason,omitempty"`
}

// fcrdns reasons (Check.Reason).
const (
	ReasonPTRMissing  = "missing"
	ReasonPTRMismatch = "mismatch"
)

// Check severities.
const (
	SeverityOK      = "ok"
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityProblem = "problem"
)

// Checks is GET /v1/checks.
type Checks struct {
	CheckedAt time.Time `json:"checked_at"`
	Checks    []Check   `json:"checks"`
}

// Credential is one mail password's metadata (GET /v1/credentials).
type Credential struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used"`
}

// Created is POST /v1/credentials' answer. Secret is the password: the
// caller zeroes it once it has written its one answer.
type Created struct {
	ID        string     `json:"id"`
	Secret    Secret     `json:"secret"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// Secret is a password as bytes (a JSON string on the wire), so it can be
// zeroed; it never prints.
type Secret []byte

// UnmarshalJSON decodes a JSON string into fresh bytes by hand: the
// password never becomes a Go string (one that could never be zeroed).
// b is the caller's buffer (json.Unmarshal passes a subslice of it), so
// wiping that buffer wipes the encoded form too.
func (s *Secret) UnmarshalJSON(b []byte) error {
	out, err := unquoteBytes(b)
	if err != nil {
		return err
	}
	*s = Secret(out)
	return nil
}

// unquoteBytes decodes the JSON string literal b into a new byte slice
// (\" \\ \/ \b \f \n \r \t and \uXXXX, surrogate pairs included);
// anything else is refused.
func unquoteBytes(b []byte) ([]byte, error) {
	bad := errors.New("secret: not a JSON string")
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return nil, bad
	}
	in := b[1 : len(b)-1]
	out := make([]byte, 0, len(in))
	hex4 := func(p []byte) (rune, bool) {
		if len(p) < 4 {
			return 0, false
		}
		var r rune
		for _, c := range p[:4] {
			r <<= 4
			switch {
			case c >= '0' && c <= '9':
				r |= rune(c - '0')
			case c >= 'a' && c <= 'f':
				r |= rune(c-'a') + 10
			case c >= 'A' && c <= 'F':
				r |= rune(c-'A') + 10
			default:
				return 0, false
			}
		}
		return r, true
	}
	fail := func() ([]byte, error) {
		for i := range out[:cap(out)] {
			out[:cap(out)][i] = 0
		}
		return nil, bad
	}
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '"' || c < 0x20:
			return fail()
		case c != '\\':
			out = append(out, c)
			continue
		}
		i++
		if i >= len(in) {
			return fail()
		}
		switch in[i] {
		case '"', '\\', '/':
			out = append(out, in[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in[i+1:])
			if !ok {
				return fail()
			}
			i += 4
			if utf16.IsSurrogate(r) {
				if i+2 >= len(in) || in[i+1] != '\\' || in[i+2] != 'u' {
					return fail()
				}
				r2, ok := hex4(in[i+3:])
				if !ok {
					return fail()
				}
				r = utf16.DecodeRune(r, r2)
				if r == utf8.RuneError {
					return fail()
				}
				i += 6
			}
			var enc [4]byte
			n := utf8.EncodeRune(enc[:], r)
			out = append(out, enc[:n]...)
		default:
			return fail()
		}
	}
	return out, nil
}

// MarshalJSON never encodes the secret.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// String never shows the secret.
func (s Secret) String() string { return "[redacted]" }

// GoString never shows the secret.
func (s Secret) GoString() string { return "[redacted]" }

// Zero overwrites the secret.
func (s Secret) Zero() {
	for i := range s {
		s[i] = 0
	}
}

// Status is GET /v1/status (MailStatus).
type Status struct {
	Bootstrap       bool           `json:"bootstrap"`
	StalwartVersion string         `json:"stalwart_version"`
	Cert            StatusCert     `json:"cert"`
	DKIM            []StatusDKIM   `json:"dkim"`
	MTASTS          []StatusMTASTS `json:"mtasts"`
	DMARC           []StatusDMARC  `json:"dmarc"`
	Queue           StatusQueue    `json:"queue"`
	ClientIP        string         `json:"client_ip"`
	RestoredAt      *time.Time     `json:"restored_at"`
	TimerSeenAt     *time.Time     `json:"timer_seen_at"`
	Former          []StatusFormer `json:"former"`
}

// StatusCert is the mail certificate.
type StatusCert struct {
	NotAfter *time.Time `json:"not_after"`
	SANs     []string   `json:"sans"`
}

// StatusDKIM is one DKIM key.
type StatusDKIM struct {
	Domain    string    `json:"domain"`
	Algorithm string    `json:"algorithm"`
	Selector  string    `json:"selector"`
	Stage     string    `json:"stage"`
	Since     time.Time `json:"since"`
}

// StatusMTASTS is one domain's MTA-STS state.
type StatusMTASTS struct {
	Domain       string    `json:"domain"`
	Mode         string    `json:"mode"`
	Since        time.Time `json:"since"`
	EnforceReady bool      `json:"enforce_ready"`
}

// StatusDMARC is one domain's DMARC state.
type StatusDMARC struct {
	Domain   string    `json:"domain"`
	Policy   string    `json:"policy"`
	Since    time.Time `json:"since"`
	Proposed *string   `json:"proposed"`
}

// StatusQueue is the outbound queue.
type StatusQueue struct {
	Messages int `json:"messages"`
	Deferred int `json:"deferred"`
}

// StatusFormer is one parked account.
type StatusFormer struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Since    time.Time `json:"since"`
}

// Actions (POST /v1/actions/<name>).
const (
	ActionDKIMRotate    = "dkim-rotate"
	ActionDMARCPromote  = "dmarc-promote"
	ActionMTASTSEnforce = "mtasts-enforce"
)

// ParkingDomain is Stalwart's domain of parked (former) accounts: never a
// mail domain, every address on it reserved (contract §19.6).
const ParkingDomain = "portcullis-former.internal"

// ReservedLocalParts are reserved on every mail domain (contract §19.6).
var ReservedLocalParts = []string{"postmaster", "abuse", "dmarc-reports", "tls-reports", "mailer-daemon"}

// MaxActivePasswords is the most active mail passwords per person.
const MaxActivePasswords = 5
