package state

import (
	"fmt"
	"time"
)

// MailSettings is Settings → Mail (contract §19.9): the Hub's own mail
// state, sent to mailctl as MailState documents. Never a secret.
type MailSettings struct {
	// PrimaryDomain is the domain of every login and first address; ""
	// = the main domain.
	PrimaryDomain string `json:"primary_domain,omitempty" yaml:"primary_domain,omitempty"`
	// Domains: domain name → its mail switch. The main domain needs no
	// entry: it is on while core's mail profile is on (PORTCULLIS_MAIL).
	Domains map[string]MailDomain `json:"domains,omitempty" yaml:"domains,omitempty"`
	// Aliases: lowercase username → its alias addresses.
	Aliases map[string][]string `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	// Lists: group name → its list.
	Lists map[string]MailList `json:"lists,omitempty" yaml:"lists,omitempty"`
	// Quotas are group-scoped rows, in the admin's order (first match).
	Quotas []MailQuotaRow `json:"quotas,omitempty" yaml:"quotas,omitempty"`
	Spam   MailSpam       `json:"spam" yaml:"spam"`
	Limits MailLimits     `json:"limits" yaml:"limits"`
	// Generation is the last MailState generation the Hub sent (saved
	// before the PUT).
	Generation int `json:"generation" yaml:"generation"`
}

// MailDomain is one domain's mail switch.
type MailDomain struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Draining: turned off, the MTA-STS mode: none phase runs until
	// mailctl reports the domain off.
	Draining bool     `json:"draining,omitempty" yaml:"draining,omitempty"`
	Groups   []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	// HadMailRecords: an MX or SPF was there before Portcullis (DMARC
	// starts at p=none).
	HadMailRecords bool `json:"had_mail_records,omitempty" yaml:"had_mail_records,omitempty"`
	// Retired: off, and its mail set removed (an added domain) or its off
	// document applied (the main domain): no longer in documents.
	Retired bool `json:"retired,omitempty" yaml:"retired,omitempty"`
}

// MailList is a group's list.
type MailList struct {
	Domain  string `json:"domain" yaml:"domain"`
	Posting string `json:"posting" yaml:"posting"` // members | anyone
}

// MailQuotaRow is one quota row: the members of Group get Bytes.
type MailQuotaRow struct {
	Group string `json:"group" yaml:"group"`
	Bytes int64  `json:"bytes" yaml:"bytes"`
}

// MailSpam is the spam filter's settings.
type MailSpam struct {
	RejectScore int      `json:"reject_score" yaml:"reject_score"`
	JunkScore   int      `json:"junk_score" yaml:"junk_score"`
	Spamhaus    bool     `json:"spamhaus" yaml:"spamhaus"`
	Spamcop     bool     `json:"spamcop" yaml:"spamcop"`
	Barracuda   bool     `json:"barracuda" yaml:"barracuda"`
	Allow       []string `json:"allow,omitempty" yaml:"allow,omitempty"`
	Block       []string `json:"block,omitempty" yaml:"block,omitempty"`
}

// MailLimits are the per-account outbound limits.
type MailLimits struct {
	RecipientsPerHour int `json:"recipients_per_hour" yaml:"recipients_per_hour"`
	RecipientsPerDay  int `json:"recipients_per_day" yaml:"recipients_per_day"`
}

// Mail defaults (contract §19.8, §19.6).
const (
	DefaultMailRejectScore       = 15
	DefaultMailJunkScore         = 5
	DefaultMailRecipientsPerHour = 300
	DefaultMailRecipientsPerDay  = 1000
	DefaultMailQuotaBytes        = int64(10) << 30
	MaxMailQuotaBytes            = int64(1) << 40
	MaxMailLimit                 = 100000
)

// DefaultMailSettings are a new install's mail settings.
func DefaultMailSettings() MailSettings {
	return MailSettings{
		Spam:   MailSpam{RejectScore: DefaultMailRejectScore, JunkScore: DefaultMailJunkScore, Spamhaus: true, Spamcop: true, Barracuda: true},
		Limits: MailLimits{RecipientsPerHour: DefaultMailRecipientsPerHour, RecipientsPerDay: DefaultMailRecipientsPerDay},
	}
}

// Check refuses settings the contract's ranges don't allow (a hand-edited
// state.yaml): the Hub never sends them.
func (m MailSettings) Check() error {
	if m.Generation < 0 {
		return fmt.Errorf("generation %d is negative", m.Generation)
	}
	if m.Spam.JunkScore < 1 || m.Spam.JunkScore >= m.Spam.RejectScore || m.Spam.RejectScore > 100 {
		return fmt.Errorf("spam scores must satisfy 1 ≤ junk (%d) < reject (%d) ≤ 100", m.Spam.JunkScore, m.Spam.RejectScore)
	}
	for _, l := range []int{m.Limits.RecipientsPerHour, m.Limits.RecipientsPerDay} {
		if l < 1 || l > MaxMailLimit {
			return fmt.Errorf("limit %d is outside 1–%d", l, MaxMailLimit)
		}
	}
	for _, q := range m.Quotas {
		if q.Group == "" || q.Bytes <= 0 || q.Bytes > MaxMailQuotaBytes {
			return fmt.Errorf("quota row %q %d: a group and 0 < bytes ≤ 1 TiB", q.Group, q.Bytes)
		}
	}
	for g, l := range m.Lists {
		if l.Domain == "" || (l.Posting != MailPostingMembers && l.Posting != MailPostingAnyone) {
			return fmt.Errorf("list %q: a domain and posting members|anyone", g)
		}
	}
	return nil
}

// List posting modes.
const (
	MailPostingMembers = "members"
	MailPostingAnyone  = "anyone"
)

// MailCredential is the metadata of one mail password (contract §13.16
// "Mail passwords"). Never the password or a hash: Stalwart holds the
// hash, the password exists only in its one create answer.
type MailCredential struct {
	// ID is the Hub's; StalwartID mailctl's credential id.
	ID         string `json:"id" yaml:"id"`
	StalwartID string `json:"stalwart_id" yaml:"stalwart_id"`
	Label      string `json:"label" yaml:"label"`
	// UUID is the person's LLDAP uuid at creation. A row matches a live
	// password on (UUID, StalwartID, CreatedAt) together.
	UUID      string     `json:"uuid" yaml:"uuid"`
	CreatedAt time.Time  `json:"created_at" yaml:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	CreatedBy string     `json:"created_by" yaml:"created_by"`
	// RevokedAt is set once the row is no longer active; Reason says why
	// (MailCredentialReason*).
	RevokedAt *time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty" yaml:"revoked_by,omitempty"`
	Reason    string     `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// Active reports whether the row is in use.
func (c MailCredential) Active() bool { return c.RevokedAt == nil }

// Mail credential end reasons (MailCredential.Reason, contract §13.16).
const (
	MailCredentialReasonRevoked     = "revoked"
	MailCredentialReasonRevokeLeave = "revoke_leave"
	MailCredentialReasonVoidRestore = "void_restore"
	MailCredentialReasonExpired     = "expired"
	MailCredentialReasonMissing     = "missing"
)
