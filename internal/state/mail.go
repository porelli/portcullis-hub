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
	// Aliases: the person's LLDAP uuid → their alias addresses (a
	// re-created username, a new uuid, never inherits them).
	Aliases map[string]MailAliases `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	// Lists: group name → its list.
	Lists map[string]MailList `json:"lists,omitempty" yaml:"lists,omitempty"`
	// Quotas are group-scoped rows, in the admin's order (first match).
	Quotas []MailQuotaRow `json:"quotas,omitempty" yaml:"quotas,omitempty"`
	Spam   MailSpam       `json:"spam" yaml:"spam"`
	Limits MailLimits     `json:"limits" yaml:"limits"`
	// Generation is the last MailState generation the Hub sent (saved
	// before the PUT).
	Generation int `json:"generation" yaml:"generation"`
	// PendingRemoval: mailctl refused a mass removal; the accounts wait
	// for an administrator's confirmation (their mail passwords are
	// revoked meanwhile). nil: none.
	PendingRemoval *MailPendingRemoval `json:"pending_removal,omitempty" yaml:"pending_removal,omitempty"`
	// RestoreHandled: the provider's restored_at the last successful full
	// reconcile of the mail passwords ran for (nil: none yet).
	RestoreHandled *time.Time `json:"restore_handled,omitempty" yaml:"restore_handled,omitempty"`

	// The mail slot (contract §19.1, §19.9). Provider: the wired
	// instance (nil: nothing wired). VoidOwed: a void is owed (saved
	// before anything else; the provider runs in void mode until a
	// verified void clears it). Held: the wired template changed (or no
	// longer validates) since wiring: void mode, no void, until an admin
	// re-confirms.
	Provider *MailProvider `json:"provider,omitempty" yaml:"provider,omitempty"`
	VoidOwed *MailVoid     `json:"void_owed,omitempty" yaml:"void_owed,omitempty"`
	Held     *MailHold     `json:"held,omitempty" yaml:"held,omitempty"`
	// RetiringDKIM: per mail domain, the old provider's DKIM records kept
	// in its set after a switch, until Until (§19.7).
	RetiringDKIM map[string]RetiringDKIM `json:"retiring_dkim,omitempty" yaml:"retiring_dkim,omitempty"`
	// TLS: the mail certificate as the CLI last reported it (POST
	// /host/mail/tls, §19.3); SeenAt is also the timer's last visit.
	TLS MailTLS `json:"tls" yaml:"tls"`
	// Relay: the outbound relay (nil: deliver directly). Its password is
	// hub_data/mail-relay-password, never here.
	Relay *MailRelay `json:"relay,omitempty" yaml:"relay,omitempty"`
	// DKIMRotate and FormerRetention are Go durations, 24h–8760h (""
	// = the defaults 4320h and 720h).
	DKIMRotate      string `json:"dkim_rotate,omitempty" yaml:"dkim_rotate,omitempty"`
	FormerRetention string `json:"former_retention,omitempty" yaml:"former_retention,omitempty"`
	// Unwiring: a draining unwire waits for every mail domain to be off,
	// then closes the provider (nil: none). Switch: a switch in progress
	// (resumed at start, never leaving both providers on the ports).
	Unwiring *MailUnwiring `json:"unwiring,omitempty" yaml:"unwiring,omitempty"`
	// DMARCPublished: per mail domain, the DMARC p= of the last set the
	// Hub validated and published (or the CLI read for the main domain):
	// with dmarc_start it makes dmarc_floor (contract §19.5).
	DMARCPublished map[string]string `json:"dmarc_published,omitempty" yaml:"dmarc_published,omitempty"`
	// MTASTSPublished: the mail domains whose last published set carries
	// _mta-sts.<d> (the Hub's own record of it: the MTA-STS policy check
	// runs for exactly those, M13).
	MTASTSPublished map[string]bool `json:"mta_sts_published,omitempty" yaml:"mta_sts_published,omitempty"`
	Switch          *MailSwitch     `json:"switch,omitempty" yaml:"switch,omitempty"`
}

// MailUnwiring is a draining unwire.
type MailUnwiring struct {
	Instance string    `json:"instance" yaml:"instance"`
	Since    time.Time `json:"since" yaml:"since"`
	By       string    `json:"by" yaml:"by"`
	// Closing: the close started (saved before it voids anything) and
	// its verified stop is still owed: resumed at start and by the retry
	// loop until the instance is down (M4).
	Closing bool `json:"closing,omitempty" yaml:"closing,omitempty"`
}

// MailSwitch is a switch in progress.
type MailSwitch struct {
	From  string    `json:"from" yaml:"from"`
	To    string    `json:"to" yaml:"to"`
	Since time.Time `json:"since" yaml:"since"`
	By    string    `json:"by" yaml:"by"`
	// Closed: the old provider's close step is done (saved with it).
	Closed bool `json:"closed,omitempty" yaml:"closed,omitempty"`
}

// MailProvider is the wired mail provider (state.yaml mail.provider):
// the instance, its template, source and commit, and the block hash at
// wiring (templates.MailBlockHash).
type MailProvider struct {
	Instance string `json:"instance" yaml:"instance"`
	Template string `json:"template" yaml:"template"`
	Source   string `json:"source" yaml:"source"`
	// SourceURL is the source's URL at the wiring (M7): another URL
	// under the same name is another repository, never a re-confirm.
	SourceURL string    `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	Commit    string    `json:"commit" yaml:"commit"`
	BlockHash string    `json:"block_hash" yaml:"block_hash"`
	WiredAt   time.Time `json:"wired_at" yaml:"wired_at"`
	WiredBy   string    `json:"wired_by" yaml:"wired_by"`
}

// MailVoid is an owed void (reason wire or restore).
type MailVoid struct {
	Reason string    `json:"reason" yaml:"reason"`
	Since  time.Time `json:"since" yaml:"since"`
	// Seq grows with every debt raised while one is owed (a restore
	// during a void): a run clears only the debt it started on (L19).
	Seq int `json:"seq,omitempty" yaml:"seq,omitempty"`
}

// Void reasons (MailVoid.Reason).
const (
	MailVoidWire    = "wire"
	MailVoidRestore = "restore"
)

// MailHold is a held provider (its template changed since wiring).
type MailHold struct {
	Reason string    `json:"reason" yaml:"reason"`
	Since  time.Time `json:"since" yaml:"since"`
	// Stopped: the held provider couldn't take a revocation, a removal
	// or a session reset, so the Hub stopped it (Ruling R-HH1, fail
	// closed); it stays stopped until the re-confirm.
	Stopped *time.Time `json:"stopped,omitempty" yaml:"stopped,omitempty"`
	// DownOwed: the down is owed (saved with Stopped, before the down;
	// cleared only once it succeeded), retried at every start and by the
	// retry loop. StopError: its last attempt's error.
	DownOwed  bool   `json:"down_owed,omitempty" yaml:"down_owed,omitempty"`
	StopError string `json:"stop_error,omitempty" yaml:"stop_error,omitempty"`
}

// MailRecord is one DNS record of a mail set.
type MailRecord struct {
	Name  string `json:"name" yaml:"name"`
	Type  string `json:"type" yaml:"type"`
	TTL   int    `json:"ttl" yaml:"ttl"`
	Value string `json:"value" yaml:"value"`
}

// RetiringDKIM is one domain's retained DKIM records after a switch.
type RetiringDKIM struct {
	Records []MailRecord `json:"records" yaml:"records"`
	Until   time.Time    `json:"until" yaml:"until"`
}

// MailTLS is the mail certificate's SPKIs and expiry as the CLI reported.
type MailTLS struct {
	SPKISHA256 []string   `json:"spki_sha256,omitempty" yaml:"spki_sha256,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty" yaml:"not_after,omitempty"`
	SeenAt     *time.Time `json:"seen_at,omitempty" yaml:"seen_at,omitempty"`
}

// MailRelay is the outbound relay (Settings → Mail).
type MailRelay struct {
	Host       string `json:"host" yaml:"host"`
	Port       int    `json:"port" yaml:"port"`
	Username   string `json:"username" yaml:"username"`
	SPFInclude string `json:"spf_include" yaml:"spf_include"`
}

// MailAliases are one person's aliases (Username: the name they had when
// they were set, for display and for the delete clean-up).
type MailAliases struct {
	Username  string   `json:"username" yaml:"username"`
	Addresses []string `json:"addresses" yaml:"addresses"`
}

// MailPendingRemoval is a refused mass removal waiting for confirmation.
type MailPendingRemoval struct {
	Since    time.Time            `json:"since" yaml:"since"`
	Accounts []MailPendingAccount `json:"accounts" yaml:"accounts"`
	// ConfirmedHash: an administrator's confirmation, bound to the hash
	// of exactly this set and Since; any change to the set voids it.
	ConfirmedHash string `json:"confirmed_hash,omitempty" yaml:"confirmed_hash,omitempty"`
}

// MailPendingAccount is one account a pending mass removal would remove.
type MailPendingAccount struct {
	Username string `json:"username" yaml:"username"`
	UUID     string `json:"uuid" yaml:"uuid"`
	// Revoked: their mail passwords are revoked (false: still retrying).
	Revoked bool `json:"revoked" yaml:"revoked"`
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
	// MailCredentialReasonProviderChanged: the mail provider was
	// unwired or switched (contract §19.9).
	MailCredentialReasonProviderChanged = "provider_changed"
)
