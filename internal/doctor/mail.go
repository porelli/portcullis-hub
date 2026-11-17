package doctor

import (
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailprovider"
)

// Mail kinds (contract §14.5 "Mail"): sixteen kinds judged on mailctl's
// checks and status and the added mail domains' plans (Inputs.Mail; nil =
// PORTCULLIS_MAIL off: none fire). Unavailable (mailctl couldn't be read
// while mail is on): no mail findings and Report.MailUnavailable. Every
// finding about a domain carries Domains [<e>].
const (
	KindMailPort25Blocked     = "mail_port25_blocked"
	KindMailPTRMissing        = "mail_ptr_missing"
	KindMailPTRMismatch       = "mail_ptr_mismatch"
	KindMailBlocklisted       = "mail_blocklisted"
	KindMailRecordsWrong      = "mail_records_wrong"
	KindMailDKIMStuck         = "mail_dkim_stuck"
	KindMailDKIMManual        = "mail_dkim_manual"
	KindMailCertExpiring      = "mail_cert_expiring"
	KindMailDMARCFailures     = "mail_dmarc_failures"
	KindMailDMARCPromote      = "mail_dmarc_promote"
	KindMailMTASTSEnforce     = "mail_mtasts_enforce"
	KindMailIPv6PTR           = "mail_ipv6_ptr"
	KindMailClientIPRewritten = "mail_client_ip_rewritten"
	KindMailRateHeld          = "mail_rate_held"
	KindMailTimerMissing      = "mail_timer_missing"
	KindMailDANEOff           = "mail_dane_off"
	KindMailLANOnlyUnenforced = "mail_lan_only_unenforced"
	KindMailMassRemovalPend   = "mail_mass_removal_pending"
	KindMailSyncBlocked       = "mail_sync_blocked"
	KindMailHubSecretInvalid  = "mail_hub_secret_invalid"
	KindMailSpamRulesMissing  = "mail_spam_rules_missing"
	KindMailExternalLookupsOn = "mail_external_lookups_on"
)

// MailKinds are the twenty-two mail kinds.
var MailKinds = []string{KindMailPort25Blocked, KindMailPTRMissing, KindMailPTRMismatch, KindMailBlocklisted, KindMailRecordsWrong,
	KindMailDKIMStuck, KindMailDKIMManual, KindMailCertExpiring, KindMailDMARCFailures, KindMailDMARCPromote, KindMailMTASTSEnforce,
	KindMailIPv6PTR, KindMailClientIPRewritten, KindMailRateHeld, KindMailTimerMissing, KindMailDANEOff, KindMailLANOnlyUnenforced, KindMailMassRemovalPend, KindMailSyncBlocked, KindMailHubSecretInvalid,
	KindMailSpamRulesMissing, KindMailExternalLookupsOn}

// Mail fix kinds (§14.6); mail_records_wrong on an added domain uses
// dns_apply with sets=mail.
const (
	FixMailDMARCPromote   = "mail_dmarc_promote"
	FixMailMTASTSEnforce  = "mail_mtasts_enforce"
	FixMailConfirmRemoval = "mail_confirm_removal"
)

// Mail steps the explain-only findings end with.
const (
	MailMainRecordsStep    = "Run `./portcullis dns setup --only mail` on the server"
	MailCertStep           = "Run `./portcullis mail cert` on the server"
	MailTimerStep          = "Run `./portcullis mail schedule --systemd` on the server"
	MailSessionsLine       = "mail sessions may still be open"
	MailLANOnlyWhy         = "LAN-only needs the real client address; rootless Podman rewrites it"
	MailLANOnlyStep        = "Turn LAN-only off: run `./portcullis mail enable --lan-only false` on the server"
	MailExternalLookupsWhy = "The spam filter's external lookups may be on and couldn't be turned off, so the mail server may contact outside feeds. mailctl retries every minute; see mailctl's log ('external lookups')."
	MailSpamRulesWhy       = "The mail server's spam filter has no rules yet, so it scores nothing (GTUBE and junk detection are off). mailctl asks for the import every minute; if this stays, see mailctl's log ('spam rules') and run ./portcullis up."
)

// Mail timing (§14.5).
const (
	mailCertWarn = 14 * 24 * time.Hour
	mailCertProb = 3 * 24 * time.Hour
	mailTimerOld = 36 * time.Hour
)

// MailIn is what the mail kinds judge.
type MailIn struct {
	// Unavailable: mailctl couldn't be read (no mail findings).
	Unavailable bool
	Checks      []mailprovider.Check
	Status      *mailprovider.Status
	// Plans are the added mail domains' DNS plans (their mail items).
	Plans []domains.Plan
	// Main is the main domain (its records are the CLI's: explain-only).
	Main string
	// RestartFailed: the Hub's last restart of mail failed (the reason).
	RestartFailed string
	// LANOnly: PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY=true; Podman: the Hub
	// runs under rootless Podman (client addresses are rewritten).
	LANOnly, Podman bool
	// ClientIPRewritten: core.env PORTCULLIS_MAIL_CLIENT_IP=rewritten
	// (the Hub's knowledge, never the provider's word).
	ClientIPRewritten bool
	// TimerKnown: the Hub tracks the mail timer's visits (POST
	// /host/mail/tls); TimerSeenAt the last one (nil: never).
	TimerKnown  bool
	TimerSeenAt *time.Time
	// Pending: a mass removal mailctl refused, waiting for confirmation
	// (nil: none).
	Pending *MailPendingIn
	// SyncBlocked: why the Hub sends mailctl nothing ("" = it does).
	SyncBlocked string
	// HubSecretInvalid: mail is on but the Hub's mail secret is missing
	// or too short: only mail_hub_secret_invalid fires.
	HubSecretInvalid bool
}

// MailPendingIn is a pending mass removal.
type MailPendingIn struct {
	Since     time.Time
	Users     []string // sorted
	UUIDs     []string // sorted
	Confirmed bool
	// Failed: the users whose mail passwords couldn't be revoked yet
	// (retrying).
	Failed []string
}

func init() {
	for _, k := range MailKinds {
		Register(mailCheck{kind: k})
	}
}

type mailCheck struct{ kind string }

func (c mailCheck) Kind() string { return c.kind }

func (c mailCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, f := range mailFindings(in) {
		if f.Kind == c.kind {
			out = append(out, f)
		}
	}
	return out
}

func sevOf(s string) Severity {
	switch s {
	case mailprovider.SeverityProblem:
		return Problem
	case mailprovider.SeverityWarning:
		return Warning
	}
	return Info
}

// mailFindings judges in.Mail (none while it's nil or unavailable).
func mailFindings(in *Inputs) []Finding {
	m := in.Mail
	if m != nil && m.HubSecretInvalid {
		return []Finding{{Kind: KindMailHubSecretInvalid, Severity: Problem,
			Title: "Mail can't be managed: the Hub's mail secret is missing or too short",
			Why:   "Mail is on, but the Hub can't reach mailctl without its secret (secrets/mail/hub-secret, at least 32 characters): nobody's mailbox, address or mail password changes, and removals don't reach the mail server.",
			Class: FixExplain, Steps: []string{"./portcullis up recreates the Hub with the mail secret"},
			FP: Fingerprint(KindMailHubSecretInvalid), Inputs: Digest(KindMailHubSecretInvalid)}}
	}
	if m == nil || m.Unavailable {
		return nil
	}
	var out []Finding
	mk := func(kind string, sev Severity, title, why string, steps []string, inputs any, dom string, subjects ...string) *Finding {
		f := Finding{Kind: kind, Severity: sev, Title: title, Why: why, Class: FixExplain, Steps: steps,
			FP: Fingerprint(kind, append([]string{dom}, subjects...)...), Inputs: Digest(inputs)}
		if dom != "" {
			f.Domains = []string{dom}
		}
		if len(f.Steps) == 0 {
			f.Steps = nil
		}
		out = append(out, f)
		return &out[len(out)-1]
	}
	byID := map[string]mailprovider.Check{}
	for _, c := range m.Checks {
		byID[c.ID] = c
	}
	bad := func(c mailprovider.Check) bool { return c.Severity != mailprovider.SeverityOK && c.Severity != "" }
	recWrong := map[string]bool{}
	for _, c := range m.Checks {
		if !bad(c) {
			continue
		}
		id, sub, _ := strings.Cut(c.ID, ":")
		switch id {
		case "port25":
			title := "Outbound mail on port 25 looks blocked"
			why := "Every delivery of the last 24 hours failed to connect to the receivers' port 25: the provider blocks it. Ask them to unblock port 25, or set a relay (MAIL_RELAY_HOST)."
			if c.Severity == mailprovider.SeverityInfo {
				title, why = "No outbound delivery yet: not known whether port 25 is open", "Nothing has been sent yet, so Portcullis can't tell whether the provider blocks port 25 (it never probes)."
			}
			mk(KindMailPort25Blocked, sevOf(c.Severity), title, why+" "+c.Detail, c.Steps, c, "")
		case "fcrdns_v4":
			kind, title := KindMailPTRMismatch, "The reverse DNS of the mail server's IPv4 address doesn't match"
			if ptrMissing(c) {
				kind, title = KindMailPTRMissing, "The mail server's IPv4 address has no reverse DNS"
			}
			mk(kind, Problem, title, "Receivers refuse or junk mail from an address whose PTR doesn't resolve back to it. "+c.Detail, c.Steps, c, "")
		case "fcrdns_v6":
			mk(KindMailIPv6PTR, Info, "Outbound mail stays on IPv4: the IPv6 address's reverse DNS isn't right",
				"Mail is sent over IPv6 only when its PTR resolves back to it. "+c.Detail, c.Steps, c, "")
		case "blocklist":
			sev := Problem
			if c.Severity == mailprovider.SeverityWarning {
				sev = Warning
			}
			mk(KindMailBlocklisted, sev, "The mail server's address is on a blocklist (or the lookup was refused)",
				"Receivers that use the blocklist refuse its mail. "+c.Detail, c.Steps, c, "")
		case "dkim_selftest":
			recWrong[sub] = true
			f := mk(KindMailRecordsWrong, Problem, "The DKIM key of "+sub+" in DNS isn't the one mail signs with",
				"Receivers fail the DKIM check of mail from "+sub+" while the published key differs. "+c.Detail, c.Steps, c, sub)
			mailRecordsFix(f, sub, m.Main)
		case "dkim_stuck":
			mk(KindMailDKIMStuck, Warning, "The new DKIM key of "+sub+" has waited over a day for DNS",
				"The key becomes active only once both public resolvers serve its record. "+c.Detail, c.Steps, c, sub)
		case "dkim_manual":
			mk(KindMailDKIMManual, Info, "DKIM keys of "+sub+" are managed by hand",
				"The main domain's DNS provider can't be written by Portcullis, so DKIM doesn't rotate. "+c.Detail, c.Steps, c, sub)
		case "cert":
			mk(KindMailCertExpiring, Problem, "The mail certificate isn't right",
				c.Detail, append(append([]string(nil), c.Steps...), MailCertStep), c, "")
		case "dmarc_reports", "tlsrpt_reports":
			mk(KindMailDMARCFailures, Warning, "Report failures: some senders of your domains fail SPF / DKIM or TLS",
				"Aggregate reports of the last 7 days name the failing sources. "+c.Detail, c.Steps, c, "", id)
		case "client_ip":
			mk(KindMailClientIPRewritten, Warning, "The mail server sees rewritten client addresses",
				"Under rootless Podman SPF, iprev and the IP blocklists are off and DMARC never rejects. "+c.Detail, c.Steps, c, "")
		case "rate_held":
			mailRateHeld(mk, m, byID, sub, c)
		case "spam_rules":
			// Only a problem (no rules imported): explain-only, no fix.
			if c.Severity == mailprovider.SeverityProblem {
				mk(KindMailSpamRulesMissing, Problem, "The mail server's spam filter has no rules yet",
					MailSpamRulesWhy, c.Steps, c, "")
			}
		case "external_lookups":
			if c.Severity == mailprovider.SeverityProblem {
				mk(KindMailExternalLookupsOn, Problem, "The spam filter's external lookups may be on",
					MailExternalLookupsWhy, c.Steps, c, "")
			}
		case "dane":
			// A Problem while DANE is off (mailctl's check says problem);
			// Info otherwise (invalid verdicts counted, nothing definite).
			sev := Info
			if c.Severity == mailprovider.SeverityProblem {
				sev = Problem
			}
			mk(KindMailDANEOff, sev, "DANE is off: the resolver can't validate DNSSEC",
				"Outbound mail doesn't verify remote domains' DANE records because mail-resolver can't validate DNSSEC from this host; check that it reaches the root servers over port 53. "+c.Detail, c.Steps, c, "")
		}
	}
	// The general mail_rate_held: sessions or a failed restart without a
	// held account.
	held := false
	for _, f := range out {
		held = held || f.Kind == KindMailRateHeld
	}
	if !held {
		var lines []string
		sev := Info
		if c, ok := byID["sessions_open"]; ok && bad(c) {
			lines, sev = append(lines, c.Detail), Warning
		}
		if m.RestartFailed != "" {
			lines, sev = append(lines, MailSessionsLine+": "+m.RestartFailed), Warning
		}
		for _, c := range m.Checks {
			if strings.HasPrefix(c.ID, "auth_failures:") && bad(c) {
				lines = append(lines, c.Detail)
			}
		}
		if len(lines) > 0 {
			mk(KindMailRateHeld, sev, "Mail sessions or logins need a look", strings.Join(lines, " "), nil, lines, "")
		}
	}
	// Added domains' plans: mail items missing or wrong.
	for _, p := range m.Plans {
		var items []domains.PlanItem
		for _, it := range p.Items {
			if it.Set == domains.SetMail && (it.Status == "missing" || it.Status == "wrong") {
				items = append(items, it)
			}
		}
		if len(items) == 0 || recWrong[p.Name] {
			continue
		}
		f := mk(KindMailRecordsWrong, Problem, "The mail records of "+p.Name+" aren't right",
			"Mail to or from "+p.Name+" fails or is refused until its MX, SPF, DKIM, DMARC and the other mail records are as wanted.",
			stepsOf(items), liveOf(items), p.Name)
		mailRecordsFix(f, p.Name, m.Main)
	}
	if p := m.Pending; p != nil {
		revokedLine := "Their mail passwords are revoked and they can't sign in to mail."
		if len(p.Failed) > 0 {
			revokedLine = "Revoking the mail passwords failed for " + strings.Join(p.Failed, ", ") + " (retrying); the others' are revoked."
		}
		f := mk(KindMailMassRemovalPend, Problem, "Removing "+itoa(len(p.Users))+" mailboxes at once waits for your confirmation",
			"More than half the mailboxes left mail_users at once ("+strings.Join(p.Users, ", ")+"), so mail refused to remove them on its own: an LDAP outage could look the same. "+revokedLine+" Their mailboxes stay until you confirm. If they shouldn't have left, add them back to mail_users instead.",
			[]string{"Check that these people really left mail_users, then confirm the removal (Settings → Mail or this fix)."},
			struct {
				UUIDs     []string
				Confirmed bool
				Failed    []string
			}{p.UUIDs, p.Confirmed, p.Failed}, "")
		if !p.Confirmed {
			f.Class, f.FixKind = FixOneClick, FixMailConfirmRemoval
		}
	}
	if m.SyncBlocked != "" {
		mk(KindMailSyncBlocked, Problem, "Mail changes aren't reaching the mail server",
			"The Hub sends the mail server nothing until this is resolved: "+m.SyncBlocked+".",
			[]string{"Confirm or resolve the pending removal (Settings → Mail), or put the people back in mail_users."}, m.SyncBlocked, "")
	}
	if m.LANOnly && (m.Podman || m.ClientIPRewritten) {
		mk(KindMailLANOnlyUnenforced, Problem, "LAN-only mail can't be enforced here",
			MailLANOnlyWhy+": mail passwords can't be limited to the local networks, so they work from anywhere.",
			[]string{MailLANOnlyStep}, struct{ LANOnly, Podman bool }{m.LANOnly, m.Podman}, "")
	}
	if st := m.Status; st != nil {
		if na := st.Cert.NotAfter; na != nil {
			left := na.Sub(in.Now)
			if left <= mailCertWarn {
				sev := Warning
				if left <= mailCertProb {
					sev = Problem
				}
				why := "The mail certificate expires on " + na.UTC().Format("2006-01-02") + ": clients and other servers then refuse TLS."
				if c, ok := byID["cert"]; ok && c.Detail != "" {
					why += " " + c.Detail
				}
				mk(KindMailCertExpiring, sev, "The mail certificate expires soon", why, []string{MailCertStep}, na.UTC(), "")
			}
		}
		for _, d := range st.DMARC {
			if d.Proposed != nil && *d.Proposed != "" {
				f := mk(KindMailDMARCPromote, Info, d.Domain+": DMARC can move to p="+*d.Proposed,
					"14 days of aggregate reports show no source failing both SPF and DKIM alignment.", nil,
					struct{ Domain, Policy, Proposed string }{d.Domain, d.Policy, *d.Proposed}, d.Domain)
				f.Class, f.FixKind = FixOneClick, FixMailDMARCPromote
			}
		}
		for _, x := range st.MTASTS {
			if x.EnforceReady {
				f := mk(KindMailMTASTSEnforce, Info, x.Domain+": MTA-STS can move to enforce",
					"7 days of testing with a valid certificate and no TLS report failure: senders may then refuse to deliver without TLS.", nil,
					struct{ Domain, Mode string }{x.Domain, x.Mode}, x.Domain)
				f.Class, f.FixKind = FixOneClick, FixMailMTASTSEnforce
			}
		}
	}
	if m.TimerKnown && (m.TimerSeenAt == nil || in.Now.Sub(*m.TimerSeenAt) > mailTimerOld) {
		last := "never"
		if m.TimerSeenAt != nil {
			last = m.TimerSeenAt.UTC().Format(time.RFC3339)
		}
		mk(KindMailTimerMissing, Warning, "The daily mail timer hasn't run",
			"Without it the mail certificate isn't renewed and the main domain's DKIM doesn't rotate (last run: "+last+").",
			[]string{MailTimerStep}, last, "")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out
}

// mailRecordsFix: on an added domain dns_apply (sets=mail); on the main
// domain explain-only with the server command.
func mailRecordsFix(f *Finding, dom, main string) {
	if strings.EqualFold(dom, main) {
		f.Class, f.FixKind = FixExplain, ""
		f.Steps = append(f.Steps, MailMainRecordsStep)
		return
	}
	f.Class, f.FixKind = FixOneClick, FixDNSApply
}

// mailRateHeld is one held account's mail_rate_held, with the
// auth_failures, sessions_open and restart lines.
func mailRateHeld(mk func(string, Severity, string, string, []string, any, string, ...string) *Finding, m *MailIn, byID map[string]mailprovider.Check, user string, c mailprovider.Check) {
	why := user + "'s outgoing mail is held by the sending limit. " + c.Detail
	if a, ok := byID["auth_failures:"+user]; ok && a.Severity != mailprovider.SeverityOK {
		why += " " + a.Detail
	}
	if s, ok := byID["sessions_open"]; ok && s.Severity != mailprovider.SeverityOK {
		why += " " + s.Detail
	}
	if m.RestartFailed != "" {
		why += " " + MailSessionsLine + ": " + m.RestartFailed
	}
	f := mk(KindMailRateHeld, Warning, user+"'s mail is held by the sending limit", why, c.Steps, c, "", user)
	f.Persons = []string{user}
}

// ptrMissing: the fcrdns check's reason is "missing". Without a reason
// (an older mailctl) the detail decides ("no PTR"), logged as a fallback.
func ptrMissing(c mailprovider.Check) bool {
	switch c.Reason {
	case mailprovider.ReasonPTRMissing:
		return true
	case mailprovider.ReasonPTRMismatch:
		return false
	}
	log.Printf("doctor: mail check %s has no reason (%q): judged from its detail", c.ID, c.Reason)
	return strings.Contains(strings.ToLower(c.Detail), "no ptr")
}

func itoa(n int) string { return strconv.Itoa(n) }
