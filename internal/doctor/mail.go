package doctor

import (
	"html"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailprovider"
)

// Mail kinds (contract §14.5 "Mail", mail provider): twenty-four kinds
// judged on the wired provider's checks and status, the Hub's own state
// (the slot, the void, the hold, the timer's visits, mail.tls) and the
// added mail domains' plans (Inputs.Mail; nil = PORTCULLIS_MAIL off: none
// fire). Unavailable (a wired provider couldn't be read): the
// provider-check kinds don't fire and Report.MailUnavailable is set; the
// Hub-judged kinds still do. Every finding about a domain carries Domains
// [<e>].
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
	KindMailProviderUnreach   = "mail_provider_unreachable"
	KindMailProviderCheck     = "mail_provider_check"
	KindMailProviderMissing   = "mail_provider_missing"
	KindMailVoidPending       = "mail_void_pending"
	KindMailProviderRefused   = "mail_provider_refused"
)

// MailKinds are the twenty-four mail kinds, in contract order.
var MailKinds = []string{KindMailPort25Blocked, KindMailPTRMissing, KindMailPTRMismatch, KindMailBlocklisted, KindMailRecordsWrong,
	KindMailDKIMStuck, KindMailDKIMManual, KindMailCertExpiring, KindMailDMARCFailures, KindMailDMARCPromote, KindMailMTASTSEnforce,
	KindMailIPv6PTR, KindMailClientIPRewritten, KindMailRateHeld, KindMailTimerMissing, KindMailDANEOff, KindMailLANOnlyUnenforced,
	KindMailMassRemovalPend, KindMailSyncBlocked, KindMailProviderUnreach, KindMailProviderCheck, KindMailProviderMissing,
	KindMailVoidPending, KindMailProviderRefused}

// Mail fix kinds (§14.6); mail_records_wrong on an added domain uses
// dns_apply with sets=mail.
const (
	FixMailDMARCPromote   = "mail_dmarc_promote"
	FixMailMTASTSEnforce  = "mail_mtasts_enforce"
	FixMailConfirmRemoval = "mail_confirm_removal"
)

// Mail steps the explain-only findings end with.
const (
	MailMainRecordsStep = "Run `./portcullis dns setup --only mail` on the server"
	MailCertStep        = "Run `./portcullis mail cert` on the server"
	MailTimerStep       = "Run `./portcullis mail schedule --systemd` on the server"
	MailSessionsLine    = "mail sessions may still be open"
	MailLANOnlyWhy      = "LAN-only needs the real client address; rootless Podman rewrites it"
	MailLANOnlyStep     = "Turn LAN-only off: run `./portcullis mail enable --lan-only false` on the server"
	MailUnreachTitle    = "Mail can't be managed: the mail provider doesn't answer"
	MailUnreachStep     = "Check the instance on its Mail tab and its logs"
	MailMissingStep     = "Wire a mail server (Settings → Mail) or run ./portcullis mail disable"
	MailVoidStep        = "Retry on the Mail tab, or look at the provider's logs"
	MailRefusedTitle    = "the mail provider's template changed: review and confirm on its Mail tab"
)

// mailUnreachAfter: the provider is reported unreachable once it hasn't
// answered (or kept bootstrap: false) this long.
const mailUnreachAfter = 10 * time.Minute

// Mail timing (§14.5).
const (
	mailCertWarn = 14 * 24 * time.Hour
	mailCertProb = 3 * 24 * time.Hour
	mailTimerOld = 36 * time.Hour
)

// MailIn is what the mail kinds judge.
type MailIn struct {
	// Wired: a provider is wired (Instance); nothing wired with the slot
	// open is mail_provider_missing.
	Wired    bool
	Instance string
	// Unavailable: the wired provider couldn't be read now (the
	// provider-check kinds don't fire); UnreachableSince is when it
	// started not answering (or answering bootstrap: false), with why.
	Unavailable      bool
	UnreachableSince *time.Time
	UnreachableWhy   string
	// VoidError: a void is owed and its last attempt failed ("" = none).
	VoidOwed  bool
	VoidError string
	// Refused: why the wired provider is held or refused (the hold's
	// reason, an unknown api_version); StopError the held stop's state.
	Refused   string
	StopError string
	// CertNotAfter: the mail certificate's not_after the CLI reported
	// (POST /host/mail/tls), nil: not reported.
	CertNotAfter *time.Time
	// SetProblems: the Hub's own mail record refusals (a provider set
	// outside the rules, an MTA-STS policy, a retiring DKIM waiting).
	SetProblems []MailSetProblem
	// LANBreachUser: a credential beyond the Local networks the Hub
	// revoked under LAN-only ("" = none).
	LANBreachUser string
	Checks        []mailprovider.Check
	Status        *mailprovider.Status
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
	// SyncBlocked: why the Hub sends the provider nothing ("" = it does).
	SyncBlocked string
}

// MailSetProblem is one domain's mail record problem the Hub judged.
type MailSetProblem struct {
	Domain, Text string
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

// mailFindings judges in.Mail (none while it's nil). The Hub-judged
// kinds always run; the provider-check kinds only while the provider
// answered.
func mailFindings(in *Inputs) []Finding {
	m := in.Mail
	if m == nil {
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
	recWrong := map[string]bool{}
	if !m.Unavailable {
		mailProviderFindings(in, m, mk, recWrong)
	}
	mailHubFindings(in, m, mk, recWrong)
	sort.SliceStable(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out
}

type mailMk = func(kind string, sev Severity, title, why string, steps []string, inputs any, dom string, subjects ...string) *Finding

// mailProviderFindings are the kinds judged on the provider's checks and
// status (mapped from the check catalog, §19.8).
func mailProviderFindings(in *Inputs, m *MailIn, mk mailMk, recWrong map[string]bool) {
	byID := map[string]mailprovider.Check{}
	for _, c := range m.Checks {
		byID[c.ID] = c
	}
	bad := func(c mailprovider.Check) bool { return c.Severity != mailprovider.SeverityOK && c.Severity != "" }
	for _, c := range m.Checks {
		if !bad(c) {
			continue
		}
		id, sub, _ := strings.Cut(c.ID, ":")
		switch {
		case strings.HasPrefix(c.ID, "x-"):
			// A provider's own check: plain text only, at most a
			// Problem, never a fix (§19.8).
			sev := sevOf(c.Severity)
			title := plainText(c.Title, 80)
			if title == "" {
				title = c.ID
			}
			var steps []string
			for _, st := range c.Steps {
				steps = append(steps, plainText(st, 200))
			}
			mk(KindMailProviderCheck, sev, title, plainText(c.Detail, 500), steps, c, "", c.ID)
			continue
		}
		switch id {
		case "port25":
			title := "Outbound mail on port 25 looks blocked"
			why := "Every delivery of the last 24 hours failed to connect to the receivers' port 25: the provider blocks it. Ask them to unblock port 25, or set a relay (Settings → Mail)."
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
		case "dkim_selftest", "records":
			if recWrong[sub] {
				continue
			}
			recWrong[sub] = true
			title := "The DKIM key of " + sub + " in DNS isn't the one mail signs with"
			why := "Receivers fail the DKIM check of mail from " + sub + " while the published key differs. "
			if id == "records" {
				title, why = "The mail records of "+sub+" aren't right", "Mail to or from "+sub+" fails or is refused until its mail records are as wanted. "
			}
			f := mk(KindMailRecordsWrong, Problem, title, why+c.Detail, c.Steps, c, sub)
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
			mailRateHeld(mk, m, sub, c)
		case "dane":
			// A Problem while DANE is off (the check says problem); Info
			// otherwise (invalid verdicts counted, nothing definite).
			sev := Info
			if c.Severity == mailprovider.SeverityProblem {
				sev = Problem
			}
			mk(KindMailDANEOff, sev, "DANE is off: the resolver can't validate DNSSEC",
				"Outbound mail doesn't verify remote domains' DANE records because the provider's resolver can't validate DNSSEC from this host; check that it reaches the root servers over port 53. "+c.Detail, c.Steps, c, "")
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
		recWrong[p.Name] = true
		f := mk(KindMailRecordsWrong, Problem, "The mail records of "+p.Name+" aren't right",
			"Mail to or from "+p.Name+" fails or is refused until its MX, SPF, DKIM, DMARC and the other mail records are as wanted.",
			stepsOf(items), liveOf(items), p.Name)
		mailRecordsFix(f, p.Name, m.Main)
	}
	if st := m.Status; st != nil {
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
}

// mailHubFindings are the kinds the Hub judges on its own state: they
// fire whether or not the provider answers.
func mailHubFindings(in *Inputs, m *MailIn, mk mailMk, recWrong map[string]bool) {
	if !m.Wired {
		mk(KindMailProviderMissing, Warning, "Mail is on, but no mail server is wired",
			"The slot is open (PORTCULLIS_MAIL=on) and no app is this server's mail provider: nobody has a mailbox and no mail is sent or received.",
			[]string{MailMissingStep}, "missing", "")
	}
	if m.Wired && m.UnreachableSince != nil && in.Now.Sub(*m.UnreachableSince) >= mailUnreachAfter {
		why := "The wired mail provider " + m.Instance + " hasn't answered (or kept reporting bootstrap: false) since " + m.UnreachableSince.UTC().Format(time.RFC3339) +
			": nobody's mailbox, address or mail password changes, and removals don't reach it."
		if m.UnreachableWhy != "" {
			why += " " + plainText(m.UnreachableWhy, 300)
		}
		mk(KindMailProviderUnreach, Problem, MailUnreachTitle, why, []string{MailUnreachStep}, m.Instance, "")
	}
	if m.VoidOwed && m.VoidError != "" {
		mk(KindMailVoidPending, Problem, "Mail passwords couldn't be voided: the mail provider stays stopped",
			"A void of every mail password is owed (a wiring, a switch or a restore) and its last attempt failed: "+plainText(m.VoidError, 300)+". The provider stays stopped and the Hub retries every 5 min.",
			[]string{MailVoidStep}, m.VoidError, "")
	}
	if m.Refused != "" || m.StopError != "" {
		why := plainText(m.Refused, 300)
		if why == "" {
			why = MailRefusedTitle
		}
		why += ". The running provider keeps serving and taking revocations until an administrator confirms; nothing of the changed template starts."
		if m.StopError != "" {
			why += " " + plainText(m.StopError, 300) + ": the held provider may still serve."
		}
		mk(KindMailProviderRefused, Problem, MailRefusedTitle, why, []string{"Review the change and confirm on the instance's Mail tab"},
			struct{ Refused, Stop string }{m.Refused, m.StopError}, "")
	}
	for _, p := range m.SetProblems {
		d := strings.ToLower(p.Domain)
		if recWrong[d] {
			continue
		}
		recWrong[d] = true
		f := mk(KindMailRecordsWrong, Problem, "The mail records of "+d+" aren't right",
			"The Hub refused what the mail provider wants published: "+plainText(p.Text, 500)+". The last good records stay published.", nil, p, d)
		mailRecordsFix(f, d, m.Main)
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
	} else if m.LANOnly && m.LANBreachUser != "" {
		mk(KindMailLANOnlyUnenforced, Problem, "A mail password of "+m.LANBreachUser+" worked beyond the local networks",
			"Under LAN-only the mail provider created or kept a mail password of "+m.LANBreachUser+" not limited to the Local networks; the Hub revoked it. The provider doesn't enforce LAN-only as it must.",
			[]string{"Check the mail provider's LAN-only support (its app page), or turn LAN-only off"}, m.LANBreachUser, "", m.LANBreachUser)
	}
	// The certificate: the CLI's not_after and the provider's, the
	// earlier one decides.
	var na *time.Time
	if m.CertNotAfter != nil {
		na = m.CertNotAfter
	}
	if !m.Unavailable && m.Status != nil && m.Status.Cert.NotAfter != nil && (na == nil || m.Status.Cert.NotAfter.Before(*na)) {
		na = m.Status.Cert.NotAfter
	}
	if na != nil {
		if left := na.Sub(in.Now); left <= mailCertWarn {
			sev := Warning
			if left <= mailCertProb {
				sev = Problem
			}
			mk(KindMailCertExpiring, sev, "The mail certificate expires soon",
				"The mail certificate expires on "+na.UTC().Format("2006-01-02")+": clients and other servers then refuse TLS.", []string{MailCertStep}, na.UTC(), "")
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
	// A failed restart alone (no held account): mail_rate_held.
	held := false
	if !m.Unavailable {
		for _, c := range m.Checks {
			held = held || (strings.HasPrefix(c.ID, "rate_held:") && c.Severity != mailprovider.SeverityOK && c.Severity != "")
		}
	}
	if !held && m.RestartFailed != "" {
		mk(KindMailRateHeld, Warning, "Mail sessions or logins need a look", MailSessionsLine+": "+m.RestartFailed, nil, m.RestartFailed, "")
	}
}

// plainText is provider-derived text for the report: one line, clipped,
// HTML-escaped (no markup, no links: §19.8).
func plainText(s string, n int) string {
	return html.EscapeString(mailprovider.Shape(s, n))
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
func mailRateHeld(mk mailMk, m *MailIn, user string, c mailprovider.Check) {
	why := user + "'s outgoing mail is held by the sending limit. " + c.Detail
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
