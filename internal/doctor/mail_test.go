package doctor

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailprovider"
)

var mailNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func chk(id, sev, detail string) mailprovider.Check {
	return mailprovider.Check{ID: id, Severity: sev, Detail: detail, Steps: []string{}}
}

func mailRun(m *MailIn) []Finding {
	return mailFindings(&Inputs{Now: mailNow, Mail: m})
}

func okStatus() *mailprovider.Status {
	na := mailNow.Add(60 * 24 * time.Hour)
	return &mailprovider.Status{Bootstrap: true, Cert: mailprovider.StatusCert{NotAfter: &na}}
}

// TestMailKinds24: one fixture per kind (twenty-four), each producing
// exactly that kind with its severity and fix class; a clean input none;
// the kinds in contract order.
func TestMailKinds24(t *testing.T) {
	soon := mailNow.Add(2 * 24 * time.Hour)
	inWeek := mailNow.Add(10 * 24 * time.Hour)
	old := mailNow.Add(-37 * time.Hour)
	q := "quarantine"
	for _, c := range []struct {
		kind  string
		sev   Severity
		class FixClass
		in    func(m *MailIn)
	}{
		{KindMailPort25Blocked, Problem, FixExplain, func(m *MailIn) { m.Checks = []mailprovider.Check{chk("port25", "problem", "2 MX hosts timed out")} }},
		{KindMailPort25Blocked, Info, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("port25", "info", "no outbound delivery yet: not known")}
		}},
		{KindMailPTRMissing, Problem, FixExplain, func(m *MailIn) {
			c := chk("fcrdns_v4", "problem", "203.0.113.5 has no PTR record")
			c.Reason = mailprovider.ReasonPTRMissing
			m.Checks = []mailprovider.Check{c}
		}},
		{KindMailPTRMismatch, Problem, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("fcrdns_v4", "problem", "203.0.113.5 → host.example.net, which doesn't resolve back")}
		}},
		{KindMailBlocklisted, Problem, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("blocklist", "problem", "listed on zen.spamhaus.org")}
		}},
		{KindMailRecordsWrong, Problem, FixOneClick, func(m *MailIn) {
			m.Plans = []domains.Plan{{Name: "team-b.example.net", Items: []domains.PlanItem{{Set: "mail", Name: "team-b.example.net", Type: "MX", Status: "missing", Want: []string{"10 mail.example.org."}}}}}
		}},
		{KindMailDKIMStuck, Warning, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("dkim_stuck:team-b.example.net", "warning", "pending 30 h")}
		}},
		{KindMailDKIMManual, Info, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("dkim_manual:example.org", "info", "publish v1-rsa-…")}
		}},
		{KindMailCertExpiring, Problem, FixExplain, func(m *MailIn) { m.Status.Cert.NotAfter = &soon }},
		{KindMailCertExpiring, Warning, FixExplain, func(m *MailIn) { m.Status.Cert.NotAfter = &inWeek }},
		{KindMailDMARCFailures, Warning, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("dmarc_reports", "warning", "198.51.100.7 fails both")}
		}},
		{KindMailDMARCPromote, Info, FixOneClick, func(m *MailIn) {
			m.Status.DMARC = []mailprovider.StatusDMARC{{Domain: "example.org", Policy: "none", Proposed: &q}}
		}},
		{KindMailMTASTSEnforce, Info, FixOneClick, func(m *MailIn) {
			m.Status.MTASTS = []mailprovider.StatusMTASTS{{Domain: "example.org", Mode: "testing", EnforceReady: true}}
		}},
		{KindMailIPv6PTR, Info, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("fcrdns_v6", "warning", "2001:db8::5 has no PTR")}
		}},
		{KindMailClientIPRewritten, Warning, FixExplain, func(m *MailIn) { m.Checks = []mailprovider.Check{chk("client_ip", "warning", "rewritten")} }},
		{KindMailRateHeld, Warning, FixExplain, func(m *MailIn) { m.Checks = []mailprovider.Check{chk("rate_held:alice", "warning", "12 held")} }},
		{KindMailTimerMissing, Warning, FixExplain, func(m *MailIn) { m.TimerKnown, m.TimerSeenAt = true, &old }},
		{KindMailDANEOff, Info, FixExplain, func(m *MailIn) { m.Checks = []mailprovider.Check{chk("dane", "info", "no AD bit")} }},
		{KindMailDANEOff, Info, FixExplain, func(m *MailIn) { m.Checks = []mailprovider.Check{chk("dane", "warning", "2 invalid verdicts")} }},
		{KindMailDANEOff, Problem, FixExplain, func(m *MailIn) { m.Checks = []mailprovider.Check{chk("dane", "problem", "DANE is off")} }},
		{KindMailLANOnlyUnenforced, Problem, FixExplain, func(m *MailIn) { m.LANOnly, m.Podman = true, true }},
		{KindMailMassRemovalPend, Problem, FixOneClick, func(m *MailIn) {
			m.Pending = &MailPendingIn{Since: mailNow, Users: []string{"alice", "bob"}, UUIDs: []string{"u1", "u2"}}
		}},
		{KindMailSyncBlocked, Problem, FixExplain, func(m *MailIn) { m.SyncBlocked = "no baseline" }},
		{KindMailMassRemovalPend, Problem, FixExplain, func(m *MailIn) {
			m.Pending = &MailPendingIn{Since: mailNow, Users: []string{"alice"}, UUIDs: []string{"u1"}, Confirmed: true}
		}},
		{KindMailLANOnlyUnenforced, Problem, FixExplain, func(m *MailIn) { m.LANOnly = true; m.ClientIPRewritten = true }},
		{KindMailLANOnlyUnenforced, Problem, FixExplain, func(m *MailIn) { m.LANOnly = true; m.LANBreachUser = "alice" }},
		{KindMailProviderUnreach, Problem, FixExplain, func(m *MailIn) {
			m.Unavailable, m.UnreachableSince = true, ptrTime(mailNow.Add(-11*time.Minute))
		}},
		{KindMailProviderCheck, Warning, FixExplain, func(m *MailIn) {
			m.Checks = []mailprovider.Check{{ID: "x-queue_db", Severity: "warning", Title: "Queue DB", Detail: "slow"}}
		}},
		{KindMailProviderMissing, Warning, FixExplain, func(m *MailIn) { m.Wired = false }},
		{KindMailVoidPending, Problem, FixExplain, func(m *MailIn) { m.VoidOwed, m.VoidError = true, "the provider's void failed" }},
		{KindMailProviderRefused, Problem, FixExplain, func(m *MailIn) { m.Refused = "the mail provider's template changed" }},
		{KindMailRecordsWrong, Problem, FixOneClick, func(m *MailIn) {
			m.SetProblems = []MailSetProblem{{Domain: "team-b.example.net", Text: "mail set: team-b.example.net A: A records are not allowed"}}
		}},
		{KindMailRecordsWrong, Problem, FixOneClick, func(m *MailIn) {
			m.Checks = []mailprovider.Check{chk("records:team-b.example.net", "problem", "MX missing")}
		}},
		{KindMailCertExpiring, Problem, FixExplain, func(m *MailIn) { m.CertNotAfter = &soon }},
	} {
		m := &MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus()}
		c.in(m)
		fs := mailRun(m)
		if len(fs) != 1 || fs[0].Kind != c.kind || fs[0].Severity != c.sev || fs[0].Class != c.class {
			t.Errorf("%s (%s): %+v", c.kind, c.sev, fs)
		}
	}
	seen := map[string]bool{}
	for _, k := range MailKinds {
		seen[k] = true
	}
	want := []string{"mail_port25_blocked", "mail_ptr_missing", "mail_ptr_mismatch", "mail_blocklisted", "mail_records_wrong", "mail_dkim_stuck",
		"mail_dkim_manual", "mail_cert_expiring", "mail_dmarc_failures", "mail_dmarc_promote", "mail_mtasts_enforce", "mail_ipv6_ptr",
		"mail_client_ip_rewritten", "mail_rate_held", "mail_timer_missing", "mail_dane_off", "mail_lan_only_unenforced",
		"mail_mass_removal_pending", "mail_sync_blocked", "mail_provider_unreachable", "mail_provider_check", "mail_provider_missing",
		"mail_void_pending", "mail_provider_refused"}
	if !slices.Equal(MailKinds, want) || len(seen) != 24 {
		t.Fatalf("mail kinds %v", MailKinds)
	}
	for _, k := range []string{"mail_hub_secret_invalid", "mail_spam_rules_missing", "mail_external_lookups_on"} {
		if slices.Contains(Kinds(), k) {
			t.Errorf("%s still registered", k)
		}
	}
	if fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus(), Checks: []mailprovider.Check{chk("port25", "ok", ""), chk("cert", "ok", "")}}); len(fs) != 0 {
		t.Fatalf("clean: %+v", fs)
	}
	for _, k := range MailKinds {
		if !slices.Contains(Kinds(), k) {
			t.Errorf("kind %s not registered", k)
		}
	}
}

// TestMailOffAndUnavailable: no mail input, no findings; unavailable,
// no provider-check findings (the Hub-judged ones still fire) and the
// report flag.
func TestMailOffAndUnavailable(t *testing.T) {
	if fs := mailFindings(&Inputs{Now: mailNow}); fs != nil {
		t.Fatalf("off: %+v", fs)
	}
	in := &Inputs{Now: mailNow, Mail: &MailIn{Wired: true, Unavailable: true, Checks: []mailprovider.Check{chk("port25", "problem", "x")}}}
	if fs := mailFindings(in); len(fs) != 0 {
		t.Fatalf("unavailable: %+v", fs)
	}
	if r := Run(in, nil); !r.MailUnavailable {
		t.Fatal("no mail_unavailable")
	}
	if r := Run(&Inputs{Now: mailNow}, nil); r.MailUnavailable {
		t.Fatal("mail_unavailable with mail off")
	}
	in.Mail.VoidOwed, in.Mail.VoidError = true, "x"
	if fs := mailFindings(in); len(fs) != 1 || fs[0].Kind != KindMailVoidPending {
		t.Fatalf("hub-judged while unavailable: %+v", fs)
	}
}

// TestProviderUnreachableAfter10Min: 9 min unanswered is nothing yet,
// 10 min is the Problem.
func TestProviderUnreachableAfter10Min(t *testing.T) {
	for _, c := range []struct {
		ago  time.Duration
		fire bool
	}{{9 * time.Minute, false}, {10 * time.Minute, true}} {
		fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Unavailable: true, UnreachableSince: ptrTime(mailNow.Add(-c.ago))})
		if (len(fs) == 1 && fs[0].Kind == KindMailProviderUnreach && fs[0].Title == MailUnreachTitle && fs[0].Steps[0] == MailUnreachStep) != c.fire {
			t.Errorf("%v: %+v", c.ago, fs)
		}
	}
}

// TestProviderMissingWhenSlotOpen: the slot open and nothing wired is a
// Warning with the step; mail off is nothing.
func TestProviderMissingWhenSlotOpen(t *testing.T) {
	fs := mailRun(&MailIn{Main: "example.org"})
	if len(fs) != 1 || fs[0].Kind != KindMailProviderMissing || fs[0].Severity != Warning || fs[0].Steps[0] != MailMissingStep {
		t.Fatalf("%+v", fs)
	}
}

// TestVoidPendingProblem: a failing owed void is a Problem; owed but not
// failed (yet) is nothing.
func TestVoidPendingProblem(t *testing.T) {
	if fs := mailRun(&MailIn{Wired: true, Main: "example.org", VoidOwed: true}); len(fs) != 0 {
		t.Fatalf("not failed yet: %+v", fs)
	}
	fs := mailRun(&MailIn{Wired: true, Main: "example.org", VoidOwed: true, VoidError: "the provider's void failed: 500"})
	if len(fs) != 1 || fs[0].Kind != KindMailVoidPending || fs[0].Severity != Problem || fs[0].Steps[0] != MailVoidStep || !strings.Contains(fs[0].Why, "void failed") {
		t.Fatalf("%+v", fs)
	}
}

// TestProviderRefusedOnHold: a hold (or an owed stop) is the Problem with
// the ruled title; the stop's state is in the why.
func TestProviderRefusedOnHold(t *testing.T) {
	fs := mailRun(&MailIn{Wired: true, Main: "example.org", Refused: "the mail provider's template changed: review and confirm on its Mail tab", StopError: "stopping the held mail provider is owed and not done yet"})
	if len(fs) != 1 || fs[0].Kind != KindMailProviderRefused || fs[0].Title != MailRefusedTitle || !strings.Contains(fs[0].Why, "owed and not done yet") {
		t.Fatalf("%+v", fs)
	}
}

// TestXCheckPlainTextNoFix: an x- check's title, detail and steps are
// plain text (escaped, one line, clipped), at most a Problem, no fix.
func TestXCheckPlainTextNoFix(t *testing.T) {
	c := mailprovider.Check{ID: "x-spam", Severity: "problem", Title: "<b>Spam</b>\n[click](http://evil)", Detail: strings.Repeat("d", 900) + "<script>",
		Steps: []string{"<a href=x>run</a>"}}
	fs := mailRun(&MailIn{Wired: true, Main: "example.org", Checks: []mailprovider.Check{c, {ID: "x-ok", Severity: "ok"}}})
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
	f := fs[0]
	if f.Kind != KindMailProviderCheck || f.Severity != Problem || f.Class != FixExplain || f.FixKind != "" ||
		strings.ContainsAny(f.Title, "<>\n") || strings.Contains(f.Why, "<script>") || len([]rune(f.Why)) > 520 || strings.Contains(f.Steps[0], "<a") {
		t.Fatalf("%+v", f)
	}
}

// TestCatalogMapping: each catalog check maps to its kind, as before.
func TestCatalogMapping(t *testing.T) {
	for id, kind := range map[string]string{"port25": KindMailPort25Blocked, "fcrdns_v6": KindMailIPv6PTR, "blocklist": KindMailBlocklisted,
		"cert": KindMailCertExpiring, "dane": KindMailDANEOff, "client_ip": KindMailClientIPRewritten, "dmarc_reports": KindMailDMARCFailures,
		"tlsrpt_reports": KindMailDMARCFailures, "records:team-b.example.net": KindMailRecordsWrong, "dkim_selftest:team-b.example.net": KindMailRecordsWrong,
		"dkim_stuck:team-b.example.net": KindMailDKIMStuck, "dkim_manual:example.org": KindMailDKIMManual, "rate_held:bob": KindMailRateHeld} {
		fs := mailRun(&MailIn{Wired: true, Main: "example.org", Status: okStatus(), Checks: []mailprovider.Check{chk(id, "problem", "x")}})
		if len(fs) != 1 || fs[0].Kind != kind {
			t.Errorf("%s: %+v", id, fs)
		}
	}
}

// TestCertExpiringFromCore: the CLI-reported not_after alone (no
// provider status) and the earlier of the two decide.
func TestCertExpiringFromCore(t *testing.T) {
	soon := mailNow.Add(48 * time.Hour)
	fs := mailRun(&MailIn{Wired: true, Main: "example.org", Unavailable: true, CertNotAfter: &soon})
	if len(fs) != 1 || fs[0].Kind != KindMailCertExpiring || fs[0].Severity != Problem {
		t.Fatalf("core only: %+v", fs)
	}
	later := mailNow.Add(10 * 24 * time.Hour)
	st := okStatus()
	st.Cert.NotAfter = &soon
	fs = mailRun(&MailIn{Wired: true, Main: "example.org", Status: st, CertNotAfter: &later})
	if len(fs) != 1 || fs[0].Severity != Problem {
		t.Fatalf("earlier wins: %+v", fs)
	}
}

// TestMailRecordsWrongFixSets: an added domain's finding is dns_apply
// with sets=mail; the main domain's is explain-only with the command;
// dkim_selftest feeds the same kind.
func TestMailRecordsWrongFixSets(t *testing.T) {
	if s := DNSFixSets(KindMailRecordsWrong); len(s) != 1 || s[0] != "mail" {
		t.Fatalf("sets %v", s)
	}
	fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus(), Checks: []mailprovider.Check{chk("dkim_selftest:example.org", "problem", "p= differs")}})
	if len(fs) != 1 || fs[0].Class != FixExplain || fs[0].Steps[len(fs[0].Steps)-1] != MailMainRecordsStep || fs[0].Domains[0] != "example.org" {
		t.Fatalf("main: %+v", fs)
	}
	fs = mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus(), Checks: []mailprovider.Check{chk("dkim_selftest:team-b.example.net", "problem", "p= differs")},
		Plans: []domains.Plan{{Name: "team-b.example.net", Items: []domains.PlanItem{{Set: "mail", Name: "x", Type: "TXT", Status: "wrong"}}}}})
	if len(fs) != 1 || fs[0].FixKind != FixDNSApply || fs[0].Domains[0] != "team-b.example.net" {
		t.Fatalf("added: %+v", fs)
	}
}

// TestTimerMissingAfter36h: null or older than 36 h fires, 35 h doesn't.
func TestTimerMissingAfter36h(t *testing.T) {
	for _, c := range []struct {
		at   *time.Time
		fire bool
	}{{nil, true}, {ptrTime(mailNow.Add(-36*time.Hour - time.Minute)), true}, {ptrTime(mailNow.Add(-35 * time.Hour)), false}} {
		fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus(), TimerKnown: true, TimerSeenAt: c.at})
		if (len(fs) == 1 && fs[0].Kind == KindMailTimerMissing) != c.fire {
			t.Errorf("%v: %+v", c.at, fs)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestMailRateHeldLines: the restart failure and sessions_open show up
// as mail_rate_held, alone or in a held account's explain.
func TestMailRateHeldLines(t *testing.T) {
	fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus(), RestartFailed: "the engine refused"})
	if len(fs) != 1 || fs[0].Kind != KindMailRateHeld || fs[0].Severity != Warning || !strings.Contains(fs[0].Why, MailSessionsLine) {
		t.Fatalf("restart failed: %+v", fs)
	}
	fs = mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus(), RestartFailed: "x",
		Checks: []mailprovider.Check{chk("rate_held:bob", "warning", "3 held")}})
	if len(fs) != 1 || fs[0].Persons[0] != "bob" || !strings.Contains(fs[0].Why, "3 held") || !strings.Contains(fs[0].Why, MailSessionsLine) {
		t.Fatalf("held: %+v", fs)
	}
}

// TestLANOnlyUnenforced: LAN-only on Docker with preserved addresses is
// fine; off is fine under Podman.
func TestLANOnlyUnenforced(t *testing.T) {
	st := okStatus()
	if fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: st, LANOnly: true}); len(fs) != 0 {
		t.Fatalf("docker LAN-only: %+v", fs)
	}
	if fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: st, Podman: true}); len(fs) != 0 {
		t.Fatalf("podman without LAN-only: %+v", fs)
	}
	fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: st, LANOnly: true, Podman: true})
	if len(fs) != 1 || !strings.Contains(fs[0].Why, MailLANOnlyWhy) || fs[0].Steps[0] != MailLANOnlyStep {
		t.Fatalf("podman LAN-only: %+v", fs)
	}
}

// TestPTRReason: the reason decides missing vs mismatch, whatever the
// detail says; without one the detail is the fallback.
func TestPTRReason(t *testing.T) {
	for _, c := range []struct {
		reason, detail, want string
	}{
		{"missing", "203.0.113.5 → host.example.net", KindMailPTRMissing},
		{"mismatch", "203.0.113.5 has no PTR record", KindMailPTRMismatch},
		{"", "203.0.113.5 has no PTR record", KindMailPTRMismatch},
		{"", "203.0.113.5 → host.example.net", KindMailPTRMismatch},
	} {
		ch := chk("fcrdns_v4", "problem", c.detail)
		ch.Reason = c.reason
		fs := mailRun(&MailIn{Wired: true, Instance: "mailsrv", Main: "example.org", Status: okStatus(), Checks: []mailprovider.Check{ch}})
		if len(fs) != 1 || fs[0].Kind != c.want {
			t.Errorf("%q %q: %+v", c.reason, c.detail, fs)
		}
	}
}
