package doctor

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailctl"
)

var mailNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func chk(id, sev, detail string) mailctl.Check {
	return mailctl.Check{ID: id, Severity: sev, Detail: detail, Steps: []string{}}
}

func mailRun(m *MailIn) []Finding {
	return mailFindings(&Inputs{Now: mailNow, Mail: m})
}

func okStatus() *mailctl.Status {
	t := mailNow.Add(-time.Hour)
	na := mailNow.Add(60 * 24 * time.Hour)
	return &mailctl.Status{Bootstrap: true, Cert: mailctl.StatusCert{NotAfter: &na}, TimerSeenAt: &t}
}

// TestMailKinds: one fixture per kind (eighteen), each producing exactly
// that kind with its severity and fix class; a clean input none.
func TestMailKinds(t *testing.T) {
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
		{KindMailPort25Blocked, Problem, FixExplain, func(m *MailIn) { m.Checks = []mailctl.Check{chk("port25", "problem", "2 MX hosts timed out")} }},
		{KindMailPort25Blocked, Info, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("port25", "info", "no outbound delivery yet: not known")}
		}},
		{KindMailPTRMissing, Problem, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("fcrdns_v4", "problem", "203.0.113.5 has no PTR record")}
		}},
		{KindMailPTRMismatch, Problem, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("fcrdns_v4", "problem", "203.0.113.5 → host.example.net, which doesn't resolve back")}
		}},
		{KindMailBlocklisted, Problem, FixExplain, func(m *MailIn) { m.Checks = []mailctl.Check{chk("blocklist", "problem", "listed on zen.spamhaus.org")} }},
		{KindMailRecordsWrong, Problem, FixOneClick, func(m *MailIn) {
			m.Plans = []domains.Plan{{Name: "team-b.example.net", Items: []domains.PlanItem{{Set: "mail", Name: "team-b.example.net", Type: "MX", Status: "missing", Want: []string{"10 mail.example.org."}}}}}
		}},
		{KindMailDKIMStuck, Warning, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("dkim_stuck:team-b.example.net", "warning", "pending 30 h")}
		}},
		{KindMailDKIMManual, Info, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("dkim_manual:example.org", "info", "publish v1-rsa-…")}
		}},
		{KindMailCertExpiring, Problem, FixExplain, func(m *MailIn) { m.Status.Cert.NotAfter = &soon }},
		{KindMailCertExpiring, Warning, FixExplain, func(m *MailIn) { m.Status.Cert.NotAfter = &inWeek }},
		{KindMailDMARCFailures, Warning, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("dmarc_reports", "warning", "198.51.100.7 fails both")}
		}},
		{KindMailDMARCPromote, Info, FixOneClick, func(m *MailIn) {
			m.Status.DMARC = []mailctl.StatusDMARC{{Domain: "example.org", Policy: "none", Proposed: &q}}
		}},
		{KindMailMTASTSEnforce, Info, FixOneClick, func(m *MailIn) {
			m.Status.MTASTS = []mailctl.StatusMTASTS{{Domain: "example.org", Mode: "testing", EnforceReady: true}}
		}},
		{KindMailIPv6PTR, Info, FixExplain, func(m *MailIn) { m.Checks = []mailctl.Check{chk("fcrdns_v6", "warning", "2001:db8::5 has no PTR")} }},
		{KindMailClientIPRewritten, Warning, FixExplain, func(m *MailIn) { m.Checks = []mailctl.Check{chk("client_ip", "warning", "rewritten")} }},
		{KindMailRateHeld, Warning, FixExplain, func(m *MailIn) { m.Checks = []mailctl.Check{chk("rate_held:alice", "warning", "12 held")} }},
		{KindMailTimerMissing, Warning, FixExplain, func(m *MailIn) { m.Status.TimerSeenAt = &old }},
		{KindMailDANEOff, Info, FixExplain, func(m *MailIn) { m.Checks = []mailctl.Check{chk("dane", "info", "no AD bit")} }},
		{KindMailLANOnlyUnenforced, Problem, FixExplain, func(m *MailIn) { m.LANOnly, m.Podman = true, true }},
		{KindMailMassRemovalPend, Problem, FixOneClick, func(m *MailIn) {
			m.Pending = &MailPendingIn{Since: mailNow, Users: []string{"alice", "bob"}, UUIDs: []string{"u1", "u2"}}
		}},
		{KindMailSyncBlocked, Problem, FixExplain, func(m *MailIn) { m.SyncBlocked = "no baseline" }},
		{KindMailHubSecretInvalid, Problem, FixExplain, func(m *MailIn) { m.HubSecretInvalid = true }},
		{KindMailSpamRulesMissing, Problem, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("spam_rules", "problem", "no spam-filter rules imported")}
		}},
		{KindMailExternalLookupsOn, Problem, FixExplain, func(m *MailIn) {
			m.Checks = []mailctl.Check{chk("external_lookups", "problem", "couldn't turn them off")}
		}},
		{KindMailMassRemovalPend, Problem, FixExplain, func(m *MailIn) {
			m.Pending = &MailPendingIn{Since: mailNow, Users: []string{"alice"}, UUIDs: []string{"u1"}, Confirmed: true}
		}},
		{KindMailLANOnlyUnenforced, Problem, FixExplain, func(m *MailIn) { m.LANOnly = true; m.Status.ClientIP = "rewritten" }},
	} {
		m := &MailIn{Main: "example.org", Status: okStatus()}
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
	if len(MailKinds) != 22 || len(seen) != 22 {
		t.Fatalf("%d mail kinds", len(MailKinds))
	}
	if fs := mailRun(&MailIn{Main: "example.org", Status: okStatus(), Checks: []mailctl.Check{chk("port25", "ok", ""), chk("cert", "ok", "")}}); len(fs) != 0 {
		t.Fatalf("clean: %+v", fs)
	}
	for _, k := range MailKinds {
		if !slices.Contains(Kinds(), k) {
			t.Errorf("kind %s not registered", k)
		}
	}
}

// TestMailSpamRulesAndLookups: the spam_rules / external_lookups
// checks' problem is mail_spam_rules_missing / mail_external_lookups_on
// with the ruled text and no fix; ok (or a warning, info) clears it.
func TestMailSpamRulesAndLookups(t *testing.T) {
	for id, want := range map[string][2]string{
		"spam_rules":       {KindMailSpamRulesMissing, MailSpamRulesWhy},
		"external_lookups": {KindMailExternalLookupsOn, MailExternalLookupsWhy},
	} {
		fs := mailRun(&MailIn{Main: "example.org", Status: okStatus(), Checks: []mailctl.Check{chk(id, "problem", "x")}})
		if len(fs) != 1 || fs[0].Kind != want[0] || fs[0].Severity != Problem || fs[0].Why != want[1] || fs[0].FixKind != "" || fs[0].Class != FixExplain {
			t.Fatalf("%s problem: %+v", id, fs)
		}
		for _, sev := range []string{"ok", "warning", "info"} {
			if fs := mailRun(&MailIn{Main: "example.org", Status: okStatus(), Checks: []mailctl.Check{chk(id, sev, "")}}); len(fs) != 0 {
				t.Errorf("%s %s: %+v", id, sev, fs)
			}
		}
	}
}

// TestMailOffAndUnavailable: no mail input, no findings; unavailable, no
// findings and the report flag.
func TestMailOffAndUnavailable(t *testing.T) {
	if fs := mailFindings(&Inputs{Now: mailNow}); fs != nil {
		t.Fatalf("off: %+v", fs)
	}
	in := &Inputs{Now: mailNow, Mail: &MailIn{Unavailable: true, Checks: []mailctl.Check{chk("port25", "problem", "x")}}}
	if fs := mailFindings(in); fs != nil {
		t.Fatalf("unavailable: %+v", fs)
	}
	if r := Run(in, nil); !r.MailUnavailable {
		t.Fatal("no mail_unavailable")
	}
	if r := Run(&Inputs{Now: mailNow}, nil); r.MailUnavailable {
		t.Fatal("mail_unavailable with mail off")
	}
}

// TestMailRecordsWrongFixSets: an added domain's finding is dns_apply
// with sets=mail; the main domain's is explain-only with the command;
// dkim_selftest feeds the same kind.
func TestMailRecordsWrongFixSets(t *testing.T) {
	if s := DNSFixSets(KindMailRecordsWrong); len(s) != 1 || s[0] != "mail" {
		t.Fatalf("sets %v", s)
	}
	fs := mailRun(&MailIn{Main: "example.org", Status: okStatus(), Checks: []mailctl.Check{chk("dkim_selftest:example.org", "problem", "p= differs")}})
	if len(fs) != 1 || fs[0].Class != FixExplain || fs[0].Steps[len(fs[0].Steps)-1] != MailMainRecordsStep || fs[0].Domains[0] != "example.org" {
		t.Fatalf("main: %+v", fs)
	}
	fs = mailRun(&MailIn{Main: "example.org", Status: okStatus(), Checks: []mailctl.Check{chk("dkim_selftest:team-b.example.net", "problem", "p= differs")},
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
		st := okStatus()
		st.TimerSeenAt = c.at
		fs := mailRun(&MailIn{Main: "example.org", Status: st})
		if (len(fs) == 1 && fs[0].Kind == KindMailTimerMissing) != c.fire {
			t.Errorf("%v: %+v", c.at, fs)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestMailRateHeldLines: the restart failure and sessions_open show up
// as mail_rate_held, alone or in a held account's explain.
func TestMailRateHeldLines(t *testing.T) {
	fs := mailRun(&MailIn{Main: "example.org", Status: okStatus(), RestartFailed: "the engine refused"})
	if len(fs) != 1 || fs[0].Kind != KindMailRateHeld || fs[0].Severity != Warning || !strings.Contains(fs[0].Why, MailSessionsLine) {
		t.Fatalf("restart failed: %+v", fs)
	}
	fs = mailRun(&MailIn{Main: "example.org", Status: okStatus(), RestartFailed: "x",
		Checks: []mailctl.Check{chk("rate_held:bob", "warning", "3 held"), chk("auth_failures:bob", "info", "25 failed logins")}})
	if len(fs) != 1 || fs[0].Persons[0] != "bob" || !strings.Contains(fs[0].Why, "25 failed logins") || !strings.Contains(fs[0].Why, MailSessionsLine) {
		t.Fatalf("held: %+v", fs)
	}
}

// TestLANOnlyUnenforced: LAN-only on Docker with preserved addresses is
// fine; off is fine under Podman.
func TestLANOnlyUnenforced(t *testing.T) {
	st := okStatus()
	st.ClientIP = "preserved"
	if fs := mailRun(&MailIn{Main: "example.org", Status: st, LANOnly: true}); len(fs) != 0 {
		t.Fatalf("docker LAN-only: %+v", fs)
	}
	if fs := mailRun(&MailIn{Main: "example.org", Status: st, Podman: true}); len(fs) != 0 {
		t.Fatalf("podman without LAN-only: %+v", fs)
	}
	fs := mailRun(&MailIn{Main: "example.org", Status: st, LANOnly: true, Podman: true})
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
		{"", "203.0.113.5 has no PTR record", KindMailPTRMissing},
		{"", "203.0.113.5 → host.example.net", KindMailPTRMismatch},
	} {
		ch := chk("fcrdns_v4", "problem", c.detail)
		ch.Reason = c.reason
		fs := mailRun(&MailIn{Main: "example.org", Status: okStatus(), Checks: []mailctl.Check{ch}})
		if len(fs) != 1 || fs[0].Kind != c.want {
			t.Errorf("%q %q: %+v", c.reason, c.detail, fs)
		}
	}
}
