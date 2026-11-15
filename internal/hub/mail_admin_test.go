package hub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailctl"
	"github.com/portcullis/hub/internal/state"
)

var mailAdmin = directory.Human("root")

// withTeamB: team-b.example.net is an assignable added domain.
func withTeamB(t *testing.T, f *mailFixture) {
	t.Helper()
	later := time.Now().Add(60 * 24 * time.Hour)
	f.dom.mu.Lock()
	f.dom.list["team-b.example.net"] = domains.Domain{Name: "team-b.example.net", State: "ready", RecordsOK: true, CertNotAfter: &later}
	f.dom.mu.Unlock()
	if _, err := f.h.RefreshDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func goodMailSettings() MailSettingsInput {
	return MailSettingsInput{PrimaryDomain: "example.org", Spam: MailSpamView{RejectScore: 15, JunkScore: 5, Allow: []string{}, Block: []string{}},
		Limits: mailctl.Limits{RecipientsPerHour: 300, RecipientsPerDay: 1000}}
}

// TestSetMailSettingsValidation: every contract range, refused with 400
// before anything changes; a good one is saved, audited and synced.
func TestSetMailSettingsValidation(t *testing.T) {
	f := newMailFixture(t)
	withTeamB(t, f)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	ctx := context.Background()
	for name, mod := range map[string]func(*MailSettingsInput){
		"junk 0":         func(in *MailSettingsInput) { in.Spam.JunkScore = 0 },
		"junk = reject":  func(in *MailSettingsInput) { in.Spam.JunkScore = 15 },
		"reject 101":     func(in *MailSettingsInput) { in.Spam.RejectScore = 101 },
		"limit 0":        func(in *MailSettingsInput) { in.Limits.RecipientsPerHour = 0 },
		"limit 100001":   func(in *MailSettingsInput) { in.Limits.RecipientsPerDay = 100001 },
		"allow bad":      func(in *MailSettingsInput) { in.Spam.Allow = []string{"not a domain"} },
		"block bad":      func(in *MailSettingsInput) { in.Spam.Block = []string{"@example.net"} },
		"quota no group": func(in *MailSettingsInput) { in.Quotas = []state.MailQuotaRow{{Group: "nope", Bytes: 1}} },
		"quota zero":     func(in *MailSettingsInput) { in.Quotas = []state.MailQuotaRow{{Group: "team_b", Bytes: 0}} },
		"quota over 1 TiB": func(in *MailSettingsInput) {
			in.Quotas = []state.MailQuotaRow{{Group: "team_b", Bytes: state.MaxMailQuotaBytes + 1}}
		},
		"primary unknown":  func(in *MailSettingsInput) { in.PrimaryDomain = "other.example" },
		"primary mail off": func(in *MailSettingsInput) { in.PrimaryDomain = "team-b.example.net" },
	} {
		in := goodMailSettings()
		mod(&in)
		if err := f.h.SetMailSettings(ctx, in, mailAdmin); statusOf(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.h.mu.RLock()
	if f.h.st.Mail.Spam.RejectScore != 15 || len(f.h.st.Mail.Quotas) != 0 {
		t.Errorf("a refused save changed state: %+v", f.h.st.Mail)
	}
	f.h.mu.RUnlock()
	in := goodMailSettings()
	in.Spam.RejectScore, in.Spam.Allow, in.Spam.Block = 20, []string{"Example.COM", "boss@example.com"}, []string{"spam@example.net"}
	in.Quotas = []state.MailQuotaRow{{Group: "team_b", Bytes: 20 << 30}}
	if err := f.h.SetMailSettings(ctx, in, mailAdmin); err != nil {
		t.Fatal(err)
	}
	v := f.h.MailSettingsView()
	if v.Spam.RejectScore != 20 || strings.Join(v.Spam.Allow, ",") != "example.com,boss@example.com" || len(v.Quotas) != 1 || v.Mail != "on" || v.Hostname != "mail.example.org" {
		t.Fatalf("view %+v", v)
	}
	if e := audit.lastOf("mail.settings"); e.Result != "ok" || e.Actor != "root" {
		t.Fatalf("audit %+v", e)
	}
	// The primary domain may be team-b once mail is on for it.
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", true, nil, mailAdmin); err != nil {
		t.Fatal(err)
	}
	in.PrimaryDomain = "team-b.example.net"
	if err := f.h.SetMailSettings(ctx, in, mailAdmin); err != nil {
		t.Fatalf("primary team-b: %v", err)
	}
	if v := f.h.MailSettingsView(); v.PrimaryDomain != "team-b.example.net" {
		t.Fatalf("primary %s", v.PrimaryDomain)
	}
	// The primary can't be turned off.
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", false, nil, mailAdmin); statusOf(err) != 409 {
		t.Fatalf("primary off: %v", err)
	}
}

// TestSetMailDomainOffDrains: on records HadMailRecords from the plan;
// off drains (never straight off); the main domain drains too; an
// unknown domain is 404; a reserved host in use refuses turning on.
func TestSetMailDomainOffDrains(t *testing.T) {
	f := newMailFixture(t)
	withTeamB(t, f)
	ctx := context.Background()
	f.dom.mu.Lock()
	f.dom.plans["team-b.example.net"] = domains.Plan{Name: "team-b.example.net", Items: []domains.PlanItem{{Set: "address", Name: "team-b.example.net", Type: "MX", Live: []string{"10 mx.old.example."}}}}
	f.dom.mu.Unlock()
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", true, []string{"team_b"}, mailAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	e := f.h.st.Mail.Domains["team-b.example.net"]
	f.h.mu.RUnlock()
	if !e.Enabled || !e.HadMailRecords || strings.Join(e.Groups, ",") != "team_b" {
		t.Fatalf("on: %+v", e)
	}
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", false, []string{"team_b"}, mailAdmin); err != nil {
		t.Fatal(err)
	}
	if s := f.h.MailDomainStates()["team-b.example.net"]; s != "draining" {
		t.Fatalf("off: %s", s)
	}
	if err := f.h.SetMailDomain(ctx, "unknown.example", true, nil, mailAdmin); statusOf(err) != 404 {
		t.Fatalf("unknown: %v", err)
	}
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", true, []string{"no-such-group"}, mailAdmin); statusOf(err) != 400 {
		t.Fatalf("bad group: %v", err)
	}
	// An instance on autoconfig.team-b refuses turning it on again.
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", false, nil, mailAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	f.h.st.Mail.Domains["team-b.example.net"] = state.MailDomain{Retired: true}
	f.h.mu.Unlock()
	f.h.mu.Lock()
	f.h.st.Instances["grafana-b"] = state.Instance{Template: "grafana", Hosts: map[string]string{"grafana": "autoconfig.team-b.example.net"}}
	f.h.mu.Unlock()
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", true, nil, mailAdmin); statusOf(err) != 409 || !strings.Contains(err.Error(), "instance grafana-b uses autoconfig.team-b.example.net") {
		t.Fatalf("reserved host in use: %v", err)
	}
	// The main domain (on by default with core mail) drains too, once
	// another domain is primary... it's the primary here: refused.
	if err := f.h.SetMailDomain(ctx, "example.org", false, nil, mailAdmin); statusOf(err) != 409 {
		t.Fatalf("main primary off: %v", err)
	}
}

// TestAliasConflict409: aliases are addresses on a mail domain, unique
// Hub-wide: another's address, another's alias, a list, a reserved local
// part are 409 naming the owner; a non-mailbox is 404.
func TestAliasConflict409(t *testing.T) {
	f := newMailFixture(t)
	ctx := context.Background()
	if err := f.h.SetUserAliases(ctx, "alice", []string{"Sales@example.org", "sales@example.org"}, mailAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	got := strings.Join(f.h.st.Mail.Aliases["alice"], ",")
	f.h.mu.RUnlock()
	if got != "sales@example.org" {
		t.Fatalf("aliases %s", got)
	}
	f.h.mu.Lock()
	f.h.st.Mail.Lists = map[string]state.MailList{"team_b": {Domain: "example.org", Posting: "members"}}
	f.h.mu.Unlock()
	for addr, owner := range map[string]string{
		"bob@example.org":    "bob's address",
		"sales@example.org":  "alice's alias",
		"team_b@example.org": "the list of group team_b",
		"abuse@example.org":  "reserved for mail",
	} {
		err := f.h.SetUserAliases(ctx, "root", []string{addr}, mailAdmin)
		if statusOf(err) != 409 || !strings.Contains(err.Error(), owner) {
			t.Errorf("%s: %v, want 409 naming %q", addr, err, owner)
		}
	}
	if err := f.h.SetUserAliases(ctx, "root", []string{"x@other.example"}, mailAdmin); statusOf(err) != 400 {
		t.Errorf("off a mail domain: %v", err)
	}
	if err := f.h.SetUserAliases(ctx, "dave", []string{"d@example.org"}, mailAdmin); statusOf(err) != 404 {
		t.Errorf("no mailbox: %v", err)
	}
	// alice may keep her own alias.
	if err := f.h.SetUserAliases(ctx, "alice", []string{"sales@example.org", "info@example.org"}, mailAdmin); err != nil {
		t.Errorf("own alias kept: %v", err)
	}
}

// TestGroupListPosting: a group becomes a list (posting members by
// default, or anyone), an address conflict is 409, off removes it.
func TestGroupListPosting(t *testing.T) {
	f := newMailFixture(t)
	ctx := context.Background()
	if err := f.h.SetGroupList(ctx, "team_b", true, "example.org", "", mailAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	l := f.h.st.Mail.Lists["team_b"]
	f.h.mu.RUnlock()
	if l.Posting != "members" || l.Domain != "example.org" {
		t.Fatalf("list %+v", l)
	}
	if err := f.h.SetGroupList(ctx, "team_b", true, "example.org", "anyone", mailAdmin); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetGroupList(ctx, "team_b", true, "example.org", "everyone", mailAdmin); statusOf(err) != 400 {
		t.Fatalf("bad posting: %v", err)
	}
	f.sync(t)
	if d := f.mc.Last(); len(d.Lists) != 1 || d.Lists[0].Posting != "anyone" || d.Lists[0].Address != "team_b@example.org" {
		t.Fatalf("document lists %+v", d.Lists)
	}
	// A group named like a person: its address is taken.
	f.people.mu.Lock()
	f.people.m.Groups["bob"] = directory.MemberGroup{ID: 9, Members: []string{"alice"}}
	f.people.mu.Unlock()
	if err := f.h.SetGroupList(ctx, "bob", true, "example.org", "", mailAdmin); statusOf(err) != 409 || !strings.Contains(err.Error(), "bob's address") {
		t.Fatalf("conflict: %v", err)
	}
	if err := f.h.SetGroupList(ctx, "team_b", true, "off.example", "", mailAdmin); statusOf(err) != 400 {
		t.Fatalf("not a mail domain: %v", err)
	}
	if err := f.h.SetGroupList(ctx, "team_b", false, "", "", mailAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	_, still := f.h.st.Mail.Lists["team_b"]
	f.h.mu.RUnlock()
	if still {
		t.Fatal("list kept after off")
	}
}

// TestHostMailDrainHub: drain makes every on domain draining (audited,
// actor host); domains lists on/draining/off, an off domain not retired
// still draining for the CLI.
func TestHostMailDrainHub(t *testing.T) {
	f := newMailFixture(t)
	withTeamB(t, f)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	ctx := context.Background()
	if err := f.h.SetMailDomain(ctx, "team-b.example.net", true, nil, mailAdmin); err != nil {
		t.Fatal(err)
	}
	if got := f.h.HostMailDomains(); len(got) != 2 || got[0].State != "on" || got[1].State != "on" {
		t.Fatalf("before %+v", got)
	}
	rows := f.h.HostMailDrain(ctx)
	for _, r := range rows {
		if r.State != "draining" {
			t.Fatalf("after drain %+v", rows)
		}
	}
	if e := audit.lastOf("mail.domain"); e.Actor != HostActor {
		t.Fatalf("audit %+v", e)
	}
	f.h.mu.Lock()
	e := f.h.st.Mail.Domains["team-b.example.net"]
	e.Draining = false
	f.h.st.Mail.Domains["team-b.example.net"] = e
	f.h.mu.Unlock()
	if got := f.h.HostMailDomains(); got[1].State != "draining" {
		t.Fatalf("off, set not removed yet: %+v", got)
	}
	f.h.mu.Lock()
	e.Retired = true
	f.h.st.Mail.Domains["team-b.example.net"] = e
	f.h.mu.Unlock()
	if got := f.h.HostMailDomains(); got[1].State != "off" {
		t.Fatalf("retired: %+v", got)
	}
}

// TestPersonMailHelp: an administrator sees the aliases; a caller who
// may not help is refused.
func TestPersonMailHelp(t *testing.T) {
	f := newMailFixture(t)
	ctx := context.Background()
	f.h.SetUserAliases(ctx, "alice", []string{"sales@example.org"}, mailAdmin)
	v, err := f.h.PersonMail(ctx, &directory.Caller{User: "root", Admin: true}, "alice")
	if err != nil || strings.Join(v.Aliases, ",") != "sales@example.org" || v.Addresses[0] != "alice@example.org" {
		t.Fatalf("admin view %+v %v", v, err)
	}
	if _, err := f.h.PersonMail(ctx, &directory.Caller{User: "bob"}, "alice"); err == nil {
		t.Fatal("a non-helper read someone's mail")
	}
}
