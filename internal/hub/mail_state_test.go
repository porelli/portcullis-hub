package hub

import (
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
)

const (
	uuidAlice = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
	uuidBob   = "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"
	uuidRoot  = "3e5a7c9b-1d2f-4a6b-8c0e-2f4a6b8c0d1e"
	uuidCarol = "11111111-2222-4333-8444-555555555555"
)

// mailMembership: alice, bob, root and carol in mail_users (carol
// without a uuid), root an LLDAP admin, alice in team_b, admin and dave
// outside.
func mailMembership() *directory.Membership {
	m := &directory.Membership{
		Users: map[string]map[string]int{
			"alice": {"mail_users": 1, "team_b": 2}, "bob": {"mail_users": 1}, "root": {"mail_users": 1, "lldap_admin": 3},
			"carol": {"mail_users": 1}, "admin": {"mail_users": 1, "lldap_admin": 3}, "dave": {}, "pm": {"lldap_password_manager": 7},
		},
		Groups: map[string]directory.MemberGroup{
			"mail_users":             {ID: 1, Members: []string{"admin", "alice", "bob", "carol", "root"}},
			"team_b":                 {ID: 2, Members: []string{"alice", "dave"}},
			"lldap_admin":            {ID: 3, Members: []string{"admin", "root"}},
			"lldap_password_manager": {ID: 7, Members: []string{"pm"}},
		},
		UUIDs:        map[string]string{"alice": uuidAlice, "bob": uuidBob, "root": uuidRoot, "admin": "99999999-2222-4333-8444-555555555555", "dave": "aaaaaaaa-2222-4333-8444-555555555555"},
		DisplayNames: map[string]string{"alice": "Alice A.", "bob": "Bob B.", "root": "Root"},
		Expired:      map[string]map[string]bool{},
	}
	return m
}

func mailInput(m *directory.Membership) MailBuildInput {
	st := state.DefaultMailSettings()
	st.Domains = map[string]state.MailDomain{"team-b.example.org": {Enabled: true, Groups: []string{"team_b"}, HadMailRecords: true}}
	return MailBuildInput{Membership: m, Settings: st, MainDomain: "example.com", CoreOn: true,
		DNSSEC: map[string]string{"example.com": "secure", "team-b.example.org": "unsigned"}, LocalNetworks: []string{"10.0.0.0/8"}, Generation: 12,
		MailHostname: "mail.example.com"}
}

// TestBuildMailStateAddresses: primary first, then one address per added
// mail domain whose groups the person is in; the contract's vector is
// what this membership builds.
func TestBuildMailStateAddresses(t *testing.T) {
	in := mailInput(mailMembership())
	in.Settings.Aliases = map[string]state.MailAliases{uuidAlice: {Username: "alice", Addresses: []string{"sales@example.com"}}}
	in.Settings.Lists = map[string]state.MailList{"team": {Domain: "example.com", Posting: "members"}}
	in.Membership.Groups["team"] = directory.MemberGroup{ID: 4, Members: []string{"alice", "bob", "dave"}}
	for _, u := range []string{"alice", "bob", "dave"} {
		in.Membership.Users[u]["team"] = 4
	}
	in.Settings.Spam.Allow = []string{"example.org"}
	in.Settings.Spam.Block = []string{"spam@example.net"}
	// The contract's postmaster is root, an account and LLDAP admin.
	got, notes := BuildMailState(in)
	if got == nil {
		t.Fatalf("no document: %v", notes)
	}
	want := mailprovider.MailState{Version: 2, Generation: 12, PrimaryDomain: "example.com", MailHostname: "mail.example.com",
		ClientIP: "preserved", DKIMRotate: "4320h", FormerRetention: "720h", TLS: mailprovider.StateTLS{SPKISHA256: []string{}},
		Domains: []mailprovider.Domain{{Name: "example.com", DMARCStart: "reject", DMARCFloor: "reject", Mail: "on", DNSSEC: "secure"},
			{Name: "team-b.example.org", DMARCStart: "none", DMARCFloor: "none", Mail: "on", DNSSEC: "unsigned"}},
		Accounts: []mailprovider.Account{
			{Username: "alice", UUID: uuidAlice, DisplayName: "Alice A.", Addresses: []string{"alice@example.com", "alice@team-b.example.org"}, QuotaBytes: 10 << 30},
			{Username: "bob", UUID: uuidBob, DisplayName: "Bob B.", Addresses: []string{"bob@example.com"}, QuotaBytes: 10 << 30},
			{Username: "root", UUID: uuidRoot, DisplayName: "Root", Addresses: []string{"root@example.com"}, QuotaBytes: 10 << 30},
		},
		Aliases:       []mailprovider.Alias{{Address: "sales@example.com", Username: "alice"}},
		Lists:         []mailprovider.List{{Address: "team@example.com", Members: []string{"alice", "bob"}, Posting: "members"}},
		Postmaster:    []string{"root"},
		Limits:        mailprovider.Limits{RecipientsPerHour: 300, RecipientsPerDay: 1000},
		Spam:          mailprovider.Spam{RejectScore: 15, JunkScore: 5, DNSBL: mailprovider.DNSBL{Spamhaus: true, Spamcop: true, Barracuda: true}, Allow: []string{"example.org"}, Block: []string{"spam@example.net"}},
		LocalNetworks: []string{"10.0.0.0/8"},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("document\n%+v\nwant\n%+v", *got, want)
	}
	// A person outside team_b's groups gets no team-b address; a domain
	// without groups gives nobody one; the primary on an added domain.
	in.Settings.Domains["team-b.example.org"] = state.MailDomain{Enabled: true}
	got, _ = BuildMailState(in)
	if a := got.Accounts[0].Addresses; len(a) != 1 {
		t.Errorf("no groups: %v", a)
	}
	in.Settings.PrimaryDomain = "team-b.example.org"
	got, _ = BuildMailState(in)
	if a := got.Accounts[0].Addresses; !reflect.DeepEqual(a, []string{"alice@team-b.example.org", "alice@example.com"}) || got.PrimaryDomain != "team-b.example.org" {
		t.Errorf("primary team-b: %v", a)
	}
}

// TestBuildMailStateSkipsNoUUID: carol (no uuid) is left out, noted,
// never sent with an empty uuid; admin and an expired membership too.
func TestBuildMailStateSkipsNoUUID(t *testing.T) {
	m := mailMembership()
	m.Expired["bob"] = map[string]bool{"mail_users": true}
	got, notes := BuildMailState(mailInput(m))
	var names []string
	for _, a := range got.Accounts {
		if a.UUID == "" {
			t.Errorf("%s sent without a uuid", a.Username)
		}
		names = append(names, a.Username)
	}
	if strings.Join(names, ",") != "alice,root" {
		t.Errorf("accounts %v", names)
	}
	if strings.Join(notes, "\n") == "" || !strings.Contains(strings.Join(notes, "\n"), "carol") {
		t.Errorf("notes %q", notes)
	}
}

// TestBuildMailStatePostmasterAdmins: postmaster = the lldap_admin
// members who are accounts (never the LLDAP admin user).
func TestBuildMailStatePostmasterAdmins(t *testing.T) {
	m := mailMembership()
	got, _ := BuildMailState(mailInput(m))
	if !reflect.DeepEqual(got.Postmaster, []string{"root"}) {
		t.Errorf("postmaster %v", got.Postmaster)
	}
	m.Groups["mail_users"] = directory.MemberGroup{ID: 1, Members: []string{"alice"}}
	got, _ = BuildMailState(mailInput(m))
	if got.Postmaster == nil || len(got.Postmaster) != 0 {
		t.Errorf("no admin account: %v", got.Postmaster)
	}
}

// TestBuildMailStateConflictsLeftOut: a document mailctl would refuse is
// never built: reserved local parts, duplicate addresses, aliases off
// mail domains, list names that aren't local parts are left out (noted).
func TestBuildMailStateConflictsLeftOut(t *testing.T) {
	m := mailMembership()
	m.Users["postmaster"] = map[string]int{"mail_users": 1}
	m.UUIDs["postmaster"] = "bbbbbbbb-2222-4333-8444-555555555555"
	m.Groups["mail_users"] = directory.MemberGroup{ID: 1, Members: []string{"alice", "bob", "postmaster", "root"}}
	m.Groups["Team A"] = directory.MemberGroup{ID: 5, Members: []string{"alice"}}
	m.Groups["bob"] = directory.MemberGroup{ID: 6, Members: []string{"alice"}}
	in := mailInput(m)
	in.Settings.Aliases = map[string]state.MailAliases{uuidAlice: {Username: "alice", Addresses: []string{"bob@example.com", "abuse@example.com", "x@other.test", "ok@team-b.example.org"}},
		"aaaaaaaa-2222-4333-8444-555555555555": {Username: "dave", Addresses: []string{"d@example.com"}}}
	in.Settings.Lists = map[string]state.MailList{"Team A": {Domain: "example.com", Posting: "members"}, "bob": {Domain: "example.com", Posting: "anyone"}}
	got, notes := BuildMailState(in)
	for _, a := range got.Accounts {
		if a.Username == "postmaster" {
			t.Error("a reserved username became an account")
		}
	}
	if !reflect.DeepEqual(got.Aliases, []mailprovider.Alias{{Address: "ok@team-b.example.org", Username: "alice"}}) {
		t.Errorf("aliases %+v", got.Aliases)
	}
	if len(got.Lists) != 0 {
		t.Errorf("lists %+v", got.Lists)
	}
	if len(notes) < 6 {
		t.Errorf("notes %q", notes)
	}
}

// TestBuildMailStateDomainStates: draining is sent as draining (its
// addresses kept), off not yet retired as off (no addresses), retired
// not at all; the main domain off unless core mail is on.
func TestBuildMailStateDomainStates(t *testing.T) {
	in := mailInput(mailMembership())
	in.Settings.Domains["team-b.example.org"] = state.MailDomain{Draining: true, Groups: []string{"team_b"}}
	got, _ := BuildMailState(in)
	if got.Domains[1].Mail != "draining" || len(got.Accounts[0].Addresses) != 2 {
		t.Errorf("draining: %+v %v", got.Domains, got.Accounts[0].Addresses)
	}
	in.Settings.Domains["team-b.example.org"] = state.MailDomain{Groups: []string{"team_b"}}
	got, _ = BuildMailState(in)
	if got.Domains[1].Mail != "off" || len(got.Accounts[0].Addresses) != 1 {
		t.Errorf("off: %+v %v", got.Domains, got.Accounts[0].Addresses)
	}
	in.Settings.Domains["team-b.example.org"] = state.MailDomain{Retired: true}
	got, _ = BuildMailState(in)
	if len(got.Domains) != 1 {
		t.Errorf("retired: %+v", got.Domains)
	}
	in.CoreOn = false
	if got, notes := BuildMailState(in); got != nil {
		t.Errorf("core mail off: %+v %v", got, notes)
	}
}

// TestMailDiff: removals vs additions vs other changes.
func TestMailDiff(t *testing.T) {
	base, _ := BuildMailState(mailInput(mailMembership()))
	same, _ := BuildMailState(mailInput(mailMembership()))
	same.Generation = 99
	if d := diffMail(base, same); d.any() {
		t.Errorf("same: %+v", d)
	}
	m := mailMembership()
	m.Groups["mail_users"] = directory.MemberGroup{ID: 1, Members: []string{"alice", "root"}}
	less, _ := BuildMailState(mailInput(m))
	if d := diffMail(base, less); !d.removal || d.addition || strings.Join(d.removedUsers, ",") != "bob" || d.removedAccounts != 1 {
		t.Errorf("bob left: %+v", d)
	}
	if d := diffMail(less, base); d.removal || !d.addition {
		t.Errorf("bob joined: %+v", d)
	}
	in := mailInput(mailMembership())
	in.Settings.Spam.RejectScore = 20
	sp, _ := BuildMailState(in)
	if d := diffMail(base, sp); d.removal || d.addition || !d.other {
		t.Errorf("spam: %+v", d)
	}
	in = mailInput(mailMembership())
	in.Settings.Domains["team-b.example.org"] = state.MailDomain{Enabled: true}
	nob, _ := BuildMailState(in)
	if d := diffMail(base, nob); !d.removal || d.removedAccounts != 0 {
		t.Errorf("address gone: %+v", d)
	}
	if d := diffMail(nil, base); !d.other {
		t.Errorf("first: %+v", d)
	}
}
