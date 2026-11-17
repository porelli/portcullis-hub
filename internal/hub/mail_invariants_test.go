package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

// TestHubRefusesMassRemovalBeforeSend: a provider without a guard gets
// no document removing more than half the mailboxes: the Hub's own
// guard holds it pending (and revokes their passwords).
func TestHubRefusesMassRemovalBeforeSend(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	f.create(t, "bob", "phone")
	f.mc.Lock(func(s *mailprovidertest.Server) { s.NoMassGuard = true })
	puts := f.mc.Puts()
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	// Nothing is sent: the fallback (the departed kept) changes nothing.
	if f.mc.Puts() != puts || len(f.mc.Last().Accounts) != 3 {
		t.Fatalf("puts %d → %d, %d accounts", puts, f.mc.Puts(), len(f.mc.Last().Accounts))
	}
	f.h.mu.RLock()
	p := f.h.st.Mail.PendingRemoval
	f.h.mu.RUnlock()
	if p == nil || len(p.Accounts) != 2 {
		t.Fatalf("pending %+v", p)
	}
	if len(f.mc.Creds("bob")) != 0 {
		t.Fatal("bob's password survived the pending removal")
	}
}

// TestMassRemovalConfirmBoundToSet: an administrator's confirmation of
// exactly the pending set lets the removal through; a changed set needs
// a new one.
func TestMassRemovalConfirmBoundToSet(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.NoMassGuard = true })
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	f.h.mu.RLock()
	var uuids []string
	for _, a := range f.h.st.Mail.PendingRemoval.Accounts {
		uuids = append(uuids, a.UUID)
	}
	f.h.mu.RUnlock()
	if err := f.h.ConfirmMailRemoval(context.Background(), uuids[:1], directory.Human("root")); statusOf(err) != 409 {
		t.Fatalf("a partial confirmation: %v", err)
	}
	if err := f.h.ConfirmMailRemoval(context.Background(), uuids, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	if n := len(f.mc.Last().Accounts); n != 1 || !f.mc.Last().ConfirmMassRemoval {
		t.Fatalf("after the confirmation: %d accounts, confirm %v", n, f.mc.Last().ConfirmMassRemoval)
	}
}

// TestDelegateNeverConfirms: only lldap_admin confirms a mass removal.
func TestDelegateNeverConfirms(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.NoMassGuard = true })
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	f.h.mu.RLock()
	var uuids []string
	for _, a := range f.h.st.Mail.PendingRemoval.Accounts {
		uuids = append(uuids, a.UUID)
	}
	f.h.mu.RUnlock()
	if err := f.h.ConfirmMailRemoval(context.Background(), uuids, directory.Human("alice")); statusOf(err) != 403 {
		t.Fatalf("a delegate confirmed: %v", err)
	}
}

// TestPendingRevokesAndRestarts: the pending removal revokes the
// people's passwords and resets the sessions (a restart).
func TestPendingRevokesAndRestarts(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	f.create(t, "alice", "phone")
	f.mc.Lock(func(s *mailprovidertest.Server) { s.NoMassGuard = true })
	restarts := len(f.engine.Restarts())
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	f.h.Wait()
	if len(f.mc.Creds("alice")) != 0 || len(f.engine.Restarts()) == restarts {
		t.Fatalf("creds %d restarts %d → %d", len(f.mc.Creds("alice")), restarts, len(f.engine.Restarts()))
	}
}

// lanOnly turns LAN-only on (core.env) with Local networks 10.0.0.0/8.
func lanOnly(t *testing.T, f *mailFixture) {
	t.Helper()
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\nPORTCULLIS_MAIL=on\nPORTCULLIS_MAIL_HOSTNAME=mail.example.org\nPORTCULLIS_MAIL_SUBMISSION_LAN_ONLY=true\nPORTCULLIS_MAIL_CLIENT_IP=preserved\n")
	f.h.mu.Lock()
	nets := []string{"10.0.0.0/8"}
	f.h.st.LocalNetworks = &nets
	f.h.mu.Unlock()
}

// TestAllowedIPsWiderRevoked: under LAN-only a credential wider than the
// Local networks is revoked at the reconcile (row ended, breach kept); a
// split of the same addresses passes; a create the provider doesn't
// limit is taken back.
func TestAllowedIPsWiderRevoked(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	lanOnly(t, f)
	f.sync(t)
	f.create(t, "alice", "phone") // the fake limits it to the Local networks
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/9"), netip.MustParsePrefix("10.128.0.0/9")}
	})
	if _, err := f.h.MyMail(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if len(f.mc.Creds("alice")) != 1 {
		t.Fatal("a split of the same addresses was revoked")
	}
	f.mc.Lock(func(s *mailprovidertest.Server) { s.AllowedIPs = []netip.Prefix{} }) // anywhere
	if _, err := f.h.MyMail(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if len(f.mc.Creds("alice")) != 0 {
		t.Fatal("a credential from anywhere survived LAN-only")
	}
	f.h.mu.RLock()
	rows := f.h.st.MailCredentials["alice"]
	f.h.mu.RUnlock()
	if len(rows) != 1 || rows[0].Active() || rows[0].RevokedBy != "lan-only" {
		t.Fatalf("rows %+v", rows)
	}
	if at, who := f.h.MailLANOnlyBreach(); at.IsZero() || who != "alice" {
		t.Fatalf("breach %v %s", at, who)
	}
	// A create the provider leaves unlimited is taken back and refused.
	if _, err := f.h.CreateMailPassword(context.Background(), "alice", "laptop", "none", testProof); statusOf(err) != 503 {
		t.Fatalf("create: %v", err)
	}
	if len(f.mc.Creds("alice")) != 0 {
		t.Fatal("the unlimited password was kept")
	}
}

// TestAllowedIPsIgnoredWhenLANOff: without LAN-only, anywhere is fine.
func TestAllowedIPsIgnoredWhenLANOff(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	f.create(t, "alice", "phone")
	f.mc.Lock(func(s *mailprovidertest.Server) { s.AllowedIPs = []netip.Prefix{} })
	if _, err := f.h.MyMail(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if len(f.mc.Creds("alice")) != 1 {
		t.Fatal("revoked without LAN-only")
	}
}

// TestSameAddressSet: split and merged prefixes compare by address.
func TestSameAddressSet(t *testing.T) {
	p := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	for _, c := range []struct {
		a, b []netip.Prefix
		want bool
	}{
		{p("10.0.0.0/8"), p("10.0.0.0/9", "10.128.0.0/9"), true},
		{p("10.0.0.0/8", "192.168.1.0/24"), p("192.168.1.0/25", "192.168.1.128/25", "10.0.0.0/8"), true},
		{p("10.0.0.0/8"), p("10.0.0.0/9"), false},
		{p("10.0.0.0/8"), p("10.0.0.0/7"), false},
		{p("127.0.0.1/32", "::1/128"), p("::1/128", "127.0.0.1/32"), true},
		{p("::ffff:10.0.0.0/104"), p("10.0.0.0/8"), true},
		{p("fd00::/8"), p("fd00::/9", "fd80::/9"), true},
		{p("10.0.0.0/8"), nil, false},
	} {
		if got := sameAddressSet(c.a, c.b); got != c.want {
			t.Errorf("%v vs %v: %v", c.a, c.b, got)
		}
	}
}

// TestBuildMailStateV2Vector: the fixture state builds exactly the
// contract's MailState v2 vector (bytes, compacted).
func TestBuildMailStateV2Vector(t *testing.T) {
	in := mailInput(mailMembership())
	in.Settings.Aliases = map[string]state.MailAliases{uuidAlice: {Username: "alice", Addresses: []string{"sales@example.com"}}}
	in.Settings.Lists = map[string]state.MailList{"team": {Domain: "example.com", Posting: "members"}}
	in.Membership.Groups["team"] = directory.MemberGroup{ID: 4, Members: []string{"alice", "bob", "dave"}}
	for _, u := range []string{"alice", "bob", "dave"} {
		in.Membership.Users[u]["team"] = 4
	}
	in.Settings.Spam.Allow = []string{"example.org"}
	in.Settings.Spam.Block = []string{"spam@example.net"}
	in.Settings.Relay = &state.MailRelay{Host: "smtp.relay.example.net", Port: 465, Username: "portcullis", SPFInclude: "_spf.relay.example.net"}
	in.Settings.TLS = state.MailTLS{SPKISHA256: []string{"99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"}}
	doc, notes := BuildMailState(in)
	if doc == nil {
		t.Fatalf("no document: %v", notes)
	}
	got, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "mailprovider", "testdata", "mailstate_v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("document\n%s\nwant\n%s", got, want.Bytes())
	}
}

// TestRelayPasswordWriteOnly: the relay password is saved to hub_data
// (0600) and the gate, never returned, never in state.yaml or the
// audit; absent keeps it, "" clears it, a null relay clears both.
func TestRelayPasswordWriteOnly(t *testing.T) {
	w := wiredFix(t)
	ctx := context.Background()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	in := MailSettingsInput{PrimaryDomain: "example.org", Spam: MailSpamView{RejectScore: 15, JunkScore: 5}, Limits: mailprovider.Limits{RecipientsPerHour: 300, RecipientsPerDay: 1000},
		Relay: json.RawMessage(`{"host": "smtp.relay.example.net", "port": 587, "username": "u", "spf_include": "_spf.relay.example.net", "password": "s3cret-relay"}`)}
	if err := w.h.SetMailSettings(ctx, in, rootActor()); err != nil {
		t.Fatal(err)
	}
	pf := filepath.Join(w.data, mailRelayPasswordFile)
	if b, err := os.ReadFile(pf); err != nil || string(b) != "s3cret-relay" {
		t.Fatalf("hub_data copy %q %v", b, err)
	}
	if fi, _ := os.Stat(pf); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if gateFile(t, w.fixture, mailGateRelayPassword) != "s3cret-relay" {
		t.Fatal("the gate copy isn't written")
	}
	v := w.h.MailSettingsView()
	if v.Relay == nil || !v.Relay.PasswordSet || v.Relay.Port != 587 {
		t.Fatalf("view %+v", v.Relay)
	}
	vb, _ := json.Marshal(v)
	stb, _ := os.ReadFile(w.h.statePath())
	if strings.Contains(string(vb), "s3cret") || strings.Contains(string(stb), "s3cret") || strings.Contains(w.audit.last().Detail, "s3cret") || strings.Contains(logs.String(), "s3cret") {
		t.Fatal("the password leaked")
	}
	// Absent keeps it.
	in.Relay = json.RawMessage(`{"host": "smtp.relay.example.net", "port": 465, "username": "u", "spf_include": ""}`)
	if err := w.h.SetMailSettings(ctx, in, rootActor()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pf); string(b) != "s3cret-relay" {
		t.Fatal("an absent password changed it")
	}
	// The relay in the next document; null clears both.
	in.Relay = json.RawMessage(`null`)
	if err := w.h.SetMailSettings(ctx, in, rootActor()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pf); !os.IsNotExist(err) || gateFile(t, w.fixture, mailGateRelayPassword) != "" {
		t.Fatal("a null relay kept the password")
	}
	for _, bad := range []string{`{"host": "x", "port": 0, "username": "", "spf_include": ""}`, `{"host": "-bad", "port": 25, "username": "", "spf_include": ""}`,
		`{"host": "smtp.example.net", "port": 25, "username": "", "spf_include": "", "extra": 1}`} {
		in.Relay = json.RawMessage(bad)
		if err := w.h.SetMailSettings(ctx, in, rootActor()); statusOf(err) != 400 {
			t.Errorf("%s: %v", bad, err)
		}
	}
	in.Relay = nil
	d := "12h"
	in.DKIMRotate = &d
	if err := w.h.SetMailSettings(ctx, in, rootActor()); statusOf(err) != 400 {
		t.Fatalf("12h accepted: %v", err)
	}
}

// TestRevokeRestartsWithin8s: a revoked mail password resets the
// sessions (a restart is requested well within the 8 s budget).
func TestRevokeRestartsWithin8s(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	c := f.create(t, "alice", "phone")
	n := len(f.engine.Restarts())
	start := time.Now()
	if err := f.h.RevokeOwnMailPassword(context.Background(), "alice", c.ID); err != nil {
		t.Fatal(err)
	}
	for len(f.engine.Restarts()) == n {
		if time.Since(start) > 8*time.Second {
			t.Fatal("no restart within 8 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLANOnlyCreateFailedRevokeNeverReturns (H2, R-HH2, fault
// injection): a wider credential whose revoke fails never reaches the
// person; the row stays active (M6: only the provider's word ends it)
// and the provider is voided.
func TestLANOnlyCreateFailedRevokeNeverReturns(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	lanOnly(t, f)
	f.sync(t)
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.AllowedIPs = []netip.Prefix{}
		s.RevokeStatus = 500
	})
	c, err := f.h.CreateMailPassword(context.Background(), "alice", "laptop", "none", testProof)
	if statusOf(err) != 503 || c != nil {
		t.Fatalf("a wider password was handed out: %v", err)
	}
	f.h.mu.RLock()
	owed := f.h.st.Mail.VoidOwed
	active := 0
	for _, r := range f.h.st.MailCredentials["alice"] {
		if r.Active() && r.Label == "laptop" {
			active++
		}
	}
	f.h.mu.RUnlock()
	if owed == nil || active != 1 {
		t.Fatalf("void %+v, active laptop rows %d", owed, active)
	}
}

// TestLANOnlyTakeBackNeedsProviderWord (M6, fault injection): the list
// fails and so does the take-back: the row stays active, the provider
// is voided.
func TestLANOnlyTakeBackNeedsProviderWord(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	lanOnly(t, f)
	f.sync(t)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.RevokeStatus = 500 })
	f.h.SetMailAPI(&listFailAPI{MailAPI: f.h.mailClient()})
	if _, err := f.h.CreateMailPassword(context.Background(), "alice", "laptop", "none", testProof); statusOf(err) != 503 {
		t.Fatalf("create: %v", err)
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	for _, r := range f.h.st.MailCredentials["alice"] {
		if r.Label == "laptop" && !r.Active() {
			t.Fatal("the row ended without the provider's word")
		}
	}
	if f.h.st.Mail.VoidOwed == nil {
		t.Fatal("not voided")
	}
}

// listFailAPI fails every credential list.
type listFailAPI struct{ MailAPI }

func (a *listFailAPI) Credentials(context.Context, string) ([]mailprovider.Credential, error) {
	return nil, errors.New("list timed out")
}

// TestRelayPasswordRolledBackOnFailedSave (L5): a failed save keeps the
// previous relay password, in hub_data and in the gate.
func TestRelayPasswordRolledBackOnFailedSave(t *testing.T) {
	w := wiredFix(t)
	ctx := context.Background()
	in := MailSettingsInput{PrimaryDomain: "example.org", Spam: MailSpamView{RejectScore: 15, JunkScore: 5}, Limits: mailprovider.Limits{RecipientsPerHour: 300, RecipientsPerDay: 1000},
		Relay: json.RawMessage(`{"host": "smtp.relay.example.net", "port": 587, "username": "u", "spf_include": "", "password": "first-pass"}`)}
	if err := w.h.SetMailSettings(ctx, in, rootActor()); err != nil {
		t.Fatal(err)
	}
	sp := w.h.statePath()
	os.Remove(sp)
	if err := os.Mkdir(sp, 0o700); err != nil {
		t.Fatal(err)
	}
	in.Relay = json.RawMessage(`{"host": "smtp.relay.example.net", "port": 587, "username": "u", "spf_include": "", "password": "second-pass"}`)
	if err := w.h.SetMailSettings(ctx, in, rootActor()); err == nil {
		t.Fatal("the save didn't fail")
	}
	if b, _ := os.ReadFile(filepath.Join(w.data, mailRelayPasswordFile)); string(b) != "first-pass" || gateFile(t, w.fixture, mailGateRelayPassword) != "first-pass" {
		t.Fatalf("hub_data %q gate %q", b, gateFile(t, w.fixture, mailGateRelayPassword))
	}
}

// TestNoBaselineRemovalWaits (Ruling R-L8): with mail-last.json lost,
// the people with an active mail password are the baseline: a document
// removing any of them is not sent until an administrator confirms.
func TestNoBaselineRemovalWaits(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	f.create(t, "bob", "phone")
	os.Remove(f.h.mailLastPath())
	f.h.mailState.mu.Lock()
	f.h.mailState.last = nil
	f.h.mailState.mu.Unlock()
	puts := f.mc.Puts()
	f.people.setMembers("mail_users", "root", "alice")
	f.sync(t)
	if f.mc.Puts() != puts {
		t.Fatal("a document removing bob was sent without a baseline")
	}
	f.h.mu.RLock()
	p := f.h.st.Mail.PendingRemoval
	f.h.mu.RUnlock()
	if p == nil || len(p.Accounts) != 1 || p.Accounts[0].Username != "bob" {
		t.Fatalf("pending %+v", p)
	}
	if err := f.h.ConfirmMailRemoval(context.Background(), []string{p.Accounts[0].UUID}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	if f.mc.Puts() == puts {
		t.Fatal("the confirmed removal wasn't sent")
	}
}
