package hub

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

func (f *mailFixture) pending() *state.MailPendingRemoval {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	if p := f.h.st.Mail.PendingRemoval; p != nil {
		c := *p
		return &c
	}
	return nil
}

// TestPendingClearsWhenPeopleReturn (M1): the outage recovers (everyone
// back, an identical document): the pending removal clears and the
// returners may create passwords again; a confirm given before the
// recovery never applies to a later outage, which waits for review.
func TestPendingClearsWhenPeopleReturn(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	p := f.pending()
	if p == nil || len(p.Accounts) != 2 {
		t.Fatalf("pending %+v", p)
	}
	if err := f.h.ConfirmMailRemoval(context.Background(), confirmIn(f.h, pendingUUIDs(p.Accounts)), mailAdmin); err != nil {
		t.Fatal(err)
	}
	// The outage recovers before the next pass.
	puts := f.mc.Puts()
	f.people.setMembers("mail_users", "alice", "bob", "root")
	f.sync(t)
	if f.pending() != nil {
		t.Fatalf("pending kept after recovery: %+v", f.pending())
	}
	if f.mc.Puts() != puts {
		t.Fatalf("a document was sent for an unchanged directory: %d", f.mc.Puts()-puts)
	}
	if _, err := f.h.CreateMailPassword(context.Background(), "alice", "again", "none", testProof); err != nil {
		t.Fatalf("a returner can't create: %v", err)
	}
	// A new outage: held for review, the old confirm doesn't carry over.
	f.advance(time.Minute)
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	if d := f.mc.Last(); d.ConfirmMassRemoval || len(d.Accounts) != 3 {
		t.Fatalf("the stale confirm applied: %+v", d)
	}
	if p := f.pending(); p == nil || p.ConfirmedHash != "" {
		t.Fatalf("new pending %+v", p)
	}
}

// TestPendingPartialReturnVoidsConfirm (M1): one person back changes the
// set: the confirm is void, the rest stays pending.
func TestPendingPartialReturnVoidsConfirm(t *testing.T) {
	f := newMailFixture(t)
	f.h.mu.Lock()
	f.h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: time.Now(), Accounts: []state.MailPendingAccount{
		{Username: "alice", UUID: uuidAlice, Revoked: true}, {Username: "bob", UUID: uuidBob, Revoked: true}}}
	f.h.mu.Unlock()
	if err := f.h.ConfirmMailRemoval(context.Background(), confirmIn(f.h, []string{uuidAlice, uuidBob}), mailAdmin); err != nil {
		t.Fatal(err)
	}
	if !f.h.mailPendingConfirmed(map[string]string{"alice": uuidAlice, "bob": uuidBob}) {
		t.Fatal("confirm not applied to its own set")
	}
	if f.h.mailPendingConfirmed(map[string]string{"bob": uuidBob}) {
		t.Fatal("confirm applied to another set")
	}
	doc, err := f.h.mailBuild(context.Background()) // alice is in mail_users
	if err != nil {
		t.Fatal(err)
	}
	doc.Accounts = doc.Accounts[:1] // alice only
	if err := f.h.mailPendingReconcile(doc); err != nil {
		t.Fatal(err)
	}
	p := f.pending()
	if p == nil || len(p.Accounts) != 1 || p.Accounts[0].Username != "bob" || p.ConfirmedHash != "" {
		t.Fatalf("pending %+v", p)
	}
	if f.h.mailPendingConfirmed(map[string]string{"bob": uuidBob}) {
		t.Fatal("void confirm applied")
	}
}

// TestBlindMassRefusal (M2): no baseline and a mass refusal: the 409's
// removed list becomes the pending removal, their passwords are revoked,
// and everything else waits (mail_sync_blocked); without the list,
// nothing is sent and the doctor says so.
func TestBlindMassRefusal(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.create(t, "alice", "phone")
	os.Remove(f.h.mailLastPath())
	f.h.mailState = mailSync{applyWait: 400 * time.Millisecond, applyPoll: 20 * time.Millisecond}
	f.people.setMembers("mail_users", "root")
	puts := f.mc.Puts()
	f.sync(t)
	// The Hub's own baseline (R-L8: alice has a mail password) refuses
	// first, naming whom it knows of.
	p := f.pending()
	if p == nil || len(p.Accounts) != 1 || p.Accounts[0].Username != "alice" {
		t.Fatalf("pending %+v", p)
	}
	if len(f.mc.Creds("alice")) != 0 {
		t.Fatal("alice's password survived")
	}
	for _, a := range p.Accounts {
		if !a.Revoked {
			t.Fatalf("not marked revoked: %+v", a)
		}
	}
	if f.mc.Puts() != puts || f.h.MailSyncBlocked() == "" {
		t.Fatalf("sent %d, blocked %q", f.mc.Puts()-puts, f.h.MailSyncBlocked())
	}
	r, _ := f.h.Doctor(context.Background())
	if findKind(r, doctor.KindMailSyncBlocked) == nil || findKind(r, doctor.KindMailMassRemovalPend) == nil {
		t.Fatal("no doctor findings")
	}

	// Without mailctl's list: nothing pending, nothing sent, blocked.
	g := newMailFixture(t)
	g.sync(t)
	os.Remove(g.h.mailLastPath())
	g.h.mailState = mailSync{applyWait: 400 * time.Millisecond, applyPoll: 20 * time.Millisecond}
	g.mc.Lock(func(s *mailprovidertest.Server) { s.OmitRemoved = true })
	g.people.setMembers("mail_users", "root")
	puts = g.mc.Puts()
	g.sync(t)
	if g.pending() != nil || g.mc.Puts() != puts || !strings.Contains(g.h.MailSyncBlocked(), "can't tell") {
		t.Fatalf("pending %+v sent %d blocked %q", g.pending(), g.mc.Puts()-puts, g.h.MailSyncBlocked())
	}
}

// TestPasswordManagerNeverConfirms (M3): an lldap_password_manager
// member's removals and deletes don't confirm a mass removal; only
// lldap_admin members' do.
func TestPasswordManagerNeverConfirms(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.people.setMembers("mail_users", "root")
	f.h.MailMemberRemoved("mail_users", "alice", "pm")
	f.h.MailMemberRemoved("mail_users", "bob", "pm")
	f.sync(t)
	if d := f.mc.Last(); d.ConfirmMassRemoval || len(d.Accounts) != 3 {
		t.Fatalf("pm confirmed: %+v", d)
	}
	if f.h.isGlobalAdmin(context.Background(), "pm") || !f.h.isGlobalAdmin(context.Background(), "root") {
		t.Fatal("isGlobalAdmin")
	}
}

// TestCreateRechecksUnderSyncLock (L1): a pending removal recorded while
// a create waits for the sync's lock refuses that create.
func TestCreateRechecksUnderSyncLock(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.h.mailState.pass.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := f.h.CreateMailPassword(context.Background(), "alice", "x", "none", testProof)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	f.h.mu.Lock()
	f.h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: time.Now(), Accounts: []state.MailPendingAccount{{Username: "alice", UUID: uuidAlice}}}
	f.h.mu.Unlock()
	f.h.mailState.pass.Unlock()
	if err := <-done; statusOf(err) != 409 {
		t.Fatalf("create: %v", err)
	}
	if len(f.mc.Creds("alice")) != 0 {
		t.Fatal("created anyway")
	}
}

// TestRevokeOnly204 (L3): a non-204 success leaves the row active (503).
func TestRevokeOnly204(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	c := f.create(t, "alice", "phone")
	f.mc.Lock(func(s *mailprovidertest.Server) { s.RevokeOK = true })
	if err := f.h.RevokeOwnMailPassword(context.Background(), "alice", c.ID); statusOf(err) != 503 {
		t.Fatalf("200: %v", err)
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	if !f.h.st.MailCredentials["alice"][0].Active() {
		t.Fatal("row ended on a 200")
	}
}

// TestPendingSaveFailureFailsPass (L4): when the pending removal can't
// be saved, nothing is revoked or sent.
func TestPendingSaveFailureFailsPass(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.create(t, "alice", "phone")
	f.people.setMembers("mail_users", "root")
	doc, err := f.h.mailBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.h.mailState.mu.Lock()
	last := f.h.mailState.last
	f.h.mailState.mu.Unlock()
	d := diffMail(last, doc)
	if err := os.Chmod(f.data, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(f.data, 0o700) })
	puts := f.mc.Puts()
	if w := f.h.mailMassRefused(context.Background(), f.mc.Client(), last, doc, d, nil); w != mailRetry {
		t.Fatalf("wait %s", w)
	}
	if f.pending() != nil || len(f.mc.Creds("alice")) != 1 || f.mc.Puts() != puts {
		t.Fatalf("acted without saving: pending %+v creds %d puts %d", f.pending(), len(f.mc.Creds("alice")), f.mc.Puts()-puts)
	}
	// A whole pass with a read-only data dir: no action either.
	if w := f.sync(t); w == 0 || len(f.mc.Creds("alice")) != 1 {
		t.Fatalf("pass: wait %s creds %d", w, len(f.mc.Creds("alice")))
	}
}

// TestPendingRevokeFailureShown (L5): a failed revoke is shown per
// person (view, doctor) and retried.
func TestPendingRevokeFailureShown(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.create(t, "alice", "phone")
	f.mc.Lock(func(s *mailprovidertest.Server) { s.RevokeStatus = 503 })
	f.people.setMembers("mail_users", "root")
	f.sync(t)
	v := f.h.MailSettingsView().PendingRemoval
	if v == nil {
		t.Fatal("no pending")
	}
	for _, a := range v.Accounts {
		if a.Username == "alice" && a.Revoked {
			t.Fatal("alice shown revoked")
		}
		if a.Username == "bob" && !a.Revoked {
			t.Fatal("bob (no passwords) not revoked")
		}
	}
	r, _ := f.h.Doctor(context.Background())
	if fd := findKind(r, doctor.KindMailMassRemovalPend); fd == nil || !strings.Contains(fd.Why, "failed for alice") {
		t.Fatalf("finding %+v", fd)
	}
	f.mc.Lock(func(s *mailprovidertest.Server) { s.RevokeStatus = 0 })
	f.advance(time.Minute)
	f.sync(t)
	for _, a := range f.pending().Accounts {
		if !a.Revoked {
			t.Fatalf("retry didn't revoke %+v", a)
		}
	}
}

// TestMailHubSecretInvalid: mail on with a missing or short hub secret:
// the Settings banner (the doctor's mail_provider_unreachable after 10
// min: TestDoctorProviderUnreachable), every mail write
// 503 with the text; once the file is valid (in place, no restart) all
// of it clears.
func TestMailHubSecretInvalid(t *testing.T) {
	f := newMailFixture(t)
	secret := f.data + "/hub-secret-test"
	os.WriteFile(secret, []byte("short\n"), 0600)
	f.h.SetMailAPI(mailprovider.New(f.mc.URL(), secret))
	ctx := context.Background()
	if v := f.h.MailSettingsView(); v.Problem != MailSecretProblem {
		t.Fatalf("view %q", v.Problem)
	}
	writes := map[string]error{
		"settings": f.h.SetMailSettings(ctx, goodMailSettings(), mailAdmin),
		"domain":   f.h.SetMailDomain(ctx, "example.org", true, nil, mailAdmin),
		"aliases":  f.h.SetUserAliases(ctx, "alice", nil, mailAdmin),
		"list":     f.h.SetGroupList(ctx, "team_b", false, "", "", mailAdmin),
		"action":   f.h.MailAction(ctx, "dkim-rotate", "example.org", mailAdmin),
		"confirm":  f.h.ConfirmMailRemoval(ctx, confirmIn(f.h, nil), mailAdmin),
	}
	_, cerr := f.h.CreateMailPassword(ctx, "alice", "x", "none", testProof)
	writes["create"] = cerr
	for k, err := range writes {
		if statusOf(err) != 503 || err.Error() != MailSecretProblem {
			t.Errorf("%s: %v", k, err)
		}
	}
	// Fixed in place: no restart needed.
	os.WriteFile(secret, []byte(mailprovidertest.Secret+"\n"), 0600)
	if v := f.h.MailSettingsView(); v.Problem != "" {
		t.Fatalf("view %q", v.Problem)
	}
	if err := f.h.SetMailSettings(ctx, goodMailSettings(), mailAdmin); err != nil {
		t.Fatalf("settings after the fix: %v", err)
	}
}
