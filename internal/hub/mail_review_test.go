package hub

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/mailctl"
	"github.com/portcullis/hub/internal/mailctl/mailctltest"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// TestFirstSyncWithoutBaselineRestarts (F3): no mail-last.json: the first
// accepted document counts as a removal (wait, restart mail); after it
// the baseline is on disk, and a restarted Hub judges removals against it.
func TestFirstSyncWithoutBaselineRestarts(t *testing.T) {
	f := newMailFixture(t)
	f.h.mailState.loaded = false
	f.sync(t)
	if r := f.engine.Restarts(); len(r) != 1 {
		t.Fatalf("blind first document: restarts %v", r)
	}
	if _, err := os.Stat(f.h.mailLastPath()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	f.create(t, "bob", "phone")
	// "Restart" the Hub's mail memory: bob leaves meanwhile.
	f.h.mailState = mailSync{applyWait: 400 * time.Millisecond, applyPoll: 20 * time.Millisecond}
	f.people.setMembers("mail_users", "alice", "root")
	f.sync(t)
	if r := f.engine.Restarts(); len(r) != 2 {
		t.Fatalf("removal across a restart: restarts %v", r)
	}
	f.h.mu.RLock()
	row := f.h.st.MailCredentials["bob"][0]
	f.h.mu.RUnlock()
	if row.Reason != state.MailCredentialReasonRevokeLeave {
		t.Fatalf("bob's row %+v", row)
	}
}

// TestMassRemovalPendingKeepsAccessClosed (F4): a refused mass removal
// revokes the departed people's passwords at once, restarts mail, sends
// every other change with their mailboxes kept, persists the pending
// removal (doctor Problem with a confirm fix), and an administrator's
// confirmation removes them.
func TestMassRemovalPendingKeepsAccessClosed(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.create(t, "alice", "phone")
	f.create(t, "bob", "laptop")
	puts := f.mc.Puts()
	// An LDAP-side shrink: alice and bob gone, root stays; and a settings
	// change that must still reach mailctl.
	f.people.setMembers("mail_users", "root")
	f.h.mu.Lock()
	f.h.st.Mail.Spam.RejectScore = 20
	f.h.mu.Unlock()
	f.sync(t)
	if len(f.mc.Creds("alice"))+len(f.mc.Creds("bob")) != 0 {
		t.Fatalf("departed passwords kept: %v %v", f.mc.Creds("alice"), f.mc.Creds("bob"))
	}
	if len(f.engine.Restarts()) == 0 {
		t.Fatal("no restart after revoking")
	}
	last := f.mc.Last()
	if f.mc.Puts() != puts+1 || last.Spam.RejectScore != 20 || len(last.Accounts) != 3 {
		t.Fatalf("fallback document %d %+v", f.mc.Puts()-puts, last)
	}
	st, _ := state.Load(f.h.statePath())
	if p := st.Mail.PendingRemoval; p == nil || len(p.Accounts) != 2 {
		t.Fatalf("pending not persisted: %+v", st.Mail.PendingRemoval)
	}
	if v := f.h.MailSettingsView(); v.PendingRemoval == nil || len(v.PendingRemoval.Accounts) != 2 {
		t.Fatalf("view %+v", v.PendingRemoval)
	}
	// Nothing new to send: no more documents.
	f.sync(t)
	if f.mc.Puts() != puts+1 {
		t.Fatalf("resent: %d", f.mc.Puts()-puts)
	}
	// The doctor shows it with a class D (touches data) confirm fix.
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fd := findKind(r, doctor.KindMailMassRemovalPend)
	if fd == nil || fd.Severity != doctor.Problem || fd.FixKind != doctor.FixMailConfirmRemoval || !strings.Contains(fd.Why, "alice, bob") {
		t.Fatalf("finding %+v", fd)
	}
	p, err := f.h.PreviewFix(context.Background(), fd.FP, nil)
	if err != nil || !p.TouchesData || !strings.Contains(p.Lines[0], "alice, bob") {
		t.Fatalf("preview %+v %v", p, err)
	}
	// A stale list is refused; the exact one confirms.
	if err := f.h.ConfirmMailRemoval(context.Background(), []string{uuidAlice}, mailAdmin); statusOf(err) != 409 {
		t.Fatalf("partial confirm: %v", err)
	}
	if err := f.h.ConfirmMailRemoval(context.Background(), []string{uuidBob, uuidAlice}, mailAdmin); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	last = f.mc.Last()
	if !last.ConfirmMassRemoval || len(last.Accounts) != 1 {
		t.Fatalf("confirmed document %+v", last)
	}
	f.h.mu.RLock()
	pend := f.h.st.Mail.PendingRemoval
	f.h.mu.RUnlock()
	if pend != nil {
		t.Fatalf("pending kept: %+v", pend)
	}
}

// TestRevokeAfterRecreate (F2): a stale row of the username's former
// holder never deletes the new holder's password with the same id and
// created_at.
func TestRevokeAfterRecreate(t *testing.T) {
	f := newMailFixture(t)
	tick := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	f.mc.Lock(func(s *mailctltest.Server) { s.Now = func() time.Time { return tick } })
	f.sync(t)
	old := f.create(t, "alice", "old")
	// alice is deleted and created again: a new uuid, a new account in
	// mailctl, a password with the same id and created_at.
	const newUUID = "77777777-2222-4333-8444-555555555555"
	f.people.mu.Lock()
	f.people.m.UUIDs["alice"] = newUUID
	f.people.mu.Unlock()
	f.mc.DropCreds("alice")
	f.sync(t)
	f.create(t, "alice", "new")
	if got := f.mc.Creds("alice"); len(got) != 1 {
		t.Fatalf("creds %+v", got)
	}
	// Put the old row back to active (as if never reconciled).
	f.h.mu.Lock()
	for i, r := range f.h.st.MailCredentials["alice"] {
		if r.ID == old.ID {
			f.h.st.MailCredentials["alice"][i].RevokedAt, f.h.st.MailCredentials["alice"][i].Reason = nil, ""
		}
	}
	f.h.mu.Unlock()
	if err := f.h.RevokeOwnMailPassword(context.Background(), "alice", old.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.mc.Creds("alice"); len(got) != 1 {
		t.Fatalf("the new holder's password was deleted: %+v", got)
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	for _, r := range f.h.st.MailCredentials["alice"] {
		if r.ID == old.ID && r.Reason != state.MailCredentialReasonRevokeLeave {
			t.Fatalf("old row %+v", r)
		}
	}
	// The new alice sees only her own row (F8).
	if v := f.h.MailPasswords("alice", newUUID); len(v) != 1 || v[0].Label != "new" {
		t.Fatalf("list %+v", v)
	}
}

// TestAliasesNotInherited (F5): aliases belong to the uuid: a re-created
// username gets none, and deleting the person drops them.
func TestAliasesNotInherited(t *testing.T) {
	f := newMailFixture(t)
	ctx := context.Background()
	if err := f.h.SetUserAliases(ctx, "alice", []string{"sales@example.org"}, mailAdmin); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	if a := f.mc.Last().Aliases; len(a) != 1 || a[0].Username != "alice" {
		t.Fatalf("aliases %+v", a)
	}
	f.people.mu.Lock()
	f.people.m.UUIDs["alice"] = "88888888-2222-4333-8444-555555555555"
	f.people.mu.Unlock()
	f.sync(t)
	if a := f.mc.Last().Aliases; len(a) != 0 {
		t.Fatalf("a re-created alice inherited %+v", a)
	}
	f.h.PersonDeleted(ctx, directory.Human("root"), "alice")
	f.h.mu.RLock()
	n := len(f.h.st.Mail.Aliases)
	f.h.mu.RUnlock()
	if n != 0 {
		t.Fatalf("aliases kept after delete: %d", n)
	}
}

// TestPasswordNeverLogged: create, profile, revoke: the password never
// reaches the log.
func TestPasswordNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f := newMailFixture(t)
	f.sync(t)
	c := f.create(t, "alice", "phone")
	secret := string(c.Password)
	if err := f.h.RevokeOwnMailPassword(context.Background(), "alice", c.ID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if strings.Contains(buf.String(), secret) || secret == "" {
		t.Fatalf("password in the log:\n%s", buf.String())
	}
}

// TestCreateWithoutUUID503 (F9): a mail_users member without an LLDAP
// uuid gets 503 at step 6, not the shared 404.
func TestCreateWithoutUUID503(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	if _, err := f.h.CreateMailPassword(context.Background(), "carol", "x", "none", testProof); statusOf(err) != 503 {
		t.Fatalf("carol: %v", err)
	}
}

// TestRemovalRetriesFast (F6): a failed removal is retried after 2 s,
// doubling to 30 s; other failures wait 30 s.
func TestRemovalRetriesFast(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.mc.Lock(func(s *mailctltest.Server) { s.PutStatus, s.PutMsg = 500, "boom" })
	f.people.setMembers("mail_users", "alice", "root")
	for _, want := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second} {
		if w := f.sync(t); w != want {
			t.Fatalf("retry %s, want %s", w, want)
		}
	}
	f.mc.Lock(func(s *mailctltest.Server) { s.PutStatus = 0 })
	f.sync(t)
	f.mc.Lock(func(s *mailctltest.Server) { s.PutStatus, s.PutMsg = 500, "boom" })
	f.h.mu.Lock()
	f.h.st.Mail.Spam.RejectScore = 30
	f.h.mu.Unlock()
	if w := f.sync(t); w != mailRetry {
		t.Fatalf("non-removal retry %s", w)
	}
}

// TestMassVsGenerationConflict (F18): the two 409s are told apart.
func TestMassVsGenerationConflict(t *testing.T) {
	gen := &mailctl.APIError{Status: 409, Msg: "generation 3 is not greater than 5"}
	mass := &mailctl.APIError{Status: 409, Msg: "anything", Kind: mailctl.ErrorKindMassRemoval}
	textOnly := &mailctl.APIError{Status: 409, Msg: "mass removal: 2 of 3 accounts"}
	if isMassRemoval(gen) || !isMassRemoval(mass) || isMassRemoval(textOnly) {
		t.Fatal("misclassified (error_kind only, no text fallback)")
	}
	// A state.yaml behind mailctl's generation moves past it.
	f := newMailFixture(t)
	f.sync(t)
	f.h.mu.Lock()
	f.h.st.Mail.Generation = 0
	f.h.st.Mail.Spam.RejectScore = 25
	f.h.mu.Unlock()
	f.sync(t)
	if d := f.mc.Last(); d.Spam.RejectScore != 25 || d.Generation <= 1 {
		t.Fatalf("generation recovery %+v", d)
	}
}

// TestMailHostnameReserved (F13): a custom MAIL_HOSTNAME is reserved too.
func TestMailHostnameReserved(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.project+"/.env", "CORE_VAR=core-value\nPORTCULLIS_MAIL=on\nPORTCULLIS_MAIL_HOSTNAME=mx.example.org\n")
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	if err := f.h.checkInstanceHostsLocked(&templates.Template{ID: "x", Subdomains: []string{"mx"}}, nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "mail server's name") {
		t.Fatalf("mx: %v", err)
	}
}

// TestDeleteDomainRefusedUntilSetRemoved (F12): off but not retired
// (its mail set not removed yet) is still refused.
func TestDeleteDomainRefusedUntilSetRemoved(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	ctx := context.Background()
	const d = "team-b.example.net"
	f.h.EnrollDomain(ctx, directory.Human("alice"), d, "cloudflare", creds())
	api.set(d, true, time.Now().Add(60*24*time.Hour))
	f.h.RefreshDomains(ctx)
	f.h.mu.Lock()
	f.h.st.Mail.Domains = map[string]state.MailDomain{d: {}}
	f.h.mu.Unlock()
	if _, err := f.h.DeleteDomain(ctx, directory.Human("alice"), d); statusOf(err) != 409 {
		t.Fatalf("off, not retired: %v", err)
	}
}

// TestMailFixStaleHash409 (F16): a stale plan hash is the synchronous 409.
func TestMailFixStaleHash409(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	q := "quarantine"
	seen := time.Now().UTC()
	f.mc.Lock(func(s *mailctltest.Server) {
		s.StatusV.DMARC = []mailctl.StatusDMARC{{Domain: "example.org", Policy: "none", Proposed: &q}}
		s.StatusV.TimerSeenAt = &seen
	})
	r, _ := f.h.Doctor(context.Background())
	fd := findKind(r, doctor.KindMailDMARCPromote)
	if fd == nil {
		t.Fatal("no finding")
	}
	if op, err := f.h.ApplyFix(context.Background(), fd.FP, nil, strings.Repeat("0", 64), mailAdmin); statusOf(err) != 409 || op != nil {
		t.Fatalf("stale hash: %v %v", op, err)
	}
}

// TestDelegateRemovalNeverConfirms (I2): a delegate's removals of
// mail_users members go through but never confirm a mass removal; a full
// administrator's do.
func TestDelegateRemovalNeverConfirms(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	f.people.setMembers("mail_users", "root")
	f.h.MailMemberRemoved("mail_users", "alice", false)
	f.h.MailMemberRemoved("mail_users", "bob", false)
	f.sync(t)
	if d := f.mc.Last(); d.ConfirmMassRemoval || len(d.Accounts) != 3 {
		t.Fatalf("a delegate confirmed a mass removal: %+v", d)
	}
	f.h.mu.RLock()
	pend := f.h.st.Mail.PendingRemoval
	f.h.mu.RUnlock()
	if pend == nil {
		t.Fatal("no pending removal")
	}
	// A delegate's delete doesn't record either.
	f.h.PersonDeleted(context.Background(), directory.Human("delegate"), "alice")
	f.h.mailState.mu.Lock()
	n := len(f.h.mailState.hubRemoved)
	f.h.mailState.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d entries from a delegate", n)
	}
	// A full administrator's removals confirm.
	f.h.MailMemberRemoved("mail_users", "alice", true)
	f.h.MailMemberRemoved("mail_users", "bob", true)
	f.sync(t)
	if d := f.mc.Last(); !d.ConfirmMassRemoval || len(d.Accounts) != 1 {
		t.Fatalf("admin removals: %+v", d)
	}
}
