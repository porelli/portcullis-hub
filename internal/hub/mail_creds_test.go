package hub

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

// newMailCredFixture: newMailFixture with fresh auth in place, an audit
// log, and the first document accepted (alice, bob and root have
// mailboxes).
func newMailCredFixture(t *testing.T) (*mailFixture, *fakeFreshAuth, *fakeAudit) {
	t.Helper()
	f := newMailFixture(t)
	fa := &fakeFreshAuth{}
	f.h.SetFreshAuth(ListenerPeople, fa)
	f.h.freshAuthReady.Store(true)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	f.sync(t)
	return f, fa, audit
}

func (f *mailFixture) create(t *testing.T, user, label string) *CreatedMailPassword {
	t.Helper()
	c, err := f.h.CreateMailPassword(context.Background(), user, label, "none", testProof)
	if err != nil {
		t.Fatalf("CreateMailPassword(%s): %v", user, err)
	}
	return c
}

// TestCreateMailPasswordOrder: each refusal in contract order, and the
// proof is never looked at before step 7.
func TestCreateMailPasswordOrder(t *testing.T) {
	f, fa, audit := newMailCredFixture(t)
	ctx := context.Background()
	try := func(user, label, expiry string) error {
		_, err := f.h.CreateMailPassword(ctx, user, label, expiry, testProof)
		return err
	}
	// 2. mailctl without the base plan: 503.
	f.mc.Lock(func(s *mailprovidertest.Server) { s.Bootstrap = false })
	if err := try("alice", "iPhone", "none"); statusOf(err) != 503 || err.Error() != "mail isn't running right now" {
		t.Fatalf("no bootstrap: %v", err)
	}
	f.mc.Lock(func(s *mailprovidertest.Server) { s.Bootstrap = true })
	// 3. Not in mail_users: the shared 404 (dave, and nobody at all).
	errDave, errNobody := try("dave", "x", "none"), try("nobody", "x", "none")
	if statusOf(errDave) != 404 || errDave.Error() != errNobody.Error() || statusOf(errNobody) != 404 {
		t.Fatalf("not a member: %v / %v", errDave, errNobody)
	}
	// 4. Label and expiry.
	for _, c := range [][2]string{{"", "none"}, {strings.Repeat("x", 65), "none"}, {"two\nlines", "none"}, {"ok", "2y"}} {
		if err := try("alice", c[0], c[1]); statusOf(err) != 400 {
			t.Errorf("%q %q: %v", c[0], c[1], err)
		}
	}
	if fa.calls.Load() != 0 {
		t.Fatalf("the proof was checked %d times before step 7", fa.calls.Load())
	}
	// 7. The proof refused: 403, audited with the reason only.
	fa.err = &freshauth.Error{Reason: "nonce mismatch"}
	if err := try("alice", "iPhone", "none"); statusOf(err) != 403 {
		t.Fatalf("refused proof: %v", err)
	}
	if e := audit.lastOf("mail_credential.create"); e.Result != "refused" || !strings.Contains(e.Detail, "nonce mismatch") || strings.Contains(e.Detail, testProof.Code) {
		t.Fatalf("audit %+v", e)
	}
	fa.err = nil
	// 5. At most 5 active: the sixth is 409 before the proof.
	for i := 0; i < 5; i++ {
		f.create(t, "alice", "device")
	}
	n := fa.calls.Load()
	if err := try("alice", "sixth", "none"); statusOf(err) != 409 || err.Error() != "at most 5 mail passwords: revoke one first" {
		t.Fatalf("sixth: %v", err)
	}
	if fa.calls.Load() != n {
		t.Fatal("the proof was checked for a sixth password")
	}
	if got := len(f.mc.Creds("alice")); got != 5 {
		t.Fatalf("mailctl holds %d", got)
	}
}

// TestCreateRequiresMailUsers: someone outside mail_users gets the same
// 404 as an unknown name, from create and from the view.
func TestCreateRequiresMailUsers(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	_, e1 := f.h.MyMail(context.Background(), "dave")
	_, e2 := f.h.MyMail(context.Background(), "nobody")
	_, e3 := f.h.CreateMailPassword(context.Background(), "dave", "x", "none", testProof)
	if statusOf(e1) != 404 || statusOf(e3) != 404 || e1.Error() != e2.Error() || e1.Error() != e3.Error() {
		t.Fatalf("%v / %v / %v", e1, e2, e3)
	}
	v, err := f.h.MyMail(context.Background(), "alice")
	if err != nil || v.Username != "alice@example.org" || v.Server != "mail.example.org" || v.IMAPS != 993 || v.Submissions != 465 || v.Submission != 587 || len(v.Passwords) != 0 {
		t.Fatalf("alice: %+v %v", v, err)
	}
}

// TestCreateWhileMailOff503: PORTCULLIS_MAIL=off: create 503, view 404.
func TestCreateWhileMailOff503(t *testing.T) {
	f, fa, _ := newMailCredFixture(t)
	setCoreMail(t, f.fixture, false)
	if _, err := f.h.CreateMailPassword(context.Background(), "alice", "x", "none", testProof); statusOf(err) != 503 || err.Error() != "mail isn't running right now" {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.h.MyMail(context.Background(), "alice"); statusOf(err) != 404 {
		t.Fatalf("view: %v", err)
	}
	if fa.calls.Load() != 0 {
		t.Fatal("proof checked")
	}
}

// TestMobileConfigFields: the profile is an Apple configuration profile
// for IMAP 993 SSL and SMTP 465 SSL with the login and the password.
func TestMobileConfigFields(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	c := f.create(t, "alice", "iPhone & <Mac>")
	secret := string(c.Password)
	if secret == "" || !strings.HasPrefix(secret, "mailpw-alice-") {
		t.Fatalf("password %q", secret)
	}
	var prof map[string]any
	if _, err := plist.Unmarshal(c.MobileConfig, &prof); err != nil {
		t.Fatalf("profile: %v\n%s", err, c.MobileConfig)
	}
	if prof["PayloadType"] != "Configuration" {
		t.Fatalf("profile %+v", prof)
	}
	a := prof["PayloadContent"].([]any)[0].(map[string]any)
	for k, want := range map[string]any{
		"PayloadType": "com.apple.mail.managed", "EmailAccountType": "EmailTypeIMAP", "EmailAddress": "alice@example.org",
		"IncomingMailServerHostName": "mail.example.org", "IncomingMailServerPortNumber": uint64(993), "IncomingMailServerUseSSL": true,
		"IncomingMailServerUsername": "alice@example.org", "IncomingPassword": secret,
		"OutgoingMailServerHostName": "mail.example.org", "OutgoingMailServerPortNumber": uint64(465), "OutgoingMailServerUseSSL": true,
		"OutgoingMailServerUsername": "alice@example.org", "OutgoingPassword": secret,
	} {
		if a[k] != want {
			t.Errorf("%s = %#v, want %#v", k, a[k], want)
		}
	}
	if !strings.Contains(a["EmailAccountDescription"].(string), "iPhone & <Mac>") {
		t.Errorf("description %v", a["EmailAccountDescription"])
	}
	c.Zero()
	for _, b := range append(append([]byte{}, c.Password...), c.MobileConfig...) {
		if b != 0 {
			t.Fatal("Zero left bytes")
		}
	}
}

// TestSecretNotInAuditOrState: the password is in neither the audit log
// nor state.yaml; the row is.
func TestSecretNotInAuditOrState(t *testing.T) {
	f, _, audit := newMailCredFixture(t)
	c := f.create(t, "alice", "iPhone")
	secret := string(c.Password)
	raw, _ := os.ReadFile(f.h.statePath())
	if strings.Contains(string(raw), secret) || !strings.Contains(string(raw), "mail_credentials:") {
		t.Fatalf("state.yaml:\n%s", raw)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	found := false
	for _, e := range audit.entries {
		if strings.Contains(e.Detail+e.Error+e.Target, secret) {
			t.Fatalf("secret in audit %+v", e)
		}
		if e.Action == "mail_credential.create" && e.Result == "ok" {
			found = strings.Contains(e.Detail, "id="+c.ID) && strings.Contains(e.Detail, "label_length=6")
		}
	}
	if !found {
		t.Fatalf("no create audit: %+v", audit.entries)
	}
}

// TestRevokeOwnMailPassword: revoked in mailctl, marked, audited, mail
// restarted; another's id is 404; a revoked row never deletes the newer
// password that reused its Stalwart id.
func TestRevokeOwnMailPassword(t *testing.T) {
	f, _, audit := newMailCredFixture(t)
	ctx := context.Background()
	a := f.create(t, "alice", "one")
	if err := f.h.RevokeOwnMailPassword(ctx, "bob", a.ID); statusOf(err) != 404 {
		t.Fatalf("bob revoking alice's: %v", err)
	}
	if err := f.h.RevokeOwnMailPassword(ctx, "alice", a.ID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if len(f.mc.Creds("alice")) != 0 || len(f.h.MailPasswords("alice", uuidAlice)) != 0 {
		t.Fatalf("still there: %v %v", f.mc.Creds("alice"), f.h.MailPasswords("alice", uuidAlice))
	}
	if len(f.engine.Restarts()) == 0 {
		t.Fatal("no restart after a revoke")
	}
	if e := audit.lastOf("mail_credential.revoke"); e.Result != "ok" || !strings.Contains(e.Detail, "actor=alice") {
		t.Fatalf("audit %+v", e)
	}
	if err := f.h.RevokeOwnMailPassword(ctx, "alice", a.ID); err != nil {
		t.Fatalf("again: %v", err)
	}
	// Stalwart id reuse: b gets id 1 after a's password vanished behind
	// the Hub's back; revoking a stale row must leave b alone.
	tick := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.Now = func() time.Time { tick = tick.Add(time.Second); return tick }
	})
	f.mc.DropCreds("alice")
	b0 := f.create(t, "alice", "two")
	f.mc.DropCreds("alice")
	b := f.create(t, "alice", "three")
	if got := f.mc.Creds("alice"); len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("ids %+v", got)
	}
	f.h.mu.Lock()
	for i, r := range f.h.st.MailCredentials["alice"] {
		if r.ID == b0.ID { // keep the stale row active (as if never reconciled)
			f.h.st.MailCredentials["alice"][i].RevokedAt = nil
			f.h.st.MailCredentials["alice"][i].Reason = ""
		}
	}
	f.h.mu.Unlock()
	if err := f.h.RevokeOwnMailPassword(ctx, "alice", b0.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.mc.Creds("alice"); len(got) != 1 {
		t.Fatalf("the newer password was deleted through a stale row: %+v (b %s)", got, b.ID)
	}
}

// TestAdminRevokeMailPassword: revoked_by the admin; no admin create.
func TestAdminRevokeMailPassword(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	a := f.create(t, "alice", "one")
	if err := f.h.AdminRevokeMailPassword(context.Background(), "alice", a.ID, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	f.h.mu.RLock()
	r := f.h.st.MailCredentials["alice"][0]
	f.h.mu.RUnlock()
	if r.Active() || r.RevokedBy != "root" || r.Reason != state.MailCredentialReasonRevoked {
		t.Fatalf("row %+v", r)
	}
}

// TestRevokeLeaveMarksRows: bob leaving mail_users ends his rows as
// revoke_leave once the removal is sent, audited with the count.
func TestRevokeLeaveMarksRows(t *testing.T) {
	f, _, audit := newMailCredFixture(t)
	f.create(t, "bob", "one")
	f.create(t, "bob", "two")
	f.create(t, "alice", "mine")
	f.people.setMembers("mail_users", "alice", "root")
	f.sync(t)
	f.h.mu.RLock()
	rows := append([]state.MailCredential{}, f.h.st.MailCredentials["bob"]...)
	alice := f.h.st.MailCredentials["alice"][0]
	f.h.mu.RUnlock()
	for _, r := range rows {
		if r.Active() || r.Reason != state.MailCredentialReasonRevokeLeave {
			t.Fatalf("bob's row %+v", r)
		}
	}
	if !alice.Active() {
		t.Fatal("alice's row ended")
	}
	if e := audit.lastOf("mail_credential.revoke_leave"); e.Target != "bob" || e.Detail != "count=2" {
		t.Fatalf("audit %+v", e)
	}
}

// TestReconcileVoidRestore: a row with no live password after a restore
// is voided (listed "voided"); without a restore it ends missing (not
// listed); an expired one ends expired.
func TestReconcileVoidRestore(t *testing.T) {
	f, _, audit := newMailCredFixture(t)
	ctx := context.Background()
	f.create(t, "alice", "phone")
	f.mc.DropCreds("alice")
	later := time.Now().UTC().Add(time.Hour)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = &later })
	v, err := f.h.MyMail(ctx, "alice")
	if err != nil || len(v.Passwords) != 1 || v.Passwords[0].Status != "voided" {
		t.Fatalf("after a restore: %+v %v", v, err)
	}
	if e := audit.lastOf("mail_credential.void_restore"); e.Detail != "count=1" {
		t.Fatalf("audit %+v", e)
	}
	// No restore since: missing (gone from the list).
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = nil })
	f.create(t, "alice", "tablet")
	f.mc.DropCreds("alice")
	v, _ = f.h.MyMail(ctx, "alice")
	if len(v.Passwords) != 1 {
		t.Fatalf("missing row listed: %+v", v.Passwords)
	}
	f.h.mu.RLock()
	last := f.h.st.MailCredentials["alice"][1]
	f.h.mu.RUnlock()
	if last.Reason != state.MailCredentialReasonMissing {
		t.Fatalf("row %+v", last)
	}
	// Expired.
	c, err := f.h.CreateMailPassword(ctx, "alice", "laptop", "90d", testProof)
	if err != nil {
		t.Fatal(err)
	}
	f.advance(91 * 24 * time.Hour)
	f.h.MyMail(ctx, "alice")
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	for _, r := range f.h.st.MailCredentials["alice"] {
		if r.ID == c.ID && r.Reason != state.MailCredentialReasonExpired {
			t.Fatalf("expired row %+v", r)
		}
	}
}

// mailReason is user's row id's reason ("" = active).
func (f *mailFixture) mailReason(user, id string) string {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	for _, r := range f.h.st.MailCredentials[user] {
		if r.ID == id {
			return r.Reason
		}
	}
	return "no row"
}

// TestPersonMailReconciles (§19.11): the administrator's view of a
// person's mail reconciles with mailctl first (a restore's rows are
// "voided" without the person opening their page); while mailctl can't
// be read the active rows are "unconfirmed", never "active".
func TestPersonMailReconciles(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	ctx := context.Background()
	root := &directory.Caller{User: "root", Admin: true}
	c := f.create(t, "alice", "phone")
	f.mc.DropCreds("alice")
	later := time.Now().UTC().Add(time.Hour)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = &later })
	v, err := f.h.PersonMail(ctx, root, "alice")
	if err != nil || len(v.Passwords) != 1 || v.Passwords[0].Status != "voided" || f.mailReason("alice", c.ID) != state.MailCredentialReasonVoidRestore {
		t.Fatalf("after a restore: %+v %v", v, err)
	}
	// mailctl unreachable: unconfirmed.
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = nil })
	c2 := f.create(t, "alice", "tablet")
	f.mc.Lock(func(s *mailprovidertest.Server) { s.Down = true })
	v, err = f.h.PersonMail(ctx, root, "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range v.Passwords {
		if p.Status == "active" || (p.ID == c2.ID && p.Status != "unconfirmed") {
			t.Fatalf("mailctl down: %+v", v.Passwords)
		}
	}
	if f.mailReason("alice", c2.ID) != "" {
		t.Fatal("an unconfirmed row was ended")
	}
	// Back: active again.
	f.mc.Lock(func(s *mailprovidertest.Server) { s.Down = false })
	v, _ = f.h.PersonMail(ctx, root, "alice")
	for _, p := range v.Passwords {
		if p.ID == c2.ID && p.Status != "active" {
			t.Fatalf("mailctl back: %+v", v.Passwords)
		}
	}
}

// failCreds is a MailAPI whose credential reads fail.
type failCreds struct{ MailAPI }

func (failCreds) Credentials(context.Context, string) ([]mailprovider.Credential, error) {
	return nil, errors.New("mailctl: connection reset")
}

// TestMailRestoreReconcile (§19.11): mailctl's restored_at later than
// the last full reconcile voids everyone's restored rows — at start
// (the first pass, the restored mailctl already holding an applied
// document) and on the 60 s tick (the Hub outlived a restore of mail
// alone); the restore is recorded only after the reconcile succeeded,
// so a failure retries on the next check.
func TestMailRestoreReconcile(t *testing.T) {
	// At start.
	f := newMailFixture(t)
	f.sync(t)
	c := f.create(t, "alice", "phone")
	f.mc.DropCreds("alice")
	later := time.Now().UTC().Add(time.Hour)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = &later })
	g := newMailFixture(t) // a Hub started on the restored data
	g.h.mu.Lock()
	g.h.st.MailCredentials = f.h.st.MailCredentials
	g.h.mu.Unlock()
	g.h.SetMailAPI(f.mc.Client())
	g.h.mailState.reconciled = true // no first accepted document
	g.sync(t)
	if r := g.mailReason("alice", c.ID); r != state.MailCredentialReasonVoidRestore {
		t.Fatalf("at start: reason %q", r)
	}

	// On the tick: the Hub outlives the restore.
	h := newMailFixture(t)
	h.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = nil })
	h.sync(t)
	c = h.create(t, "bob", "phone")
	h.mc.DropCreds("bob")
	at := time.Now().UTC().Add(time.Hour)
	h.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = &at })
	h.sync(t) // inside the 60 s: not checked yet
	if r := h.mailReason("bob", c.ID); r != "" {
		t.Fatalf("before the tick: reason %q", r)
	}
	h.advance(mailRestoreEvery)
	if next := h.sync(t); next > mailRestoreEvery {
		t.Fatalf("next pass in %v", next)
	}
	if r := h.mailReason("bob", c.ID); r != state.MailCredentialReasonVoidRestore {
		t.Fatalf("on the tick: reason %q", r)
	}

	// A failed reconcile isn't recorded: the next check retries.
	c = h.create(t, "alice", "laptop")
	h.mc.DropCreds("alice")
	at2 := at.Add(time.Hour)
	h.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = &at2 })
	api := h.mc.Client()
	handled := func() time.Time {
		h.h.mu.RLock()
		defer h.h.mu.RUnlock()
		if h.h.st.Mail.RestoreHandled == nil {
			return time.Time{}
		}
		return *h.h.st.Mail.RestoreHandled
	}
	h.h.mailRestoreReconcile(context.Background(), failCreds{api})
	if r := h.mailReason("alice", c.ID); r != "" || !handled().Equal(at) {
		t.Fatalf("failed: reason %q, handled %v", r, handled())
	}
	h.h.mailRestoreReconcile(context.Background(), api)
	if r := h.mailReason("alice", c.ID); r != state.MailCredentialReasonVoidRestore || !handled().Equal(at2) {
		t.Fatalf("retried: reason %q, handled %v", r, handled())
	}
	// Persisted: a restarted Hub doesn't run it again.
	h.h.mu.Lock()
	h.h.st.MailCredentials["alice"] = append(h.h.st.MailCredentials["alice"], state.MailCredential{ID: "mx", StalwartID: "gone", UUID: h.h.st.MailCredentials["alice"][0].UUID, CreatedAt: at2.Add(-time.Minute)})
	h.h.mu.Unlock()
	h.h.mailState.reconciled = true
	h.h.mailRestoreReconcile(context.Background(), api)
	if r := h.mailReason("alice", "mx"); r != "" {
		t.Fatalf("a handled restore ran again: %q", r)
	}
}

// TestReconcileCreateRace: a create that lands between a reconcile's
// live-list read and its end-rows step waits for it (the person's mail
// credential lock) and its row stays active; a row recorded after the
// list was read (bypassing the lock) is never ended by that reconcile.
func TestReconcileCreateRace(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	ctx := context.Background()
	f.create(t, "alice", "phone")
	f.mc.DropCreds("alice") // the old row has no live password: ended
	// (A flag, not sync.Once: Once would make the create's own reconcile
	// wait on the hook, hiding a missing lock.)
	var fired atomic.Bool
	var created *CreatedMailPassword
	var createErr error
	done := make(chan struct{})
	f.h.mailReconcileHook = func(user string) {
		if fired.Swap(true) {
			return
		}
		func() {
			go func() {
				defer close(done)
				created, createErr = f.h.CreateMailPassword(context.Background(), "alice", "tablet", "none", testProof)
			}()
			select {
			case <-done:
				t.Error("the create didn't wait for the reconcile")
			case <-time.After(150 * time.Millisecond):
			}
		}()
	}
	if _, err := f.h.MyMail(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	<-done
	if createErr != nil {
		t.Fatal(createErr)
	}
	if r := f.mailReason("alice", created.ID); r != "" {
		t.Fatalf("the new row ended: %q", r)
	}
	v, _ := f.h.MyMail(ctx, "alice")
	if len(v.Passwords) != 1 || v.Passwords[0].ID != created.ID || v.Passwords[0].Status != "active" {
		t.Fatalf("after: %+v", v.Passwords)
	}

	// Belt and braces: a row recorded after the list read (no live
	// password in that list) isn't judged by that reconcile.
	late := state.MailCredential{ID: "mlate", StalwartID: "s-late", Label: "late", UUID: "uuid-alice", CreatedAt: time.Now().UTC()}
	var once2 sync.Once
	f.h.mailReconcileHook = func(string) {
		once2.Do(func() {
			f.h.mu.Lock()
			late.UUID = f.h.st.MailCredentials["alice"][0].UUID
			f.h.st.MailCredentials["alice"] = append(f.h.st.MailCredentials["alice"], late)
			f.h.mu.Unlock()
		})
	}
	f.mc.DropCreds("alice")
	f.h.MyMail(ctx, "alice")
	if r := f.mailReason("alice", "mlate"); r != "" {
		t.Fatalf("a row recorded after the list read was ended: %q", r)
	}
	if r := f.mailReason("alice", created.ID); r != state.MailCredentialReasonMissing {
		t.Fatalf("the judged row: %q", r)
	}
	f.h.mailReconcileHook = nil
	f.h.MyMail(ctx, "alice") // the next reconcile judges it
	if r := f.mailReason("alice", "mlate"); r != state.MailCredentialReasonMissing {
		t.Fatalf("next reconcile: %q", r)
	}
}

// deletePerson takes user out of the fixture's directory entirely (no
// uuid, no groups).
func (f *mailFixture) deletePerson(user string) {
	f.people.mu.Lock()
	delete(f.people.m.UUIDs, user)
	delete(f.people.m.Users, user)
	f.people.mu.Unlock()
}

// TestRestoreReconcileKeepsUnremovedRows (final review M1): bob deleted
// from the directory while mailctl still holds his account (the removal
// document not accepted yet), a restore to handle: the reconcile at
// start never ends his row on the directory's word alone; once mailctl
// accepted the removal his row ends revoke_leave.
func TestRestoreReconcileKeepsUnremovedRows(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	c := f.create(t, "bob", "phone")
	f.deletePerson("bob")
	later := time.Now().UTC().Add(time.Hour)
	f.mc.Lock(func(s *mailprovidertest.Server) {
		s.StatusV.RestoredAt = &later
		s.PutStatus = 503 // the removal isn't accepted
	})
	f.advance(mailRestoreEvery)
	f.sync(t)
	if r := f.mailReason("bob", c.ID); r != "" {
		t.Fatalf("ended before mailctl removed bob: %q", r)
	}
	// A pending removal naming him (its revoke failing) holds it too.
	f.h.mu.Lock()
	uuid := f.h.st.MailCredentials["bob"][0].UUID
	f.h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: time.Now(), Accounts: []state.MailPendingAccount{{Username: "bob", UUID: uuid}}}
	f.h.mu.Unlock()
	if !f.h.reconcileAllMailPasswords(context.Background(), f.mc.Client(), nil) {
		t.Fatal("reconcile failed")
	}
	if r := f.mailReason("bob", c.ID); r != "" {
		t.Fatalf("ended while a removal is pending: %q", r)
	}
	f.h.mu.Lock()
	f.h.st.Mail.PendingRemoval = nil
	f.h.mu.Unlock()
	// Accepted: ended revoke_leave.
	f.mc.Lock(func(s *mailprovidertest.Server) { s.PutStatus = 0 })
	f.sync(t)
	if r := f.mailReason("bob", c.ID); r != state.MailCredentialReasonRevokeLeave {
		t.Fatalf("after the removal: %q", r)
	}
}

// TestPersonMailUnknownUserNoEnd (final review M1): an administrator's
// view of a deleted username mailctl still holds leaves the rows as they
// are (shown unconfirmed) and revokes nothing.
func TestPersonMailUnknownUserNoEnd(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	c := f.create(t, "bob", "phone")
	f.deletePerson("bob")
	var dels int
	f.mc.Lock(func(s *mailprovidertest.Server) { dels = len(s.Deletes) })
	v, err := f.h.PersonMail(context.Background(), &directory.Caller{User: "root", Admin: true}, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if r := f.mailReason("bob", c.ID); r != "" {
		t.Fatalf("a deleted username's row ended: %q", r)
	}
	for _, p := range v.Passwords {
		if p.Status == "active" {
			t.Fatalf("shown active: %+v", v.Passwords)
		}
	}
	f.mc.Lock(func(s *mailprovidertest.Server) {
		if len(s.Deletes) != dels {
			t.Errorf("revoked: %v", s.Deletes[dels:])
		}
	})
}

// slowCreds is a MailAPI whose credential reads take 2 s.
type slowCreds struct{ MailAPI }

func (s slowCreds) Credentials(ctx context.Context, user string) ([]mailprovider.Credential, error) {
	time.Sleep(2 * time.Second)
	return s.MailAPI.Credentials(ctx, user)
}

// TestRestoreReconcileNeverDelaysRemoval (final review L1): with a
// restore check due and mailctl's credential reads slow, a removal is
// still sent at once: the reconcile runs after the pass, in the
// background, without the sync lock.
func TestRestoreReconcileNeverDelaysRemoval(t *testing.T) {
	f, _, _ := newMailCredFixture(t)
	f.create(t, "alice", "phone")
	f.mc.DropCreds("alice")
	later := time.Now().UTC().Add(time.Hour)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.StatusV.RestoredAt = &later })
	f.h.SetMailAPI(slowCreds{f.mc.Client()})
	f.advance(mailRestoreEvery)
	puts := f.mc.Puts()
	f.people.setMembers("mail_users", "alice", "root")
	start := time.Now()
	f.h.mailSyncOnce(context.Background())
	if d := time.Since(start); d >= time.Second || f.mc.Puts() != puts+1 {
		t.Fatalf("the removal took %v (%d puts)", d, f.mc.Puts()-puts)
	}
	// The sync lock is free while the reconcile runs: a second pass
	// doesn't wait for it.
	start = time.Now()
	f.h.mailSyncOnce(context.Background())
	if d := time.Since(start); d >= time.Second {
		t.Fatalf("the next pass waited %v", d)
	}
	f.h.mailState.reconWG.Wait()
	f.h.mu.RLock()
	r := f.h.st.MailCredentials["alice"][0].Reason
	f.h.mu.RUnlock()
	if r != state.MailCredentialReasonVoidRestore {
		t.Fatalf("after the background reconcile: %q", r)
	}
}
