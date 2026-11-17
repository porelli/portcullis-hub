package hub

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

// wiredFix is a wireFix with mailsrv wired through the op and alice
// holding a mail password.
func wiredFix(t *testing.T) *wireFix {
	t.Helper()
	w := newWireFix(t)
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatal(err)
	}
	if lo := w.h.LastOp(mailProviderID); lo == nil || !lo.OK {
		t.Fatalf("wiring %+v", lo)
	}
	w.create(t, "alice", "iPhone")
	return w
}

func (w *wireFix) unwire(t *testing.T, drain bool, actor directory.Actor) error {
	t.Helper()
	_, err := w.h.StartUnwireMail(mailProviderID, drain, actor)
	w.h.Wait()
	return err
}

// TestUnwireOrder: rows voided (provider_changed) → the provider's void
// (best effort) → the secret and .present deleted → the unwired override
// → stopped (disabled, data kept); the record cleared; audited.
func TestUnwireOrder(t *testing.T) {
	w := wiredFix(t)
	voids := len(w.mc.Voids)
	if err := w.unwire(t, false, rootActor()); err != nil {
		t.Fatal(err)
	}
	if len(w.mc.Voids) != voids+1 {
		t.Fatal("no best-effort void")
	}
	if gateFile(t, w.fixture, mailGateAPISecret) != "" || gateFile(t, w.fixture, mailGatePresent) != "" {
		t.Fatal("the gate is still open")
	}
	w.h.mu.RLock()
	p := w.h.st.Mail.Provider
	rows := w.h.st.MailCredentials["alice"]
	enabled := w.h.st.IsEnabled(mailProviderID)
	w.h.mu.RUnlock()
	if p != nil || enabled {
		t.Fatalf("provider %+v enabled %v", p, enabled)
	}
	if len(rows) != 1 || rows[0].Active() || rows[0].Reason != state.MailCredentialReasonProviderChanged {
		t.Fatalf("rows %+v", rows)
	}
	calls := w.runner.Calls()
	if calls[len(calls)-1] != "down:portcullis-"+mailProviderID {
		t.Fatalf("not stopped: %v", calls)
	}
	if ov := renderMail(t, w.fixture, mailUnwired); strings.Contains(ov, "0.0.0.0:25") {
		t.Fatal("unwired override publishes")
	}
	var actions []string
	for _, e := range w.audit.entries {
		actions = append(actions, e.Action)
	}
	if !strings.Contains(strings.Join(actions, ","), "mail_credential.void_provider,mail.provider_unwired") {
		t.Fatalf("audit %v", actions)
	}
	v := w.h.MailPasswords("alice", uuidAlice)
	if len(v) != 1 || v[0].Status != "voided" || !strings.Contains(v[0].VoidedReason, "the mail server changed on ") {
		t.Fatalf("view %+v", v)
	}
}

// TestUnwireForceRemovesNow: drain false deletes every added domain's
// mail set at once.
func TestUnwireForceRemovesNow(t *testing.T) {
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Domains["team-b.example.net"] = state.MailDomain{Enabled: true}
	w.h.mu.Unlock()
	if err := w.unwire(t, false, rootActor()); err != nil {
		t.Fatal(err)
	}
	w.dom.mu.Lock()
	calls := strings.Join(w.dom.mailCalls, ",")
	w.dom.mu.Unlock()
	if !strings.Contains(calls, "delete team-b.example.net") {
		t.Fatalf("set not removed: %v", calls)
	}
}

// TestUnwireDrainThenRemoveSets: drain true makes every domain draining
// and keeps the provider wired until every domain is off; then the
// unwire finishes on its own.
func TestUnwireDrainThenRemoveSets(t *testing.T) {
	w := wiredFix(t)
	if err := w.unwire(t, true, rootActor()); err != nil {
		t.Fatal(err)
	}
	w.h.mu.RLock()
	p, u := w.h.st.Mail.Provider, w.h.st.Mail.Unwiring
	main := w.h.mailDomainStateLocked("example.org", true)
	w.h.mu.RUnlock()
	if p == nil || u == nil || main != mailprovider.MailDraining {
		t.Fatalf("provider %+v unwiring %+v main %s", p, u, main)
	}
	// The provider reports the drain finished: the sync turns it off and
	// the unwire completes.
	w.mc.Lock(func(s *mailprovidertest.Server) {
		s.StatusV.MTASTS = []mailprovider.StatusMTASTS{{Domain: "example.org", Mode: "off"}}
	})
	w.h.mu.Lock()
	e := w.h.st.Mail.Domains["example.org"]
	e.Draining = false
	w.h.st.Mail.Domains["example.org"] = e
	w.h.mu.Unlock()
	w.h.mailFinishUnwireIfDrained()
	w.h.Wait()
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Provider != nil || w.h.st.Mail.Unwiring != nil {
		t.Fatalf("not finished: %+v %+v", w.h.st.Mail.Provider, w.h.st.Mail.Unwiring)
	}
}

// TestUnwireWithProviderDownClosesGate: a provider that's down or hangs
// never keeps the gate open or the instance running.
func TestUnwireWithProviderDownClosesGate(t *testing.T) {
	w := wiredFix(t)
	w.mc.Lock(func(s *mailprovidertest.Server) { s.Down = true })
	start := time.Now()
	if err := w.unwire(t, false, rootActor()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 40*time.Second {
		t.Fatal("waited on the provider")
	}
	if gateFile(t, w.fixture, mailGateAPISecret) != "" || gateFile(t, w.fixture, mailGatePresent) != "" {
		t.Fatal("gate open")
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Provider != nil || w.h.st.IsEnabled(mailProviderID) {
		t.Fatal("still wired or enabled")
	}
}

// TestUnwireRefusedFromAI: an AI actor and a delegate are refused.
func TestUnwireRefusedFromAI(t *testing.T) {
	w := wiredFix(t)
	if err := w.unwire(t, false, directory.Actor{User: "root", Via: directory.ViaAI, Client: "x"}); statusOf(err) != 403 {
		t.Fatalf("ai: %v", err)
	}
	if err := w.unwire(t, false, directory.Human("alice")); statusOf(err) != 403 {
		t.Fatalf("delegate: %v", err)
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Provider == nil {
		t.Fatal("unwired")
	}
}

// TestDeleteRefusedWhileWired: the guarded delete of the wired instance
// is 409 "unwire it first (Settings → Mail)".
func TestDeleteRefusedWhileWired(t *testing.T) {
	w := wiredFix(t)
	_, err := w.h.DeleteInstance(mailProviderID, mailProviderID, rootActor())
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "unwire it first (Settings → Mail)") {
		t.Fatalf("%v", err)
	}
}

// switchFix adds a second mail instance (othermail, the same template)
// to a wired fixture.
func switchFix(t *testing.T) *wireFix {
	t.Helper()
	w := newWireFix(t, otherMailID)
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatal(err)
	}
	w.create(t, "alice", "iPhone")
	return w
}

func (w *wireFix) switchTo(t *testing.T, to string, in SwitchRequest, actor directory.Actor) error {
	t.Helper()
	_, err := w.h.StartSwitchMail(context.Background(), to, in, actor)
	w.h.Wait()
	return err
}

// TestSwitchConfirmEmptyPhrase: the phrase names the mailboxes of
// mail-last.json exactly.
func TestSwitchConfirmEmptyPhrase(t *testing.T) {
	w := switchFix(t)
	in := SwitchRequest{Confirm: otherMailID, ConfirmEmpty: "2 mailboxes start empty", Proof: &wireProof}
	err := w.switchTo(t, otherMailID, in, rootActor())
	if statusOf(err) != 400 || !strings.Contains(err.Error(), `"3 mailboxes start empty"`) {
		t.Fatalf("%v", err)
	}
	in.ConfirmEmpty = "3 mailboxes start empty"
	if err := w.switchTo(t, otherMailID, in, rootActor()); err != nil {
		t.Fatal(err)
	}
	if lo := w.h.LastOp(otherMailID); lo == nil || !lo.OK {
		t.Fatalf("switch %+v", lo)
	}
}

func doSwitch(t *testing.T, w *wireFix) {
	t.Helper()
	in := SwitchRequest{Confirm: otherMailID, ConfirmEmpty: "3 mailboxes start empty", Proof: &wireProof}
	if err := w.switchTo(t, otherMailID, in, rootActor()); err != nil {
		t.Fatal(err)
	}
	if lo := w.h.LastOp(otherMailID); lo == nil || !lo.OK {
		t.Fatalf("switch %+v", lo)
	}
}

// TestSwitchVoidsRowsProviderChanged and TestSwitchMovesPorts: the old
// rows end provider_changed, the old provider is stopped (never both on
// the ports), the new one wired in normal mode; audited.
func TestSwitchVoidsRowsProviderChanged(t *testing.T) {
	w := switchFix(t)
	doSwitch(t, w)
	w.h.mu.RLock()
	rows := w.h.st.MailCredentials["alice"]
	p := w.h.st.Mail.Provider
	oldOn, newOn := w.h.st.IsEnabled(mailProviderID), w.h.st.IsEnabled(otherMailID)
	w.h.mu.RUnlock()
	if rows[0].Reason != state.MailCredentialReasonProviderChanged || p == nil || p.Instance != otherMailID || oldOn || !newOn {
		t.Fatalf("rows %+v provider %+v old %v new %v", rows, p, oldOn, newOn)
	}
	if e := w.audit.last(); e.Action != "mail.provider_switched" || !strings.Contains(e.Detail, "from=mailsrv to=othermail") {
		t.Fatalf("audit %+v", e)
	}
}

func TestSwitchMovesPorts(t *testing.T) {
	w := switchFix(t)
	doSwitch(t, w)
	// The old provider's last action is its down, before the new one's
	// first normal up.
	calls := w.runner.Calls()
	lastOldDown, firstNewUp := -1, -1
	for i, c := range calls {
		if c == "down:portcullis-"+mailProviderID {
			lastOldDown = i
		}
		if c == "up:portcullis-"+otherMailID && firstNewUp < 0 {
			firstNewUp = i
		}
	}
	if lastOldDown < 0 || firstNewUp < 0 || lastOldDown > firstNewUp {
		t.Fatalf("calls %v", calls)
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.mailModeLocked(mailProviderID) != mailUnwired || w.h.mailModeLocked(otherMailID) != mailNormal {
		t.Fatal("modes")
	}
}

// TestSwitchKeepsOldDKIM7Days: the old provider's DKIM records are kept
// 7 days in each domain's set, then dropped once the new set is written.
func TestSwitchKeepsOldDKIM7Days(t *testing.T) {
	w := switchFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Domains["team-b.example.net"] = state.MailDomain{Enabled: true}
	w.h.mu.Unlock()
	w.mc.Lock(func(s *mailprovidertest.Server) {
		s.DNSSets["team-b.example.net"] = mailprovider.DNSSet{Domain: "team-b.example.net", DKIM: "auto", Records: []mailprovider.Record{
			{Name: "team-b.example.net", Type: "MX", TTL: 3600, Value: "10 mail.example.org."},
			{Name: "old1._domainkey.team-b.example.net", Type: "TXT", TTL: 3600, Value: "v=DKIM1; k=ed25519; p=OLD"}}}
	})
	w.sync(t)
	doSwitch(t, w)
	w.h.mu.RLock()
	r := w.h.st.Mail.RetiringDKIM["team-b.example.net"]
	w.h.mu.RUnlock()
	if len(r.Records) != 1 || r.Records[0].Name != "old1._domainkey.team-b.example.net" || r.Until.Sub(w.now) < 7*24*time.Hour-time.Minute {
		t.Fatalf("retiring %+v", r)
	}
	// The new set carries the retiring record until Until.
	w.mc.Lock(func(s *mailprovidertest.Server) {
		s.DNSSets["team-b.example.net"] = mailprovider.DNSSet{Domain: "team-b.example.net", DKIM: "auto", Records: []mailprovider.Record{
			{Name: "team-b.example.net", Type: "MX", TTL: 3600, Value: "10 mail.example.org."}}}
	})
	if err := w.h.writeMailSet(context.Background(), w.mc.Client(), w.dom, "team-b.example.net"); err != nil {
		t.Fatal(err)
	}
	if !setHas(w, "team-b.example.net", "old1._domainkey.team-b.example.net") {
		t.Fatal("the old DKIM record isn't kept")
	}
	w.advance(7*24*time.Hour + time.Minute)
	if err := w.h.writeMailSet(context.Background(), w.mc.Client(), w.dom, "team-b.example.net"); err != nil {
		t.Fatal(err)
	}
	if setHas(w, "team-b.example.net", "old1._domainkey.team-b.example.net") {
		t.Fatal("the old DKIM record outlived 7 days")
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if _, ok := w.h.st.Mail.RetiringDKIM["team-b.example.net"]; ok {
		t.Fatal("retention not cleared")
	}
}

// TestSwitchPartialDNSKeepsRetention: a domain whose new set fails to be
// written keeps its retiring records past Until (cleared only after its
// own write).
func TestSwitchPartialDNSKeepsRetention(t *testing.T) {
	w := switchFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.RetiringDKIM = map[string]state.RetiringDKIM{"team-b.example.net": {
		Records: []state.MailRecord{{Name: "old1._domainkey.team-b.example.net", Type: "TXT", TTL: 3600, Value: "v=DKIM1; p=OLD"}},
		Until:   w.now.Add(-time.Hour)}}
	w.h.st.Mail.Domains["team-b.example.net"] = state.MailDomain{Enabled: true}
	w.h.mu.Unlock()
	w.dom.mu.Lock()
	w.dom.mailSetErr = errors.New("boom")
	w.dom.mu.Unlock()
	err := w.h.writeMailSet(context.Background(), w.mc.Client(), w.dom, "team-b.example.net")
	if err == nil {
		t.Fatal("write didn't fail")
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if _, ok := w.h.st.Mail.RetiringDKIM["team-b.example.net"]; !ok {
		t.Fatal("retention cleared before the domain's own write")
	}
}

// TestSwitchResumesAfterRestart: a switch interrupted after the unwire
// (the old provider closed, the new not recorded) resumes the wiring of
// the new one; never both on the ports.
func TestSwitchResumesAfterRestart(t *testing.T) {
	w := switchFix(t)
	unlock, _ := w.h.lockApp(mailProviderID)
	w.h.mu.Lock()
	w.h.st.Mail.Switch = &state.MailSwitch{From: mailProviderID, To: otherMailID, By: "root"}
	w.h.mu.Unlock()
	if err := w.h.closeMailProvider(context.Background(), mailProviderID, rootActor()); err != nil {
		t.Fatal(err)
	}
	unlock()
	w.h.resumeMail()
	w.h.Wait()
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if p := w.h.st.Mail.Provider; p == nil || p.Instance != otherMailID || w.h.st.Mail.Switch != nil || w.h.st.IsEnabled(mailProviderID) {
		t.Fatalf("provider %+v switch %+v", p, w.h.st.Mail.Switch)
	}
}

// setHas: the domains service's stored mail set of d has a record name.
func setHas(w *wireFix, d, name string) bool {
	w.dom.mu.Lock()
	defer w.dom.mu.Unlock()
	for _, r := range w.dom.mailSets[d] {
		if r.Name == name {
			return true
		}
	}
	return false
}
