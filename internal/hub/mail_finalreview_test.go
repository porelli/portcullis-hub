package hub

import (
	"context"
	"errors"
	"github.com/portcullis/hub/internal/directory"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/state"
)

// After one failed `hub mail restore`, the fixed retry must succeed.
func TestFinalReviewRestoreRetryAfterFailure(t *testing.T) {
	w, archive, pending := restoreFix(t)
	fail := true
	w.h.testHookApplyRestore = func(stage string) error {
		if stage == "volumes" && fail {
			fail = false
			return errors.New("a volume failed")
		}
		return nil
	}
	op, err := w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	v := w.h.HostMailOp(op.Instance, op.OpID)
	t.Logf("first op: %+v", v)
	w.h.mu.RLock()
	st := w.h.st.Instances[mailProviderID].State
	w.h.mu.RUnlock()
	t.Logf("instance state after failure: %q (restoring=%v)", st, st == state.InstanceRestoring)
	fail = false
	op, err = w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatalf("retry refused: %v", err)
	}
	w.h.Wait()
	v = w.h.HostMailOp(op.Instance, op.OpID)
	if v == nil || !v.OK {
		t.Fatalf("retry op failed: %+v", v)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Fatal("hold stayed")
	}
}

// A switch whose close fails to stop the old provider: is the stop ever
// retried (as M4 does for an unwire)?
func TestFinalReviewSwitchFailedStopRetried(t *testing.T) {
	w := switchFix(t)
	w.runner.downErr, w.runner.byNameErr = errors.New("engine down"), errors.New("engine down")
	in := SwitchRequest{Confirm: otherMailID, ConfirmEmpty: "3 mailboxes start empty", Proof: &wireProof}
	_ = w.switchTo(t, otherMailID, in, rootActor())
	w.h.mu.RLock()
	t.Logf("after failed switch: provider=%+v switch=%+v unwiring=%+v enabled(old)=%v", w.h.st.Mail.Provider, w.h.st.Mail.Switch, w.h.st.Mail.Unwiring, w.h.st.IsEnabled(mailProviderID))
	w.h.mu.RUnlock()
	w.runner.downErr, w.runner.byNameErr = nil, nil
	before := len(w.runner.Calls())
	w.h.mailVoidRetryOnce(context.Background())
	w.h.resumeMail()
	w.h.Wait()
	calls := w.runner.Calls()[before:]
	downs := 0
	for _, c := range calls {
		if c == "down:portcullis-"+mailProviderID || c == "downbyname:portcullis-"+mailProviderID {
			downs++
		}
	}
	t.Logf("calls after retry/resume: %v", calls)
	if downs == 0 {
		t.Fatal("the old provider's failed stop is never retried")
	}
}

// A Stop accepted during the void step: is the wiring undone (as a Stop
// before the normal step should be), or does it stay wired and resume?
func TestFinalReviewWireStopDuringVoid(t *testing.T) {
	w := newWireFix(t)
	ctx, cancel := context.WithCancel(context.Background())
	t0 := w.h.Template(mailProviderID)
	unlock, err := w.h.lockApp(mailProviderID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	w.runner.upHook = func(project string) {
		n++
		if n == 2 { // runVoid's own up: the Stop lands during the void step
			cancel()
		}
	}
	_, err = w.h.runWireMail(ctx, t0, rootActor(), state.MailVoidWire)
	unlock()
	w.runner.upHook = nil
	t.Logf("runWireMail: %v", err)
	w.h.mu.RLock()
	p, owed := w.h.st.Mail.Provider, w.h.st.Mail.VoidOwed
	w.h.mu.RUnlock()
	t.Logf("after Stop: provider=%+v owed=%+v", p, owed)
	// L3: the undo removes every gate file and mail_slot's metrics secret.
	if gateFile(t, w.fixture, mailGateMetricsSecret) != "" || gateFile(t, w.fixture, mailGateRelayPassword) != "" {
		t.Fatal("secrets left in the gate after the undo")
	}
	if _, err := os.Stat(filepath.Join(w.h.cfg.MailSlotDir, mailGateMetricsSecret)); !os.IsNotExist(err) {
		t.Fatal("mail_slot's metrics secret left after the undo")
	}
	if p != nil {
		// does the retry loop finish the stopped wiring?
		w.h.mailVoidRetryOnce(context.Background())
		w.h.Wait()
		w.h.mu.RLock()
		p, owed = w.h.st.Mail.Provider, w.h.st.Mail.VoidOwed
		mode := w.h.mailModeLocked(mailProviderID)
		w.h.mu.RUnlock()
		t.Fatalf("a Stopped wiring stays wired; after one retry pass: provider=%v owed=%+v mode=%v", p != nil, owed, mode)
	}
}

// A core restore onto a newer template checkout: the provider is held at
// start and a core restore is pending. Can the operator ever get it back?
func TestFinalReviewHeldPlusRestorePending(t *testing.T) {
	w, archive, pending := restoreFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.Held = &state.MailHold{Reason: MailHoldText}
	w.h.mu.Unlock()
	op, err := w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatalf("restore refused: %v", err)
	}
	w.h.Wait()
	v := w.h.HostMailOp(op.Instance, op.OpID)
	t.Logf("restore while held: %+v", v)
	w.h.mu.RLock()
	st := w.h.st.Instances[mailProviderID].State
	w.h.mu.RUnlock()
	t.Logf("instance state: %q", st)
	// the operator re-confirms on the host path
	rop, err := w.h.StartWireMail(context.Background(), mailProviderID, WireRequest{Confirm: mailProviderID, Host: true}, directory.Human(HostActor))
	t.Logf("re-confirm: %v", err)
	w.h.Wait()
	if rop != nil {
		t.Logf("re-confirm op: %+v", w.h.LastOp(mailProviderID))
	}
	op, err = w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatalf("second restore refused: %v", err)
	}
	w.h.Wait()
	v = w.h.HostMailOp(op.Instance, op.OpID)
	if v == nil || !v.OK {
		t.Fatalf("second restore failed: %+v", v)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Fatal("hold stayed")
	}
}

// An unwire whose stop failed leaves mail.unwiring.closing; a new wiring
// of the same instance meanwhile: does the stale close unwire it?
func TestFinalReviewStaleClosingUnwiresNewWiring(t *testing.T) {
	w := wiredFix(t)
	w.runner.downErr, w.runner.byNameErr = errors.New("engine down"), errors.New("engine down")
	_ = w.unwire(t, false, rootActor())
	w.runner.downErr, w.runner.byNameErr = nil, nil
	w.h.mu.RLock()
	t.Logf("after failed unwire: provider=%v unwiring=%+v", w.h.st.Mail.Provider != nil, w.h.st.Mail.Unwiring)
	w.h.mu.RUnlock()
	// RR2-M1: no wiring while the stop is owed; the retry downs it,
	// then the wiring goes.
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); statusOf(err) != 409 {
		t.Fatalf("re-wire while the stop is owed: %v", err)
	}
	w.h.mailVoidRetryOnce(context.Background())
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatalf("re-wire: %v", err)
	}
	w.h.mu.RLock()
	t.Logf("after re-wire: provider=%v unwiring=%+v lastop=%+v", w.h.st.Mail.Provider != nil, w.h.st.Mail.Unwiring, w.h.LastOp(mailProviderID).OK)
	w.h.mu.RUnlock()
	w.h.mailVoidRetryOnce(context.Background())
	w.h.Wait()
	w.h.mu.RLock()
	p := w.h.st.Mail.Provider
	en := w.h.st.IsEnabled(mailProviderID)
	w.h.mu.RUnlock()
	if p == nil || !en {
		t.Fatalf("the stale close unwired the new wiring: provider=%v enabled=%v", p != nil, en)
	}
}

// A draining unwire of mailsrv is pending; the admin switches to
// othermail instead. When the domains are off, does the stale unwire
// void the NEW provider?
func TestFinalReviewStaleDrainUnwireAfterSwitch(t *testing.T) {
	w := switchFix(t)
	if err := w.unwire(t, true, rootActor()); err != nil {
		t.Fatal(err)
	}
	doSwitch(t, w)
	w.create(t, "alice", "new phone")
	voids := len(w.mc.Voids)
	w.h.mu.Lock()
	for d, e := range w.h.st.Mail.Domains {
		e.Draining = false
		w.h.st.Mail.Domains[d] = e
	}
	t.Logf("before: provider=%s unwiring=%+v", w.h.st.Mail.Provider.Instance, w.h.st.Mail.Unwiring)
	w.h.mu.Unlock()
	w.h.mailFinishUnwireIfDrained()
	w.h.Wait()
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	active := 0
	for _, r := range w.h.st.MailCredentials["alice"] {
		if r.Active() {
			active++
		}
	}
	t.Logf("after: provider=%v active rows=%d provider voids %d -> %d", w.h.st.Mail.Provider, active, voids, len(w.mc.Voids))
	if active == 0 || len(w.mc.Voids) != voids {
		t.Fatal("the stale drained unwire of the old provider voided the new provider's passwords")
	}
}

// Unwire of mailsrv with a failed stop, then othermail wired: the stale
// close of mailsrv must not touch othermail.
func TestFinalReviewStaleClosingVoidsOtherProvider(t *testing.T) {
	w := switchFix(t)
	w.runner.downErr, w.runner.byNameErr = errors.New("engine down"), errors.New("engine down")
	_ = w.unwire(t, false, rootActor())
	w.runner.downErr, w.runner.byNameErr = nil, nil
	if _, err := w.h.StartWireMail(context.Background(), otherMailID, WireRequest{Confirm: otherMailID, Proof: &wireProof}, rootActor()); statusOf(err) != 409 {
		t.Fatalf("wire othermail while the stop is owed: %v", err)
	}
	w.h.mailVoidRetryOnce(context.Background())
	if _, err := w.h.StartWireMail(context.Background(), otherMailID, WireRequest{Confirm: otherMailID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatalf("wire othermail: %v", err)
	}
	w.h.Wait()
	t.Logf("wire op: %+v", w.h.LastOp(otherMailID).OK)
	w.create(t, "alice", "new phone")
	voids := len(w.mc.Voids)
	w.h.mailVoidRetryOnce(context.Background())
	w.h.Wait()
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	active := 0
	for _, r := range w.h.st.MailCredentials["alice"] {
		if r.Active() {
			active++
		}
	}
	t.Logf("provider=%v active=%d voids %d -> %d", w.h.st.Mail.Provider != nil, active, voids, len(w.mc.Voids))
	if active == 0 || len(w.mc.Voids) != voids {
		t.Fatal("the stale close of mailsrv voided othermail's passwords")
	}
}

// An unwire whose stop failed, then the slot closed (mail disable): is
// the owed stop retried by the retry loop?
func TestFinalReviewClosingNotRetriedWithSlotClosed(t *testing.T) {
	w := wiredFix(t)
	w.runner.downErr, w.runner.byNameErr = errors.New("engine down"), errors.New("engine down")
	_ = w.unwire(t, false, rootActor())
	w.runner.downErr, w.runner.byNameErr = nil, nil
	w.h.SetMailCoreForTest(false, "")
	w.h.mailVoidRetryOnce(context.Background())
	w.h.Wait()
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if u := w.h.st.Mail.Unwiring; u != nil && u.Closing {
		t.Fatalf("the owed stop isn't retried while the slot is closed: %+v", u)
	}
}

// The tree changes on disk after the start primitive's hold gate but
// before compose create/up reads compose.yml from the checkout.
func TestFinalReviewHoldGateTOCTOU(t *testing.T) {
	w := wiredFix(t)
	w.runner.createHook = func(project string) {
		if project == "portcullis-"+mailProviderID {
			changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
			w.runner.createHook = nil
		}
	}
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	downs := len(w.runner.callsMatching("down"))
	unlock, _ := w.h.lockApp(mailProviderID)
	err := w.h.composeUp(context.Background(), w.h.Template(mailProviderID))
	unlock()
	w.mu.Lock()
	n := len(w.ups)
	w.mu.Unlock()
	w.h.mu.RLock()
	held := w.h.st.Mail.Held
	w.h.mu.RUnlock()
	t.Logf("up err=%v ups=%d held=%v", err, n, held != nil)
	if err == nil && n > 0 {
		t.Fatal("the changed (unreviewed) tree was brought up: the gate isn't re-checked after the create/up")
	}
	if held == nil || len(w.runner.callsMatching("down")) == downs {
		t.Fatal("the changed tree wasn't held and stopped after its up")
	}
}

// Blind confirm bound to a stale set: the provider named {admin, alice,
// bob}; an admin confirmed exactly that; root then also leaves; the next
// document removes 4 and carries confirm_mass_removal.
func TestFinalReviewBlindConfirmStaleSet(t *testing.T) {
	f := newMailFixture(t)
	f.sync(t)
	t.Logf("first doc accounts=%d", len(f.mc.Last().Accounts))
	os.Remove(f.h.mailLastPath())
	f.h.mailState.mu.Lock()
	f.h.mailState.last = nil
	f.h.mailState.mu.Unlock()
	f.people.setMembers("mail_users", "root")
	puts := f.mc.Puts()
	f.sync(t)
	f.h.mu.RLock()
	p := f.h.st.Mail.PendingRemoval
	f.h.mu.RUnlock()
	if p == nil {
		t.Fatalf("no pending; puts=%d", f.mc.Puts()-puts)
	}
	var ids []string
	for _, a := range p.Accounts {
		ids = append(ids, a.UUID)
		t.Logf("pending %s", a.Username)
	}
	if err := f.h.ConfirmMailRemoval(context.Background(), ids, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	// root leaves too before the next pass.
	f.people.setMembers("mail_users")
	f.sync(t)
	d := f.mc.Last()
	t.Logf("puts=%d last confirm=%v accounts=%d", f.mc.Puts()-puts, d.ConfirmMassRemoval, len(d.Accounts))
	if d.ConfirmMassRemoval && len(d.Accounts) == 0 {
		t.Errorf("BUG: confirm_mass_removal sent for a superset of the confirmed accounts (root's mailbox removed unconfirmed)")
	}
}

// TestRRSideServiceJoinsCoreProxyStatic (re-review N-H1, Ruling RR2-H1):
// a side service listing portcullis-proxy (at Traefik's pinned address)
// and portcullis-mail-api only in its own networks is refused at load,
// and — written on disk after the load — at the render (the rendered
// project's attachments to core networks are only the Hub's).
func TestRRSideServiceJoinsCoreProxyStatic(t *testing.T) {
	fs := mailTemplateFiles(t)
	old := "      - ./templates/mailsrv/unbound.conf:/etc/unbound/unbound.conf:ro\n    networks: [internal, egress]\n"
	bad := "      - ./templates/mailsrv/unbound.conf:/etc/unbound/unbound.conf:ro\n    networks:\n      internal: {}\n      egress: {}\n      portcullis-proxy: {ipv4_address: 172.31.250.2}\n      portcullis-mail-api: {}\n"
	if !strings.Contains(fs["compose.yml"], old) {
		t.Fatal("no anchor")
	}
	badFS := mailTemplateFiles(t)
	badFS["compose.yml"] = strings.Replace(fs["compose.yml"], old, bad, 1)
	f := newFixtureExtra(t, map[string]map[string]string{mailProviderID: badFS}, func(root string, c *Config) {
		c.SecretsDir = filepath.Join(root, "secrets")
		os.Mkdir(c.SecretsDir, 0o700)
	})
	if f.h.Template(mailProviderID) != nil {
		t.Fatal("the template loaded")
	}
	// The render check, on a wired provider whose tree changed on disk.
	w := wiredFix(t)
	tp := w.h.Template(mailProviderID)
	b, _ := os.ReadFile(tp.ComposePath())
	writeFile(t, tp.ComposePath(), strings.Replace(string(b), old, bad, 1))
	err := w.h.checkSecretsMounts(context.Background(), w.h.Template(mailProviderID))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "core network") {
		t.Fatalf("render check: %v", err)
	}
}
