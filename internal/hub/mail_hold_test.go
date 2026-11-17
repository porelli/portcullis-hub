package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/state"
)

// changeMailTemplate edits a file of mailsrv's template directory.
func changeMailTemplate(t *testing.T, w *wireFix, name, content string) {
	t.Helper()
	writeFile(t, filepath.Join(w.src, mailProviderID, name), content)
}

// syncNow runs the post-sync rediscovery and hold check as a source sync
// does (the fixture's source is no git clone).
func syncNow(w *wireFix) {
	w.h.syncSources(SyncAPI, gitTimeout)
	w.h.Wait()
}

// TestTemplateChangeHoldsNoUp: a template change after the wiring holds
// the provider with no up; the hold is saved.
func TestTemplateChangeHoldsNoUp(t *testing.T) {
	w := wiredFix(t)
	ups := len(w.runner.callsMatching("up"))
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	if n := len(w.runner.callsMatching("up")); n != ups {
		t.Fatalf("%d ups after the sync", n-ups)
	}
	st, err := state.Load(w.h.statePath())
	if err != nil || st.Mail.Held == nil || st.Mail.Held.Reason != MailHoldText {
		t.Fatalf("held %+v %v", st.Mail.Held, err)
	}
	if w.h.mailClient() != nil {
		t.Fatal("mail routes still served while held")
	}
}

// TestHeldUpRendersVoidOnly: an up while held (a restart) renders void
// mode and runs no void.
func TestHeldUpRendersVoidOnly(t *testing.T) {
	w := wiredFix(t)
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	voids := len(w.mc.Voids)
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	if err := w.h.RestartApp(mailProviderID); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.ups) == 0 || strings.Contains(w.ups[len(w.ups)-1].override, "0.0.0.0:25:") || !strings.Contains(w.ups[len(w.ups)-1].override, "internal: true") {
		t.Fatalf("held up isn't void mode")
	}
	if len(w.mc.Voids) != voids {
		t.Fatal("a void ran while held")
	}
}

// TestUnrelatedTemplateSyncNoHold: a change to another template holds
// nothing.
func TestUnrelatedTemplateSyncNoHold(t *testing.T) {
	w := wiredFix(t)
	writeFile(t, filepath.Join(w.src, "grafana", "conf", "grafana.ini"), "[changed]\n")
	syncNow(w)
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Held != nil {
		t.Fatalf("held %+v", w.h.st.Mail.Held)
	}
}

// TestRewireClearsHoldAndKeepsPasswords (isRewire): the guarded
// re-confirm of the held instance records the new hash, clears the hold
// and starts it normally — without a void: alice's password survives.
// A first wiring (and a switch) void.
func TestRewireClearsHoldAndKeepsPasswords(t *testing.T) {
	w := wiredFix(t)
	if n := len(w.mc.Voids); n != 1 {
		t.Fatalf("the first wiring voided %d times", n)
	}
	w.h.mu.RLock()
	oldHash := w.h.st.Mail.Provider.BlockHash
	w.h.mu.RUnlock()
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	v, _ := w.h.InstanceMailProvider(context.Background(), mailProviderID)
	if v.Held == nil || v.HoldWarning != MailHoldWarning || v.Mode != "void" {
		t.Fatalf("view %+v", v)
	}
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatal(err)
	}
	if lo := w.h.LastOp(mailProviderID); lo == nil || !lo.OK || lo.Op != OpMailRewire {
		t.Fatalf("op %+v", lo)
	}
	w.h.mu.RLock()
	p, held := w.h.st.Mail.Provider, w.h.st.Mail.Held
	rows := w.h.st.MailCredentials["alice"]
	w.h.mu.RUnlock()
	if held != nil || p.BlockHash == oldHash || len(p.BlockHash) != 64 {
		t.Fatalf("held %+v hash %s", held, p.BlockHash)
	}
	if len(w.mc.Voids) != 1 || len(w.mc.Creds("alice")) != 1 || !rows[0].Active() {
		t.Fatalf("the re-confirm voided: voids %v creds %d rows %+v", w.mc.Voids, len(w.mc.Creds("alice")), rows)
	}
	if w.h.mailClient() == nil {
		t.Fatal("not serving after the re-confirm")
	}
	if e := w.audit.last(); e.Action != "mail.provider_wired" || !strings.Contains(e.Detail, "reconfirm=true") {
		t.Fatalf("audit %+v", e)
	}
	// Not held any more: a second confirm is refused.
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); statusOf(err) != 409 {
		t.Fatalf("second confirm: %v", err)
	}
}

// TestRewireNeedsAllGuards: the re-confirm is refused from AI, for a
// delegate, without a fresh proof and with a wrong typed id.
func TestRewireNeedsAllGuards(t *testing.T) {
	w := wiredFix(t)
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	for _, c := range []struct {
		in    WireRequest
		actor directory.Actor
		want  int
	}{
		{WireRequest{Confirm: mailProviderID, Proof: &wireProof}, directory.Actor{User: "root", Via: directory.ViaAI, Client: "x"}, 403},
		{WireRequest{Confirm: mailProviderID, Proof: &wireProof}, directory.Human("alice"), 403},
		{WireRequest{Confirm: mailProviderID}, rootActor(), 403},
		{WireRequest{Confirm: "x", Proof: &freshauth.Proof{Code: "c", CodeVerifier: "v", Nonce: "n"}}, rootActor(), 400},
	} {
		if _, err := w.wire(t, c.in, c.actor); statusOf(err) != c.want {
			t.Errorf("%+v %v: %v", c.in, c.actor, err)
		}
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Held == nil {
		t.Fatal("a refused re-confirm cleared the hold")
	}
}

// TestTemplateChangeDuringWireHolds: a change between the wiring's
// record and its normal step holds it: no normal override for a tree
// that no longer matches.
func TestTemplateChangeDuringWireHolds(t *testing.T) {
	w := newWireFix(t)
	changed := false
	w.runner.upHook = func(project string) {
		if project == "portcullis-"+mailProviderID && !changed {
			changed = true
			// The first (void-mode) up: the template changes meanwhile.
			os.WriteFile(filepath.Join(w.src, mailProviderID, "gate.sh"), []byte("#!/bin/sh\necho changed\n"), 0o644)
		}
	}
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatal(err)
	}
	if lo := w.h.LastOp(mailProviderID); lo == nil || lo.OK || !strings.Contains(lo.Error, "template changed") {
		t.Fatalf("op %+v", lo)
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Held == nil || w.h.mailModeLocked(mailProviderID) != mailVoid {
		t.Fatalf("not held: %+v", w.h.st.Mail.Held)
	}
	b, _ := os.ReadFile(w.h.overridePath(mailProviderID))
	if strings.Contains(string(b), "0.0.0.0:25:") {
		t.Fatal("the normal override was rendered")
	}
}

// TestTemplateNowInvalidHolds: a template that no longer validates holds
// with its own reason.
func TestTemplateNowInvalidHolds(t *testing.T) {
	w := wiredFix(t)
	m, _ := os.ReadFile(filepath.Join(w.src, mailProviderID, "manifest.yaml"))
	changeMailTemplate(t, w, "manifest.yaml", strings.Replace(string(m), "api_version: 1", "api_version: 2", 1))
	syncNow(w)
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if h := w.h.st.Mail.Held; h == nil || h.Reason != MailInvalidText {
		t.Fatalf("held %+v", h)
	}
}
