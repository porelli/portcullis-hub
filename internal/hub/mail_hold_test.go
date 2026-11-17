package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
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
	// R-HH1: the running, confirmed provider keeps taking revocations.
	if _, ok := w.h.mailClient().(*heldMailAPI); !ok {
		t.Fatal("no held client: revocations would pause while held")
	}
}

// TestHeldUpRefused (R-HH3): an up while held (a restart) is refused in
// the start primitive: nothing of the changed tree starts, no void runs.
func TestHeldUpRefused(t *testing.T) {
	w := wiredFix(t)
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	voids := len(w.mc.Voids)
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	if err := w.h.RestartApp(mailProviderID); statusOf(err) != 409 {
		t.Fatalf("a held restart: %v", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.ups) != 0 {
		t.Fatalf("%d ups while held", len(w.ups))
	}
	if len(w.mc.Voids) != voids {
		t.Fatal("a void ran while held")
	}
}

// TestUpBeforeHoldRecordedRefused (H3): the tree changed on disk but no
// sync recorded the hold yet (a pull mid-sync, a boot restart): the up
// is refused and the hold recorded.
func TestUpBeforeHoldRecordedRefused(t *testing.T) {
	w := wiredFix(t)
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	if err := w.h.composeUp(context.Background(), w.h.Template(mailProviderID)); statusOf(err) != 409 {
		t.Fatalf("an up of the unreviewed tree: %v", err)
	}
	w.mu.Lock()
	n := len(w.ups)
	w.mu.Unlock()
	w.h.mu.RLock()
	held := w.h.st.Mail.Held
	w.h.mu.RUnlock()
	if n != 0 || held == nil {
		t.Fatalf("ups %d held %+v", n, held)
	}
}

// TestHeldKeepsRevoking (R-HH1): while held, a revoke and a removal
// reach the running provider; one it can't take stops the provider.
func TestHeldKeepsRevoking(t *testing.T) {
	w := wiredFix(t)
	c := w.create(t, "alice", "phone").ID
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	if err := w.h.RevokeOwnMailPassword(context.Background(), "alice", c); err != nil {
		t.Fatal(err)
	}
	if len(w.mc.Creds("alice")) != 0 {
		t.Fatal("the revoke didn't reach the held provider")
	}
	c2 := w.create(t, "alice", "laptop").ID
	w.mc.Lock(func(s *mailprovidertest.Server) { s.RevokeStatus = 500 })
	downs := len(w.runner.callsMatching("downbyname"))
	if err := w.h.RevokeOwnMailPassword(context.Background(), "alice", c2); err == nil {
		t.Fatal("a failed revoke answered ok")
	}
	w.h.mu.RLock()
	held := w.h.st.Mail.Held
	w.h.mu.RUnlock()
	if held == nil || held.Stopped == nil || len(w.runner.callsMatching("downbyname")) == downs {
		t.Fatalf("the held provider wasn't stopped: %+v", held)
	}
	if w.h.mailClient() != nil {
		t.Fatal("a stopped provider still served")
	}
	v, _ := w.h.InstanceMailProvider(context.Background(), mailProviderID)
	if v.Mode != "stopped" {
		t.Fatalf("mode %q", v.Mode)
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
	if v.Held == nil || v.HoldWarning != MailHoldWarning || v.Mode != "normal" {
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
