package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestHeldKeepsRevoking (R-HH1): while held, a revoke reaches the
// running provider; its session reset never restarts it in place, it
// stops it instead (R-HH3).
func TestHeldKeepsRevoking(t *testing.T) {
	w := wiredFix(t)
	c := w.create(t, "alice", "phone").ID
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	before := len(w.mc.Creds("alice"))
	if err := w.h.RevokeOwnMailPassword(context.Background(), "alice", c); err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	if len(w.mc.Creds("alice")) != before-1 {
		t.Fatal("the revoke didn't reach the held provider")
	}
	w.h.mu.RLock()
	held := w.h.st.Mail.Held
	w.h.mu.RUnlock()
	if held == nil || held.Stopped == nil {
		t.Fatalf("the session reset didn't stop the held provider: %+v", held)
	}
	v, _ := w.h.InstanceMailProvider(context.Background(), mailProviderID)
	if v.Mode != "stopped" || w.h.mailClient() != nil {
		t.Fatalf("mode %q", v.Mode)
	}
}

// TestHeldFailedRevokeStops (R-HH1, fault injection): a revoke the held
// provider can't take stops it at once.
func TestHeldFailedRevokeStops(t *testing.T) {
	w := wiredFix(t)
	c := w.create(t, "alice", "phone").ID
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	w.mc.Lock(func(s *mailprovidertest.Server) { s.RevokeStatus = 500 })
	downs := len(w.runner.callsMatching("downbyname"))
	if err := w.h.RevokeOwnMailPassword(context.Background(), "alice", c); err == nil {
		t.Fatal("a failed revoke answered ok")
	}
	w.h.mu.RLock()
	held := w.h.st.Mail.Held
	w.h.mu.RUnlock()
	if held == nil || held.Stopped == nil || len(w.runner.callsMatching("downbyname")) == downs {
		t.Fatalf("the held provider wasn't stopped: %+v", held)
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
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof, BlockHash: v.BlockHash}, rootActor()); err != nil {
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

// TestRewireBoundToReviewedTree (M1): the re-confirm echoes the Mail
// tab's block_hash; a second change since the review (or no hash) is
// refused and the hold stays.
func TestRewireBoundToReviewedTree(t *testing.T) {
	w := wiredFix(t)
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	v, _ := w.h.InstanceMailProvider(context.Background(), mailProviderID)
	if len(v.BlockHash) != 64 {
		t.Fatalf("no block_hash in the view: %q", v.BlockHash)
	}
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed again\n")
	for _, hash := range []string{v.BlockHash, ""} {
		if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof, BlockHash: hash}, rootActor()); statusOf(err) != 409 {
			t.Fatalf("%q: %v", hash, err)
		}
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Held == nil {
		t.Fatal("the hold went")
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

// heldFix is a wired provider held by a template change.
func heldFix(t *testing.T) *wireFix {
	t.Helper()
	w := wiredFix(t)
	changeMailTemplate(t, w, "gate.sh", "#!/bin/sh\necho changed\n")
	syncNow(w)
	w.h.mu.RLock()
	held := w.h.st.Mail.Held
	w.h.mu.RUnlock()
	if held == nil {
		t.Fatal("not held")
	}
	return w
}

// TestHeldStopOwedBeforeDown (security review): the stop is recorded
// before the down, so a failed down still leaves the provider treated as
// stopped (no client, no targets), the error kept for the doctor and the
// down retried until it succeeds.
func TestHeldStopOwedBeforeDown(t *testing.T) {
	w := heldFix(t)
	w.runner.byNameErr = errors.New("engine down")
	w.h.mailStopHeld("a test")
	if w.h.mailClient() != nil || len(readTargets(t, w.fixture)) != 0 {
		t.Fatal("a stop owed still serves")
	}
	if w.h.MailHeldStopError() == "" {
		t.Fatal("the failed down isn't kept")
	}
	st, _ := state.Load(w.h.statePath())
	if st.Mail.Held == nil || st.Mail.Held.Stopped == nil {
		t.Fatal("the owed stop isn't saved")
	}
	w.runner.byNameErr = nil
	w.h.mailVoidRetryOnce(context.Background())
	if w.h.MailHeldStopError() != "" {
		t.Fatal("the retry didn't clear the error")
	}
}

// TestHeldNoRestartInPlace (R-HH3): a session reset of a held provider
// never restarts it in place: it is stopped instead.
func TestHeldNoRestartInPlace(t *testing.T) {
	w := heldFix(t)
	n := len(w.engine.Restarts())
	if err := w.h.mailRestart(context.Background(), "a test"); err != nil {
		t.Fatal(err)
	}
	if len(w.engine.Restarts()) != n {
		t.Fatal("restarted in place while held")
	}
	w.h.mu.RLock()
	held := w.h.st.Mail.Held
	w.h.mu.RUnlock()
	if held.Stopped == nil {
		t.Fatal("not stopped")
	}
}

// TestHeldGetsNoDelivery (R-HH3): no data files or hooks of the changed
// tree reach a held provider's running containers.
func TestHeldGetsNoDelivery(t *testing.T) {
	w := heldFix(t)
	rep, err := w.h.Deliver(context.Background(), mailProviderID, TriggerSave)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Units) != 1 || rep.Units[0].Skipped != SkipBusy || !strings.Contains(rep.Units[0].Message, "template changed") {
		t.Fatalf("%+v", rep.Units)
	}
}

// TestHeldDownOwedRetriedAtStart (security review): a crash between the
// saved stop and the down: the start retries the owed down.
func TestHeldDownOwedRetriedAtStart(t *testing.T) {
	w := heldFix(t)
	now := w.now
	w.h.mu.Lock()
	c := *w.h.st.Mail.Held
	c.Stopped, c.DownOwed = &now, true
	w.h.st.Mail.Held = &c
	w.h.mu.Unlock()
	if w.h.MailHeldStopError() == "" {
		t.Fatal("an owed down isn't reported")
	}
	downs := len(w.runner.callsMatching("downbyname"))
	w.h.resumeMail()
	w.h.Wait()
	if len(w.runner.callsMatching("downbyname")) == downs || w.h.MailHeldStopError() != "" {
		t.Fatal("the owed down wasn't retried at start")
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Held.DownOwed || w.h.st.Mail.Held.Stopped == nil {
		t.Fatalf("%+v", w.h.st.Mail.Held)
	}
}

// TestHeldDownTimeoutStaysOwed: a down that hangs is cut at the bound
// and stays owed.
func TestHeldDownTimeoutStaysOwed(t *testing.T) {
	w := heldFix(t)
	w.h.mailStopWait = 50 * time.Millisecond
	w.runner.byNameBlock = true
	w.h.mailStopHeld("a test")
	w.h.mu.RLock()
	hd := *w.h.st.Mail.Held
	w.h.mu.RUnlock()
	if !hd.DownOwed || hd.StopError == "" || w.h.mailClient() != nil {
		t.Fatalf("%+v", hd)
	}
}

// TestWiredSourceNotRemovable (M7): the wired provider's source can't be
// removed while it is wired.
func TestWiredSourceNotRemovable(t *testing.T) {
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Sources = append(w.h.st.Sources, state.Source{Name: "local", URL: "https://example.org/a.git"})
	w.h.mu.Unlock()
	if err := w.h.RemoveSource("local"); statusOf(err) != 409 || !strings.Contains(err.Error(), "unwire it first") {
		t.Fatalf("%v", err)
	}
}

// TestSourceURLChangeIsNoRewire (M7): the same source name pointing at
// another repository holds the provider and refuses the re-confirm.
func TestSourceURLChangeIsNoRewire(t *testing.T) {
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Sources = append(w.h.st.Sources, state.Source{Name: "local", URL: "https://example.org/a.git"})
	w.h.st.Mail.Provider.SourceURL = "https://example.org/a.git"
	w.h.st.Sources[len(w.h.st.Sources)-1].URL = "https://example.net/other.git"
	w.h.mu.Unlock()
	w.h.checkMailHold()
	v, _ := w.h.InstanceMailProvider(context.Background(), mailProviderID)
	if v.Held == nil || v.Held.Reason != MailSourceChangedText {
		t.Fatalf("held %+v", v.Held)
	}
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof, BlockHash: v.BlockHash}, rootActor()); statusOf(err) != 409 {
		t.Fatalf("re-confirm: %v", err)
	}
}
