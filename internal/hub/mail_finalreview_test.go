package hub

import (
	"context"
	"errors"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
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
	if err := f.h.ConfirmMailRemoval(context.Background(), confirmIn(f.h, ids), directory.Human("root")); err != nil {
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

// TestHubRestartLeavesRunningProviderAlone (core build-and-test): a Hub
// start with the wired provider running and unchanged (same tree, same
// rendering, nothing owed or held) issues no compose up, down or restart
// of the provider's project: a Hub upgrade never interrupts mail.
func TestHubRestartLeavesRunningProviderAlone(t *testing.T) {
	w := wiredFix(t)
	// The running containers carry exactly the rendered override's labels.
	w.h.mu.Lock()
	r, err := w.h.mailRenderLocked(w.h.findLocked(mailProviderID), mailNormal)
	w.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	w.engine.mu.Lock()
	for _, svc := range []string{"stalwart", "adapter", "resolver", "bootstrap"} {
		c := container("prov-"+svc, "portcullis-"+mailProviderID, svc, "running")
		for k, v := range r.labels[svc] {
			c.Labels[k] = v
		}
		w.engine.containers = append(w.engine.containers, c)
	}
	w.engine.mu.Unlock()
	before := len(w.runner.Calls())
	restarts := len(w.engine.Restarts())
	// The start's mail and VPN passes, as Init runs them.
	w.h.checkMailHold()
	w.h.writeMailTargets()
	w.h.resumeMail()
	w.h.vpnStartCheck(context.Background(), w.h.rt)
	w.h.Wait()
	w.h.owedMu.Lock()
	owedEffect := w.h.owedLocked(mailProviderID)
	w.h.owedMu.Unlock()
	var touched []string
	for _, c := range w.runner.Calls()[before:] {
		if strings.Contains(c, "portcullis-"+mailProviderID) {
			touched = append(touched, c)
		}
	}
	if len(touched) > 0 || len(w.engine.Restarts()) != restarts || owedEffect != "" && owedEffect != "none" {
		t.Fatalf("the start touched the running provider: %v restarts %d→%d owed %q", touched, restarts, len(w.engine.Restarts()), owedEffect)
	}
}

// TestRestartSameModeUpNoDown: the provider's last applied mode is
// persisted after each successful up; a Hub start whose running
// networks confirm it needs no down before a later up in that mode. A
// network contradicting the record, a missing one, or networks that
// can't be read keep the down first (fail closed).
func TestRestartSameModeUpNoDown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		networks func(declared map[string]bool, names []string, external map[string]bool) []runtime.Network
		listErr  error
		wantDown bool
	}{
		{name: "confirmed", networks: projectNets(func(k string, declared map[string]bool) bool { return declared[k] })},
		{name: "contradicted", wantDown: true, networks: projectNets(func(string, map[string]bool) bool { return true })},
		{name: "missing", wantDown: true, networks: func(map[string]bool, []string, map[string]bool) []runtime.Network { return nil }},
		{name: "unreadable", wantDown: true, listErr: errors.New("engine away"),
			networks: projectNets(func(k string, declared map[string]bool) bool { return declared[k] })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := wiredFix(t)
			w.h.mu.RLock()
			upMode, upInst := w.h.st.Mail.UpMode, w.h.st.Mail.UpModeInstance
			w.h.mu.RUnlock()
			if upMode != "normal" || upInst != mailProviderID {
				t.Fatalf("persisted mode %q %q", upMode, upInst)
			}
			names, external, declared := topLevelNetworkFlags(w.h.Template(mailProviderID).ReadCompose())
			w.engine.mu.Lock()
			w.engine.networks = append(w.engine.networks, tc.networks(declared, names, external)...)
			w.engine.networksErr = tc.listErr
			w.engine.mu.Unlock()
			downs := providerDowns(w)
			// A Hub restart: the new Hub knows only the saved state.
			h := reopen(t, w.fixture)
			h.SetPeople(w.people)
			h.SetMailAPI(w.mc.Client())
			h.SetDomainsAPI(w.dom)
			h.Init() // resumeMail cross-checks the record here
			h.Wait()
			w.engine.mu.Lock()
			w.engine.networksErr = nil
			w.engine.mu.Unlock()
			tp := h.Template(mailProviderID)
			if tp == nil {
				t.Fatal("no template after the restart")
			}
			if _, err := os.Stat(tp.ComposePath()); err != nil {
				t.Fatal(err)
			}
			ups := len(w.runner.callsMatching("up"))
			// An owed delivery's up, same mode.
			unlock, err := h.lockApp(mailProviderID)
			if err != nil {
				t.Fatal(err)
			}
			err = h.composeUp(context.Background(), h.Template(mailProviderID))
			unlock()
			if err != nil && !tc.wantDown {
				t.Fatal(err)
			}
			if len(w.runner.callsMatching("up")) == ups {
				t.Fatal("no up ran")
			}
			// The start and the up together: a confirmed record downs
			// nothing; anything else downs before an up (the start's own
			// or this one).
			got := providerDowns(w) > downs
			if got != tc.wantDown {
				t.Fatalf("down before the up: %v, want %v (%v)", got, tc.wantDown, w.runner.Calls())
			}
		})
	}
}

// projectNets is the provider project's declared networks with internal
// flags from flag.
func projectNets(flag func(key string, declared map[string]bool) bool) func(map[string]bool, []string, map[string]bool) []runtime.Network {
	return func(declared map[string]bool, names []string, external map[string]bool) []runtime.Network {
		var out []runtime.Network
		for _, k := range names {
			if external[k] {
				continue
			}
			out = append(out, runtime.Network{Name: "portcullis-" + mailProviderID + "_" + k, Internal: flag(k, declared),
				Labels: map[string]string{"com.docker.compose.project": "portcullis-" + mailProviderID, "com.docker.compose.network": k}})
		}
		return out
	}
}

// providerDowns counts the provider project's downs so far.
func providerDowns(w *wireFix) int {
	n := 0
	for _, c := range w.runner.Calls() {
		if c == "down:portcullis-"+mailProviderID {
			n++
		}
	}
	return n
}
