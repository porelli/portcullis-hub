package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

func readTargets(t *testing.T, f *fixture) []mailTarget {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.h.cfg.MailSlotDir, mailTargetsFile))
	if err != nil {
		t.Fatal(err)
	}
	var out []mailTarget
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return out
}

// TestMailTargetsEmptyWhenUnwired: [] with nothing wired, in void mode
// and after an unwire.
func TestMailTargetsEmptyWhenUnwired(t *testing.T) {
	f := newMailSlotFixture(t, false)
	f.h.writeMailTargets()
	if tg := readTargets(t, f); tg == nil || len(tg) != 0 {
		t.Fatalf("%+v", tg)
	}
	w := wiredFix(t)
	if len(readTargets(t, w.fixture)) == 0 {
		t.Fatal("no targets once wired")
	}
	w.h.mu.Lock()
	w.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidRestore}
	w.h.mu.Unlock()
	w.h.writeMailTargets()
	if len(readTargets(t, w.fixture)) != 0 {
		t.Fatal("targets in void mode")
	}
	w.h.mu.Lock()
	w.h.st.Mail.VoidOwed = nil
	w.h.mu.Unlock()
	if err := w.unwire(t, false, rootActor()); err != nil {
		t.Fatal(err)
	}
	if len(readTargets(t, w.fixture)) != 0 {
		t.Fatal("targets after the unwire")
	}
}

// TestMailTargetsLabelsAndPath: the provider target with service
// provider, the server's with service server and its metrics path.
func TestMailTargetsLabelsAndPath(t *testing.T) {
	w := wiredFix(t)
	tg := readTargets(t, w.fixture)
	if len(tg) != 2 || tg[0].Targets[0] != "mail-provider-metrics:9100" || tg[0].Labels["service"] != "provider" ||
		tg[1].Targets[0] != "mail-provider-server-metrics:9180" || tg[1].Labels["service"] != "server" || tg[1].Labels["__metrics_path__"] != "/metrics/prometheus" {
		t.Fatalf("%+v", tg)
	}
}

// TestMetricsSecretGid65534: the metrics secret in a setgid mail_slot
// directory takes the directory's group (Prometheus's 65534 on a host),
// mode 0640, the same value as the gate's.
func TestMetricsSecretGid65534(t *testing.T) {
	w := wiredFix(t)
	if err := os.Chmod(w.h.cfg.MailSlotDir, 0o2750); err != nil {
		t.Fatal(err)
	}
	w.h.mu.Lock()
	err := w.h.writeMailMetricsSecretLocked(mailProviderID)
	w.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	di, _ := os.Stat(w.h.cfg.MailSlotDir)
	fi, err := os.Stat(filepath.Join(w.h.cfg.MailSlotDir, mailGateMetricsSecret))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 || fi.Sys().(*syscall.Stat_t).Gid != di.Sys().(*syscall.Stat_t).Gid {
		t.Fatalf("mode %v gid %d (dir %d)", fi.Mode(), fi.Sys().(*syscall.Stat_t).Gid, di.Sys().(*syscall.Stat_t).Gid)
	}
	b, _ := os.ReadFile(filepath.Join(w.h.cfg.MailSlotDir, mailGateMetricsSecret))
	if string(b) != gateFile(t, w.fixture, mailGateMetricsSecret) {
		t.Fatal("the two metrics secrets differ")
	}
}

// TestHostTLSRecordsAndReloads: POST /host/mail/tls records the SPKIs,
// not_after and the timer's visit, then reloads the provider; the next
// document carries the SPKIs; bad SPKIs are refused.
func TestHostTLSRecordsAndReloads(t *testing.T) {
	w := wiredFix(t)
	spki := strings.Repeat("ab", 32)
	na := w.now.Add(60 * 24 * time.Hour)
	serving, err := w.h.HostMailTLS(context.Background(), []string{spki}, na)
	if err != nil || serving != spki {
		t.Fatalf("%q %v", serving, err)
	}
	w.h.mu.RLock()
	tls := w.h.st.Mail.TLS
	w.h.mu.RUnlock()
	if len(tls.SPKISHA256) != 1 || tls.NotAfter == nil || !tls.NotAfter.Equal(na) || tls.SeenAt == nil {
		t.Fatalf("%+v", tls)
	}
	var reloads int
	w.mc.Lock(func(s *mailprovidertest.Server) { reloads = len(s.Reloads) })
	if reloads != 1 {
		t.Fatalf("reloads %d", reloads)
	}
	w.advance(time.Minute)
	w.sync(t)
	if got := w.mc.Last().TLS.SPKISHA256; len(got) != 1 || got[0] != spki {
		t.Fatalf("document tls %v", got)
	}
	for _, bad := range [][]string{nil, {"AB"}, {spki, spki, spki}} {
		if _, err := w.h.HostMailTLS(context.Background(), bad, na); statusOf(err) != 400 {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

// TestHostBackupReasonCore: POST /host/mail/backup backs the wired
// provider up with reason core and answers the archive.
func TestHostBackupReasonCore(t *testing.T) {
	w := wiredFix(t)
	archive, err := w.h.HostMailBackup()
	if err != nil || !strings.HasPrefix(archive, mailProviderID+"/") {
		t.Fatalf("%q %v", archive, err)
	}
	list, err := w.h.ListBackups(mailProviderID)
	if err != nil || len(list) == 0 || list[0].Reason != BackupCore {
		t.Fatalf("%+v %v", list, err)
	}
	w.h.mu.Lock()
	w.h.st.Mail.Provider = nil
	w.h.mu.Unlock()
	if _, err := w.h.HostMailBackup(); statusOf(err) != 409 {
		t.Fatalf("nothing wired: %v", err)
	}
}

// TestCoreBackupDuringVoidStaysVoid (Review Focus 2): a core backup while
// a void is owed starts the provider again in void mode, never normal.
func TestCoreBackupDuringVoidStaysVoid(t *testing.T) {
	w := wiredFix(t)
	w.h.mu.Lock()
	w.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidRestore}
	w.h.mu.Unlock()
	w.engine.containers = append(w.engine.containers, container("portcullis-"+mailProviderID+"-c", "portcullis-"+mailProviderID, "stalwart", "running"))
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	if _, err := w.h.HostMailBackup(); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.ups) == 0 {
		t.Fatal("the provider wasn't started again")
	}
	for _, u := range w.ups {
		if strings.Contains(u.override, "0.0.0.0:25:") || !strings.Contains(u.override, "internal: true") {
			t.Fatal("a normal up during an owed void")
		}
	}
}

// TestInstanceRestoreOwesVoidFirst: restoring the wired provider owes a
// restore void before its volumes are replaced (saved), so it starts in
// void mode.
func TestInstanceRestoreOwesVoidFirst(t *testing.T) {
	w := wiredFix(t)
	archive, err := w.h.HostMailBackup()
	if err != nil {
		t.Fatal(err)
	}
	var owedAtUp []bool
	w.runner.upHook = func(project string) {
		w.h.mu.RLock()
		owedAtUp = append(owedAtUp, w.h.st.Mail.VoidOwed != nil)
		w.h.mu.RUnlock()
	}
	op, err := w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	if v := w.h.HostMailOp(op.Instance, op.OpID); v == nil || v.Running || !v.OK {
		t.Fatalf("op %+v", v)
	}
	if len(owedAtUp) == 0 || !owedAtUp[0] {
		t.Fatalf("ups with a void owed: %v", owedAtUp)
	}
	st, err := state.Load(w.h.statePath())
	if err != nil || st.Mail.VoidOwed == nil || st.Mail.VoidOwed.Reason != state.MailVoidRestore {
		t.Fatalf("saved %+v %v", st.Mail.VoidOwed, err)
	}
}

// TestRestorePendingHoldsProvider (core interface C1): while
// hub_data/mail-restore-pending exists the wired provider is never
// started; `hub mail restore` removes it and the restore starts it (in
// void mode).
func TestRestorePendingHoldsProvider(t *testing.T) {
	w := wiredFix(t)
	archive, err := w.h.HostMailBackup()
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(w.h.cfg.DataDir, mailRestorePendingFile)
	writeFile(t, pending, archive+"\n")
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	if err := w.h.composeUp(context.Background(), w.h.Template(mailProviderID)); statusOf(err) != 409 {
		t.Fatalf("an up during the hold: %v", err)
	}
	w.mu.Lock()
	n := len(w.ups)
	w.mu.Unlock()
	if n != 0 {
		t.Fatal("the provider started during the hold")
	}
	op, err := w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	if v := w.h.HostMailOp(op.Instance, op.OpID); v == nil || !v.OK {
		t.Fatalf("op %+v", v)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Fatal("the hold wasn't removed")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.ups) == 0 || strings.Contains(w.ups[0].override, "0.0.0.0:25:") {
		t.Fatalf("ups %d", len(w.ups))
	}
}

// TestHostDNSMainRules (core interface H5/M6): the rule context with the
// main set.
func TestHostDNSMainRules(t *testing.T) {
	w := wiredFix(t)
	r := w.h.HostMailDNSRules()
	if r.DMARCFloor == "" || r.Draining {
		t.Fatalf("%+v", r)
	}
}

// TestHostRestoreArchiveChecked: the archive name is checked before any
// filesystem call: a traversal or another instance's archive is 400, the
// same as a missing one would never be told apart by existence.
func TestHostRestoreArchiveChecked(t *testing.T) {
	w := wiredFix(t)
	other := filepath.Join(w.h.backupsDir(), "grafana")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(other, "20261117T000000Z.tar"), "x")
	for _, a := range []string{"../../etc/passwd", "../../no-such-file", "grafana/20261118T000000Z.tar", mailProviderID + "/../grafana/20261117T000000Z.tar", "grafana/20261117T000000Z.tar", mailProviderID + "/x.tar", ""} {
		if _, err := w.h.HostMailRestore(a); statusOf(err) != 400 {
			t.Errorf("%q: %v", a, err)
		}
	}
	if _, err := w.h.HostMailRestore(mailProviderID + "/20261117T000000Z.tar"); statusOf(err) != 404 {
		t.Fatalf("a missing archive of its own: %v", err)
	}
}

// TestHostTLSOnlyServedIsSuccess (core interface fix round 1, item 2):
// the answer is a success only when the provider serves a posted SPKI.
func TestHostTLSOnlyServedIsSuccess(t *testing.T) {
	w := wiredFix(t)
	spki := strings.Repeat("ab", 32)
	na := w.now.Add(60 * 24 * time.Hour)
	w.mc.Lock(func(s *mailprovidertest.Server) { s.ServingSPKI = strings.Repeat("cd", 32) })
	if _, err := w.h.HostMailTLS(context.Background(), []string{spki}, na); statusOf(err) != 502 {
		t.Fatalf("another served SPKI: %v", err)
	}
	w.mc.Lock(func(s *mailprovidertest.Server) { s.ServingSPKI = "" })
	w.h.mu.Lock()
	w.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidRestore}
	w.h.mu.Unlock()
	if _, err := w.h.HostMailTLS(context.Background(), []string{spki}, na); statusOf(err) != 503 {
		t.Fatalf("nothing serving: %v", err)
	}
	w.h.mu.RLock()
	rec := w.h.st.Mail.TLS.SPKISHA256
	w.h.mu.RUnlock()
	if len(rec) != 1 || rec[0] != spki {
		t.Fatalf("not recorded: %v", rec)
	}
}

// TestHostStatusNullOrObject (item 4): void_owed and held are null or an
// object, never false.
func TestHostStatusNullOrObject(t *testing.T) {
	w := wiredFix(t)
	b, _ := json.Marshal(w.h.HostMailStatus(context.Background()))
	if !strings.Contains(string(b), `"void_owed":null`) || !strings.Contains(string(b), `"held":null`) {
		t.Fatalf("%s", b)
	}
	w.h.mu.Lock()
	w.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidRestore}
	w.h.st.Mail.Held = &state.MailHold{Reason: MailHoldText}
	w.h.mu.Unlock()
	b, _ = json.Marshal(w.h.HostMailStatus(context.Background()))
	var v map[string]json.RawMessage
	json.Unmarshal(b, &v)
	if !strings.HasPrefix(string(v["void_owed"]), `{"reason":"restore"`) || !strings.HasPrefix(string(v["held"]), `{"reason":`) {
		t.Fatalf("%s", b)
	}
}

// TestRestorePendingNamesTheArchive (item 5): the pending file is the
// archive's name and a newline; a restore of another archive, or a
// malformed file, is refused and the hold stays.
func TestRestorePendingNamesTheArchive(t *testing.T) {
	w := wiredFix(t)
	archive, err := w.h.HostMailBackup()
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(w.h.cfg.DataDir, mailRestorePendingFile)
	for _, body := range []string{mailProviderID + "/20200101T000000Z.tar\n", archive, archive + "\n\n", "../x\n"} {
		writeFile(t, pending, body)
		if _, err := w.h.HostMailRestore(archive); statusOf(err) != 409 {
			t.Errorf("%q: %v", body, err)
		}
		if _, err := os.Stat(pending); err != nil {
			t.Fatalf("%q: the hold went: %v", body, err)
		}
	}
	writeFile(t, pending, archive+"\n")
	op, err := w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	if v := w.h.HostMailOp(op.Instance, op.OpID); v == nil || !v.OK {
		t.Fatalf("op %+v", v)
	}
}

// TestUnwireRemovesSlotMetricsSecret (L22): mail_slot's metrics secret
// goes with the unwire.
func TestUnwireRemovesSlotMetricsSecret(t *testing.T) {
	w := wiredFix(t)
	p := filepath.Join(w.h.cfg.MailSlotDir, mailGateMetricsSecret)
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	if err := w.unwire(t, false, rootActor()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("still there: %v", err)
	}
}

// notFoundListAPI answers 404 to every credential list.
type notFoundListAPI struct{ MailAPI }

func (a *notFoundListAPI) Credentials(context.Context, string) ([]mailprovider.Credential, error) {
	return nil, &mailprovider.APIError{Status: 404, Msg: "no such account"}
}

// TestVoidVerify404IsNoCredentials (L21): a 404 list is an account the
// provider doesn't have: nothing to revoke, the verification passes.
func TestVoidVerify404IsNoCredentials(t *testing.T) {
	w := wiredFix(t)
	if err := verifyMailVoid(context.Background(), &notFoundListAPI{MailAPI: w.mc.Client()}, []string{uuidAlice}); err != nil {
		t.Fatal(err)
	}
}

// TestRestorePendingKeptOnFailedRestore (R2-N4, fault injection): a
// restore that fails keeps the hold: no empty store goes live.
func TestRestorePendingKeptOnFailedRestore(t *testing.T) {
	w := wiredFix(t)
	archive, err := w.h.HostMailBackup()
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(w.h.cfg.DataDir, mailRestorePendingFile)
	writeFile(t, pending, archive+"\n")
	w.runner.upErr = errors.New("compose up failed")
	op, err := w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	if v := w.h.HostMailOp(op.Instance, op.OpID); v == nil || v.OK {
		t.Fatalf("op %+v", v)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("the hold went with a failed restore: %v", err)
	}
	w.runner.upErr = nil
	if err := w.h.composeUp(context.Background(), w.h.Template(mailProviderID)); statusOf(err) != 409 {
		t.Fatalf("an up after the failed restore: %v", err)
	}
}

// restoreFix is a wired provider with a backup and a pending core
// restore naming it.
func restoreFix(t *testing.T) (*wireFix, string, string) {
	t.Helper()
	w := wiredFix(t)
	archive, err := w.h.HostMailBackup()
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(w.h.cfg.DataDir, mailRestorePendingFile)
	writeFile(t, pending, archive+"\n")
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	return w, archive, pending
}

func (w *wireFix) upCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.ups)
}

// TestRestoreCommitTokenOnly (security review): only the restore's final
// start, after its volumes came back, passes the hold.
func TestRestoreCommitTokenOnly(t *testing.T) {
	t.Run("failed before the start", func(t *testing.T) {
		w, archive, pending := restoreFix(t)
		w.h.testHookApplyRestore = func(stage string) error {
			if stage == "volumes" {
				return errors.New("a volume failed")
			}
			return nil
		}
		op, err := w.h.HostMailRestore(archive)
		if err != nil {
			t.Fatal(err)
		}
		w.h.Wait()
		if v := w.h.HostMailOp(op.Instance, op.OpID); v == nil || v.OK {
			t.Fatalf("op %+v", v)
		}
		if n := w.upCount(); n != 0 {
			t.Fatalf("%d ups passed the hold (the rollback's included)", n)
		}
		if _, err := os.Stat(pending); err != nil {
			t.Fatal("the hold went")
		}
	})
	t.Run("concurrent up", func(t *testing.T) {
		w, archive, _ := restoreFix(t)
		var upErr error
		w.h.testHookApplyRestore = func(stage string) error {
			if stage == "volumes" {
				upErr = w.h.composeUp(context.Background(), w.h.Template(mailProviderID))
			}
			return nil
		}
		if _, err := w.h.HostMailRestore(archive); err != nil {
			t.Fatal(err)
		}
		w.h.Wait()
		if statusOf(upErr) != 409 {
			t.Fatalf("a concurrent up: %v", upErr)
		}
	})
	t.Run("success", func(t *testing.T) {
		w, archive, pending := restoreFix(t)
		var pendingAtUp []bool
		w.runner.upHook = func(project string) {
			_, err := os.Stat(pending)
			pendingAtUp = append(pendingAtUp, err == nil)
		}
		op, err := w.h.HostMailRestore(archive)
		if err != nil {
			t.Fatal(err)
		}
		w.h.Wait()
		if v := w.h.HostMailOp(op.Instance, op.OpID); v == nil || !v.OK {
			t.Fatalf("op %+v", v)
		}
		if len(pendingAtUp) != 1 || !pendingAtUp[0] {
			t.Fatalf("ups %v (want exactly one, with the hold still on)", pendingAtUp)
		}
		if _, err := os.Stat(pending); !os.IsNotExist(err) {
			t.Fatal("the hold stayed after a successful restore")
		}
	})
}

// TestRestorePendingRefusesOtherRestores (security review): while a core
// restore is pending, the wired provider's UI/API/MCP restore is 409 and
// starts nothing; `hub mail restore` with another archive is 409.
func TestRestorePendingRefusesOtherRestores(t *testing.T) {
	w, archive, _ := restoreFix(t)
	if _, err := w.h.RestoreInstance(mailProviderID, archive, rootActor()); statusOf(err) != 409 || !strings.Contains(err.Error(), "a core restore is pending") {
		t.Fatalf("RestoreInstance: %v", err)
	}
	if _, err := w.h.StartRestore(mailProviderID, archive, rootActor()); statusOf(err) != 409 {
		t.Fatalf("StartRestore: %v", err)
	}
	w.h.Wait()
	if n := w.upCount(); n != 0 {
		t.Fatalf("%d ups", n)
	}
	other, err := w.h.HostMailBackup()
	if err != nil {
		t.Fatal(err)
	}
	if other == archive {
		t.Skip("same second: no second archive name")
	}
	if _, err := w.h.HostMailRestore(other); statusOf(err) != 409 {
		t.Fatalf("another archive: %v", err)
	}
}

// TestRestoreHoldClearedByHandStaysStopped (FH-H3 c): the hold file
// removed by hand (`mail restore-hold clear`) never starts the provider
// on its own; the administrator's Retry does, through a void.
func TestRestoreHoldClearedByHandStaysStopped(t *testing.T) {
	w, _, pending := restoreFix(t)
	w.h.mailNoteRestorePending()
	os.Remove(pending)
	w.h.mailVoidRetryOnce(context.Background())
	w.h.Wait()
	if err := w.h.composeUp(context.Background(), w.h.Template(mailProviderID)); statusOf(err) != 409 {
		t.Fatalf("an up after the hand clear: %v", err)
	}
	if n := w.upCount(); n != 0 {
		t.Fatalf("%d ups", n)
	}
	voids := len(w.mc.Voids)
	if _, err := w.h.RetryMailVoid(rootActor()); err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	if w.upCount() == 0 || len(w.mc.Voids) == voids {
		t.Fatalf("Retry: ups %d voids %d → %d", w.upCount(), voids, len(w.mc.Voids))
	}
}

// TestWiredProviderRestoredOnlyOnHost (final review M3): without any
// pending core restore, a UI/API/MCP restore of the wired provider is
// 409 and starts nothing; `hub mail restore` still works.
func TestWiredProviderRestoredOnlyOnHost(t *testing.T) {
	w := wiredFix(t)
	archive, err := w.h.HostMailBackup()
	if err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.ups = nil
	w.mu.Unlock()
	if _, err := w.h.RestoreInstance(mailProviderID, archive, rootActor()); statusOf(err) != 409 || !strings.Contains(err.Error(), "restored only on the host") {
		t.Fatalf("RestoreInstance: %v", err)
	}
	if _, err := w.h.StartRestore(mailProviderID, archive, rootActor()); statusOf(err) != 409 {
		t.Fatalf("StartRestore: %v", err)
	}
	if w.upCount() != 0 {
		t.Fatal("an up")
	}
	op, err := w.h.HostMailRestore(archive)
	if err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	if v := w.h.HostMailOp(op.Instance, op.OpID); v == nil || !v.OK {
		t.Fatalf("host restore %+v", v)
	}
}
