package hub

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/mailprovider/mailprovidertest"
	"github.com/portcullis/hub/internal/state"
)

// gateFile is one of mailsrv's gate files ("" = absent).
func gateFile(t *testing.T, f *fixture, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.h.cfg.SecretsDir, mailProviderID, "_mail", name))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// voidFixture is the mail fixture with a fast void (short waits), a
// first accepted document and alice holding one mail password.
func voidFixture(t *testing.T) *mailFixture {
	t.Helper()
	f, _, _ := newMailCredFixture(t)
	f.h.mailBootstrapWait, f.h.mailPollEvery = 200*time.Millisecond, time.Millisecond
	f.create(t, "alice", "iPhone")
	return f
}

// runVoidNow owes and runs a void under the app lock.
func runVoidNow(t *testing.T, f *mailFixture) error {
	t.Helper()
	unlock, err := f.h.lockApp(mailProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	return f.h.runVoid(context.Background(), mailProviderID, state.MailVoidWire)
}

// TestVoidMarkerSavedFirst: a failed state save leaves the gate files
// and the state untouched and answers the error.
func TestVoidMarkerSavedFirst(t *testing.T) {
	f := voidFixture(t)
	f.h.mu.Lock()
	if err := f.h.mailGateWrite(mailProviderID, mailGatePresent, []byte(mailGateSentinel+"\n")); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Unlock()
	if err := os.Chmod(f.data, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(f.data, 0o755) })
	f.h.mu.Lock()
	err := f.h.markVoidOwedLocked(state.MailVoidWire)
	owed := f.h.st.Mail.VoidOwed
	f.h.mu.Unlock()
	os.Chmod(f.data, 0o755)
	if err == nil || owed != nil {
		t.Fatalf("err %v owed %+v", err, owed)
	}
	if gateFile(t, f.fixture, mailGatePresent) != mailGateSentinel+"\n" || gateFile(t, f.fixture, mailGateVoidPending) != "" || gateFile(t, f.fixture, mailGateFileVoidSession) != "" {
		t.Fatal("the gate changed after a failed save")
	}
	// Saved: void-pending, a fresh session, no .present.
	f.h.mu.Lock()
	err = f.h.markVoidOwedLocked(state.MailVoidWire)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if gateFile(t, f.fixture, mailGatePresent) != "" || gateFile(t, f.fixture, mailGateVoidPending) == "" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(gateFile(t, f.fixture, mailGateFileVoidSession)) {
		t.Fatal("the gate isn't in void mode")
	}
	st, err := state.Load(f.h.statePath())
	if err != nil || st.Mail.VoidOwed == nil || st.Mail.VoidOwed.Reason != state.MailVoidWire {
		t.Fatalf("saved %+v %v", st.Mail.VoidOwed, err)
	}
}

// TestVoidVerifiesByListing: after the void the Hub lists ?uuid= for
// every account of mail-last.json and every row's uuid, then opens the
// gate and clears the debt.
func TestVoidVerifiesByListing(t *testing.T) {
	f := voidFixture(t)
	n := len(f.mc.Requests)
	if err := runVoidNow(t, f); err != nil {
		t.Fatal(err)
	}
	var lists []string
	for _, r := range f.mc.Requests[n:] {
		if r == "GET /v1/credentials" {
			lists = append(lists, r)
		}
	}
	if len(lists) < 3 || f.mc.Voids[len(f.mc.Voids)-1] != state.MailVoidWire {
		t.Fatalf("lists %d voids %v requests %v", len(lists), f.mc.Voids, f.mc.Requests[n:])
	}
	if len(f.mc.Creds("alice")) != 0 {
		t.Fatal("alice's password survived")
	}
	f.h.mu.RLock()
	owed := f.h.st.Mail.VoidOwed
	f.h.mu.RUnlock()
	if owed != nil || gateFile(t, f.fixture, mailGatePresent) != mailGateSentinel+"\n" || gateFile(t, f.fixture, mailGateVoidPending) != "" || gateFile(t, f.fixture, mailGateFileVoidSession) != "" {
		t.Fatalf("owed %+v / gate not open", owed)
	}
	if len(gateFile(t, f.fixture, mailGateAPISecret)) != mailSecretLen {
		t.Fatal("no API secret written")
	}
}

// TestVoidLeftoverCredentialRevokedThenFails: a provider that ignores
// the void and whose revoke fails keeps a credential: the void fails,
// the instance is stopped and the debt stays; one whose revoke works
// passes once the leftover is gone.
func TestVoidLeftoverCredentialRevokedThenFails(t *testing.T) {
	f := voidFixture(t)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.VoidKeeps, s.RevokeStatus = true, 500 })
	downs := len(f.runner.callsMatching("down"))
	err := runVoidNow(t, f)
	if err == nil || !strings.Contains(err.Error(), "still holds 1") {
		t.Fatalf("err %v", err)
	}
	f.h.mu.RLock()
	owed := f.h.st.Mail.VoidOwed
	f.h.mu.RUnlock()
	if owed == nil || gateFile(t, f.fixture, mailGatePresent) != "" {
		t.Fatal("the debt cleared or the gate opened")
	}
	if len(f.runner.callsMatching("down")) == downs {
		t.Fatal("the instance wasn't stopped")
	}
	if msg, _ := f.h.MailVoidError(); !strings.Contains(msg, "still holds") {
		t.Fatalf("recorded %q", msg)
	}
	// The revoke works: the leftover goes, the void passes.
	f.mc.Lock(func(s *mailprovidertest.Server) { s.RevokeStatus = 0 })
	if err := runVoidNow(t, f); err != nil {
		t.Fatal(err)
	}
	if msg, _ := f.h.MailVoidError(); msg != "" {
		t.Fatalf("error kept: %q", msg)
	}
}

// failList fails every credential listing.
type failList struct{ MailAPI }

func (failList) Credentials(context.Context, string) ([]mailprovider.Credential, error) {
	return nil, &mailprovider.APIError{Status: 500, Msg: "boom"}
}

// TestVoidListErrorFails: a list error is a failed void.
func TestVoidListErrorFails(t *testing.T) {
	f := voidFixture(t)
	f.h.SetMailAPI(failList{f.mc.Client()})
	if err := runVoidNow(t, f); err == nil || !strings.Contains(err.Error(), "listing") {
		t.Fatalf("err %v", err)
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	if f.h.st.Mail.VoidOwed == nil {
		t.Fatal("the debt cleared")
	}
}

// watchVoid sees the gate when the provider is asked to void.
type watchVoid struct {
	MailAPI
	seen func()
}

func (w watchVoid) Void(ctx context.Context, reason string) (mailprovider.VoidResult, error) {
	w.seen()
	return w.MailAPI.Void(ctx, reason)
}

// TestPresentWrittenOnlyAfterVerify: during the void the gate holds
// void-pending and the session but no .present; .present only after the
// verification; a failed provider void never opens it.
func TestPresentWrittenOnlyAfterVerify(t *testing.T) {
	f := voidFixture(t)
	f.h.mu.Lock()
	f.h.mailGateWrite(mailProviderID, mailGatePresent, []byte(mailGateSentinel))
	f.h.mu.Unlock()
	var during atomic.Value
	f.h.SetMailAPI(watchVoid{f.mc.Client(), func() {
		during.Store(gateFile(t, f.fixture, mailGatePresent) + "|" + gateFile(t, f.fixture, mailGateVoidPending))
	}})
	if err := runVoidNow(t, f); err != nil {
		t.Fatal(err)
	}
	if d := during.Load().(string); !strings.HasPrefix(d, "|") || d == "|" {
		t.Fatalf("gate during the void: %q", d)
	}
	if gateFile(t, f.fixture, mailGatePresent) != mailGateSentinel+"\n" {
		t.Fatal("no .present after the verified void")
	}
	f.mc.Lock(func(s *mailprovidertest.Server) { s.VoidStatus = 500 })
	if err := runVoidNow(t, f); err == nil {
		t.Fatal("a failed provider void passed")
	}
	if gateFile(t, f.fixture, mailGatePresent) != "" {
		t.Fatal(".present after a failed void")
	}
}

// TestGateFilesInPlace: rewriting a gate file keeps its inode (a bound
// file stays bound); mode 0640, the gate's group; the directory 2750.
func TestGateFilesInPlace(t *testing.T) {
	f := voidFixture(t)
	ino := func() uint64 {
		fi, err := os.Stat(filepath.Join(f.h.cfg.SecretsDir, mailProviderID, "_mail", mailGateAPISecret))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o640 || int(fi.Sys().(*syscall.Stat_t).Gid) != os.Getgid() {
			t.Fatalf("mode %v gid %d", fi.Mode(), fi.Sys().(*syscall.Stat_t).Gid)
		}
		return fi.Sys().(*syscall.Stat_t).Ino
	}
	f.h.mu.Lock()
	err := f.h.writeMailSecretLocked(mailProviderID)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	a, s1 := ino(), gateFile(t, f.fixture, mailGateAPISecret)
	f.h.mu.Lock()
	err = f.h.writeMailSecretLocked(mailProviderID)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if b, s2 := ino(), gateFile(t, f.fixture, mailGateAPISecret); a != b || s1 == s2 || !regexp.MustCompile(`^[A-Za-z0-9]{48}$`).MatchString(s2) {
		t.Fatalf("inode %d → %d, secret %q → %q", a, b, s1, s2)
	}
	di, err := os.Stat(filepath.Join(f.h.cfg.SecretsDir, mailProviderID, "_mail"))
	if err != nil || di.Mode().Perm() != 0o750 || di.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("dir %v %v", di.Mode(), err)
	}
	// The metrics secret also lands in mail_slot for Prometheus.
	f.h.mu.Lock()
	err = f.h.writeMailMetricsSecretLocked(mailProviderID)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := os.ReadFile(filepath.Join(f.h.cfg.MailSlotDir, mailGateMetricsSecret))
	if string(ms) != gateFile(t, f.fixture, mailGateMetricsSecret) || len(ms) != mailSecretLen {
		t.Fatal("metrics secrets differ")
	}
	// The relay password: the Hub's copy, or an empty file.
	f.h.mu.Lock()
	err = f.h.writeRelayPasswordLocked(mailProviderID)
	f.h.mu.Unlock()
	if err != nil || gateFile(t, f.fixture, mailGateRelayPassword) != "" {
		t.Fatalf("relay %v", err)
	}
	writeFile(t, filepath.Join(f.data, mailRelayPasswordFile), "relay-pw-1")
	f.h.mu.Lock()
	err = f.h.writeRelayPasswordLocked(mailProviderID)
	f.h.mu.Unlock()
	if err != nil || gateFile(t, f.fixture, mailGateRelayPassword) != "relay-pw-1" {
		t.Fatalf("relay copy %v", err)
	}
}

// TestSecretNeverLogged: no gate secret appears in the log of a wiring's
// secret writes and a void.
func TestSecretNeverLogged(t *testing.T) {
	f := voidFixture(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f.mc.Lock(func(s *mailprovidertest.Server) { s.VoidStatus = 500 })
	runVoidNow(t, f)
	f.mc.Lock(func(s *mailprovidertest.Server) { s.VoidStatus = 0 })
	if err := runVoidNow(t, f); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{mailGateAPISecret, mailGateMetricsSecret} {
		if s := gateFile(t, f.fixture, name); s == "" || strings.Contains(logs.String(), s) {
			t.Fatalf("%s logged (or missing)", name)
		}
	}
	if strings.Contains(logs.String(), testVoidSession) {
		t.Fatal("void session logged")
	}
}

// TestCreateRefusedWhileVoidOwed: 503 while a void is owed.
func TestCreateRefusedWhileVoidOwed(t *testing.T) {
	f := voidFixture(t)
	f.h.mu.Lock()
	f.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidRestore}
	f.h.mu.Unlock()
	_, err := f.h.CreateMailPassword(context.Background(), "bob", "phone", "none", testProof)
	if statusOf(err) != 503 {
		t.Fatalf("create while a void is owed: %v", err)
	}
}

// TestEpochMismatchOwesVoid: a core restore (the secrets epoch differs)
// with a provider wired owes a restore void, saved; a reconcile without
// a mismatch keeps the wired provider's gate and removes another
// instance's.
func TestEpochMismatchOwesVoid(t *testing.T) {
	f := voidFixture(t)
	f.h.mu.Lock()
	f.h.mailGateWrite(mailProviderID, mailGatePresent, []byte(mailGateSentinel))
	f.h.mu.Unlock()
	writeFile(t, filepath.Join(f.h.cfg.SecretsDir, "grafana", "_mail", ".present"), "x")
	if _, err := f.h.reconcileSecrets("test"); err != nil {
		t.Fatal(err)
	}
	if gateFile(t, f.fixture, mailGatePresent) == "" {
		t.Fatal("the wired provider's gate was removed as an orphan")
	}
	if _, err := os.Stat(filepath.Join(f.h.cfg.SecretsDir, "grafana", "_mail")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("another instance's gate kept")
	}
	writeFile(t, filepath.Join(f.h.cfg.SecretsDir, epochFile), "0000")
	if _, err := f.h.reconcileSecrets("test"); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(f.h.statePath())
	if err != nil || st.Mail.VoidOwed == nil || st.Mail.VoidOwed.Reason != state.MailVoidRestore {
		t.Fatalf("owed %+v %v", st.Mail.VoidOwed, err)
	}
	if gateFile(t, f.fixture, mailGatePresent) != "" {
		t.Fatal("the gate survived the emptied volume")
	}
}

// TestVoidRetryEvery5Min: the retry loop runs an owed void each period
// (a failure first, then a pass), never while held.
func TestVoidRetryEvery5Min(t *testing.T) {
	f := voidFixture(t)
	f.h.mu.Lock()
	f.h.st.Mail.Held = &state.MailHold{Reason: "template changed"}
	f.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidRestore}
	f.h.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.mc.Lock(func(s *mailprovidertest.Server) { s.VoidStatus = 500 })
	done := make(chan struct{})
	go func() { f.h.RunMailVoidRetry(ctx, 5*time.Millisecond); close(done) }()
	time.Sleep(50 * time.Millisecond)
	f.mc.Lock(func(s *mailprovidertest.Server) {
		if len(s.Voids) != 0 {
			t.Errorf("voided while held: %v", s.Voids)
		}
	})
	f.h.mu.Lock()
	f.h.st.Mail.Held = nil
	f.h.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		f.mc.Lock(func(s *mailprovidertest.Server) { n = len(s.Voids) })
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no retry")
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.mc.Lock(func(s *mailprovidertest.Server) { s.VoidStatus = 0 })
	for {
		f.h.mu.RLock()
		owed := f.h.st.Mail.VoidOwed
		f.h.mu.RUnlock()
		if owed == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the retry never passed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if MailVoidRetryEvery != 5*time.Minute {
		t.Fatal("the retry period isn't 5 min")
	}
	cancel()
	<-done
	f.h.Wait()
}

// callsMatching are the runner's calls starting with op.
func (f *fakeRunner) callsMatching(op string) []string {
	var out []string
	for _, c := range f.Calls() {
		if strings.HasPrefix(c, op+":") {
			out = append(out, c)
		}
	}
	return out
}
