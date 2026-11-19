package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The gate and the void (contract §19.1, §19.4, §19.11). The Hub's files
// at the root of the mail_provider_slot volume (HUB_MAIL_PROVIDER_SLOT_DIR;
// directory 2750, files 0640, group
// 2000, written in place: O_TRUNC on the same inode, then fsync; never a
// rename over a mounted file, never on argv, in a log, an op record or
// the audit). Every gated service starts only when void-pending is
// absent and .present is exactly the sentinel, or void-pending exists and
// $PORTCULLIS_MAIL_VOID_SESSION equals void-session.

const (
	mailGatePresent       = ".present"
	mailGateSentinel      = "portcullis-mail-gate"
	mailGateVoidPending   = "void-pending"
	mailGateAPISecret     = "api-secret"
	mailGateMetricsSecret = "metrics-secret"
	mailGateRelayPassword = "relay-password"
	// mailRelayPasswordFile is the Hub's own copy in hub_data (0600).
	mailRelayPasswordFile = "mail-relay-password"
	// mailSecretLen is the API secret's length ([A-Za-z0-9]).
	mailSecretLen = 48
	// mailBootstrapWait bounds the wait for bootstrap: true.
	mailBootstrapWait = 5 * time.Minute
	// MailVoidRetryEvery is the failed void's retry period.
	MailVoidRetryEvery = 5 * time.Minute
)

// mailVoidState is the last void's outcome (memory; the doctor's
// mail_void_pending and the API's void.error).
type mailVoidState struct {
	mu      sync.Mutex
	err     string
	at      time.Time
	running bool
}

// mailGID is the gate's group (cfg.MailGID, default 2000).
func (h *Hub) mailGID() int {
	if h.cfg.MailGID != 0 {
		return h.cfg.MailGID
	}
	return MailProviderGID
}

// mailRandString is n characters of [A-Za-z0-9] from crypto/rand.
func mailRandString(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[k.Int64()]
	}
	return string(b), nil
}

// mailGateRoot opens the mail_provider_slot volume (R-POD2) and makes
// its root 2750, group 2000. The caller closes it; names are relative
// to the root (dir ".").
func (h *Hub) mailGateRoot(id string) (*os.Root, string, error) {
	dir := h.mailSlotDir(id)
	if dir == "" {
		return nil, "", statusErr(http.StatusServiceUnavailable, "the mail provider's slot volume isn't available: the mail gate can't be written")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", fmt.Errorf("the mail provider's slot volume: %w", err)
	}
	d, err := r.Open(".")
	if err != nil {
		r.Close()
		return nil, "", err
	}
	defer d.Close()
	if err := d.Chown(-1, h.mailGID()); err != nil {
		r.Close()
		return nil, "", fmt.Errorf("the mail gate directory's group: %w", err)
	}
	if err := d.Chmod(0o750 | fs.ModeSetgid); err != nil {
		r.Close()
		return nil, "", err
	}
	return r, ".", nil
}

// mailSlotEmpty removes every entry of the slot volume (an unwire, a
// switch, a wiring's start: the next wiring writes its own files).
func (h *Hub) mailSlotEmpty() error {
	dir := h.cfg.MailProviderSlotDir
	if dir == "" {
		return nil
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("the mail provider's slot volume: %w", err)
	}
	defer r.Close()
	es, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		return err
	}
	var first error
	for _, e := range es {
		if err := r.RemoveAll(e.Name()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// writeInPlace writes data to name inside r: the same inode when it
// exists (O_TRUNC, never a rename: a bound file stays bound), then
// fsync; mode 0640, group gid (-1: unchanged).
func writeInPlace(r *os.Root, name string, data []byte, gid int) error {
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return fmt.Errorf("%s isn't a regular file", filepath.Base(name))
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Chmod(0o640)
	}
	if err == nil && gid >= 0 {
		err = f.Chown(-1, gid)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// mailGateWrite writes one gate file of instance id.
func (h *Hub) mailGateWrite(id, name string, data []byte) error {
	r, dir, err := h.mailGateRoot(id)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := writeInPlace(r, filepath.Join(dir, name), data, h.mailGID()); err != nil {
		return fmt.Errorf("writing the mail gate's %s: %w", name, err)
	}
	return nil
}

// mailGateRemove removes one gate file (absent is fine).
func (h *Hub) mailGateRemove(id, name string) error {
	dir := h.mailSlotDir(id)
	if dir == "" {
		return nil
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing the mail gate's %s: %w", name, err)
	}
	return nil
}

// mailGateRead reads one gate file ("" = absent or unreadable).
func (h *Hub) mailGateRead(id, name string) string {
	dir := h.mailSlotDir(id)
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(b)
}

// writeMailSecretLocked writes a fresh API secret (48 characters
// [A-Za-z0-9]) for instance id, in place. Caller must hold mu.
func (h *Hub) writeMailSecretLocked(id string) error {
	s, err := mailRandString(mailSecretLen)
	if err != nil {
		return err
	}
	return h.mailGateWrite(id, mailGateAPISecret, []byte(s))
}

// writeMailMetricsSecretLocked writes a fresh metrics password to the
// gate and the same value to mail_slot/metrics-secret for Prometheus
// (0640; the directory's setgid gives it group 65534). Caller must hold
// mu.
func (h *Hub) writeMailMetricsSecretLocked(id string) error {
	s, err := mailRandString(mailSecretLen)
	if err != nil {
		return err
	}
	if err := h.mailGateWrite(id, mailGateMetricsSecret, []byte(s)); err != nil {
		return err
	}
	if h.cfg.MailSlotDir == "" {
		return nil
	}
	r, err := os.OpenRoot(h.cfg.MailSlotDir)
	if err != nil {
		return fmt.Errorf("the mail_slot volume: %w", err)
	}
	defer r.Close()
	if err := writeInPlace(r, mailGateMetricsSecret, []byte(s), -1); err != nil {
		return fmt.Errorf("writing mail_slot's metrics-secret: %w", err)
	}
	return nil
}

// writeRelayPasswordLocked copies hub_data/mail-relay-password to the
// gate (an empty file when the relay has none). Caller must hold mu.
func (h *Hub) writeRelayPasswordLocked(id string) error {
	b, err := os.ReadFile(filepath.Join(h.cfg.DataDir, mailRelayPasswordFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reading the relay password: %w", err)
	}
	defer wipeBytes(b)
	return h.mailGateWrite(id, mailGateRelayPassword, b)
}

// wipeBytes zeroes b.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// markVoidOwedLocked owes a void (reason wire or restore): state.yaml
// first (a failed save changes nothing and answers the error), then, for
// the wired instance, void-pending and a fresh void-session, then
// .present removed. A void already owed keeps its reason and since.
// Caller must hold mu (write).
func (h *Hub) markVoidOwedLocked(reason string) error {
	prev, prevGen := h.st.Mail.VoidOwed, h.st.Mail.VoidGen
	h.raiseVoidDebtLocked(reason)
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.VoidOwed, h.st.Mail.VoidGen = prev, prevGen
		return err
	}
	p := h.st.Mail.Provider
	if p == nil {
		return nil
	}
	return h.mailVoidFilesLocked(p.Instance)
}

// raiseVoidDebtLocked raises a void debt in memory (the caller saves):
// the generation always grows, also while a void is owed; an owed void
// keeps its start and becomes a restore when this one is. Every path
// that owes a void goes through it. Caller must hold mu (write).
func (h *Hub) raiseVoidDebtLocked(reason string) {
	h.st.Mail.VoidGen++
	next := state.MailVoid{Reason: reason, Since: h.mailNow().UTC()}
	if prev := h.st.Mail.VoidOwed; prev != nil {
		next = *prev
		if reason == state.MailVoidRestore {
			next.Reason = reason
		}
	}
	h.st.Mail.VoidOwed = &next
}

// mailVoidFilesLocked writes void-pending and a fresh void-session, then
// removes .present (the gate admits only the Hub's void mode).
func (h *Hub) mailVoidFilesLocked(id string) error {
	if err := h.mailGateWrite(id, mailGateVoidPending, []byte(h.st.Mail.VoidOwed.Reason+"\n")); err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	if err := h.mailGateWrite(id, mailGateFileVoidSession, []byte(hex.EncodeToString(nonce[:]))); err != nil {
		return err
	}
	return h.mailGateRemove(id, mailGatePresent)
}

// mailVoidUUIDs are the uuids the verification lists: every account of
// mail-last.json and every uuid of a mail_credentials row.
func (h *Hub) mailVoidUUIDs(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if last, _ := h.loadMailLast(); last != nil {
		for _, a := range last.Accounts {
			add(a.UUID)
		}
	}
	h.mu.RLock()
	for _, rows := range h.st.MailCredentials {
		for _, r := range rows {
			add(r.UUID)
		}
	}
	h.mu.RUnlock()
	// The accounts of the document about to be sent (M16): a first
	// wiring or a lost mail-last.json still lists everyone. A directory
	// that can't be read fails the void (never a vacuous verification).
	doc, err := h.mailBuild(ctx)
	if err != nil {
		if _, ok := err.(*StatusError); ok {
			return nil, fmt.Errorf("the void can't list the mail accounts to verify: %v", err)
		}
	}
	if doc != nil {
		for _, a := range doc.Accounts {
			add(a.UUID)
		}
	}
	return out, nil
}

// verifyMailVoid (P8): lists ?uuid= for every uuid, revokes every
// credential found, lists again. Any credential left or any list error
// (but 404: no such account) fails the void.
func verifyMailVoid(ctx context.Context, api MailAPI, uuids []string) error {
	list := func(u string) ([]mailprovider.Credential, error) {
		rows, err := api.Credentials(ctx, u)
		// 404: the provider has no account with that uuid (contract
		// §19.5), so it holds no credential of it either (L21): nothing
		// to revoke, and nothing that could survive.
		if mailprovider.StatusOf(err) == http.StatusNotFound {
			return nil, nil
		}
		return rows, err
	}
	for _, u := range uuids {
		rows, err := list(u)
		if err != nil {
			return fmt.Errorf("listing the mail passwords of an account failed: %v", err)
		}
		for _, c := range rows {
			if err := api.RevokeCredential(ctx, u, c.ID); err != nil {
				log.Printf("mail: void: revoking a leftover mail password failed: %v", err)
			}
		}
		if len(rows) == 0 {
			continue
		}
		left, err := list(u)
		if err != nil {
			return fmt.Errorf("listing the mail passwords of an account failed: %v", err)
		}
		if len(left) > 0 {
			return fmt.Errorf("the provider still holds %d mail password(s) after the void", len(left))
		}
	}
	return nil
}

// MailVoidError is the last failed void's error and when ("" = none).
func (h *Hub) MailVoidError() (string, time.Time) {
	h.mailVoid.mu.Lock()
	defer h.mailVoid.mu.Unlock()
	return h.mailVoid.err, h.mailVoid.at
}

func (h *Hub) setMailVoidErr(msg string) {
	h.mailVoid.mu.Lock()
	h.mailVoid.err, h.mailVoid.at = msg, h.mailNow().UTC()
	h.mailVoid.mu.Unlock()
}

// runVoid owes and runs a void of instance id (§19.11): the void-mode
// override and up, bootstrap: true (≤ 5 min), POST /v1/void, the
// verification (P8). On success .present is written, void-session and
// void-pending go and void_owed is cleared (the caller then renders the
// normal override); on failure the instance is stopped, the void stays
// owed and the error is kept for the doctor. The caller holds the app
// lock (lockApp(id)); one void runs at a time.
func (h *Hub) runVoid(ctx context.Context, id, reason string) error {
	h.mailVoid.mu.Lock()
	if h.mailVoid.running {
		h.mailVoid.mu.Unlock()
		return statusErr(http.StatusConflict, "a void is already running")
	}
	h.mailVoid.running = true
	h.mailVoid.mu.Unlock()
	defer func() {
		h.mailVoid.mu.Lock()
		h.mailVoid.running = false
		h.mailVoid.mu.Unlock()
	}()
	err := h.runVoidLocked(ctx, id, reason)
	if err == nil {
		h.setMailVoidErr("")
		return nil
	}
	h.setMailVoidErr(err.Error())
	log.Printf("mail: the void of %s failed: %v: the provider stays stopped and the void is retried", id, err)
	h.mu.RLock()
	var live *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		live = &c
	}
	h.mu.RUnlock()
	if live != nil {
		if derr := h.composeDown(live); derr != nil {
			log.Printf("mail: stopping %s after a failed void: %v", id, derr)
		}
	}
	return err
}

// runVoidLocked is runVoid's work.
func (h *Hub) runVoidLocked(ctx context.Context, id, reason string) error {
	h.mu.Lock()
	p := h.st.Mail.Provider
	if p == nil || p.Instance != id {
		h.mu.Unlock()
		return errMailNotWired
	}
	if err := h.markVoidOwedLocked(reason); err != nil {
		h.mu.Unlock()
		return err
	}
	runGen := h.st.Mail.VoidGen
	// The stored debt's reason (L10): a restore owed wins over a stale
	// caller's wire.
	reason = h.st.Mail.VoidOwed.Reason
	// A fresh void session for this run; the secrets the provider needs
	// (a core restore emptied hub_secrets).
	err := h.mailVoidFilesLocked(id)
	if err == nil && h.mailGateRead(id, mailGateAPISecret) == "" {
		err = h.writeMailSecretLocked(id)
	}
	if err == nil && h.mailGateRead(id, mailGateMetricsSecret) == "" {
		err = h.writeMailMetricsSecretLocked(id)
	}
	if err == nil {
		err = h.writeRelayPasswordLocked(id)
	}
	var live *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		live = &c
	}
	api := h.mailProviderAPILocked()
	h.mu.Unlock()
	if err != nil {
		return err
	}
	if live == nil || api == nil {
		return errMailNotWired
	}
	// Void mode (the state owes a void) and up.
	if err := h.composeUp(ctx, live); err != nil {
		return fmt.Errorf("starting the provider in void mode: %w", err)
	}
	wait := h.mailBootstrapWait
	if wait == 0 {
		wait = mailBootstrapWait
	}
	deadline := time.Now().Add(wait)
	for {
		st, err := api.State(ctx)
		if err == nil && st.Bootstrap {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("the provider didn't report bootstrap: true within 5 minutes")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(h.mailPoll()):
		}
	}
	vctx, cancel := context.WithTimeout(ctx, mailprovider.VoidTimeout)
	_, err = api.Void(vctx, reason)
	cancel()
	if err != nil {
		return fmt.Errorf("the provider's void failed: %v", err)
	}
	uuids, err := h.mailVoidUUIDs(ctx)
	if err != nil {
		return err
	}
	if err := verifyMailVoid(ctx, api, uuids); err != nil {
		return err
	}
	// Verified: open the gate, then clear the debt — only the debt this
	// run started on (L19): a newer one keeps the gate closed and runs
	// again.
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur := h.st.Mail.VoidOwed; cur != nil && h.st.Mail.VoidGen != runGen {
		h.kickMailVoid()
		return statusErr(http.StatusConflict, "another void was owed during this one (%s): it runs again", cur.Reason)
	}
	if err := h.mailGateWrite(id, mailGatePresent, []byte(mailGateSentinel+"\n")); err != nil {
		return err
	}
	for _, f := range []string{mailGateFileVoidSession, mailGateVoidPending} {
		if err := h.mailGateRemove(id, f); err != nil {
			return err
		}
	}
	prev := h.st.Mail.VoidOwed
	h.st.Mail.VoidOwed = nil
	// A wiring of another instance: its void completed, in the same save
	// that opens it to the sync (R-SWITCH-BASE-2): the first pass starts
	// from an empty baseline, the old provider's pending removal gone.
	prevFresh, prevPendingFresh, prevPR := h.st.Mail.FreshInstance, h.st.Mail.FreshPending, h.st.Mail.PendingRemoval
	if h.st.Mail.FreshPending == id {
		h.st.Mail.FreshInstance, h.st.Mail.FreshPending = id, ""
		if pr := h.st.Mail.PendingRemoval; pr != nil {
			h.st.Mail.PendingRemoval = nil
			log.Printf("mail: the pending removal of %d mailboxes was the previous provider's: dropped (the new provider starts empty)", len(pr.Accounts))
		}
	}
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.VoidOwed = prev
		h.st.Mail.FreshInstance, h.st.Mail.FreshPending, h.st.Mail.PendingRemoval = prevFresh, prevPendingFresh, prevPR
		return err
	}
	return nil
}

// mailPoll is the bootstrap poll interval (tests shorten it).
func (h *Hub) mailPoll() time.Duration {
	if h.mailPollEvery > 0 {
		return h.mailPollEvery
	}
	return 2 * time.Second
}

// RunMailVoidRetry retries an owed void every `every` (main: 5 min)
// while a provider is wired, not held and no void runs; a verified void
// is followed by the normal override's up.
func (h *Hub) RunMailVoidRetry(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-h.mailVoidKick:
		}
		h.mailVoidRetryOnce(ctx)
	}
}

// kickMailVoid asks RunMailVoidRetry for a pass now (never blocks).
func (h *Hub) kickMailVoid() {
	select {
	case h.mailVoidKick <- struct{}{}:
	default:
	}
}

// mailVoidRetryOnce runs one retry when one is due.
func (h *Hub) mailVoidRetryOnce(ctx context.Context) {
	h.mu.RLock()
	p, owed, held := h.st.Mail.Provider, h.st.Mail.VoidOwed, h.st.Mail.Held
	h.mu.RUnlock()
	// Owed stops first, whatever the slot (M8): a closed slot never
	// leaves an old provider serving.
	if held != nil && held.DownOwed {
		h.mailRetryHeldStop()
	}
	h.mailResumeClosing()
	h.mailNoteRestorePending()
	if !h.mailOn() {
		return
	}
	if p == nil || owed == nil || held != nil {
		return
	}
	// A pending core restore runs the void itself (`hub mail restore`):
	// a retry now would only hold the app lock that restore needs.
	if h.mailRestoreHolds(p.Instance) {
		return
	}
	if err := h.mailVoidAndResume(ctx, p.Instance, owed.Reason); err != nil && !errors.As(err, new(ErrBusy)) && !strings.Contains(err.Error(), "already running") {
		log.Printf("mail: void retry: %v", err)
	}
}

// mailVoidAndResume runs the void and, verified, the normal override's
// up, under the app lock.
func (h *Hub) mailVoidAndResume(ctx context.Context, id, reason string) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()
	if err := h.runVoid(ctx, id, reason); err != nil {
		return err
	}
	h.mu.RLock()
	var live *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		live = &c
	}
	h.mu.RUnlock()
	if live == nil {
		return errMailNotWired
	}
	return h.composeUp(ctx, live)
}

// OpMailVoidRetry is the Mail tab's Retry of an owed void.
const OpMailVoidRetry = "mail_void_retry"

// RetryMailVoid is POST /api/mail/provider/retry-void (contract §19.11):
// the owed void and, verified, the normal up, now (409: no void owed or
// the provider is held). Audited mail.void_retry.
func (h *Hub) RetryMailVoid(actor directory.Actor) (*AsyncOp, error) {
	h.mu.RLock()
	cur := h.st.Mail.Provider
	h.mu.RUnlock()
	if cur != nil && h.mailRestorePendingFor(cur.Instance) {
		return nil, errMailRestorePending
	}
	// A missing or short API secret (the slot emptied) is fixed by a
	// void, which writes a fresh one (T28 gap 3): Retry owes one then.
	secretBad := h.mailSecretInvalid()
	h.mu.Lock()
	p, held := h.st.Mail.Provider, h.st.Mail.Held
	if p != nil && secretBad && h.st.Mail.VoidOwed == nil {
		h.raiseVoidDebtLocked(state.MailVoidWire)
		h.saveLocked()
	}
	// After a core restore's hold went by hand (`mail restore-hold
	// clear`), the administrator's Retry is what starts the provider
	// again, always through a void (FH-H3 c).
	if p != nil && h.st.Mail.RestoreHeld == p.Instance {
		h.st.Mail.RestoreHeld = ""
		if h.st.Mail.VoidOwed == nil {
			h.raiseVoidDebtLocked(state.MailVoidRestore)
		}
		h.saveLocked()
	}
	owed := h.st.Mail.VoidOwed
	h.mu.Unlock()
	if p == nil || owed == nil {
		return nil, statusErr(http.StatusConflict, "no void of the mail passwords is owed")
	}
	if held != nil {
		return nil, statusErr(http.StatusConflict, "%s", held.Reason)
	}
	id, reason := p.Instance, owed.Reason
	return h.startAsync(id, OpMailVoidRetry, actor, nil, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		err := h.mailVoidAndResume(context.WithoutCancel(ctx), id, reason)
		h.auditOp(actor, "mail.void_retry", id, "reason="+reason, err)
		return nil, nil, err
	})
}
