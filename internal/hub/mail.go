package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/fsutil"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
)

// Mail sync timing (contract §19.6).
const (
	// mailDebounce: additions wait this long; removals never wait.
	mailDebounce = 60 * time.Second
	// mailApplyWait: after a removal, how long the Hub waits for mailctl
	// to apply it before restarting mail anyway (8 s budget: 4 + restart).
	mailApplyWait = 4 * time.Second
	mailApplyPoll = 200 * time.Millisecond
	// mailRetry: the next try after a failed send or read.
	mailRetry = 30 * time.Second
	// mailDNSEvery: the added domains' mail sets are rewritten this often
	// (and after every accepted document).
	mailDNSEvery = 6 * time.Hour
	// mailIdle: the longest sleep without a kick.
	mailIdle = 5 * time.Minute
	// mailSyncTimeout bounds one sync pass.
	mailSyncTimeout = time.Minute
)

// mailSync is RunMailSync's memory (its own lock; never held across a
// network call except by the one sync pass that owns it).
type mailSync struct {
	// pass serialises sync passes (RunMailSync and direct calls).
	pass sync.Mutex
	// passWiring is the wiring the running pass's client talks to (set
	// at its start, under pass): what an accepted document is bound to.
	passWiring mailWiring

	mu sync.Mutex
	// last is the last document mailctl accepted (nil: none since start).
	last *mailprovider.MailState
	// blindListed: without a baseline, the uuids (sorted) the provider's
	// own mass-removal refusal named: a confirmation of exactly that set
	// is the only one that sends confirm_mass_removal (R-L8).
	blindListed []string
	// blindDoc: the accounts of the document that refusal answered; the
	// flag is sent only for a document keeping every one of them (M1:
	// nobody else rides on the confirmation).
	blindDoc []string
	// addSince: when the pending additions were first seen (zero: none).
	addSince time.Time
	// hubRemoved: the accounts (by uuid) an admin took out of mail_users
	// (or deleted) through the Hub since the last accepted document: each
	// recorded only while the person had a mailbox in last, with that
	// document's generation and the time; cleared on every accepted
	// document, worth nothing after mailHubRemovalTTL.
	hubRemoved map[string]hubRemoval
	// noted: the build notes already logged (each once).
	noted map[string]bool
	// lastErr: the last logged failure (each once in a row).
	lastErr string
	// dnsAt: the last full mail-set pass; hashAt the last hash pass;
	// dnsHash: per added domain, mailctl's set hash last written.
	dnsAt, hashAt time.Time
	dnsHash       map[string]string
	// reconciled: the start-time reconcile of every person's mail
	// passwords succeeded (wanted after the first accepted document:
	// reconAll).
	reconciled, reconAll bool
	// restoreAt: the last restore check (mailRestoreIfDue); reconRunning:
	// the background reconcile runs (mailReconcileSoon), reconAgain: run
	// it once more when it ends.
	restoreAt                time.Time
	reconRunning, reconAgain bool
	// reconWG: the background reconcile runs (tests wait on it).
	reconWG sync.WaitGroup
	// personMu: each person's mail credential lock (mailPersonLock).
	personMu map[string]*sync.Mutex
	// loaded: last was read from hub_data (mail-last.json) once; blind:
	// it wasn't there, so the first accepted document may remove people
	// (treated as a removal: wait, then restart mail).
	loaded, blind bool
	// removalRetry: the next retry of a failed removal (2 s, doubling to
	// 30 s); zero after a success.
	removalRetry time.Duration
	// blocked: why the sync sends nothing (doctor mail_sync_blocked; ""
	// = it isn't).
	blocked string
	// applyWait / applyPoll: mailWaitApplied's budget and poll (zero: the
	// defaults; tests shorten them).
	applyWait, applyPoll time.Duration
	// recSeq counts recorded admin removals (a pass keeps only those
	// recorded after it built its document).
	recSeq uint64
}

// mailLastFile is the last accepted MailState in hub_data (0600): the
// baseline removals are judged against across Hub restarts.
const mailLastFile = "mail-last.json"

func (h *Hub) mailLastPath() string { return filepath.Join(h.cfg.DataDir, mailLastFile) }

// loadMailLast reads the persisted last accepted document (nil, true:
// none or unreadable: the first document is treated as removing).
func (h *Hub) loadMailLast() (*mailprovider.MailState, bool) {
	b, err := os.ReadFile(h.mailLastPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("mail: %s unreadable (%v): the first document is treated as a removal", mailLastFile, err)
		}
		return nil, true
	}
	var d mailprovider.MailState
	if err := json.Unmarshal(b, &d); err != nil || d.Version != mailprovider.StateVersion {
		log.Printf("mail: %s is corrupt: the first document is treated as a removal", mailLastFile)
		return nil, true
	}
	return &d, false
}

// saveMailLast persists an accepted document (a failure is logged: the
// next start then treats its first document as a removal).
func (h *Hub) saveMailLast(d *mailprovider.MailState, wr mailWiring) {
	// The wiring that accepted it (the pass's client's). A switch since
	// the send: discarded, so the new wiring's next pass starts as a new
	// wiring (it never accepted this document).
	current := func() bool {
		p := h.st.Mail.Provider
		return p != nil && p.Seq == wr.seq && p.Instance == wr.instance
	}
	h.mu.RLock()
	ok := current()
	h.mu.RUnlock()
	if !ok {
		log.Printf("mail: the provider changed after the document was accepted: it isn't kept as the new provider's baseline")
		return
	}
	b, err := json.Marshal(d)
	if err == nil {
		err = fsutil.WriteFileAtomic(h.mailLastPath(), b, 0600)
	}
	if err != nil {
		log.Printf("mail: saving %s: %v", mailLastFile, err)
		return
	}
	// The binding after the file: a crash between the two leaves the
	// file bound to the wiring before (a resend), never another
	// wiring's document trusted.
	h.mu.Lock()
	if current() && (h.st.Mail.LastDocSeq != wr.seq || h.st.Mail.LastDocInstance != wr.instance || h.st.Mail.FreshInstance != "") {
		h.st.Mail.LastDocSeq, h.st.Mail.LastDocInstance = wr.seq, wr.instance
		// Its first document is accepted: the empty baseline is spent.
		if h.st.Mail.FreshInstance == wr.instance {
			h.st.Mail.FreshInstance = ""
		}
		h.saveLocked()
	}
	h.mu.Unlock()
}

// hubRemoval is one recorded admin removal.
type hubRemoval struct {
	gen int
	at  time.Time
	seq uint64 // recSeq when recorded
}

// mailHubRemovalTTL: an admin removal older than this confirms nothing.
const mailHubRemovalTTL = 10 * time.Minute

// mailNow is the mail clock (tests set h.mailClock).
func (h *Hub) mailNow() time.Time {
	if h.mailClock != nil {
		return h.mailClock()
	}
	return time.Now().UTC()
}

// TriggerMailSync asks RunMailSync for a pass: non-blocking, coalesced.
// Safe from directory hooks and under any Hub lock.
func (h *Hub) TriggerMailSync() {
	select {
	case h.mailKick <- struct{}{}:
	default:
	}
}

// MailMemberRemoved records a global administrator's removal of user
// from group (directory.Service.MemberRemoved; actor: who removed): a
// shrink of mail_users made by an lldap_admin member through the Hub may
// confirm a mass removal (contract §19.5). Anyone else's removal (a
// delegate, lldap_password_manager) goes through, and their passwords
// are revoked, but never confirms one (rulings I2, M3).
func (h *Hub) MailMemberRemoved(group, user, actor string) {
	if !strings.EqualFold(group, MailUsersGroup) {
		return
	}
	if !h.isGlobalAdmin(context.Background(), actor) {
		h.TriggerMailSync()
		return
	}
	h.mailRecordHubRemoval(user)
}

func (h *Hub) mailRecordHubRemoval(user string) {
	user = strings.ToLower(user)
	now := h.mailNow()
	s := &h.mailState
	s.mu.Lock()
	// Only a person with a mailbox in the last accepted document, keyed
	// by that account's uuid and the document's generation.
	if s.last != nil {
		for _, a := range s.last.Accounts {
			if a.Username == user {
				if s.hubRemoved == nil {
					s.hubRemoved = map[string]hubRemoval{}
				}
				s.recSeq++
				s.hubRemoved[a.UUID] = hubRemoval{gen: s.last.Generation, at: now, seq: s.recSeq}
			}
		}
	}
	s.mu.Unlock()
	h.TriggerMailSync()
}

// RunMailSync sends the mail state on every TriggerMailSync and when a
// debounce or a retry is due, until ctx is done.
func (h *Hub) RunMailSync(ctx context.Context) {
	wait := time.Duration(0)
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-h.mailKick:
			t.Stop()
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, mailSyncTimeout)
		wait = h.mailSyncOnce(pctx)
		cancel()
	}
}

// mailLogOnce logs msg unless it was the last one logged.
func (h *Hub) mailLogOnce(msg string) {
	s := &h.mailState
	s.mu.Lock()
	same := s.lastErr == msg
	s.lastErr = msg
	s.mu.Unlock()
	if !same && msg != "" {
		log.Print(msg)
	}
}

// mailBuild reads the directory and builds the document (nil: nothing
// to send, with why).
func (h *Hub) mailBuild(ctx context.Context) (*mailprovider.MailState, error) {
	m, err := h.membership(ctx)
	if err != nil {
		// A directory error sends nothing (contract §19.5).
		return nil, err
	}
	dnssec := h.mailDNSSEC(ctx)
	core := h.mailCore()
	h.mu.RLock()
	in := MailBuildInput{Membership: m, Settings: h.st.Mail, MainDomain: h.cfg.Domain, CoreOn: true, DNSSEC: dnssec,
		LocalNetworks: prefixStrings(h.localNetworksLocked()), Generation: h.st.Mail.Generation,
		MailHostname: core.Hostname, ClientIPRewritten: core.ClientIPRewritten, SubmissionLANOnly: core.SubmissionLAN}
	doc, notes := BuildMailState(in)
	h.mu.RUnlock()
	s := &h.mailState
	s.mu.Lock()
	if s.noted == nil {
		s.noted = map[string]bool{}
	}
	var fresh []string
	for _, n := range notes {
		if !s.noted[n] {
			s.noted[n] = true
			fresh = append(fresh, n)
		}
	}
	s.mu.Unlock()
	for _, n := range fresh {
		log.Print(n)
	}
	if doc == nil {
		return nil, errors.New(strings.Join(notes, "; "))
	}
	return doc, nil
}

// mailDNSSEC is each mail domain's zone state: the added domains' from
// the known list, the main domain's from its plan (unknown on failure).
func (h *Hub) mailDNSSEC(ctx context.Context) map[string]string {
	out := map[string]string{}
	h.mu.RLock()
	for _, d := range h.st.Domains {
		if d.DNSSEC != "" {
			out[strings.ToLower(d.Name)] = d.DNSSEC
		}
	}
	api := h.domainsAPI
	h.mu.RUnlock()
	if api != nil {
		if p, err := api.MainPlan(ctx, false); err == nil && p.DNSSEC.State != "" {
			out[strings.ToLower(h.cfg.Domain)] = p.DNSSEC.State
		}
	}
	return out
}

// mailSyncOnce is one sync pass: build, compare with the last accepted
// document, send (removals at once, additions after mailDebounce), wait
// for a removal to apply and restart mail, then the DNS pass when due.
// It returns how long to sleep before the next pass without a kick.
func (h *Hub) mailSyncOnce(ctx context.Context) (next time.Duration) {
	s := &h.mailState
	s.pass.Lock()
	defer s.pass.Unlock()
	api, passWiring := h.mailClientSeq()
	if api == nil {
		return mailIdle
	}
	s.passWiring = passWiring
	// After every pass (so a slow mailctl never delays what it sent), in
	// the background without the sync lock: the start-time reconcile and
	// the restore check (a restore of mail voids every mail password,
	// also one the Hub outlived), at least every 60 s.
	defer func() { next = min(next, h.mailReconcileSoon(api)) }()
	// A draining unwire finishes once every domain is off.
	defer h.mailFinishUnwireIfDrained()
	s.mu.Lock()
	first := !s.loaded
	if first {
		s.loaded = true
		s.last, s.blind = h.loadMailLast()
	}
	startSeq := s.recSeq
	s.mu.Unlock()
	if first {
		h.mailWarnReservedInUse()
	}
	doc, err := h.mailBuild(ctx)
	if err != nil {
		h.mailLogOnce("mail: no state sent (nothing changes in mail): " + err.Error())
		return mailRetry
	}
	now := h.mailNow()
	// The last document is the current wiring's only: after a switch or
	// a re-wire the provider has none of it (core e2e-mail 11/12: the
	// unchanged directory sent nothing to the new provider), so the pass
	// starts without a baseline (blind: the first document counts as a
	// removal, judged by the Hub's own row baseline).
	//
	// Ruling R-SWITCH-BASE: another instance (a switch, a re-wire to a
	// different instance) starts empty and its wiring's void revoked
	// every credential: an EMPTY baseline, no removal computed, the first
	// document sent at once (the provider's own guard, against its live
	// accounts, still applies). The same instance re-wired keeps its
	// store: the last document stays the baseline, and one is sent. The
	// R-L8 row baseline is only for a lost mail-last.json.
	//
	// Ruling R-SWITCH-BASE-2: only the explicit mark (FreshInstance, set
	// once the wiring's own void completed) grants the empty baseline;
	// any other mismatch (an unknown or empty binding, a failed void) is
	// blind: the R-L8 row baseline judges the first document (fail
	// closed).
	h.mu.RLock()
	lastWiring := mailWiring{h.st.Mail.LastDocSeq, h.st.Mail.LastDocInstance}
	freshProvider := passWiring.instance != "" && h.st.Mail.FreshInstance == passWiring.instance
	h.mu.RUnlock()
	s.mu.Lock()
	switch {
	case freshProvider:
		s.last, s.blind = nil, false
	case s.last != nil && passWiring != lastWiring:
		s.last, s.blind = nil, true
	}
	last := s.last
	d := diffMail(last, doc)
	// No baseline (a first start, a lost mail-last.json): whoever left
	// meanwhile is unknown, so the first document counts as a removal.
	blind := s.blind && last == nil
	if blind {
		d.removal = true
	}
	s.mu.Unlock()
	// (The old provider's pending removal was dropped once, by the
	// wiring's void that set the fresh mark: a pending removal seen now
	// is the new provider's own refusal, kept (R-SWITCH-BASE-3).)
	// People back in mail_users leave the pending removal on every pass
	// (an emptied set clears it, a changed one voids its confirmation).
	if err := h.mailPendingReconcile(doc); err != nil {
		h.mailLogOnce("mail: saving the pending removal failed (nothing sent, retrying): " + err.Error())
		return mailRetry
	}
	s.mu.Lock()
	if !d.any() {
		s.addSince = time.Time{}
		s.mu.Unlock()
		return h.mailDNSIfDue(ctx, api, now, false)
	}
	if !d.removal && !d.other {
		if s.addSince.IsZero() {
			s.addSince = now
		}
		if due := s.addSince.Add(mailDebounce); now.Before(due) {
			s.mu.Unlock()
			return min(due.Sub(now), h.mailDNSIfDue(ctx, api, now, false))
		}
	}
	// A mass removal is confirmed only when every account that goes was
	// taken out by an admin through the Hub since the last accepted
	// document, within mailHubRemovalTTL — or an administrator confirmed
	// exactly the pending removal (ConfirmMailRemoval).
	confirm := d.removedAccounts > 0 && last != nil
	for _, uuid := range d.removedUUIDs {
		r, ok := s.hubRemoved[uuid]
		confirm = confirm && ok && r.gen == last.Generation && now.Sub(r.at) <= mailHubRemovalTTL
	}
	s.mu.Unlock()
	confirm = confirm || (d.removedAccounts > 0 && h.mailPendingConfirmed(d.removedUUIDs))
	// The Hub's own guard first (contract §19.5): a document removing
	// more than half of the last accepted one's accounts is never sent
	// unconfirmed, whatever the provider would do.
	if removed, needs := mailMassRemoval(doc, last); needs && !confirm {
		return h.mailMassRefused(ctx, api, last, doc, d, errHubMassRemoval(removed))
	}
	// No baseline (mail-last.json lost; Ruling R-L8): the provider API
	// has no account list, so the Hub's own record of accounts that
	// exist there (every person with an active mail password) is the
	// baseline, and a document removing any of them waits for an
	// administrator's confirmation.
	// A confirmation then sends confirm_mass_removal only when it is of
	// exactly the set the provider's own refusal named; otherwise the
	// provider's guard judges the rest (a guardless one gets only what
	// an administrator confirmed the Hub knows of).
	if last == nil && !freshProvider {
		h.mu.RLock()
		pr := h.st.Mail.PendingRemoval
		confirmed := pr != nil && pr.ConfirmedHash != "" && pr.ConfirmedHash == pendingHash(pr)
		var pending []string
		if pr != nil {
			pending = pendingUUIDs(pr.Accounts)
		}
		// The provider's own refusal is in play (R-SWITCH-BASE-4/4b): its
		// lists are authoritative (an old revoke_leave row the provider
		// no longer held isn't a removal), and every removal of this
		// document among what the provider then held must be inside the
		// pending set: one more is a new pending removal, held.
		fromProvider := pr != nil && pr.FromProvider
		var extra []state.MailPendingAccount
		if fromProvider {
			extra = h.mailProviderPendingExtraLocked(pr, doc, h.mailRowBaselineLocked())
		}
		h.mu.RUnlock()
		if len(extra) > 0 {
			if err := h.mailExtendPending(extra); err != nil {
				h.mailLogOnce("mail: the pending removal couldn't be saved (nothing done, retrying): " + err.Error())
				return mailRetry
			}
			h.mailLogOnce(fmt.Sprintf("mail: %d more mailboxes would go since the provider's refusal: the pending removal waits for a new confirmation", len(extra)))
			h.mailRevokePending(ctx, api)
			h.mailSetBlocked("the pending removal changed: it waits for an administrator's confirmation")
			return mailRetry
		}
		if !fromProvider {
			if removed := mailRemovedFromRows(h.mailRowBaseline(), doc); len(removed) > 0 {
				covered := confirmed
				for _, r := range removed {
					covered = covered && slices.Contains(pending, r.UUID)
				}
				if !covered {
					return h.mailMassRefused(ctx, api, nil, doc, d, errHubMassRemoval(removed))
				}
			}
		}
		s.mu.Lock()
		listed := s.blindListed
		s.mu.Unlock()
		kept := true
		s.mu.Lock()
		for _, u := range s.blindDoc {
			kept = kept && slices.ContainsFunc(doc.Accounts, func(a mailprovider.Account) bool { return a.UUID == u })
		}
		s.mu.Unlock()
		// A provider refusal's removals were judged above against its
		// persisted lists (kept is that check's in-memory form).
		confirm = confirmed && (fromProvider || (len(listed) > 0 && slices.Equal(listed, pending) && kept))
	}

	gen, err := h.mailSend(ctx, api, doc, confirm)
	if errors.Is(err, errMailPendingHold) || errors.Is(err, errMailNoTLS) {
		return mailRetry
	}
	if err != nil {
		if isMassRemoval(err) {
			var ae *mailprovider.APIError
			if last == nil && errors.As(err, &ae) {
				ids := make([]string, 0, len(ae.Removed))
				for _, r := range ae.Removed {
					ids = append(ids, r.UUID)
				}
				sort.Strings(ids)
				docIDs := make([]string, 0, len(doc.Accounts))
				for _, a := range doc.Accounts {
					docIDs = append(docIDs, a.UUID)
				}
				s.mu.Lock()
				s.blindListed, s.blindDoc = ids, docIDs
				s.mu.Unlock()
			}
			return h.mailMassRefused(ctx, api, last, doc, d, err)
		}
		wait := mailRetry
		if d.removal {
			// A removal must reach mailctl within seconds: 2 s, doubling.
			s.mu.Lock()
			s.removalRetry = min(max(2*s.removalRetry, 2*time.Second), mailRetry)
			wait = s.removalRetry
			s.mu.Unlock()
		}
		h.mailLogOnce(fmt.Sprintf("mail: the state was not sent (the next try in %s): %v", wait, err))
		return wait
	}
	h.mailLogOnce("")
	s.mu.Lock()
	sent := *doc
	sent.Generation, sent.ConfirmMassRemoval = gen, confirm
	prevGen := -1
	if last != nil {
		prevGen = last.Generation
	}
	s.last, s.blind, s.removalRetry = &sent, false, 0
	s.addSince = time.Time{}
	// Admin removals recorded during this pass, after its document was
	// built, keep counting at the new generation; every other entry is
	// spent (those it removed, those from before the accepted document).
	gone := map[string]bool{}
	for _, id := range d.removedUUIDs {
		gone[id] = true
	}
	kept := map[string]hubRemoval{}
	for id, r := range s.hubRemoved {
		if gone[id] || r.gen != prevGen || r.seq <= startSeq {
			continue
		}
		r.gen = gen
		kept[id] = r
	}
	s.hubRemoved = kept
	if !s.reconciled {
		s.reconAll = true
	}
	s.mu.Unlock()
	h.saveMailLast(&sent, s.passWiring)
	h.mailSetBlocked("")
	settleErr := h.mailPendingSettled()
	if d.removal {
		h.mailWaitApplied(ctx, api, gen)
		// Stalwart keeps open sessions through the change: restart mail
		// after every removal (contract §6), also when the wait timed out.
		h.mailRestart(ctx, "a removal")
		if len(d.removedUUIDs) > 0 {
			// The holder left: mailctl destroys their passwords before it
			// disables the account (and retries until it has).
			h.mailMarkLeft(d.removedUUIDs)
		}
	}
	if settleErr != nil {
		h.mailLogOnce("mail: clearing the pending removal failed (retrying): " + settleErr.Error())
		return mailRetry
	}
	h.mailRetireMainLocked(doc)
	return h.mailDNSIfDue(ctx, api, now, true)
}

// mailSend saves the next generation, then PUTs the document. A 409
// "generation not greater" (state.yaml older than mailctl's) moves the
// generation past mailctl's and tries once more.
// errMailNoTLS: no certificate key posted yet; nothing is sent.
var errMailNoTLS = errors.New("no mail certificate key posted yet")

func (h *Hub) mailSend(ctx context.Context, api MailAPI, doc *mailprovider.MailState, confirm bool) (int, error) {
	// An unconfirmed pending removal holds every document that still
	// omits one of its accounts (security review of R-L8): only an
	// administrator's confirmation of exactly that set releases it.
	// (A document confirmed by the Hub's own removal records, confirm,
	// is the reviewed second path: every account that goes was taken out
	// by an administrator through the Hub.)
	// No certificate key posted yet (core: the provider refuses a
	// document whose tls.spki_sha256 isn't 1–2 keys): nothing is sent
	// until `./portcullis mail rotate` posts one (POST /host/mail/tls).
	if len(doc.TLS.SPKISHA256) == 0 {
		h.mailLogOnce("mail: no state sent yet: the mail certificate's key isn't posted (./portcullis mail rotate on the host posts it)")
		return 0, errMailNoTLS
	}
	if who := h.mailPendingOmitted(doc); who != "" && !confirm {
		h.mailSetBlocked("the pending removal of " + who + " waits for an administrator's confirmation: nothing that removes them is sent")
		return 0, errMailPendingHold
	}
	for try := 0; try < 2; try++ {
		h.mu.Lock()
		h.st.Mail.Generation++
		gen := h.st.Mail.Generation
		err := h.saveStateLocked()
		h.mu.Unlock()
		if err != nil {
			return 0, err
		}
		out := *doc
		out.Generation, out.ConfirmMassRemoval = gen, confirm
		_, err = api.PutState(ctx, &out)
		if err == nil {
			return gen, nil
		}
		if mailprovider.StatusOf(err) != 409 || try > 0 || isMassRemoval(err) {
			return 0, err
		}
		st, serr := api.State(ctx)
		if serr != nil {
			return 0, err
		}
		h.mu.Lock()
		h.st.Mail.Generation = max(h.st.Mail.Generation, st.Generation, st.AppliedGeneration)
		h.mu.Unlock()
	}
	return 0, errors.New("mail: generation refused twice")
}

// mailWaitApplied polls GET /v1/state until applied_generation reaches
// gen, at most mailApplyWait.
func (h *Hub) mailWaitApplied(ctx context.Context, api MailAPI, gen int) bool {
	s := &h.mailState
	s.mu.Lock()
	wait, poll := s.applyWait, s.applyPoll
	s.mu.Unlock()
	if wait <= 0 {
		wait = mailApplyWait
	}
	if poll <= 0 {
		poll = mailApplyPoll
	}
	deadline := time.Now().Add(wait)
	for {
		if st, err := api.State(ctx); err == nil && st.AppliedGeneration >= gen {
			return true
		}
		if time.Now().Add(poll).After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(poll):
		}
	}
}

// isMassRemoval: mailctl's 409 for a document removing more than half
// the accounts, by its error_kind "mass_removal" only (never the text;
// any other 409 is the generation's).
func isMassRemoval(err error) bool {
	var ae *mailprovider.APIError
	return errors.As(err, &ae) && ae.Status == http.StatusConflict && ae.Kind == mailprovider.ErrorKindMassRemoval
}

// mailRetireMainLocked: the main domain turned off is no longer sent once
// a document with it off was accepted (the CLI owns its DNS).
func (h *Hub) mailRetireMainLocked(doc *mailprovider.MailState) {
	main := strings.ToLower(h.cfg.Domain)
	for _, d := range doc.Domains {
		if d.Name != main || d.Mail != mailprovider.MailOff {
			continue
		}
		h.mu.Lock()
		if e, ok := h.st.Mail.Domains[main]; ok && !e.Enabled && !e.Draining && !e.Retired {
			e.Retired = true
			h.st.Mail.Domains[main] = e
			h.saveLocked()
		}
		h.mu.Unlock()
	}
}

// mailForgetPerson drops a deleted person's aliases (those set while the
// username was theirs): a re-created username starts with none.
func (h *Hub) mailForgetPerson(user string) {
	user = strings.ToLower(user)
	h.mu.Lock()
	defer h.mu.Unlock()
	changed := false
	for id, al := range h.st.Mail.Aliases {
		if strings.EqualFold(al.Username, user) {
			delete(h.st.Mail.Aliases, id)
			changed = true
		}
	}
	if changed {
		h.saveLocked()
	}
}
