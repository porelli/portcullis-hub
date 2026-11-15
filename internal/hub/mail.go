package hub

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/mailctl"
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

	mu sync.Mutex
	// last is the last document mailctl accepted (nil: none since start).
	last *mailctl.MailState
	// addSince: when the pending additions were first seen (zero: none).
	addSince time.Time
	// hubRemoved: people an admin took out of mail_users (or deleted)
	// through the Hub since the last accepted document.
	hubRemoved map[string]bool
	// noted: the build notes already logged (each once).
	noted map[string]bool
	// lastErr: the last logged failure (each once in a row).
	lastErr string
	// dnsAt: the last mail-set pass.
	dnsAt time.Time
	// onRemoved (Task 15): called with the usernames whose accounts left
	// an accepted and applied document.
	onRemoved func(ctx context.Context, users []string)
}

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

// MailMemberRemoved records an admin's removal of user from group
// (directory.Service.MemberRemoved): a shrink of mail_users made through
// the Hub may confirm a mass removal (contract §19.5).
func (h *Hub) MailMemberRemoved(group, user string) {
	if !strings.EqualFold(group, MailUsersGroup) {
		return
	}
	h.mailRecordHubRemoval(user)
}

func (h *Hub) mailRecordHubRemoval(user string) {
	s := &h.mailState
	s.mu.Lock()
	if s.hubRemoved == nil {
		s.hubRemoved = map[string]bool{}
	}
	s.hubRemoved[strings.ToLower(user)] = true
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
func (h *Hub) mailBuild(ctx context.Context) (*mailctl.MailState, error) {
	m, err := h.membership(ctx)
	if err != nil {
		// A directory error sends nothing (contract §19.5).
		return nil, err
	}
	dnssec := h.mailDNSSEC(ctx)
	h.mu.RLock()
	in := MailBuildInput{Membership: m, Settings: h.st.Mail, MainDomain: h.cfg.Domain, CoreOn: true, DNSSEC: dnssec,
		LocalNetworks: prefixStrings(h.localNetworksLocked()), Generation: h.st.Mail.Generation}
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
func (h *Hub) mailSyncOnce(ctx context.Context) time.Duration {
	s := &h.mailState
	s.pass.Lock()
	defer s.pass.Unlock()
	api := h.mailClient()
	if api == nil {
		return mailIdle
	}
	doc, err := h.mailBuild(ctx)
	if err != nil {
		h.mailLogOnce("mail: no state sent (nothing changes in mail): " + err.Error())
		return mailRetry
	}
	now := h.mailNow()
	s.mu.Lock()
	last := s.last
	d := diffMail(last, doc)
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
	// taken out by an admin through the Hub.
	confirm := d.removedAccounts > 0
	for _, u := range d.removedUsers {
		confirm = confirm && s.hubRemoved[u]
	}
	s.mu.Unlock()

	gen, err := h.mailSend(ctx, api, doc, confirm)
	if err != nil {
		h.mailLogOnce("mail: the state was not sent (the next try in 30 s): " + err.Error())
		return mailRetry
	}
	h.mailLogOnce("")
	s.mu.Lock()
	sent := *doc
	sent.Generation, sent.ConfirmMassRemoval = gen, confirm
	s.last = &sent
	s.addSince = time.Time{}
	for _, u := range d.removedUsers {
		delete(s.hubRemoved, u)
	}
	onRemoved := s.onRemoved
	s.mu.Unlock()
	if d.removal {
		applied := h.mailWaitApplied(ctx, api, gen)
		// Stalwart keeps open sessions through the change: restart mail
		// after every removal (contract §6), also when the wait timed out.
		h.mailRestart(ctx, "a removal")
		if applied && onRemoved != nil && len(d.removedUsers) > 0 {
			onRemoved(ctx, d.removedUsers)
		}
	}
	h.mailRetireMainLocked(doc)
	return h.mailDNSIfDue(ctx, api, now, true)
}

// mailSend saves the next generation, then PUTs the document. A 409
// "generation not greater" (state.yaml older than mailctl's) moves the
// generation past mailctl's and tries once more.
func (h *Hub) mailSend(ctx context.Context, api MailAPI, doc *mailctl.MailState, confirm bool) (int, error) {
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
		if mailctl.StatusOf(err) != 409 || try > 0 || !strings.Contains(err.Error(), "generation") {
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
	deadline := time.Now().Add(mailApplyWait)
	for {
		if st, err := api.State(ctx); err == nil && st.AppliedGeneration >= gen {
			return true
		}
		if time.Now().Add(mailApplyPoll).After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(mailApplyPoll):
		}
	}
}

// mailRetireMainLocked: the main domain turned off is no longer sent once
// a document with it off was accepted (the CLI owns its DNS).
func (h *Hub) mailRetireMainLocked(doc *mailctl.MailState) {
	main := strings.ToLower(h.cfg.Domain)
	for _, d := range doc.Domains {
		if d.Name != main || d.Mail != mailctl.MailOff {
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
