package hub

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/mailctl"
	"github.com/portcullis/hub/internal/state"
)

// A refused mass removal (contract §19.5, controller ruling): mailctl
// refuses a document that removes more than half the live accounts (it
// fails closed, e.g. against an LDAP outage that empties mail_users).
// The guard never keeps people's access: while the removal waits for an
// administrator's confirmation, the Hub revokes the departed people's
// mail passwords one by one, restarts mail, and sends every other change
// in a document that still lists their (now password-less) mailboxes.
// Only the mailbox removal (parking) waits. The pending removal is in
// state.yaml (mail.pending_removal), so it survives Hub restarts; doctor
// mail_mass_removal_pending and Settings → Mail show it and confirm it.

// mailMassRefused handles mailctl's mass-removal 409 for doc (d: the diff
// from last): records the pending removal, revokes the departed people's
// passwords (once each) and restarts mail, then sends the fallback
// document. It returns the next pass's sleep.
func (h *Hub) mailMassRefused(ctx context.Context, api MailAPI, last, doc *mailctl.MailState, d mailDiff) time.Duration {
	if last == nil {
		return mailRetry
	}
	var gone []mailctl.Account
	for _, a := range last.Accounts {
		for _, id := range d.removedUUIDs {
			if a.UUID == id {
				gone = append(gone, a)
			}
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].Username < gone[j].Username })
	h.mailRecordPending(gone)
	h.mailLogOnce(fmt.Sprintf("mail: mailctl refused removing %d of %d mailboxes at once: waiting for an administrator's confirmation (their mail passwords are revoked meanwhile)", len(gone), len(last.Accounts)))

	// Revoke the departed people's mail passwords now.
	s := &h.mailState
	revoked := map[string]string{}
	for _, a := range gone {
		s.mu.Lock()
		done := s.pendingRevoked[a.UUID]
		s.mu.Unlock()
		if done {
			continue
		}
		live, err := api.Credentials(ctx, a.Username)
		if err != nil && mailctl.StatusOf(err) != http.StatusNotFound {
			log.Printf("mail: revoking %s's mail passwords (pending removal): %v", a.Username, err)
			continue
		}
		failed := false
		for _, c := range live {
			if err := api.RevokeCredential(ctx, a.Username, c.ID); err != nil && mailctl.StatusOf(err) != http.StatusNotFound {
				log.Printf("mail: revoking %s's mail password %s (pending removal): %v", a.Username, c.ID, err)
				failed = true
			}
		}
		if failed {
			continue
		}
		s.mu.Lock()
		if s.pendingRevoked == nil {
			s.pendingRevoked = map[string]bool{}
		}
		s.pendingRevoked[a.UUID] = true
		s.mu.Unlock()
		revoked[a.Username] = a.UUID
	}
	if len(revoked) > 0 {
		h.mailMarkLeft(revoked)
		h.mailRestart(ctx, "revoking the mail passwords of a pending removal")
	}

	// Every other change: the document with the departed mailboxes kept.
	fb := mailFallback(last, doc, d.removedUUIDs)
	if fb == nil {
		return mailRetry
	}
	d2 := diffMail(last, fb)
	if !d2.any() {
		return mailRetry
	}
	gen, err := h.mailSend(ctx, api, fb, false)
	if err != nil {
		h.mailLogOnce("mail: the document without the pending removal was not sent either: " + err.Error())
		return mailRetry
	}
	sent := *fb
	sent.Generation = gen
	s.mu.Lock()
	s.last, s.blind = &sent, false
	s.mu.Unlock()
	h.saveMailLast(&sent)
	if d2.removal {
		h.mailWaitApplied(ctx, api, gen)
		h.mailRestart(ctx, "a removal")
		if len(d2.removedUUIDs) > 0 {
			h.mailMarkLeft(d2.removedUUIDs)
		}
	}
	return mailRetry
}

// mailFallback is doc with the accounts removed (by uuid) put back as last
// had them: their addresses that are still on a live domain of doc and
// unused there; nil when one can't keep its primary address.
func mailFallback(last, doc *mailctl.MailState, removed map[string]string) *mailctl.MailState {
	fb := *doc
	fb.Accounts = append([]mailctl.Account(nil), doc.Accounts...)
	fb.ConfirmMassRemoval = false
	live := map[string]bool{}
	for _, dm := range doc.Domains {
		if dm.Mail != mailctl.MailOff {
			live[dm.Name] = true
		}
	}
	used := map[string]bool{}
	for _, a := range doc.Accounts {
		for _, x := range a.Addresses {
			used[x] = true
		}
	}
	for _, x := range doc.Aliases {
		used[x.Address] = true
	}
	for _, l := range doc.Lists {
		used[l.Address] = true
	}
	ids := map[string]bool{}
	for _, id := range removed {
		ids[id] = true
	}
	for _, a := range last.Accounts {
		if !ids[a.UUID] {
			continue
		}
		if slices.ContainsFunc(fb.Accounts, func(x mailctl.Account) bool { return x.Username == a.Username }) {
			// The username is someone else's now: their old mailbox can
			// only wait for the confirmation.
			return nil
		}
		k := a
		k.Addresses = nil
		for i, x := range a.Addresses {
			_, dom, _ := strings.Cut(x, "@")
			if used[x] || !live[dom] || (i == 0 && dom != doc.PrimaryDomain) {
				if i == 0 {
					return nil
				}
				continue
			}
			used[x] = true
			k.Addresses = append(k.Addresses, x)
		}
		fb.Accounts = append(fb.Accounts, k)
	}
	sort.Slice(fb.Accounts, func(i, j int) bool { return fb.Accounts[i].Username < fb.Accounts[j].Username })
	return &fb
}

// mailRecordPending persists the pending removal (a changed account set
// drops an earlier confirmation).
func (h *Hub) mailRecordPending(gone []mailctl.Account) {
	accts := make([]state.MailPendingAccount, 0, len(gone))
	for _, a := range gone {
		accts = append(accts, state.MailPendingAccount{Username: a.Username, UUID: a.UUID})
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.st.Mail.PendingRemoval
	if p != nil && slices.Equal(pendingUUIDs(p.Accounts), pendingUUIDs(accts)) {
		return
	}
	h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: h.mailNow(), Accounts: accts}
	h.saveLocked()
}

func pendingUUIDs(a []state.MailPendingAccount) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, x.UUID)
	}
	sort.Strings(out)
	return out
}

// mailPendingConfirmed: an administrator confirmed exactly a pending
// removal that covers every account removed (by uuid).
func (h *Hub) mailPendingConfirmed(removed map[string]string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p := h.st.Mail.PendingRemoval
	if p == nil || len(p.Confirmed) == 0 {
		return false
	}
	for _, id := range removed {
		if !slices.Contains(p.Confirmed, id) {
			return false
		}
	}
	return true
}

// mailPendingSettled clears the pending removal once a normal document
// (the directory as it is, not the fallback) was accepted: its accounts
// are either gone (confirmed, or no longer a mass removal) or back in
// mail_users.
func (h *Hub) mailPendingSettled(_ *mailctl.MailState) {
	h.mu.Lock()
	p := h.st.Mail.PendingRemoval
	if p != nil {
		h.st.Mail.PendingRemoval = nil
		h.saveLocked()
	}
	h.mu.Unlock()
	if p != nil {
		s := &h.mailState
		s.mu.Lock()
		s.pendingRevoked = nil
		s.mu.Unlock()
	}
}

// MailPendingView is Settings → Mail's pending_removal.
type MailPendingView struct {
	Since     time.Time                  `json:"since"`
	Accounts  []state.MailPendingAccount `json:"accounts"`
	Confirmed bool                       `json:"confirmed"`
}

// mailPendingView is the pending removal (nil: none). Caller holds mu.
func (h *Hub) mailPendingViewLocked() *MailPendingView {
	p := h.st.Mail.PendingRemoval
	if p == nil {
		return nil
	}
	return &MailPendingView{Since: p.Since, Accounts: append([]state.MailPendingAccount{}, p.Accounts...), Confirmed: len(p.Confirmed) > 0}
}

// ConfirmMailRemoval confirms the pending mass removal: uuids must be
// exactly its accounts (409 otherwise: it changed since it was shown).
// The next document carries confirm_mass_removal for exactly them.
// Audited mail.confirm_removal.
func (h *Hub) ConfirmMailRemoval(ctx context.Context, uuids []string, actor directory.Actor) (err error) {
	defer func() { h.auditOp(actor, "mail.confirm_removal", "mail", fmt.Sprintf("count=%d", len(uuids)), err) }()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusBadRequest, "no signed-in user to audit the change as")
	}
	if err := aiUnconfirmed(actor, "confirming a mass removal of mailboxes"); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.st.Mail.PendingRemoval
	if p == nil {
		return statusErr(http.StatusConflict, "no mass removal is waiting")
	}
	want := slices.Clone(uuids)
	sort.Strings(want)
	if !slices.Equal(want, pendingUUIDs(p.Accounts)) {
		return statusErr(http.StatusConflict, "the pending removal changed since it was shown: look again")
	}
	p.Confirmed = want
	if err := h.saveStateLocked(); err != nil {
		p.Confirmed = nil
		return err
	}
	h.TriggerMailSync()
	return nil
}

// mailWarnReservedInUse logs instances on a hostname mail reserves (at
// the first sync pass: core mail may have been turned on by the CLI).
func (h *Hub) mailWarnReservedInUse() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	doms := h.mailDomainsLocked(true)
	for _, e := range doms {
		if id, host := h.mailReservedUserLocked(e); id != "" {
			log.Printf("mail: instance %s uses %s, which mail reserves on %s: move it to another hostname", id, host, e)
		}
	}
	if hn := h.mailCore().Hostname; hn != "" {
		for i := range h.instances {
			for _, host := range h.instances[i].Hosts {
				if n := NormalizeHost(host); n == hn || strings.HasSuffix(n, "."+hn) {
					log.Printf("mail: instance %s uses %s, the mail server's hostname: move it to another hostname", h.instances[i].ID, n)
				}
			}
		}
	}
}

// isFullAdmin: user is in an administrator group (not a delegate), read
// from the directory now; unknown = no (fail closed).
func (h *Hub) isFullAdmin(ctx context.Context, user string) bool {
	if strings.TrimSpace(user) == "" {
		return false
	}
	m, err := h.membership(ctx)
	return err == nil && m.Administrators[strings.ToLower(user)]
}
