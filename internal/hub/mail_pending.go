package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/mailprovider"
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

// mailMassRefused handles mailctl's mass-removal 409 (refusal) for doc
// (d: the diff from last): records the pending removal (from last, or on
// a blind pass from the 409's own removed list), revokes the departed
// people's passwords (each until it succeeds) and restarts mail, then
// sends the fallback document. Anything it can't do safely blocks the
// sync (mail_sync_blocked) and sends nothing. It returns the next sleep.
func (h *Hub) mailMassRefused(ctx context.Context, api MailAPI, last, doc *mailprovider.MailState, d mailDiff, refusal error) time.Duration {
	var gone []state.MailPendingAccount
	if last != nil {
		for _, a := range last.Accounts {
			for _, id := range d.removedUUIDs {
				if a.UUID == id {
					gone = append(gone, state.MailPendingAccount{Username: a.Username, UUID: a.UUID})
				}
			}
		}
	} else {
		// No baseline: mailctl's own list of the accounts it refused to
		// remove is the only safe source.
		var ae *mailprovider.APIError
		if errors.As(refusal, &ae) {
			for _, r := range ae.Removed {
				if r.UUID != "" && r.Username != "" {
					gone = append(gone, state.MailPendingAccount{Username: strings.ToLower(r.Username), UUID: r.UUID})
				}
			}
		}
	}
	if len(gone) == 0 {
		h.mailSetBlocked("mailctl refused a mass removal and the Hub can't tell whose mailboxes it would remove (no baseline, and mailctl named none): nothing is sent until it can")
		return mailRetry
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].Username < gone[j].Username })
	if err := h.mailRecordPending(gone); err != nil {
		h.mailLogOnce("mail: the pending removal couldn't be saved (nothing done, retrying): " + err.Error())
		return mailRetry
	}
	h.mailLogOnce(fmt.Sprintf("mail: mailctl refused removing %d mailboxes at once: waiting for an administrator's confirmation (their mail passwords are revoked meanwhile)", len(gone)))
	if !h.mailRevokePending(ctx, api) {
		return mailRetry
	}

	// Every other change: the document with the departed mailboxes kept.
	if last == nil {
		h.mailSetBlocked("no baseline document: every other mail change waits until the pending removal is confirmed or the people are back in mail_users")
		return mailRetry
	}
	fb := mailFallback(last, doc, d.removedUUIDs)
	if fb == nil {
		h.mailSetBlocked("a departed person's mailbox can't be kept meanwhile (their name or primary address is someone else's now): every other mail change waits until the pending removal is confirmed")
		return mailRetry
	}
	h.mailSetBlocked("")
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
	s := &h.mailState
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

// mailRevokePending revokes the mail passwords of every pending account
// not yet revoked, marks each one revoked once mailctl confirmed every
// password, and restarts mail when any was. false: the state couldn't be
// saved (the pass fails).
func (h *Hub) mailRevokePending(ctx context.Context, api MailAPI) bool {
	h.mu.RLock()
	var todo []state.MailPendingAccount
	if p := h.st.Mail.PendingRemoval; p != nil {
		for _, a := range p.Accounts {
			if !a.Revoked {
				todo = append(todo, a)
			}
		}
	}
	h.mu.RUnlock()
	revoked := map[string]string{}
	for _, a := range todo {
		live, err := api.Credentials(ctx, a.UUID)
		if err != nil && mailprovider.StatusOf(err) != http.StatusNotFound {
			log.Printf("mail: revoking %s's mail passwords (pending removal): %v", a.Username, err)
			continue
		}
		ok := true
		for _, c := range live {
			if err := api.RevokeCredential(ctx, a.UUID, c.ID); err != nil {
				log.Printf("mail: revoking %s's mail password %s (pending removal): %v", a.Username, c.ID, err)
				ok = false
			}
		}
		if ok {
			revoked[a.Username] = a.UUID
		}
	}
	if len(revoked) == 0 {
		return true
	}
	h.mu.Lock()
	p := h.st.Mail.PendingRemoval
	var undo []int
	if p != nil {
		for i := range p.Accounts {
			if _, ok := revoked[p.Accounts[i].Username]; ok && revoked[p.Accounts[i].Username] == p.Accounts[i].UUID && !p.Accounts[i].Revoked {
				p.Accounts[i].Revoked = true
				undo = append(undo, i)
			}
		}
	}
	err := h.saveStateLocked()
	if err != nil && p != nil {
		for _, i := range undo {
			p.Accounts[i].Revoked = false
		}
	}
	h.mu.Unlock()
	h.mailMarkLeft(revoked)
	h.mailRestart(ctx, "revoking the mail passwords of a pending removal")
	return err == nil
}

// mailSetBlocked records why the sync sends nothing ("" clears it): the
// doctor's mail_sync_blocked.
func (h *Hub) mailSetBlocked(why string) {
	s := &h.mailState
	s.mu.Lock()
	s.blocked = why
	s.mu.Unlock()
	if why != "" {
		h.mailLogOnce("mail: sync blocked: " + why)
	}
}

// MailSyncBlocked is why the mail sync sends nothing ("" = it isn't).
func (h *Hub) MailSyncBlocked() string {
	s := &h.mailState
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocked
}

// mailFallback is doc with the accounts removed (by uuid) put back as last
// had them: their addresses that are still on a live domain of doc and
// unused there; nil when one can't keep its primary address.
func mailFallback(last, doc *mailprovider.MailState, removed map[string]string) *mailprovider.MailState {
	fb := *doc
	fb.Accounts = append([]mailprovider.Account(nil), doc.Accounts...)
	fb.ConfirmMassRemoval = false
	live := map[string]bool{}
	for _, dm := range doc.Domains {
		if dm.Mail != mailprovider.MailOff {
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
		if slices.ContainsFunc(fb.Accounts, func(x mailprovider.Account) bool { return x.Username == a.Username }) {
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

// mailRecordPending persists the pending removal: the same set keeps
// what is recorded (revoked flags, a confirmation); a different set is a
// new pending removal (a new Since, no confirmation). A save failure
// leaves the old state and is returned (the pass fails).
func (h *Hub) mailRecordPending(gone []state.MailPendingAccount) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.st.Mail.PendingRemoval
	if p != nil && slices.Equal(pendingUUIDs(p.Accounts), pendingUUIDs(gone)) {
		return nil
	}
	h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: h.mailNow(), Accounts: gone}
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.PendingRemoval = p
		return err
	}
	return nil
}

func pendingUUIDs(a []state.MailPendingAccount) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, x.UUID)
	}
	sort.Strings(out)
	return out
}

// pendingHash binds a confirmation to exactly p's set and Since.
func pendingHash(p *state.MailPendingRemoval) string {
	return doctor.Digest(struct {
		UUIDs []string
		Since string
	}{pendingUUIDs(p.Accounts), p.Since.UTC().Format(time.RFC3339Nano)})
}

// mailPendingConfirmed: an administrator confirmed exactly the pending
// set as it is now, and the document removes exactly that set.
func (h *Hub) mailPendingConfirmed(removed map[string]string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p := h.st.Mail.PendingRemoval
	if p == nil || p.ConfirmedHash == "" || p.ConfirmedHash != pendingHash(p) {
		return false
	}
	ids := make([]string, 0, len(removed))
	for _, id := range removed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return slices.Equal(ids, pendingUUIDs(p.Accounts))
}

// mailPendingReconcile drops the pending accounts that are back in
// mail_users (in doc); an emptied set clears the pending removal, any
// change voids a confirmation. Their passwords stay revoked (they make
// new ones). A save failure is returned (the pass fails).
func (h *Hub) mailPendingReconcile(doc *mailprovider.MailState) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.st.Mail.PendingRemoval
	if p == nil {
		return nil
	}
	back := map[string]bool{}
	for _, a := range doc.Accounts {
		back[a.UUID] = true
	}
	var keep []state.MailPendingAccount
	for _, a := range p.Accounts {
		if !back[a.UUID] {
			keep = append(keep, a)
		}
	}
	if len(keep) == len(p.Accounts) {
		return nil
	}
	old := *p
	if len(keep) == 0 {
		h.st.Mail.PendingRemoval = nil
	} else {
		h.st.Mail.PendingRemoval = &state.MailPendingRemoval{Since: p.Since, Accounts: keep}
	}
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.PendingRemoval = &old
		return err
	}
	return nil
}

// mailPendingSettled clears the pending removal once a normal document
// (the directory as it is, not the fallback) was accepted: its accounts
// are gone (confirmed, or no longer a mass removal) or back. A save
// failure keeps it and is returned.
func (h *Hub) mailPendingSettled() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.st.Mail.PendingRemoval
	if p == nil {
		return nil
	}
	h.st.Mail.PendingRemoval = nil
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.PendingRemoval = p
		return err
	}
	return nil
}

// MailPendingView is Settings → Mail's pending_removal.
type MailPendingView struct {
	Since time.Time `json:"since"`
	// Accounts: each with revoked (their mail passwords are revoked;
	// false: revoking failed, retrying).
	Accounts  []state.MailPendingAccount `json:"accounts"`
	Confirmed bool                       `json:"confirmed"`
}

// mailPendingView is the pending removal (nil: none). Caller holds mu.
func (h *Hub) mailPendingViewLocked() *MailPendingView {
	p := h.st.Mail.PendingRemoval
	if p == nil {
		return nil
	}
	return &MailPendingView{Since: p.Since, Accounts: append([]state.MailPendingAccount{}, p.Accounts...), Confirmed: p.ConfirmedHash != "" && p.ConfirmedHash == pendingHash(p)}
}

// ConfirmMailRemoval confirms the pending mass removal: uuids must be
// exactly its accounts (409 otherwise: it changed since it was shown).
// The next document carries confirm_mass_removal for exactly them.
// Audited mail.confirm_removal.
func (h *Hub) ConfirmMailRemoval(ctx context.Context, uuids []string, actor directory.Actor) (err error) {
	if err := h.mailWriteGuard(); err != nil {
		return err
	}
	defer func() { h.auditOp(actor, "mail.confirm_removal", "mail", fmt.Sprintf("count=%d", len(uuids)), err) }()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusBadRequest, "no signed-in user to audit the change as")
	}
	if err := aiUnconfirmed(actor, "confirming a mass removal of mailboxes"); err != nil {
		return err
	}
	// Full administrators only (lldap_admin, one predicate): never a
	// delegate, whatever route or fix called it.
	if !h.isGlobalAdmin(ctx, actor.User) {
		return statusErr(http.StatusForbidden, "%s", mailNotAdminText)
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
	p.ConfirmedHash = pendingHash(p)
	if err := h.saveStateLocked(); err != nil {
		p.ConfirmedHash = ""
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

// isGlobalAdmin is the one "full administrator" test for mail (I2 /
// M3): membership of lldap_admin, the global admin group, read from the
// directory now; unknown = no (fail closed). Delegates and the other
// protected groups (lldap_password_manager, app admins) never are.
func (h *Hub) isGlobalAdmin(ctx context.Context, user string) bool {
	if strings.TrimSpace(user) == "" {
		return false
	}
	m, err := h.membership(ctx)
	return err == nil && isLLDAPAdmin(m, strings.ToLower(user))
}
