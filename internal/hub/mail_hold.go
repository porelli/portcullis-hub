package hub

import (
	"context"
	"log"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The template-change hold (contract §19.9 "Template updates hold", P4):
// after every source sync (and at start) the wired instance's block hash
// is recomputed; a change, or a template that no longer validates, holds
// the provider: no up, re-render or recreate is issued for it, every
// lifecycle path that needs an up renders void mode and runs no void, and
// the mail routes answer as for an unreachable provider, until a guarded
// re-confirm. A re-confirm of the same instance voids no mail password
// (the ledger's ruling: the same mailbox store).

// MailHoldText is the hold's reason (doctor mail_provider_refused).
const (
	MailHoldText    = "the mail provider's template changed: review and confirm on its Mail tab"
	MailInvalidText = "the mail provider's template no longer validates: fix or update it, then confirm on its Mail tab"
	// MailSourceChangedText: its source now points at another repository
	// (M7): no re-confirm, only an unwire and a new wiring (a void).
	MailSourceChangedText = "the mail provider's template source now points at another repository: unwire it and wire it again"
)

// mailSourceURLLocked is source name's URL ("" when unknown). Caller
// must hold mu.
func (h *Hub) mailSourceURLLocked(name string) string {
	for _, s := range h.st.Sources {
		if s.Name == name {
			return s.URL
		}
	}
	return ""
}

// OpMailRewire is the re-confirm op.
const OpMailRewire = "mail_rewire"

// mailHoldReasonLocked is why the wired provider must be held ("" =
// its tree still matches the recorded hash). Caller must hold mu.
func (h *Hub) mailHoldReasonLocked() string {
	p := h.st.Mail.Provider
	if p == nil {
		return ""
	}
	t := h.findLocked(p.Instance)
	if t == nil || t.Manifest.Mail == nil || !t.MailProvider {
		return MailInvalidText
	}
	if t.Source != p.Source || (p.SourceURL != "" && h.mailSourceURLLocked(t.Source) != p.SourceURL) {
		return MailSourceChangedText
	}
	hash, err := templates.MailBlockHash(t.Path, t.Manifest.Mail, t.ReadCompose())
	if err != nil {
		return MailInvalidText
	}
	if hash != p.BlockHash {
		return MailHoldText
	}
	return ""
}

// mailHoldGateLocked is the hold in the start primitive (Ruling R-HH3):
// an up of the wired provider is refused (409) while it is held or its
// tree on disk no longer matches the confirmed hash (the hold is then
// recorded), on every up path — boot restarts, reconcile, owed restarts,
// the void retry, doctor fixes. The stored hold is only a cache of this.
// Caller must hold mu (write).
func (h *Hub) mailHoldGateLocked(t *templates.Template) error {
	p := h.st.Mail.Provider
	if p == nil || p.Instance != t.ID {
		return nil
	}
	h.checkMailHoldLocked()
	if hd := h.st.Mail.Held; hd != nil {
		return statusErr(http.StatusConflict, "%s", hd.Reason)
	}
	return nil
}

// checkMailHoldLocked holds the wired provider when its template changed
// (saved; no up). Caller must hold mu (write).
func (h *Hub) checkMailHoldLocked() bool {
	if h.st.Mail.Provider == nil || h.st.Mail.Held != nil {
		return false
	}
	why := h.mailHoldReasonLocked()
	if why == "" {
		return false
	}
	h.st.Mail.Held = &state.MailHold{Reason: why, Since: h.mailNow().UTC()}
	h.saveLocked()
	log.Printf("mail: %s is held: %s (no up until an administrator confirms)", h.st.Mail.Provider.Instance, why)
	return true
}

// checkMailHold is checkMailHoldLocked under mu.
func (h *Hub) checkMailHold() {
	h.mu.Lock()
	held := h.checkMailHoldLocked()
	h.mu.Unlock()
	if held {
		h.writeMailTargets()
	}
}

func mailRewirePlan() []Step {
	return []Step{
		{Key: StepMailRecord, Label: "Recording the confirmed template"},
		{Key: StepMailVoid, Label: "Voiding every mail password (only for a restore still owed)"},
		{Key: StepMailNormal, Label: "Starting the updated provider"},
		{Key: StepMailDocument, Label: "Sending the mail document"},
	}
}

// startRewireMail is the re-confirm of the held, wired instance t (every
// guard ran): the new commit and hash recorded, the hold cleared, the
// normal override and up — no void (isRewire), unless a void is owed for
// another reason (a restore), which runs first. Audited
// mail.provider_wired reconfirm=true.
func (h *Hub) startRewireMail(t *templates.Template, actor directory.Actor, in WireRequest) (*AsyncOp, error) {
	h.mu.RLock()
	held := h.st.Mail.Held != nil
	h.mu.RUnlock()
	if !held {
		err := statusErr(http.StatusConflict, "%s is already this server's mail provider", t.ID)
		h.auditOp(actor, "mail.provider_wired", t.ID, "reconfirm=true", err)
		return nil, err
	}
	h.mu.Lock()
	sourceChanged := h.mailHoldReasonLocked() == MailSourceChangedText || (h.st.Mail.Held != nil && h.st.Mail.Held.Reason == MailSourceChangedText)
	h.mu.Unlock()
	if sourceChanged {
		err := statusErr(http.StatusConflict, "%s", MailSourceChangedText)
		h.auditOp(actor, "mail.provider_wired", t.ID, "reconfirm=true", err)
		return nil, err
	}
	// The reviewed tree (M1): the browser echoes the Mail tab's
	// block_hash; the host path confirms the tree on disk now.
	live := h.Template(t.ID)
	if live == nil || live.Manifest.Mail == nil {
		return nil, statusErr(http.StatusConflict, "%s", MailInvalidText)
	}
	now, herr := templates.MailBlockHash(live.Path, live.Manifest.Mail, live.ReadCompose())
	if herr != nil {
		return nil, statusErr(http.StatusConflict, "%s", MailInvalidText)
	}
	confirmed := in.BlockHash
	if in.Host {
		confirmed = now
	}
	if confirmed == "" || confirmed != now {
		err := statusErr(http.StatusConflict, "the template changed since you reviewed it: look again")
		h.auditOp(actor, "mail.provider_wired", t.ID, "reconfirm=true", err)
		return nil, err
	}
	id := t.ID
	return h.startAsync(id, OpMailRewire, actor, mailRewirePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		unlockSlot, err := h.lockMailSlot()
		if err != nil {
			return nil, nil, err
		}
		defer unlockSlot()
		unlock, err := h.lockApp(id)
		if err != nil {
			return nil, nil, h.busyErr(id, err)
		}
		defer unlock()
		h.mailSlotLocked(OpMailRewire)
		h.mu.RLock()
		ok := h.st.Mail.Provider != nil && h.st.Mail.Provider.Instance == id && h.st.Mail.Held != nil
		h.mu.RUnlock()
		if !ok {
			err := statusErr(http.StatusConflict, "%s is no longer a held mail provider: look again", id)
			h.auditOp(actor, "mail.provider_wired", id, "reconfirm=true", err)
			return nil, nil, err
		}
		ready()
		p, err := h.runRewireMail(context.WithoutCancel(ctx), t, actor, confirmed)
		detail := "reconfirm=true"
		if p != nil {
			detail += " " + mailWiredDetail(p)
		}
		h.auditOp(actor, "mail.provider_wired", id, detail, err)
		return nil, nil, err
	})
}

// runRewireMail is the re-confirm's work. Caller holds the app lock.
func (h *Hub) runRewireMail(ctx context.Context, t *templates.Template, actor directory.Actor, confirmed string) (*state.MailProvider, error) {
	prog := progressFrom(ctx)
	id := t.ID
	prog.planned(StepMailRecord).Start(StepMailRecord)
	// The tree as confirmed now (a reload since the guards: the live one).
	live := h.Template(id)
	if live == nil || live.Manifest.Mail == nil {
		err := statusErr(http.StatusConflict, "%s", MailInvalidText)
		prog.planned(StepMailRecord).Fail(StepMailRecord, err)
		return nil, err
	}
	hash, err := templates.MailBlockHash(live.Path, live.Manifest.Mail, live.ReadCompose())
	if err != nil {
		prog.planned(StepMailRecord).Fail(StepMailRecord, err)
		return nil, err
	}
	// Another change landed since the review (M1): never accepted
	// unreviewed.
	if hash != confirmed {
		err := statusErr(http.StatusConflict, "the template changed again since you reviewed it: look again")
		prog.planned(StepMailRecord).Fail(StepMailRecord, err)
		return nil, err
	}
	h.mu.Lock()
	prev := h.st.Mail.Provider
	if prev == nil || prev.Instance != id {
		h.mu.Unlock()
		return nil, statusErr(http.StatusConflict, "%s isn't this server's mail provider any more", id)
	}
	np := *prev
	np.Commit, np.BlockHash = gitHead(live.Path), hash
	np.WiredAt, np.WiredBy = h.mailNow().UTC(), actor.User
	prevHeld := h.st.Mail.Held
	h.st.Mail.Provider, h.st.Mail.Held = &np, nil
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.Provider, h.st.Mail.Held = prev, prevHeld
		h.mu.Unlock()
		prog.planned(StepMailRecord).Fail(StepMailRecord, err)
		return nil, err
	}
	owed := h.st.Mail.VoidOwed
	h.mu.Unlock()
	prog.planned(StepMailRecord).Done(StepMailRecord)
	// A core restore holds the provider (FH-H3 b): the confirmation is
	// recorded and nothing starts; `hub mail restore` starts it.
	if h.mailRestoreHolds(id) {
		for _, k := range []string{StepMailVoid, StepMailNormal, StepMailDocument} {
			prog.planned(k).Detail(k, "a core restore is pending: the provider starts after `hub mail restore`")
			prog.planned(k).Done(k)
		}
		return &np, nil
	}
	prog.planned(StepMailVoid).Start(StepMailVoid)
	if owed != nil {
		if err := h.runVoid(ctx, id, owed.Reason); err != nil {
			prog.planned(StepMailVoid).Fail(StepMailVoid, err)
			return &np, err
		}
	}
	prog.planned(StepMailVoid).Done(StepMailVoid)
	prog.planned(StepMailNormal).Start(StepMailNormal)
	if err := h.mailUpInstance(ctx, id); err != nil {
		prog.planned(StepMailNormal).Fail(StepMailNormal, err)
		return &np, err
	}
	prog.planned(StepMailNormal).Done(StepMailNormal)
	h.writeMailTargets()
	prog.planned(StepMailDocument).Start(StepMailDocument)
	h.mailSyncOnce(ctx)
	prog.planned(StepMailDocument).Done(StepMailDocument)
	return &np, nil
}
