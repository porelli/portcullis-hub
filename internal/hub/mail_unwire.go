package hub

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Unwiring and switching (contract §19.9, spec §5.2–§5.3).

// Op names (on the instance's record: the unwired one, or the switch's
// target).
const (
	OpMailUnwire = "mail_unwire"
	OpMailSwitch = "mail_switch"
)

// Steps.
const (
	StepMailDrain   = "drain"
	StepMailSets    = "sets"
	StepMailClose   = "close"
	StepMailUnwire  = "unwire"
	mailCallTimeout = 30 * time.Second
	// MailDKIMRetention is how long a switch keeps the old DKIM records.
	MailDKIMRetention = 7 * 24 * time.Hour
)

// mailDeleteRefusal is the guarded delete's refusal while wired.
const mailDeleteRefusal = "unwire it first (Settings → Mail)"

// voidProviderRowsLocked ends every active mail password row with
// reason (provider_changed), audited with the count only. Caller must
// hold mu (write); the caller saves.
func (h *Hub) voidProviderRowsLocked(reason string, actor directory.Actor) int {
	now := h.mailNow().UTC()
	n := 0
	for user, rows := range h.st.MailCredentials {
		for i := range rows {
			if rows[i].Active() {
				rows[i].RevokedAt, rows[i].Reason, rows[i].RevokedBy = &now, reason, actor.User
				n++
			}
		}
		h.st.MailCredentials[user] = rows
	}
	return n
}

func mailUnwirePlan(drain bool) []Step {
	steps := []Step{}
	if drain {
		steps = append(steps, Step{Key: StepMailDrain, Label: "Draining every mail domain (MTA-STS mode none)"})
	} else {
		steps = append(steps, Step{Key: StepMailSets, Label: "Removing every mail DNS set"})
	}
	return append(steps, Step{Key: StepMailClose, Label: "Closing the mail gate and stopping the provider"})
}

// StartUnwireMail unwires instance id (guards 1–2 only: it narrows
// rights). drain: every domain drains first and the unwire finishes on
// its own once all are off (state.yaml mail.unwiring); else the sets go
// now. Audited mail.provider_unwired.
func (h *Hub) StartUnwireMail(id string, drain bool, actor directory.Actor) (*AsyncOp, error) {
	return h.startUnwireMail(id, drain, actor, false)
}

// startUnwireMail is StartUnwireMail; host: the host socket (no admin
// check: the host operator holds the host).
func (h *Hub) startUnwireMail(id string, drain bool, actor directory.Actor, host bool) (*AsyncOp, error) {
	if err := h.mailActorGuard(context.Background(), actor, host); err != nil {
		h.auditOp(actor, "mail.provider_unwired", id, "", err)
		return nil, err
	}
	h.mu.RLock()
	p := h.st.Mail.Provider
	h.mu.RUnlock()
	if p == nil || p.Instance != id {
		return nil, statusErr(http.StatusConflict, "%s isn't this server's mail provider", id)
	}
	return h.startAsync(id, OpMailUnwire, actor, mailUnwirePlan(drain), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
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
		h.mailSlotLocked(OpMailUnwire)
		h.mu.RLock()
		cur := h.st.Mail.Provider
		h.mu.RUnlock()
		if cur == nil || cur.Instance != id {
			return nil, nil, statusErr(http.StatusConflict, "%s isn't this server's mail provider any more", id)
		}
		ready()
		// An unwire can't be stopped (contract §19.9 "Stop").
		ctx = context.WithoutCancel(ctx)
		err = h.runUnwireMail(ctx, id, drain, actor)
		h.auditOp(actor, "mail.provider_unwired", id, "drain="+strconv.FormatBool(drain), err)
		return nil, nil, err
	})
}

// runUnwireMail is the unwire op. Caller holds the app lock.
func (h *Hub) runUnwireMail(ctx context.Context, id string, drain bool, actor directory.Actor) error {
	prog := progressFrom(ctx)
	if drain {
		prog.planned(StepMailDrain).Start(StepMailDrain)
		h.mailDrainAll(actor)
		h.mu.Lock()
		h.st.Mail.Unwiring = &state.MailUnwiring{Instance: id, Since: h.mailNow().UTC(), By: actor.User}
		if p := h.st.Mail.Provider; p != nil && p.Instance == id {
			h.st.Mail.Unwiring.WiredAt, h.st.Mail.Unwiring.WireSeq = p.WiredAt, p.Seq
		}
		err := h.saveStateLocked()
		h.mu.Unlock()
		if err != nil {
			return err
		}
		prog.planned(StepMailDrain).Done(StepMailDrain)
		if !h.mailAllDrained() {
			// The sync finishes it once every domain is off.
			prog.planned(StepMailClose).Detail(StepMailClose, "waiting for every mail domain to finish draining")
			prog.planned(StepMailClose).Done(StepMailClose)
			return nil
		}
	} else {
		prog.planned(StepMailSets).Start(StepMailSets)
		if err := h.mailRemoveAllSets(ctx); err != nil {
			prog.planned(StepMailSets).Detail(StepMailSets, err.Error()+": remove it by hand in its DNS")
		}
		prog.planned(StepMailSets).Done(StepMailSets)
	}
	prog.planned(StepMailClose).Start(StepMailClose)
	if err := h.closeMailProvider(ctx, id, actor); err != nil {
		prog.planned(StepMailClose).Fail(StepMailClose, err)
		return err
	}
	prog.planned(StepMailClose).Done(StepMailClose)
	return nil
}

// mailDrainAll makes every on mail domain draining (as mail disable).
func (h *Hub) mailDrainAll(actor directory.Actor) {
	coreOn := h.mailOn()
	h.mu.Lock()
	var changed []string
	for _, n := range h.mailDomainNamesLocked() {
		if h.mailDomainStateLocked(n, coreOn) != mailprovider.MailOn {
			continue
		}
		if h.st.Mail.Domains == nil {
			h.st.Mail.Domains = map[string]state.MailDomain{}
		}
		e := h.st.Mail.Domains[n]
		e.Enabled, e.Draining = false, true
		h.st.Mail.Domains[n] = e
		changed = append(changed, n)
	}
	if len(changed) > 0 {
		h.saveLocked()
	}
	h.mu.Unlock()
	for _, n := range changed {
		h.auditOp(actor, "mail.domain", n, "enabled=false (drain)", nil)
	}
	h.TriggerMailSync()
}

// mailAllDrained: no mail domain is on or draining any more.
func (h *Hub) mailAllDrained() bool {
	for _, r := range h.mailDomainRows() {
		if r.State != mailprovider.MailOff {
			return false
		}
	}
	return true
}

// mailRemoveAllSets deletes every added domain's mail set now (drain
// false: senders may bounce); the main domain's goes with the CLI timer.
func (h *Hub) mailRemoveAllSets(ctx context.Context) error {
	h.mu.RLock()
	dapi := h.domainsAPI
	h.mu.RUnlock()
	if dapi == nil {
		return nil
	}
	var first error
	for _, d := range h.mailDNSDomains() {
		dctx, cancel := context.WithTimeout(ctx, mailCallTimeout)
		if _, err := dapi.DeleteMailSet(dctx, d.name); err != nil && domainsStatus(err) != http.StatusNotFound {
			log.Printf("mail: unwire: removing %s's mail set: %v", d.name, err)
			if first == nil {
				first = fmt.Errorf("removing %s's mail set: %w", d.name, err)
			}
		} else {
			h.mailForgetDNSHash(d.name)
			h.mailSetPublished(d.name, nil) // no _mta-sts any more (M13)
		}
		cancel()
	}
	return first
}

// closeMailProvider is the unwire's close step (contract §19.9): every
// active row voided (provider_changed), POST /v1/void (best effort, 30
// s), the API secret and .present deleted (the gate closes), the record
// cleared, the unwired override rendered and the instance stopped
// (disabled; its data stays). Whatever the provider answers, the gate is
// closed. Caller holds the app lock.
func (h *Hub) closeMailProvider(ctx context.Context, id string, actor directory.Actor) error {
	h.mu.Lock()
	// The close is recorded first (M4, and a switch's too: M5): a crash
	// or a failed stop from here on is resumed until the instance is
	// verified down — bound to this wiring (FH-H2).
	{
		u := h.st.Mail.Unwiring
		if u == nil || u.Instance != id {
			u = &state.MailUnwiring{Instance: id, Since: h.mailNow().UTC(), By: actor.User}
		} else {
			c := *u
			u = &c
		}
		if p := h.st.Mail.Provider; p != nil && p.Instance == id {
			u.WiredAt, u.WireSeq = p.WiredAt, p.Seq
		}
		u.Closing = true
		prevU := h.st.Mail.Unwiring
		h.st.Mail.Unwiring = u
		if err := h.saveStateLocked(); err != nil {
			h.st.Mail.Unwiring = prevU
			h.mu.Unlock()
			return err
		}
	}
	n := h.voidProviderRowsLocked(state.MailCredentialReasonProviderChanged, actor)
	if n > 0 {
		h.saveLocked()
	}
	api := h.mailProviderAPILocked()
	h.mu.Unlock()
	if n > 0 {
		h.auditOp(actor, "mail_credential.void_provider", id, fmt.Sprintf("count=%d", n), nil)
	}
	if api != nil && api.Available() == nil {
		vctx, cancel := context.WithTimeout(ctx, mailCallTimeout)
		if _, err := api.Void(vctx, mailprovider.VoidWire); err != nil {
			log.Printf("mail: unwire: the provider's void failed (the gate closes anyway): %v", err)
		}
		cancel()
	}
	var gateErr error
	for _, f := range []string{mailGateAPISecret, mailGatePresent, mailGateMetricsSecret, mailGateRelayPassword, mailGateFileVoidSession, mailGateVoidPending} {
		if err := h.mailGateRemove(id, f); err != nil && gateErr == nil {
			gateErr = err
		}
	}
	h.mu.Lock()
	if p := h.st.Mail.Provider; p != nil && p.Instance == id {
		h.st.Mail.Provider, h.st.Mail.VoidOwed, h.st.Mail.Held = nil, nil, nil
	}
	// A switch's close is recorded in the same save (its resume relies
	// on it).
	if sw := h.st.Mail.Switch; sw != nil && sw.From == id {
		c := *sw
		c.Closed = true
		h.st.Mail.Switch = &c
	}
	var live *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		live = &c
		if err := h.generateOverrideLocked(live, h.st.Settings[id]); err != nil {
			log.Printf("mail: unwire: rendering %s's unwired override: %v", id, err)
		}
	}
	h.st.SetEnabled(id, false)
	h.rebuildLocked()
	h.refreshPublishedLocked()
	saveErr := h.saveStateLocked()
	h.mu.Unlock()
	h.writeMailTargets()
	// mail_slot's copy of the metrics secret goes too (L22).
	if h.cfg.MailSlotDir != "" {
		if r, err := os.OpenRoot(h.cfg.MailSlotDir); err == nil {
			if err := r.Remove(mailGateMetricsSecret); err != nil && !errors.Is(err, fs.ErrNotExist) && gateErr == nil {
				gateErr = fmt.Errorf("removing mail_slot's metrics-secret: %w", err)
			}
			r.Close()
		}
	}
	var downErr error
	if live != nil {
		downErr = h.composeDown(live)
	}
	if downErr != nil {
		if err := h.rt.DownByName(context.Background(), projectName(id)); err != nil {
			downErr = fmt.Errorf("stopping %s: %v", id, downErr)
		} else {
			downErr = nil
		}
	}
	h.writePolicyLogged()
	h.TriggerReconcile()
	for _, err := range []error{gateErr, saveErr, downErr} {
		if err != nil {
			return err
		}
	}
	// Verified down: the unwire is done.
	h.mu.Lock()
	if u := h.st.Mail.Unwiring; u != nil && u.Instance == id {
		h.st.Mail.Unwiring = nil
		h.saveLocked()
	}
	h.mu.Unlock()
	return nil
}

// mailResumeClosing finishes a close that crashed or whose stop failed
// (M4): at start and from the retry loop.
func (h *Hub) mailResumeClosing() {
	h.mu.RLock()
	u := h.st.Mail.Unwiring
	h.mu.RUnlock()
	if u == nil || !u.Closing {
		return
	}
	unlockSlot, err := h.lockMailSlot()
	if err != nil {
		return
	}
	defer unlockSlot()
	unlock, err := h.lockApp(u.Instance)
	if err != nil {
		return
	}
	defer unlock()
	h.mu.RLock()
	still := h.st.Mail.Unwiring != nil && h.st.Mail.Unwiring.Closing && h.st.Mail.Unwiring.Instance == u.Instance
	stale := h.mailUnwiringStaleLocked(u)
	h.mu.RUnlock()
	if !still {
		return
	}
	actor := directory.Human(u.By)
	if stale {
		h.mailDropStaleUnwiring(u, actor)
		return
	}
	err = h.closeMailProvider(context.Background(), u.Instance, actor)
	if err != nil {
		log.Printf("mail: finishing the unwire of %s (retrying): %v", u.Instance, err)
	}
	h.auditOp(actor, "mail.provider_unwired", u.Instance, "closing resumed", err)
}

// mailFinishUnwireIfDrained completes a draining unwire once every
// domain is off (called after every sync pass and by the retry loop).
func (h *Hub) mailFinishUnwireIfDrained() {
	h.mu.RLock()
	u := h.st.Mail.Unwiring
	h.mu.RUnlock()
	if u == nil || !h.mailAllDrained() {
		return
	}
	h.goBackground(func() {
		unlockSlot, err := h.lockMailSlot()
		if err != nil {
			return // another slot op: the next pass tries again
		}
		defer unlockSlot()
		unlock, err := h.lockApp(u.Instance)
		if err != nil {
			return // busy: the next pass tries again
		}
		defer unlock()
		h.mu.RLock()
		still := h.st.Mail.Unwiring != nil && h.st.Mail.Unwiring.Instance == u.Instance
		stale := h.mailUnwiringStaleLocked(u)
		h.mu.RUnlock()
		if !still {
			return
		}
		actor := directory.Human(u.By)
		if stale {
			h.mailDropStaleUnwiring(u, actor)
			return
		}
		// Every added domain's set goes first (M5, spec §5.3); a DELETE
		// that fails keeps the unwire for the next pass.
		if err := h.mailRemoveAllSets(context.Background()); err != nil {
			log.Printf("mail: the drained unwire of %s waits: %v", u.Instance, err)
			return
		}
		err = h.closeMailProvider(context.Background(), u.Instance, actor)
		h.auditOp(actor, "mail.provider_unwired", u.Instance, "drain=true (finished)", err)
	})
}

// SwitchRequest is a switch: the target's typed id, the typed phrase
// "<n> mailboxes start empty", the fresh-auth proof.
type SwitchRequest struct {
	Confirm      string
	ConfirmEmpty string
	Proof        *freshauth.Proof
	Listener     string
	Host         bool
}

func mailSwitchPlan() []Step {
	return append([]Step{{Key: StepMailUnwire, Label: "Unwiring the current mail provider"}}, mailWirePlan()...)
}

// mailEmptyPhrase is the switch's typed phrase for n mailboxes.
func mailEmptyPhrase(n int) string { return strconv.Itoa(n) + " mailboxes start empty" }

// StartSwitchMail switches the mail provider to instance to (contract
// §19.9): every wiring guard for to (but "another is wired"), the typed
// phrase, then the op mail_switch on to's record: the old provider's
// close (no drain, the sets stay, its DKIM retained 7 days), then the
// wiring steps. Audited mail.provider_switched {from, to}.
func (h *Hub) StartSwitchMail(ctx context.Context, to string, in SwitchRequest, actor directory.Actor) (*AsyncOp, error) {
	h.mu.RLock()
	p := h.st.Mail.Provider
	h.mu.RUnlock()
	if p == nil {
		return nil, statusErr(http.StatusConflict, "no mail provider is wired: wire one instead")
	}
	from := p.Instance
	if from == to {
		return nil, statusErr(http.StatusConflict, "%s is already this server's mail provider", to)
	}
	t, err := h.mailWireGuards(ctx, to, WireRequest{Confirm: in.Confirm, Proof: in.Proof, Listener: in.Listener, Host: in.Host}, actor, from)
	if err == nil {
		n := 0
		if last, _ := h.loadMailLast(); last != nil {
			n = len(last.Accounts)
		}
		if want := mailEmptyPhrase(n); in.ConfirmEmpty != want {
			err = statusErr(http.StatusBadRequest, "type %q to confirm", want)
		}
	}
	if err != nil {
		h.auditOp(actor, "mail.provider_switched", to, "from="+from, err)
		return nil, err
	}
	return h.startAsync(to, OpMailSwitch, actor, mailSwitchPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		unlockSlot, err := h.lockMailSlot()
		if err != nil {
			h.auditOp(actor, "mail.provider_switched", to, "from="+from, err)
			return nil, nil, err
		}
		defer unlockSlot()
		unlock, err := h.lockApp(to)
		if err != nil {
			return nil, nil, h.busyErr(to, err)
		}
		defer unlock()
		unlockFrom, err := h.lockApp(from)
		if err != nil {
			return nil, nil, h.busyErr(from, err)
		}
		// The guards ran before the locks: the provider must still be
		// from, and no switch may be pending; then the switch is recorded
		// first (a restart resumes it: never both providers on the ports).
		h.mailSlotLocked(OpMailSwitch)
		h.mu.Lock()
		cur := h.st.Mail.Provider
		if cur == nil || cur.Instance != from || h.st.Mail.Switch != nil {
			h.mu.Unlock()
			unlockFrom()
			err := statusErr(http.StatusConflict, "the mail provider changed meanwhile: look again before switching")
			h.auditOp(actor, "mail.provider_switched", to, "from="+from, err)
			return nil, nil, err
		}
		h.st.Mail.Switch = &state.MailSwitch{From: from, To: to, Since: h.mailNow().UTC(), By: actor.User}
		serr := h.saveStateLocked()
		if serr != nil {
			h.st.Mail.Switch = nil
		}
		h.mu.Unlock()
		if serr != nil {
			unlockFrom()
			return nil, nil, serr
		}
		ready()
		_, err = h.runSwitchMail(ctx, t, from, actor, unlockFrom)
		h.auditOp(actor, "mail.provider_switched", to, "from="+from+" to="+to, err)
		return nil, nil, err
	})
}

// runSwitchMail is the switch's work: the old provider closed (its
// DKIM kept as retiring, no drain, the sets stay), then the wiring of
// t. A Stop is accepted only before the unwire changes anything. The
// caller holds both app locks (unlockFrom releases from's).
func (h *Hub) runSwitchMail(ctx context.Context, t *templates.Template, from string, actor directory.Actor, unlockFrom func()) (*state.MailProvider, error) {
	prog := progressFrom(ctx)
	if err := ctx.Err(); err != nil {
		unlockFrom()
		h.mu.Lock()
		h.st.Mail.Switch = nil
		h.saveLocked()
		h.mu.Unlock()
		return nil, err
	}
	ctx = context.WithoutCancel(ctx)
	prog.planned(StepMailUnwire).Start(StepMailUnwire)
	// Under the slot op and both app locks: the old provider is closed
	// when it is still wired; nothing wired is fine only when the
	// persisted switch says its close is done (a resume); the new one
	// already wired means it is finished; anything else aborts.
	h.mu.RLock()
	cur, sw := h.st.Mail.Provider, h.st.Mail.Switch
	h.mu.RUnlock()
	to := t.ID
	switch {
	case cur != nil && cur.Instance == from:
		h.mailRetainDKIM(ctx)
		if err := h.closeMailProvider(ctx, from, actor); err != nil {
			unlockFrom()
			prog.planned(StepMailUnwire).Fail(StepMailUnwire, err)
			return nil, err
		}
	case cur == nil && sw != nil && sw.From == from && sw.To == to && sw.Closed:
	case cur != nil && cur.Instance == to && sw != nil && sw.Closed:
		// The new one is recorded, but its wiring may be unfinished (a
		// crash after the record, M3): a void still owed runs the wiring
		// again from the gate on; else the normal up, the targets and
		// the document (idempotent). The switch ends only on success.
		unlockFrom()
		prog.planned(StepMailUnwire).Done(StepMailUnwire)
		h.mu.RLock()
		owed := h.st.Mail.VoidOwed
		h.mu.RUnlock()
		p, err := cur, error(nil)
		if owed != nil {
			p, err = h.runWireMail(ctx, t, actor, owed.Reason)
		} else if err = h.mailUpInstance(ctx, to); err == nil {
			h.writeMailTargets()
			h.mailSyncOnce(ctx)
		}
		if err == nil {
			h.mu.Lock()
			h.st.Mail.Switch = nil
			h.saveLocked()
			h.mu.Unlock()
		}
		return p, err
	default:
		unlockFrom()
		h.mu.Lock()
		h.st.Mail.Switch = nil
		h.saveLocked()
		h.mu.Unlock()
		err := statusErr(http.StatusConflict, "the mail provider changed meanwhile: the switch from %s to %s was dropped", from, to)
		prog.planned(StepMailUnwire).Fail(StepMailUnwire, err)
		return nil, err
	}
	unlockFrom()
	prog.planned(StepMailUnwire).Done(StepMailUnwire)
	p, err := h.runWireMail(ctx, t, actor, state.MailVoidWire)
	h.mu.Lock()
	if err == nil {
		h.st.Mail.Switch = nil
		h.saveLocked()
	}
	h.mu.Unlock()
	return p, err
}

// mailRetainDKIM records, per mail domain, the old provider's DKIM TXT
// records (its current set, read once with a bound) as retiring for 7
// days: merged into the domain's set until then (writeMailSet).
func (h *Hub) mailRetainDKIM(ctx context.Context) {
	h.mu.RLock()
	api := h.mailProviderAPILocked()
	h.mu.RUnlock()
	if api == nil || api.Available() != nil {
		return
	}
	h.mu.RLock()
	dapi := h.domainsAPI
	h.mu.RUnlock()
	until := h.mailNow().UTC().Add(MailDKIMRetention)
	keep := map[string]state.RetiringDKIM{}
	names := []string{strings.ToLower(h.cfg.Domain)}
	for _, d := range h.mailDNSDomains() {
		if d.state != mailprovider.MailOff {
			names = append(names, d.name)
		}
	}
	for i, name := range names {
		wild := true // the main domain: *.<d> is core's
		if i > 0 && dapi != nil {
			if w, err := planHasWildcard(ctx, dapi, name); err == nil {
				wild = w
			}
		}
		dctx, cancel := context.WithTimeout(ctx, mailCallTimeout)
		set, err := api.DNS(dctx, name, wild)
		cancel()
		if err != nil {
			log.Printf("mail: switch: reading %s's DKIM records from the old provider: %v", name, err)
			continue
		}
		var recs []state.MailRecord
		for _, r := range set.Records {
			mr := state.MailRecord{Name: r.Name, Type: r.Type, TTL: r.TTL, Value: r.Value}
			if mailRetiringShape(name, mr) { // M8: the shape at retention too
				recs = append(recs, mr)
			}
		}
		if len(recs) > 0 {
			keep[name] = state.RetiringDKIM{Records: recs, Until: until}
		}
	}
	if len(keep) == 0 {
		return
	}
	h.mu.Lock()
	if h.st.Mail.RetiringDKIM == nil {
		h.st.Mail.RetiringDKIM = map[string]state.RetiringDKIM{}
	}
	for d, r := range keep {
		h.st.Mail.RetiringDKIM[d] = r
	}
	h.saveLocked()
	h.mu.Unlock()
}

// resumeSwitchMail finishes a switch interrupted by a restart (contract
// §19.9 "Resuming"): the old provider closed when it is still wired,
// then the wiring of the new one; never both on the ports.
func (h *Hub) resumeSwitchMail(sw *state.MailSwitch) {
	unlockSlot, err := h.lockMailSlot()
	if err != nil {
		log.Printf("mail: resuming the switch to %s: %v (the next start resumes it)", sw.To, err)
		return
	}
	defer unlockSlot()
	unlock, err := h.lockApp(sw.To)
	if err != nil {
		log.Printf("mail: resuming the switch to %s: %v", sw.To, err)
		return
	}
	defer unlock()
	unlockFrom, err := h.lockApp(sw.From)
	if err != nil {
		log.Printf("mail: resuming the switch from %s: %v", sw.From, err)
		return
	}
	t := h.Template(sw.To)
	if t == nil || t.Manifest.Mail == nil {
		unlockFrom()
		log.Printf("mail: resuming the switch: %s is no mail provider instance any more: the switch is dropped", sw.To)
		h.mu.Lock()
		h.st.Mail.Switch = nil
		h.saveLocked()
		h.mu.Unlock()
		return
	}
	actor := directory.Human(sw.By)
	_, err = h.runSwitchMail(context.Background(), t, sw.From, actor, unlockFrom)
	h.auditOp(actor, "mail.provider_switched", sw.To, "from="+sw.From+" to="+sw.To+" (resumed)", err)
}

// HostMailUnwire is POST /host/mail/unwire {drain}: the wired provider's
// unwire with actor host (`./portcullis mail disable`).
func (h *Hub) HostMailUnwire(drain bool) (*AsyncOp, error) {
	h.mu.RLock()
	p := h.st.Mail.Provider
	h.mu.RUnlock()
	if p == nil {
		return nil, statusErr(http.StatusConflict, "no mail provider is wired")
	}
	return h.startUnwireMail(p.Instance, drain, directory.Human(HostActor), true)
}

// mailUnwiringStaleLocked: u is of another wiring than the slot holds
// now (FH-H2): something else (or the same instance again) was wired
// since. Nothing wired is not stale (the close is still owed). Caller
// must hold mu.
func (h *Hub) mailUnwiringStaleLocked(u *state.MailUnwiring) bool {
	p := h.st.Mail.Provider
	if p == nil {
		return false
	}
	return p.Instance != u.Instance || p.Seq != u.WireSeq || !p.WiredAt.Equal(u.WiredAt)
}

// mailDropStaleUnwiring drops a stale unwiring record (FH-H2) once the
// old instance is confirmed stopped (another instance: its owed down;
// the same one wired again: its new wiring is running, nothing to stop).
// Never a void or an unwire of the current wiring. Audited
// mail.unwire_stale.
func (h *Hub) mailDropStaleUnwiring(u *state.MailUnwiring, actor directory.Actor) {
	h.mu.RLock()
	p := h.st.Mail.Provider
	h.mu.RUnlock()
	var err error
	if p == nil || p.Instance != u.Instance {
		ctx, cancel := context.WithTimeout(context.Background(), mailStopTimeout)
		err = h.rt.DownByName(ctx, projectName(u.Instance))
		cancel()
	}
	if err == nil {
		h.mu.Lock()
		if cur := h.st.Mail.Unwiring; cur != nil && cur.Instance == u.Instance && cur.WireSeq == u.WireSeq && cur.WiredAt.Equal(u.WiredAt) {
			h.st.Mail.Unwiring = nil
			h.saveLocked()
		}
		h.mu.Unlock()
	}
	h.auditOp(actor, "mail.unwire_stale", u.Instance, "", err)
}
