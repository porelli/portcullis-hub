package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Wiring a mail provider (contract §19.9): a deliberate, guarded act — a
// full administrator with a fresh sign-in (the host operator's typed
// confirmation on the host path), the instance id typed, the powers
// spelled out, never from MCP or AI, audited. Every wiring starts with a
// void.

// MailWarning is the exact text shown and answered before every wiring.
const MailWarning = "This app becomes the mail server for every person and every mail domain. It gets public ports 25, 465, 587 and 993, writes the mail DNS records of every mail domain, creates and checks the mail passwords of every person in mail_users, sends mail to the internet (outbound SMTP), and can read every mailbox."

// MailHoldWarning is shown with the warning while the provider is held.
const MailHoldWarning = "The template changed since you wired it. Confirming keeps every mail password and mailbox: the updated app gets them as they are."

// Refusal texts (contract §19.9).
const (
	mailTypeIDText   = "type the instance id to confirm"
	mailSlotOffText  = "mail is off: run ./portcullis mail enable on the host"
	mailKubeText     = "mail isn't available on Kubernetes yet (Docker or rootless Podman only)"
	mailNotAdminText = "not allowed: full administrators only (lldap_admin)"
	mailAIText       = "not allowed: mail providers are never wired, switched or unwired through MCP or AI"
)

// OpMailWire is the wiring op (on the instance's record).
const OpMailWire = "mail_wire"

// The wiring op's steps (each saved before the next).
const (
	StepMailRecord   = "record"
	StepMailGate     = "gate"
	StepMailVoidMode = "void_mode"
	StepMailVoid     = "void"
	StepMailNormal   = "normal"
	StepMailDocument = "document"
	StepMailDNS      = "dns"
)

func mailWirePlan() []Step {
	return []Step{
		{Key: StepMailRecord, Label: "Recording the mail provider"},
		{Key: StepMailGate, Label: "Writing the API secret and the gate"},
		{Key: StepMailVoidMode, Label: "Starting the provider in void mode"},
		{Key: StepMailVoid, Label: "Voiding and checking every mail password"},
		{Key: StepMailNormal, Label: "Opening the mail ports"},
		{Key: StepMailDocument, Label: "Sending the first mail document"},
		{Key: StepMailDNS, Label: "Publishing the mail DNS records"},
	}
}

// WireRequest is one wiring: the typed instance id, the fresh-auth
// proof (people / Hub listener) or the host path (no proof: the host
// operator's typed confirmation stands in).
type WireRequest struct {
	Confirm  string
	Proof    *freshauth.Proof
	Listener string
	Host     bool
	// BlockHash: a re-confirm's reviewed tree (the Mail tab's
	// block_hash, M1): the op refuses another one. The host path's
	// re-confirm takes the tree on disk at the request.
	BlockHash string
}

// mailActorGuard is guards 1–2 (and the host path's own actor): an AI
// or MCP token never, a full administrator only.
func (h *Hub) mailActorGuard(ctx context.Context, actor directory.Actor, host bool) error {
	if actor.Via != "" {
		return statusErr(http.StatusForbidden, "%s", mailAIText)
	}
	if host {
		return nil
	}
	if !h.isGlobalAdmin(ctx, actor.User) {
		return statusErr(http.StatusForbidden, "%s", mailNotAdminText)
	}
	return nil
}

// mailWireRefusalsLocked are guards 5–10 for instance t (except: the
// wired instance itself, a re-confirm, isn't "another"): every reason
// wiring is refused now, in guard order (409 each). Caller must hold mu.
func (h *Hub) mailWireRefusalsLocked(t *templates.Template, except string) []string {
	var out []string
	core := h.mailCore()
	if !core.On {
		out = append(out, mailSlotOffText)
	}
	if p := h.st.Mail.Provider; p != nil && p.Instance != t.ID && p.Instance != except {
		out = append(out, p.Instance+" is this server's mail provider: switch instead")
	}
	if h.kubeOn() {
		out = append(out, mailKubeText)
	}
	if h.rootlessOn() {
		if n := h.unprivilegedPortStart(); n > 25 {
			out = append(out, fmt.Sprintf("net.ipv4.ip_unprivileged_port_start = %d: mail publishes ports 25, 465 and 587 (sysctl -w net.ipv4.ip_unprivileged_port_start=25, and keep it in /etc/sysctl.d/; unprivileged users may then bind 25-79)", n))
		}
	}
	for _, other := range h.st.Enabled {
		if other == t.ID || other == except {
			continue
		}
		o := h.findLocked(other)
		if o == nil {
			continue
		}
		for _, b := range h.appPortsLocked(o) {
			for _, p := range mailPorts {
				if portOverlap(b, portBinding{Bind: "0.0.0.0", Port: p, Protocol: "tcp"}) {
					out = append(out, fmt.Sprintf("%s publishes port %d: free it first", other, p))
				}
			}
		}
	}
	if t.Manifest.Mail == nil || !t.MailProvider {
		out = append(out, "the template "+t.TemplateID+" has no valid mail: block")
	} else if t.Manifest.Mail.APIVersion != 1 {
		out = append(out, "mail.api_version: only 1")
	}
	return out
}

// mailWireGuards runs every guard of a wiring of id in order (contract
// §19.9); rewire: the instance is the wired one (a re-confirm). The
// proof is verified last of the request's own checks (guard 3), before
// the typed id. Outside mu.
func (h *Hub) mailWireGuards(ctx context.Context, id string, in WireRequest, actor directory.Actor, except string) (*templates.Template, error) {
	if err := h.mailActorGuard(ctx, actor, in.Host); err != nil {
		return nil, err
	}
	if !in.Host {
		if in.Proof == nil || in.Proof.Code == "" || in.Proof.CodeVerifier == "" || in.Proof.Nonce == "" {
			return nil, errFreshAuth
		}
		listener := in.Listener
		if listener == "" {
			listener = ListenerHub
		}
		if _, err := h.verifyTouch(ctx, listener, *in.Proof, actor.User); err != nil {
			var tr *touchRefused
			if errors.As(err, &tr) {
				return nil, tr.err
			}
			return nil, errFreshAuth
		}
	}
	if in.Confirm != id {
		return nil, statusErr(http.StatusBadRequest, "%s", mailTypeIDText)
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	if t == nil || t.Manifest.Mail == nil {
		return nil, statusErr(http.StatusNotFound, "%s is no instance of a mail provider template", id)
	}
	if r := h.mailWireRefusalsLocked(t, except); len(r) > 0 {
		return nil, statusErr(http.StatusConflict, "%s", r[0])
	}
	c := *t
	return &c, nil
}

// mailIsRewire: wiring id is a re-confirm of the wired, held instance
// (Task 10): the same mailbox store, so no void (the ledger's ruling).
func (h *Hub) mailIsRewireLocked(id string) bool {
	p := h.st.Mail.Provider
	return p != nil && p.Instance == id
}

// StartWireMail wires instance id as the server's mail provider in the
// background (202 with the op), after every guard. Refusals are
// synchronous.
func (h *Hub) StartWireMail(ctx context.Context, id string, in WireRequest, actor directory.Actor) (*AsyncOp, error) {
	h.mu.RLock()
	rewire := h.mailIsRewireLocked(id)
	h.mu.RUnlock()
	except := ""
	if rewire {
		except = id
	}
	t, err := h.mailWireGuards(ctx, id, in, actor, except)
	if err != nil {
		h.auditOp(actor, "mail.provider_wired", id, "", err)
		return nil, err
	}
	if rewire {
		return h.startRewireMail(t, actor, in)
	}
	return h.startAsync(id, OpMailWire, actor, mailWirePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		unlockSlot, err := h.lockMailSlot()
		if err != nil {
			h.auditOp(actor, "mail.provider_wired", id, "", err)
			return nil, nil, err
		}
		defer unlockSlot()
		unlock, err := h.lockApp(id)
		if err != nil {
			return nil, nil, h.busyErr(id, err)
		}
		defer unlock()
		// The guards ran before the locks: nothing may have been wired
		// meanwhile.
		h.mailSlotLocked(OpMailWire)
		h.mu.RLock()
		cur := h.st.Mail.Provider
		// Every 409 refusal again under the locks (L2: the slot, the
		// runtime, the ports, the template's validity may have changed).
		var refusals []string
		if lt := h.findLocked(id); lt == nil {
			refusals = []string{id + " is no instance any more"}
		} else {
			refusals = h.mailWireRefusalsLocked(lt, "")
		}
		h.mu.RUnlock()
		if cur != nil {
			err := statusErr(http.StatusConflict, "%s is this server's mail provider: switch instead", cur.Instance)
			h.auditOp(actor, "mail.provider_wired", id, "", err)
			return nil, nil, err
		}
		if len(refusals) > 0 {
			err := statusErr(http.StatusConflict, "%s", refusals[0])
			h.auditOp(actor, "mail.provider_wired", id, "", err)
			return nil, nil, err
		}
		ready()
		p, err := h.runWireMail(ctx, t, actor, state.MailVoidWire)
		detail := ""
		if p != nil {
			detail = mailWiredDetail(p)
		}
		h.auditOp(actor, "mail.provider_wired", id, detail, err)
		return nil, nil, err
	})
}

// mailWiredDetail is the audit detail of a wiring (never a secret).
func mailWiredDetail(p *state.MailProvider) string {
	return "template=" + p.Template + " source=" + p.Source + " commit=" + p.Commit + " block_hash=" + p.BlockHash
}

// runWireMail is the wiring op's steps (contract §19.9) for the
// instance view t; voidReason is the void the record owes (wire). A Stop
// before the normal step undoes it. Caller holds the app lock.
func (h *Hub) runWireMail(ctx context.Context, t *templates.Template, actor directory.Actor, voidReason string) (*state.MailProvider, error) {
	prog := progressFrom(ctx)
	id := t.ID
	step := func(k string) { prog.planned(k).Start(k) }
	done := func(k string) { prog.planned(k).Done(k) }
	fail := func(k string, err error) error {
		prog.planned(k).Fail(k, err)
		return err
	}
	stopped := func() bool { return ctx.Err() != nil }
	recordGen := 0 // the void generation the record raised
	undo := func() error {
		h.undoWireMail(id, recordGen)
		return ctx.Err()
	}
	// 1. record: the provider and the owed void in one save.
	step(StepMailRecord)
	hash, herr := templates.MailBlockHash(t.Path, t.Manifest.Mail, t.ReadCompose())
	if herr != nil {
		return nil, fail(StepMailRecord, herr)
	}
	by := actor.User
	if by == "" {
		by = "host"
	}
	h.mu.Lock()
	p := &state.MailProvider{Instance: id, Template: t.TemplateID, Source: t.Source, SourceURL: h.mailSourceURLLocked(t.Source), Commit: gitHead(t.Path), BlockHash: hash,
		WiredAt: h.mailNow().UTC(), WiredBy: by}
	prevP, prevV, prevGen, prevSeq := h.st.Mail.Provider, h.st.Mail.VoidOwed, h.st.Mail.VoidGen, h.st.Mail.WireSeq
	h.st.Mail.WireSeq++
	p.Seq = h.st.Mail.WireSeq
	h.st.Mail.Provider = p
	h.raiseVoidDebtLocked(voidReason)
	// The undo clears only a debt this record started (not an older one
	// it joined) and only while nothing was raised since.
	recordGen = -1
	if prevV == nil {
		recordGen = h.st.Mail.VoidGen
	}
	h.st.Mail.Held = nil
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.Provider, h.st.Mail.VoidOwed, h.st.Mail.VoidGen, h.st.Mail.WireSeq = prevP, prevV, prevGen, prevSeq
		h.mu.Unlock()
		return nil, fail(StepMailRecord, err)
	}
	h.mu.Unlock()
	done(StepMailRecord)
	if stopped() {
		return p, undo()
	}
	// 2. gate: fresh API and metrics secrets, the relay password, the
	// void files.
	step(StepMailGate)
	h.mu.Lock()
	err := h.writeMailSecretLocked(id)
	if err == nil {
		err = h.writeMailMetricsSecretLocked(id)
	}
	if err == nil {
		err = h.writeRelayPasswordLocked(id)
	}
	if err == nil {
		err = h.mailVoidFilesLocked(id)
	}
	h.mu.Unlock()
	if err != nil {
		if stopped() { // a Stop during the step: undone (M7)
			fail(StepMailGate, err)
			return p, undo()
		}
		return p, fail(StepMailGate, err)
	}
	done(StepMailGate)
	if stopped() {
		return p, undo()
	}
	// 3. void_mode: the void-mode override and up (enabled if it isn't).
	step(StepMailVoidMode)
	if err := h.mailUpInstance(ctx, id); err != nil {
		if stopped() { // a Stop during the step: undone (M7)
			fail(StepMailVoidMode, err)
			return p, undo()
		}
		return p, fail(StepMailVoidMode, err)
	}
	done(StepMailVoidMode)
	if stopped() {
		return p, undo()
	}
	// 4. void: bootstrap, POST /v1/void, the verification.
	step(StepMailVoid)
	h.mu.RLock()
	reason := voidReason
	if v := h.st.Mail.VoidOwed; v != nil {
		reason = v.Reason
	}
	h.mu.RUnlock()
	if err := h.runVoid(ctx, id, reason); err != nil {
		if stopped() { // a Stop during the step: undone (M7)
			fail(StepMailVoid, err)
			return p, undo()
		}
		return p, fail(StepMailVoid, err)
	}
	done(StepMailVoid)
	if stopped() {
		return p, undo()
	}
	// The tree changed since the record (a sync meanwhile): the hold
	// wins, no normal override for it.
	h.mu.Lock()
	h.checkMailHoldLocked()
	held := h.st.Mail.Held
	h.mu.Unlock()
	if held != nil {
		err := statusErr(http.StatusConflict, "%s", held.Reason)
		return p, fail(StepMailNormal, err)
	}
	// 5. normal: the normal override and up (no Stop from here on).
	step(StepMailNormal)
	if err := h.mailUpInstance(context.WithoutCancel(ctx), id); err != nil {
		return p, fail(StepMailNormal, err)
	}
	done(StepMailNormal)
	h.writeMailTargets()
	// 6. document and 7. dns: the first MailState, then the sets.
	step(StepMailDocument)
	h.mailSyncOnce(context.WithoutCancel(ctx))
	done(StepMailDocument)
	step(StepMailDNS)
	if api := h.mailClient(); api != nil {
		h.mailDNSIfDue(context.WithoutCancel(ctx), api, h.mailNow(), true)
	}
	done(StepMailDNS)
	return p, nil
}

// mailUpInstance starts instance id with its current override (enabling
// it when it isn't). Caller holds the app lock.
func (h *Hub) mailUpInstance(ctx context.Context, id string) error {
	t := h.Template(id)
	if t == nil {
		return ErrNotFound
	}
	if !t.Enabled {
		if _, err := h.enableInner(ctx, id, false); err != nil {
			return err
		}
		return nil
	}
	return h.composeUp(ctx, t)
}

// undoWireMail is a Stopped wiring's undo: the gate closed, the provider
// record and the wiring's void cleared, the unwired override rendered
// and the instance stopped. Caller holds the app lock.
func (h *Hub) undoWireMail(id string, recordGen int) {
	h.mu.Lock()
	if p := h.st.Mail.Provider; p != nil && p.Instance == id {
		h.st.Mail.Provider = nil
		// Only the record's own debt: one raised since (a restore, the
		// secrets epoch) stays owed.
		if h.st.Mail.VoidOwed != nil && h.st.Mail.VoidGen == recordGen {
			h.st.Mail.VoidOwed = nil
		}
		h.saveLocked()
	}
	for _, f := range []string{mailGateAPISecret, mailGatePresent, mailGateFileVoidSession, mailGateVoidPending} {
		if err := h.mailGateRemove(id, f); err != nil {
			log.Printf("mail: undoing the wiring of %s: %v", id, err)
		}
	}
	var live *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		live = &c
		if err := h.generateOverrideLocked(live, h.st.Settings[id]); err != nil {
			log.Printf("mail: undoing the wiring of %s: rendering: %v", id, err)
		}
	}
	h.mu.Unlock()
	if live != nil {
		if err := h.composeDown(live); err != nil {
			log.Printf("mail: undoing the wiring of %s: stopping: %v", id, err)
		}
	}
	h.writeMailTargets()
}

// resumeMail resumes the slot at start (contract §19.9 "Resuming"): a
// void owed with a provider wired (and not held) resumes void mode and
// the void, never the normal override first.
func (h *Hub) resumeMail() {
	h.mu.RLock()
	p, owed, held, sw := h.st.Mail.Provider, h.st.Mail.VoidOwed, h.st.Mail.Held, h.st.Mail.Switch
	h.mu.RUnlock()
	// An owed down of a stopped hold first (a crash between its save
	// and the down).
	if held != nil && held.DownOwed {
		h.goBackground(h.mailRetryHeldStop)
	}
	h.goBackground(h.mailResumeClosing)
	h.mailNoteRestorePending()
	if sw != nil {
		h.goBackground(func() { h.resumeSwitchMail(sw) })
		return
	}
	h.mailFinishUnwireIfDrained()
	if p == nil || owed == nil || held != nil || !h.mailOn() {
		return
	}
	id, reason := p.Instance, owed.Reason
	h.goBackground(func() {
		if err := h.mailVoidAndResume(context.Background(), id, reason); err != nil {
			log.Printf("mail: resuming the void of %s: %v", id, err)
		}
	})
}

// MailProviderView is GET /api/instances/{id}/mail-provider (the
// instance's Mail tab).
type MailProviderView struct {
	Wired          bool            `json:"wired"`
	Mode           string          `json:"mode"`
	Provider       any             `json:"provider"`
	Void           *MailVoidView   `json:"void"`
	Held           *state.MailHold `json:"held"`
	RefusedBecause []string        `json:"refused_because"`
	Warning        string          `json:"warning"`
	HoldWarning    string          `json:"hold_warning,omitempty"`
	// BlockHash is the held tree's hash as on disk now: the re-confirm
	// echoes it (M1).
	BlockHash string              `json:"block_hash,omitempty"`
	Wiring    *state.MailProvider `json:"-"`
}

// MailVoidView is an owed void with the last attempt's error.
type MailVoidView struct {
	Reason string `json:"reason"`
	Since  string `json:"since"`
	Error  string `json:"error"`
}

// mailVoidViewLocked is the owed void (nil: none). Caller holds mu.
func (h *Hub) mailVoidViewLocked() *MailVoidView {
	v := h.st.Mail.VoidOwed
	if v == nil {
		return nil
	}
	msg, _ := h.MailVoidError()
	return &MailVoidView{Reason: v.Reason, Since: v.Since.UTC().Format("2006-01-02T15:04:05Z"), Error: msg}
}

// InstanceMailProvider is instance id's Mail tab (404: no mail block).
func (h *Hub) InstanceMailProvider(ctx context.Context, id string) (*MailProviderView, error) {
	h.mu.RLock()
	t := h.findLocked(id)
	if t == nil || t.Manifest.Mail == nil {
		h.mu.RUnlock()
		return nil, statusErr(http.StatusNotFound, "%s is no instance of a mail provider template", id)
	}
	mode := h.mailModeLocked(id)
	v := &MailProviderView{Wired: mode != mailUnwired, Mode: h.mailModeTextLocked(id), Warning: MailWarning, RefusedBecause: []string{}}
	except := ""
	if v.Wired {
		except = id
		v.Void = h.mailVoidViewLocked()
		if hd := h.st.Mail.Held; hd != nil {
			c := *hd
			v.Held = &c
			v.HoldWarning = MailHoldWarning
			if hash, err := templates.MailBlockHash(t.Path, t.Manifest.Mail, t.ReadCompose()); err == nil {
				v.BlockHash = hash
			}
		}
	}
	if !v.Wired || v.Held != nil {
		v.RefusedBecause = append(v.RefusedBecause, h.mailWireRefusalsLocked(t, except)...)
	}
	var api MailAPI
	if v.Wired {
		api = h.mailProviderAPILocked()
	}
	h.mu.RUnlock()
	if api != nil && api.Available() == nil {
		pctx, cancel := context.WithTimeout(ctx, 5e9)
		if info, err := api.Provider(pctx); err == nil {
			v.Provider = info
		}
		cancel()
	}
	return v, nil
}

// HostMailProvider is GET /host/mail/provider (contract §19.10).
type HostMailProvider struct {
	Slot     string `json:"slot"`
	Wired    bool   `json:"wired"`
	Instance string `json:"instance"`
	Template string `json:"template"`
	Label    string `json:"label"`
	Version  string `json:"version"`
	VoidOwed bool   `json:"void_owed"`
	Held     bool   `json:"held"`
	Warning  string `json:"warning"`
	// Export is the wired block's export (nil: none or nothing wired):
	// `./portcullis mail export` execs it, never through the Hub.
	Export *templates.Export `json:"export"`
}

// HostMailProviderView answers GET /host/mail/provider.
func (h *Hub) HostMailProviderView(ctx context.Context) HostMailProvider {
	v := HostMailProvider{Slot: "closed", Warning: MailWarning}
	if h.mailOn() {
		v.Slot = "open"
	}
	h.mu.RLock()
	p := h.st.Mail.Provider
	var api MailAPI
	if p != nil {
		v.Wired, v.Instance, v.Template = true, p.Instance, p.Template
		v.VoidOwed, v.Held = h.st.Mail.VoidOwed != nil, h.st.Mail.Held != nil
		if t, m := h.mailWiredLocked(); t != nil {
			v.Label = m.Label
			if m.Export != nil {
				e := *m.Export
				e.Argv = append([]string(nil), e.Argv...)
				v.Export = &e
			}
		}
		api = h.mailProviderAPILocked()
	}
	h.mu.RUnlock()
	if api != nil && api.Available() == nil {
		pctx, cancel := context.WithTimeout(ctx, 5e9)
		if info, err := api.Provider(pctx); err == nil {
			v.Version = info.Version
		}
		cancel()
	}
	return v
}

// HostMailInstall is POST /host/mail/install {template, source, confirm}:
// the template's default instance (created when no instance of it
// exists, else the existing one), then the wiring as §19.9 with actor
// host (the operator's typed confirmation, no proof).
func (h *Hub) HostMailInstall(ctx context.Context, template, source, confirm string) (*AsyncOp, error) {
	actor := directory.Human(HostActor)
	if !templates.ValidID(template) {
		return nil, statusErr(http.StatusBadRequest, "invalid template id")
	}
	// The source is required (L1): never another source's template of
	// the same name.
	if source == "" {
		return nil, statusErr(http.StatusBadRequest, "source is required")
	}
	h.mu.RLock()
	ct := h.catalogLocked(template)
	found := ct != nil && ct.Source == source
	label := ""
	if found {
		label = ct.Manifest.Name
	}
	// An instance of it that exists (created): the default one first.
	id := ""
	if found {
		var ids []string
		for iid, e := range h.st.Instances {
			if e.Template == template {
				ids = append(ids, iid)
			}
		}
		slices.Sort(ids)
		// The default instance exists implicitly once enabled (§11.1).
		if slices.Contains(ids, template) || h.st.IsEnabled(template) {
			id = template
		} else if len(ids) > 0 {
			id = ids[0]
		}
	}
	h.mu.RUnlock()
	if !found {
		return nil, statusErr(http.StatusNotFound, "no template %s from source %s", template, strconv.Quote(source))
	}
	if id == "" {
		// None yet: its default instance is installed first (R-HH5,
		// contract §19.10), then wired. The typed id is checked first:
		// a wrong confirmation installs nothing.
		if confirm != template {
			return nil, statusErr(http.StatusBadRequest, "%s", mailTypeIDText)
		}
		if _, err := h.CreateInstanceAs(CreateRequest{Template: template, ID: template, Label: label}, actor); err != nil {
			return nil, err
		}
		id = template
	}
	return h.StartWireMail(ctx, id, WireRequest{Confirm: confirm, Host: true}, actor)
}

// lockMailSlot takes the one mail-slot op (wire, unwire, switch,
// re-confirm); a second one at the same time is refused (409).
func (h *Hub) lockMailSlot() (func(), error) {
	if !h.mailSlotOp.TryLock() {
		return nil, statusErr(http.StatusConflict, "another mail provider operation is running: try again when it has ended")
	}
	return h.mailSlotOp.Unlock, nil
}

// mailSlotLocked runs the test hook once an op holds its locks.
func (h *Hub) mailSlotLocked(op string) {
	if h.testHookMailSlotLocked != nil {
		h.testHookMailSlotLocked(op)
	}
}
