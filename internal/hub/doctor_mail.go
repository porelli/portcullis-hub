package hub

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/runtime"
)

// The doctor's mail inputs and fixes (contract §14.5–14.6): mailctl's
// checks and status, the added mail domains' plans and the Hub's last
// mail restart. nil with PORTCULLIS_MAIL off; Unavailable when mailctl
// can't be read (the report says mail_unavailable). The fixes
// mail_dmarc_promote and mail_mtasts_enforce run mailctl's action under
// the domain's op key and always need the confirmation through the AI.

// mailInputsTimeout bounds reading mailctl for one doctor run.
const mailInputsTimeout = 10 * time.Second

func init() {
	RegisterFixer(mailActionFixer{kind: doctor.FixMailDMARCPromote, action: mailprovider.ActionDMARCPromote})
	RegisterFixer(mailActionFixer{kind: doctor.FixMailMTASTSEnforce, action: mailprovider.ActionMTASTSEnforce})
	RegisterFixer(mailConfirmRemovalFixer{})
}

// doctorMailIn gathers the mail kinds' inputs (never under mu). plans are
// the doctor's DNS plans already read (the added mail domains' are kept).
func (h *Hub) doctorMailIn(ctx context.Context, plans []domains.Plan) *doctor.MailIn {
	if !h.mailOn() {
		return nil
	}
	core := h.mailCore()
	in := &doctor.MailIn{Main: strings.ToLower(h.cfg.Domain), LANOnly: core.SubmissionLAN, Podman: h.cfg.Runtime == runtime.KindPodman,
		ClientIPRewritten: core.ClientIPRewritten, TimerKnown: true}
	if _, why := h.MailRestartFailed(); why != "" {
		in.RestartFailed = why
	}
	in.SyncBlocked = h.MailSyncBlocked()
	if at, who := h.MailLANOnlyBreach(); !at.IsZero() {
		in.LANBreachUser = who
	}
	for _, p := range h.MailDNSProblems() {
		in.SetProblems = append(in.SetProblems, doctor.MailSetProblem{Domain: p.Domain, Text: p.Reason})
	}
	now := h.mailNow()
	// The doctor judges on the wall clock; the mail times are on
	// mailNow's (the same outside tests): shifted onto the doctor's.
	shift := time.Now().Sub(now)
	onWall := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		w := t.Add(shift)
		return &w
	}
	defer func() {
		in.UnreachableSince = onWall(in.UnreachableSince)
	}()
	h.mu.RLock()
	p := h.st.Mail.Provider
	if p != nil {
		in.Wired, in.Instance = true, p.Instance
	}
	in.VoidOwed = h.st.Mail.VoidOwed != nil
	if hd := h.st.Mail.Held; hd != nil {
		in.Refused = hd.Reason
	}
	in.TimerSeenAt = onWall(h.st.Mail.TLS.SeenAt)
	in.CertNotAfter = h.st.Mail.TLS.NotAfter
	// A switch's retiring DKIM past its 7 days still waits for the new
	// provider's set of that domain.
	for d, r := range h.st.Mail.RetiringDKIM {
		if !now.Before(r.Until.Add(24 * time.Hour)) {
			in.SetProblems = append(in.SetProblems, doctor.MailSetProblem{Domain: d, Text: "the retiring DKIM keys of the former mail provider still wait for the new provider's set"})
		}
	}
	if pr := h.st.Mail.PendingRemoval; pr != nil {
		pi := &doctor.MailPendingIn{Since: pr.Since, UUIDs: pendingUUIDs(pr.Accounts), Confirmed: pr.ConfirmedHash != "" && pr.ConfirmedHash == pendingHash(pr)}
		for _, a := range pr.Accounts {
			pi.Users = append(pi.Users, a.Username)
			if !a.Revoked {
				pi.Failed = append(pi.Failed, a.Username)
			}
		}
		sort.Strings(pi.Users)
		sort.Strings(pi.Failed)
		in.Pending = pi
	}
	h.mu.RUnlock()
	sort.Slice(in.SetProblems, func(i, j int) bool { return in.SetProblems[i].Domain < in.SetProblems[j].Domain })
	if in.VoidOwed {
		in.VoidError, _ = h.MailVoidError()
	}
	in.StopError = h.MailHeldStopError()
	if !in.Wired {
		h.mailReach(true, "")
		return in
	}
	if in.VoidOwed {
		// Void mode: the provider's API is the void's (no checks); its
		// own kind reports a failing void.
		h.mailReach(true, "")
		return in
	}
	api := h.mailClient()
	if api == nil {
		in.Unavailable = true
		why := "its API secret is missing or too short"
		if in.StopError != "" || in.Refused != "" {
			why = "it is held and stopped"
		} else {
			in.SecretInvalid = h.mailSecretInvalid()
		}
		in.UnreachableSince, in.UnreachableWhy = h.mailReach(false, why)
		return in
	}
	ctx, cancel := context.WithTimeout(ctx, mailInputsTimeout)
	defer cancel()
	if info, err := api.Provider(ctx); errors.Is(err, mailprovider.ErrAPIVersion) {
		in.Refused = "the mail provider speaks another provider API version (only 1)"
	} else if err == nil && info.APIVersion != mailprovider.APIVersion {
		in.Refused = "the mail provider speaks another provider API version (only 1)"
	}
	st, err := api.State(ctx)
	if err != nil || !st.Bootstrap {
		why := "bootstrap: false"
		if err != nil {
			why = err.Error()
		}
		log.Printf("doctor: mail provider checks skipped: %s", mailprovider.Shape(why, 300))
		in.Unavailable = true
		in.UnreachableSince, in.UnreachableWhy = h.mailReach(false, why)
		return in
	}
	ch, err := api.Checks(ctx, false)
	if err == nil {
		var sts mailprovider.Status
		if sts, err = api.Status(ctx); err == nil {
			in.Checks, in.Status = ch.Checks, &sts
		}
	}
	if err != nil {
		log.Printf("doctor: mail provider checks skipped: %s", mailprovider.Shape(err.Error(), 300))
		in.Unavailable = true
		in.UnreachableSince, in.UnreachableWhy = h.mailReach(false, err.Error())
		return in
	}
	h.mailReach(true, "")
	states := h.MailDomainStates()
	for _, p := range plans {
		if s := states[strings.ToLower(p.Name)]; s == mailprovider.MailOn || s == mailprovider.MailDraining {
			in.Plans = append(in.Plans, p)
		}
	}
	return in
}

// mailReach records whether the wired provider answered: since is when
// it first didn't (nil: it answers), with the last why.
func (h *Hub) mailReach(ok bool, why string) (*time.Time, string) {
	h.mailUnreach.mu.Lock()
	defer h.mailUnreach.mu.Unlock()
	if ok {
		h.mailUnreach.since = time.Time{}
		return nil, ""
	}
	if h.mailUnreach.since.IsZero() {
		h.mailUnreach.since = h.mailNow()
	}
	h.mailUnreach.why = why
	t := h.mailUnreach.since
	return &t, why
}

// mailActionFixer is the mail_dmarc_promote / mail_mtasts_enforce fix.
type mailActionFixer struct {
	kind, action string
}

func (f mailActionFixer) Kind() string { return f.kind }

// TouchesData: no data on disk, no access.
func (mailActionFixer) TouchesData() bool { return false }

// AlwaysConfirm: a stricter policy makes remote senders refuse mail that
// fails it (contract §14.6: doctor_apply_fix is D for both).
func (mailActionFixer) AlwaysConfirm() bool { return true }

func (mailActionFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	return strings.Join(f.Domains, ",")
}

// mailFixPlan is the fix's one preview line and the hash over the
// domain and what mailctl says now.
func (h *Hub) mailFixPlan(ctx context.Context, kind string, f doctor.Finding, params map[string]string) (domain, line, hash string, err error) {
	if err := checkFixParams(params); err != nil {
		return "", "", "", err
	}
	if len(f.Domains) != 1 || f.Domains[0] == "" {
		return "", "", "", statusErr(http.StatusConflict, "this finding names no single domain")
	}
	domain = NormalizeHost(f.Domains[0])
	api, err := h.mailUp(ctx)
	if err != nil {
		return "", "", "", err
	}
	st, err := api.Status(ctx)
	if err != nil {
		return "", "", "", errMailDown
	}
	switch kind {
	case doctor.FixMailDMARCPromote:
		for _, d := range st.DMARC {
			if strings.EqualFold(d.Domain, domain) && d.Proposed != nil && *d.Proposed != "" {
				return domain, domain + ": DMARC p=" + d.Policy + " → p=" + *d.Proposed,
					doctor.Digest(struct{ Domain, Policy, Proposed string }{domain, d.Policy, *d.Proposed}), nil
			}
		}
	case doctor.FixMailMTASTSEnforce:
		for _, x := range st.MTASTS {
			if strings.EqualFold(x.Domain, domain) && x.EnforceReady {
				return domain, domain + ": MTA-STS " + x.Mode + " → enforce (max_age 604800)",
					doctor.Digest(struct{ Domain, Mode string }{domain, x.Mode}), nil
			}
		}
	}
	return "", "", "", statusErr(http.StatusConflict, "the setup changed since the preview")
}

func (f mailActionFixer) Preview(ctx context.Context, h *Hub, fd doctor.Finding, params map[string]string) (*FixPlan, error) {
	_, line, hash, err := h.mailFixPlan(ctx, f.kind, fd, params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: []string{line}, Hash: hash}, nil
}

func (f mailActionFixer) Apply(h *Hub, fd doctor.Finding, params map[string]string, planHash string, actor directory.Actor) (*AsyncOp, error) {
	if len(fd.Domains) != 1 || fd.Domains[0] == "" {
		return nil, statusErr(http.StatusConflict, "this finding names no single domain")
	}
	name := NormalizeHost(fd.Domains[0])
	// A stale preview is the synchronous 409 (§14.6); the op checks again.
	pctx, cancel := context.WithTimeout(context.Background(), mailInputsTimeout)
	_, _, hash, err := h.mailFixPlan(pctx, f.kind, fd, params)
	cancel()
	if err != nil {
		return nil, err
	}
	if planHash == "" || hash != planHash {
		return nil, statusErr(http.StatusConflict, "the setup changed since the preview")
	}
	return h.startAsync(opKeyDomain(name), f.kind, actor, nil, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		domain, _, hash, err := h.mailFixPlan(ctx, f.kind, fd, params)
		if err != nil {
			return nil, nil, err
		}
		if planHash == "" || hash != planHash {
			return nil, nil, statusErr(http.StatusConflict, "the setup changed since the preview")
		}
		ready()
		if err := h.MailAction(ctx, f.action, domain, actor); err != nil {
			return nil, nil, err
		}
		return map[string]string{"domain": domain}, nil, nil
	})
}

// mailConfirmRemovalFixer is mail_mass_removal_pending's fix: the
// administrator's confirmation of exactly the pending removal. It parks
// the mailboxes (deleted after the former retention): TouchesData, and
// always confirmed through the AI.
type mailConfirmRemovalFixer struct{}

func (mailConfirmRemovalFixer) Kind() string { return doctor.FixMailConfirmRemoval }

func (mailConfirmRemovalFixer) TouchesData() bool { return true }

func (mailConfirmRemovalFixer) AlwaysConfirm() bool { return true }

// confirmRemovalPlan is the preview's one line and the hash over the
// pending uuids.
func (h *Hub) confirmRemovalPlan(params map[string]string) (string, string, []string, error) {
	if err := checkFixParams(params); err != nil {
		return "", "", nil, err
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	p := h.st.Mail.PendingRemoval
	if p == nil || (p.ConfirmedHash != "" && p.ConfirmedHash == pendingHash(p)) {
		return "", "", nil, statusErr(http.StatusConflict, "the setup changed since the preview")
	}
	var users []string
	for _, a := range p.Accounts {
		users = append(users, a.Username)
	}
	sort.Strings(users)
	ids := pendingUUIDs(p.Accounts)
	return "removes the mailboxes of " + strings.Join(users, ", ") + " (parked, deleted after the former retention)", doctor.Digest(ids), ids, nil
}

func (mailConfirmRemovalFixer) Preview(_ context.Context, h *Hub, _ doctor.Finding, params map[string]string) (*FixPlan, error) {
	line, hash, _, err := h.confirmRemovalPlan(params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: []string{line}, Hash: hash, TouchesData: true}, nil
}

func (mailConfirmRemovalFixer) Apply(h *Hub, _ doctor.Finding, params map[string]string, planHash string, actor directory.Actor) (*AsyncOp, error) {
	_, hash, ids, err := h.confirmRemovalPlan(params)
	if err != nil {
		return nil, err
	}
	if planHash == "" || hash != planHash {
		return nil, statusErr(http.StatusConflict, "the setup changed since the preview")
	}
	return h.startAsync(opKeyDomain(strings.ToLower(h.cfg.Domain)), doctor.FixMailConfirmRemoval, actor, nil, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		if err := h.ConfirmMailRemoval(ctx, ids, actor); err != nil {
			return nil, nil, err
		}
		return map[string]string{"accounts": strconv.Itoa(len(ids))}, nil, nil
	})
}
