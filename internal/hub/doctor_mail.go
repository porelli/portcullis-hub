package hub

import (
	"context"
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
	h.mu.RLock()
	api := h.mailAPI
	h.mu.RUnlock()
	if !h.mailOn() {
		return nil
	}
	core := h.mailCore()
	in := &doctor.MailIn{Main: strings.ToLower(h.cfg.Domain), LANOnly: core.SubmissionLAN, Podman: h.cfg.Runtime == runtime.KindPodman,
		// The timer's visits are recorded by POST /host/mail/tls (Task 13).
		ClientIPRewritten: core.ClientIPRewritten}
	if _, why := h.MailRestartFailed(); why != "" {
		in.RestartFailed = why
	}
	in.SyncBlocked = h.MailSyncBlocked()
	h.mu.RLock()
	if p := h.st.Mail.PendingRemoval; p != nil {
		pi := &doctor.MailPendingIn{Since: p.Since, UUIDs: pendingUUIDs(p.Accounts), Confirmed: p.ConfirmedHash != "" && p.ConfirmedHash == pendingHash(p)}
		for _, a := range p.Accounts {
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
	if api == nil || api.Available() != nil {
		// Read again at every doctor run: fixed in place, it clears.
		in.HubSecretInvalid = true
		return in
	}
	ctx, cancel := context.WithTimeout(ctx, mailInputsTimeout)
	defer cancel()
	ch, err := api.Checks(ctx, false)
	if err != nil {
		log.Printf("doctor: mail checks skipped: %v", err)
		in.Unavailable = true
		return in
	}
	st, err := api.Status(ctx)
	if err != nil {
		log.Printf("doctor: mail checks skipped: %v", err)
		in.Unavailable = true
		return in
	}
	in.Checks, in.Status = ch.Checks, &st
	states := h.MailDomainStates()
	for _, p := range plans {
		if s := states[strings.ToLower(p.Name)]; s == mailprovider.MailOn || s == mailprovider.MailDraining {
			in.Plans = append(in.Plans, p)
		}
	}
	return in
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
// the mailboxes (deleted after MAIL_FORMER_RETENTION): TouchesData, and
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
	return "removes the mailboxes of " + strings.Join(users, ", ") + " (parked, deleted after MAIL_FORMER_RETENTION)", doctor.Digest(ids), ids, nil
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
