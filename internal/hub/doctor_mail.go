package hub

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailctl"
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
	RegisterFixer(mailActionFixer{kind: doctor.FixMailDMARCPromote, action: mailctl.ActionDMARCPromote})
	RegisterFixer(mailActionFixer{kind: doctor.FixMailMTASTSEnforce, action: mailctl.ActionMTASTSEnforce})
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
	in := &doctor.MailIn{Main: strings.ToLower(h.cfg.Domain), LANOnly: core.SubmissionLAN, Podman: h.cfg.Runtime == runtime.KindPodman}
	if _, why := h.MailRestartFailed(); why != "" {
		in.RestartFailed = why
	}
	if api == nil || api.Available() != nil {
		in.Unavailable = true
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
		if s := states[strings.ToLower(p.Name)]; s == mailctl.MailOn || s == mailctl.MailDraining {
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
