package hub

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/templates"
)

// The doctor's DNS inputs and fixes (contract §14.5–14.6, DNS hardening).
// The inputs are the cached plans (no refresh) of every added domain and
// of the main domain, read outside mu within dnsInputsTimeout; when they
// can't be read the doctor has no DNS findings and its report says
// dns_unavailable. The fixes run in the background under the op key
// _domain.<name> (GET /api/domains/{name}/op): dns_apply writes the
// finding's record set, dnssec_sign turns signing on (zone-wide, so it
// always needs the confirmation through the AI, though it touches no
// data).

// DNS fix operations (their op record key is opKeyDomain(name)).
const (
	OpDNSApply   = "dns_apply"
	OpDNSSECSign = "dnssec_sign"
)

// dnsInputsTimeout bounds reading the plans for one doctor run.
const dnsInputsTimeout = 10 * time.Second

func opKeyDomain(name string) string { return "_domain." + name }

// OpKeyDomain is an added domain's op record key (the DNS fixes').
func OpKeyDomain(name string) string { return opKeyDomain(NormalizeHost(name)) }

// validDomainOpKey: k is an opKeyDomain of a valid hostname.
func validDomainOpKey(k string) bool {
	n, ok := strings.CutPrefix(k, "_domain.")
	return ok && templates.ValidHostname(n)
}

func init() {
	RegisterFixer(dnsApplyFixer{})
	RegisterFixer(dnssecSignFixer{})
}

// dnsDoctorInputs reads the cached DNS plans (before mu). nil, nil: they
// couldn't be read (logged). A domain the service doesn't answer for
// (404: removed meanwhile) is left out.
func (h *Hub) dnsDoctorInputs(ctx context.Context) ([]domains.Plan, *domains.Plan) {
	api, err := h.dnsAPI()
	if err != nil {
		log.Printf("doctor: DNS checks skipped: %v", err)
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, dnsInputsTimeout)
	defer cancel()
	h.mu.RLock()
	var names []string
	for _, d := range h.st.Domains {
		if d.State != DomainMissing && !h.domainsDeleting[d.Name] {
			names = append(names, d.Name)
		}
	}
	h.mu.RUnlock()
	main, err := api.MainPlan(ctx, false)
	if err != nil {
		log.Printf("doctor: DNS checks skipped: the main domain's plan: %v", err)
		return nil, nil
	}
	plans := []domains.Plan{}
	for _, n := range names {
		p, err := api.Plan(ctx, n, false)
		var ae *domains.APIError
		switch {
		case errors.As(err, &ae) && ae.Status == http.StatusNotFound:
			continue
		case err != nil:
			log.Printf("doctor: DNS checks skipped: the plan of %s: %v", n, err)
			return nil, nil
		}
		if p.Name == "" {
			p.Name = n
		}
		plans = append(plans, p)
	}
	return plans, &main
}

// confirmAlways is an optional Fixer part: a fix that always needs the
// person's confirmation through the AI although it touches no data
// (dnssec_sign: zone-wide, not undoable from Portcullis).
type confirmAlways interface{ AlwaysConfirm() bool }

func fixerAlwaysConfirms(fx Fixer) bool {
	c, ok := fx.(confirmAlways)
	return ok && c.AlwaysConfirm()
}

// findingDomain is the one added domain finding f is about (409 for the
// main domain or none: its fixes are explain-only).
func (h *Hub) findingDomain(f doctor.Finding) (string, error) {
	if len(f.Domains) != 1 || f.Domains[0] == "" {
		return "", statusErr(http.StatusConflict, "this finding names no single domain")
	}
	name := NormalizeHost(f.Domains[0])
	if strings.EqualFold(name, h.cfg.Domain) {
		return "", statusErr(http.StatusConflict, "the main domain's records are set on the server: run ./portcullis dns setup there")
	}
	return name, nil
}

// ── dns_apply ──────────────────────────────────────────

type dnsApplyFixer struct{}

func (dnsApplyFixer) Kind() string { return doctor.FixDNSApply }

// TouchesData: DNS records at the provider, no data on disk, no access.
func (dnsApplyFixer) TouchesData() bool { return false }

func (dnsApplyFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	return strings.Join(f.Domains, ",") + " sets=" + strings.Join(doctor.DNSFixSets(f.Kind), ",")
}

// dnsApplyPlan is the fix's preview: the finding's set, the refreshed
// plan's differing items of that set, the hash over their live values.
type dnsApplyPlan struct {
	name  string
	sets  []string
	lines []string
	hash  string
}

func (h *Hub) dnsApplyPlan(ctx context.Context, f doctor.Finding, params map[string]string) (*dnsApplyPlan, error) {
	if err := checkFixParams(params, "sets"); err != nil {
		return nil, err
	}
	name, err := h.findingDomain(f)
	if err != nil {
		return nil, err
	}
	sets := doctor.DNSFixSets(f.Kind)
	if len(sets) == 0 {
		return nil, statusErr(http.StatusConflict, "finding %s writes no record set", f.Kind)
	}
	if v := params["sets"]; v != "" && v != strings.Join(sets, ",") {
		return nil, statusErr(http.StatusBadRequest, "this finding's fix writes sets=%s", strings.Join(sets, ","))
	}
	p, err := h.DomainPlan(ctx, name, true)
	if err != nil {
		return nil, err
	}
	pl := &dnsApplyPlan{name: name, sets: sets}
	var live [][]string
	for _, it := range p.Items {
		if !slices.Contains(sets, it.Set) || (it.Status != "missing" && it.Status != "wrong") {
			continue
		}
		cur := "—"
		if len(it.Live) > 0 {
			cur = strings.Join(it.Live, ", ")
		}
		pl.lines = append(pl.lines, it.Set+" "+it.Name+" "+it.Type+": "+cur+" → "+strings.Join(it.Want, ", "))
		live = append(live, append([]string{it.Set, it.Name, it.Type}, it.Live...))
	}
	if len(pl.lines) == 0 {
		return nil, statusErr(http.StatusConflict, "the %s records of %s already match: run the doctor again", strings.Join(sets, ","), name)
	}
	pl.hash = doctor.Digest(struct {
		Name string
		Sets []string
		Live [][]string
	}{name, sets, live})
	return pl, nil
}

func (dnsApplyFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	pl, err := h.dnsApplyPlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: pl.lines, Hash: pl.hash}, nil
}

func errDNSChanged() error {
	return statusErr(http.StatusConflict, "the DNS records changed since the preview: preview it again")
}

func (dnsApplyFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash string, actor directory.Actor) (*AsyncOp, error) {
	name, err := h.findingDomain(f)
	if err != nil {
		return nil, err
	}
	return h.startAsync(opKeyDomain(name), OpDNSApply, actor, nil, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		pl, err := h.dnsApplyPlan(ctx, f, params)
		if err != nil {
			return nil, nil, err
		}
		if planHash == "" || pl.hash != planHash {
			return nil, nil, errDNSChanged()
		}
		ready()
		d, err := h.ApplyDomainDNS(ctx, actor, name, pl.sets)
		if err != nil {
			return nil, nil, err
		}
		return map[string]string{"domain": name, "sets": strings.Join(pl.sets, ","), "state": d.State}, nil, nil
	})
}

// ── dnssec_sign ────────────────────────────────────────

type dnssecSignFixer struct{}

func (dnssecSignFixer) Kind() string { return doctor.FixDNSSECSign }

// TouchesData: signing changes the zone at the provider, no data on disk
// and no access — but it is zone-wide: AlwaysConfirm.
func (dnssecSignFixer) TouchesData() bool { return false }

// AlwaysConfirm: doctor_apply_fix is D for it (security ruling, like
// enable_domain_dnssec).
func (dnssecSignFixer) AlwaysConfirm() bool { return true }

func (dnssecSignFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	return strings.Join(f.Domains, ",")
}

// dnssecSignPlan: the zone and its state (unsigned, the provider signs).
func (h *Hub) dnssecSignPlan(ctx context.Context, f doctor.Finding, params map[string]string) (name, zone, hash string, err error) {
	if err := checkFixParams(params); err != nil {
		return "", "", "", err
	}
	if name, err = h.findingDomain(f); err != nil {
		return "", "", "", err
	}
	p, err := h.DomainPlan(ctx, name, true)
	if err != nil {
		return "", "", "", err
	}
	switch {
	case p.DNSSEC.State != "unsigned":
		return "", "", "", statusErr(http.StatusConflict, "the zone of %s is %s now, not unsigned: run the doctor again", name, clip(p.DNSSEC.State, 32))
	case !p.DNSSEC.ProviderCanSign:
		return "", "", "", statusErr(http.StatusConflict, "the provider of %s can't sign the zone through its API", name)
	}
	zone = p.DNSSEC.Zone
	if zone == "" {
		zone = name
	}
	return name, zone, doctor.Digest(struct{ Zone, State string }{zone, p.DNSSEC.State}), nil
}

func (dnssecSignFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	_, zone, hash, err := h.dnssecSignPlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: []string{"turns on signing for the whole zone " + zone}, Hash: hash}, nil
}

func (dnssecSignFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash string, actor directory.Actor) (*AsyncOp, error) {
	name, err := h.findingDomain(f)
	if err != nil {
		return nil, err
	}
	return h.startAsync(opKeyDomain(name), OpDNSSECSign, actor, nil, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		_, zone, hash, err := h.dnssecSignPlan(ctx, f, params)
		if err != nil {
			return nil, nil, err
		}
		if planHash == "" || hash != planHash {
			return nil, nil, errDNSChanged()
		}
		ready()
		d, err := h.EnableDomainDNSSEC(ctx, actor, name)
		if err != nil {
			return nil, nil, err
		}
		return map[string]string{"domain": name, "zone": zone, "state": d.State}, nil, nil
	})
}
