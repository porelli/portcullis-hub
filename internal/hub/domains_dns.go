package hub

import (
	"context"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
)

// DNS hardening (contract §12.2–12.3): an added domain's DNS plan, the main
// domain's read-only plan, applying record sets and turning DNSSEC
// signing on, all through the domains service. Applying is audited
// domain.dns_apply (detail sets=<a,b>), signing domain.dnssec_enable; the
// doctor's DNS fixes (doctor_dns.go) call the same methods. CAA and
// DNSSEC never block hostnames (assignability is unchanged).

// dnsAPI is the connected domains service (503 without one, or while
// its secret is unreadable).
func (h *Hub) dnsAPI() (DomainsAPI, error) {
	api := h.api()
	if api == nil {
		return nil, &StatusError{Status: 503, Err: domains.ErrNotConfigured}
	}
	if err := api.Available(); err != nil {
		return nil, &StatusError{Status: 503, Err: err}
	}
	return api, nil
}

// knownDomainAPI is the service for an added domain name (404 when the
// Hub doesn't know it, 409 while it is being deleted).
func (h *Hub) knownDomainAPI(name string) (DomainsAPI, error) {
	api, err := h.dnsAPI()
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	known, deleting := h.knownLocked(name), h.domainsDeleting[name]
	h.mu.RUnlock()
	switch {
	case !known:
		return nil, statusErr(404, "%s is not an added domain", name)
	case deleting:
		return nil, statusErr(409, "%s is being removed", name)
	}
	return api, nil
}

// DomainPlan is an added domain's DNS plan (refresh: built again; the
// service throttles it to one per 30 s per name).
func (h *Hub) DomainPlan(ctx context.Context, name string, refresh bool) (domains.Plan, error) {
	name = NormalizeHost(name)
	api, err := h.knownDomainAPI(name)
	if err != nil {
		return domains.Plan{}, err
	}
	p, err := api.Plan(ctx, name, refresh)
	if err != nil {
		return domains.Plan{}, domainsErr(err)
	}
	return p, nil
}

// MainDNSPlan is the main domain's read-only plan (no credentials, every
// fix manual: "run ./portcullis dns setup on the server").
func (h *Hub) MainDNSPlan(ctx context.Context, refresh bool) (domains.Plan, error) {
	api, err := h.dnsAPI()
	if err != nil {
		return domains.Plan{}, err
	}
	p, err := api.MainPlan(ctx, refresh)
	if err != nil {
		return domains.Plan{}, domainsErr(err)
	}
	return p, nil
}

// validDNSSets: a non-empty list of known record sets, each once (400
// otherwise, before anything is forwarded).
func validDNSSets(sets []string) error {
	if len(sets) == 0 {
		return statusErr(400, "no record set: name one or more of %s", strings.Join(domains.Sets, ", "))
	}
	seen := map[string]bool{}
	for _, s := range sets {
		if !slices.Contains(domains.Sets, s) {
			return statusErr(400, "unknown record set %q (one of %s)", clip(s, 32), strings.Join(domains.Sets, ", "))
		}
		if seen[s] {
			return statusErr(400, "record set %s named twice", s)
		}
		seen[s] = true
	}
	return nil
}

// ApplyDomainDNS makes sets due on an added domain (the service's records
// step writes them in the background). Audited domain.dns_apply, detail
// sets=<a,b> (only valid set names ever reach the detail).
func (h *Hub) ApplyDomainDNS(ctx context.Context, actor directory.Actor, name string, sets []string) (d domains.Domain, err error) {
	name = NormalizeHost(name)
	detail := "sets=(invalid)"
	if validDNSSets(sets) == nil {
		detail = "sets=" + strings.Join(sets, ",")
	}
	defer func() { h.auditOp(actor, "domain.dns_apply", name, detail, err) }()
	if strings.TrimSpace(actor.User) == "" {
		return d, statusErr(400, "no signed-in user to audit the change as")
	}
	if err := validDNSSets(sets); err != nil {
		return d, err
	}
	return h.domainCall(ctx, name, func(ctx context.Context, api DomainsAPI) (domains.Domain, error) {
		return api.ApplySets(ctx, name, sets)
	})
}

// EnableDomainDNSSEC asks the service to turn DNSSEC signing on for an
// added domain's zone (zone-wide; never turned off from Portcullis). The
// service's 409 "<provider> can't sign the zone through its API" passes
// through. Audited domain.dnssec_enable. Through the AI it needs the
// consumed confirmation (defence in depth: enable_domain_dnssec is D).
func (h *Hub) EnableDomainDNSSEC(ctx context.Context, actor directory.Actor, name string) (d domains.Domain, err error) {
	name = NormalizeHost(name)
	defer func() { h.auditOp(actor, "domain.dnssec_enable", name, "", err) }()
	if strings.TrimSpace(actor.User) == "" {
		return d, statusErr(400, "no signed-in user to audit the change as")
	}
	if err := aiUnconfirmed(actor, "turning on DNSSEC signing signs the whole zone"); err != nil {
		return d, err
	}
	return h.domainCall(ctx, name, func(ctx context.Context, api DomainsAPI) (domains.Domain, error) {
		return api.EnableDNSSEC(ctx, name)
	})
}

// domainCall runs call on an added domain under the domain-operation lock
// (no delete in between) and records the answer in the known list.
func (h *Hub) domainCall(ctx context.Context, name string, call func(context.Context, DomainsAPI) (domains.Domain, error)) (domains.Domain, error) {
	h.domainOpMu.Lock()
	defer h.domainOpMu.Unlock()
	api, err := h.knownDomainAPI(name)
	if err != nil {
		return domains.Domain{}, err
	}
	d, err := call(context.WithoutCancel(ctx), api)
	if err != nil {
		return domains.Domain{}, domainsErr(err)
	}
	h.mu.Lock()
	h.domainsGen++
	h.upsertKnownLocked(d)
	h.saveLocked()
	h.mu.Unlock()
	return d, nil
}
