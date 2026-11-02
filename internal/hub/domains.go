package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Enrolled domains (contract §12.3): the Hub enrolls, re-keys and removes
// domains through core's domains service, and keeps the last known list
// (names, provider, status — never credentials) in state.yaml. That list
// is the production DomainSource: it feeds host validation (assignable =
// records OK + a certificate valid now + the service reachable),
// extra_domains in the policy file and domains in portal-apps.json, also
// while the service is down. Credentials pass through EnrollDomain /
// ReplaceDomainToken once and are never stored, logged, audited or put in
// errors here.

// DomainUnreachable is the Domain state while the domains service can't be
// reached (or isn't configured): hosts on enrolled domains can't be newly
// assigned (503), existing ones stay.
const DomainUnreachable = "unreachable"

// DomainsAPI is core's domains service (internal/domains.Client).
type DomainsAPI interface {
	Available() error
	List(ctx context.Context) ([]domains.Domain, error)
	Enroll(ctx context.Context, name, provider string, creds map[string]string) (domains.Domain, error)
	SetToken(ctx context.Context, name, provider string, creds map[string]string) (domains.Domain, error)
	Delete(ctx context.Context, name string) (warning string, err error)
}

// SetDomainsAPI connects the domains service; the known list in state.yaml
// becomes the domain source (it already is by default).
func (h *Hub) SetDomainsAPI(api DomainsAPI) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.domainsAPI = api
	h.domains = knownDomains{h}
	h.rebuildLocked()
}

// knownDomains is the DomainSource over state.yaml's last known list. Its
// Domains is called under h.mu and does no I/O.
type knownDomains struct{ h *Hub }

func (k knownDomains) Domains() []Domain {
	h := k.h
	out := []Domain{{Name: h.cfg.Domain, State: DomainReady}}
	now := time.Now()
	for _, d := range h.st.Domains {
		st := d.State
		switch {
		case !h.domainsReachable:
			st = DomainUnreachable
		case knownAssignable(d, now):
			st = DomainReady
		case st == DomainReady:
			st = "certificate expired"
		}
		out = append(out, Domain{Name: d.Name, State: st})
	}
	return out
}

func knownAssignable(d state.KnownDomain, now time.Time) bool {
	return d.RecordsOK && d.CertNotAfter != nil && d.CertNotAfter.After(now)
}

func toKnown(list []domains.Domain) []state.KnownDomain {
	out := make([]state.KnownDomain, 0, len(list))
	for _, d := range list {
		out = append(out, state.KnownDomain{Name: NormalizeHost(d.Name), Provider: d.Provider, RecordsOK: d.RecordsOK,
			CertNotAfter: d.CertNotAfter, LastError: d.LastError, State: d.State})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func fromKnown(list []state.KnownDomain) []domains.Domain {
	out := make([]domains.Domain, 0, len(list))
	for _, d := range list {
		out = append(out, domains.Domain{Name: d.Name, Provider: d.Provider, RecordsOK: d.RecordsOK,
			CertNotAfter: d.CertNotAfter, LastError: d.LastError, State: d.State})
	}
	return out
}

func knownNames(list []state.KnownDomain) []string {
	out := make([]string, 0, len(list))
	for _, d := range list {
		out = append(out, d.Name)
	}
	return out
}

// domainsErr maps a domains client error to a StatusError (the service's
// 400/404/409 pass through; unreachable / not configured is 503). The
// client already keeps credentials out of its errors.
func domainsErr(err error) error {
	var ae *domains.APIError
	switch {
	case errors.As(err, &ae):
		status := ae.Status
		if status >= 500 || status == 401 {
			status = 502
		}
		return &StatusError{Status: status, Err: err}
	case errors.Is(err, domains.ErrUnreachable), errors.Is(err, domains.ErrNotConfigured):
		return &StatusError{Status: 503, Err: err}
	}
	return &StatusError{Status: 502, Err: err}
}

func (h *Hub) api() DomainsAPI {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.domainsAPI
}

func (h *Hub) setReachable(ok bool) {
	h.mu.Lock()
	h.domainsReachable = ok
	h.mu.Unlock()
}

// DomainsAvailable reports why the Domains section is disabled (nil = it
// works).
func (h *Hub) DomainsAvailable() error {
	api := h.api()
	if api == nil {
		return domains.ErrNotConfigured
	}
	return api.Available()
}

// KnownDomains is the last known list (state.yaml), for when the service
// can't be reached.
func (h *Hub) KnownDomains() []domains.Domain {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return fromKnown(h.st.Domains)
}

// RefreshDomains reads the service's list and makes it the known list
// (the service is authoritative while reachable). Unreachable: 503 and
// the known list stays (and keeps being published).
func (h *Hub) RefreshDomains(ctx context.Context) ([]domains.Domain, error) {
	api := h.api()
	if api == nil {
		return nil, &StatusError{Status: 503, Err: domains.ErrNotConfigured}
	}
	if err := api.Available(); err != nil {
		h.setReachable(false)
		return nil, &StatusError{Status: 503, Err: err}
	}
	list, err := api.List(ctx)
	if err != nil {
		h.setReachable(false)
		return nil, domainsErr(err)
	}
	known := toKnown(list)
	h.mu.Lock()
	h.domainsReachable = true
	namesChanged := !reflect.DeepEqual(knownNames(known), knownNames(h.st.Domains))
	changed := !reflect.DeepEqual(known, h.st.Domains)
	if changed {
		if len(known) == 0 {
			h.st.Domains = nil
		} else {
			h.st.Domains = known
		}
		h.saveLocked()
	}
	h.mu.Unlock()
	if namesChanged {
		if err := h.WritePolicy(); err != nil {
			log.Printf("domains: policy write after a domain list change failed: %v", err)
		}
	}
	return list, nil
}

// RunDomainSync refreshes the known list every interval (status and
// reachability for host validation).
func (h *Hub) RunDomainSync(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if h.api() != nil {
			c, cancel := context.WithTimeout(ctx, 30*time.Second)
			if _, err := h.RefreshDomains(c); err != nil {
				log.Printf("domains: %v", err)
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// knownHostsLocked is every hostname the Hub knows to be in use or
// reserved: instance views, state instances, published snapshots, the
// hosts running app projects route (runtime), and every template's default
// hostnames on the main domain. Caller holds mu.
func (h *Hub) knownHostsLocked(runtime map[string][]string) map[string]string {
	main := strings.ToLower(h.cfg.Domain)
	out := map[string]string{} // host → who
	add := func(host, who string) {
		if host = NormalizeHost(host); host != "" {
			if _, ok := out[host]; !ok {
				out[host] = who
			}
		}
	}
	for i := range h.instances {
		v := &h.instances[i]
		for _, host := range v.Hosts {
			add(host, "instance "+v.ID)
		}
		for _, s := range v.Subdomains {
			add(s+"."+main, "instance "+v.ID)
		}
	}
	for id, e := range h.st.Instances {
		for _, host := range e.Hosts {
			add(host, "instance "+id)
		}
	}
	for id, snap := range h.st.Published {
		for _, host := range append(append([]string{}, snap.Hosts...), snap.PublicHosts...) {
			add(host, "instance "+id+" (published)")
		}
	}
	for id, hosts := range runtime {
		for _, host := range hosts {
			add(host, "running project of "+id)
		}
	}
	for _, t := range h.allTemplates {
		for _, s := range t.Subdomains {
			add(s+"."+main, "template "+t.ID+" (default hostname)")
		}
	}
	return out
}

// checkEnrollLocked applies §12.3 "Enroll" and the reclassification rule:
// a domain must not turn hosts the Hub already knows into extra-domain
// hosts (e.g. team-a.<main> while a template defaults to subdomain team-a,
// or x.team-a.<main> routed by an instance). Caller holds mu.
func (h *Hub) checkEnrollLocked(name string, runtime map[string][]string) error {
	main := strings.ToLower(h.cfg.Domain)
	if name == main || strings.HasSuffix(main, "."+name) {
		return statusErr(400, "%s is the main domain or a parent of it: it can't be enrolled", name)
	}
	for sub := range policy.CoreSubdomains() {
		c := sub + "." + main
		if name == c || strings.HasSuffix(name, "."+c) {
			return statusErr(409, "%s is at or under the core host %s: extra domains never carry core pages", name, c)
		}
	}
	for _, d := range h.st.Domains {
		switch {
		case d.Name == name:
			return statusErr(409, "%s is already enrolled", name)
		case strings.HasSuffix(name, "."+d.Name):
			return statusErr(409, "%s is under the enrolled domain %s (enrolled domains never nest)", name, d.Name)
		case strings.HasSuffix(d.Name, "."+name):
			return statusErr(409, "%s is above the enrolled domain %s (enrolled domains never nest)", name, d.Name)
		}
	}
	known := h.knownHostsLocked(runtime)
	hosts := make([]string, 0, len(known))
	for host := range known {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		if host == name || strings.HasSuffix(host, "."+name) {
			return statusErr(409, "%s would take over the hostname %s (%s): change that hostname first", name, host, known[host])
		}
	}
	return nil
}

func (h *Hub) runtimeCopy() map[string][]string {
	h.driftMu.Lock()
	defer h.driftMu.Unlock()
	out := make(map[string][]string, len(h.runtimeHosts))
	for id, hosts := range h.runtimeHosts {
		out[id] = append([]string(nil), hosts...)
	}
	return out
}

// upsertKnownLocked records d in the known list. Caller holds mu.
func (h *Hub) upsertKnownLocked(d domains.Domain) {
	k := toKnown([]domains.Domain{d})[0]
	for i := range h.st.Domains {
		if h.st.Domains[i].Name == k.Name {
			h.st.Domains[i] = k
			return
		}
	}
	h.st.Domains = append(h.st.Domains, k)
	sort.Slice(h.st.Domains, func(i, j int) bool { return h.st.Domains[i].Name < h.st.Domains[j].Name })
}

func (h *Hub) knownLocked(name string) bool {
	for _, d := range h.st.Domains {
		if d.Name == name {
			return true
		}
	}
	return false
}

// EnrollDomain enrolls name (contract §12.3): validated against the known
// domains and hosts, forwarded once with the credentials, recorded without
// them. Audited as domain.enroll (provider only).
func (h *Hub) EnrollDomain(ctx context.Context, actor, name, provider string, creds map[string]string) (d domains.Domain, err error) {
	name = NormalizeHost(name)
	defer func() { h.auditOp(actor, "domain.enroll", name, "provider "+provider, err) }()
	if strings.TrimSpace(actor) == "" {
		return d, statusErr(400, "no signed-in user to audit the change as")
	}
	if !templates.ValidHostname(name) {
		return d, statusErr(400, "%q is not a valid hostname (lowercase labels, no scheme, port or wildcard)", name)
	}
	h.domainOpMu.Lock()
	defer h.domainOpMu.Unlock()
	if _, err := h.RefreshDomains(ctx); err != nil {
		return d, err
	}
	runtime := h.runtimeCopy()
	h.mu.RLock()
	err = h.checkEnrollLocked(name, runtime)
	api := h.domainsAPI
	h.mu.RUnlock()
	if err != nil {
		return d, err
	}
	d, err = api.Enroll(ctx, name, provider, creds)
	if err != nil {
		return d, domainsErr(err)
	}
	// Re-check: a host may have been taken meanwhile (create, hostname
	// change). Undo the enrollment then.
	runtime = h.runtimeCopy()
	h.mu.Lock()
	if cerr := h.checkEnrollLocked(name, runtime); cerr != nil {
		h.mu.Unlock()
		if _, derr := api.Delete(context.Background(), name); derr != nil {
			log.Printf("domains: undoing the enrollment of %s after a lost race failed: %v", name, derr)
		}
		return domains.Domain{}, cerr
	}
	h.upsertKnownLocked(d)
	h.saveLocked()
	h.mu.Unlock()
	if perr := h.WritePolicy(); perr != nil {
		log.Printf("domains: policy write after enrolling %s failed: %v", name, perr)
	}
	log.Printf("domains: %s enrolled (provider %s)", name, provider)
	return d, nil
}

// ReplaceDomainToken replaces an enrolled domain's credentials. Audited as
// domain.token (provider only).
func (h *Hub) ReplaceDomainToken(ctx context.Context, actor, name, provider string, creds map[string]string) (d domains.Domain, err error) {
	name = NormalizeHost(name)
	defer func() { h.auditOp(actor, "domain.token", name, "provider "+provider, err) }()
	if strings.TrimSpace(actor) == "" {
		return d, statusErr(400, "no signed-in user to audit the change as")
	}
	h.domainOpMu.Lock()
	defer h.domainOpMu.Unlock()
	if _, err := h.RefreshDomains(ctx); err != nil {
		return d, err
	}
	h.mu.RLock()
	known, api := h.knownLocked(name), h.domainsAPI
	h.mu.RUnlock()
	if !known {
		return d, statusErr(404, "%s is not enrolled", name)
	}
	d, err = api.SetToken(ctx, name, provider, creds)
	if err != nil {
		return d, domainsErr(err)
	}
	h.mu.Lock()
	h.upsertKnownLocked(d)
	h.saveLocked()
	h.mu.Unlock()
	return d, nil
}

// domainUsersLocked lists the instances with a hostname on name (enabled
// or not, resolvable or not, published snapshots included). Caller holds mu.
func (h *Hub) domainUsersLocked(name string) []string {
	set := map[string]bool{}
	on := func(host string) bool {
		host = NormalizeHost(host)
		return host == name || strings.HasSuffix(host, "."+name)
	}
	for i := range h.instances {
		for _, host := range h.instances[i].Hosts {
			if on(host) {
				set[h.instances[i].ID] = true
			}
		}
	}
	for id, e := range h.st.Instances {
		for _, host := range e.Hosts {
			if on(host) {
				set[id] = true
			}
		}
	}
	for id, snap := range h.st.Published {
		for _, host := range append(append([]string{}, snap.Hosts...), snap.PublicHosts...) {
			if on(host) {
				set[id] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// DeleteDomain removes an enrolled domain; 409 while any instance has a
// hostname on it (the Hub is the authority on assignments, §12.3).
// Audited as domain.delete. warning: DNS records the service couldn't
// remove.
func (h *Hub) DeleteDomain(ctx context.Context, actor, name string) (warning string, err error) {
	name = NormalizeHost(name)
	defer func() { h.auditOp(actor, "domain.delete", name, warning, err) }()
	if strings.TrimSpace(actor) == "" {
		return "", statusErr(400, "no signed-in user to audit the change as")
	}
	h.domainOpMu.Lock()
	defer h.domainOpMu.Unlock()
	if _, err := h.RefreshDomains(ctx); err != nil {
		return "", err
	}
	h.mu.RLock()
	known, users, api := h.knownLocked(name), h.domainUsersLocked(name), h.domainsAPI
	h.mu.RUnlock()
	if !known {
		return "", statusErr(404, "%s is not enrolled", name)
	}
	if len(users) > 0 {
		return "", statusErr(409, "%s is used by instance(s) %s: move their hostnames or delete them first", name, strings.Join(users, ", "))
	}
	warning, err = api.Delete(ctx, name)
	var ae *domains.APIError
	if err != nil && !(errors.As(err, &ae) && ae.Status == 404) {
		return "", domainsErr(err)
	}
	h.mu.Lock()
	// An instance may have taken a host on it meanwhile: it keeps it, but
	// the domain is gone either way (the service deleted it).
	if late := h.domainUsersLocked(name); len(late) > 0 {
		log.Printf("domains: %s was removed while instance(s) %s took a hostname on it", name, strings.Join(late, ", "))
	}
	kept := h.st.Domains[:0]
	for _, d := range h.st.Domains {
		if d.Name != name {
			kept = append(kept, d)
		}
	}
	h.st.Domains = kept
	if len(h.st.Domains) == 0 {
		h.st.Domains = nil
	}
	h.saveLocked()
	h.mu.Unlock()
	if perr := h.WritePolicy(); perr != nil {
		log.Printf("domains: policy write after removing %s failed: %v", name, perr)
	}
	log.Printf("domains: %s removed%s", name, map[bool]string{true: " (warning: " + warning + ")", false: ""}[warning != ""])
	return warning, nil
}

// errDomainsUnreachable is the 503 placeHost returns for a new host on an
// enrolled domain while the service is down.
func errDomainsUnreachable(host, router, domain string) error {
	return &StatusError{Status: 503, Err: fmt.Errorf("hostname %s (host router %s): the domains service is unreachable, so domain %s can't receive new hostnames right now", host, router, domain)}
}
