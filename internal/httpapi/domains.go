package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/hub"
)

// Added domains (contract §11.7, §12.3): Hub listener only, admins only
// (lldap_admin; delegates 403), proxy-secret + CSRF like every route,
// audited in the Hub (domain.add|token|delete). Credentials are
// write-only: they are read from the body, forwarded once and never
// echoed — not in answers, not in errors (a malformed body gets a fixed
// message, never the decoder's).

func (s *Server) registerDomains(mux routeMux) {
	mux.HandleFunc("GET /api/domains", s.handleDomains)
	mux.HandleFunc("POST /api/domains", s.handleEnrollDomain)
	mux.HandleFunc("POST /api/domains/{name}/token", s.handleDomainToken)
	mux.HandleFunc("DELETE /api/domains/{name}", s.handleDeleteDomain)
	// DNS hardening (§12.2–12.3): the DNS plan, applying record sets,
	// turning DNSSEC signing on, the main domain's read-only plan.
	mux.HandleFunc("GET /api/domains/{name}/dns", s.handleDomainDNS)
	mux.HandleFunc("POST /api/domains/{name}/dns/apply", s.handleDomainDNSApply)
	mux.HandleFunc("POST /api/domains/{name}/dnssec", s.handleDomainDNSSEC)
	mux.HandleFunc("GET /api/dns/main", s.handleMainDNS)
	// The op record of the domain's last doctor DNS fix (F2).
	mux.HandleFunc("GET /api/domains/{name}/op", s.handleDomainOp)
}

func (s *Server) handleDomainOp(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	name := hub.NormalizeHost(r.PathValue("name"))
	s.rec("LastOp", hub.OpKeyDomain(name))
	s.writeOpRecord(w, hub.OpKeyDomain(name), "domain "+name)
}

// adminOnly resolves the caller and refuses non-admins (403). Without the
// directory (LLDAP) nobody can be checked: 503.
func (s *Server) adminOnly(w http.ResponseWriter, r *http.Request) bool {
	if s.Directory == nil {
		http.Error(w, "user management not configured: admin check unavailable", http.StatusServiceUnavailable)
		return false
	}
	c, ok := s.caller(w, r)
	if !ok {
		return false
	}
	if !c.Admin {
		http.Error(w, "not allowed: admins only", http.StatusForbidden)
		return false
	}
	return true
}

type domainCredsBody struct {
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
}

// readDomainCreds decodes the credentials body; errors never quote it.
func readDomainCreds(w http.ResponseWriter, r *http.Request) (domainCredsBody, bool) {
	var b domainCredsBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, `body must be {"name": "<domain>", "provider": "<provider>", "credentials": {"<key>": "<string>", ...}}`, http.StatusBadRequest)
		return b, false
	}
	if b.Provider == "" || len(b.Credentials) == 0 {
		http.Error(w, "provider and credentials are required", http.StatusBadRequest)
		return b, false
	}
	return b, true
}

// domainsErr writes a hub error as {"error": msg} JSON (the UI shows it).
func writeDomainsErr(w http.ResponseWriter, err error) {
	code := http.StatusBadGateway
	var se *hub.StatusError
	if errors.As(err, &se) {
		code = se.Status
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// handleDomains passes the service's list through. While the service is
// unreachable (or not configured): 503 with the reason and the last known
// list, so the page can still show it.
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	if err := s.Hub.DomainsAvailable(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "domains disabled: " + err.Error(), "disabled": true, "domains": s.Hub.KnownDomains()})
		return
	}
	list, err := s.Hub.RefreshDomains(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error(), "domains": s.Hub.KnownDomains()})
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleEnrollDomain(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	b, ok := readDomainCreds(w, r)
	if !ok {
		return
	}
	d, err := s.Hub.EnrollDomain(r.Context(), requestActor(r), b.Name, b.Provider, b.Credentials)
	noStore(w)
	if err != nil {
		writeDomainsErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(d)
}

func (s *Server) handleDomainToken(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	b, ok := readDomainCreds(w, r)
	if !ok {
		return
	}
	if b.Name != "" && hub.NormalizeHost(b.Name) != hub.NormalizeHost(r.PathValue("name")) {
		http.Error(w, "name in the body differs from the path", http.StatusBadRequest)
		return
	}
	d, err := s.Hub.ReplaceDomainToken(r.Context(), requestActor(r), r.PathValue("name"), b.Provider, b.Credentials)
	noStore(w)
	if err != nil {
		writeDomainsErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(d)
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	warning, err := s.deleteDomain(r.Context(), requestActor(r), r.PathValue("name"))
	noStore(w)
	if err != nil {
		writeDomainsErr(w, err)
		return
	}
	if warning != "" {
		writeJSON(w, map[string]string{"warning": warning})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteDomain is the removal's work (route and delete_domain); audited
// domain.delete by the Hub. A plain error is the route's 502.
func (s *Server) deleteDomain(ctx context.Context, a directory.Actor, name string) (string, error) {
	s.rec("DeleteDomain", name)
	warning, err := s.Hub.DeleteDomain(ctx, a, name)
	return warning, defaultStatus(err, http.StatusBadGateway)
}

// ── DNS plans (DNS hardening) ─────────────────────────────

// refreshParam: ?refresh=1 asks the service to build the plan again.
func refreshParam(r *http.Request) bool { return r.URL.Query().Get("refresh") == "1" }

// domainDNS is GET /api/domains/{name}/dns's work (route and get_domain_dns).
func (s *Server) domainDNS(ctx context.Context, name string, refresh bool) (domains.Plan, error) {
	s.rec("DomainPlan", name, refresh)
	p, err := s.Hub.DomainPlan(ctx, name, refresh)
	return p, defaultStatus(err, http.StatusBadGateway)
}

// mainDNS is GET /api/dns/main's work (route and get_main_dns).
func (s *Server) mainDNS(ctx context.Context, refresh bool) (domains.Plan, error) {
	s.rec("MainDNSPlan", refresh)
	p, err := s.Hub.MainDNSPlan(ctx, refresh)
	return p, defaultStatus(err, http.StatusBadGateway)
}

// applyDomainDNS is POST /api/domains/{name}/dns/apply's work (route and
// apply_domain_dns); audited domain.dns_apply by the Hub.
func (s *Server) applyDomainDNS(ctx context.Context, a directory.Actor, name string, sets []string) (domains.Domain, error) {
	s.rec("ApplyDomainDNS", name, sets)
	d, err := s.Hub.ApplyDomainDNS(ctx, a, name, sets)
	return d, defaultStatus(err, http.StatusBadGateway)
}

// enableDomainDNSSEC is POST /api/domains/{name}/dnssec's work (route and
// enable_domain_dnssec); audited domain.dnssec_enable by the Hub.
func (s *Server) enableDomainDNSSEC(ctx context.Context, a directory.Actor, name string) (domains.Domain, error) {
	s.rec("EnableDomainDNSSEC", name)
	d, err := s.Hub.EnableDomainDNSSEC(ctx, a, name)
	return d, defaultStatus(err, http.StatusBadGateway)
}

func (s *Server) handleDomainDNS(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	p, err := s.domainDNS(r.Context(), r.PathValue("name"), refreshParam(r))
	noStore(w)
	if err != nil {
		writeDomainsErr(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) handleMainDNS(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	p, err := s.mainDNS(r.Context(), refreshParam(r))
	noStore(w)
	if err != nil {
		writeDomainsErr(w, err)
		return
	}
	writeJSON(w, p)
}

// decodeStrictBody decodes exactly one JSON value into v with known
// fields only (64 KiB); false = a bad body (the caller answers a fixed
// message, never the decoder's).
func decodeStrictBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && dec.Decode(&struct{}{}) == io.EOF
}

func (s *Server) handleDomainDNSApply(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Sets []string `json:"sets"`
	}
	if !decodeStrictBody(w, r, &b) || len(b.Sets) == 0 {
		http.Error(w, `body must be {"sets": ["address" | "caa" | "nomail", ...]}`, http.StatusBadRequest)
		return
	}
	d, err := s.applyDomainDNS(r.Context(), requestActor(r), r.PathValue("name"), b.Sets)
	noStore(w)
	if err != nil {
		writeDomainsErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(d)
}

func (s *Server) handleDomainDNSSEC(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Enable *bool `json:"enable"`
	}
	if !decodeStrictBody(w, r, &b) || b.Enable == nil || !*b.Enable {
		http.Error(w, `body must be {"enable": true} (signing is never turned off)`, http.StatusBadRequest)
		return
	}
	d, err := s.enableDomainDNSSEC(r.Context(), requestActor(r), r.PathValue("name"))
	noStore(w)
	if err != nil {
		writeDomainsErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(d)
}

// domainsView is GET /api/domains' answer as a value (list_domains): the
// service's list, or — disabled or unreachable — the reason and the last
// known list.
func (s *Server) domainsView(ctx context.Context) map[string]any {
	if err := s.Hub.DomainsAvailable(); err != nil {
		return map[string]any{"error": "domains disabled: " + err.Error(), "disabled": true, "domains": s.Hub.KnownDomains()}
	}
	list, err := s.Hub.RefreshDomains(ctx)
	if err != nil {
		return map[string]any{"error": err.Error(), "domains": s.Hub.KnownDomains()}
	}
	return map[string]any{"domains": list}
}
