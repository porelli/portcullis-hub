package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/portcullis/hub/internal/hub"
)

// Enrolled domains (contract §11.7, §12.3): Hub listener only, admins only
// (lldap_admin; delegates 403), proxy-secret + CSRF like every route,
// audited in the Hub (domain.enroll|token|delete). Credentials are
// write-only: they are read from the body, forwarded once and never
// echoed — not in answers, not in errors (a malformed body gets a fixed
// message, never the decoder's).

func (s *Server) registerDomains(mux routeMux) {
	mux.HandleFunc("GET /api/domains", s.handleDomains)
	mux.HandleFunc("POST /api/domains", s.handleEnrollDomain)
	mux.HandleFunc("POST /api/domains/{name}/token", s.handleDomainToken)
	mux.HandleFunc("DELETE /api/domains/{name}", s.handleDeleteDomain)
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
	d, err := s.Hub.EnrollDomain(r.Context(), actor(r), b.Name, b.Provider, b.Credentials)
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
	d, err := s.Hub.ReplaceDomainToken(r.Context(), actor(r), r.PathValue("name"), b.Provider, b.Credentials)
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
	warning, err := s.Hub.DeleteDomain(r.Context(), actor(r), r.PathValue("name"))
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
