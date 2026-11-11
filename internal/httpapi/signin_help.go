package httpapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// The person's Sign-in routes (contract §9.7 "Person's Sign-in routes",
// D32): part of the directory route set, on both listeners, behind the
// proxy secret and the CSRF guard. Who may act is the Hub's decision
// (an administrator, or a sign_in_help holder the directory lets target
// the person: CheckHelp on a fresh snapshot). The setup-link and
// passkey routes stay the existing directory routes (they accept
// holders through the directory's delegation).

// registerSignInHelp registers the four routes (registerDirectory).
func (s *Server) registerSignInHelp(mux routeMux) {
	mux.HandleFunc("GET /api/directory/users/{username}/signin", s.handlePersonSignIn)
	mux.HandleFunc("GET /api/directory/users/{username}/signin/history", s.handlePersonSignInHistory)
	mux.HandleFunc("DELETE /api/directory/users/{username}/certificates/{serial}", s.handleRevokePersonCert)
	mux.HandleFunc("POST /api/directory/users/{username}/certificates", s.handleIssueYubiKeyCert)
}

// handlePersonSignIn → 200 hub.PersonSignIn (fresh_auth: this
// listener's own fresh-auth client), no-store.
func (s *Server) handlePersonSignIn(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	u := r.PathValue("username")
	s.rec("PersonSignInView", u)
	v, err := s.Hub.PersonSignInView(r.Context(), c, u)
	if err != nil {
		mySignInErr(w, "sign-in view of "+u, err)
		return
	}
	v.FreshAuth = s.Hub.FreshAuthInfoFor(listenerOf(r))
	noStore(w)
	writeJSON(w, v)
}

// handlePersonSignInHistory → 200 hub.HistoryPage under the same rule;
// before is passed through unchanged (an opaque cursor), limit 1–100,
// default 50.
func (s *Server) handlePersonSignInHistory(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	q := r.URL.Query()
	limit := hub.HistoryDefaultLimit
	if v, set := q["limit"]; set {
		if len(v) != 1 || !limitRe.MatchString(v[0]) {
			http.Error(w, "limit must be 1 to 100", http.StatusBadRequest)
			return
		}
		limit, _ = strconv.Atoi(v[0])
	}
	if v := q["before"]; len(v) > 1 {
		http.Error(w, "before must be given once", http.StatusBadRequest)
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	u := r.PathValue("username")
	page, err := s.Hub.PersonSignInHistory(r.Context(), c, u, q.Get("before"), limit)
	if err != nil {
		mySignInErr(w, "sign-in history of "+u, err)
		return
	}
	noStore(w)
	writeJSON(w, page)
}

// handleRevokePersonCert → 204.
func (s *Server) handleRevokePersonCert(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	u := r.PathValue("username")
	if err := s.revokePersonCert(r.Context(), c, u, r.PathValue("serial")); err != nil {
		mySignInErr(w, "revoking a certificate of "+u, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleIssueYubiKeyCert → 200 {certificate, serial, not_after}
// (administrators only; the proof is this listener's).
func (s *Server) handleIssueYubiKeyCert(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	var b struct {
		CSR          string `json:"csr"`
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		Nonce        string `json:"nonce"`
	}
	if !readMySignInBody(w, r, &b, `{"csr": "<PEM>", "code": "...", "code_verifier": "...", "nonce": "..."}`) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	u := r.PathValue("username")
	ic, err := s.Hub.IssueYubiKeyCertificateOn(r.Context(), listenerOf(r), c, u, b.CSR, freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce})
	if err != nil {
		mySignInErr(w, "issuing a YubiKey certificate for "+u, err)
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"certificate": ic.PEM, "serial": ic.Serial, "not_after": ic.NotAfter.UTC()})
}

// revokePersonCert is the revocation the route and its tools share.
func (s *Server) revokePersonCert(ctx context.Context, c *directory.Caller, user, serial string) error {
	s.rec("RevokePersonCertificate", user, serial)
	return s.Hub.RevokePersonCertificate(ctx, c, user, serial)
}
