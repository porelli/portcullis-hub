package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// Verified emails (contract §9.8). The admin route (both listeners, like
// every /api/directory route) and the signed-in person's two code routes
// (people listener only; X-Forwarded-User, lowercased, acts only on its
// own email; CSRF and RefuseWhileImpersonated from the listener's chain).
// The code is never echoed, logged or audited.

// registerMyEmail registers the two self-service code routes.
func (s *Server) registerMyEmail(mux routeMux) {
	mux.HandleFunc("POST /api/me/email/verify", s.handleStartEmailVerify)
	mux.HandleFunc("POST /api/me/email/verify/confirm", s.handleConfirmEmailVerify)
}

// handleMarkEmailVerified: POST /api/directory/users/{username}/email/verified
// → 204 (edit_details; 400 "this person has no email"; audited
// user.email_verified).
func (s *Server) handleMarkEmailVerified(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.Directory.MarkEmailVerified(r.Context(), c, r.PathValue("username")); err != nil {
		dirErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// emailVerifyErr answers a refusal: a 4xx with the Hub's text, anything
// else 503 with the generic text (the cause logged; it never holds the
// code).
func emailVerifyErr(w http.ResponseWriter, what string, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 {
		http.Error(w, se.Error(), se.Status)
		return
	}
	if errors.As(err, &se) && se.Status == http.StatusServiceUnavailable {
		http.Error(w, se.Error(), se.Status)
		return
	}
	log.Printf("people: email verification: %s: %v", what, err)
	http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
}

// handleStartEmailVerify: POST /api/me/email/verify → 202 {"expires_at"};
// 409 mail off, 429 too many codes.
func (s *Server) handleStartEmailVerify(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	exp, err := s.Hub.StartEmailVerification(r.Context(), user)
	if err != nil {
		emailVerifyErr(w, "sending "+user+" a code", err)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"expires_at": exp.UTC()})
}

// handleConfirmEmailVerify: POST /api/me/email/verify/confirm {"code"} →
// 200 {"verified": true}; 400 {"attempts_left"}; 410 expired, used up or
// the email changed.
func (s *Server) handleConfirmEmailVerify(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b struct {
		Code string `json:"code"`
	}
	if !readMySignInBody(w, r, &b, `{"code": "<8 digits>"}`) {
		return
	}
	left, err := s.Hub.ConfirmEmailVerification(r.Context(), user, b.Code)
	switch {
	case errors.Is(err, hub.ErrWrongCode):
		noStore(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]int{"attempts_left": left})
	case err != nil:
		emailVerifyErr(w, "confirming "+user+"'s code", err)
	default:
		noStore(w)
		writeJSON(w, map[string]bool{"verified": true})
	}
}
