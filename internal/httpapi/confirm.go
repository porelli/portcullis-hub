package httpapi

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// Confirmations (contract §15.6, §5.1, §15.7; plan 4 Task 14). Both
// browser listeners serve the page and the decision; each answers only
// for confirmations created for it (404 otherwise, like another person's
// or an unknown id). The internal API (MCP listener) creates and
// consumes companion confirmations for the gate.

// registerConfirm adds the page and the decision route (Hub and people
// listeners; the listener is the request's, isPeople).
func (s *Server) registerConfirm(mux routeMux) {
	mux.HandleFunc("GET /confirm/{id}", s.handleConfirmPage)
	mux.HandleFunc("POST /api/me/confirmations/{id}", s.handleConfirmDecision)
}

// listenerOf is the listener r came in on.
func listenerOf(r *http.Request) string {
	if isPeople(r) {
		return hub.ListenerPeople
	}
	return hub.ListenerHub
}

// confirmCSP: the page loads only its own scripts (/static/), its inline
// <style>, and fetches only its own origin; it can never be framed
// (clickjacking an approval) and has no form or base to redirect.
const confirmCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// confirmPageData is confirm.html's data (html/template escapes all of
// it; confirm.js reads the data-* attributes with dataset and writes
// only textContent).
type confirmPageData struct {
	*hub.ConfirmationView
	Pending   bool
	CreatedAt string
	ExpiresAt string
	FA        freshauth.AuthorizeInfo
}

// handleConfirmPage: GET /confirm/{id} → the page for the caller's own
// confirmation of this listener (anything else 404); no caller 401.
func (s *Server) handleConfirmPage(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	v, err := s.Hub.ConfirmationPage(listenerOf(r), r.PathValue("id"), user)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := confirmPageData{ConfirmationView: v, Pending: v.State == "pending",
		CreatedAt: v.Created.UTC().Format(time.RFC3339), ExpiresAt: v.Expires.UTC().Format(time.RFC3339)}
	if v.FreshAuth != nil {
		d.FA = *v.FreshAuth
	}
	t, err := s.confirmTemplate()
	if err != nil {
		log.Printf("confirm page: %v", err)
		http.Error(w, directory.GenericUnavailable, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", confirmCSP)
	if err := t.Execute(w, d); err != nil {
		log.Printf("render confirm page: %v", err)
	}
}

// confirmTemplate parses confirm.html once.
func (s *Server) confirmTemplate() (*template.Template, error) {
	s.confirmOnce.Do(func() {
		s.confirmPage, s.confirmErr = template.ParseFS(s.Web, "confirm.html")
	})
	return s.confirmPage, s.confirmErr
}

// decisionBody is POST /api/me/confirmations/{id}'s body (§5.1).
type decisionBody struct {
	Decision     string `json:"decision"`
	Typed        string `json:"typed"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

const decisionUsage = `body must be {"decision": "approve"|"decline", "typed": "...", "code": "...", "code_verifier": "...", "nonce": "..."}`

// handleConfirmDecision: POST /api/me/confirmations/{id} → 200 {"state"}
// | 404 | 409 {"state"} (not pending) | 409 "type <check> to confirm" |
// 403 freshauth.Message | 429 | 503; no caller 401; > 8 KiB 413; unknown
// fields, trailing data or another decision 400.
func (s *Server) handleConfirmDecision(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	var b decisionBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, credentialBodyMax))
	dec.DisallowUnknownFields()
	err := dec.Decode(&b)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	if err == nil && b.Decision != "approve" && b.Decision != "decline" {
		err = errors.New("decision")
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, decisionUsage, http.StatusBadRequest)
		return
	}
	noStoreHeaders(w)
	state, err := s.Hub.DecideConfirmation(r.Context(), listenerOf(r), r.PathValue("id"), user, hub.Decision{
		Approve: b.Decision == "approve", Typed: b.Typed,
		Proof: freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce},
	})
	if err != nil {
		var st *hub.ConfirmationStateError
		if errors.As(err, &st) {
			writeJSONStatus(w, http.StatusConflict, map[string]string{"state": st.State})
			return
		}
		credentialErr(w, user, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]string{"state": state})
}

// handleInternalConfirmCreate: POST /internal/confirmations {"user",
// "client", "resource", "tool", "args_sha256", "args_preview", "reason"}
// → 201 {"id", "url", "expires_at"} | 403 | 404 | 400 | 429 {"code":
// "too_many"}; anything else (503 directory down) a fixed body.
func (s *Server) handleInternalConfirmCreate(w http.ResponseWriter, r *http.Request) {
	var q struct {
		User        *string `json:"user"`
		Client      *string `json:"client"`
		Resource    *string `json:"resource"`
		Tool        *string `json:"tool"`
		ArgsSHA256  *string `json:"args_sha256"`
		ArgsPreview *string `json:"args_preview"`
		Reason      *string `json:"reason"`
	}
	if !decodeInternal(w, r, &q, "user", "client", "resource", "tool", "args_sha256", "args_preview", "reason") {
		return
	}
	if q.User == nil || q.Client == nil || q.Resource == nil || q.Tool == nil || q.ArgsSHA256 == nil || q.ArgsPreview == nil || q.Reason == nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "every field is required"})
		return
	}
	c, err := s.Hub.CreateCompanionConfirmation(r.Context(), hub.CompanionConfirmRequest{
		User: *q.User, Client: *q.Client, Resource: *q.Resource, Tool: *q.Tool,
		ArgsSHA256: *q.ArgsSHA256, ArgsPreview: *q.ArgsPreview, Reason: *q.Reason,
	})
	if err != nil {
		switch code := errStatus(err, http.StatusInternalServerError); code {
		case http.StatusTooManyRequests:
			writeJSONStatus(w, code, map[string]string{"code": "too_many"})
		case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound:
			writeJSONStatus(w, code, map[string]string{"error": http.StatusText(code)})
		default:
			log.Printf("internal api: confirmation for %q: %d: %s", clipMessage(*q.User, 64), code, clipMessage(err.Error(), 500))
			writeJSONStatus(w, code, map[string]string{"error": http.StatusText(code)})
		}
		return
	}
	writeJSONStatus(w, http.StatusCreated, map[string]string{"id": c.ID, "url": s.Hub.ConfirmationURL(c), "expires_at": c.Expires.UTC().Format(time.RFC3339)})
}

// handleInternalConfirmConsume: POST /internal/confirmations/consume
// {"user", "resource", "tool", "args_sha256"} → 200 {"id"} | 404 | 409
// {"state": "pending"|"declined"}.
func (s *Server) handleInternalConfirmConsume(w http.ResponseWriter, r *http.Request) {
	var q struct {
		User       *string `json:"user"`
		Resource   *string `json:"resource"`
		Tool       *string `json:"tool"`
		ArgsSHA256 *string `json:"args_sha256"`
	}
	if !decodeInternal(w, r, &q, "user", "resource", "tool", "args_sha256") {
		return
	}
	if q.User == nil || q.Resource == nil || q.Tool == nil || q.ArgsSHA256 == nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "every field is required"})
		return
	}
	id, state, err := s.Hub.ConsumeCompanionConfirmation(r.Context(), *q.User, *q.Resource, *q.Tool, *q.ArgsSHA256)
	if err != nil {
		code := errStatus(err, http.StatusInternalServerError)
		if code < 500 {
			code = http.StatusServiceUnavailable
		}
		log.Printf("internal api: consume for %q: %d: %s", clipMessage(*q.User, 64), code, clipMessage(err.Error(), 500))
		writeJSONStatus(w, code, map[string]string{"error": http.StatusText(code)})
		return
	}
	switch state {
	case hub.ConsumeConsumed:
		writeJSONStatus(w, http.StatusOK, map[string]string{"id": id})
	case hub.ConsumePending, hub.ConsumeDeclined:
		writeJSONStatus(w, http.StatusConflict, map[string]string{"state": state})
	default:
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
	}
}
