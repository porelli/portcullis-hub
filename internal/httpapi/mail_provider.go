package httpapi

import (
	"errors"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// The mail provider routes (contract §19.9): Hub listener, proxy-secret
// and CSRF guards, strict bodies ≤ 64 KiB, full administrators only, and
// never from MCP or AI (no tool, ever: mailNoToolRoutes).

// registerMailProvider registers them (registerMailAdmin's listener).
func (s *Server) registerMailProvider(mux routeMux) {
	mux.HandleFunc("GET /api/instances/{id}/mail-provider", s.handleInstanceMailProvider)
	mux.HandleFunc("PUT /api/instances/{id}/mail-provider", s.handleSetInstanceMailProvider)
	mux.HandleFunc("POST /api/mail/provider/switch", s.handleSwitchMailProvider)
	mux.HandleFunc("POST /api/mail/provider/retry-void", s.handleRetryMailVoid)
	mux.HandleFunc("POST /api/mail/admin-view", s.handleMailAdminView)
}

// handleMailAdminView: POST /api/mail/admin-view {} → 200 {url}, the
// wired provider's read-only admin view (contract §19.13). Full
// administrators in the browser only: an AI or MCP caller and a delegate
// are refused first (403). Audited mail.admin_view_opened.
func (s *Server) handleMailAdminView(w http.ResponseWriter, r *http.Request) {
	a := requestActor(r)
	if a.Via != "" {
		http.Error(w, "not allowed: the mail admin view opens only in the browser, never through MCP or AI", http.StatusForbidden)
		return
	}
	if !s.adminOnly(w, r) {
		return
	}
	var b struct{}
	if !readMailBody(w, r, &b, `{}`) {
		return
	}
	u, err := s.Hub.MailAdminViewURL(a)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, map[string]string{"url": u})
}

// handleSwitchMailProvider: POST /api/mail/provider/switch {to, confirm,
// confirm_empty, code, code_verifier, nonce} → 202 {op of to…, warning}.
func (s *Server) handleSwitchMailProvider(w http.ResponseWriter, r *http.Request) {
	if !s.mailProviderGate(w, r) {
		return
	}
	var b struct {
		To           string `json:"to"`
		Confirm      string `json:"confirm"`
		ConfirmEmpty string `json:"confirm_empty"`
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		Nonce        string `json:"nonce"`
	}
	if !readMailBody(w, r, &b, `{"to": "<instance>", "confirm": "<instance>", "confirm_empty": "<n> mailboxes start empty", "code": "…", "code_verifier": "…", "nonce": "…"}`) {
		return
	}
	in := hub.SwitchRequest{Confirm: b.Confirm, ConfirmEmpty: b.ConfirmEmpty, Listener: listenerOf(r)}
	if b.Code != "" || b.CodeVerifier != "" || b.Nonce != "" {
		in.Proof = &freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce}
	}
	op, err := s.Hub.StartSwitchMail(r.Context(), b.To, in, requestActor(r))
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, mailWireAccepted{acceptedBody(op), hub.MailWarning})
}

// errMailAdminOnly: a non-admin's mail-provider write.
var errMailAdminOnly = errors.New("not allowed: admins only")

// mailProviderGate: an AI or MCP actor is refused first (403), then a
// non-admin (adminOnly).
func (s *Server) mailProviderGate(w http.ResponseWriter, r *http.Request) bool {
	a := requestActor(r)
	if a.Via != "" {
		http.Error(w, "not allowed: mail providers are never wired, switched or unwired through MCP or AI", http.StatusForbidden)
		return false
	}
	if !s.adminOnly(w, r) {
		// Audited (final review L8), the write routes only.
		if r.Method != http.MethodGet && a.User != "" {
			s.auditOpAs(a, r.PathValue("id"), directory.AuditEntry{Action: "mail.provider", Target: r.URL.Path, Detail: r.Method}, &hub.StatusError{Status: http.StatusForbidden, Err: errMailAdminOnly}, http.StatusForbidden)
		}
		return false
	}
	return true
}

// handleInstanceMailProvider: GET /api/instances/{id}/mail-provider → the
// instance's Mail tab (404 without a mail: block).
func (s *Server) handleInstanceMailProvider(w http.ResponseWriter, r *http.Request) {
	if !s.mailProviderGate(w, r) {
		return
	}
	v, err := s.Hub.InstanceMailProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	// The Hub listener's fresh sign-in parameters for the wiring's proof.
	writeJSON(w, struct {
		*hub.MailProviderView
		FreshAuth *freshauth.AuthorizeInfo `json:"fresh_auth"`
	}{v, s.Hub.AdminFreshAuthInfo()})
}

// handleRetryMailVoid: POST /api/mail/provider/retry-void → 202 the
// owed void retried now (409: none owed).
func (s *Server) handleRetryMailVoid(w http.ResponseWriter, r *http.Request) {
	if !s.mailProviderGate(w, r) {
		return
	}
	op, err := s.Hub.RetryMailVoid(requestActor(r))
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, acceptedBody(op))
}

// mailProviderBody is the PUT's body.
type mailProviderBody struct {
	Wired        *bool  `json:"wired"`
	Confirm      string `json:"confirm"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
	Drain        *bool  `json:"drain"`
	BlockHash    string `json:"block_hash"`
}

// mailWireAccepted is the PUT and switch answers: the op and the warning.
type mailWireAccepted struct {
	OpStarted
	Warning string `json:"warning"`
}

// handleSetInstanceMailProvider: PUT /api/instances/{id}/mail-provider
// {wired: true, confirm, code, code_verifier, nonce} wires (or
// re-confirms) → 202 {op…, warning}.
func (s *Server) handleSetInstanceMailProvider(w http.ResponseWriter, r *http.Request) {
	if !s.mailProviderGate(w, r) {
		return
	}
	var b mailProviderBody
	if !readMailBody(w, r, &b, `{"wired": true, "confirm": "<instance id>", "code": "…", "code_verifier": "…", "nonce": "…"} or {"wired": false, "drain": true}`) {
		return
	}
	if b.Wired == nil {
		http.Error(w, "wired is required", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	if !*b.Wired {
		drain := b.Drain == nil || *b.Drain
		op, err := s.Hub.StartUnwireMail(id, drain, requestActor(r))
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSONStatus(w, http.StatusAccepted, mailWireAccepted{acceptedBody(op), hub.MailWarning})
		return
	}
	in := hub.WireRequest{Confirm: b.Confirm, Listener: listenerOf(r), BlockHash: b.BlockHash}
	if b.Code != "" || b.CodeVerifier != "" || b.Nonce != "" {
		in.Proof = &freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce}
	}
	op, err := s.Hub.StartWireMail(r.Context(), id, in, requestActor(r))
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, mailWireAccepted{acceptedBody(op), hub.MailWarning})
}
