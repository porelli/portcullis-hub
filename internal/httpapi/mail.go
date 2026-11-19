package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// Settings → Mail and the admin mail routes (contract §19.9): Hub
// listener, administrators only, strict JSON bodies ≤ 64 KiB. The
// person's mail routes are directory routes (both listeners): an
// administrator, or a sign_in_help holder who may target the person (GET
// with aliases [] and DELETE of a password; never PUT).

const mailBodyMax = 64 << 10

// registerMailAdmin registers the Hub listener's mail routes.
func (s *Server) registerMailAdmin(mux routeMux) {
	mux.HandleFunc("GET /api/mail/settings", s.handleMailSettings)
	mux.HandleFunc("PUT /api/mail/settings", s.handleSetMailSettings)
	mux.HandleFunc("GET /api/mail/status", s.handleMailStatus)
	mux.HandleFunc("GET /api/mail/checks", s.handleMailChecks)
	mux.HandleFunc("PUT /api/mail/domains/{name}", s.handleSetMailDomain)
	mux.HandleFunc("PUT /api/directory/groups/{group}/mail-list", s.handleSetGroupList)
	mux.HandleFunc("POST /api/mail/actions/{action}", s.handleMailAction)
	mux.HandleFunc("POST /api/mail/confirm-removal", s.handleConfirmMailRemoval)
}

// handleConfirmMailRemoval confirms the pending mass removal: the body
// lists exactly its accounts' uuids (409 when it changed) → 204.
func (s *Server) handleConfirmMailRemoval(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Accounts     []string `json:"accounts"`
		Confirm      string   `json:"confirm"`
		Code         string   `json:"code"`
		CodeVerifier string   `json:"code_verifier"`
		Nonce        string   `json:"nonce"`
	}
	if !readMailBody(w, r, &b, `{"accounts": ["<uuid>", …], "confirm": "<the pending removal's confirm_phrase>", "code", "code_verifier", "nonce"}`) {
		return
	}
	in := hub.ConfirmRemovalInput{Accounts: b.Accounts, Confirm: b.Confirm, Listener: listenerOf(r)}
	if b.Code != "" || b.CodeVerifier != "" || b.Nonce != "" {
		in.Proof = &freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce}
	}
	if err := s.Hub.ConfirmMailRemoval(r.Context(), in, requestActor(r)); err != nil {
		mailErr(w, "confirming a mail removal", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// registerPersonMail registers the person's mail routes (registerDirectory:
// both listeners).
func (s *Server) registerPersonMail(mux routeMux) {
	mux.HandleFunc("GET /api/directory/users/{username}/mail", s.handlePersonMail)
	mux.HandleFunc("PUT /api/directory/users/{username}/mail", s.handleSetPersonMail)
	mux.HandleFunc("DELETE /api/directory/users/{username}/mail/passwords/{id}", s.handleRevokePersonMailPassword)
}

// readMailBody decodes a strict body (unknown fields, trailing data:
// 400; over 64 KiB: 413).
func readMailBody(w http.ResponseWriter, r *http.Request, v any, usage string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, mailBodyMax))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "body must be "+usage, http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) handleMailSettings(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	// The Hub listener's fresh sign-in parameters (the relay, DKIM
	// rotation and former retention forms).
	writeJSON(w, struct {
		hub.MailSettingsView
		FreshAuth *freshauth.AuthorizeInfo `json:"fresh_auth"`
	}{s.Hub.MailSettingsView(), s.Hub.AdminFreshAuthInfo()})
}

func (s *Server) handleSetMailSettings(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		hub.MailSettingsInput
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		Nonce        string `json:"nonce"`
	}
	if !readMailBody(w, r, &b, `{"primary_domain", "spam", "limits", "quotas", "relay"?, "dkim_rotate"?, "former_retention"?, "code"?, "code_verifier"?, "nonce"?}`) {
		return
	}
	in := b.MailSettingsInput
	in.Listener = listenerOf(r)
	if b.Code != "" || b.CodeVerifier != "" || b.Nonce != "" {
		in.Proof = &freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce}
	}
	if err := s.Hub.SetMailSettings(r.Context(), in, requestActor(r)); err != nil {
		mailErr(w, "saving the mail settings", err)
		return
	}
	writeJSON(w, s.Hub.MailSettingsView())
}

func (s *Server) handleMailStatus(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.MailStatus(r.Context()))
}

func (s *Server) handleMailChecks(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	c, err := s.Hub.MailChecks(r.Context(), r.URL.Query().Get("refresh") == "1")
	if err != nil {
		mailErr(w, "the mail checks", err)
		return
	}
	noStore(w)
	writeJSON(w, c)
}

func (s *Server) handleSetMailDomain(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Enabled bool     `json:"enabled"`
		Groups  []string `json:"groups"`
	}
	if !readMailBody(w, r, &b, `{"enabled": true|false, "groups": ["…"]}`) {
		return
	}
	if err := s.Hub.SetMailDomain(r.Context(), r.PathValue("name"), b.Enabled, b.Groups, requestActor(r)); err != nil {
		mailErr(w, "mail for a domain", err)
		return
	}
	writeJSON(w, s.Hub.MailSettingsView())
}

func (s *Server) handleSetGroupList(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Enabled bool   `json:"enabled"`
		Domain  string `json:"domain"`
		Posting string `json:"posting"`
	}
	if !readMailBody(w, r, &b, `{"enabled": true|false, "domain", "posting": "members"|"anyone"}`) {
		return
	}
	if err := s.Hub.SetGroupList(r.Context(), r.PathValue("group"), b.Enabled, b.Domain, b.Posting, requestActor(r)); err != nil {
		mailErr(w, "a group's list", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMailAction(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Domain string `json:"domain"`
	}
	if !readMailBody(w, r, &b, `{"domain": "…"}`) {
		return
	}
	if err := s.Hub.MailAction(r.Context(), r.PathValue("action"), b.Domain, requestActor(r)); err != nil {
		mailErr(w, "a mail action", err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handlePersonMail(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	v, err := s.Hub.PersonMail(r.Context(), c, r.PathValue("username"))
	if err != nil {
		mailErr(w, "a person's mail", err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

// handleSetPersonMail sets a person's aliases: administrators only (a
// sign_in_help holder never edits addresses).
func (s *Server) handleSetPersonMail(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Aliases []string `json:"aliases"`
	}
	if !readMailBody(w, r, &b, `{"aliases": ["…"]}`) {
		return
	}
	if err := s.Hub.SetUserAliases(r.Context(), r.PathValue("username"), b.Aliases, requestActor(r)); err != nil {
		mailErr(w, "a person's aliases", err)
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	v, err := s.Hub.PersonMail(r.Context(), c, r.PathValue("username"))
	if err != nil {
		mailErr(w, "a person's mail", err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) handleRevokePersonMailPassword(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.Hub.PersonRevokeMailPassword(r.Context(), c, r.PathValue("username"), r.PathValue("id")); err != nil {
		mailErr(w, "revoking a person's mail password", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
