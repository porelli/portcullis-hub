package httpapi

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// Mail passwords on the Sign-in page (contract §5.1 "Mail passwords",
// §19.9): people listener only, caller only (X-Forwarded-User), bodies ≤
// 8 KiB, CSRF and RefuseWhileImpersonated from the listener's chain. No
// route creates a mail password for anyone else, and none is an MCP tool.

// registerMyMail registers the three mail-password routes.
func (s *Server) registerMyMail(mux routeMux) {
	mux.HandleFunc("GET /api/me/mail", s.handleMyMail)
	mux.HandleFunc("POST /api/me/mail/passwords", s.handleCreateMailPassword)
	mux.HandleFunc("DELETE /api/me/mail/passwords/{id}", s.handleRevokeOwnMailPassword)
}

// mailErr answers a refusal: a 4xx with the Hub's text, mail's own 503s
// with their fixed text, anything else 503 generic (the cause logged).
func mailErr(w http.ResponseWriter, what string, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) && (se.Status >= 400 && se.Status < 500 || se.Status == http.StatusServiceUnavailable && hub.IsMailUnavailable(err)) {
		http.Error(w, se.Error(), se.Status)
		return
	}
	log.Printf("people: mail: %s: %v", what, err)
	http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
}

func (s *Server) handleMyMail(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	v, err := s.Hub.MyMail(r.Context(), user)
	if err != nil {
		mailErr(w, "the mail section of "+user, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

func (s *Server) handleCreateMailPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b struct {
		Label        string `json:"label"`
		Expiry       string `json:"expiry"`
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		Nonce        string `json:"nonce"`
	}
	if !readMySignInBody(w, r, &b, `{"label": "...", "expiry": "none|90d|1y", "code": "...", "code_verifier": "...", "nonce": "..."}`) {
		return
	}
	cc, err := s.Hub.CreateMailPassword(r.Context(), user, b.Label, b.Expiry, freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce})
	if err != nil {
		mailErr(w, "creating a mail password for "+user, err)
		return
	}
	defer cc.Zero()
	// The answer is built from bytes (never a string copy of the
	// password, which couldn't be zeroed) and zeroed after the write.
	prof := make([]byte, base64.StdEncoding.EncodedLen(len(cc.MobileConfig)))
	base64.StdEncoding.Encode(prof, cc.MobileConfig)
	// Sized for the worst escape (\u00XX: 6 bytes per byte) so appends
	// never reallocate; net/http's bufio copy is an accepted residual.
	buf := make([]byte, 0, len(cc.Password)*6+len(cc.ID)*6+len(prof)+96)
	buf = append(buf, `{"id":`...)
	buf = appendJSONString(buf, []byte(cc.ID))
	buf = append(buf, `,"password":`...)
	buf = appendJSONString(buf, cc.Password)
	buf = append(buf, `,"mobileconfig_b64":"`...)
	buf = append(buf, prof...)
	buf = append(buf, "\"}\n"...)
	noStoreHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(buf)
	zeroPassword(buf)
	zeroPassword(prof)
}

func (s *Server) handleRevokeOwnMailPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	if err := s.Hub.RevokeOwnMailPassword(r.Context(), user, r.PathValue("id")); err != nil {
		mailErr(w, "revoking a mail password of "+user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// appendJSONString appends b as a JSON string, escaping in place (no
// intermediate string).
func appendJSONString(dst, b []byte) []byte {
	const hexd = "0123456789abcdef"
	dst = append(dst, '"')
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c < 0x20 || c == 0x7f:
			dst = append(dst, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&0xf])
		case c == '<' || c == '>' || c == '&':
			dst = append(dst, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}
