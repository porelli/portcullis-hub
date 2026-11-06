package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// Credential routes (contract §5.1, §13.16; Task 12 plan 3): the caller
// creates, regenerates and revokes their own file-sharing password on the
// people listener; admins list and revoke on the Hub listener.

// credentialBodyMax: body limit for credential requests (8 KiB, §5.1).
const credentialBodyMax = 8 << 10

// zeroPassword is the function that zeros password buffers after writing the
// response. Tests replace it with a spy to verify it was called.
var zeroPassword = credentials.Zero

// credentialBody is the create/regenerate body: code, code_verifier, nonce.
type credentialBody struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

// readCredentialBody decodes a credential request body (≤ 8 KiB: 413 beyond;
// unknown fields and trailing data 400, with a fixed usage message).
func readCredentialBody(w http.ResponseWriter, r *http.Request) (credentialBody, bool) {
	var b credentialBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, credentialBodyMax))
	dec.DisallowUnknownFields()
	err := dec.Decode(&b)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return b, false
		}
		http.Error(w, `body must be {"code": "...", "code_verifier": "...", "nonce": "..."}`, http.StatusBadRequest)
		return b, false
	}
	return b, true
}

// credentialErr answers a credential request's refusal: 4xx with the Hub's
// text (it never names another person); 5xx the generic message, the cause
// only logged.
func credentialErr(w http.ResponseWriter, who string, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) && se.Status < 500 {
		http.Error(w, se.Error(), se.Status)
		return
	}
	log.Printf("people: credential of %s: %v", who, err)
	http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
}

// noStoreHeaders sets both Cache-Control: no-store and Pragma: no-cache for
// credential responses that contain the password (§5.1: the password goes in
// the answer only). The noStore function (directory.go) sets only
// Cache-Control for other no-cache responses (My apps, admin views) that
// contain no secrets.
func noStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// handleCreateCredential creates or regenerates the caller's (X-Forwarded-User,
// lowercased) own credential → 200 {password, credential}. The password is
// zeroed after the response is written. No caller 401; 404, 409, 403 as in
// Task 8; 413 > 8 KiB.
func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	b, ok := readCredentialBody(w, r)
	if !ok {
		return
	}

	proof := freshauth.Proof{
		Code:         b.Code,
		CodeVerifier: b.CodeVerifier,
		Nonce:        b.Nonce,
	}

	cc, err := s.Hub.CreateCredential(r.Context(), r.PathValue("instance"), r.PathValue("key"), user, proof)
	if err != nil {
		credentialErr(w, user, err)
		return
	}

	// Zero the password after writing the response
	defer zeroPassword(cc.Password)
	for _, c := range cc.Password {
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			// Never: the alphabet needs no escaping (fail closed).
			log.Printf("people: credential of %s: the password has a byte JSON would escape", user)
			http.Error(w, directory.GenericUnavailable, http.StatusInternalServerError)
			return
		}
	}

	noStoreHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// C-M1: the answer is built from bytes — never a string copy of the
	// password (a string can't be zeroed) — and its buffer zeroed after
	// the write. The alphabet and dashes need no JSON escaping; the
	// credential view (always active on creation) is metadata only.
	since, err := json.Marshal(cc.Credential.CreatedAt)
	if err != nil {
		since = []byte(`null`)
	}
	buf := make([]byte, 0, len(cc.Password)+len(since)+64)
	buf = append(buf, `{"password":"`...)
	buf = append(buf, cc.Password...)
	buf = append(buf, `","credential":{"status":"active","since":`...)
	buf = append(buf, since...)
	buf = append(buf, "}}\n"...)
	w.Write(buf)
	zeroPassword(buf)
}

// handleRevokeOwnCredential revokes the caller's own credential → 204 (also
// when nothing was set). No caller 401.
func (s *Server) handleRevokeOwnCredential(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}

	if err := s.Hub.RevokeOwnCredential(r.Context(), r.PathValue("instance"), r.PathValue("key"), user); err != nil {
		credentialErr(w, user, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleAdminCredentials lists an instance's person_secret options with their
// metadata (admin view; Hub listener, adminOnly). No password or hash field
// anywhere in the JSON. → 200 []CredentialsView.
func (s *Server) handleAdminCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}

	id, ok := instanceID(w, r)
	if !ok {
		return
	}

	views, err := s.Hub.Credentials(r.Context(), id)
	if err != nil {
		var se *hub.StatusError
		if errors.As(err, &se) {
			http.Error(w, se.Error(), se.Status)
			return
		}
		log.Printf("admin: credentials of %s: %v", id, err)
		http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
		return
	}

	noStore(w)
	writeJSON(w, views)
}

// handleAdminRevokeCredential revokes a person's credential (admin; Hub
// listener, adminOnly). Audited with actor. → 204.
func (s *Server) handleAdminRevokeCredential(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}

	id, ok := instanceID(w, r)
	if !ok {
		return
	}

	key := r.PathValue("key")
	user := strings.ToLower(r.PathValue("user"))
	if user == "" {
		http.Error(w, "user is required", http.StatusBadRequest)
		return
	}

	if err := s.Hub.AdminRevokeCredential(r.Context(), id, key, user, requestActor(r)); err != nil {
		var se *hub.StatusError
		if errors.As(err, &se) {
			http.Error(w, se.Error(), se.Status)
			return
		}
		log.Printf("admin: revoke credential %s/%s/%s: %v", id, key, user, err)
		http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
