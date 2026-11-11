package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
)

// The Sign-in page (contract §5.1 "Sign-in page", plan D24–D26): GET
// /signin and the caller's own routes under /api/me/signin, on the
// people listener only. The caller is X-Forwarded-User (lowercased)
// only; no route takes a username. These are the only routes under
// /api/me/signin/ (group-gate lets any switched-on method reach these
// paths, D24): any route added here that adds a method must need D26's
// proof.

// mySignInBodyMax: the Sign-in page's bodies (8 KiB, §5.1).
const mySignInBodyMax = 8 << 10

// presentedCertHeader is where the people router's client-cert-pem@file
// passes the certificate the browser presented (D25).
const presentedCertHeader = "X-Forwarded-Tls-Client-Cert"

// registerMySignIn registers the page and the D25 routes.
func (s *Server) registerMySignIn(mux routeMux) {
	mux.HandleFunc("GET /signin", s.handleMySignInPage)
	mux.HandleFunc("GET /api/me/signin", s.handleMySignIn)
	mux.HandleFunc("GET /api/me/signin/history", s.handleMySignInHistory)
	mux.HandleFunc("POST /api/me/signin/browser-certificates", s.handleCreateBrowserCert)
	mux.HandleFunc("DELETE /api/me/signin/certificates/{serial}", s.handleRevokeOwnCert)
	mux.HandleFunc("POST /api/me/signin/yubikey-certificate/renew", s.handleRenewYubiKeyCert)
	mux.HandleFunc("PUT /api/me/signin/password", s.handleSetOwnPassword)
	mux.HandleFunc("DELETE /api/me/signin/password", s.handleRemoveOwnPassword)
}

// mySignInUser is the caller, or a 401.
func mySignInUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return "", false
	}
	return user, true
}

// mySignInErr answers a refusal: a 4xx with the Hub's text (it never
// names anyone else), anything else 503 with the generic text, the
// cause only logged.
func mySignInErr(w http.ResponseWriter, what string, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 {
		http.Error(w, se.Error(), se.Status)
		return
	}
	log.Printf("people: sign-in page: %s: %v", what, err)
	http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
}

// readMySignInBody decodes a Sign-in page body into v (≤ 8 KiB: 413;
// unknown fields or trailing data: 400 with usage, never the body).
func readMySignInBody(w http.ResponseWriter, r *http.Request, v any, usage string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, mySignInBodyMax))
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

// handleMySignInPage serves the Sign-in page (web/mysignin.html).
func (s *Server) handleMySignInPage(w http.ResponseWriter, r *http.Request) {
	page, err := fs.ReadFile(s.Web, "mysignin.html")
	if err != nil {
		log.Printf("people: sign-in page: %v", err)
		http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(page)
}

// handleMySignIn → 200 hub.MySignIn, no-store.
func (s *Server) handleMySignIn(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	v, err := s.Hub.MySignInView(r.Context(), user)
	if err != nil {
		mySignInErr(w, "view of "+user, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

var limitRe = regexp.MustCompile(`^[0-9]{1,3}$`)

// handleMySignInHistory → 200 hub.HistoryPage: before is passed through
// unchanged (an opaque cursor; malformed 400), limit 1–100, default 50.
func (s *Server) handleMySignInHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
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
	page, err := s.Hub.SignInHistory(r.Context(), user, q.Get("before"), limit)
	if err != nil {
		mySignInErr(w, "history of "+user, err)
		return
	}
	noStore(w)
	writeJSON(w, page)
}

// browserCertBody is the create body.
type browserCertBody struct {
	Days         int    `json:"days"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

// zeroBytes zeroes answer buffers after the write (tests spy on it).
var zeroBytes = func(b []byte) { clear(b) }

// handleCreateBrowserCert creates the caller's browser certificate → 200
// {p12, password, filename, certificate} with Cache-Control: no-store and
// Pragma: no-cache. The .p12 and its password are in this answer only:
// written from bytes, the buffers and the certificate cleared after.
func (s *Server) handleCreateBrowserCert(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b browserCertBody
	if !readMySignInBody(w, r, &b, `{"days": <n>, "code": "...", "code_verifier": "...", "nonce": "..."}`) {
		return
	}
	bc, err := s.Hub.CreateBrowserCertificate(r.Context(), user, b.Days, freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce})
	if err != nil {
		mySignInErr(w, "browser certificate of "+user, err)
		return
	}
	defer bc.Clear()
	for _, c := range bc.Password {
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			// Never: the alphabet needs no escaping (fail closed).
			log.Printf("people: browser certificate of %s: the password has a byte JSON would escape", user)
			http.Error(w, directory.GenericUnavailable, http.StatusInternalServerError)
			return
		}
	}
	tail, err := json.Marshal(struct {
		Filename    string      `json:"filename"`
		Certificate hub.CertRow `json:"certificate"`
	}{bc.Filename, s.Hub.NewCertRow(invite.KindBrowser, bc.Serial, time.Now(), bc.NotAfter)})
	if err != nil {
		http.Error(w, directory.GenericUnavailable, http.StatusInternalServerError)
		return
	}
	n := base64.StdEncoding.EncodedLen(len(bc.P12))
	buf := make([]byte, 0, n+len(bc.Password)+len(tail)+32)
	buf = append(buf, `{"p12":"`...)
	enc := buf[len(buf) : len(buf)+n]
	base64.StdEncoding.Encode(enc, bc.P12)
	buf = buf[:len(buf)+n]
	buf = append(buf, `","password":"`...)
	buf = append(buf, bc.Password...)
	buf = append(buf, `",`...)
	buf = append(buf, tail[1:]...) // "filename":…,"certificate":…}
	buf = append(buf, '\n')
	noStoreHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
	zeroBytes(buf)
}

// handleRevokeOwnCert revokes the caller's own browser certificate →
// 204 (a YubiKey certificate or someone else's: 404).
func (s *Server) handleRevokeOwnCert(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	if err := s.Hub.RevokeOwnBrowserCertificateAs(r.Context(), selfActor(r, user), r.PathValue("serial")); err != nil {
		mySignInErr(w, "revoking a certificate of "+user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRenewYubiKeyCert renews the caller's YubiKey certificate with
// the one their browser presents → 200 {certificate, serial, not_after}.
func (s *Server) handleRenewYubiKeyCert(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b struct {
		CSR string `json:"csr"`
	}
	if !readMySignInBody(w, r, &b, `{"csr": "<PEM>"}`) {
		return
	}
	ic, err := s.Hub.RenewYubiKeyCertificate(r.Context(), user, r.Header.Get(presentedCertHeader), b.CSR)
	if err != nil {
		mySignInErr(w, "renewing the YubiKey certificate of "+user, err)
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"certificate": ic.PEM, "serial": ic.Serial, "not_after": ic.NotAfter.UTC()})
}

// handleSetOwnPassword sets the caller's own password → 204.
func (s *Server) handleSetOwnPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var b struct {
		Password     string `json:"password"`
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		Nonce        string `json:"nonce"`
	}
	if !readMySignInBody(w, r, &b, `{"password": "...", "code": "...", "code_verifier": "...", "nonce": "..."}`) {
		return
	}
	if err := s.Hub.SetOwnPassword(r.Context(), user, b.Password, freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce}); err != nil {
		mySignInErr(w, "setting the password of "+user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveOwnPassword removes the caller's own password → 204.
func (s *Server) handleRemoveOwnPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	if err := s.Hub.RemoveOwnPassword(r.Context(), user); err != nil {
		mySignInErr(w, "removing the password of "+user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
