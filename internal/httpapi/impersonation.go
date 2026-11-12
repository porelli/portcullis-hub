package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
)

// Signing in as someone else (contract §5.1 "Signing in as someone
// else", §8.1 "Impersonation", §9.7, D36–D38, D41–D43, D46):
//   - the administrators' routes on a person (directory routes, both
//     listeners): the start and Stop;
//   - the Hub listener's list and switch;
//   - the impersonating browser's routes (people listener only): the
//     banner's read, its Stop and the Stop page.
//
// X-Forwarded-Impersonation is trusted only as group-gate's (it sets it
// from the validated file record; Traefik deletes client copies): the
// people listener answers GET /api/me/impersonation and the own Stop
// from it, and both listeners' read-only rule (RefuseWhileImpersonated)
// only gets stricter for a client-sent copy.

// registerImpersonation registers the administrators' routes on a person
// (registerDirectory: both listeners).
func (s *Server) registerImpersonation(mux routeMux) {
	mux.HandleFunc("POST /api/directory/users/{username}/impersonation", s.handleStartImpersonation)
	mux.HandleFunc("POST /api/directory/users/{username}/impersonation/stop", s.handleStopImpersonation)
}

// registerImpersonationAdmin registers the Hub listener's list and switch.
func (s *Server) registerImpersonationAdmin(mux routeMux) {
	mux.HandleFunc("GET /api/impersonations", s.handleImpersonations)
	mux.HandleFunc("PUT /api/signin/impersonation", s.handleSetImpersonation)
}

// registerMyImpersonation registers the impersonating browser's routes
// (registerPeopleApps: people listener only).
func (s *Server) registerMyImpersonation(mux routeMux) {
	mux.HandleFunc("GET /api/me/impersonation", s.handleMyImpersonation)
	mux.HandleFunc("POST "+stopOwnImpersonationPath, s.handleStopOwnImpersonation)
	mux.HandleFunc("GET /impersonation/stop", s.handleImpersonationStopPage)
}

// callerSID is the sid of the caller's X-Forwarded-Access-Token (D36.8):
// its payload decoded (base64url, padded or not, then encoding/json)
// without checking the signature, inside the trust boundary as
// group-gate does — oauth2-proxy verified the token, Traefik deletes
// client copies and the proxy secret holds. "" when the header is
// absent or several, the token isn't three segments, the payload isn't
// base64url JSON, or sid isn't a string.
func callerSID(r *http.Request) string {
	vals := r.Header.Values("X-Forwarded-Access-Token")
	if len(vals) != 1 {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(vals[0]), ".")
	if len(parts) != 3 || parts[1] == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	var sid string
	if json.Unmarshal(claims["sid"], &sid) != nil {
		return ""
	}
	return sid
}

// impErr answers a refusal: a 4xx with the Hub's text; anything else on
// the people listener 503 with the generic text (the cause logged), on
// the Hub listener as writeErr does.
func impErr(w http.ResponseWriter, r *http.Request, what string, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 {
		http.Error(w, se.Error(), se.Status)
		return
	}
	if isPeople(r) {
		log.Printf("people: impersonation: %s: %v", what, err)
		http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
		return
	}
	writeErr(w, err, http.StatusInternalServerError)
}

// handleStartImpersonation: POST /api/directory/users/{u}/impersonation
// {reason, code, code_verifier, nonce} (≤ 8 KiB: 413; an unknown field
// 400) → 200 {id, next, until}, no-store. The Hub checks D36's rules in
// order (administrators only, on a fresh snapshot; the sid of the
// caller's access token; the fresh touch on this listener's verifier).
// No tool mirrors it (D46).
func (s *Server) handleStartImpersonation(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	var b struct {
		Reason       string `json:"reason"`
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		Nonce        string `json:"nonce"`
	}
	if !readMySignInBody(w, r, &b, `{"reason": "...", "code": "...", "code_verifier": "...", "nonce": "..."}`) {
		return
	}
	u := r.PathValue("username")
	out, err := s.Hub.StartImpersonation(r.Context(), hub.StartImpersonation{
		Target: u, Reason: b.Reason, AdminSID: callerSID(r), Listener: listenerOf(r),
		Proof: freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce},
	}, requestActor(r))
	if err != nil {
		impErr(w, r, "starting to sign in as "+u, err)
		return
	}
	noStore(w)
	writeJSON(w, out)
}

// handleStopImpersonation: POST /api/directory/users/{u}/impersonation/stop
// → 204 (administrators only: 403; none running 404).
func (s *Server) handleStopImpersonation(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if _, ok := mySignInUser(w, r); !ok {
		return
	}
	u := r.PathValue("username")
	if err := s.stopImpersonation(r.Context(), requestActor(r), u); err != nil {
		impErr(w, r, "stopping the impersonation of "+u, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleImpersonations: GET /api/impersonations → ImpersonationsView
// (Hub listener, administrators).
func (s *Server) handleImpersonations(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.impersonations())
}

// handleSetImpersonation: PUT /api/signin/impersonation {allowed} →
// ImpersonationsView (Hub listener, administrators). Audited
// signin.impersonation on / off.
func (s *Server) handleSetImpersonation(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	var b struct {
		Allowed *bool `json:"allowed"`
	}
	if !decodeStrict(w, r, &b, `{"allowed": true|false}`) {
		return
	}
	if b.Allowed == nil {
		writeJSONError(w, http.StatusBadRequest, "allowed is required")
		return
	}
	v, err := s.setImpersonationAllowed(r.Context(), requestActor(r), *b.Allowed)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

// myImpersonation is GET /api/me/impersonation's active value.
type myImpersonation struct {
	Person  string `json:"person"`
	Admin   string `json:"admin"`
	Reason  string `json:"reason"`
	Until   string `json:"until"`
	StopURL string `json:"stop_url"`
}

// impStopURL is the Stop page (https://people.<domain>/impersonation/stop).
func (s *Server) impStopURL() string { return s.peopleHome() + "impersonation/stop" }

// handleMyImpersonation: GET /api/me/impersonation → {"active": null},
// or the running impersonation X-Forwarded-Impersonation names when its
// person is the caller (another id, another person's or an ended one:
// null). no-store.
func (s *Server) handleMyImpersonation(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	var active *myImpersonation
	if v := s.Hub.ImpersonationOf(user, r.Header.Get(ImpersonationHeader)); v != nil {
		active = &myImpersonation{Person: v.Person, Admin: v.Admin, Reason: v.Reason,
			Until: v.Until.UTC().Format(time.RFC3339), StopURL: s.impStopURL()}
	}
	noStore(w)
	writeJSON(w, map[string]any{"active": active})
}

// handleStopOwnImpersonation: POST /api/me/impersonation/stop (CSRF; the
// one change RefuseWhileImpersonated lets through) → 200 {"sign_out"},
// no-store: ends the impersonation X-Forwarded-Impersonation names when
// its person is the caller (how stopped, audited with actor = the
// record's administrator); otherwise 404.
func (s *Server) handleStopOwnImpersonation(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	signOut, err := s.Hub.StopOwnImpersonation(r.Context(), r.Header.Get(ImpersonationHeader), user)
	noStoreHeaders(w)
	if err != nil {
		impErr(w, r, "stopping the own impersonation of "+user, err)
		return
	}
	writeJSON(w, map[string]string{"sign_out": signOut})
}

// handleImpersonationStopPage: GET /impersonation/stop, the Stop page
// (web/impersonation-stop.html; its script asks GET
// /api/me/impersonation and does the POST above).
func (s *Server) handleImpersonationStopPage(w http.ResponseWriter, r *http.Request) {
	if s.impStop == nil {
		http.NotFound(w, r)
		return
	}
	domain := ""
	if s.Hub != nil {
		domain = s.Hub.Domain()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.impStop.Execute(w, map[string]any{"Domain": domain, "HubURL": s.HubURL, "PeopleURL": s.PeopleURL}); err != nil {
		log.Printf("people: impersonation stop page: %v", err)
	}
}

// ── shared by the routes and their tools ─────────────────

func (s *Server) impersonations() hub.ImpersonationsView {
	s.rec("Impersonations")
	return s.Hub.Impersonations()
}

func (s *Server) stopImpersonation(ctx context.Context, a directory.Actor, user string) error {
	s.rec("StopImpersonation", user)
	return s.Hub.StopImpersonation(ctx, user, a)
}

func (s *Server) setImpersonationAllowed(ctx context.Context, a directory.Actor, allowed bool) (*hub.ImpersonationsView, error) {
	s.rec("SetImpersonationAllowed", allowed)
	return s.Hub.SetImpersonationAllowed(ctx, allowed, a)
}
