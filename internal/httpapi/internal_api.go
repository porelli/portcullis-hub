package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
)

// The gate ⇄ Hub internal API (contract §15.7), on the MCP listener only
// (MCPHandler: behind MCPSecret). Companion resources only; bodies are
// strict JSON (DisallowUnknownFields, no trailing data, ≤ 64 KiB: else
// 400 / 413). Answers are exactly the contract's: the gate refuses
// anything else (fail closed, G26).

// internalBodyMax bounds an internal API body.
const internalBodyMax = 64 << 10

// registerInternal adds the /internal routes (companion credentials and
// confirmations, §15.6: confirm.go).
func (s *Server) registerInternal(mux routeMux) {
	mux.HandleFunc("POST /internal/credentials", s.handleInternalCredentials)
	mux.HandleFunc("POST /internal/confirmations", s.handleInternalConfirmCreate)
	mux.HandleFunc("POST /internal/confirmations/consume", s.handleInternalConfirmConsume)
}

// decodeInternal decodes r's body strictly into v; false = answered (400
// a bad body, 413 over 64 KiB). keys are v's exact JSON names: like the
// gate's strict(), the top level must be one object whose keys are among
// them, spelled exactly (encoding/json would match "User" or "USER" to
// "user") and never repeated (it would keep the last); then
// DisallowUnknownFields and no trailing data. The message never quotes
// the body.
func decodeInternal(w http.ResponseWriter, r *http.Request, v any, keys ...string) bool {
	bad := func() bool {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "body must be one JSON object with exactly the documented fields"})
		return false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, internalBodyMax))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body over 64 KiB"})
			return false
		}
		return bad()
	}
	if !exactKeys(b, keys) {
		return bad()
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		return bad()
	}
	if _, err := dec.Token(); err != io.EOF {
		return bad()
	}
	return true
}

// exactKeys: b is one JSON object whose top-level keys are each in
// allowed (exact spelling) and appear once.
func exactKeys(b []byte, allowed []string) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		k, ok := t.(string)
		if !ok || seen[k] || !slices.Contains(allowed, k) {
			return false
		}
		seen[k] = true
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return false
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return false
	}
	return true
}

// handleInternalCredentials: POST /internal/credentials {"resource",
// "user"} → 200 {"id"} | 409 {"code": "no_account", "app_url"} | 403 (not
// in the population, fresh directory snapshot) | 404 (not a current
// app_token companion resource) | 502 {"code": "mint_failed"}. Anything
// else (a directory outage: 503) is a failure to the gate.
func (s *Server) handleInternalCredentials(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Resource *string `json:"resource"`
		User     *string `json:"user"`
	}
	if !decodeInternal(w, r, &req, "resource", "user") {
		return
	}
	if req.Resource == nil || req.User == nil || *req.Resource == "" || *req.User == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "resource and user are required"})
		return
	}
	res, err := s.Hub.MintCredential(r.Context(), *req.Resource, *req.User)
	if err != nil {
		switch code := errStatus(err, http.StatusInternalServerError); code {
		case http.StatusBadGateway:
			writeJSONStatus(w, code, map[string]string{"code": "mint_failed"})
		default:
			// 403 / 404 and every answer outside the contract (503, 500):
			// a fixed body; the detail only in the log.
			if code != http.StatusForbidden && code != http.StatusNotFound {
				log.Printf("internal api: credentials for %q: %d: %s", clipMessage(*req.User, 64), code, clipMessage(err.Error(), 500))
			}
			writeJSONStatus(w, code, map[string]string{"error": http.StatusText(code)})
		}
		return
	}
	if res.NoAccount {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"code": "no_account", "app_url": res.AppURL})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]string{"id": res.ID})
}
