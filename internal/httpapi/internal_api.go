package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// The gate ⇄ Hub internal API (contract §15.7), on the MCP listener only
// (MCPHandler: behind MCPSecret). Companion resources only; bodies are
// strict JSON (DisallowUnknownFields, no trailing data, ≤ 64 KiB: else
// 400 / 413). Answers are exactly the contract's: the gate refuses
// anything else (fail closed, G26).

// internalBodyMax bounds an internal API body.
const internalBodyMax = 64 << 10

// registerInternal adds the /internal routes. The confirmation routes are
// Task 14's (companion confirmations, §15.6): 501 until then.
func (s *Server) registerInternal(mux routeMux) {
	mux.HandleFunc("POST /internal/credentials", s.handleInternalCredentials)
	mux.HandleFunc("POST /internal/confirmations", notYet("companion confirmations (Task 14)"))
	mux.HandleFunc("POST /internal/confirmations/consume", notYet("consuming companion confirmations (Task 14)"))
}

// decodeInternal decodes r's body strictly into v; false = answered (400
// a bad body, 413 over 64 KiB). The message never quotes the body.
func decodeInternal(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, internalBodyMax))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if err = dec.Decode(&struct{}{}); err == io.EOF {
			return true
		} else if err == nil {
			err = errors.New("trailing data")
		}
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body over 64 KiB"})
		return false
	}
	writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "body must be one JSON object with exactly the documented fields"})
	return false
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
	if !decodeInternal(w, r, &req) {
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
		case http.StatusForbidden, http.StatusNotFound:
			writeJSONStatus(w, code, map[string]string{"error": http.StatusText(code)})
		default:
			writeJSONStatus(w, code, map[string]string{"error": clipMessage(err.Error(), 500)})
		}
		return
	}
	if res.NoAccount {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"code": "no_account", "app_url": res.AppURL})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]string{"id": res.ID})
}
