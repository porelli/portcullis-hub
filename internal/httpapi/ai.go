package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

// Settings → AI and model providers (contract §15.11–15.12, plan 4 Task
// 9): Hub listener only (never people), admins only (folderAdmin: no
// X-Forwarded-User 401, then adminOnly — no Users & Groups 503, delegates
// 403), proxy-secret + CSRF like every route. Bodies are strict JSON
// (decodeAPI: 64 KiB, unknown fields and trailing data refused, a fixed
// usage message — never the decoder's error, which could quote a
// secret). Every answer shows a provider secret as {set, updated_at}
// only; a provider body has no secret field (one is an unknown field).
// The Hub audits each change (settings.ai, ai.provider.add|update|
// secret|delete) with the request's actor.

func (s *Server) registerAI(mux routeMux) {
	mux.HandleFunc("GET /api/ai/settings", s.handleAISettings)
	mux.HandleFunc("PUT /api/ai/settings", s.handleSaveAISettings)
	mux.HandleFunc("GET /api/ai/providers", s.handleModelProviders)
	mux.HandleFunc("POST /api/ai/providers", s.handleAddModelProvider)
	mux.HandleFunc("PUT /api/ai/providers/{name}", s.handleUpdateModelProvider)
	mux.HandleFunc("DELETE /api/ai/providers/{name}", s.handleDeleteModelProvider)
	mux.HandleFunc("PUT /api/ai/providers/{name}/secrets/{field}", s.handleProviderSecret)
	// Per-instance AI support (Task 12a, §15.11).
	mux.HandleFunc("GET /api/instances/{id}/ai", s.handleInstanceAI)
	mux.HandleFunc("PUT /api/instances/{id}/ai", s.handleUpdateInstanceAI)
	// What saving a Hub default policy would switch off first (G43).
	mux.HandleFunc("POST /api/settings/preview", s.handleDefaultPolicyPreview)
}

const (
	aiSettingsUsage = `{"enabled": bool, "clients": {"claude"|"claude_code"|"generic": {"offered": bool, "admin": bool}}, ` +
		`"portcullis_admin": bool, "portcullis_people": bool, "offline_idle_days": n, "offline_max_days": n, ` +
		`"limits": {"resource_rpm", "resource_burst", "person_rpm", "tool_calls_rpm", "confirmations_per_hour", "mints_per_minute", "fanout": n}, ` +
		`"allowed_origins": ["https://<host>[:port]", ...]} (only what changed)`
	providerUsage = `{"name", "label", "kind", "instance", "base_url", "region", "instance_name", "api_version", ` +
		`"deployments": {"<deployment>": "<model>"}, "models": {"fetch": bool, "list": ["<model>", ...]}, "credentials": "admin"|"per_person"} (no secret fields)`
	providerSecretUsage = `{"value": "<secret>"} or {"clear": true}`
	instanceAIUsage     = `{"companions": {"<name>": {"enabled": bool, "mode": "read_only"|"read_write"}}}`
)

// handleDefaultPolicyPreview: {"default_auth_policy"} → {"warnings"}
// (nothing stored).
func (s *Server) handleDefaultPolicyPreview(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var b struct {
		DefaultAuthPolicy *policy.AuthPolicy `json:"default_auth_policy"`
	}
	if !decodeAPI(w, r, &b, `{"default_auth_policy": {"factors": [...], "op": "any"|"all"}}`) {
		return
	}
	if b.DefaultAuthPolicy == nil {
		writeJSONError(w, http.StatusBadRequest, "body must be {\"default_auth_policy\": {...}}")
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"warnings": append([]string{}, s.Hub.DefaultPolicyAIWarnings(*b.DefaultAuthPolicy)...)})
}

// handleInstanceAI is the instance's AI tab.
func (s *Server) handleInstanceAI(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	v, err := s.Hub.InstanceAI(id)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

// handleUpdateInstanceAI switches companions and modes (the Hub audits
// ai.enable / ai.disable / ai.mode with the request's actor). The
// provider selection (ai.chat) is Task 23's: "providers" is an unknown
// field until then.
func (s *Server) handleUpdateInstanceAI(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var u hub.InstanceAIUpdate
	if !decodeAPI(w, r, &u, instanceAIUsage) {
		return
	}
	res, err := s.Hub.UpdateInstanceAI(r.Context(), id, u, requestActor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}

func (s *Server) handleAISettings(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.AISettings())
}

func (s *Server) handleSaveAISettings(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var u hub.AISettingsUpdate
	if !decodeAPI(w, r, &u, aiSettingsUsage) {
		return
	}
	if err := s.Hub.SaveAISettings(u, requestActor(r)); err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.AISettings())
}

func (s *Server) handleModelProviders(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"providers": s.Hub.ModelProviders(r.Context())})
}

func (s *Server) handleAddModelProvider(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var p state.ModelProvider
	if !decodeAPI(w, r, &p, providerUsage) {
		return
	}
	v, err := s.Hub.AddModelProvider(p, requestActor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSONStatus(w, http.StatusCreated, map[string]any{"provider": v})
}

func (s *Server) handleUpdateModelProvider(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var p state.ModelProvider
	if !decodeAPI(w, r, &p, providerUsage) {
		return
	}
	v, err := s.Hub.UpdateModelProvider(r.PathValue("name"), p, requestActor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"provider": v})
}

func (s *Server) handleDeleteModelProvider(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	if err := s.Hub.DeleteModelProvider(r.PathValue("name"), requestActor(r)); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleProviderSecret: exactly one of {"value"} (non-empty) and
// {"clear": true}. The value is taken from the raw body as bytes and
// zeroed after the store write (Go strings can't be zeroed: a value with
// JSON escapes passes through one string).
func (s *Server) handleProviderSecret(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var b struct {
		Value *json.RawMessage `json:"value"`
		Clear *bool            `json:"clear"`
	}
	if !decodeAPI(w, r, &b, providerSecretUsage) {
		return
	}
	defer func() {
		if b.Value != nil {
			clear(*b.Value)
		}
	}()
	name, field := r.PathValue("name"), r.PathValue("field")
	var (
		v   hub.SecretView
		err error
	)
	switch {
	case b.Value != nil && b.Clear == nil:
		val, ok := rawJSONString(*b.Value)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "body must be "+providerSecretUsage)
			return
		}
		v, err = s.Hub.SetProviderSecret(name, field, val, requestActor(r))
	case b.Value == nil && b.Clear != nil && *b.Clear:
		v, err = s.Hub.ClearProviderSecret(name, field, requestActor(r))
	default:
		writeJSONError(w, http.StatusBadRequest, "body must be "+providerSecretUsage)
		return
	}
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

// rawJSONString is the bytes of the JSON string raw (ok false: not a
// string). Without escapes the bytes are copied straight out of raw;
// with escapes they go through encoding/json once.
func rawJSONString(raw []byte) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	inner := raw[1 : len(raw)-1]
	if !bytes.ContainsRune(inner, '\\') {
		return bytes.Clone(inner), true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil, false
	}
	return []byte(s), true
}
