package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/directory"
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
	// Revoke AI credentials now (§15.11; Task 17b: the twin of the
	// Portcullis MCP's revoke_ai_access).
	mux.HandleFunc("POST /api/instances/{id}/ai/revoke", s.handleRevokeAI)
	// The gate's access log (§15.8, §15.11; Task 17b: ai_activity's twin).
	mux.HandleFunc("GET /api/ai/activity", s.handleAIActivity)
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
	revokeAIUsage       = `{"companion": "<name>", "user": "<username>"} (user omitted = everyone)`
)

// maxActivity is GET /api/ai/activity's largest n (§15.11); defActivity
// its default.
const (
	maxActivity = 200
	defActivity = 50
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
	res, err := s.updateInstanceAI(r.Context(), requestActor(r), id, u)
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
	v, err := s.saveAISettings(requestActor(r), u)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
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
	v, err := s.addModelProvider(requestActor(r), p)
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
	v, err := s.updateModelProvider(requestActor(r), r.PathValue("name"), p)
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
	if err := s.deleteModelProvider(requestActor(r), r.PathValue("name")); err != nil {
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

// handleRevokeAI revokes one person's or everyone's AI credentials for a
// companion now (§15.11; audited ai.credential.revoke by the Hub).
func (s *Server) handleRevokeAI(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b struct {
		Companion string `json:"companion"`
		User      string `json:"user"`
	}
	if !decodeAPI(w, r, &b, revokeAIUsage) {
		return
	}
	res, err := s.revokeAI(r.Context(), requestActor(r), id, b.Companion, b.User)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}

// handleAIActivity: the access log's lines, newest first, filtered by
// instance and user, n ≤ 200 (§15.11).
func (s *Server) handleAIActivity(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	n := 0
	if v := q.Get("n"); v != "" {
		var err error
		// An explicit n is 1–200 (0 only means "the default" to aiActivity).
		if n, err = strconv.Atoi(v); err != nil || n < 1 {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("n must be 1-%d", maxActivity))
			return
		}
	}
	lines, err := s.aiActivity(q.Get("instance"), q.Get("user"), n)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"lines": lines})
}

// aiActivity is the access log read (route and ai_activity): n 0 = the
// default, else 1–200; instance / user "" = any (user lowercased).
func (s *Server) aiActivity(instance, user string, n int) ([]hub.AccessLine, error) {
	if n == 0 {
		n = defActivity
	}
	if n < 1 || n > maxActivity {
		return nil, badArg(fmt.Sprintf("n must be 1-%d", maxActivity))
	}
	user = strings.ToLower(user)
	return s.Hub.AccessLog(func(l hub.AccessLine) bool {
		return (instance == "" || l.Instance == instance) && (user == "" || l.User == user)
	}, n)
}

// revokeAI is the revoke's work (route and revoke_ai_access).
func (s *Server) revokeAI(ctx context.Context, a directory.Actor, id, companion, user string) (map[string]any, error) {
	user = strings.ToLower(user)
	s.rec("RevokeAICredentials", id, companion, user)
	if err := s.Hub.RevokeAICredentials(ctx, id, companion, user, a); err != nil {
		return nil, err
	}
	who := user
	if who == "" {
		who = "everyone"
	}
	return map[string]any{"status": "revoked", "instance": id, "companion": companion, "user": who}, nil
}

// updateInstanceAI is the AI tab's save (route, set_ai_support and
// set_ai_mode); audited ai.enable / ai.disable / ai.mode by the Hub.
func (s *Server) updateInstanceAI(ctx context.Context, a directory.Actor, id string, u hub.InstanceAIUpdate) (*hub.InstanceAIResult, error) {
	s.rec("UpdateInstanceAI", id, u)
	return s.Hub.UpdateInstanceAI(ctx, id, u, a)
}

// saveAISettings is Settings → AI's save (route and save_hub_settings);
// audited settings.ai by the Hub. → the settings as stored.
func (s *Server) saveAISettings(a directory.Actor, u hub.AISettingsUpdate) (hub.AISettingsView, error) {
	s.rec("SaveAISettings", u)
	if err := s.Hub.SaveAISettings(u, a); err != nil {
		return hub.AISettingsView{}, err
	}
	return s.Hub.AISettings(), nil
}

// addModelProvider, updateModelProvider and deleteModelProvider are the
// provider routes' work (and add_model_provider, save_model_provider,
// delete_model_provider); audited ai.provider.add|update|delete by the
// Hub.
func (s *Server) addModelProvider(a directory.Actor, p state.ModelProvider) (hub.ProviderView, error) {
	s.rec("AddModelProvider", p)
	return s.Hub.AddModelProvider(p, a)
}

func (s *Server) updateModelProvider(a directory.Actor, name string, p state.ModelProvider) (hub.ProviderView, error) {
	s.rec("UpdateModelProvider", name, p)
	return s.Hub.UpdateModelProvider(name, p, a)
}

func (s *Server) deleteModelProvider(a directory.Actor, name string) error {
	s.rec("DeleteModelProvider", name)
	return s.Hub.DeleteModelProvider(name, a)
}
