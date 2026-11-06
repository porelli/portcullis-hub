package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/policy"
)

// Instance settings (contract §13, Task 13): Hub listener only (never
// people), admins only (adminOnly: delegates 403; without Users & Groups
// nobody can be checked, 503 — settings need Users & Groups), no
// X-Forwarded-User 401, proxy-secret + CSRF like every route. Secret
// values are write-only: never in an answer, an error or a log — a body
// that doesn't decode gets a fixed message, never the decoder's.

// settingsBodyMax bounds a settings body.
const settingsBodyMax = 256 << 10

func (s *Server) registerSettings(mux routeMux) {
	mux.HandleFunc("GET /api/instances/{id}/settings", s.handleSettingsPanel)
	mux.HandleFunc("PUT /api/instances/{id}/settings", s.handleSaveSettings)
	mux.HandleFunc("POST /api/instances/{id}/settings/preview", s.handlePreviewSettings)
	mux.HandleFunc("POST /api/instances/{id}/settings/retry", s.handleRetryDeliveries)
	// Person-entered values (Task 15A): admins view them in the panel,
	// set one with admin_override, and can always clear one.
	mux.HandleFunc("PUT /api/instances/{id}/settings/entries/{key}/{user}", s.handlePutEntry)
	mux.HandleFunc("DELETE /api/instances/{id}/settings/entries/{key}/{user}", s.handleDeleteEntry)
}

// handlePutEntry sets a person's value as the admin (the option needs
// admin_override: else 403) → 200 hub.EntryRow.
func (s *Server) handlePutEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := s.settingsAdmin(w, r)
	if !ok {
		return
	}
	v, ok := readEntryBody(w, r)
	if !ok {
		return
	}
	row, err := s.Hub.SetEntryAsAdmin(r.Context(), id, r.PathValue("key"), r.PathValue("user"), v, requestActor(r))
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, row)
}

// handleDeleteEntry clears a person's value as the admin → 204.
func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := s.settingsAdmin(w, r)
	if !ok {
		return
	}
	if err := s.Hub.ClearEntryAsAdmin(r.Context(), id, r.PathValue("key"), r.PathValue("user"), requestActor(r)); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// settingsBody is the PUT / preview body.
type settingsBody struct {
	Values       map[string]json.RawMessage       `json:"values"`
	ValueIDs     map[string]map[string]int        `json:"value_group_ids"`
	Person       map[string]hub.PersonChange      `json:"person"`
	Groups       map[string][]hub.GroupValueInput `json:"groups"`
	Secrets      map[string]secretBody            `json:"secrets"`
	Ports        map[string]string                `json:"ports"`
	Policy       *policy.AuthPolicy               `json:"auth_policy"`
	Inherit      bool                             `json:"auth_policy_inherit"`
	PublicAccess *json.RawMessage                 `json:"public_access"` // true | false | "default"
	PublicMode   *string                          `json:"public_mode"`
	PublicTokens *[]string                        `json:"public_tokens"`
	SignIn       *string                          `json:"sign_in"`
}

// secretBody is one secret change: exactly one of value, generate, clear
// (the Hub checks it).
type secretBody struct {
	Value    *string `json:"value"`
	Generate bool    `json:"generate"`
	Clear    bool    `json:"clear"`
}

// settingsUsage is the fixed message of a body that doesn't decode.
const settingsUsage = `body must be {"values": {"<key>": <value>}, "value_group_ids": {"<key>": {"<group>": <id>}}, "person": {"<key>": {"default", "resolve", "rows": [{"group", "value", "group_id"}]}}, ` +
	`"groups": {"<key>": [{"group", "value", "group_id"}]}, "secrets": {"<key>": {"value" | "generate": true | "clear": true}}, ` +
	`"ports": {"<KEY>": "<port>"}, "auth_policy", "auth_policy_inherit", "public_access": true | false | "default", "public_mode", "public_tokens", "sign_in"}`

// settingsAdmin: a signed-in admin (no user 401; see adminOnly).
func (s *Server) settingsAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if requestActor(r).User == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return "", false
	}
	if !s.adminOnly(w, r) {
		return "", false
	}
	return instanceID(w, r)
}

// readSettingsBody decodes a settings body (unknown fields refused,
// 256 KiB); a failure answers settingsUsage, never echoing the body.
func readSettingsBody(w http.ResponseWriter, r *http.Request) (hub.SettingsUpdate, bool) {
	var b settingsBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, settingsBodyMax))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, settingsUsage, http.StatusBadRequest)
		return hub.SettingsUpdate{}, false
	}
	u := hub.SettingsUpdate{
		Values:        b.Values,
		ValueGroupIDs: b.ValueIDs,
		Person:        b.Person,
		Groups:        b.Groups,
		Ports:         b.Ports,
		Policy:        b.Policy,
		Inherit:       b.Inherit,
		PublicMode:    b.PublicMode,
		PublicTokens:  b.PublicTokens,
		SignIn:        b.SignIn,
	}
	if len(b.Secrets) > 0 {
		u.Secrets = make(map[string]hub.SecretChange, len(b.Secrets))
		for k, sc := range b.Secrets {
			u.Secrets[k] = hub.SecretChange{Value: sc.Value, Generate: sc.Generate, Clear: sc.Clear}
		}
	}
	if b.PublicAccess != nil {
		var on bool
		switch raw := bytes.TrimSpace(*b.PublicAccess); {
		case string(raw) == `"default"`:
			u.PublicAccessDefault = true
		case json.Unmarshal(raw, &on) == nil:
			u.PublicAccess = &on
		default:
			http.Error(w, `public_access must be true, false or "default"`, http.StatusBadRequest)
			return hub.SettingsUpdate{}, false
		}
	}
	return u, true
}

func (s *Server) handleSettingsPanel(w http.ResponseWriter, r *http.Request) {
	id, ok := s.settingsAdmin(w, r)
	if !ok {
		return
	}
	p, err := s.Hub.SettingsPanel(r.Context(), id)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, p)
}

// handleSaveSettings answers the SaveResult {effect, changed, warnings,
// deliveries}. A sign-in mode change (or refused change) is audited as
// app.sign_in, besides the Hub's settings.change entries.
func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	id, ok := s.settingsAdmin(w, r)
	if !ok {
		return
	}
	u, ok := readSettingsBody(w, r)
	if !ok {
		return
	}
	before := s.Hub.SignInMode(id)
	res, err := s.Hub.SaveSettings(id, u, requestActor(r))
	if u.SignIn != nil && (err != nil || s.Hub.SignInMode(id) != before) {
		s.auditSignIn(r, id, before, *u.SignIn, err)
	}
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, res)
}

// handlePreviewSettings: what saving the body would do (nothing stored).
func (s *Server) handlePreviewSettings(w http.ResponseWriter, r *http.Request) {
	id, ok := s.settingsAdmin(w, r)
	if !ok {
		return
	}
	u, ok := readSettingsBody(w, r)
	if !ok {
		return
	}
	p, err := s.Hub.PreviewSettings(r.Context(), id, u)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, p)
}

// handleRetryDeliveries runs the instance's deliveries again (audited
// settings.retry); the body is ignored.
func (s *Server) handleRetryDeliveries(w http.ResponseWriter, r *http.Request) {
	id, ok := s.settingsAdmin(w, r)
	if !ok {
		return
	}
	rep, err := s.Hub.RetryDeliveries(r.Context(), id, requestActor(r))
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}
