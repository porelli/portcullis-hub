package httpapi

import (
	"context"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/signin"
)

// Sign-in methods management (contract §8.1): Hub listener only (never
// people), admins only (adminOnly; without Users & Groups 503).

const signInUsage = `JSON body expected`

func (s *Server) registerSignIn(mux routeMux) {
	mux.HandleFunc("GET /api/signin", s.handleSignIn)
	mux.HandleFunc("PUT /api/signin/methods/{method}", s.handleSetMethod)
	mux.HandleFunc("POST /api/signin/templates", s.handleCreateTemplate)
	mux.HandleFunc("PUT /api/signin/templates/{id}", s.handleUpdateTemplate)
	mux.HandleFunc("PUT /api/signin/templates/{id}/enabled", s.handleSetTemplateEnabled)
	mux.HandleFunc("DELETE /api/signin/templates/{id}", s.handleDeleteTemplate)
	mux.HandleFunc("POST /api/signin/templates/preview", s.handlePreviewTemplate)
	mux.HandleFunc("PUT /api/signin/default", s.handleSetDefault)
	mux.HandleFunc("PUT /api/signin/core/{key}", s.handleSetCore)
	mux.HandleFunc("PUT /api/signin/add-stronger", s.handleSetAddStronger)
	mux.HandleFunc("GET /api/instances/{id}/signin", s.handleInstanceSignIn)
}

// signInAdmin: a signed-in admin (no user 401; then adminOnly: no Users
// & Groups 503, anyone else 403).
func (s *Server) signInAdmin(w http.ResponseWriter, r *http.Request) bool {
	if requestActor(r).User == "" {
		writeJSONError(w, http.StatusUnauthorized, "no signed-in user (X-Forwarded-User)")
		return false
	}
	return s.adminOnly(w, r)
}

// handleSignIn: GET /api/signin → SignInView.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	view, err := s.signInView(r.Context())
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, view)
}

// handleSetMethod: PUT /api/signin/methods/{method} {on} → SignInChange.
func (s *Server) handleSetMethod(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	m := signin.Method(r.PathValue("method"))
	var b struct {
		On bool `json:"on"`
	}
	if !decodeStrict(w, r, &b, signInUsage) {
		return
	}
	ch, err := s.setMethod(r.Context(), requestActor(r), m, b.On)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, ch)
}

// handleCreateTemplate: POST /api/signin/templates {id,name,rule} → SignInChange.
func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	var in struct {
		ID   string       `json:"id"`
		Name string       `json:"name"`
		Rule *signin.Node `json:"rule"`
	}
	if !decodeStrict(w, r, &in, signInUsage) {
		return
	}
	if in.Rule == nil {
		writeJSONError(w, http.StatusBadRequest, "rule is required")
		return
	}
	ch, err := s.saveSignInTemplate(r.Context(), requestActor(r), in.ID, hub.TemplateInput{Name: in.Name, Rule: *in.Rule}, true)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusCreated, ch)
}

// handleUpdateTemplate: PUT /api/signin/templates/{id} {name,rule} → SignInChange.
func (s *Server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	var in struct {
		Name string       `json:"name"`
		Rule *signin.Node `json:"rule"`
	}
	if !decodeStrict(w, r, &in, signInUsage) {
		return
	}
	if in.Rule == nil {
		writeJSONError(w, http.StatusBadRequest, "rule is required")
		return
	}
	ch, err := s.saveSignInTemplate(r.Context(), requestActor(r), id, hub.TemplateInput{Name: in.Name, Rule: *in.Rule}, false)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, ch)
}

// handleSetTemplateEnabled: PUT /api/signin/templates/{id}/enabled {on} → SignInChange.
func (s *Server) handleSetTemplateEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	var b struct {
		On bool `json:"on"`
	}
	if !decodeStrict(w, r, &b, signInUsage) {
		return
	}
	ch, err := s.setTemplateEnabled(r.Context(), requestActor(r), id, b.On)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, ch)
}

// handleDeleteTemplate: DELETE /api/signin/templates/{id} → 204.
func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.deleteTemplate(r.Context(), requestActor(r), id); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePreviewTemplate: POST /api/signin/templates/preview {id?,name,rule} → TemplatePreview.
func (s *Server) handlePreviewTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	var in struct {
		ID   string       `json:"id"`
		Name string       `json:"name"`
		Rule *signin.Node `json:"rule"`
	}
	if !decodeStrict(w, r, &in, signInUsage) {
		return
	}
	if in.Rule == nil {
		writeJSONError(w, http.StatusBadRequest, "rule is required")
		return
	}
	preview, err := s.previewTemplate(r.Context(), in.ID, hub.TemplateInput{Name: in.Name, Rule: *in.Rule})
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, preview)
}

// handleSetDefault: PUT /api/signin/default {template} → SignInChange.
func (s *Server) handleSetDefault(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	var b struct {
		Template string `json:"template"`
	}
	if !decodeStrict(w, r, &b, signInUsage) {
		return
	}
	ch, err := s.setDefaultTemplate(r.Context(), requestActor(r), b.Template)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, ch)
}

// handleSetCore: PUT /api/signin/core/{key} {template} → SignInChange.
func (s *Server) handleSetCore(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	key := r.PathValue("key")
	var b struct {
		Template string `json:"template"`
	}
	if !decodeStrict(w, r, &b, signInUsage) {
		return
	}
	ch, err := s.setCoreTemplate(r.Context(), requestActor(r), key, b.Template)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, ch)
}

// handleSetAddStronger: PUT /api/signin/add-stronger {on} → 204.
func (s *Server) handleSetAddStronger(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	var b struct {
		On bool `json:"on"`
	}
	if !decodeStrict(w, r, &b, signInUsage) {
		return
	}
	if err := s.setAddStronger(r.Context(), requestActor(r), b.On); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleInstanceSignIn: GET /api/instances/{id}/signin → InstanceSignInView.
func (s *Server) handleInstanceSignIn(w http.ResponseWriter, r *http.Request) {
	if !s.signInAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	view, err := s.instanceSignIn(r.Context(), id)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, view)
}

// ── Shared work (HTTP handlers and MCP tools) ──

// signInView is the sign-in view (route and get_sign_in).
func (s *Server) signInView(ctx context.Context) (*hub.SignInView, error) {
	s.rec("SignInView")
	return s.Hub.SignInView(ctx)
}

// setMethod is the method switch (route and set_sign_in_method).
func (s *Server) setMethod(ctx context.Context, a directory.Actor, m signin.Method, on bool) (*hub.SignInChange, error) {
	s.rec("SetMethod", m, on)
	return s.Hub.SetMethod(ctx, m, on, a)
}

// saveSignInTemplate is the template save (route and save_sign_in_template).
func (s *Server) saveSignInTemplate(ctx context.Context, a directory.Actor, id string, in hub.TemplateInput, create bool) (*hub.SignInChange, error) {
	s.rec("SaveTemplate", id, in, create)
	return s.Hub.SaveTemplate(ctx, id, in, create, a)
}

// setTemplateEnabled is the enable/disable (route and set_sign_in_template_enabled).
func (s *Server) setTemplateEnabled(ctx context.Context, a directory.Actor, id string, on bool) (*hub.SignInChange, error) {
	s.rec("SetTemplateEnabled", id, on)
	return s.Hub.SetTemplateEnabled(ctx, id, on, a)
}

// deleteTemplate is the template delete (route and delete_sign_in_template).
func (s *Server) deleteTemplate(ctx context.Context, a directory.Actor, id string) error {
	s.rec("DeleteTemplate", id)
	return s.Hub.DeleteTemplate(ctx, id, a)
}

// previewTemplate is the template preview (route and preview_sign_in_template).
func (s *Server) previewTemplate(ctx context.Context, id string, in hub.TemplateInput) (*hub.TemplatePreview, error) {
	s.rec("PreviewTemplate", id, in)
	return s.Hub.PreviewTemplate(ctx, id, in)
}

// setDefaultTemplate is the default template save (route and set_default_template).
func (s *Server) setDefaultTemplate(ctx context.Context, a directory.Actor, id string) (*hub.SignInChange, error) {
	s.rec("SetDefaultTemplate", id)
	return s.Hub.SetDefaultTemplate(ctx, id, a)
}

// setCoreTemplate is the core template save (route and set_core_template).
func (s *Server) setCoreTemplate(ctx context.Context, a directory.Actor, key, id string) (*hub.SignInChange, error) {
	s.rec("SetCoreTemplate", key, id)
	return s.Hub.SetCoreTemplate(ctx, key, id, a)
}

// setAddStronger is the add_stronger switch (route and set_add_stronger).
func (s *Server) setAddStronger(ctx context.Context, a directory.Actor, on bool) error {
	s.rec("SetAddStronger", on)
	return s.Hub.SetAddStronger(on, a)
}

// instanceSignIn is the instance sign-in view (route).
func (s *Server) instanceSignIn(ctx context.Context, id string) (*hub.InstanceSignInView, error) {
	s.rec("InstanceSignIn", id)
	return s.Hub.InstanceSignIn(ctx, id)
}
