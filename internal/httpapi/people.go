package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/rules"
)

// Directory routes added with the people listener (contract §5.1, §9.6):
// who am I, fields, details, rules, exceptions, expiries, permissions and
// the CSV import. Both listeners register them; every mutation builds its
// Caller once (s.caller) and the service decides (authz.go).

const importReviewPath = "POST /api/directory/import/review"

// maxCSVUpload is the import file limit (the service refuses more too);
// maxImportBody bounds the multipart request and the JSON import bodies
// (rows sent back for review, apply requests).
const (
	maxCSVUpload  = 5 << 20
	maxImportBody = maxCSVUpload + 1<<20
	maxImportJSON = 8 << 20
)

func statusJSON(w http.ResponseWriter, status string) {
	writeJSON(w, map[string]string{"status": status})
}

// jsonError answers status with a JSON body {error, ...extra}.
func jsonError(w http.ResponseWriter, status int, body map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// decodeLarge is decodeJSON with a larger limit; an oversized body is 413.
func decodeLarge(w http.ResponseWriter, r *http.Request, limit int64, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// ── my apps (people listener only, contract §5.1) ───────

// registerPeopleApps registers the caller-only app routes of the people
// listener (never the Hub listener): the caller is X-Forwarded-User,
// lowercased; nothing about anyone else is answered. Contract §5.1 /
// G12: exactly these nine routes.
func (s *Server) registerPeopleApps(mux routeMux) {
	mux.HandleFunc("GET /api/me/apps", s.handleMyApps)
	// The caller's own person-entered values (Task 15A, spec call 32).
	mux.HandleFunc("PUT /api/me/apps/{instance}/values/{key}", s.handlePutMyValue)
	mux.HandleFunc("DELETE /api/me/apps/{instance}/values/{key}", s.handleDeleteMyValue)
	// The caller's own file-sharing credentials (Task 12, plan 3).
	mux.HandleFunc("POST /api/me/apps/{instance}/credentials/{key}", s.handleCreateCredential)
	mux.HandleFunc("DELETE /api/me/apps/{instance}/credentials/{key}", s.handleRevokeOwnCredential)
	// The caller's own AI connections and activity (plan 4 Task 21):
	// people listener only (404 on the Hub listener).
	mux.HandleFunc("GET /api/me/ai", s.handleMyAI)
	mux.HandleFunc("DELETE /api/me/ai/connections/{client}", s.handleDisconnectAI)
	// The caller's own confirmations (plan 4 Task 14, §15.6): also on the
	// Hub listener, each answering only for its own.
	s.registerConfirm(mux)
	// The Sign-in page and the caller's own sign-in routes (sign-in
	// part 2, D24/D25): people listener only.
	s.registerMySignIn(mux)
}

// handleMyAI answers the caller's (X-Forwarded-User, lowercased) AI
// connections and their own last 50 access-log lines → 200 hub.MyAIView,
// no-store. No caller 401; a refusal of the Hub's (4xx) its text; any
// other failure (Keycloak, the access log) 503 with the generic text,
// the cause only logged.
func (s *Server) handleMyAI(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	v, err := s.Hub.MyAI(r.Context(), user)
	if err != nil {
		myAIErr(w, "my AI of "+user, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

// handleDisconnectAI revokes the caller's own consent and offline
// sessions for one AI client → 204 (also when there was none). 404 for
// anything but one of the Hub's AI client ids; 429 past the refusal
// limit; 503 generic when Keycloak can't be changed.
func (s *Server) handleDisconnectAI(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	if err := s.Hub.DisconnectAI(r.Context(), user, r.PathValue("client"), selfActor(r, user)); err != nil {
		myAIErr(w, "disconnecting "+user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// myAIErr: a 4xx StatusError with the Hub's text (it names no one
// else); everything else 503 with the generic text, the cause logged.
func myAIErr(w http.ResponseWriter, what string, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 {
		http.Error(w, se.Error(), se.Status)
		return
	}
	log.Printf("people: %s: %v", what, err)
	http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
}

// entryBody is a person-entered value's body: {"value": <json>}.
type entryBody struct {
	Value json.RawMessage `json:"value"`
}

// readEntryBody decodes an entry body (≤ hub.EntryBodyMax: 413 beyond;
// unknown fields and trailing data 400, never echoing the body).
func readEntryBody(w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	var b entryBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, hub.EntryBodyMax))
	dec.DisallowUnknownFields()
	err := dec.Decode(&b)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, `body must be {"value": <value>}`, http.StatusBadRequest)
		return nil, false
	}
	return b.Value, true
}

// entryErr answers a person-entered value's refusal: 4xx with the Hub's
// text (it never names another person); 5xx the generic message, the
// cause only logged.
func entryErr(w http.ResponseWriter, who string, err error) {
	var se *hub.StatusError
	if errors.As(err, &se) && se.Status < 500 {
		http.Error(w, se.Error(), se.Status)
		return
	}
	log.Printf("people: value of %s: %v", who, err)
	http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
}

// selfActor is the caller acting on their own entry: requestActor's
// via / client, the user lowercased (user = strings.ToLower(actor(r))).
func selfActor(r *http.Request, user string) directory.Actor {
	a := requestActor(r)
	a.User = user
	return a
}

// handlePutMyValue stores the caller's (X-Forwarded-User, lowercased)
// own value → 200 hub.MyEntry. No caller 401.
func (s *Server) handlePutMyValue(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	v, ok := readEntryBody(w, r)
	if !ok {
		return
	}
	me, err := s.Hub.SetPersonValue(r.Context(), r.PathValue("instance"), r.PathValue("key"), user, v, selfActor(r, user))
	if err != nil {
		entryErr(w, user, err)
		return
	}
	noStore(w)
	writeJSON(w, me)
}

// handleDeleteMyValue clears the caller's own value → 204 (also when
// nothing was set).
func (s *Server) handleDeleteMyValue(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	if err := s.Hub.ClearPersonValue(r.Context(), r.PathValue("instance"), r.PathValue("key"), user, selfActor(r, user)); err != nil {
		entryErr(w, user, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMyApps answers hub.MyAppsView ({"apps": [hub.MyApp…],
// "fresh_auth": {…}}): the caller's own resolved per-person values,
// entries and credential cards. No caller 401; the directory unavailable 503 with
// the generic message (the cause is logged, never answered).
func (s *Server) handleMyApps(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(actor(r))
	if user == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return
	}
	view, err := s.Hub.MyApps(r.Context(), user)
	if err != nil {
		log.Printf("people: my apps of %s: %v", user, err)
		http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, view)
}

// ── me ──────────────────────────────────────────────────

func perms(c *directory.Caller) []string {
	if c.Admin {
		return []string{directory.PermEditDetails, directory.PermInvite, directory.PermRemove, directory.PermSignInHelp}
	}
	out := []string{}
	for p, ok := range c.Perms {
		if ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	noStore(w)
	writeJSON(w, map[string]interface{}{"user": c.User, "admin": c.Admin, "perms": perms(c)})
}

// ── fields ──────────────────────────────────────────────

// fieldBody: omitted values are nil. Create: share_with_apps defaults to
// true (contract §9.6), the rest to their zero value. Update: omitted
// values keep the field's current ones (directory.FieldPatch).
type fieldBody struct {
	Name          *string              `json:"name"`
	Label         *string              `json:"label"`
	Kind          *directory.FieldKind `json:"kind"`
	Values        []string             `json:"values"`
	Multi         *bool                `json:"multi"`
	ShareWithApps *bool                `json:"share_with_apps"`
	AdminOnly     *bool                `json:"admin_only"`
}

func (b fieldBody) apply(f directory.Field) directory.Field {
	if b.Name != nil {
		f.Name = *b.Name
	}
	if b.Label != nil {
		f.Label = *b.Label
	}
	if b.Kind != nil {
		f.Kind = *b.Kind
	}
	if b.Values != nil {
		f.Values = b.Values
	}
	if b.Multi != nil {
		f.Multi = *b.Multi
	}
	if b.ShareWithApps != nil {
		f.ShareWithApps = *b.ShareWithApps
	}
	if b.AdminOnly != nil {
		f.AdminOnly = *b.AdminOnly
	}
	return f
}

func (s *Server) handleCreateField(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req fieldBody
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	f := req.apply(directory.Field{ShareWithApps: true})
	if err := s.createField(r.Context(), c, f); err != nil {
		dirErr(w, err)
		return
	}
	out := map[string]interface{}{"status": "created"}
	// The field as stored (normalised by CreateField).
	if cfg, err := s.Directory.Store.Load(); err == nil {
		for _, sf := range cfg.Fields {
			if sf.Name == strings.TrimSpace(f.Name) {
				out["field"] = sf
			}
		}
	}
	writeJSON(w, out)
}

func (s *Server) handleUpdateField(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req fieldBody
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	// Merged with the stored field inside the service's lock.
	f, err := s.patchField(r.Context(), c, r.PathValue("name"), directory.FieldPatch{
		Label: req.Label, Kind: req.Kind, Values: req.Values, Multi: req.Multi, ShareWithApps: req.ShareWithApps, AdminOnly: req.AdminOnly})
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "saved", "field": f})
}

func (s *Server) handleDeleteField(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req confirmBody
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.deleteField(r.Context(), c, r.PathValue("name"), req.Confirm); err != nil {
		dirErr(w, err)
		return
	}
	statusJSON(w, "deleted")
}

// ── details ─────────────────────────────────────────────

func (s *Server) handleSetDetails(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		Attrs map[string][]string `json:"attrs"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Attrs == nil {
		http.Error(w, "attrs is required", http.StatusBadRequest)
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.setDetails(r.Context(), c, r.PathValue("username"), req.Attrs); err != nil {
		dirErr(w, err)
		return
	}
	statusJSON(w, "saved")
}

// ── rules ───────────────────────────────────────────────

// ruleBody is a rule as text (rule) or as a tree (expr), exactly one.
type ruleBody struct {
	Rule *string     `json:"rule"`
	Expr *rules.Expr `json:"expr"`
}

// parse returns the rule; on error it has answered 400: a text that
// doesn't parse as JSON {error, column} (1-based), anything else as text.
func (b ruleBody) parse(w http.ResponseWriter) (*rules.Expr, bool) {
	switch {
	case b.Rule != nil && b.Expr != nil:
		http.Error(w, "send either rule (text) or expr, not both", http.StatusBadRequest)
	case b.Rule != nil:
		e, err := rules.Parse(*b.Rule)
		if err != nil {
			jsonError(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error(), "column": rules.ErrorColumn(err)})
			return nil, false
		}
		return e, true
	case b.Expr != nil:
		if err := rules.Validate(b.Expr); err != nil {
			jsonError(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid rule: " + err.Error(), "column": 0})
			return nil, false
		}
		return b.Expr, true
	default:
		http.Error(w, "a rule (text) or expr is required", http.StatusBadRequest)
	}
	return nil, false
}

// ruleJSON is the rule in both forms, so the UI can show either.
func ruleJSON(e *rules.Expr) map[string]interface{} {
	return map[string]interface{}{"text": rules.Format(e), "expr": e}
}

// handleRulePreview: any signed-in caller. Also the text ⇄ blocks
// converter: the answer carries the rule in both forms.
func (s *Server) handleRulePreview(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req ruleBody
	if !decodeJSON(w, r, &req) {
		return
	}
	rule, ok := req.parse(w)
	if !ok {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	users, err := s.Directory.PreviewRule(r.Context(), c, rule)
	if err != nil {
		dirErr(w, err)
		return
	}
	out := ruleJSON(rule)
	out["users"] = users
	writeJSON(w, out)
}

func (s *Server) handleSetGroupRule(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		ruleBody
		Manual bool `json:"manual"` // drop the rule: the group becomes manual
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	var rule *rules.Expr
	if req.Manual {
		if req.Rule != nil || req.Expr != nil {
			http.Error(w, "manual takes no rule", http.StatusBadRequest)
			return
		}
	} else {
		var ok bool
		if rule, ok = req.parse(w); !ok {
			return
		}
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	st, err := s.setGroupRule(r.Context(), c, r.PathValue("group"), rule)
	if err != nil {
		dirErr(w, err)
		return
	}
	if rule == nil {
		writeJSON(w, st.with(map[string]any{"status": "saved", "text": "", "expr": nil}))
		return
	}
	out := ruleJSON(rule)
	out["status"] = "saved"
	writeJSON(w, st.with(out))
}

func (s *Server) handleConvertPreview(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req ruleBody
	if !decodeJSON(w, r, &req) {
		return
	}
	rule, ok := req.parse(w)
	if !ok {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	p, err := s.Directory.ConvertPreview(r.Context(), c, r.PathValue("group"), rule)
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, p)
}

// handleConvert applies a reviewed conversion: preview echoes what the
// admin saw; if the group or the people changed since, 409 (review again).
func (s *Server) handleConvert(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		ruleBody
		Keep    []string                  `json:"keep"`
		Preview *directory.ConvertPreview `json:"preview"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	rule, ok := req.parse(w)
	if !ok {
		return
	}
	if req.Preview == nil {
		http.Error(w, "preview is required: send back the convert-preview you reviewed", http.StatusBadRequest)
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	st, err := s.convertGroup(r.Context(), c, r.PathValue("group"), rule, req.Keep, req.Preview)
	if err != nil {
		dirErr(w, err)
		return
	}
	out := ruleJSON(rule)
	out["status"] = "saved"
	writeJSON(w, st.with(out))
}

// ── exceptions, expiry, permissions ─────────────────────

func (s *Server) handleAddException(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		User    string     `json:"user"`
		Reason  string     `json:"reason"`
		Include bool       `json:"include"`
		Until   *time.Time `json:"until"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	ex := directory.Exception{User: req.User, Reason: req.Reason, Include: req.Include, Until: req.Until}
	st, err := s.addException(r.Context(), c, r.PathValue("group"), ex)
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, st.with(map[string]any{"status": "saved"}))
}

func (s *Server) handleRemoveException(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	st, err := s.removeException(r.Context(), c, r.PathValue("group"), r.PathValue("username"))
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, st.with(map[string]any{"status": "removed"}))
}

func (s *Server) handleSetExpiry(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		Until *time.Time `json:"until"` // null: no end
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	st, err := s.setMemberExpiry(r.Context(), c, r.PathValue("group"), r.PathValue("username"), req.Until)
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, st.with(map[string]any{"status": "saved"}))
}

func (s *Server) handleSetPermission(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		Group string `json:"group"` // "": nobody
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.setPermission(r.Context(), c, r.PathValue("perm"), req.Group); err != nil {
		dirErr(w, err)
		return
	}
	statusJSON(w, "saved")
}

// ── import ──────────────────────────────────────────────

// handleImportReview reviews a CSV upload (multipart, field "file", at
// most 5 MB: 413 beyond) or rows the UI sends back after editing (JSON
// {header, rows}, so the effect box follows the edits). Read-only.
func (s *Server) handleImportReview(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	// Who and whether first: nothing is read for a caller who can't import.
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if !c.CanImport() {
		http.Error(w, "not allowed: needs edit_details, invite or remove", http.StatusForbidden)
		return
	}
	var header []string
	var rows [][]string
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt == "multipart/form-data" {
		var ok bool
		if header, rows, ok = readCSVUpload(w, r); !ok {
			return
		}
	} else {
		var req struct {
			Header []string   `json:"header"`
			Rows   [][]string `json:"rows"`
		}
		if !decodeLarge(w, r, maxImportJSON, &req) {
			return
		}
		var err error
		if header, rows, err = directory.NormalizeImport(req.Header, req.Rows); err != nil {
			dirErr(w, err)
			return
		}
	}
	rev, err := s.Directory.ImportReview(r.Context(), c, header, rows)
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, map[string]interface{}{"header": header, "rows": rows, "review": rev})
}

// readCSVUpload streams the multipart part "file" through ParseCSV; on
// failure it has answered (413 past 5 MB).
func readCSVUpload(w http.ResponseWriter, r *http.Request) ([]string, [][]string, bool) {
	tooLarge := func() ([]string, [][]string, bool) {
		http.Error(w, "CSV file too large (max 5 MB)", http.StatusRequestEntityTooLarge)
		return nil, nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBody)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "invalid multipart body: "+err.Error(), http.StatusBadRequest)
		return nil, nil, false
	}
	for {
		part, err := mr.NextPart()
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			return tooLarge()
		case err == io.EOF:
			http.Error(w, `the upload has no "file" part`, http.StatusBadRequest)
			return nil, nil, false
		case err != nil:
			http.Error(w, "invalid multipart body: "+err.Error(), http.StatusBadRequest)
			return nil, nil, false
		}
		if part.FormName() != "file" {
			part.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(part, maxCSVUpload+1))
		part.Close()
		if errors.As(err, &mbe) || len(data) > maxCSVUpload {
			return tooLarge()
		}
		if err != nil {
			http.Error(w, "read upload: "+err.Error(), http.StatusBadRequest)
			return nil, nil, false
		}
		header, rows, err := directory.ParseCSV(bytes.NewReader(data))
		if err != nil {
			dirErr(w, err)
			return nil, nil, false
		}
		return header, rows, true
	}
}

// handleImportApply applies the ticked rows; results may carry one-time
// invite links (never logged, not cached).
func (s *Server) handleImportApply(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if !c.CanImport() {
		http.Error(w, "not allowed: needs edit_details, invite or remove", http.StatusForbidden)
		return
	}
	var req directory.ApplyRequest
	if !decodeLarge(w, r, maxImportJSON, &req) {
		return
	}
	res, err := s.importApply(r.Context(), c, req)
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}
