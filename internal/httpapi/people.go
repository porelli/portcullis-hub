package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/directory"
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

// ── me ──────────────────────────────────────────────────

func perms(c *directory.Caller) []string {
	if c.Admin {
		return []string{directory.PermEditDetails, directory.PermInvite, directory.PermRemove}
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
// values keep the field's current ones.
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
	if err := s.Directory.CreateField(r.Context(), c, f); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "created", "field": f})
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
	name := r.PathValue("name")
	// Start from the current definition so a partial body changes only
	// what it names (UpdateField re-reads and checks everything).
	cur := directory.Field{Name: name}
	if s.Directory.Store != nil {
		if cfg, err := s.Directory.Store.Load(); err == nil {
			for _, f := range cfg.Fields {
				if f.Name == name {
					cur = f
				}
			}
		}
	}
	req.Name = nil // the path names the field
	f := req.apply(cur)
	if err := s.Directory.UpdateField(r.Context(), c, f); err != nil {
		dirErr(w, err)
		return
	}
	statusJSON(w, "saved")
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
	if err := s.Directory.DeleteField(r.Context(), c, r.PathValue("name"), req.Confirm); err != nil {
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
	if err := s.Directory.SetDetails(r.Context(), c, r.PathValue("username"), req.Attrs); err != nil {
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
	if err := s.Directory.SetGroupRule(r.Context(), c, r.PathValue("group"), rule); err != nil {
		dirErr(w, err)
		return
	}
	if rule == nil {
		writeJSON(w, map[string]interface{}{"status": "saved", "text": "", "expr": nil})
		return
	}
	out := ruleJSON(rule)
	out["status"] = "saved"
	writeJSON(w, out)
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
	if err := s.Directory.ConvertApplyReviewed(r.Context(), c, r.PathValue("group"), rule, req.Keep, req.Preview); err != nil {
		dirErr(w, err)
		return
	}
	out := ruleJSON(rule)
	out["status"] = "saved"
	writeJSON(w, out)
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
	if err := s.Directory.AddException(r.Context(), c, r.PathValue("group"), ex); err != nil {
		dirErr(w, err)
		return
	}
	statusJSON(w, "saved")
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
	if err := s.Directory.RemoveException(r.Context(), c, r.PathValue("group"), r.PathValue("username")); err != nil {
		dirErr(w, err)
		return
	}
	statusJSON(w, "removed")
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
	if err := s.Directory.SetMemberExpiry(r.Context(), c, r.PathValue("group"), r.PathValue("username"), req.Until); err != nil {
		dirErr(w, err)
		return
	}
	statusJSON(w, "saved")
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
	if err := s.Directory.SetPermission(r.Context(), c, r.PathValue("perm"), req.Group); err != nil {
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
	c, ok := s.caller(w, r)
	if !ok {
		return
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
	var req directory.ApplyRequest
	if !decodeLarge(w, r, maxImportJSON, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.Directory.ImportApply(r.Context(), c, req)
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}
