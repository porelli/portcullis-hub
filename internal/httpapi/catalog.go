package httpapi

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/templates"
)

// The catalog assets (contract §11.7 "Catalog assets"): a template's logo
// and screenshots, the bytes the Hub checked at template load, served
// from memory (never the file) on the Hub listener only. A logo is shown
// only as <img src>; the headers make it inert if opened directly too.

// catalogCSP sandboxes an asset opened in a tab (an SVG then runs
// nothing).
const catalogCSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

// shotIndexRe: decimal digits only (no sign, no hex), bounded.
var shotIndexRe = regexp.MustCompile(`^[0-9]{1,3}$`)

func (s *Server) registerCatalog(mux *recordingMux) {
	mux.HandleFunc("GET /api/catalog/{id}/logo.svg", s.handleCatalogLogo)
	mux.HandleFunc("GET /api/catalog/{id}/screenshots/{n}", s.handleCatalogScreenshot)
}

// catalogTemplate is the template the path names (false: answered 404).
func (s *Server) catalogTemplate(w http.ResponseWriter, r *http.Request) (templates.Template, bool) {
	id := r.PathValue("id")
	if !templates.ValidID(id) {
		http.NotFound(w, r)
		return templates.Template{}, false
	}
	t, ok := s.Hub.CatalogTemplate(id)
	if !ok {
		http.NotFound(w, r)
	}
	return t, ok
}

func writeCatalogAsset(w http.ResponseWriter, ctype, filename string, b []byte) {
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", catalogCSP)
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Content-Disposition", `inline; filename="`+filename+`"`)
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Server) handleCatalogLogo(w http.ResponseWriter, r *http.Request) {
	t, ok := s.catalogTemplate(w, r)
	if !ok {
		return
	}
	b := t.LogoSVG()
	if b == nil {
		http.NotFound(w, r)
		return
	}
	writeCatalogAsset(w, "image/svg+xml", t.ID+"-logo.svg", b)
}

func (s *Server) handleCatalogScreenshot(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("n")
	if !shotIndexRe.MatchString(ns) {
		http.NotFound(w, r)
		return
	}
	n, _ := strconv.Atoi(ns)
	t, ok := s.catalogTemplate(w, r)
	if !ok {
		return
	}
	b, ctype, ok := t.Screenshot(n)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ext := strings.TrimPrefix(ctype, "image/")
	if ext == "jpeg" {
		ext = "jpg"
	}
	writeCatalogAsset(w, ctype, t.ID+"-"+strconv.Itoa(n)+"."+ext, b)
}
