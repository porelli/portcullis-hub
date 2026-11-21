package templates

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/svgsafe"
)

// The catalog fields of contract §3 ("Catalog fields") and the asset
// routes' data (§11.7 "Catalog assets").

// Links is the manifest's links: the project's own homepage (what the
// Marketplace links) and its source repository (nil for a closed-source
// app, which says why in SourceNote).
type Links struct {
	Website    string  `yaml:"website" json:"website"`
	Source     *string `yaml:"source" json:"source"`
	SourceNote string  `yaml:"source_note" json:"source_note,omitempty"`
}

// Resources are the minimums the project documents (nil = not stated; a
// figure given is in range, 0 included in the refusal, contract §3).
type Resources struct {
	MinMemoryMiB *int `yaml:"min_memory_mib" json:"min_memory_mib,omitempty"`
	MinDiskGiB   *int `yaml:"min_disk_gib" json:"min_disk_gib,omitempty"`
}

// Screenshot is one screenshots entry.
type Screenshot struct {
	File    string `yaml:"file" json:"file"`
	Caption string `yaml:"caption" json:"caption"`
}

// Category is a catalog category: its slug and label.
type Category struct {
	Slug  string `json:"slug"`
	Label string `json:"label"`
}

// Categories are the 16 categories in the Marketplace's order (contract
// §3); a category's rank is its 1-based place here.
var Categories = []Category{
	{"productivity", "Productivity"},
	{"communication", "Communication"},
	{"mail", "Mail"},
	{"storage", "Files & storage"},
	{"media", "Media"},
	{"creative", "Creative tools"},
	{"home-automation", "Home automation"},
	{"ai", "AI"},
	{"finance", "Finance"},
	{"devops", "Developer tools"},
	{"monitoring", "Monitoring"},
	{"networking", "Networking"},
	{"vpn", "VPN"},
	{"remote-access", "Remote access"},
	{"security", "Security"},
	{"public", "Public sites"},
}

// UnknownCategoryRank sorts a slug outside Categories last.
const UnknownCategoryRank = 1000

// CategoryOf returns slug's label and rank. A community template's slug
// outside the list is labelled from the slug (weird-thing → "Weird
// thing") and ranked UnknownCategoryRank.
func CategoryOf(slug string) (label string, rank int) {
	for i, c := range Categories {
		if c.Slug == slug {
			return c.Label, i + 1
		}
	}
	l := strings.ReplaceAll(slug, "-", " ")
	if r, n := utf8.DecodeRuneInString(l); n > 0 && r != utf8.RuneError {
		l = strings.ToUpper(string(r)) + l[n:]
	}
	return l, UnknownCategoryRank
}

// Limits and names (contract §3).
const (
	MaxLogoBytes       = svgsafe.MaxBytes
	MaxScreenshotBytes = 512 << 10
	MaxScreenshots     = 6
	MaxCaptionRunes    = 120
	maxSourceNote      = 200
)

var (
	logoNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}\.svg$`)
	shotNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}\.(png|jpg|webp)$`)
	// httpsURLRe is the templates schema's httpsUrl.
	httpsURLRe = regexp.MustCompile(`^https://[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+(?::[0-9]{1,5})?(?:[/?#][^\s{}<>"\\^` + "`" + `|]*)?$`)
)

// checkHTTPSURL: an absolute https URL with a dotted host, no whitespace,
// credentials or placeholders, at most 512 bytes (the schema's httpsUrl).
func checkHTTPSURL(field, u string) error {
	if len(u) > 512 || !httpsURLRe.MatchString(u) || HasHiddenText(u) {
		return fmt.Errorf("%s %q must be an https:// URL with a host (no credentials, whitespace or placeholders)", field, u)
	}
	return nil
}

// validateCatalog checks the catalog fields' shapes (before any file is
// read): ValidateManifest.
func validateCatalog(m *Manifest) error {
	if err := validateMarkdown("long_description", m.LongDescription); err != nil {
		return err
	}
	if l := m.Links; l != nil {
		if err := checkHTTPSURL("links.website", l.Website); err != nil {
			return err
		}
		if l.Source != nil {
			if err := checkHTTPSURL("links.source", *l.Source); err != nil {
				return err
			}
		}
		// HasHiddenText also refuses a newline (a control character).
		if l.SourceNote != "" && (HasHiddenText(l.SourceNote) || utf8.RuneCountInString(l.SourceNote) > maxSourceNote) {
			return fmt.Errorf("links.source_note must be one line of at most %d characters", maxSourceNote)
		}
	}
	if m.Logo != "" && !logoNameRe.MatchString(m.Logo) {
		return fmt.Errorf("logo: %q must be a file name in the template folder matching %s", m.Logo, logoNameRe)
	}
	if r := m.Resources; r != nil {
		if v := r.MinMemoryMiB; v != nil && (*v < 16 || *v > 1048576) {
			return fmt.Errorf("resources.min_memory_mib %d must be 16–1048576 (leave it out when upstream states none)", *v)
		}
		if v := r.MinDiskGiB; v != nil && (*v < 1 || *v > 65536) {
			return fmt.Errorf("resources.min_disk_gib %d must be 1–65536 (leave it out when upstream states none)", *v)
		}
	}
	if len(m.Screenshots) > MaxScreenshots {
		return fmt.Errorf("screenshots: at most %d entries (got %d)", MaxScreenshots, len(m.Screenshots))
	}
	for i, s := range m.Screenshots {
		if !shotNameRe.MatchString(s.File) {
			return fmt.Errorf("screenshots[%d]: file %q must be a file name in the template folder matching %s", i, s.File, shotNameRe)
		}
		if s.Caption == "" || HasHiddenText(s.Caption) || utf8.RuneCountInString(s.Caption) > MaxCaptionRunes {
			return fmt.Errorf("screenshots[%d]: caption must be one line of 1–%d characters", i, MaxCaptionRunes)
		}
	}
	return nil
}

// readAsset reads name from the template directory dir: a regular file
// (never a symlink, os.Lstat; the opened file must be the one checked), at
// most max bytes.
func readAsset(dir, name string, max int64) ([]byte, error) {
	if dir == "" {
		return nil, errors.New("no template directory")
	}
	p := filepath.Join(dir, name)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: no such file", name)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: unreadable", name)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("over %d KiB", max>>10)
	}
	// O_NONBLOCK: a FIFO swapped in after the Lstat can't block the open
	// (SameFile then refuses it).
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: unreadable", name)
	}
	defer f.Close()
	if fi2, err := f.Stat(); err != nil || !os.SameFile(fi, fi2) {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("%s: unreadable", name)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("over %d KiB", max>>10)
	}
	return b, nil
}

// imageKinds: a screenshot's extension, its leading bytes, content type
// and name. The Hub checks only these (no image decoder; pixel sizes are
// the templates validator's, contract §3).
var imageKinds = map[string]struct {
	match       func([]byte) bool
	ctype, name string
}{
	".png":  {func(b []byte) bool { return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) }, "image/png", "PNG"},
	".jpg":  {func(b []byte) bool { return bytes.HasPrefix(b, []byte("\xff\xd8\xff")) }, "image/jpeg", "JPEG"},
	".webp": {func(b []byte) bool { return len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP" }, "image/webp", "WebP"},
}

// CatalogPath is the catalog asset routes' prefix (contract §11.7).
const CatalogPath = "/api/catalog/"

// loadCatalog fills t's catalog fields: the category's label and rank,
// routerless, and the logo and screenshots, read once from t.Path and
// checked (the logo with svgsafe.Check, a screenshot by its size and
// leading bytes). Fails closed: a file that doesn't pass refuses the
// template.
func loadCatalog(t *Template) error {
	m := &t.Manifest
	t.CategoryLabel, t.CategoryRank = CategoryOf(m.Category)
	t.Routerless = m.Routerless()
	if m.Logo != "" {
		b, err := readAsset(t.Path, m.Logo, MaxLogoBytes)
		if err != nil {
			return fmt.Errorf("logo: %w", err)
		}
		if err := svgsafe.Check(b); err != nil {
			return fmt.Errorf("logo: %w", err)
		}
		t.logoSVG = b
		t.LogoURL = CatalogPath + t.ID + "/logo.svg"
	}
	for i, s := range m.Screenshots {
		b, err := readAsset(t.Path, s.File, MaxScreenshotBytes)
		if err != nil {
			return fmt.Errorf("screenshots[%d]: %w", i, err)
		}
		k := imageKinds[filepath.Ext(s.File)]
		if k.match == nil || !k.match(b) {
			return fmt.Errorf("screenshots[%d]: not a %s", i, k.name)
		}
		t.shots = append(t.shots, b)
		t.shotTypes = append(t.shotTypes, k.ctype)
		t.ScreenshotURLs = append(t.ScreenshotURLs, fmt.Sprintf("%s%s/screenshots/%d", CatalogPath, t.ID, i))
	}
	return nil
}

// LogoSVG is the template's logo as read and checked at load (nil
// without one). Shared: the caller must not modify it.
func (t *Template) LogoSVG() []byte { return t.logoSVG }

// Screenshot is screenshot n as read and checked at load, and its content
// type. Shared: the caller must not modify it.
func (t *Template) Screenshot(n int) (data []byte, contentType string, ok bool) {
	if n < 0 || n >= len(t.shots) {
		return nil, "", false
	}
	return t.shots[n], t.shotTypes[n], true
}
