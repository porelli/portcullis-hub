package hub

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/templates"
)

// PortalVersion is the portal-apps.json format version (contract §10).
const PortalVersion = 1

// PortalApp is one enabled app as the landing portal shows it.
type PortalApp struct {
	// ID is the instance id, Template the template id (both the template
	// id for the default instance).
	ID          string             `json:"id"`
	Template    string             `json:"template"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Icon        string             `json:"icon"`
	Category    string             `json:"category"`
	URLs        []templates.AppURL `json:"urls"`
	AuthMethod  string             `json:"auth_method"`
	// AccessGroup is the LLDAP group group-gate requires ("" = any
	// signed-in user); AdminGroup is informational.
	AccessGroup string `json:"access_group"`
	AdminGroup  string `json:"admin_group"`
	// Note is the first paragraph of the template's auth.notes (≤ 300
	// runes, else "No web page.") for router-less instances (contract
	// §10); always present then, and only when URLs is empty.
	Note string `json:"note,omitempty"`
}

// PortalDocument is portal-apps.json (contract §10).
type PortalDocument struct {
	Version int         `json:"version"`
	Apps    []PortalApp `json:"apps"`
	// Domains lists, sorted, every enrolled domain on which at least one
	// listed instance has a hostname (contract §10; still format version 1).
	// Always an array, never null.
	Domains []string `json:"domains"`
}

// portalLocked lists enabled instances whose template is present (an instance
// with a missing template has no name/URL to show). Caller holds h.mu (read).
func (h *Hub) portalLocked() PortalDocument {
	doc := PortalDocument{Version: PortalVersion, Apps: []PortalApp{}, Domains: []string{}}
	domainsUsed := map[string]bool{}
	enrolled := h.enrolledLocked()
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		m := t.Manifest
		a := PortalApp{ID: t.ID, Template: t.TemplateID, Name: instanceName(t), Description: m.Description, Icon: m.Icon, Category: m.Category,
			AuthMethod: m.Auth.Method, AdminGroup: m.Auth.AdminGroup}
		// Router-less instances (contract §3, §10): URLs empty, note present.
		if m.Routerless() {
			a.URLs = []templates.AppURL{}
			a.Note = portalNote(m.Auth.Notes)
		} else {
			a.URLs = append([]templates.AppURL{}, m.URLs...)
		}
		if h.accessLocked(t).groupAccess(t) {
			a.AccessGroup = m.Auth.AccessGroup
		}
		doc.Apps = append(doc.Apps, a)
		// Track which enrolled domains have hosts in use (contract §10).
		for _, host := range t.Hosts {
			if d, ok := extraDomainOf(host, enrolled); ok {
				domainsUsed[d.Name] = true
			}
		}
	}
	sort.Slice(doc.Apps, func(i, j int) bool { return doc.Apps[i].ID < doc.Apps[j].ID })
	for d := range domainsUsed {
		doc.Domains = append(doc.Domains, d)
	}
	sort.Strings(doc.Domains)
	return doc
}

// Portal returns the current portal document.
func (h *Hub) Portal() PortalDocument {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.portalLocked()
}

func (h *Hub) portalPath() string { return filepath.Join(h.cfg.DataDir, "portal-apps.json") }

func writePortal(path string, doc PortalDocument) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(b, '\n'), 0644)
}

// instanceName is the template's name, followed by " (<instance-id>)" for
// instances other than the default one (contract §10).
func instanceName(t *templates.Template) string {
	if t.IsDefault() {
		return t.Manifest.Name
	}
	return t.Manifest.Name + " (" + t.ID + ")"
}

// portalNoteMax caps a router-less entry's note (runes).
const portalNoteMax = 300

// portalNoNote is a router-less entry's note when auth.notes gives none.
const portalNoNote = "No web page."

// portalNote is a router-less entry's portal note (contract §10, B-M6 /
// C-M4): the first paragraph of auth.notes (up to the first blank line;
// its lines trimmed and joined with spaces) when it is at most
// portalNoteMax runes, else "No web page." — never empty (group-gate
// renders the card). The rest of auth.notes is for operators.
func portalNote(notes string) string {
	var lines []string
	for _, l := range strings.Split(notes, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			break
		}
		lines = append(lines, l)
	}
	p := strings.Join(lines, " ")
	if p == "" || utf8.RuneCountInString(p) > portalNoteMax {
		return portalNoNote
	}
	return p
}
