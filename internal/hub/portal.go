package hub

import (
	"encoding/json"
	"path/filepath"
	"sort"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/templates"
)

// PortalVersion is the portal-apps.json format version (contract §10).
const PortalVersion = 1

// PortalApp is one enabled app as the landing portal shows it.
type PortalApp struct {
	ID          string             `json:"id"`
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
}

// PortalDocument is portal-apps.json.
type PortalDocument struct {
	Version int         `json:"version"`
	Apps    []PortalApp `json:"apps"`
}

// portalLocked lists enabled apps whose template is present (an app with
// a missing template has no name/URL to show). Caller holds h.mu (read).
func (h *Hub) portalLocked() PortalDocument {
	doc := PortalDocument{Version: PortalVersion, Apps: []PortalApp{}}
	for i := range h.templates {
		t := &h.templates[i]
		if !t.Enabled {
			continue
		}
		m := t.Manifest
		a := PortalApp{ID: t.ID, Name: m.Name, Description: m.Description, Icon: m.Icon, Category: m.Category,
			URLs: append([]templates.AppURL{}, m.URLs...), AuthMethod: m.Auth.Method, AdminGroup: m.Auth.AdminGroup}
		if h.accessLocked(t).groupAccess(t) {
			a.AccessGroup = m.Auth.AccessGroup
		}
		doc.Apps = append(doc.Apps, a)
	}
	sort.Slice(doc.Apps, func(i, j int) bool { return doc.Apps[i].ID < doc.Apps[j].ID })
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
