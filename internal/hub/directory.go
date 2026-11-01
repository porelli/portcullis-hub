package hub

import "github.com/portcullis/hub/internal/directory"

// DirectoryApps lists every template's groups for the Users page
// (group suggestions and "used by").
func (h *Hub) DirectoryApps() []directory.App {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]directory.App, 0, len(h.templates))
	for i := range h.templates {
		t := &h.templates[i]
		out = append(out, directory.App{ID: t.ID, Name: t.Manifest.Name, Enabled: t.Enabled,
			AccessGroup: t.Manifest.Auth.AccessGroup, AdminGroup: t.Manifest.Auth.AdminGroup})
	}
	return out
}
