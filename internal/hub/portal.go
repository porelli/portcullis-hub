package hub

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/publish"
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
	// Note is the plain text of the first Markdown paragraph of the
	// template's auth.notes (≤ 300 runes, else "No web page.") for
	// router-less instances (contract §10); always present then, and only
	// when URLs is empty. NoteHTML is that paragraph rendered and
	// sanitised like the Hub's notes_html (internal/notes).
	Note     string `json:"note,omitempty"`
	NoteHTML string `json:"note_html,omitempty"`
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

// portalLocked is portalWithLocked under the policy document last
// written (gatePolicy). Caller holds h.mu (read).
func (h *Hub) portalLocked() PortalDocument {
	return h.portalWithLocked(h.gatePolicy.Load())
}

// portalWithLocked lists enabled instances whose template is present (an
// instance with a missing template has no name/URL to show). An instance
// whose routed hosts group-gate denies under gate (gateDenies) carries
// access_group DenyGroup, so the portal hides it (contract §10); gate nil
// (no policy written yet): no such check. Caller holds h.mu (read).
func (h *Hub) portalWithLocked(gate *policy.Document) PortalDocument {
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
			AuthMethod: m.Auth.Method}
		_, admins := h.instanceGroupsLocked(t)
		a.AdminGroup = admins
		a.AccessGroup = h.portalAccessGroupLocked(t)
		if gate != nil && gateDenies(gate, h.routedHostsLocked(t)) {
			a.AccessGroup = policy.DenyGroup
		}
		// Router-less instances (contract §3, §10): URLs empty, note present.
		if m.Routerless() {
			a.URLs = []templates.AppURL{}
			a.Note, a.NoteHTML = portalNote(&m.Auth)
		} else {
			a.URLs = append([]templates.AppURL{}, m.URLs...)
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

// portalAccessGroupLocked is the access_group t's portal entry carries:
// its access group (instanceGroupsLocked) whenever it has one — also when
// group-gate doesn't enforce it (auth.group_access false, or the app's
// own login only, e.g. Firefox Sync's open host), so only its members see
// the tile, administrators included (contract §10); "" (any signed-in
// person) only when the manifest has no access group. My apps (MyApps)
// lists an app by the same group (gateOpenLocked). Display only: what
// group-gate enforces is the policy file's. Caller holds h.mu (read).
func (h *Hub) portalAccessGroupLocked(t *templates.Template) string {
	users, _ := h.instanceGroupsLocked(t)
	return users
}

// routedHostsLocked is the hostnames t's routers serve that the policy
// publishes (core hostnames and invalid names left out, as writePolicy
// does). Caller holds h.mu (read).
func (h *Hub) routedHostsLocked(t *templates.Template) []string {
	return slices.Sorted(maps.Keys(hostSet(slices.Collect(maps.Values(t.Hosts)), policy.CoreHosts(h.cfg.Domain))))
}

// gateDenies reports whether group-gate denies every request to some of
// hosts under the policy document gate: the host is published with
// DenyGroup (no known config, an unpublished template or one that can't
// be combined: policy.Build), or its template — its own pick, else the
// default — isn't published.
func gateDenies(gate *policy.Document, hosts []string) bool {
	for _, host := range hosts {
		if gate.Groups[host] == policy.DenyGroup {
			return true
		}
		tid, ok := gate.Hosts[host]
		if !ok {
			tid = gate.Default
		}
		if _, published := gate.Templates[tid]; !published {
			return true
		}
	}
	return false
}

// gateOpen is My apps' decision (MyApps): whether group-gate, under the
// policy document last written (gate), lets user (in m) open enabled
// instance t, and whether that needs the VPN. Failing closed: no policy
// written yet, a person m doesn't know, a denied host (gateDenies), a
// required group they aren't in or whose membership ended (expired:
// group-gate denies it) — for every routed host. A routed instance with
// no published host opens nowhere. A router-less instance (no routes,
// contract §3) opens by its portal access group alone, and every app
// needs that group too (portalAccessGroupLocked). vpnOnly: some host
// is VPN-only (the policy's vpn.hosts): listed, with a badge. Caller
// holds h.mu (read).
func (h *Hub) gateOpenLocked(gate *policy.Document, t *templates.Template, m *directory.Membership, user string) (open, vpnOnly bool) {
	groups, known := m.Users[user]
	if gate == nil || !known || !t.Enabled {
		return false, false
	}
	member := func(g string) bool {
		_, in := groups[g]
		return g == "" || (in && !m.Expired[user][g])
	}
	// The portal's group too (portalAccessGroupLocked): an app whose
	// hosts group-gate leaves open is still listed only for its members.
	if !member(h.portalAccessGroupLocked(t)) {
		return false, false
	}
	if t.Manifest.Routerless() {
		return true, false
	}
	hosts := h.routedHostsLocked(t)
	if len(hosts) == 0 || gateDenies(gate, hosts) {
		return false, false
	}
	for _, host := range hosts {
		if !member(gate.Groups[host]) {
			return false, false
		}
		if _, ok := gate.VPN.Hosts[host]; ok {
			vpnOnly = true
		}
	}
	return true, vpnOnly
}

// Portal returns the current portal document.
func (h *Hub) Portal() PortalDocument {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.portalLocked()
}

func (h *Hub) portalPath() string { return filepath.Join(h.cfg.DataDir, "portal-apps.json") }

// publishPortal publishes the landing portal's app list (contract §10).
func (h *Hub) publishPortal(doc PortalDocument) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return h.publish(publish.PortalApps, append(b, '\n'))
}

// portalNoteMax caps a router-less entry's note (runes).
const portalNoteMax = 300

// portalNoNote is a router-less entry's note when auth.notes gives none.
const portalNoNote = "No web page."

// portalNote is a router-less entry's portal note (contract §10, B-M6 /
// C-M4) and its HTML: the first Markdown paragraph of auth.notes as plain
// text (inline markup removed, whitespace collapsed) and as sanitised
// HTML, both rendered once when the template was built (Auth.NoteText /
// NoteHTML, never under h.mu), when the text is at most portalNoteMax
// runes, else "No web page." — never empty (group-gate renders the card).
// The rest of auth.notes is for operators.
func portalNote(a *templates.Auth) (string, string) {
	if a.NoteText == "" || utf8.RuneCountInString(a.NoteText) > portalNoteMax {
		return portalNoNote, "<p>" + portalNoNote + "</p>"
	}
	return a.NoteText, a.NoteHTML
}
