package policy

import (
	"encoding/json"
	"log"
	"sort"

	"github.com/portcullis/hub/internal/fsutil"
)

// FileVersion is the policy-file format version (contract §4).
const FileVersion = 2

// CoreSubdomains are owned by the core stack (group-gate-map.conf); templates
// may never publish policies, groups or path groups for them.
var CoreSubdomains = map[string]bool{"auth": true, "traefik": true, "hub": true, "directory": true, "enroll": true}

// PathGroup requires Group for request paths under Prefix.
type PathGroup struct {
	Prefix string `json:"prefix"`
	Group  string `json:"group"`
}

// Document is the JSON written for group-gate.
type Document struct {
	Version    int                    `json:"version"`
	Default    AuthPolicy             `json:"default"`
	Policies   map[string]AuthPolicy  `json:"policies"`
	Groups     map[string]string      `json:"groups"`
	PathGroups map[string][]PathGroup `json:"path_groups"`
}

// App is the per-template input to Build: only enabled apps should be passed
// with Enabled=true; disabled ones publish nothing but their ID-keyed policy.
type App struct {
	ID          string
	Enabled     bool
	Subdomains  []string
	GroupAccess bool
	AccessGroup string
	AdminGroup  string
	AdminPaths  []string
}

// Build assembles the policy document.
//
// group-gate keys everything by request subdomain while the Hub keys
// policies by template ID; the two differ for many apps (gitlab → git, …).
// So every per-app policy is written under the template ID *and* under each
// subdomain the (enabled) template routes. Core subdomains are never
// published.
func Build(apps []App, perApp map[string]AuthPolicy, def AuthPolicy) Document {
	doc := Document{
		Version:    FileVersion,
		Default:    def,
		Policies:   make(map[string]AuthPolicy, len(perApp)),
		Groups:     map[string]string{},
		PathGroups: map[string][]PathGroup{},
	}
	for id, p := range perApp {
		if !CoreSubdomains[id] {
			doc.Policies[id] = p
		}
	}
	// Deterministic order so collisions between templates resolve the same
	// way every time.
	sorted := append([]App(nil), apps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, a := range sorted {
		if !a.Enabled {
			continue
		}
		var subs []string
		for _, sub := range a.Subdomains {
			if CoreSubdomains[sub] {
				log.Printf("auth-policy: template %s routes core subdomain %q — ignored for policies/groups", a.ID, sub)
				continue
			}
			subs = append(subs, sub)
		}
		if p, ok := perApp[a.ID]; ok {
			for _, sub := range subs {
				if _, taken := doc.Policies[sub]; !taken {
					doc.Policies[sub] = p
				}
			}
		}
		// Only apps that opt into group-based access get a required group;
		// for the others access_group is informational.
		if a.GroupAccess && a.AccessGroup != "" {
			for _, sub := range subs {
				doc.Groups[sub] = a.AccessGroup
			}
		}
		if a.AdminGroup != "" && len(a.AdminPaths) > 0 {
			for _, sub := range subs {
				seen := map[string]bool{}
				for _, pg := range doc.PathGroups[sub] {
					seen[pg.Prefix] = true
				}
				for _, prefix := range a.AdminPaths {
					if seen[prefix] {
						continue
					}
					seen[prefix] = true
					doc.PathGroups[sub] = append(doc.PathGroups[sub], PathGroup{Prefix: prefix, Group: a.AdminGroup})
				}
				sort.Slice(doc.PathGroups[sub], func(i, j int) bool {
					return doc.PathGroups[sub][i].Prefix < doc.PathGroups[sub][j].Prefix
				})
			}
		}
	}
	return doc
}

// Write serialises doc and writes it atomically (temp file + rename) so
// group-gate never reads a partial document. 0644: group-gate reads it from
// a read-only mount as another user.
func Write(path string, doc Document) error {
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(payload, '\n'), 0644)
}
