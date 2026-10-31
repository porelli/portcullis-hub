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

// DenyGroup is published as the required group of subdomains the Hub knows
// are routed but cannot attribute a config to. group-gate matches groups
// exactly and no user is a member of this group, so every request is
// denied. Never create an LLDAP group with this name.
const DenyGroup = "__portcullis_deny__"

// App is the per-template input to Build.
type App struct {
	ID      string
	Enabled bool
	// Deny marks an app whose subdomains are known (e.g. from running
	// containers' labels) but whose config is not: its subdomains get
	// DenyGroup unless an enabled app with a known config claims them.
	Deny        bool
	Subdomains  []string
	GroupAccess bool
	AccessGroup string
	AdminGroup  string
	AdminPaths  []string
}

// Stricter reports whether a is strictly stricter than b: higher LoA first,
// then "all" over "any"; at equal op, more required factors ("all") or fewer
// accepted alternatives ("any"/single). A non-public policy is always
// stricter than a public one.
func Stricter(a, b AuthPolicy) bool {
	if la, lb := LoA(a), LoA(b); la != lb {
		return la > lb
	}
	aAll, bAll := a.Op == "all" && len(a.Factors) > 1, b.Op == "all" && len(b.Factors) > 1
	if aAll != bAll {
		return aAll
	}
	if aAll {
		return len(a.Factors) > len(b.Factors)
	}
	return len(a.Factors) < len(b.Factors) && len(a.Factors) > 0
}

// Build assembles the policy document.
//
// group-gate looks policies, groups and path groups up by request subdomain
// only, so only enabled templates publish entries, and only under the
// subdomains they route (never under their template ID: an ID can equal
// another app's subdomain). Core subdomains are never published.
//
// The Hub refuses to enable two templates that route the same subdomain; if
// it happens anyway (state edited by hand, compose changed on disk) the
// writer stays deterministic and fails towards the stricter outcome: the
// stricter effective policy wins, path groups are merged, and the access
// group of the lowest template ID wins. Each collision is logged.
func Build(apps []App, perApp map[string]AuthPolicy, def AuthPolicy) Document {
	doc := Document{
		Version:    FileVersion,
		Default:    def,
		Policies:   map[string]AuthPolicy{},
		Groups:     map[string]string{},
		PathGroups: map[string][]PathGroup{},
	}
	sorted := append([]App(nil), apps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	type claim struct {
		app      string
		policy   AuthPolicy
		override bool
	}
	claims := map[string][]claim{}
	groupOwner := map[string]string{}
	for _, a := range sorted {
		if !a.Enabled || a.Deny {
			continue
		}
		p, override := perApp[a.ID]
		if !override {
			p = def
		}
		for _, sub := range a.Subdomains {
			if CoreSubdomains[sub] {
				log.Printf("auth-policy: template %s routes core subdomain %q — ignored", a.ID, sub)
				continue
			}
			claims[sub] = append(claims[sub], claim{a.ID, p, override})

			// Only apps that opt into group-based access get a required
			// group; for the others access_group is informational.
			if a.GroupAccess && a.AccessGroup != "" {
				if owner, taken := groupOwner[sub]; taken {
					if doc.Groups[sub] != a.AccessGroup {
						log.Printf("auth-policy: subdomain %q is routed by %s and %s — keeping group %q of %s", sub, owner, a.ID, doc.Groups[sub], owner)
					}
				} else {
					groupOwner[sub] = a.ID
					doc.Groups[sub] = a.AccessGroup
				}
			}
			if a.AdminGroup != "" && len(a.AdminPaths) > 0 {
				have := map[string]string{}
				for _, pg := range doc.PathGroups[sub] {
					have[pg.Prefix] = pg.Group
				}
				for _, prefix := range a.AdminPaths {
					if g, ok := have[prefix]; ok {
						if g != a.AdminGroup {
							log.Printf("auth-policy: subdomain %q path %q claimed with groups %q and %q — keeping %q", sub, prefix, g, a.AdminGroup, g)
						}
						continue
					}
					have[prefix] = a.AdminGroup
					doc.PathGroups[sub] = append(doc.PathGroups[sub], PathGroup{Prefix: prefix, Group: a.AdminGroup})
				}
				sort.Slice(doc.PathGroups[sub], func(i, j int) bool {
					return doc.PathGroups[sub][i].Prefix < doc.PathGroups[sub][j].Prefix
				})
			}
		}
	}
	for _, a := range sorted {
		if !a.Deny {
			continue
		}
		for _, sub := range a.Subdomains {
			if CoreSubdomains[sub] {
				continue
			}
			if _, claimed := claims[sub]; claimed {
				continue
			}
			if doc.Groups[sub] != DenyGroup {
				log.Printf("auth-policy: DENYING ALL ACCESS to %q (app %s has running containers but no known config)", sub, a.ID)
			}
			doc.Groups[sub] = DenyGroup
		}
	}
	for sub, cs := range claims {
		anyOverride := false
		best := cs[0]
		for _, c := range cs {
			anyOverride = anyOverride || c.override
			if Stricter(c.policy, best.policy) {
				best = c
			}
		}
		if len(cs) > 1 {
			ids := make([]string, len(cs))
			for i, c := range cs {
				ids[i] = c.app
			}
			log.Printf("auth-policy: subdomain %q is routed by %v — publishing the strictest policy (of %s)", sub, ids, best.app)
		}
		// Apps without an override inherit "default" in group-gate already.
		if anyOverride {
			doc.Policies[sub] = best.policy
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
