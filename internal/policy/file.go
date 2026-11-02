package policy

import (
	"encoding/json"
	"log"
	"sort"

	"github.com/portcullis/hub/internal/fsutil"
)

// FileVersion is the policy-file format version (contract §4). Version 5
// keys policies, groups and path groups by full hostname instead of subdomain,
// and adds extra_domains. group-gate serves only version 5: the Hub and core
// must be upgraded together.
const FileVersion = 5

// coreSubdomains are the core subdomain labels (group-gate-map.conf uses
// `<sub>=<group>` entries; contract §4).
var coreSubdomains = []string{"auth", "traefik", "hub", "directory", "enroll", "metrics", "people"}

// CoreSubdomains returns the core subdomain labels as a set.
func CoreSubdomains() map[string]bool {
	set := make(map[string]bool, len(coreSubdomains))
	for _, s := range coreSubdomains {
		set[s] = true
	}
	return set
}

// CoreHosts returns the full hostnames owned by the core stack
// (group-gate-map.conf); templates may never publish policies, groups or path
// groups for them (contract §4).
func CoreHosts(mainDomain string) map[string]bool {
	hosts := map[string]bool{mainDomain: true}
	for _, sub := range coreSubdomains {
		hosts[sub+"."+mainDomain] = true
	}
	return hosts
}

// PathGroup requires Group for request paths under Prefix.
type PathGroup struct {
	Prefix string `json:"prefix"`
	Group  string `json:"group"`
}

// Expiring is a membership that ends at At (manual-group expiry or an
// "added" exception with an end date). Usernames are lowercase; timestamps
// are RFC 3339 in UTC. The Hub writes at most one entry per (user, group)
// pair: the earliest At when multiple expiries exist.
type Expiring struct {
	User  string `json:"user"`
	Group string `json:"group"`
	At    string `json:"at"` // RFC 3339 UTC timestamp
}

// Document is the JSON written for group-gate.
type Document struct {
	Version int        `json:"version"`
	Default AuthPolicy `json:"default"`
	// ExtraDomains lists enrolled domains (contract §12); extra-domain hosts
	// lie on one of them. group-gate uses this to build step-up URLs. Version 5+.
	ExtraDomains []string               `json:"extra_domains"`
	Policies     map[string]AuthPolicy  `json:"policies"`
	Groups       map[string]string      `json:"groups"`
	PathGroups   map[string][]PathGroup `json:"path_groups"`
	// PublicPaths is, per hostname, the public exception core's public
	// guard enforces on the Hub's public router (forward-auth and the group
	// check don't run there). Listed share tokens stay "{token}".
	PublicPaths map[string]PublicEntry `json:"public_paths"`
	// Expiring lists pending membership expiries for group-gate to enforce
	// strictly, even when the Hub is down. Version 4+.
	Expiring []Expiring `json:"expiring"`
}

// PublicPath is one pattern core's public guard allows: Match is "prefix"
// (segment boundary), "exact" or "static" (static files below Path); a
// "{token}" segment matches one segment TokenPattern accepts.
type PublicPath struct {
	Path  string `json:"path"`
	Match string `json:"match"`
}

// PublicEntry is a subdomain's public exception for core's public guard:
// what is public, and which credentials it must refuse there.
type PublicEntry struct {
	Paths             []PublicPath `json:"paths"`
	TokenPattern      string       `json:"token_pattern,omitempty"`
	StaticExtensions  []string     `json:"static_extensions"`
	CredentialHeaders []string     `json:"credential_headers"`
	CredentialCookies []string     `json:"credential_cookies"`
	CredentialQuery   []string     `json:"credential_query"`
}

// DenyGroup is published as the required group of subdomains the Hub knows
// are routed but cannot attribute a config to. group-gate matches groups
// exactly and no user is a member of this group, so every request is
// denied. Never create an LLDAP group with this name.
const DenyGroup = "__portcullis_deny__"

// App is the per-instance input to Build (contract v5).
type App struct {
	ID      string
	Enabled bool
	// Deny marks an app whose hosts are known (e.g. from running
	// containers' labels) but whose config is not: its hosts get
	// DenyGroup unless an enabled app with a known config claims them.
	Deny        bool
	Hosts       map[string]string // hostname → hostname (keyed by host for iteration)
	GroupAccess bool
	AccessGroup string
	AdminGroup  string
	AdminPaths  []string
	// PublicHosts / Public: the app's public exception, when a public
	// router exists.
	PublicHosts map[string]string
	Public      *PublicEntry
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

// Build assembles the policy document (contract v5, keyed by hostname).
//
// group-gate looks policies, groups and path groups up by full hostname, so
// only enabled instances publish entries, and only under the hostnames they
// route. Core hostnames are never published (they come from
// group-gate-map.conf, §4).
//
// The Hub refuses to enable instances with hostname collisions; if it happens
// anyway (state edited by hand, compose changed on disk) the writer stays
// deterministic and fails towards the stricter outcome: the stricter effective
// policy wins, path groups are merged, and the access group of the lowest
// instance ID wins. Each collision is logged.
//
// mainDomain names the core hosts (CoreHosts): any app, public or deny host
// equal to one is skipped and logged. extraDomains is the list of enrolled
// domains (§12) for extra_domains.
func Build(apps []App, perApp map[string]AuthPolicy, def AuthPolicy, mainDomain string, extraDomains []string) Document {
	doc := Document{
		Version:      FileVersion,
		Default:      def,
		ExtraDomains: append([]string{}, extraDomains...),
		Policies:     map[string]AuthPolicy{},
		Groups:       map[string]string{},
		PathGroups:   map[string][]PathGroup{},
		PublicPaths:  map[string]PublicEntry{},
		Expiring:     []Expiring{},
	}
	sort.Strings(doc.ExtraDomains)
	sorted := append([]App(nil), apps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	core := CoreHosts(mainDomain)
	isCore := func(a App, host, kind string) bool {
		if core[host] {
			log.Printf("auth-policy: app %s routes core hostname %q (%s) — ignored", a.ID, host, kind)
			return true
		}
		return false
	}
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
		for host := range a.Hosts {
			if isCore(a, host, "host") {
				continue
			}
			claims[host] = append(claims[host], claim{a.ID, p, override})

			// Only apps that opt into group-based access get a required
			// group; for the others access_group is informational.
			if a.GroupAccess && a.AccessGroup != "" {
				if owner, taken := groupOwner[host]; taken {
					if doc.Groups[host] != a.AccessGroup {
						log.Printf("auth-policy: hostname %q is routed by %s and %s — keeping group %q of %s", host, owner, a.ID, doc.Groups[host], owner)
					}
				} else {
					groupOwner[host] = a.ID
					doc.Groups[host] = a.AccessGroup
				}
			}
			if a.AdminGroup != "" && len(a.AdminPaths) > 0 {
				have := map[string]string{}
				for _, pg := range doc.PathGroups[host] {
					have[pg.Prefix] = pg.Group
				}
				for _, prefix := range a.AdminPaths {
					if g, ok := have[prefix]; ok {
						if g != a.AdminGroup {
							log.Printf("auth-policy: hostname %q path %q claimed with groups %q and %q — keeping %q", host, prefix, g, a.AdminGroup, g)
						}
						continue
					}
					have[prefix] = a.AdminGroup
					doc.PathGroups[host] = append(doc.PathGroups[host], PathGroup{Prefix: prefix, Group: a.AdminGroup})
				}
				sort.Slice(doc.PathGroups[host], func(i, j int) bool {
					return doc.PathGroups[host][i].Prefix < doc.PathGroups[host][j].Prefix
				})
			}
		}
	}
	for _, a := range sorted {
		if !a.Enabled || a.Deny || a.Public == nil {
			continue
		}
		for host := range a.PublicHosts {
			if isCore(a, host, "public host") {
				continue
			}
			if _, routed := a.Hosts[host]; !routed {
				// A public exception only ever opens a host the app routes.
				log.Printf("auth-policy: app %s has a public exception for %q, which is not one of its hosts — ignored", a.ID, host)
				continue
			}
			if _, taken := doc.PublicPaths[host]; taken {
				// Only one public router per host can exist (one owner
				// per hostname); keep the lowest instance ID's.
				log.Printf("auth-policy: hostname %q has public exceptions from several apps — keeping the first (%s ignored)", host, a.ID)
				continue
			}
			doc.PublicPaths[host] = *a.Public
		}
	}
	for _, a := range sorted {
		if !a.Deny {
			continue
		}
		for host := range a.Hosts {
			if isCore(a, host, "deny host") {
				continue
			}
			if _, claimed := claims[host]; claimed {
				continue
			}
			if doc.Groups[host] != DenyGroup {
				log.Printf("auth-policy: DENYING ALL ACCESS to %q (app %s has running containers but no known config)", host, a.ID)
			}
			doc.Groups[host] = DenyGroup
		}
	}
	for host, cs := range claims {
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
			log.Printf("auth-policy: hostname %q is routed by %v — publishing the strictest policy (of %s)", host, ids, best.app)
		}
		// Apps without an override inherit "default" in group-gate already.
		if anyOverride {
			doc.Policies[host] = best.policy
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
