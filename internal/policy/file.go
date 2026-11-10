package policy

import (
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/signin"
)

// FileVersion is the policy-file format version (contract §4). Version 6
// replaces v5's factor policies with sign-in templates (§8.1): methods,
// templates, default, hosts, core, people and add_stronger. group-gate
// serves only version 6: the Hub and core must be upgraded together.
const FileVersion = 6

// CorePages are the core page keys group-gate gates, each published under
// its full hostname in core (§8.1 "Core pages"): portal is the main
// domain, the others <key>.<main domain>. auth and mcp take no template.
var CorePages = []string{"portal", "hub", "people", "directory", "enroll", "metrics", "traefik"}

// CorePageHost is core page key's hostname.
func CorePageHost(key, mainDomain string) string {
	if key == "portal" {
		return mainDomain
	}
	return key + "." + mainDomain
}

// coreSubdomains are the core subdomain labels (group-gate-map.conf uses
// `<sub>=<group>` entries; contract §4).
var coreSubdomains = []string{"auth", "traefik", "hub", "directory", "enroll", "metrics", "people", "mcp"}

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

// Document is the JSON written for group-gate (version 6).
type Document struct {
	Version int `json:"version"`
	// Methods are the switched-on method ids, sorted.
	Methods []string `json:"methods"`
	// Templates: template id → compiled rule, enabled templates only (plus
	// synthetic collision.<n> ones).
	Templates map[string]signin.Node `json:"templates"`
	Default   string                 `json:"default"`
	// Hosts: app hostname → template id, only for instances with their
	// own pick; Core: every gated core hostname → template id.
	Hosts map[string]string `json:"hosts"`
	Core  map[string]string `json:"core"`
	// People: lowercase user → the switched-on methods they have set up
	// (page text only, never an access decision).
	People      map[string][]string `json:"people"`
	AddStronger bool                `json:"add_stronger"`
	// ExtraDomains lists enrolled domains (contract §12); extra-domain hosts
	// lie on one of them. group-gate uses this to build step-up URLs.
	ExtraDomains []string               `json:"extra_domains"`
	Groups       map[string]string      `json:"groups"`
	PathGroups   map[string][]PathGroup `json:"path_groups"`
	// PublicPaths is, per hostname, the public exception core's public
	// guard enforces on the Hub's public router (forward-auth and the group
	// check don't run there). Listed share tokens stay "{token}".
	PublicPaths map[string]PublicEntry `json:"public_paths"`
	// Expiring lists pending membership expiries for group-gate to enforce
	// strictly, even when the Hub is down.
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
	// Template is the instance's own sign-in template pick; "" = the
	// default (and for apps that take no template).
	Template string
}

// BuildInput is what Build publishes: the apps, the default and core
// picks, the compiled enabled templates, the switched-on methods, the
// people's set-up methods and the add-stronger switch.
type BuildInput struct {
	Apps    []App
	Default string
	// Core: core page key (CorePages) → template id, "" = the default.
	Core         map[string]string
	Templates    map[string]signin.Node
	Methods      []signin.Method
	People       map[string][]signin.Method
	AddStronger  bool
	MainDomain   string
	ExtraDomains []string
}

// Build assembles the policy document (contract §4 v6, keyed by hostname).
//
// group-gate looks templates, groups and path groups up by full hostname, so
// only enabled instances publish entries, and only under the hostnames they
// route. Core hostnames are never published for apps (their groups come
// from group-gate-map.conf, their templates from core).
//
// The Hub refuses to enable instances with hostname collisions; if it happens
// anyway (state edited by hand, compose changed on disk) the writer stays
// deterministic and fails towards the stricter outcome: the template that
// implies the other wins, or, when neither does, a synthetic
// collision.<n> = all of both (never weaker); path groups are merged, and the
// access group of the lowest instance ID wins. Each collision is logged. A
// host whose template can't be published (not among in.Templates, or a
// collision rule outside the readers' limits) is denied (DenyGroup).
func Build(in BuildInput) Document {
	mainDomain := in.MainDomain
	doc := Document{
		Version:      FileVersion,
		Methods:      []string{},
		Templates:    map[string]signin.Node{},
		Default:      in.Default,
		Hosts:        map[string]string{},
		Core:         map[string]string{},
		People:       map[string][]string{},
		AddStronger:  in.AddStronger,
		ExtraDomains: append([]string{}, in.ExtraDomains...),
		Groups:       map[string]string{},
		PathGroups:   map[string][]PathGroup{},
		PublicPaths:  map[string]PublicEntry{},
		Expiring:     []Expiring{},
	}
	sort.Strings(doc.ExtraDomains)
	for _, m := range in.Methods {
		if !slices.Contains(doc.Methods, string(m)) {
			doc.Methods = append(doc.Methods, string(m))
		}
	}
	sort.Strings(doc.Methods)
	for id, n := range in.Templates {
		doc.Templates[id] = n
	}
	for user, ms := range in.People {
		out := []string{}
		for _, m := range ms {
			if slices.Contains(in.Methods, m) && !slices.Contains(out, string(m)) {
				out = append(out, string(m))
			}
		}
		sort.Strings(out)
		doc.People[strings.ToLower(user)] = out
	}
	if _, ok := doc.Templates[in.Default]; !ok {
		log.Printf("auth-policy: the default template %q isn't published — group-gate denies every request", in.Default)
	}
	for _, k := range CorePages {
		id := in.Core[k]
		if id == "" {
			id = in.Default
		}
		if _, ok := doc.Templates[id]; !ok {
			// A missing core host is denied by group-gate (fail closed).
			log.Printf("auth-policy: core page %s: template %q isn't published — left out (denied)", k, id)
			continue
		}
		doc.Core[CorePageHost(k, mainDomain)] = id
	}

	sorted := append([]App(nil), in.Apps...)
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
		template string // effective: "" resolved to the default
		own      bool
	}
	claims := map[string][]claim{}
	groupOwner := map[string]string{}
	for _, a := range sorted {
		if !a.Enabled || a.Deny {
			continue
		}
		tid := a.Template
		if tid == "" {
			tid = in.Default
		}
		for host := range a.Hosts {
			if isCore(a, host, "host") {
				continue
			}
			claims[host] = append(claims[host], claim{a.ID, tid, a.Template != ""})

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
	// Hosts in a fixed order: collision templates are numbered from 1.
	collisions := map[[2]string]string{}
	for _, host := range slices.Sorted(maps.Keys(claims)) {
		cs := claims[host]
		own := false
		best := ""
		ok := true
		for _, c := range cs {
			own = own || c.own
			if _, published := doc.Templates[c.template]; !published {
				log.Printf("auth-policy: hostname %q: template %q of %s isn't published — DENYING ALL ACCESS to it", host, c.template, c.app)
				ok = false
				break
			}
			if best == "" {
				best = c.template
				continue
			}
			if best, ok = stricterOf(doc.Templates, collisions, best, c.template); !ok {
				log.Printf("auth-policy: hostname %q: templates of %v can't be combined within the readers' limits — DENYING ALL ACCESS to it", host, cs)
				break
			}
		}
		if !ok {
			doc.Groups[host] = DenyGroup
			continue
		}
		if len(cs) > 1 {
			ids := make([]string, len(cs))
			for i, c := range cs {
				ids[i] = c.app
			}
			log.Printf("auth-policy: hostname %q is routed by %v — publishing template %q", host, ids, best)
		}
		// Apps without their own pick inherit "default" in group-gate.
		if own || best != in.Default {
			doc.Hosts[host] = best
		}
	}
	return doc
}

// stricterOf is the template id published for a host claimed under
// templates a and b: the one that implies the other (a when they imply
// each other), else a synthetic collision.<n> = all of both, added to
// tmpls (one per pair). false when the synthetic rule is outside the
// readers' limits.
func stricterOf(tmpls map[string]signin.Node, collisions map[[2]string]string, a, b string) (string, bool) {
	if a == b {
		return a, true
	}
	ra, rb := tmpls[a], tmpls[b]
	if signin.Implies(ra, rb) {
		return a, true
	}
	if signin.Implies(rb, ra) {
		return b, true
	}
	key := [2]string{min(a, b), max(a, b)}
	if id, ok := collisions[key]; ok {
		return id, true
	}
	both := signin.Node{Op: signin.OpAll, Items: []signin.Node{ra, rb}}
	if signin.ValidateCompiled(both) != nil {
		// One level less: the "all" groups' items spliced in.
		both = signin.Node{Op: signin.OpAll}
		for _, r := range []signin.Node{ra, rb} {
			if r.Op == signin.OpAll {
				both.Items = append(both.Items, r.Items...)
			} else {
				both.Items = append(both.Items, r)
			}
		}
		if signin.ValidateCompiled(both) != nil || len(both.Items) > signin.MaxItems {
			return "", false
		}
	}
	id := fmt.Sprintf("collision.%d", len(collisions)+1)
	collisions[key] = id
	tmpls[id] = both
	return id, true
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
