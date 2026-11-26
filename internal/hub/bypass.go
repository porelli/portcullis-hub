package hub

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

// Bypass badges (contract §11.7 "bypass"): each way an instance skips part
// of Portcullis's normal protection, as the Hub renders its routers
// (routeLabelsLocked — the same model the compose override and the
// Kubernetes IngressRoutes come from). Display only: nothing here decides
// access.

// Bypass kinds.
const (
	// BypassOpenHost: the app has no Portcullis sign-in at all (auth
	// method custom or public, or its own login only): every host is open.
	BypassOpenHost = "open_host"
	// BypassOpenRouter: one router of an app with Portcullis sign-in has
	// no forward-auth in its chain (a template's ungated path or host).
	BypassOpenRouter = "open_router"
	// BypassPublicPaths: the admin's public exception (auth.public_access)
	// is on: its paths skip sign-in.
	BypassPublicPaths = "public_paths"
	// BypassWeakTLS: the app asks for no client certificate (public@file)
	// while the server's default sign-in template asks for one.
	BypassWeakTLS = "weak_tls"
)

// BypassPath is one path matcher of an open router or a public exception:
// Match "prefix" (the path and everything under it), "exact" or "static"
// (static files under the prefix only).
type BypassPath struct {
	Path  string `json:"path"`
	Match string `json:"match"`
}

// Bypass is one way an instance skips part of Portcullis's protection.
type Bypass struct {
	Kind string `json:"kind"`
	// Router is the open router (open_router only).
	Router string `json:"router,omitempty"`
	// Hosts are the hostnames concerned; Paths the open paths (none: the
	// whole host); Rule the router's rule when its matchers aren't plain
	// paths (open_router only).
	Hosts []string     `json:"hosts"`
	Paths []BypassPath `json:"paths"`
	Rule  string       `json:"rule,omitempty"`
	// Tier is the TLS option the hosts get (policy.Tier*).
	Tier string `json:"tier"`
	// VPNOnly: reachable on the VPN only (not from the internet).
	VPNOnly bool `json:"vpn_only,omitempty"`
	// Reason says why, shortly: the Hub's account of the mechanism; Note
	// the template's own words (the first paragraph of auth.notes, ≤ 300
	// runes) or the exception's description.
	Reason string `json:"reason"`
	Note   string `json:"note,omitempty"`
}

// bypassNoteMax caps a bypass note (runes), like the portal note.
const bypassNoteMax = 300

// templateNote is the first paragraph of t's auth.notes when short enough.
func templateNote(t *templates.Template) string {
	if n := t.Manifest.Auth.NoteText; utf8.RuneCountInString(n) <= bypassNoteMax {
		return n
	}
	return ""
}

// hostReason returns the per-host reason for router from the template's
// hosts.reasons map (contract §3: keyed by host router, a reason per
// host): the router's own entry when it is a host router, else — a path
// router — the entry of the host router of the one hostname its rule
// routes (by its hostname variable). A router routing several hostnames,
// or a hostname without a reason, falls back to templateNote. The reason
// is rendered escaped in the UI: it comes from the template manifest
// (trusted input).
func hostReason(t *templates.Template, router string, ri *templates.RouterInfo) string {
	reasons := t.Manifest.GetReasons()
	if reason := reasons[router]; reason != "" {
		return reason
	}
	if ri != nil && len(ri.HostVars) == 1 && ri.HostVars[0] != "" {
		for hr, v := range t.HostVars {
			if v == ri.HostVars[0] {
				if reason := reasons[hr]; reason != "" {
					return reason
				}
				break
			}
		}
	}
	return templateNote(t)
}

// baselineTierLocked is the TLS option the server's default sign-in
// template gives an app (no public exception): the norm a weak_tls badge
// compares with. A default that can't be compiled counts as the strictest.
// Caller holds mu.
func (h *Hub) baselineTierLocked() string {
	c, ok := compiledIn(h.st.SignIn, h.st.SignIn.Default)
	if !ok {
		return policy.TierProtected
	}
	return policy.Tier(&c, h.st.SignIn.MethodsOn(), false)
}

// bypassLocked lists how t skips Portcullis's protection: never nil. A
// router-less instance has no network entry; one whose routes can't be
// rendered lists nothing (it can't start either). Caller holds mu.
func (h *Hub) bypassLocked(t *templates.Template) []Bypass {
	out := []Bypass{}
	if t.Manifest.Routerless() {
		return out
	}
	rl, err := h.routeLabelsLocked(t)
	if err != nil {
		return out
	}
	acc := h.accessLocked(t)
	names := make([]string, 0, len(rl.routes.Info))
	for name := range rl.routes.Info {
		names = append(names, name)
	}
	sort.Strings(names)
	vpnRouter := func(name string) bool { return rl.vpnOnly && rl.entrypoints[name] == EntrypointsVPN }
	hostsOf := func(name string) []string {
		return sortedUnique(routerHosts(t, rl.routes.Info[name], h.cfg.Domain))
	}

	switch acc.Capability.Enforcement {
	case policy.EnforceNone:
		var hosts []string
		vpn := len(names) > 0
		for _, name := range names {
			hosts = append(hosts, hostsOf(name)...)
			vpn = vpn && vpnRouter(name)
		}
		reason := "No Portcullis sign-in: the app's auth method is " + t.Manifest.Auth.Method + ", so nothing in front checks who is asking."
		switch {
		case acc.SignIn == SignInNative:
			reason = "Set to the app's own login only: no Portcullis sign-in in front of it."
		case t.Manifest.Auth.Method == "public":
			reason = "A public app: no sign-in by design."
		}
		out = append(out, Bypass{Kind: BypassOpenHost, Hosts: sortedUnique(hosts), Paths: []BypassPath{}, Tier: rl.tier, VPNOnly: vpn,
			Reason: reason, Note: templateNote(t)})
	case policy.EnforcePerRequest:
		chains, err := templateChains(t.ReadCompose())
		if err != nil {
			chains = map[string][]string{}
		}
		for _, name := range names {
			ri := rl.routes.Info[name]
			mws := ri.Middlewares
			if m, ok := rl.middlewares[name]; ok {
				mws = strings.Split(m, ",")
			}
			if chainSignsIn(chains, mws) {
				continue
			}
			b := Bypass{Kind: BypassOpenRouter, Router: name, Hosts: hostsOf(name), Paths: []BypassPath{}, Tier: rl.tierOf(name), VPNOnly: vpnRouter(name),
				Reason: "The template's router " + name + " has no Portcullis sign-in in its middlewares.", Note: hostReason(t, name, ri)}
			for _, p := range ri.Paths {
				m := "exact"
				if p.Prefix {
					m = "prefix"
				}
				b.Paths = append(b.Paths, BypassPath{Path: p.Value, Match: m})
			}
			if len(ri.Opaque) > 0 {
				b.Rule = ri.Rule
			}
			out = append(out, b)
		}
	}

	if pub := h.publicLocked(t, rl.plan); pub.Active() {
		b := Bypass{Kind: BypassPublicPaths, Hosts: h.publicPlanHostsLocked(t, rl.plan), Paths: []BypassPath{}, Tier: rl.tier, VPNOnly: rl.publicVPN,
			Reason: "The public exception is on: these paths skip Portcullis sign-in, for anyone with the link.",
			Note:   t.Manifest.Auth.PublicAccess.Description}
		if pub.Mode == templates.ModeListed {
			b.Reason = "The public exception is on for the listed shares: these paths skip Portcullis sign-in."
		}
		for _, gp := range templates.GuardPaths(pub.Published) {
			b.Paths = append(b.Paths, BypassPath{Path: gp[0], Match: gp[1]})
		}
		out = append(out, b)
	}

	// A weaker TLS tier than the norm: only public@file (no certificate
	// asked) counts, and only while the default template asks for one; an
	// app without sign-in is already listed as open.
	if acc.Capability.Templates && rl.tier == policy.TierPublic {
		if base := h.baselineTierLocked(); base != policy.TierPublic {
			var hosts []string
			for _, name := range names {
				hosts = append(hosts, hostsOf(name)...)
			}
			name := acc.Template
			if st, ok := h.st.SignIn.Templates[acc.Template]; ok && st.Name != "" {
				name = st.Name
			}
			out = append(out, Bypass{Kind: BypassWeakTLS, Hosts: sortedUnique(hosts), Paths: []BypassPath{}, Tier: rl.tier,
				Reason: fmt.Sprintf("Its sign-in template %q asks for no certificate, so the TLS handshake requests none (the server's default template gets %s).", name, tierWords(base))})
		}
	}
	return out
}

// publicPlanHostsLocked are the hostnames a public plan serves: its full
// hostnames (v2 form), else in the legacy form each subdomain's host
// router's host (routerHosts' rule). Caller holds mu.
func (h *Hub) publicPlanHostsLocked(t *templates.Template, plan *templates.PublicPlan) []string {
	if len(plan.Hosts) > 0 {
		return sortedUnique(plan.Hosts)
	}
	var out []string
	for _, sub := range plan.Subdomains {
		host := sub + "." + h.cfg.Domain
		for r, s := range t.HostRouters {
			if s == sub && t.Hosts[r] != "" {
				host = t.Hosts[r]
				break
			}
		}
		out = append(out, host)
	}
	return sortedUnique(out)
}

// chainSignsIn: a rendered router chain has Portcullis sign-in
// (portcullis-auth, its extra-domain variant, or a template chain that
// reaches it).
func chainSignsIn(chains map[string][]string, mws []string) bool {
	for _, m := range mws {
		m = strings.TrimSpace(m)
		if m == ExtAuthMiddleware {
			return true
		}
		base, prov, _ := strings.Cut(m, "@")
		if prov != "" && prov != "docker" {
			continue
		}
		if base == authMiddlewareName || chainReachesAuth(chains, base, map[string]bool{}) {
			return true
		}
	}
	return false
}

// tierWords names a TLS option for people.
func tierWords(tier string) string {
	switch tier {
	case policy.TierProtected:
		return "protected (a YubiKey certificate required)"
	case policy.TierProtectedAny:
		return "protected-any (a certificate required)"
	case policy.TierDefault:
		return "default (a certificate if the browser has one)"
	case policy.TierPublic:
		return "public (no certificate asked)"
	}
	return tier
}

func sortedUnique(in []string) []string {
	set := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
