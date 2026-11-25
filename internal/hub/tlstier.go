package hub

import (
	"strings"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

// routerTiersLocked is the TLS option of each of t's routers (contract §5
// "TLS option per host"): Traefik picks options per SNI host, so every
// router of one host gets the same value. Hosts that share a router are
// one group. A group whose routers all lack Portcullis sign-in
// (chainSignsIn of the rendered chain) gets public@file; one mixing
// signed-in and open routers gets policy.HostTier(instance tier, true)
// (protected / protected-any → default); one whose routers all sign in
// keeps the instance tier (rl.tier). A router without a host keeps the
// instance tier.
//
// Only apps whose sign-in is per request (forward-auth, header-auth) are
// split: an mtls app's certificate is its authentication, a native-oidc
// app's login is Keycloak's, and an app without sign-in is public@file
// already. A chain that can't be read keeps every router on the
// instance tier (never weaker). Caller holds mu.
func (h *Hub) routerTiersLocked(t *templates.Template, rl *routeLabels) map[string]string {
	out := make(map[string]string, len(rl.routes.Info))
	for name := range rl.routes.Info {
		out[name] = rl.tier
	}
	if h.accessLocked(t).Capability.Enforcement != policy.EnforcePerRequest {
		return out
	}
	chains, err := templateChains(t.ReadCompose())
	if err != nil {
		return out
	}
	// Union-find over hostnames.
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if p, ok := parent[x]; ok && p != x {
			r := find(p)
			parent[x] = r
			return r
		}
		parent[x] = x
		return x
	}
	hostsOf := map[string][]string{}
	for name, ri := range rl.routes.Info {
		var hs []string
		for _, host := range routerHosts(t, ri, h.cfg.Domain) {
			if n := NormalizeHost(host); n != "" {
				hs = append(hs, n)
			}
		}
		hostsOf[name] = hs
		for _, host := range hs {
			parent[find(host)] = find(hs[0])
		}
	}
	open, gated := map[string]bool{}, map[string]bool{}
	for name, hs := range hostsOf {
		if len(hs) == 0 {
			continue
		}
		ri := rl.routes.Info[name]
		mws := ri.Middlewares
		if m, ok := rl.middlewares[name]; ok {
			mws = strings.Split(m, ",")
		}
		if chainSignsIn(chains, mws) {
			gated[find(hs[0])] = true
		} else {
			open[find(hs[0])] = true
		}
	}
	for name, hs := range hostsOf {
		if len(hs) == 0 {
			continue
		}
		g := find(hs[0])
		switch {
		case open[g] && !gated[g]:
			out[name] = policy.TierPublic
		case open[g]:
			out[name] = policy.HostTier(rl.tier, true)
		}
	}
	return out
}

// tierOf is the TLS option of the template's router r (rl.routerTier),
// else the instance tier.
func (rl *routeLabels) tierOf(r string) string {
	if t, ok := rl.routerTier[r]; ok {
		return t
	}
	return rl.tier
}
