package hub

import (
	"context"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/vpn"
)

// Reach (contract §5, §11; spec §8): an instance is reachable from the
// internet (the default: every router on websecure,vpnsecure) or only
// through Portcullis VPNs (vpnsecure only, the portcullis-vpnallow-<id>
// allowlist first in every chain, a friendly portcullis-vpnonly-<id>
// router on websecure answering /vpn-required). Server mode makes every
// instance VPN-only but the provider control routers and the public
// routers of instances with the public-links opt-in. Switches only ever
// narrow.

// Hub-rendered names and values (the prefix portcullis-vpn is the Hub's).
const (
	VPNAllowPrefix        = "portcullis-vpnallow-"
	VPNOnlyPrefix         = "portcullis-vpnonly-"
	VPNRequiredMiddleware = "vpn-required-path@docker"
	EntrypointsBoth       = "websecure,vpnsecure"
	EntrypointsVPN        = "vpnsecure"
	// vpnNoClient is the allowlist of a VPN-only instance with no
	// accepted provider: Traefik refuses an empty range, and this one
	// matches no client.
	vpnNoClient = "0.0.0.0/32"
	// vpnNetwork is core's portcullis-vpn network (external to apps).
	vpnNetwork = "portcullis-vpn"
	// VPNGroupsMiddleware is core's VPN forwardAuth to group-gate (the
	// device ↔ person binding is checked only for requests that came in
	// on vpnsecure): it replaces portcullis-groups@docker in a VPN-only
	// router's chain. Core names it; change it here only.
	VPNGroupsMiddleware = "portcullis-groups-vpn@docker"
	// VarVPNEdge is the gateway's edge address in its environment.
	VarVPNEdge = "PORTCULLIS_VPN_EDGE"
)

// VPNAllowMiddleware is instance id's allowlist middleware.
func VPNAllowMiddleware(id string) string { return VPNAllowPrefix + id }

// VPNOnlyRouter is instance id's friendly router.
func VPNOnlyRouter(id string) string { return VPNOnlyPrefix + id }

// effectiveReachLocked: whether t renders VPN-only, and the providers it
// accepts. Server mode makes every instance VPN-only through every
// provider (an instance's own narrower via stays). Caller holds mu.
func (h *Hub) effectiveReachLocked(t *templates.Template) (vpnOnly bool, via []string) {
	r, ok := h.st.Reach[t.ID]
	if ok && r.Mode == state.ReachVPN {
		return true, slices.Clone(r.Via)
	}
	if h.vpnCoreEnv().Mode == VPNModeServer {
		return true, []string{state.ReachAny}
	}
	return false, nil
}

// publicLinksLocked: t's public router stays on the internet in server
// mode (the per-instance opt-in; never for an instance set to vpn
// itself). Caller holds mu.
func (h *Hub) publicLinksLocked(t *templates.Template) bool {
	r, ok := h.st.Reach[t.ID]
	return ok && r.Mode != state.ReachVPN && r.PublicLinks && h.vpnCoreEnv().Mode == VPNModeServer
}

// controlRoutersOf are t's provider control routers (they keep
// websecure, contract §3.3).
func controlRoutersOf(t *templates.Template) map[string]bool {
	out := map[string]bool{}
	if t.Manifest.VPN != nil {
		for _, r := range t.Manifest.VPN.ControlRouters {
			out[r] = true
		}
	}
	return out
}

// vpnAllowRanges are the client ranges a VPN-only instance accepting via
// lets through: the built-in subnet (when on) and every wired provider's
// ranges, narrowed to via ("*" = all). Sorted; never empty
// (vpnNoClient).
func (h *Hub) vpnAllowRanges(via []string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.vpnAllowRangesLocked(via)
}

func (h *Hub) vpnAllowRangesLocked(via []string) []string {
	any := slices.Contains(via, state.ReachAny)
	accepts := func(id string) bool { return any || slices.Contains(via, id) }
	var out []string
	if accepts(vpn.BuiltinID) && !h.st.VPN.BuiltinOff {
		h.vpnrt.mu.Lock()
		p := h.vpnrt.people
		h.vpnrt.mu.Unlock()
		if p != nil {
			if sub, err := netip.ParsePrefix(p.Subnet); err == nil {
				out = append(out, sub.Masked().String())
			}
		}
	}
	for _, id := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		if !accepts(id) {
			continue
		}
		t := h.findLocked(id)
		if t == nil || t.Manifest.VPN == nil {
			continue
		}
		if rs, err := h.providerRangesLocked(t); err == nil {
			out = append(out, vpn.Strings(rs)...)
		}
	}
	if len(out) == 0 {
		return []string{vpnNoClient}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// vpnGatewayLocked is wired provider t's gateway attachment: its
// portcullis-vpn address and edge (wg ip:port); ok false when t isn't
// wired. Caller holds mu.
func (h *Hub) vpnGatewayLocked(t *templates.Template) (gw netip.Addr, edge string, ok bool) {
	p, wired := h.st.VPN.Providers[t.ID]
	if !wired || t.Manifest.VPN == nil {
		return netip.Addr{}, "", false
	}
	core := h.vpnCoreEnv()
	gw, err := vpn.GatewayAddr(core.Net, p.Slot)
	if err != nil {
		return netip.Addr{}, "", false
	}
	return gw, fmt.Sprintf("%s:%d", core.WGIP, vpn.EdgePort(p.Slot)), true
}

// vpnRoutesLocked sets rl's entrypoints, prepends the allowlist to every
// VPN-only chain and renders the allowlist and friendly router (on the
// first traefik.enable service). Caller holds mu.
func (h *Hub) vpnRoutesLocked(t *templates.Template, rl *routeLabels) error {
	vpnOnly, via := h.effectiveReachLocked(t)
	ctrl := controlRoutersOf(t)
	rl.entrypoints = map[string]string{}
	allow := VPNAllowMiddleware(t.ID) + "@docker"
	prepend := func(chain string) string {
		if chain == "" {
			return allow
		}
		return allow + "," + vpnGroupsChain(chain)
	}
	for name, ri := range rl.routes.Info {
		if !vpnOnly || ctrl[name] {
			rl.entrypoints[name] = EntrypointsBoth
			continue
		}
		rl.entrypoints[name] = EntrypointsVPN
		chain, ok := rl.middlewares[name]
		if !ok {
			chain = strings.Join(ri.Middlewares, ",")
		}
		if rl.middlewares == nil {
			rl.middlewares = map[string]string{}
		}
		rl.middlewares[name] = prepend(chain)
	}
	rl.vpnOnly = vpnOnly
	rl.publicVPN = vpnOnly && !h.publicLinksLocked(t)
	if !vpnOnly {
		return nil
	}
	// The sign-in and MCP routers of a VPN-only instance go VPN-only too.
	for k := range rl.signInLabels {
		if strings.HasSuffix(k, ".entrypoints") {
			rl.signInLabels[k] = EntrypointsVPN
			mk := strings.TrimSuffix(k, ".entrypoints") + ".middlewares"
			rl.signInLabels[mk] = prepend(rl.signInLabels[mk])
		}
	}
	for k := range rl.mcpLabels {
		if strings.HasSuffix(k, ".entrypoints") {
			rl.mcpLabels[k] = EntrypointsVPN
			mw := strings.TrimSuffix(k, ".entrypoints") + ".middlewares"
			rl.mcpLabels[mw] = prepend(rl.mcpLabels[mw])
		}
	}
	svc, err := templates.FirstEnabledService(t.ReadCompose())
	if err != nil {
		return err
	}
	if svc == "" {
		// The first service with HTTP routers carries them.
		if svcs := slices.Sorted(maps.Keys(rl.routes.Routers)); len(svcs) > 0 {
			svc = svcs[0]
		}
	}
	if svc == "" {
		return fmt.Errorf("no service with Traefik routers for the VPN allowlist")
	}
	hosts := map[string]bool{}
	for _, hst := range t.Hosts {
		if hst = NormalizeHost(hst); hst != "" {
			hosts[hst] = true
		}
	}
	rl.vpnService, rl.vpnLabels = svc, map[string]string{}
	m := "traefik.http.middlewares." + VPNAllowMiddleware(t.ID) + ".ipallowlist."
	rl.vpnLabels[m+"sourcerange"] = strings.Join(h.vpnAllowRangesLocked(via), ",")
	rl.vpnLabels[m+"rejectstatuscode"] = "403"
	if len(hosts) > 0 {
		var match []string
		for _, hst := range slices.Sorted(maps.Keys(hosts)) {
			match = append(match, "Host(`"+hst+"`)")
		}
		r := "traefik.http.routers." + VPNOnlyRouter(t.ID) + "."
		rl.vpnLabels[r+"rule"] = strings.Join(match, " || ")
		rl.vpnLabels[r+"entrypoints"] = "websecure"
		rl.vpnLabels[r+"priority"] = "1"
		rl.vpnLabels[r+"tls.options"] = rl.tier
		rl.vpnLabels[r+"middlewares"] = VPNRequiredMiddleware
		rl.vpnLabels[r+"service"] = "group-gate@docker"
	}
	return nil
}

// SetInstanceReach sets instance id's Reachable from / Through and the
// public-links opt-in (contract §11 PUT /api/instances/{id}/reach): vpn
// needs a live provider in via (ErrNoLiveProvider), via is ["*"] or
// wired provider ids (400), public_links only for an instance with
// public exceptions. Audited instance.reach ("internet -> vpn via=*")
// and vpn.public_links ("off -> on"); the override is rendered again and
// a restart owed.
func (h *Hub) SetInstanceReach(ctx context.Context, actor directory.Actor, id string, r state.Reach) (err error) {
	h.mu.RLock()
	cur, had := h.st.Reach[id]
	h.mu.RUnlock()
	from := reachDetail(cur, had)
	switch r.Mode {
	case state.ReachInternet:
		r.Via = nil
	case state.ReachVPN:
		if len(r.Via) == 0 {
			r.Via = []string{state.ReachAny}
		}
	}
	to := reachDetail(r, true)
	defer func() {
		if err != nil {
			h.auditOp(actor, "instance.reach", id, from+" -> "+clip(to, 200), err)
		}
	}()
	if r.Mode != state.ReachInternet && r.Mode != state.ReachVPN {
		return statusErr(http.StatusBadRequest, "mode must be internet or vpn")
	}
	live := h.liveProviders()
	h.mu.Lock()
	t := h.findLocked(id)
	if t == nil {
		h.mu.Unlock()
		return statusErr(http.StatusNotFound, "no instance %s", clip(id, 64))
	}
	if r.Mode == state.ReachVPN {
		if len(r.Via) > 8 {
			h.mu.Unlock()
			return statusErr(http.StatusBadRequest, "via: at most 8 providers")
		}
		seen := map[string]bool{}
		for _, v := range r.Via {
			switch {
			case v == state.ReachAny && len(r.Via) == 1:
			case v == vpn.BuiltinID, hasProvider(h.st.VPN.Providers, v):
			default:
				h.mu.Unlock()
				return statusErr(http.StatusBadRequest, "via: %s is not a wired VPN provider (use [\"*\"] or wired provider ids)", clip(v, 64))
			}
			if seen[v] {
				h.mu.Unlock()
				return statusErr(http.StatusBadRequest, "via: %s listed twice", clip(v, 64))
			}
			seen[v] = true
		}
		ok := false
		for _, l := range live {
			if slices.Contains(r.Via, state.ReachAny) || slices.Contains(r.Via, l) {
				ok = true
			}
		}
		if !ok {
			h.mu.Unlock()
			return ErrNoLiveProvider
		}
	}
	if r.PublicLinks && t.Public == nil {
		h.mu.Unlock()
		return statusErr(http.StatusBadRequest, "%s has no public exceptions: there are no public links to keep on the internet", id)
	}
	prev, hadPrev := h.st.Reach[id]
	if r.Mode == state.ReachInternet && !r.PublicLinks {
		delete(h.st.Reach, id)
	} else {
		h.st.Reach[id] = r
	}
	if err := h.saveStateLocked(); err != nil {
		if hadPrev {
			h.st.Reach[id] = prev
		} else {
			delete(h.st.Reach, id)
		}
		h.mu.Unlock()
		return err
	}
	enabled := h.st.IsEnabled(id)
	if oerr := h.generateOverrideLocked(t, h.st.Settings[id]); oerr != nil {
		log.Printf("vpn: %s: override: %v", id, oerr)
	}
	h.mu.Unlock()
	if from != to {
		h.auditOp(actor, "instance.reach", id, from+" -> "+to, nil)
	}
	if prev.PublicLinks != r.PublicLinks {
		h.auditOp(actor, "vpn.public_links", id, onOff(prev.PublicLinks)+" -> "+onOff(r.PublicLinks), nil)
	}
	if werr := h.WritePolicy(); werr != nil {
		log.Printf("vpn: %s: policy file: %v", id, werr)
	}
	if enabled {
		h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
	}
	return nil
}

func hasProvider(m map[string]state.VPNProvider, id string) bool { _, ok := m[id]; return ok }

// reachDetail is a reach as the audit shows it.
func reachDetail(r state.Reach, set bool) string {
	if !set || r.Mode != state.ReachVPN {
		return state.ReachInternet
	}
	return "vpn via=" + strings.Join(r.Via, ",")
}

// vpnPolicyLocked is the policy file's vpn section (contract §4 v7):
// every host of every enabled VPN-only instance with its via, and the
// core env's mode and public enrolment. Caller holds mu.
func (h *Hub) vpnPolicyLocked() policy.VPNPolicy {
	core := h.vpnCoreEnv()
	out := policy.VPNPolicy{Hosts: map[string]policy.VPNHost{}, ServerMode: core.Mode == VPNModeServer,
		AdminOnly: core.Mode == VPNModeAdmin, PublicEnrol: core.PublicEnrol, DevicesFile: policy.VPNDevicesFile}
	coreHosts := policy.CoreHosts(h.cfg.Domain)
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		vpnOnly, via := h.effectiveReachLocked(t)
		if !vpnOnly {
			continue
		}
		// A host stays out only when every router on it is a provider
		// control router (those stay public); a router whose host can't
		// be told keeps every host in (fail closed).
		onlyCtrl := h.vpnControlOnlyHostsLocked(t)
		for _, hst := range t.Hosts {
			hst = NormalizeHost(hst)
			if hst == "" || coreHosts[hst] || onlyCtrl[hst] {
				continue
			}
			out.Hosts[hst] = policy.VPNHost{Via: slices.Clone(via)}
		}
	}
	return out
}

// vpnAttach is a wired provider's gateway attachment in its override.
type vpnAttach struct {
	ingress  string            // "" = none
	addr     netip.Addr        // on portcullis-vpn
	networks []string          // the ingress's own networks (or default)
	env      map[string]string // service → its PORTCULLIS_VPN_EDGE line
}

// vpnAttachLocked is t's gateway attachment (contract §3.3; none unless
// t is a wired provider): the ingress keeps the template's networks (or
// default) and joins portcullis-vpn at its slot's address; it and every
// service in its network namespace get PORTCULLIS_VPN_EDGE (V11).
// Caller holds mu.
func (h *Hub) vpnAttachLocked(t *templates.Template) vpnAttach {
	gw, edge, ok := h.vpnGatewayLocked(t)
	if !ok {
		return vpnAttach{}
	}
	compose := t.ReadCompose()
	routes, err := templates.ParseRoutes(compose)
	if err != nil {
		return vpnAttach{}
	}
	ing := t.Manifest.VPN.Ingress.Service
	a := vpnAttach{ingress: ing, addr: gw, env: map[string]string{}}
	a.networks = slices.Clone(templates.ServiceNetworks(compose)[ing].Networks)
	if len(a.networks) == 0 {
		a.networks = []string{"default"}
	}
	slices.Sort(a.networks)
	line := VarVPNEdge + ": " + yamlQuote(edge)
	a.env[ing] = line
	for _, svc := range t.Services {
		if ns, ok := routes.NetNS(svc); ok && ns == ing && svc != ing {
			a.env[svc] = line
		}
	}
	return a
}

// vpnRenderKeyLocked is what of t's override follows the VPN maps: its
// allowlist ranges and its gateway attachment.
func (h *Hub) vpnRenderKeyLocked(t *templates.Template) string {
	var b strings.Builder
	if vpnOnly, via := h.effectiveReachLocked(t); vpnOnly {
		b.WriteString(strings.Join(h.vpnAllowRangesLocked(via), ","))
	}
	if gw, edge, ok := h.vpnGatewayLocked(t); ok {
		b.WriteString("|" + gw.String() + "|" + edge)
	}
	return b.String()
}

// vpnRangesChanged re-renders the override of every enabled instance
// whose VPN rendering moved (allowlist ranges, gateway attachment) and
// owes it a restart (V7; rare: wiring, unwiring, a provider's ranges).
func (h *Hub) vpnRangesChanged() {
	h.mu.Lock()
	var restart []string
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		key := h.vpnRenderKeyLocked(t)
		h.vpnrt.mu.Lock()
		prev, known := h.vpnrt.rendered[t.ID]
		h.vpnrt.rendered[t.ID] = key
		h.vpnrt.mu.Unlock()
		if known && prev == key {
			continue
		}
		if err := h.generateOverrideLocked(t, h.st.Settings[t.ID]); err != nil {
			log.Printf("vpn: %s: override: %v", t.ID, err)
			continue
		}
		// Never rendered by this run: the file is current again, the
		// exposure drift covers its labels.
		if known {
			restart = append(restart, t.ID)
		}
	}
	h.mu.Unlock()
	for _, id := range restart {
		h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
	}
}

// vpnControlOnlyHostsLocked are t's hosts served by provider control
// routers only. Caller holds mu.
func (h *Hub) vpnControlOnlyHostsLocked(t *templates.Template) map[string]bool {
	ctrl := controlRoutersOf(t)
	if len(ctrl) == 0 {
		return nil
	}
	routes, err := templates.ParseRoutes(t.ReadCompose())
	if err != nil {
		return nil
	}
	ctrlHost, other := map[string]bool{}, map[string]bool{}
	for name, ri := range routes.Info {
		var hosts []string
		for _, hv := range ri.HostVars {
			if hst := NormalizeHost(t.InstanceEnv[hv]); hv != "" && hst != "" {
				hosts = append(hosts, hst)
			}
		}
		if len(hosts) == 0 {
			return nil
		}
		for _, hst := range hosts {
			if ctrl[name] {
				ctrlHost[hst] = true
			} else {
				other[hst] = true
			}
		}
	}
	out := map[string]bool{}
	for hst := range ctrlHost {
		if !other[hst] {
			out[hst] = true
		}
	}
	return out
}

// vpnGroupsChain swaps core's group check for its VPN variant in a
// VPN-only router's chain (contract §4: the binding is enforced only on
// requests that came in on vpnsecure).
func vpnGroupsChain(chain string) string {
	parts := strings.Split(chain, ",")
	for i, m := range parts {
		base, prov, _ := strings.Cut(strings.TrimSpace(m), "@")
		if strings.EqualFold(base, "portcullis-groups") && (prov == "" || prov == "docker") {
			parts[i] = VPNGroupsMiddleware
		}
	}
	return strings.Join(parts, ",")
}
