package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

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
	// PublicGuardVPNMiddleware is core's VPN public guard (group-gate
	// /public-guard/vpn): a VPN-only instance's public router uses it.
	PublicGuardVPNMiddleware = "portcullis-public-guard-vpn@docker"
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
	// The override follows (a failed narrowing write fails closed, a
	// disabled instance is rendered at its next enable).
	h.vpnRerender(map[string]bool{id: true})
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

// vpnRenderKeyLocked is what of t's override and access follow the VPN
// state, as fields "name=value" joined by "|": r (the allowlist ranges,
// "" = internet), via (the accepted providers, sorted; "*" = all), gw
// and edge (the gateway attachment), pl (the public-links opt-in).
// vpnNarrows compares them field by field.
func (h *Hub) vpnRenderKeyLocked(t *templates.Template) string {
	r, ok := h.st.Reach[t.ID]
	return h.vpnAccessKeyLocked(t, r, ok)
}

// vpnAccessKeyLocked is the render key t would have with reach r (set:
// t has a reach entry).
func (h *Hub) vpnAccessKeyLocked(t *templates.Template, r state.Reach, set bool) string {
	ranges, via := "", ""
	vpnOnly, accepted := false, []string(nil)
	switch {
	case set && r.Mode == state.ReachVPN:
		vpnOnly, accepted = true, slices.Clone(r.Via)
		if len(accepted) == 0 {
			accepted = []string{state.ReachAny}
		}
	case h.vpnCoreEnv().Mode == VPNModeServer:
		vpnOnly, accepted = true, []string{state.ReachAny}
	}
	if vpnOnly {
		ranges = strings.Join(h.vpnAllowRangesLocked(accepted), ",")
		slices.Sort(accepted)
		via = strings.Join(slices.Compact(accepted), ",")
	}
	gw, edge := "", ""
	if a, e, ok := h.vpnGatewayLocked(t); ok {
		gw, edge = a.String(), e
	}
	pl := "0"
	if set && r.PublicLinks {
		pl = "1"
	}
	return "r=" + ranges + "|via=" + via + "|gw=" + gw + "|edge=" + edge + "|pl=" + pl
}

// ReachChangeNarrows reports whether setting instance id's reach to next
// keeps or narrows its access (every field of the access key: no new
// range, no new provider, no gateway change, no public links added):
// the change set_instance_reach may make without a confirmation. An
// unknown instance is false (fail closed).
func (h *Hub) ReachChangeNarrows(id string, next state.Reach) bool {
	if next.Mode != state.ReachInternet && next.Mode != state.ReachVPN {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	if t == nil {
		return false
	}
	cur, set := h.st.Reach[id]
	prev := h.vpnAccessKeyLocked(t, cur, set)
	nk := h.vpnAccessKeyLocked(t, next, next.Mode == state.ReachVPN || next.PublicLinks)
	// next narrows or keeps prev iff going back from next to prev takes
	// nothing away: next allows nothing prev didn't.
	return !vpnNarrows(nk, prev)
}

// vpnKeyFields parses a render key ("" = none: every field empty).
func vpnKeyFields(key string) map[string]string {
	out := map[string]string{}
	if key == "" {
		return out
	}
	for _, f := range strings.Split(key, "|") {
		k, v, _ := strings.Cut(f, "=")
		out[k] = v
	}
	return out
}

// vpnRenderRetry is a VPN re-render that failed: retried with backoff;
// closed: a narrowing change couldn't be applied, so the instance was
// stopped (fail closed) until a render succeeds.
type vpnRenderRetry struct {
	next   time.Time
	delay  time.Duration
	closed bool
}

const (
	vpnRetryMin = 5 * time.Second
	vpnRetryMax = 5 * time.Minute
)

// vpnRangesOf is a render key's allowlist ranges (nil = internet).
func vpnRangesOf(key string) []string {
	r := vpnKeyFields(key)["r"]
	if r == "" {
		return nil
	}
	return strings.Split(r, ",")
}

// vpnNarrows: going from render key prev to next takes away something
// prev allowed, field by field (fail closed: a field whose effect isn't
// known counts as narrowing whenever it changes):
//   - r: internet → VPN-only, or an accepted range no longer accepted
//     (the no-client sentinel accepts nothing);
//   - via: an accepted provider no longer accepted ("*" holds all);
//   - gw / edge: the gateway attachment lost or moved;
//   - pl: public links leave the internet.
func vpnNarrows(prev, next string) bool {
	p, n := vpnKeyFields(prev), vpnKeyFields(next)
	keys := map[string]bool{}
	for k := range p {
		keys[k] = true
	}
	for k := range n {
		keys[k] = true
	}
	for k := range keys {
		pv, nv := p[k], n[k]
		if pv == nv {
			continue
		}
		switch k {
		case "r":
			if nv == "" {
				continue // internet: wider
			}
			if pv == "" {
				return true // internet → VPN-only
			}
			nr := strings.Split(nv, ",")
			for _, r := range strings.Split(pv, ",") {
				if r != vpnNoClient && !slices.Contains(nr, r) {
					return true
				}
			}
		case "via":
			// The accepted providers: "*" holds every one; "" (internet)
			// is covered by r.
			if pv == "" || nv == "" {
				continue
			}
			if pv == state.ReachAny {
				if nv != state.ReachAny {
					return true
				}
				continue
			}
			if nv == state.ReachAny {
				continue // wider
			}
			nl := strings.Split(nv, ",")
			for _, x := range strings.Split(pv, ",") {
				if !slices.Contains(nl, x) {
					return true
				}
			}
		case "gw", "edge":
			if pv != "" {
				return true // the attachment lost or moved
			}
		case "pl":
			if pv == "1" {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// vpnRangesChanged re-renders the override of every enabled instance
// whose VPN rendering moved (allowlist ranges, gateway attachment) and
// owes it a restart (V7). The render key is committed only after the
// write succeeded. A failed write is retried with backoff; if the change
// narrowed access, the instance is stopped (fail closed, audited
// vpn.reach_failed_closed, a doctor Problem) until a render succeeds,
// then started again.
func (h *Hub) vpnRangesChanged() { h.vpnRerender(nil) }

// vpnRerender is vpnRangesChanged, forcing the instances in force (a
// reach change): rendered again and restarted even when their key looks
// unchanged.
func (h *Hub) vpnRerender(force map[string]bool) {
	now := h.vpnrt.now()
	h.mu.Lock()
	var restart, closeIDs []string
	closeWhy := map[string]error{}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		key := h.vpnRenderKeyLocked(t)
		h.vpnrt.mu.Lock()
		prev, known := h.vpnrt.rendered[t.ID]
		fail := h.vpnrt.renderFail[t.ID]
		h.vpnrt.mu.Unlock()
		if !force[t.ID] && known && prev == key && fail == nil {
			continue
		}
		if !force[t.ID] && fail != nil && now.Before(fail.next) {
			// In backoff: a narrowing change (against the committed
			// key) still fails closed at once.
			if !fail.closed && vpnNarrows(prev, key) {
				h.vpnrt.mu.Lock()
				fail.closed = true
				h.vpnrt.mu.Unlock()
				closeIDs = append(closeIDs, t.ID)
				closeWhy[t.ID] = errors.New("an earlier VPN render failed and is retried")
			}
			continue
		}
		if err := h.generateOverrideLocked(t, h.st.Settings[t.ID]); err != nil {
			log.Printf("vpn: %s: override: %v (retried)", t.ID, err)
			h.vpnrt.mu.Lock()
			if fail == nil {
				fail = &vpnRenderRetry{delay: vpnRetryMin}
				h.vpnrt.renderFail[t.ID] = fail
			} else {
				fail.delay = min(2*fail.delay, vpnRetryMax)
			}
			fail.next = now.Add(fail.delay)
			// Fail closed: a narrowing change that can't be applied
			// (an instance never rendered by this run counts as one when
			// it renders VPN-only).
			if !fail.closed && (known && vpnNarrows(prev, key) || !known && vpnNarrows("r=|via=|gw=|edge=|pl=1", key)) {
				fail.closed = true
				closeIDs = append(closeIDs, t.ID)
				closeWhy[t.ID] = err
			}
			h.vpnrt.mu.Unlock()
			continue
		}
		h.vpnrt.mu.Lock()
		delete(h.vpnrt.renderFail, t.ID)
		h.vpnrt.mu.Unlock()
		// Never rendered by this run: the file is current again, the
		// exposure drift covers its labels; a fail-closed instance starts
		// again.
		if known || force[t.ID] || fail != nil && fail.closed {
			restart = append(restart, t.ID)
		}
	}
	h.mu.Unlock()
	for _, id := range closeIDs {
		h.vpnFailClosed(id, clipRunes(h.RedactErr(id, closeWhy[id]), 600))
	}
	for _, id := range restart {
		h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
	}
}

// vpnFailClosed stops instance id (compose down, volumes kept; its
// enabled flag unchanged) because a narrowing VPN change couldn't be
// rendered, records the op and audits vpn.reach_failed_closed.
func (h *Hub) vpnFailClosed(id, why string) {
	err := h.compose.DownByName(context.Background(), projectName(id))
	msg := "the VPN allowlist couldn't be narrowed (" + why + "): the instance was stopped until it can"
	if err != nil {
		msg += "; stopping it failed: " + clipRunes(h.RedactErr(id, err), 300)
		log.Printf("ERROR: vpn: %s: failing closed: stop: %v", id, err)
	}
	h.recordOp(id, OpRecord{Op: OpStop, At: h.vpnrt.now().UTC(), OK: false, Error: msg})
	h.auditOp(directory.Human("hub"), "vpn.reach_failed_closed", id, "", errors.New(msg))
}

// vpnFailedClosed are the instances stopped by vpnFailClosed (the
// doctor's Problem), sorted.
func (h *Hub) vpnFailedClosed() []string {
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	var out []string
	for id, f := range h.vpnrt.renderFail {
		if f.closed {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// vpnRenderRetryDue: a failed VPN re-render is due again.
func (h *Hub) vpnRenderRetryDue() bool {
	now := h.vpnrt.now()
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	for _, f := range h.vpnrt.renderFail {
		if !now.Before(f.next) {
			return true
		}
	}
	return false
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
