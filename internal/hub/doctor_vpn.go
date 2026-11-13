package hub

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/vpn"
)

// doctorVPNIn are the VPN kinds' inputs (contract §14.5): from state, the
// in-memory maps, wg's status.json and the guarded engine (container
// networks, the gateways' inspects; never under mu). nil when nothing
// about the VPN is configured (no wg status file, nothing wired, no
// VPN-only instance, mode apps): the kinds stay silent.
func (h *Hub) doctorVPNIn(ctx context.Context, m *directory.Membership) *doctor.VPNIn {
	if h.cfg.VPNStatusFile == "" && h.cfg.VPNDocDir == "" {
		return nil
	}
	st, serr := h.wgStatus()
	hs := st.Handshakes()
	core := h.vpnCoreEnv()
	priv := h.vpnGatewayPrivileged(ctx)
	running := h.vpnGatewaysUp(ctx)
	var dockerNets []netip.Prefix
	if h.engine != nil {
		if nets, err := h.engine.ListNetworks(ctx); err == nil {
			for _, n := range nets {
				if n.Name == vpnNetwork {
					continue // the Hub's own gateways sit there
				}
				dockerNets = append(dockerNets, n.Subnets...)
			}
		}
	}
	now := h.vpnrt.now()
	in := &doctor.VPNIn{Mode: core.Mode, WGUp: serr == nil && st.Edge.OK, FailedClosed: h.vpnFailedClosed(), DockerNets: dockerNets}
	switch {
	case serr != nil:
		in.WGError = serr.Error()
	case !st.Edge.OK:
		in.WGError = st.Edge.Error
	}
	isAdmin := func(u string) bool {
		if m == nil {
			return false
		}
		_, ok := m.Users[u][lldap.AdminGroup]
		return ok && !m.Expired[u][lldap.AdminGroup]
	}
	seen := func(at time.Time) {
		if at.After(in.AdminSeen) {
			in.AdminSeen = at
		}
	}
	h.mu.RLock()
	in.LocalNetworks = h.localNetworksLocked()
	_, in.Builtin = h.builtinOnLocked(st)
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		if vpnOnly, via := h.effectiveReachLocked(t); vpnOnly {
			in.VPNOnly = append(in.VPNOnly, t.ID)
			r := h.st.Reach[t.ID]
			in.Instances = append(in.Instances, doctor.VPNInstanceIn{ID: t.ID, Via: slices.Clone(via), PublicLinks: r.PublicLinks})
		} else if r, ok := h.st.Reach[t.ID]; ok && r.PublicLinks && h.publicLinksLocked(t) {
			in.Instances = append(in.Instances, doctor.VPNInstanceIn{ID: t.ID, PublicLinks: true})
		}
	}
	for _, id := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		t := h.findLocked(id)
		if t == nil || t.Manifest.VPN == nil {
			continue
		}
		p := h.st.VPN.Providers[id]
		v := t.Manifest.VPN
		pin := doctor.VPNProviderIn{ID: id, Label: v.Label, Source: v.Identity.Source, GatewayUp: running[id], DNSManual: v.DNS.Manual, DNSAcked: p.DNSAcked,
			GatewayPrivileged: len(priv[id]) > 0, PrivilegedServices: priv[id]}
		if rs, err := h.providerRangesLocked(t); err == nil {
			pin.Ranges = rs
		}
		if v.Identity.Source == templates.VPNSourceHook {
			pm := h.vpnProviderMap(id)
			pin.Stale = pm == nil || pm.refreshedAt.IsZero() || !now.Before(pm.staleAfter)
			if pm != nil {
				pin.LastError, pin.DNSError = pm.lastErr, pm.lastDNSErr
				for _, d := range pm.problems {
					switch d.Reason {
					case vpn.DropDuplicate:
						pin.Duplicates++
					case vpn.DropOutside:
						pin.Outside++
					case vpn.DropUnresolved:
						pin.Unresolved++
					}
				}
				for _, d := range pm.devices {
					if mt := pm.meta[d.IP]; isAdmin(d.User) && mt.LastSeen != nil {
						seen(*mt.LastSeen)
					} else if isAdmin(d.User) && mt.Online {
						seen(now)
					}
				}
			}
		}
		in.Providers = append(in.Providers, pin)
	}
	for _, d := range h.st.VPN.Devices {
		dv := doctor.VPNDeviceIn{ID: d.ID, User: d.User, Name: d.Name, Created: d.Created, Expires: d.Expires}
		if at, ok := hs[d.PublicKey]; ok {
			at := at
			dv.LastHandshake = &at
			if isAdmin(d.User) {
				seen(at)
			}
		}
		in.Devices = append(in.Devices, dv)
	}
	h.mu.RUnlock()
	return in
}

// vpnGatewaysUp: wired provider → its ingress service has a running
// container.
func (h *Hub) vpnGatewaysUp(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	if h.engine == nil {
		return out
	}
	h.mu.RLock()
	var ts []templates.Template
	for id := range h.st.VPN.Providers {
		if t := h.findLocked(id); t != nil && t.Manifest.VPN != nil {
			ts = append(ts, *t)
		}
	}
	h.mu.RUnlock()
	for i := range ts {
		cs, _, err := h.appContainers(ctx, &ts[i])
		if err == nil && runningContainer(cs, ts[i].Manifest.VPN.Ingress.Service) != nil {
			out[ts[i].ID] = true
		}
	}
	return out
}
