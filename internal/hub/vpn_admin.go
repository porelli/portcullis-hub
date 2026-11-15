package hub

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/vpn"
)

// Settings → VPN and the admin overview (contract §11 GET /api/vpn, PUT
// /api/vpn/settings). Never key material.

// VPNView is GET /api/vpn.
type VPNView struct {
	Mode        string            `json:"mode"`
	PublicEnrol bool              `json:"public_enrol"`
	WG          VPNWGView         `json:"wg"`
	Builtin     *VPNBuiltinView   `json:"builtin"`
	Providers   []VPNProviderView `json:"providers"`
	Settings    VPNSettingsView   `json:"settings"`
	// FailedClosed: instances stopped because a narrowing VPN change
	// couldn't be applied.
	FailedClosed []string `json:"failed_closed"`
	// Reach: every instance set to anything but plain internet.
	Reach map[string]state.Reach `json:"reach"`
}

// VPNWGView is the wg service's health.
type VPNWGView struct {
	Up    bool   `json:"up"`
	Error string `json:"error"`
}

// VPNBuiltinView is the built-in provider (nil: off).
type VPNBuiltinView struct {
	Subnet  string `json:"subnet"`
	Port    int    `json:"port"`
	Devices int    `json:"devices"`
	Online  int    `json:"online"`
}

// VPNProviderView is one VPN-capable instance (wired or not).
type VPNProviderView struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	Source      string            `json:"source"`
	Wired       bool              `json:"wired"`
	Stale       bool              `json:"stale"`
	Ranges      []string          `json:"ranges"`
	Devices     int               `json:"devices"`
	Online      int               `json:"online"`
	RefreshedAt *time.Time        `json:"refreshed_at"`
	LastError   string            `json:"last_error"`
	Compat      *templates.Compat `json:"compat"`
	// Problems are the devices left out of the map and why (the VPN
	// tab), DNS the dns hook's state.
	Problems   []vpn.Dropped     `json:"problems"`
	DNSManual  bool              `json:"dns_manual"`
	DNSAcked   bool              `json:"dns_acked"`
	DNSError   string            `json:"dns_error"`
	DNSRecords []vpn.Record      `json:"dns_records"`
	Static     []state.VPNStatic `json:"static"`
	Refresh    string            `json:"refresh"`
}

// VPNSettingsView is Settings → VPN.
type VPNSettingsView struct {
	UsersGroup       string `json:"users_group"`
	DevicesPerPerson int    `json:"devices_per_person"`
	Expiry           string `json:"expiry"`
}

// VPNSettingsUpdate changes the set fields only.
type VPNSettingsUpdate struct {
	UsersGroup       *string `json:"users_group"`
	DevicesPerPerson *int    `json:"devices_per_person"`
	Expiry           *string `json:"expiry"`
}

// VPNOverview is the VPN admin view.
func (h *Hub) VPNOverview(ctx context.Context) VPNView {
	st, serr := h.wgStatus()
	hs := st.Handshakes()
	now := h.vpnrt.now()
	core := h.vpnCoreEnv()
	out := VPNView{Mode: core.Mode, PublicEnrol: core.PublicEnrol, Providers: []VPNProviderView{}, FailedClosed: h.vpnFailedClosed()}
	if out.FailedClosed == nil {
		out.FailedClosed = []string{}
	}
	switch {
	case serr != nil:
		out.WG.Error = serr.Error()
	case !st.Edge.OK:
		out.WG.Error = st.Edge.Error
	default:
		out.WG.Up = true
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out.Reach = maps.Clone(h.st.Reach)
	if out.Reach == nil {
		out.Reach = map[string]state.Reach{}
	}
	out.Settings = VPNSettingsView{UsersGroup: h.st.VPN.UsersGroup, DevicesPerPerson: h.devicesPerPersonLocked(), Expiry: h.st.VPN.Expiry}
	if out.Settings.Expiry == "" {
		out.Settings.Expiry = "1y"
	}
	if ps, ok := h.builtinOnLocked(st); ok && ps != nil {
		b := &VPNBuiltinView{Subnet: ps.Subnet, Port: ps.Port}
		for _, d := range h.st.VPN.Devices {
			b.Devices++
			if at, ok := hs[d.PublicKey]; ok && now.Sub(at) < vpnOnlineWindow {
				b.Online++
			}
		}
		out.Builtin = b
	}
	for i := range h.instances {
		t := &h.instances[i]
		if t.Manifest.VPN == nil {
			continue
		}
		v := t.Manifest.VPN
		p, wired := h.st.VPN.Providers[t.ID]
		pv := VPNProviderView{ID: t.ID, Label: v.Label, Source: v.Identity.Source, Wired: wired, Ranges: []string{}, Compat: t.Compat,
			Problems: []vpn.Dropped{}, DNSManual: v.DNS.Manual, DNSAcked: p.DNSAcked, DNSRecords: []vpn.Record{}, Static: []state.VPNStatic{}}
		refresh := time.Duration(p.Refresh)
		if refresh == 0 {
			refresh = v.Identity.EffectiveRefresh()
		}
		pv.Refresh = refresh.String()
		h.vpnrt.mu.Lock()
		if why := h.vpnrt.overlapBad[t.ID]; why != "" {
			pv.LastError = why
		}
		h.vpnrt.mu.Unlock()
		if rs, err := h.providerRangesLocked(t); err == nil {
			pv.Ranges = vpn.Strings(rs)
		} else {
			pv.LastError = err.Error()
		}
		if v.Identity.Source == templates.VPNSourceStatic {
			pv.Static = append(pv.Static, h.st.VPN.Static[t.ID]...)
			pv.Devices = len(pv.Static)
		} else if pm := h.vpnProviderMap(t.ID); pm != nil {
			pv.Devices = len(pm.devices)
			for _, m := range pm.meta {
				if m.Online {
					pv.Online++
				}
			}
			if !pm.refreshedAt.IsZero() {
				ra := pm.refreshedAt
				pv.RefreshedAt = &ra
			}
			pv.Stale = pm.refreshedAt.IsZero() || !now.Before(pm.staleAfter)
			if pm.lastErr != "" {
				pv.LastError = pm.lastErr
			}
			pv.Problems = append(pv.Problems, pm.problems...)
			pv.DNSError = pm.lastDNSErr
			if pm.gateway.IsValid() {
				pv.DNSRecords = h.vpnDNSRecordsLocked(pm.gateway)
			}
		} else if wired {
			pv.Stale = true
		}
		out.Providers = append(out.Providers, pv)
	}
	slices.SortFunc(out.Providers, func(a, b VPNProviderView) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// SetVPNSettings changes Settings → VPN (the set fields only): the users
// group (an existing group, "" = every person), devices per person 1–100,
// the expiry 30d, 90d, 1y, never or a duration of at least 30 days.
// Audited vpn.settings.
func (h *Hub) SetVPNSettings(ctx context.Context, actor directory.Actor, u VPNSettingsUpdate) (err error) {
	var parts []string
	defer func() {
		if len(parts) > 0 || err != nil {
			h.auditOp(actor, "vpn.settings", "vpn", strings.Join(parts, " "), err)
		}
	}()
	if u.DevicesPerPerson != nil && (*u.DevicesPerPerson < 1 || *u.DevicesPerPerson > vpnMaxDevicesPerPerson) {
		return statusErr(http.StatusBadRequest, "devices_per_person: 1–%d", vpnMaxDevicesPerPerson)
	}
	if u.Expiry != nil {
		if _, err := vpnExpiryOf(*u.Expiry); err != nil || *u.Expiry == "" {
			return statusErr(http.StatusBadRequest, "expiry: 30d, 90d, 1y, never or a duration of at least 30 days")
		}
	}
	if u.UsersGroup != nil && *u.UsersGroup != "" {
		m, merr := h.vpnMembership(ctx)
		if merr != nil {
			return statusErr(http.StatusServiceUnavailable, "the directory is unavailable: try again later")
		}
		if _, ok := m.Groups[*u.UsersGroup]; !ok {
			return statusErr(http.StatusBadRequest, "unknown group %s", clip(*u.UsersGroup, 64))
		}
	}
	h.mu.Lock()
	prev := h.st.VPN
	if u.UsersGroup != nil && *u.UsersGroup != prev.UsersGroup {
		h.st.VPN.UsersGroup = *u.UsersGroup
		g := clip(*u.UsersGroup, 64)
		if g == "" {
			g = "(everyone)" // a widening: every person may use the VPN (M18)
		}
		parts = append(parts, "users_group="+g)
	}
	if u.DevicesPerPerson != nil && *u.DevicesPerPerson != prev.DevicesPerPerson {
		h.st.VPN.DevicesPerPerson = *u.DevicesPerPerson
		parts = append(parts, fmt.Sprintf("devices_per_person=%d", *u.DevicesPerPerson))
	}
	if u.Expiry != nil && *u.Expiry != prev.Expiry {
		h.st.VPN.Expiry = *u.Expiry
		parts = append(parts, "expiry="+*u.Expiry)
	}
	if len(parts) == 0 {
		h.mu.Unlock()
		return nil
	}
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.UsersGroup, h.st.VPN.DevicesPerPerson, h.st.VPN.Expiry = prev.UsersGroup, prev.DevicesPerPerson, prev.Expiry
		h.mu.Unlock()
		parts = nil
		return err
	}
	h.mu.Unlock()
	// A narrower users group drops devices from the maps now.
	h.TriggerVPNPublish()
	return nil
}

// AllVPNDevices are every person's devices (GET /api/vpn/devices without
// a user; never key material).
func (h *Hub) AllVPNDevices(ctx context.Context, user string) []HostDeviceView {
	if user != "" {
		return h.HostVPNDevices(ctx, user)
	}
	users := map[string]bool{}
	h.mu.RLock()
	for _, d := range h.st.VPN.Devices {
		users[d.User] = true
	}
	for id := range h.st.VPN.Providers {
		for _, s := range h.st.VPN.Static[id] {
			users[s.User] = true
		}
	}
	ids := slices.Collect(maps.Keys(h.st.VPN.Providers))
	h.mu.RUnlock()
	for _, id := range ids {
		if pm := h.vpnProviderMap(id); pm != nil {
			for _, d := range pm.devices {
				users[d.User] = true
			}
		}
	}
	out := []HostDeviceView{}
	for _, u := range slices.Sorted(maps.Keys(users)) {
		for _, d := range h.VPNDevices(ctx, u) {
			out = append(out, HostDeviceView{User: u, VPNDeviceView: d})
		}
	}
	return out
}

// vpnGatewayPrivileged reports, for the doctor, the wired gateways (or
// services sharing their network namespace) whose running containers
// have NET_ADMIN, privileged or host devices: provider id → services.
// The inspects go through the guarded engine.
func (h *Hub) vpnGatewayPrivileged(ctx context.Context) map[string][]string {
	out := map[string][]string{}
	if h.noEngine() {
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
		t := &ts[i]
		routes, err := templates.ParseRoutes(t.ReadCompose())
		if err != nil {
			continue
		}
		ing := t.Manifest.VPN.Ingress.Service
		cs, _, err := h.appContainers(ctx, t)
		if err != nil {
			continue
		}
		for _, c := range cs {
			svc := c.Labels[docker.LabelService]
			if ns, ok := routes.NetNS(svc); !ok || ns != ing {
				continue
			}
			info, err := h.rt.Inspect(ctx, c.ID)
			if err != nil {
				continue
			}
			if info.Privileged || len(info.Devices) > 0 || slices.ContainsFunc(info.CapAdd, func(c string) bool {
				c = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
				return c == "NET_ADMIN" || c == "ALL"
			}) {
				out[t.ID] = append(out[t.ID], svc)
			}
		}
		slices.Sort(out[t.ID])
	}
	return out
}
