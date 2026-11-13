package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/vpn"
)

// Built-in VPN devices (contract §5.1, §16; spec §10): a person adds one
// on people.<d>/vpn/ after a fresh sign-in, with a key pair made in the
// browser (only the public key reaches the Hub); the host operator can
// add one for anybody through the control socket. Every change rewrites
// vpn.json; removed addresses are quarantined 7 days. No key material is
// ever audited, logged or returned beyond the public key's own device.

// ListenerPeopleVPN is the VPN page's fresh-auth verifier (redirect
// https://people.<d>/vpn/, contract §8 per-host model).
const ListenerPeopleVPN = "people-vpn"

// Built-in client values (contract §16).
const (
	BuiltinAllowedIPsSuffix = "/32"
	defaultVPNPort          = 51820
	// vpnOnlineWindow: a handshake this recent counts as online.
	vpnOnlineWindow = 3 * time.Minute
	// AdminDeviceWindow: the lock-out guard's "seen recently".
	AdminDeviceWindow = 10 * time.Minute
	// HostActor is the audit actor of the host control socket.
	HostActor = "host"
	// vpnMaxDevicesPerPerson bounds Settings → VPN's devices per person.
	vpnMaxDevicesPerPerson = 100
)

// VPNDeviceConfig is what the page needs to build a device's WireGuard
// configuration (never a private key).
type VPNDeviceConfig struct {
	Address         string `json:"address"`
	ServerPublicKey string `json:"server_public_key"`
	Endpoint        string `json:"endpoint"`
	AllowedIPs      string `json:"allowed_ips"`
	DNS             string `json:"dns"`
	MTU             int    `json:"mtu"`
}

// VPNDeviceView is one device of a person, from any provider.
type VPNDeviceView struct {
	ID            string     `json:"id"`
	Provider      string     `json:"provider"`
	ProviderLabel string     `json:"provider_label"`
	Name          string     `json:"name"`
	Address       string     `json:"address"`
	LastSeen      *time.Time `json:"last_seen"`
	Expires       *time.Time `json:"expires"`
	Online        bool       `json:"online"`
	// Managed: a built-in device (rename and remove here); else the
	// provider's app manages it.
	Managed bool `json:"managed"`
}

// HostInfo is what the host CLI's lock-out guard and overlap checks read
// (GET /host/vpn/info).
type HostInfo struct {
	LocalNetworks   []string `json:"local_networks"`
	ProviderRanges  []string `json:"provider_ranges"`
	AdminDeviceSeen bool     `json:"admin_device_seen"`
}

// vpnExpiryOf is Settings → VPN's expiry as a lifetime (0 = never).
func vpnExpiryOf(s string) (time.Duration, error) {
	switch s {
	case "", "1y":
		return vpn.DefaultExpiry, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	case "90d":
		return 90 * 24 * time.Hour, nil
	case "never":
		return 0, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		if d, err := strconv.Atoi(n); err == nil && d >= 30 && strconv.Itoa(d) == n {
			return time.Duration(d) * 24 * time.Hour, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < vpn.MinExpiry {
		return 0, fmt.Errorf("expiry: 30d, 90d, 1y, never or a duration of at least 30 days")
	}
	return d, nil
}

// devicesPerPersonLocked is the built-in device limit.
func (h *Hub) devicesPerPersonLocked() int {
	if n := h.st.VPN.DevicesPerPerson; n > 0 {
		return n
	}
	return vpn.DefaultDevicesPerPerson
}

func newDeviceID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// builtinConfigLocked is device d's client configuration.
func (h *Hub) builtinConfigLocked(ps *vpn.PeopleState, d state.VPNDevice) *VPNDeviceConfig {
	sub, _ := netip.ParsePrefix(ps.Subnet)
	server := vpn.ServerAddr(sub).String()
	port := ps.Port
	if port == 0 {
		port = defaultVPNPort
	}
	mtu := ps.MTU
	if mtu == 0 {
		mtu = vpn.BuiltinMTU
	}
	return &VPNDeviceConfig{Address: d.IP, ServerPublicKey: ps.PublicKey,
		Endpoint: fmt.Sprintf("%s:%d", strings.ToLower(h.cfg.Domain), port), AllowedIPs: server + BuiltinAllowedIPsSuffix, DNS: server, MTU: mtu}
}

// AddVPNDevice adds a built-in device for user after a fresh sign-in on
// the VPN page (contract §5.1). 400: a bad name or key; 409: the builtin
// off, a key in use, the device limit; 403: not a VPN user, or the proof
// refused. Audited vpn.device_added (detail the name; never a key).
func (h *Hub) AddVPNDevice(ctx context.Context, user, name, publicKey string, p freshauth.Proof) (*VPNDeviceConfig, error) {
	user = strings.ToLower(user)
	return h.addVPNDevice(ctx, directory.Human(user), user, name, publicKey, func(ctx context.Context) error {
		return h.vpnFreshAuth(ctx, p, user)
	})
}

// vpnFreshAuth checks a VPN page proof: the people template's fresh
// sign-in through the /vpn/ verifier, and (defence in depth) the
// caller's own, at most freshauth.MaxAge old.
func (h *Hub) vpnFreshAuth(ctx context.Context, p freshauth.Proof, user string) error {
	res, _, err := h.checkFreshAuthOn(ctx, ListenerPeopleVPN, govCore("people"), p, user)
	if err != nil {
		return err
	}
	if res == nil || res.Result == nil || !strings.EqualFold(res.User, user) || h.vpnrt.now().Sub(res.AuthTime) > freshauth.MaxAge {
		return errFreshAuth
	}
	return nil
}

// HostAddVPNDevice is AddVPNDevice for the host operator (the control
// socket only, `./portcullis vpn add-device`): no proof; audited with the
// actor host.
func (h *Hub) HostAddVPNDevice(ctx context.Context, user, name, publicKey string) (*VPNDeviceConfig, error) {
	user = strings.ToLower(strings.TrimSpace(user))
	return h.addVPNDevice(ctx, directory.Human(HostActor), user, name, publicKey, nil)
}

func (h *Hub) addVPNDevice(ctx context.Context, actor directory.Actor, user, name, publicKey string, fresh func(context.Context) error) (cfg *VPNDeviceConfig, err error) {
	var dev state.VPNDevice
	defer func() {
		target := user
		if dev.ID != "" {
			target = user + "/" + dev.ID
		}
		h.auditOp(actor, "vpn.device_added", target, clip(name, 64), err)
	}()
	if !validDeviceName(name) {
		return nil, statusErr(http.StatusBadRequest, "the device name must be one line of 1–64 characters")
	}
	if !vpn.ValidPublicKey(publicKey) {
		return nil, statusErr(http.StatusBadRequest, "not a valid WireGuard public key (32 bytes, base64)")
	}
	st, _ := h.wgStatus()
	h.mu.RLock()
	ps, on := h.builtinOnLocked(st)
	h.mu.RUnlock()
	if !on || ps == nil {
		return nil, statusErr(http.StatusConflict, "the built-in VPN is off")
	}
	members, merr := h.vpnMembership(ctx)
	if merr != nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the directory is unavailable: try again later")
	}
	h.mu.RLock()
	allowed := vpnUserOK(members, h.st.VPN.UsersGroup, user)
	h.mu.RUnlock()
	if !allowed {
		return nil, statusErr(http.StatusForbidden, "you are not allowed to use the VPN")
	}
	if fresh != nil {
		if err := fresh(ctx); err != nil {
			return nil, err
		}
	}
	sub, perr := netip.ParsePrefix(ps.Subnet)
	if perr != nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the VPN service reports no subnet")
	}
	now := h.vpnrt.now().UTC()
	h.mu.Lock()
	n := 0
	used := map[netip.Addr]bool{}
	for _, d := range h.st.VPN.Devices {
		if d.PublicKey == publicKey {
			h.mu.Unlock()
			return nil, statusErr(http.StatusConflict, "this public key is already used by a device")
		}
		if d.User == user {
			n++
		}
		if a, err := netip.ParseAddr(d.IP); err == nil {
			used[a] = true
		}
	}
	if n >= h.devicesPerPersonLocked() {
		h.mu.Unlock()
		return nil, statusErr(http.StatusConflict, "at most %d devices per person", h.devicesPerPersonLocked())
	}
	quar := map[netip.Addr]time.Time{}
	for ip, at := range h.st.VPN.Quarantine {
		if a, err := netip.ParseAddr(ip); err == nil {
			quar[a] = at
		}
	}
	addr, aerr := vpn.NextFree(sub, used, quar, now)
	if aerr != nil {
		h.mu.Unlock()
		return nil, statusErr(http.StatusConflict, "%v", aerr)
	}
	life, _ := vpnExpiryOf(h.st.VPN.Expiry)
	dev = state.VPNDevice{ID: newDeviceID(), User: user, UUID: members.UUIDs[user], Name: name, IP: addr.String(), PublicKey: publicKey, Created: now}
	if life > 0 {
		exp := now.Add(life)
		dev.Expires = &exp
	}
	h.st.VPN.Devices = append(h.st.VPN.Devices, dev)
	delete(h.st.VPN.Quarantine, addr.String())
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.Devices = h.st.VPN.Devices[:len(h.st.VPN.Devices)-1]
		h.mu.Unlock()
		dev = state.VPNDevice{}
		return nil, err
	}
	cfg = h.builtinConfigLocked(ps, dev)
	h.mu.Unlock()
	h.vpnChanged()
	return cfg, nil
}

// vpnDeviceIndexLocked is built-in device id's index (-1: none).
func (h *Hub) vpnDeviceIndexLocked(id string) int {
	return slices.IndexFunc(h.st.VPN.Devices, func(d state.VPNDevice) bool { return d.ID == id })
}

// RenameVPNDevice renames user's built-in device id (404 when it isn't
// theirs). Audited vpn.device_renamed ("<old> -> <new>").
func (h *Hub) RenameVPNDevice(ctx context.Context, actor directory.Actor, user, id, name string) (err error) {
	user = strings.ToLower(user)
	old := ""
	defer func() {
		h.auditOp(actor, "vpn.device_renamed", user+"/"+clip(id, 32), clip(old, 64)+" -> "+clip(name, 64), err)
	}()
	if !validDeviceName(name) {
		return statusErr(http.StatusBadRequest, "the device name must be one line of 1–64 characters")
	}
	h.mu.Lock()
	i := h.vpnDeviceIndexLocked(id)
	if i < 0 || h.st.VPN.Devices[i].User != user {
		h.mu.Unlock()
		return statusErr(http.StatusNotFound, "no such device")
	}
	old = h.st.VPN.Devices[i].Name
	h.st.VPN.Devices[i].Name = name
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.Devices[i].Name = old
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()
	h.TriggerVPNPublish()
	return nil
}

// VPNDeviceOwner is built-in device id's owner ("" = none).
func (h *Hub) VPNDeviceOwner(id string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if i := h.vpnDeviceIndexLocked(id); i >= 0 {
		return h.st.VPN.Devices[i].User
	}
	return ""
}

// RemoveVPNDevice removes built-in device id (404 when there is none;
// the caller checks who may). Its address is quarantined. Audited
// vpn.device_removed.
func (h *Hub) RemoveVPNDevice(ctx context.Context, actor directory.Actor, id string) error {
	return h.removeVPNDevices(actor, "vpn.device_removed", "", func(d state.VPNDevice) bool { return d.ID == id }, true)
}

// removeVPNDevices removes every built-in device match keeps, quarantines
// their addresses and audits each (action, detail reason); none removed
// is a 404 when one was asked for.
func (h *Hub) removeVPNDevices(actor directory.Actor, action, reason string, match func(state.VPNDevice) bool, want bool) error {
	now := h.vpnrt.now().UTC()
	h.mu.Lock()
	prev := slices.Clone(h.st.VPN.Devices)
	prevQ := maps.Clone(h.st.VPN.Quarantine)
	var gone []state.VPNDevice
	h.st.VPN.Devices = slices.DeleteFunc(h.st.VPN.Devices, func(d state.VPNDevice) bool {
		if match(d) {
			gone = append(gone, d)
			return true
		}
		return false
	})
	if len(gone) == 0 {
		h.mu.Unlock()
		if want {
			return statusErr(http.StatusNotFound, "no such device")
		}
		return nil
	}
	for _, d := range gone {
		h.st.VPN.Quarantine[d.IP] = now
	}
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.Devices, h.st.VPN.Quarantine = prev, prevQ
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()
	for _, d := range gone {
		detail := clip(d.Name, 64)
		if reason != "" {
			detail += " (reason=" + reason + ")"
		}
		h.auditOp(actor, action, d.User+"/"+d.ID, detail, nil)
	}
	h.vpnChanged()
	return nil
}

// RenewVPNDevice re-keys user's built-in device id after a fresh sign-in:
// same id and address, the new public key, a new expiry. Audited
// vpn.device_added (detail "renewed").
func (h *Hub) RenewVPNDevice(ctx context.Context, user, id, publicKey string, p freshauth.Proof) (cfg *VPNDeviceConfig, err error) {
	user = strings.ToLower(user)
	defer func() { h.auditOp(directory.Human(user), "vpn.device_added", user+"/"+clip(id, 32), "", err) }()
	if !vpn.ValidPublicKey(publicKey) {
		return nil, statusErr(http.StatusBadRequest, "not a valid WireGuard public key (32 bytes, base64)")
	}
	h.mu.RLock()
	i := h.vpnDeviceIndexLocked(id)
	mine := i >= 0 && h.st.VPN.Devices[i].User == user
	h.mu.RUnlock()
	if !mine {
		return nil, statusErr(http.StatusNotFound, "no such device")
	}
	if err := h.vpnFreshAuth(ctx, p, user); err != nil {
		return nil, err
	}
	st, _ := h.wgStatus()
	now := h.vpnrt.now().UTC()
	h.mu.Lock()
	defer h.mu.Unlock()
	ps, on := h.builtinOnLocked(st)
	if !on || ps == nil {
		return nil, statusErr(http.StatusConflict, "the built-in VPN is off")
	}
	i = h.vpnDeviceIndexLocked(id)
	if i < 0 || h.st.VPN.Devices[i].User != user {
		return nil, statusErr(http.StatusNotFound, "no such device")
	}
	for j, d := range h.st.VPN.Devices {
		if j != i && d.PublicKey == publicKey {
			return nil, statusErr(http.StatusConflict, "this public key is already used by a device")
		}
	}
	prev := h.st.VPN.Devices[i]
	d := prev
	d.PublicKey = publicKey
	d.Expires = nil
	if life, _ := vpnExpiryOf(h.st.VPN.Expiry); life > 0 {
		exp := now.Add(life)
		d.Expires = &exp
	}
	h.st.VPN.Devices[i] = d
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.Devices[i] = prev
		return nil, err
	}
	cfg = h.builtinConfigLocked(ps, d)
	h.goBackground(h.vpnChanged)
	return cfg, nil
}

// VPNDevices are user's devices on every provider (built-in ones
// managed here, the others read-only: managed in their app; static
// assignments included).
func (h *Hub) VPNDevices(ctx context.Context, user string) []VPNDeviceView {
	user = strings.ToLower(user)
	st, _ := h.wgStatus()
	hs := st.Handshakes()
	now := h.vpnrt.now()
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []VPNDeviceView{}
	for _, d := range h.st.VPN.Devices {
		if d.User != user {
			continue
		}
		v := VPNDeviceView{ID: d.ID, Provider: vpn.BuiltinID, ProviderLabel: "Portcullis VPN", Name: d.Name, Address: d.IP, Expires: d.Expires, Managed: true}
		if at, ok := hs[d.PublicKey]; ok {
			at := at
			v.LastSeen, v.Online = &at, now.Sub(at) < vpnOnlineWindow
		}
		out = append(out, v)
	}
	for _, id := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		t := h.findLocked(id)
		if t == nil || t.Manifest.VPN == nil {
			continue
		}
		label := t.Manifest.VPN.Label
		if t.Manifest.VPN.Identity.Source == templates.VPNSourceStatic {
			for _, s := range h.st.VPN.Static[id] {
				if s.User == user {
					out = append(out, VPNDeviceView{ID: id + ":" + s.IP, Provider: id, ProviderLabel: label, Name: s.Name, Address: s.IP})
				}
			}
			continue
		}
		pm := h.vpnProviderMap(id)
		if pm == nil {
			continue
		}
		for _, d := range pm.devices {
			if d.User != user {
				continue
			}
			m := pm.meta[d.IP]
			out = append(out, VPNDeviceView{ID: d.DeviceID, Provider: id, ProviderLabel: label, Name: d.Name, Address: d.IP, Expires: d.Expires, LastSeen: m.LastSeen, Online: m.Online})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Managed != out[j].Managed {
			return out[i].Managed
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// VPNHostInfo is the host CLI's view: Local networks, every provider's
// ranges (the built-in subnet included), and whether an administrator
// (lldap_admin) had a device seen within AdminDeviceWindow on the
// built-in or a hook provider (statics never count).
func (h *Hub) VPNHostInfo(ctx context.Context) HostInfo {
	members, _ := h.vpnMembership(ctx)
	st, _ := h.wgStatus()
	hs := st.Handshakes()
	now := h.vpnrt.now()
	h.mu.RLock()
	defer h.mu.RUnlock()
	info := HostInfo{LocalNetworks: []string{}, ProviderRanges: []string{}}
	for _, p := range h.localNetworksLocked() {
		info.LocalNetworks = append(info.LocalNetworks, p.String())
	}
	info.ProviderRanges = append(info.ProviderRanges, h.vpnAllowRangesLocked([]string{state.ReachAny})...)
	info.ProviderRanges = slices.DeleteFunc(info.ProviderRanges, func(s string) bool { return s == vpnNoClient })
	admin := func(u string) bool {
		if members == nil {
			return false
		}
		_, ok := members.Users[u][lldap.AdminGroup]
		return ok && !members.Expired[u][lldap.AdminGroup]
	}
	for _, d := range h.st.VPN.Devices {
		if at, ok := hs[d.PublicKey]; ok && admin(d.User) && now.Sub(at) <= AdminDeviceWindow {
			info.AdminDeviceSeen = true
		}
	}
	for id := range h.st.VPN.Providers {
		pm := h.vpnProviderMap(id)
		if pm == nil {
			continue
		}
		for _, d := range pm.devices {
			if m := pm.meta[d.IP]; admin(d.User) && (m.Online || m.LastSeen != nil && now.Sub(*m.LastSeen) <= AdminDeviceWindow) {
				info.AdminDeviceSeen = true
			}
		}
	}
	return info
}

// RunVPNExpiry expires built-in devices (audited vpn.device_expired) and
// revokes those whose owner left the VPN users group, was disabled or
// deleted, or re-created (another LLDAP uuid), every interval.
func (h *Hub) RunVPNExpiry(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.vpnExpireOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// vpnExpireOnce is one RunVPNExpiry pass.
func (h *Hub) vpnExpireOnce(ctx context.Context) {
	now := h.vpnrt.now()
	sys := directory.Human("hub")
	if err := h.removeVPNDevices(sys, "vpn.device_expired", "", func(d state.VPNDevice) bool { return expired(d.Expires, now) }, false); err != nil {
		log.Printf("vpn: expiring devices: %v", err)
	}
	members, err := h.vpnMembership(ctx)
	if err != nil || members == nil {
		return // revocations wait for the directory (vpn.json still filters)
	}
	h.mu.RLock()
	group := h.st.VPN.UsersGroup
	h.mu.RUnlock()
	why := func(d state.VPNDevice) string {
		if _, ok := members.Users[d.User]; !ok {
			return "person deleted or disabled"
		}
		if members.UUIDs[d.User] != d.UUID {
			return "account re-created"
		}
		if !vpnUserOK(members, group, d.User) {
			return "not a VPN user"
		}
		return ""
	}
	for _, reason := range []string{"person deleted or disabled", "account re-created", "not a VPN user"} {
		if err := h.removeVPNDevices(sys, "vpn.device_removed", reason, func(d state.VPNDevice) bool { return why(d) == reason }, false); err != nil {
			log.Printf("vpn: revoking devices: %v", err)
		}
	}
}

// PersonVPNDevices are user's devices on every provider, for People →
// person (administrators and sign_in_help holders who may target user:
// 403 otherwise; 404 for an unknown person).
func (h *Hub) PersonVPNDevices(ctx context.Context, c *directory.Caller, user string) ([]VPNDeviceView, error) {
	u, _, err := h.helpPerson(ctx, c, user)
	if err != nil {
		return nil, err
	}
	return h.VPNDevices(ctx, u), nil
}

// RemovePersonVPNDevice removes user's built-in device id for People →
// person (the same rule); a marketplace device is 409 "managed in
// <label>", anything else 404.
func (h *Hub) RemovePersonVPNDevice(ctx context.Context, c *directory.Caller, user, id string) error {
	u, _, err := h.helpPerson(ctx, c, user)
	if err != nil {
		return err
	}
	if h.VPNDeviceOwner(id) == u {
		return h.RemoveVPNDevice(ctx, c.Actor(), id)
	}
	for _, d := range h.VPNDevices(ctx, u) {
		if d.ID == id && !d.Managed {
			return statusErr(http.StatusConflict, "managed in %s", d.ProviderLabel)
		}
	}
	return statusErr(http.StatusNotFound, "no such device")
}

// HostDeviceView is a device as the host CLI lists it (with its owner).
type HostDeviceView struct {
	User string `json:"user"`
	VPNDeviceView
}

// HostVPNDevices lists user's devices on every provider ("" = every
// person's built-in devices), for `hub vpn devices`.
func (h *Hub) HostVPNDevices(ctx context.Context, user string) []HostDeviceView {
	out := []HostDeviceView{}
	var users []string
	if user = strings.ToLower(strings.TrimSpace(user)); user != "" {
		users = []string{user}
	} else {
		h.mu.RLock()
		seen := map[string]bool{}
		for _, d := range h.st.VPN.Devices {
			if !seen[d.User] {
				seen[d.User] = true
				users = append(users, d.User)
			}
		}
		h.mu.RUnlock()
		sort.Strings(users)
	}
	for _, u := range users {
		for _, d := range h.VPNDevices(ctx, u) {
			if user == "" && !d.Managed {
				continue
			}
			out = append(out, HostDeviceView{User: u, VPNDeviceView: d})
		}
	}
	return out
}
