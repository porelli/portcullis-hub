package hub

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/vpn"
)

// VPN providers (contract §3.3, §11, §16; spec §3.3, §5, §6): wiring a
// template instance with a vpn: block (an edge slot: port 9001+slot and
// gateway .16+slot on portcullis-vpn), its identity hook's device map
// (memory only, never in state.yaml), its dns hook, static assignments,
// and vpn.json v2 publishing. The hooks run outside Hub.mu, through the
// guarded engine; their stdout is never stored, logged or audited.

// The fail-closed 409s (contract §11).
var (
	ErrVPNNotRunning  = &StatusError{Status: http.StatusConflict, Err: errors.New("the VPN service isn't running: run ./portcullis vpn init on the host")}
	ErrNoLiveProvider = &StatusError{Status: http.StatusConflict, Err: errors.New("wire a VPN first")}
)

// Core env keys (secrets/hub/core.env, contract §2): never template
// variables.
const (
	VarVPNMode        = "PORTCULLIS_VPN_MODE"
	VarVPNPublicEnrol = "PORTCULLIS_VPN_PUBLIC_ENROL"
	VarVPNNet         = "PORTCULLIS_VPN_NET"
	VarVPNBuiltin     = "PORTCULLIS_VPN_BUILTIN"
	VarVPNWGIP        = "PORTCULLIS_VPN_WG_IP"
	// VarVPNReserved: core's reserved ranges (a comma or space separated
	// CIDR list): no provider range may overlap one.
	VarVPNReserved = "PORTCULLIS_VPN_RESERVED_RANGES"

	VPNModeApps   = "apps"
	VPNModeAdmin  = "admin"
	VPNModeServer = "server"

	// DefaultVPNNet is portcullis-vpn's default subnet.
	DefaultVPNNet = "172.31.254.0/26"
	// DefaultVPNStatusFile is wg's status.json as the Hub mounts it.
	DefaultVPNStatusFile = "/wg-data/status.json"
	// DefaultVPNDocDir is the vpn_doc volume as the Hub mounts it, and
	// DefaultVPNDocGID vpn.json's group (core's CT_GID_VPN_DOC: the Hub,
	// wg and group-gate only).
	DefaultVPNDocDir = "/vpn-doc"
	DefaultVPNDocGID = 10007
)

// VPNKeycloak resolves oidc_sub owners (keycloak.Client.UsernamesByID).
type VPNKeycloak interface {
	UsernamesByID(ctx context.Context) (map[string]string, error)
}

// providerMap is one hook provider's last good device map and its
// freshness (memory only, never in state.yaml).
type providerMap struct {
	refreshedAt time.Time
	staleAfter  time.Time
	gateway     netip.Addr
	devices     []vpn.Device
	meta        map[string]deviceMeta // by IP: online / last seen
	problems    []vpn.Dropped
	// rangeDrops: devices the last publish left out because the current
	// ranges no longer hold them.
	rangeDrops []vpn.Dropped
	lastErr    string
	lastRun    time.Time
	running    bool

	// The dns hook: the records last applied (with their gateway), the
	// last failure and attempt.
	dnsApplied string
	dnsRunning bool
	dnsTried   string
	lastDNSErr string
	lastDNSRun time.Time
}

// deviceMeta is what a hook says about a device beyond the map.
type deviceMeta struct {
	Online   bool
	LastSeen *time.Time
}

// vpnRuntime is the Hub's VPN memory (under its own mutex; lock order
// Hub.mu → vpnRuntime.mu, never the reverse; never held across an exec).
type vpnRuntime struct {
	mu   sync.Mutex
	maps map[string]*providerMap
	kc   VPNKeycloak
	// members is the last directory snapshot the publisher read (nil:
	// none yet).
	members *directory.Membership
	// people is the last good people-role status (server key, subnet),
	// used while status.json is momentarily stale.
	people *vpn.PeopleState

	// rendered: instance → its VPN render key at the last re-render
	// check (vpnRangesChanged).
	rendered map[string]string
	// pubErr / pubDelay / pubNext: the last failed vpn.json write and its
	// retry backoff; validAt anchors valid_until; testWrite replaces
	// vpn.WriteGroup (tests).
	pubErr    string
	pubDelay  time.Duration
	pubNext   time.Time
	validAt   time.Time
	testWrite func(path string, d vpn.Doc, gid int, now time.Time) error
	// overlapBad: wired provider → why its ranges overlap now (left out
	// of vpn.json); overlapAt: the last check.
	overlapBad map[string]string
	overlapAt  time.Time
	// renderFail: instance → its failed VPN re-render (retry, closed).
	renderFail map[string]*vpnRenderRetry

	pubMu       sync.Mutex // serialises publishes
	pubPending  atomic.Bool
	lastWritten []byte
	lastWriteAt time.Time

	now func() time.Time
}

func newVPNRuntime() *vpnRuntime {
	return &vpnRuntime{maps: map[string]*providerMap{}, rendered: map[string]string{}, renderFail: map[string]*vpnRenderRetry{}, now: time.Now}
}

// SetVPNKeycloak wires the oidc_sub resolver (nil: oidc_sub owners never
// resolve).
func (h *Hub) SetVPNKeycloak(k VPNKeycloak) {
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	h.vpnrt.kc = k
}

// vpnCore is the core env's VPN subset.
type vpnCore struct {
	Mode        string
	PublicEnrol bool
	Net         netip.Prefix
	WGIP        netip.Addr
	Builtin     bool
	// Reserved are core's reserved ranges; ReservedBad: the list didn't
	// parse (fail closed: no provider can be wired or published).
	Reserved    []netip.Prefix
	ReservedBad bool
	// ReservedDefault: the key is unset, DefaultVPNReservedRanges apply.
	ReservedDefault bool
}

// vpnCoreEnv reads the VPN keys of the core env (<ProjectDir>/.env).
// Fail closed: an unknown mode is server (everything VPN-only), a public
// enrolment that isn't exactly "true" (or unset) is off, a builtin that
// isn't "on" is off; an unparsable network keeps the default.
// vpnWGIPOK: a is a host address of net and not a gateway slot.
func vpnWGIPOK(net netip.Prefix, a netip.Addr) bool {
	if !a.Is4() || !net.Contains(a) || a == net.Addr() {
		return false
	}
	u := func(x netip.Addr) uint32 { b := x.As4(); return binary.BigEndian.Uint32(b[:]) }
	off := u(a) - u(net.Addr())
	last := uint32(1)<<(32-net.Bits()) - 1
	return off != last && (off < vpn.GatewayFirst || off > vpn.GatewayLast)
}

func (h *Hub) vpnCoreEnv() vpnCore {
	core := readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env"))
	c := vpnCore{Mode: VPNModeApps, PublicEnrol: true}
	switch m := core[VarVPNMode]; m {
	case "", VPNModeApps:
	case VPNModeAdmin, VPNModeServer:
		c.Mode = m
	default:
		log.Printf("vpn: the core env's %s %s is unknown: treated as server", VarVPNMode, clipQuoted(m))
		c.Mode = VPNModeServer
	}
	if v, ok := core[VarVPNPublicEnrol]; ok && v != "true" {
		c.PublicEnrol = false
	}
	c.Builtin = core[VarVPNBuiltin] == "on"
	c.Net = netip.MustParsePrefix(DefaultVPNNet)
	if h.cfg.VPNNet.IsValid() {
		c.Net = h.cfg.VPNNet
	} else if raw := core[VarVPNNet]; raw != "" {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Addr().Is4() && p.Bits() <= 26 {
			c.Net = p.Masked()
		} else {
			log.Printf("vpn: the core env's %s %s is not an IPv4 /26 or wider: the default is used", VarVPNNet, clipQuoted(raw))
		}
	}
	// The readers' own defaults (vpn.DefaultReserved) always apply;
	// core's list (its subnets, the link subnet, Podman's pools under
	// podman) adds to them. Unset (an older core, a hand-edited
	// core.env): the defaults only, never nothing (I8); the doctor warns.
	c.Reserved = append(c.Reserved, vpn.DefaultReserved...)
	reserved := core[VarVPNReserved]
	if strings.TrimSpace(reserved) == "" {
		c.ReservedDefault = true
	}
	for _, f := range strings.FieldsFunc(reserved, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			log.Printf("vpn: the core env's %s holds %s, not a CIDR: no VPN provider is wired or published", VarVPNReserved, clipQuoted(f))
			c.ReservedBad = true
			continue
		}
		if p = p.Masked(); !slices.Contains(c.Reserved, p) {
			c.Reserved = append(c.Reserved, p)
		}
	}
	// wg's address on portcullis-vpn, where every gateway dials the edge
	// (PORTCULLIS_VPN_EDGE): core.env's PORTCULLIS_VPN_WG_IP, else core's
	// default .3. A value outside the network, its network or broadcast
	// address, or a gateway slot (.16–.62) keeps the default, logged.
	c.WGIP = c.Net.Addr().Next().Next().Next() // .3
	if raw := core[VarVPNWGIP]; raw != "" {
		if a, err := netip.ParseAddr(raw); err == nil && vpnWGIPOK(c.Net, a) {
			c.WGIP = a
		} else {
			log.Printf("vpn: the core env's %s %s isn't a free address of %s: wg is assumed at %s", VarVPNWGIP, clipQuoted(raw), c.Net, c.WGIP)
		}
	}
	return c
}

// wgStatus is wg's status.json (vpn.ReadStatus: stale or missing = wg
// down).
func (h *Hub) wgStatus() (*vpn.Status, error) {
	if h.cfg.VPNStatusFile == "" {
		return nil, errors.New("no VPN status file is configured")
	}
	s, err := vpn.ReadStatus(h.cfg.VPNStatusFile, h.vpnrt.now())
	if err != nil {
		return nil, err
	}
	if s.People != nil && s.People.OK {
		p := *s.People
		h.vpnrt.mu.Lock()
		h.vpnrt.people = &p
		h.vpnrt.mu.Unlock()
	}
	return s, nil
}

// wgUp: status.json is fresh and the edge role is healthy.
func (h *Hub) wgUp() bool {
	s, err := h.wgStatus()
	return err == nil && s.Edge.OK
}

// builtinOnLocked: the built-in provider is on — status.json reports a
// healthy people role (or, momentarily stale, the last one did) and the
// admin hasn't turned it off. Caller holds mu (read).
func (h *Hub) builtinOnLocked(st *vpn.Status) (*vpn.PeopleState, bool) {
	if h.st.VPN.BuiltinOff {
		return nil, false
	}
	if st != nil {
		if st.People == nil || !st.People.OK {
			return nil, false
		}
		return st.People, true
	}
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	return h.vpnrt.people, h.vpnrt.people != nil
}

// vpnTemplateLocked is a provider instance's view with its vpn: block
// (400 without one, 404 for an unknown instance). Caller holds mu.
func (h *Hub) vpnTemplateLocked(id string) (*templates.Template, error) {
	t := h.findLocked(id)
	if t == nil {
		return nil, statusErr(http.StatusNotFound, "no instance %s", clip(id, 64))
	}
	if t.Manifest.VPN == nil {
		return nil, statusErr(http.StatusBadRequest, "%s is not a VPN provider (its template has no vpn: block)", id)
	}
	return t, nil
}

// providerRangesLocked is wired (or wiring) provider id's ranges.
func (h *Hub) providerRangesLocked(t *templates.Template) ([]netip.Prefix, error) {
	return templates.ResolveVPNRanges(&t.Manifest, h.st.Settings[t.ID].Values)
}

// SetVPNProvider wires (or unwires) instance id as a VPN provider
// (contract §11 PUT /api/instances/{id}/vpn-provider). Wiring needs wg
// running (ErrVPNNotRunning) and ranges that overlap neither the
// built-in subnet, another provider, a Docker network nor portcullis-vpn
// (409 naming both prefixes; Local networks may overlap). refresh 0 is
// the template's. Audited vpn.provider_wired / vpn.provider_unwired
// (target the provider id, no detail).
func (h *Hub) SetVPNProvider(ctx context.Context, actor directory.Actor, id string, wired bool, refresh time.Duration) (err error) {
	action := "vpn.provider_unwired"
	if wired {
		action = "vpn.provider_wired"
	}
	defer func() { h.auditOp(actor, action, id, "", err) }()
	var nets []docker.Network
	var st *vpn.Status
	if wired {
		if st, err = h.wgStatus(); err != nil || !st.Edge.OK {
			return ErrVPNNotRunning
		}
		if h.engine == nil {
			return statusErr(http.StatusServiceUnavailable, "no container engine: the Docker networks can't be checked")
		}
		if nets, err = h.engine.ListNetworks(ctx); err != nil {
			return statusErr(http.StatusServiceUnavailable, "listing the container networks failed: %v", err)
		}
	}
	h.mu.Lock()
	t, err := h.vpnTemplateLocked(id)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	prev, had := h.st.VPN.Providers[id]
	if !wired {
		if !had {
			h.mu.Unlock()
			return nil
		}
		delete(h.st.VPN.Providers, id)
		if err := h.saveStateLocked(); err != nil {
			h.st.VPN.Providers[id] = prev
			h.mu.Unlock()
			return err
		}
		h.mu.Unlock()
		h.vpnrt.mu.Lock()
		delete(h.vpnrt.maps, id)
		h.vpnrt.mu.Unlock()
		h.vpnChanged()
		return nil
	}
	if refresh == 0 {
		refresh = t.Manifest.VPN.Identity.EffectiveRefresh()
	}
	if refresh < vpn.RefreshMin || refresh > vpn.RefreshMax {
		h.mu.Unlock()
		return statusErr(http.StatusBadRequest, "refresh: between 15s and 10m")
	}
	ranges, err := h.providerRangesLocked(t)
	if err != nil {
		h.mu.Unlock()
		return statusErr(http.StatusConflict, "%s's client ranges: %v", id, err)
	}
	if err := h.vpnOverlapLocked(id, ranges, st, nets); err != nil {
		h.mu.Unlock()
		return err
	}
	p := prev
	if !had {
		slot, ok := h.freeSlotLocked()
		if !ok {
			h.mu.Unlock()
			return statusErr(http.StatusConflict, "at most %d VPN providers can be wired", vpn.GatewayLast-vpn.GatewayFirst+1)
		}
		p = state.VPNProvider{Slot: slot, WiredAt: h.vpnrt.now().UTC()}
	}
	p.Refresh = templates.Duration(refresh)
	h.st.VPN.Providers[id] = p
	if err := h.saveStateLocked(); err != nil {
		if had {
			h.st.VPN.Providers[id] = prev
		} else {
			delete(h.st.VPN.Providers, id)
		}
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()
	h.vpnChanged()
	return nil
}

// vpnOverlapLocked refuses ranges of provider id that overlap the
// built-in subnet, another wired provider, a Docker network or
// portcullis-vpn (409 naming both). Caller holds mu.
func (h *Hub) vpnOverlapLocked(id string, ranges []netip.Prefix, st *vpn.Status, nets []docker.Network) error {
	refuse := func(a, b netip.Prefix, what string) error {
		return statusErr(http.StatusConflict, "%s's range %s overlaps %s (%s): the provider can't be wired", id, a, b, what)
	}
	if st != nil && st.People != nil {
		if sub, err := netip.ParsePrefix(st.People.Subnet); err == nil {
			if a, b, ok := vpn.FirstOverlap(ranges, []netip.Prefix{sub}); ok {
				return refuse(a, b, "the built-in VPN subnet")
			}
		}
	}
	core := h.vpnCoreEnv()
	if a, b, ok := vpn.FirstOverlap(ranges, []netip.Prefix{core.Net}); ok {
		return refuse(a, b, "the portcullis-vpn network")
	}
	if core.ReservedBad {
		return statusErr(http.StatusConflict, "the core env's %s doesn't parse: no VPN provider can be wired", VarVPNReserved)
	}
	if a, b, ok := vpn.FirstOverlap(ranges, core.Reserved); ok {
		return refuse(a, b, "a range core reserves: Docker allocates networks (app instances' too) from these ranges")
	}
	for _, other := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		if other == id {
			continue
		}
		ot := h.findLocked(other)
		if ot == nil || ot.Manifest.VPN == nil {
			continue
		}
		ors, err := h.providerRangesLocked(ot)
		if err != nil {
			continue
		}
		if a, b, ok := vpn.FirstOverlap(ranges, ors); ok {
			return refuse(a, b, "the ranges of provider "+other)
		}
	}
	for _, n := range nets {
		if a, b, ok := vpn.FirstOverlap(ranges, n.Subnets); ok {
			return refuse(a, b, "the container network "+n.Name)
		}
	}
	return nil
}

// freeSlotLocked is the lowest edge slot no wired provider holds.
func (h *Hub) freeSlotLocked() (int, bool) {
	used := map[int]bool{}
	for _, p := range h.st.VPN.Providers {
		used[p.Slot] = true
	}
	for s := 0; s <= vpn.GatewayLast-vpn.GatewayFirst; s++ {
		if !used[s] {
			return s, true
		}
	}
	return 0, false
}

// vpnChanged follows any change of providers, devices, statics or the
// directory: the overrides whose accepted ranges moved, then vpn.json.
func (h *Hub) vpnChanged() {
	h.vpnRangesChanged()
	h.TriggerVPNPublish()
}

// vpnUserOK: user is a Portcullis person (in the directory snapshot m)
// and, when Settings → VPN names a users group, a current member of it.
func vpnUserOK(m *directory.Membership, group, user string) bool {
	if m == nil {
		return false
	}
	gs, ok := m.Users[user]
	if !ok {
		return false
	}
	if group == "" {
		return true
	}
	if _, in := gs[group]; !in {
		return false
	}
	return !m.Expired[user][group]
}

// vpnMembership reads the directory (never under mu).
func (h *Hub) vpnMembership(ctx context.Context) (*directory.Membership, error) {
	h.mu.RLock()
	p := h.people
	h.mu.RUnlock()
	if p == nil {
		return nil, errors.New("the directory isn't connected")
	}
	m, err := p.Membership(ctx, h.vpnrt.now())
	if err == nil {
		h.vpnrt.mu.Lock()
		h.vpnrt.members = m
		h.vpnrt.mu.Unlock()
	}
	return m, err
}

// validDeviceName: one line of 1–64 characters.
func validDeviceName(n string) bool {
	return strings.TrimSpace(n) != "" && len([]rune(n)) <= 64 && !templates.HasControlChars(n)
}

// AssignVPNAddress assigns static provider id's address ip to person
// user as device name (400: not a static provider, an address outside
// its ranges, a person who isn't an enabled VPN user, a bad name).
// Audited vpn.static_assigned (detail "<ip> <user>").
func (h *Hub) AssignVPNAddress(ctx context.Context, actor directory.Actor, id, ip, user, name string) (err error) {
	user = strings.ToLower(strings.TrimSpace(user))
	defer func() { h.auditOp(actor, "vpn.static_assigned", id, clip(ip, 64)+" "+clip(user, 64), err) }()
	addr, perr := netip.ParseAddr(ip)
	if perr != nil || !addr.Is4() {
		return statusErr(http.StatusBadRequest, "%s is not an IPv4 address", clip(ip, 64))
	}
	if !validDeviceName(name) {
		return statusErr(http.StatusBadRequest, "the device name must be one line of 1–64 characters")
	}
	h.mu.RLock()
	_, terr := h.vpnTemplateLocked(id)
	h.mu.RUnlock()
	if terr != nil {
		return terr
	}
	m, merr := h.vpnMembership(ctx)
	if merr != nil {
		return statusErr(http.StatusServiceUnavailable, "the directory is unavailable: %v", merr)
	}
	h.mu.Lock()
	t, err := h.vpnTemplateLocked(id)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	if t.Manifest.VPN.Identity.Source != templates.VPNSourceStatic {
		h.mu.Unlock()
		return statusErr(http.StatusBadRequest, "%s maps its devices with a hook: addresses can't be assigned by hand", id)
	}
	ranges, err := h.providerRangesLocked(t)
	if err != nil {
		h.mu.Unlock()
		return statusErr(http.StatusConflict, "%s's client ranges: %v", id, err)
	}
	if !slices.ContainsFunc(ranges, func(p netip.Prefix) bool { return p.Contains(addr) }) {
		h.mu.Unlock()
		return statusErr(http.StatusBadRequest, "%s is outside %s's ranges (%s)", addr, id, strings.Join(vpn.Strings(ranges), ", "))
	}
	if !vpnUserOK(m, h.st.VPN.UsersGroup, user) {
		h.mu.Unlock()
		return statusErr(http.StatusBadRequest, "%s is not an enabled Portcullis person allowed to use the VPN", clip(user, 64))
	}
	prev := slices.Clone(h.st.VPN.Static[id])
	next := slices.DeleteFunc(slices.Clone(prev), func(s state.VPNStatic) bool { return s.IP == addr.String() })
	next = append(next, state.VPNStatic{IP: addr.String(), User: user, Name: name})
	sort.Slice(next, func(i, j int) bool { return ipLess(next[i].IP, next[j].IP) })
	h.st.VPN.Static[id] = next
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.Static[id] = prev
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()
	h.vpnChanged()
	return nil
}

// UnassignVPNAddress removes static provider id's assignment of ip (404
// when there is none). Audited vpn.static_unassigned (detail the ip).
func (h *Hub) UnassignVPNAddress(ctx context.Context, actor directory.Actor, id, ip string) (err error) {
	defer func() { h.auditOp(actor, "vpn.static_unassigned", id, clip(ip, 64), err) }()
	h.mu.Lock()
	if _, err := h.vpnTemplateLocked(id); err != nil {
		h.mu.Unlock()
		return err
	}
	prev := h.st.VPN.Static[id]
	next := slices.DeleteFunc(slices.Clone(prev), func(s state.VPNStatic) bool { return s.IP == ip })
	if len(next) == len(prev) {
		h.mu.Unlock()
		return statusErr(http.StatusNotFound, "%s has no assignment of %s", id, clip(ip, 64))
	}
	if len(next) == 0 {
		delete(h.st.VPN.Static, id)
	} else {
		h.st.VPN.Static[id] = next
	}
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.Static[id] = prev
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()
	h.vpnChanged()
	return nil
}

// AckVPNDNS records that the admin configured wired provider id's DNS
// records by hand (dns: manual only; the doctor's vpn_dns_manual goes
// away). Audited vpn.dns_acknowledged.
func (h *Hub) AckVPNDNS(ctx context.Context, actor directory.Actor, id string) (err error) {
	defer func() { h.auditOp(actor, "vpn.dns_acknowledged", id, "", err) }()
	h.mu.Lock()
	defer h.mu.Unlock()
	t, err := h.vpnTemplateLocked(id)
	if err != nil {
		return err
	}
	if !t.Manifest.VPN.DNS.Manual {
		return statusErr(http.StatusBadRequest, "%s applies its DNS records with a hook", id)
	}
	p, ok := h.st.VPN.Providers[id]
	if !ok {
		return statusErr(http.StatusConflict, "%s is not wired as a VPN provider", id)
	}
	if p.DNSAcked {
		return nil
	}
	prev := p
	p.DNSAcked = true
	h.st.VPN.Providers[id] = p
	if err := h.saveStateLocked(); err != nil {
		h.st.VPN.Providers[id] = prev
		return err
	}
	return nil
}

// ipLess orders IPv4 address strings numerically (invalid ones last, by
// text).
func ipLess(a, b string) bool {
	x, ex := netip.ParseAddr(a)
	y, ey := netip.ParseAddr(b)
	switch {
	case ex == nil && ey == nil:
		return x.Less(y)
	case ex == nil:
		return true
	case ey == nil:
		return false
	}
	return a < b
}

// ── the hook runner ─────────────────────────────────────

// RunVPNMaps runs every wired source: hook provider's identity hook when
// it is due (its refresh after the last run; never debounced), the dns
// hooks whose records changed, and republishes vpn.json, every tick
// until ctx ends.
func (h *Hub) RunVPNMaps(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		h.vpnTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// vpnTick starts each due hook run (one at a time per provider, in the
// background) and publishes.
func (h *Hub) vpnTick(ctx context.Context) {
	now := h.vpnrt.now()
	h.mu.RLock()
	type due struct {
		id      string
		refresh time.Duration
	}
	var runs []due
	for _, id := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		t := h.findLocked(id)
		if t == nil || t.Manifest.VPN == nil || t.Manifest.VPN.Identity.Source != templates.VPNSourceHook {
			continue
		}
		refresh := time.Duration(h.st.VPN.Providers[id].Refresh)
		if refresh == 0 {
			refresh = t.Manifest.VPN.Identity.EffectiveRefresh()
		}
		runs = append(runs, due{id, refresh})
	}
	h.mu.RUnlock()
	for _, r := range runs {
		h.vpnrt.mu.Lock()
		pm := h.vpnrt.maps[r.id]
		if pm == nil {
			pm = &providerMap{}
			h.vpnrt.maps[r.id] = pm
		}
		start := !pm.running && (pm.lastRun.IsZero() || !now.Before(pm.lastRun.Add(r.refresh)))
		if start {
			pm.running, pm.lastRun = true, now
		}
		h.vpnrt.mu.Unlock()
		if start {
			id := r.id
			h.goBackground(func() {
				h.runVPNProvider(ctx, id)
				h.vpnrt.mu.Lock()
				if pm := h.vpnrt.maps[id]; pm != nil {
					pm.running = false
				}
				h.vpnrt.mu.Unlock()
				h.runVPNDNS(ctx, id)
				h.TriggerVPNPublish()
			})
		} else {
			id := r.id
			h.goBackground(func() { h.runVPNDNS(ctx, id) })
		}
	}
	// I7: anything the access depends on may have moved without a Hub
	// call (the built-in subnet in status.json, a provider's cidr
	// setting, the core env's mode): re-render when an enabled
	// instance's access key differs from the committed one.
	h.wgStatus() // the built-in subnet as wg reports it now
	h.vpnCheckProviderOverlaps(ctx, now)
	if h.vpnRenderRetryDue() || h.vpnKeysMoved() {
		h.vpnRangesChanged()
	}
	h.TriggerVPNPublish()
}

// vpnKeysMoved: an enabled instance's access key differs from the
// committed one (known instances only: the start check covers the rest).
func (h *Hub) vpnKeysMoved() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		key := h.vpnRenderKeyLocked(t)
		h.vpnrt.mu.Lock()
		prev, known := h.vpnrt.rendered[t.ID]
		h.vpnrt.mu.Unlock()
		if known && prev != key {
			return true
		}
	}
	return false
}

// vpnOverlapCheckEvery throttles the wired providers' overlap re-checks.
const vpnOverlapCheckEvery = 30 * time.Second

// vpnCheckProviderOverlaps re-runs wiring's overlap checks on every wired
// provider (its ranges may follow a cidr setting, I7): one that overlaps
// now is left out of vpn.json until it doesn't (vpnrt.overlapBad, shown as
// its last error).
func (h *Hub) vpnCheckProviderOverlaps(ctx context.Context, now time.Time) {
	h.vpnrt.mu.Lock()
	due := now.Sub(h.vpnrt.overlapAt) >= vpnOverlapCheckEvery
	if due {
		h.vpnrt.overlapAt = now
	}
	h.vpnrt.mu.Unlock()
	if !due || h.engine == nil {
		return
	}
	nets, err := h.engine.ListNetworks(ctx)
	if err != nil {
		return // kept as they were: the next check retries
	}
	st, _ := h.wgStatus()
	bad := map[string]string{}
	h.mu.RLock()
	for _, id := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		t := h.findLocked(id)
		if t == nil || t.Manifest.VPN == nil {
			continue
		}
		rs, err := h.providerRangesLocked(t)
		if err != nil {
			bad[id] = err.Error()
			continue
		}
		if err := h.vpnOverlapLocked(id, rs, st, nets); err != nil {
			bad[id] = err.Error()
		}
	}
	h.mu.RUnlock()
	h.vpnrt.mu.Lock()
	h.vpnrt.overlapBad = bad
	h.vpnrt.mu.Unlock()
}

// vpnHookOf is t's vpn hook name (nil when it isn't one).
func vpnHookOf(t *templates.Template, name string) *templates.Hook {
	for i := range t.Manifest.Hooks {
		if hk := &t.Manifest.Hooks[i]; hk.Name == name && hk.IsVPN() {
			return hk
		}
	}
	return nil
}

// execVPNHook runs vpn hook name of instance t with stdin (ExecStdinSplit,
// the hook's user and timeout, in a running container of its service).
// stdout goes back to the caller only; on failure it is zeroed and the
// error holds the exit and stderr only, redacted (the instance's secrets
// and every piece of stdout), then clipped.
func (h *Hub) execVPNHook(ctx context.Context, t *templates.Template, name string, stdin []byte) ([]byte, error) {
	hk := vpnHookOf(t, name)
	if hk == nil {
		return nil, fmt.Errorf("hook %s: not a vpn hook of the template", clip(name, 64))
	}
	if h.engine == nil {
		return nil, fmt.Errorf("hook %s: no container engine", name)
	}
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		return nil, errors.New(clipRunes(h.secretRedactor(t.ID)(fmt.Sprintf("hook %s: listing the %s containers: %v", name, hk.Service, err)), unitErrorMax))
	}
	c := runningContainer(cs, hk.Service)
	if c == nil {
		return nil, fmt.Errorf("hook %s: no running container of service %s", name, hk.Service)
	}
	r, err := h.engine.ExecStdinSplit(ctx, c.ID, docker.ExecInput{Cmd: slices.Clone(hk.Command), User: hk.User, Stdin: slices.Clone(stdin), Timeout: hk.EffectiveTimeout()})
	var why string
	switch {
	case err != nil:
		why = "failed: " + err.Error()
	case r == nil:
		why = "failed: no result"
	case r.TimedOut:
		why = fmt.Sprintf("timed out after %s (the process may still run)", hk.EffectiveTimeout())
	case r.ExitCode != 0:
		why = fmt.Sprintf("exited %d", r.ExitCode)
	default:
		return r.Stdout, nil
	}
	var out, errText []byte
	if r != nil {
		out, errText = r.Stdout, r.Stderr
	}
	redact := h.secretRedactor(t.ID, stdoutPieces(out))
	clear(out)
	msg := "hook " + name + ": " + why
	if s := strings.TrimSpace(string(errText)); s != "" {
		msg += ": stderr: " + s
	}
	return nil, errors.New(clipRunes(redact(msg), unitErrorMax))
}

// runVPNProvider runs provider id's identity hook once: a good document
// replaces the map (owners resolved to enabled VPN users, the others
// dropped as "not a Portcullis person"); a failure keeps the last good
// map (it goes stale on its own) and records the redacted error.
func (h *Hub) runVPNProvider(ctx context.Context, id string) {
	h.mu.RLock()
	t := h.findLocked(id)
	p, wired := h.st.VPN.Providers[id]
	group := h.st.VPN.UsersGroup
	var ranges []netip.Prefix
	var rerr error
	var tc templates.Template
	if t != nil {
		tc = *t
		if t.Manifest.VPN != nil {
			ranges, rerr = h.providerRangesLocked(t)
		}
	}
	h.mu.RUnlock()
	if t == nil || !wired || tc.Manifest.VPN == nil || tc.Manifest.VPN.Identity.Source != templates.VPNSourceHook {
		return
	}
	fail := func(msg string) {
		h.vpnrt.mu.Lock()
		pm := h.vpnrt.maps[id]
		if pm == nil {
			pm = &providerMap{}
			h.vpnrt.maps[id] = pm
		}
		pm.lastErr = clipRunes(msg, unitErrorMax)
		h.vpnrt.mu.Unlock()
	}
	if rerr != nil {
		fail("the client ranges: " + rerr.Error())
		return
	}
	vb := tc.Manifest.VPN
	stdin, _ := json.Marshal(vpn.HookInput{Version: vpn.HookDocVersion, Trigger: vpn.Trigger, Instance: id, Op: vpn.OpDevices, Ranges: vpn.Strings(ranges)})
	out, err := h.execVPNHook(ctx, &tc, vb.Identity.Hook, stdin)
	if err != nil {
		fail(err.Error())
		return
	}
	doc, perr := vpn.ParseHookDevices(out, ranges)
	redact := h.secretRedactor(id, stdoutPieces(out))
	clear(out)
	if perr != nil {
		fail(redact(perr.Error()))
		return
	}
	members, merr := h.vpnMembership(ctx)
	if merr != nil {
		fail("the directory is unavailable: " + merr.Error())
		return
	}
	var byID map[string]string
	if vb.Identity.Owner == templates.VPNOwnerOIDCSub {
		h.vpnrt.mu.Lock()
		kc := h.vpnrt.kc
		h.vpnrt.mu.Unlock()
		if kc == nil {
			fail("Keycloak isn't connected: oidc_sub owners can't be resolved")
			return
		}
		if byID, err = kc.UsernamesByID(ctx); err != nil {
			fail("resolving the owners through Keycloak failed: " + err.Error())
			return
		}
	}
	now := h.vpnrt.now()
	pm := providerMap{refreshedAt: now.UTC(), gateway: doc.Gateway, problems: slices.Clone(doc.Dropped), meta: map[string]deviceMeta{}}
	refresh := time.Duration(p.Refresh)
	if refresh == 0 {
		refresh = vb.Identity.EffectiveRefresh()
	}
	pm.staleAfter = vpn.StaleAfter(pm.refreshedAt, refresh)
	for _, d := range doc.Devices {
		user := ""
		switch vb.Identity.Owner {
		case templates.VPNOwnerOIDCSub:
			user = byID[d.Owner]
		case templates.VPNOwnerName:
			user = strings.ToLower(d.Owner)
		}
		if user == "" || !vpnUserOK(members, group, user) {
			pm.problems = append(pm.problems, vpn.Dropped{ID: dropID(d.ID), Reason: vpn.DropUnresolved})
			continue
		}
		name := d.Name
		if !validDeviceName(name) {
			name = d.ID
		}
		pm.devices = append(pm.devices, vpn.Device{IP: d.Address.String(), Provider: id, User: user, DeviceID: id + ":" + d.ID, Name: clipRunes(name, 64), Expires: d.Expires})
		pm.meta[d.Address.String()] = deviceMeta{Online: d.Online, LastSeen: d.LastSeen}
	}
	sort.Slice(pm.devices, func(i, j int) bool { return ipLess(pm.devices[i].IP, pm.devices[j].IP) })
	// Unwired while the hook ran: its map is gone for good (M4).
	h.mu.RLock()
	defer h.mu.RUnlock()
	if _, still := h.st.VPN.Providers[id]; !still {
		return
	}
	h.vpnrt.mu.Lock()
	if old := h.vpnrt.maps[id]; old != nil {
		pm.lastRun, pm.running = old.lastRun, old.running
		pm.dnsApplied, pm.lastDNSErr, pm.lastDNSRun, pm.dnsRunning = old.dnsApplied, old.lastDNSErr, old.lastDNSRun, old.dnsRunning
	}
	h.vpnrt.maps[id] = &pm
	h.vpnrt.mu.Unlock()
}

func dropID(s string) string {
	if len(s) > 64 || templates.HasControlChars(s) {
		return "?"
	}
	return s
}

// vpnDNSRecordsLocked are the A records a provider's clients need: every
// core host and every enabled instance's hosts, at gateway. Caller holds
// mu (read).
func (h *Hub) vpnDNSRecordsLocked(gateway netip.Addr) []vpn.Record {
	hosts := map[string]bool{}
	for hst := range policy.CoreHosts(strings.ToLower(h.cfg.Domain)) {
		hosts[hst] = true
	}
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil {
			for _, hst := range t.Hosts {
				if hst != "" {
					hosts[strings.ToLower(hst)] = true
				}
			}
		}
	}
	out := make([]vpn.Record, 0, len(hosts))
	for _, n := range slices.Sorted(maps.Keys(hosts)) {
		out = append(out, vpn.Record{Name: n, Type: "A", Value: gateway.String()})
	}
	return out
}

// runVPNDNS runs provider id's dns hook when its records (or the
// gateway) changed since the last success; after a failure, again once
// its refresh has passed. A failure never marks the map stale.
func (h *Hub) runVPNDNS(ctx context.Context, id string) {
	h.vpnrt.mu.Lock()
	pm := h.vpnrt.maps[id]
	if pm == nil || pm.dnsRunning {
		h.vpnrt.mu.Unlock()
		return // one dns run at a time per provider (M2)
	}
	pm.dnsRunning = true
	h.vpnrt.mu.Unlock()
	defer func() {
		h.vpnrt.mu.Lock()
		if pm := h.vpnrt.maps[id]; pm != nil {
			pm.dnsRunning = false
		}
		h.vpnrt.mu.Unlock()
	}()
	h.vpnrt.mu.Lock()
	pm = h.vpnrt.maps[id]
	var gw netip.Addr
	var applied string
	var lastRun time.Time
	var failed bool
	if pm != nil {
		gw, applied, lastRun, failed = pm.gateway, pm.dnsApplied, pm.lastDNSRun, pm.lastDNSErr != ""
	}
	h.vpnrt.mu.Unlock()
	if !gw.IsValid() {
		return
	}
	h.mu.RLock()
	t := h.findLocked(id)
	p, wired := h.st.VPN.Providers[id]
	var tc templates.Template
	var recs []vpn.Record
	if t != nil {
		tc = *t
		recs = h.vpnDNSRecordsLocked(gw)
	}
	h.mu.RUnlock()
	if t == nil || !wired || tc.Manifest.VPN == nil || tc.Manifest.VPN.DNS.Hook == "" {
		return
	}
	stdin, _ := json.Marshal(vpn.HookInput{Version: vpn.HookDocVersion, Trigger: vpn.Trigger, Instance: id, Op: vpn.OpDNS, Records: recs})
	key := string(stdin)
	now := h.vpnrt.now()
	refresh := time.Duration(p.Refresh)
	if refresh == 0 {
		refresh = tc.Manifest.VPN.Identity.EffectiveRefresh()
	}
	// Applied already, or this same set failed less than a refresh ago
	// (retried then); a new set runs at once.
	h.vpnrt.mu.Lock()
	tried := pm != nil && pm.dnsTried == key
	h.vpnrt.mu.Unlock()
	if key == applied || failed && tried && now.Before(lastRun.Add(refresh)) {
		return
	}
	out, err := h.execVPNHook(ctx, &tc, tc.Manifest.VPN.DNS.Hook, stdin)
	clear(out)
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	pm = h.vpnrt.maps[id]
	if pm == nil {
		return
	}
	pm.lastDNSRun, pm.dnsTried = now, key
	if err != nil {
		pm.lastDNSErr = err.Error()
		return
	}
	pm.lastDNSErr, pm.dnsApplied = "", key
}

// liveProviders are the providers a VPN-only instance can be reached
// through now: wg up, and the built-in provider (on) or a wired
// provider whose map is fresh (static ones always are). Sorted.
func (h *Hub) liveProviders() []string {
	st, err := h.wgStatus()
	if err != nil || !st.Edge.OK {
		return nil
	}
	now := h.vpnrt.now()
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []string
	if _, ok := h.builtinOnLocked(st); ok {
		out = append(out, vpn.BuiltinID)
	}
	for _, id := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		t := h.findLocked(id)
		if t == nil || t.Manifest.VPN == nil {
			continue
		}
		if t.Manifest.VPN.Identity.Source == templates.VPNSourceStatic {
			out = append(out, id)
			continue
		}
		h.vpnrt.mu.Lock()
		pm := h.vpnrt.maps[id]
		fresh := pm != nil && !pm.refreshedAt.IsZero() && now.Before(pm.staleAfter)
		h.vpnrt.mu.Unlock()
		if fresh {
			out = append(out, id)
		}
	}
	return out
}

// vpnProviderMap is a copy of provider id's in-memory map (nil = none).
func (h *Hub) vpnProviderMap(id string) *providerMap {
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	pm := h.vpnrt.maps[id]
	if pm == nil {
		return nil
	}
	c := *pm
	c.devices = slices.Clone(pm.devices)
	c.problems = append(slices.Clone(pm.problems), pm.rangeDrops...)
	c.meta = maps.Clone(pm.meta)
	return &c
}

// dropVPNInstanceLocked forgets instance id's VPN state (its delete):
// wiring, statics and its own reach. Caller holds mu (write) and saves.
func (h *Hub) dropVPNInstanceLocked(id string) bool {
	_, wired := h.st.VPN.Providers[id]
	_, static := h.st.VPN.Static[id]
	_, reach := h.st.Reach[id]
	delete(h.st.VPN.Providers, id)
	delete(h.st.VPN.Static, id)
	delete(h.st.Reach, id)
	// Other instances' via keep naming it (C1): a provider that is gone
	// accepts nothing (deny-all allowlist, group-gate finds no such
	// provider), as after an unwire — never "every provider".
	return wired || static || reach
}
