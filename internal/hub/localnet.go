package hub

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Local networks and exposure (contract §14.7): the admin's LAN / VPN
// CIDRs, the main domain's addresses and the ports the doctor judges.

// DefaultLocalNetworks: RFC 1918, IPv6 ULA and the tailnet (CGNAT range).
var DefaultLocalNetworks = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10"}

// The main domain's lookup: timeout and cache lifetimes.
const (
	dnsTimeout  = 2 * time.Second
	dnsCacheFor = 5 * time.Minute
)

// dnsCache is the last lookup of the main domain (guarded by Hub.dnsMu,
// never mu).
type dnsCache struct {
	domain string
	at     time.Time
	addrs  []netip.Addr
	err    error
}

// defaultLookupIP resolves host's A / AAAA records: New's lookupIP (the
// package's tests replace it, so no test reaches the network).
var defaultLookupIP lookupIPFunc = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// IsLocal: a (unmapped first) is loopback or inside one of nets.
func IsLocal(a netip.Addr, nets []netip.Prefix) bool { return doctor.IsLocal(a, nets) }

// LocalNetworks is the stored list, else the defaults (loopback always
// counts as local on top: IsLocal).
func (h *Hub) LocalNetworks() []netip.Prefix {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.localNetworksLocked()
}

// localNetworksLocked: caller holds mu. A stored list is checked at Load
// and at every save; one that fails anyway counts as loopback only
// (fail closed: nothing else is local).
func (h *Hub) localNetworksLocked() []netip.Prefix {
	cidrs := DefaultLocalNetworks
	if h.st.LocalNetworks != nil {
		cidrs = *h.st.LocalNetworks
	}
	nets, err := state.ParseLocalNetworks(cidrs)
	if err != nil {
		return nil
	}
	return nets
}

// LocalNetworksView is the list as the admin sees it; isDefault: nothing
// stored (the defaults apply).
func (h *Hub) LocalNetworksView() (cidrs []string, isDefault bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.st.LocalNetworks == nil {
		return slices.Clone(DefaultLocalNetworks), true
	}
	return append([]string{}, *h.st.LocalNetworks...), false
}

// SetLocalNetworks stores the admin's list: nil = back to the defaults,
// [] = loopback only. At most 64 CIDRs, no host bits, no /0 (400 naming
// the entry). Audited settings.local_networks "<N> networks" (N the
// effective count), refusals "refused", after mu.
func (h *Hub) SetLocalNetworks(cidrs []string, actor directory.Actor) error {
	n := len(cidrs)
	if cidrs == nil {
		n = len(DefaultLocalNetworks)
	}
	err := h.setLocalNetworks(cidrs, actor)
	h.auditFolder(actor, "settings.local_networks", "local_networks", fmt.Sprintf("%d networks", n), err)
	return err
}

func (h *Hub) setLocalNetworks(cidrs []string, actor directory.Actor) error {
	if actor.User == "" {
		return statusErr(http.StatusUnauthorized, "changing the local networks needs a signed-in admin")
	}
	var stored *[]string
	if cidrs != nil {
		nets, err := state.ParseLocalNetworks(cidrs)
		if err != nil {
			return statusErr(http.StatusBadRequest, "local networks: %v", err)
		}
		list := make([]string, 0, len(nets))
		for _, p := range nets {
			list = append(list, p.String())
		}
		stored = &list
	}
	h.mu.Lock()
	prev := h.st.LocalNetworks
	prevEnv := h.localNetworksEnvLocked()
	h.st.LocalNetworks = stored
	if err := h.saveStateLocked(); err != nil {
		h.st.LocalNetworks = prev
		h.mu.Unlock()
		return err
	}
	// F35: the enabled instances whose compose reads
	// ${PORTCULLIS_LOCAL_NETWORKS} restart (the restart writes the .env
	// again); the others get the value at their next .env write.
	var restart []templates.Template
	if h.localNetworksEnvLocked() == prevEnv {
		// The effective list is unchanged (the same list saved again, or
		// the defaults written out): nothing to restart.
		h.mu.Unlock()
		return nil
	}
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil && t.UsesLocalNetworks {
			restart = append(restart, *t)
		}
	}
	h.mu.Unlock()
	for _, t := range restart {
		h.setOwed(t.ID, settings.EffectRestart)
		h.goBackground(func() { h.Restart(t) })
	}
	return nil
}

// domainAddrs are the main domain's A / AAAA records (unmapped), looked
// up with a 2 s timeout and cached for 5 minutes (a failure too: a
// doctor view never waits on DNS more than once per 5 minutes). Never
// under mu. No main domain: nothing, no error.
func (h *Hub) domainAddrs(ctx context.Context) ([]netip.Addr, error) {
	domain := h.cfg.Domain
	if domain == "" {
		return nil, nil
	}
	h.dnsMu.Lock()
	defer h.dnsMu.Unlock()
	c := h.dnsCache
	if c.domain == domain && !c.at.IsZero() && time.Since(c.at) < dnsCacheFor {
		return slices.Clone(c.addrs), c.err
	}
	lctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	lookup := h.lookupIP
	if lookup == nil {
		lookup = defaultLookupIP
	}
	addrs, err := lookup(lctx, domain)
	var out []netip.Addr
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	if err != nil {
		out = nil
	}
	h.dnsCache = dnsCache{domain: domain, at: time.Now(), addrs: out, err: err}
	return slices.Clone(out), err
}

// portInsLocked are the published ports of the enabled instances as the
// doctor reads them: each template port as set in Settings, then the
// custom override's ports, each matched to the template port with the
// same service and container port (its key, label and lan_only).
// Caller holds mu (read).
func (h *Hub) portInsLocked() []doctor.PortIn {
	var out []doctor.PortIn
	for i := range h.instances {
		t := &h.instances[i]
		if !h.st.IsEnabled(t.ID) {
			continue
		}
		byKey := map[string]templates.Port{}
		// Matched by service, container port and protocol (ruling): a UDP
		// override port is never the TCP lan_only port, nor the reverse.
		type svcPort struct {
			service, proto string
			port           int
		}
		bySvc := map[svcPort]templates.Port{}
		for _, p := range t.Manifest.Ports {
			byKey[p.Key] = p
			if p.Service != "" && p.Container > 0 && !p.NetworkModeHost {
				k := svcPort{p.Service, portProto(p.Protocol), p.Container}
				if _, dup := bySvc[k]; !dup || p.LanOnly {
					bySvc[k] = p
				}
			}
		}
		for _, b := range h.appPortsLocked(t) {
			pi := doctor.PortIn{
				Instance: t.ID, Key: b.Key, Service: b.Service, Bind: b.Bind, Port: b.Port, Container: b.Container,
				Protocol: b.Protocol, HostNetwork: b.NetworkModeHost, Custom: b.Custom,
			}
			if b.RangeEnd > 0 {
				pi.Port, pi.PortEnd = b.RangeStart, b.RangeEnd
			}
			mp, ok := byKey[b.Key]
			if b.Custom {
				mp, ok = bySvc[svcPort{b.Service, b.Protocol, b.Container}]
				if ok {
					pi.Key = mp.Key
				}
			}
			if ok {
				pi.Label, pi.LanOnly = mp.Label, mp.LanOnly
			}
			out = append(out, pi)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

// portProto is a manifest port's protocol as bindings carry it.
func portProto(p string) string {
	if p == "" {
		return "tcp"
	}
	return strings.ToLower(p)
}

// lookupIPFunc resolves a host name (Hub.lookupIP; test-settable).
type lookupIPFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// SetLookupIP replaces the main domain's A / AAAA lookup and forgets the
// cached answer: other packages' tests stub DNS with it, so no test
// resolves a real name (nil: the system resolver).
func (h *Hub) SetLookupIP(f func(ctx context.Context, host string) ([]netip.Addr, error)) {
	h.dnsMu.Lock()
	defer h.dnsMu.Unlock()
	h.lookupIP = f
	h.dnsCache = dnsCache{}
}
