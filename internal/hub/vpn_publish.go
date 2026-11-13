package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/vpn"
)

// vpn.json v2 publishing (contract §4, §16; spec §6.4): the built-in
// provider (peers from state.VPN.Devices, the server key and subnet from
// wg's status.json), every wired provider (hook maps from memory, static
// assignments from state) and their devices, sorted deterministically.
// Rewritten on every map change and at least every refresh while a
// provider is live.

// vpnJSONPath is vpn.json in the vpn_doc volume (HUB_VPN_DOC_DIR, never
// in hub_data: wg mustn't read the Hub's data).
func (h *Hub) vpnJSONPath() string { return filepath.Join(h.cfg.VPNDocDir, vpn.FileName) }

// TriggerVPNPublish republishes vpn.json in the background (coalesced: a
// publish already pending covers this one).
func (h *Hub) TriggerVPNPublish() {
	if h.cfg.VPNDocDir == "" {
		return // nowhere to write it (unit tests of other features)
	}
	if !h.vpnrt.pubPending.CompareAndSwap(false, true) {
		return
	}
	h.goBackground(func() {
		h.vpnrt.pubMu.Lock()
		defer h.vpnrt.pubMu.Unlock()
		h.vpnrt.pubPending.Store(false)
		h.mu.RLock()
		hasPeople := h.people != nil
		h.mu.RUnlock()
		if hasPeople {
			if _, err := h.vpnMembership(context.Background()); err != nil {
				log.Printf("vpn: the directory is unavailable (%v): the last snapshot is used", err)
			}
		}
		if err := h.publishVPN(); err != nil {
			log.Printf("vpn: writing %s: %v", vpn.FileName, err)
		}
	})
}

// publishVPN writes vpn.json (caller holds pubMu, not mu).
func (h *Hub) publishVPN() error {
	st, _ := h.wgStatus()
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.publishVPNLocked(st)
}

// publishVPNLocked builds and writes vpn.json when it changed, or when the
// last write is older than the shortest live refresh. Caller holds mu
// (read) and pubMu.
func (h *Hub) publishVPNLocked(st *vpn.Status) error {
	doc, minRefresh := h.vpnDocLocked(st)
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	now := h.vpnrt.now()
	if bytes.Equal(b, h.vpnrt.lastWritten) && (minRefresh == 0 || now.Sub(h.vpnrt.lastWriteAt) < minRefresh) {
		return nil
	}
	if err := vpn.WriteGroup(h.vpnJSONPath(), doc, h.cfg.VPNDocGID); err != nil {
		return err
	}
	h.vpnrt.lastWritten, h.vpnrt.lastWriteAt = b, now
	return nil
}

// vpnDocLocked is vpn.json now, and the shortest refresh of the live hook
// providers (0 = none). Caller holds mu (read).
func (h *Hub) vpnDocLocked(st *vpn.Status) (vpn.Doc, time.Duration) {
	now := h.vpnrt.now()
	h.vpnrt.mu.Lock()
	members := h.vpnrt.members
	h.vpnrt.mu.Unlock()
	group := h.st.VPN.UsersGroup
	// A device's owner must still be a VPN user (defence in depth: the
	// revocations remove them; before the first directory read, state is
	// taken as it is).
	ownerOK := func(user string) bool { return members == nil || vpnUserOK(members, group, user) }
	doc := vpn.Doc{Version: vpn.DocVersion, Providers: []vpn.Provider{}, Devices: []vpn.Device{}}
	if ps, ok := h.builtinOnLocked(st); ok {
		if sub, err := netip.ParsePrefix(ps.Subnet); err == nil && vpn.ValidPublicKey(ps.PublicKey) {
			b := &vpn.Builtin{Subnet: sub.String(), ServerPublicKey: ps.PublicKey, Domains: h.vpnDomainsLocked(), Peers: []vpn.Peer{}}
			for _, d := range h.st.VPN.Devices {
				a, err := netip.ParseAddr(d.IP)
				if err != nil || !sub.Contains(a) || expired(d.Expires, now) || !ownerOK(d.User) || !vpn.ValidPublicKey(d.PublicKey) {
					continue
				}
				if members != nil && members.UUIDs[d.User] != d.UUID {
					continue // the account was re-created: never inherited
				}
				b.Peers = append(b.Peers, vpn.Peer{IP: a.String(), PublicKey: d.PublicKey, DeviceID: d.ID, Expires: d.Expires})
				doc.Devices = append(doc.Devices, vpn.Device{IP: a.String(), Provider: vpn.BuiltinID, User: d.User, DeviceID: d.ID, Name: d.Name, Expires: d.Expires})
			}
			sort.Slice(b.Peers, func(i, j int) bool { return ipLess(b.Peers[i].IP, b.Peers[j].IP) })
			doc.Builtin = b
			doc.Providers = append(doc.Providers, vpn.Provider{ID: vpn.BuiltinID, Source: vpn.SourceBuiltin, Ranges: []string{sub.String()}})
		}
	}
	core := h.vpnCoreEnv()
	var minRefresh time.Duration
	for _, id := range slices.Sorted(maps.Keys(h.st.VPN.Providers)) {
		p := h.st.VPN.Providers[id]
		t := h.findLocked(id)
		if t == nil || t.Manifest.VPN == nil {
			continue
		}
		ranges, err := h.providerRangesLocked(t)
		if err != nil {
			continue // unpublished: its addresses are denied
		}
		// Never a range core reserves (core refuses such a file).
		if core.ReservedBad {
			continue
		}
		if _, _, clash := vpn.FirstOverlap(ranges, core.Reserved); clash {
			continue
		}
		if doc.Builtin != nil {
			if sub, err := netip.ParsePrefix(doc.Builtin.Subnet); err == nil {
				if _, _, clash := vpn.FirstOverlap(ranges, []netip.Prefix{sub}); clash {
					continue
				}
			}
		}
		clash := false
		for _, q := range doc.Providers {
			qs, _ := vpn.ParseRanges(q.Ranges)
			if _, _, ok := vpn.FirstOverlap(ranges, qs); ok {
				clash = true
			}
		}
		if clash {
			continue
		}
		gw, err := vpn.GatewayAddr(core.Net, p.Slot)
		if err != nil {
			continue
		}
		pv := vpn.Provider{ID: id, Label: t.Manifest.VPN.Label, Ranges: vpn.Strings(ranges), EdgePort: vpn.EdgePort(p.Slot), GatewayIP: gw.String()}
		var devs []vpn.Device
		if t.Manifest.VPN.Identity.Source == templates.VPNSourceStatic {
			// An admin's assignments never go stale: no timestamps.
			pv.Source = vpn.SourceStatic
			for _, s := range h.st.VPN.Static[id] {
				a, err := netip.ParseAddr(s.IP)
				if err != nil || !slices.ContainsFunc(ranges, func(r netip.Prefix) bool { return r.Contains(a) }) || !ownerOK(s.User) {
					continue
				}
				devs = append(devs, vpn.Device{IP: a.String(), Provider: id, User: s.User, DeviceID: id + ":" + a.String(), Name: s.Name})
			}
		} else {
			refresh := time.Duration(p.Refresh)
			if refresh == 0 {
				refresh = t.Manifest.VPN.Identity.EffectiveRefresh()
			}
			pv.Source = vpn.SourceHook
			h.vpnrt.mu.Lock()
			pm := h.vpnrt.maps[id]
			omit := pm == nil || pm.refreshedAt.IsZero()
			if !omit {
				ra, sa := pm.refreshedAt, pm.staleAfter
				pv.RefreshedAt, pv.StaleAfter = &ra, &sa
				pv.Stale = !now.Before(sa)
				if !pv.Stale {
					devs = slices.Clone(pm.devices)
					if minRefresh == 0 || refresh < minRefresh {
						minRefresh = refresh
					}
				}
			}
			h.vpnrt.mu.Unlock()
			if omit {
				// No good run since the start: left out (its addresses
				// are denied; nothing else is affected).
				continue
			}
		}
		doc.Providers = append(doc.Providers, pv)
		for _, d := range devs {
			if ownerOK(d.User) {
				doc.Devices = append(doc.Devices, d)
			}
		}
	}
	sort.SliceStable(doc.Providers, func(i, j int) bool { return doc.Providers[i].ID < doc.Providers[j].ID })
	sort.SliceStable(doc.Devices, func(i, j int) bool { return ipLess(doc.Devices[i].IP, doc.Devices[j].IP) })
	return doc, minRefresh
}

// vpnDomainsLocked are the built-in resolver's domains: the main domain
// and the enrolled ones, sorted.
func (h *Hub) vpnDomainsLocked() []string {
	set := map[string]bool{strings.ToLower(h.cfg.Domain): true}
	for _, d := range h.enrolledLocked() {
		set[strings.ToLower(d.Name)] = true
	}
	return slices.Sorted(maps.Keys(set))
}

func expired(t *time.Time, now time.Time) bool { return t != nil && !now.Before(*t) }
