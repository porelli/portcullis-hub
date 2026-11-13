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
		h.publishVPNRetrying()
	})
}

// Publish retries (I3): a failed write is tried again with backoff (each
// tick re-triggers a publish); the error is the doctor's
// vpn_publish_failed until a write succeeds. The file's valid_until ends
// it for every reader if the writes keep failing.
const (
	vpnPublishRetryMin = 5 * time.Second
	vpnPublishRetryMax = 5 * time.Minute
	// vpnValidFor is how long a written vpn.json stays valid, and
	// vpnValidRenew how often valid_until moves on.
	vpnValidFor   = time.Hour
	vpnValidRenew = 10 * time.Minute
)

// publishVPNRetrying is publishVPN within the retry backoff (caller holds
// pubMu).
func (h *Hub) publishVPNRetrying() {
	now := h.vpnrt.now()
	h.vpnrt.mu.Lock()
	wait := h.vpnrt.pubErr != "" && now.Before(h.vpnrt.pubNext)
	h.vpnrt.mu.Unlock()
	if wait {
		return
	}
	err := h.publishVPN()
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	if err == nil {
		h.vpnrt.pubErr, h.vpnrt.pubDelay = "", 0
		return
	}
	log.Printf("vpn: writing %s: %v (retried)", vpn.FileName, err)
	h.vpnrt.pubErr = clipRunes(err.Error(), 600)
	h.vpnrt.pubDelay = min(max(2*h.vpnrt.pubDelay, vpnPublishRetryMin), vpnPublishRetryMax)
	h.vpnrt.pubNext = now.Add(h.vpnrt.pubDelay)
}

// vpnPublishError is the last failed vpn.json write ("" = fine).
func (h *Hub) vpnPublishError() string {
	h.vpnrt.mu.Lock()
	defer h.vpnrt.mu.Unlock()
	return h.vpnrt.pubErr
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
	if minRefresh == 0 || minRefresh > vpnValidRenew {
		minRefresh = vpnValidRenew
	}
	if bytes.Equal(b, h.vpnrt.lastWritten) && now.Sub(h.vpnrt.lastWriteAt) < minRefresh {
		return nil
	}
	write := vpn.WriteGroup
	if h.vpnrt.testWrite != nil {
		write = h.vpnrt.testWrite
	}
	if err := write(h.vpnJSONPath(), doc, h.cfg.VPNDocGID); err != nil {
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
	// valid_until: an hour ahead, moved on every vpnValidRenew (stable
	// bytes in between).
	h.vpnrt.mu.Lock()
	if h.vpnrt.validAt.IsZero() || !now.Before(h.vpnrt.validAt.Add(vpnValidRenew)) {
		h.vpnrt.validAt = now.UTC()
	}
	vu := h.vpnrt.validAt.Add(vpnValidFor)
	h.vpnrt.mu.Unlock()
	doc := vpn.Doc{Version: vpn.DocVersion, ValidUntil: &vu, Providers: []vpn.Provider{}, Devices: []vpn.Device{}}
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
		// Never a range core reserves (core refuses such a file), nor
		// one that overlaps since it was wired (I7).
		if core.ReservedBad {
			continue
		}
		h.vpnrt.mu.Lock()
		_, overlap := h.vpnrt.overlapBad[id]
		h.vpnrt.mu.Unlock()
		if overlap {
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
					// Re-checked against the ranges as they are now (a
					// cidr setting may have moved since the run, I3).
					pm.rangeDrops = nil
					for _, d := range pm.devices {
						a, err := netip.ParseAddr(d.IP)
						if err != nil || !slices.ContainsFunc(ranges, func(r netip.Prefix) bool { return r.Contains(a) }) {
							pm.rangeDrops = append(pm.rangeDrops, vpn.Dropped{ID: strings.TrimPrefix(d.DeviceID, id+":"), Reason: vpn.DropOutside})
							continue
						}
						devs = append(devs, d)
					}
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
