package hub

import (
	"net/netip"
	"sort"

	"github.com/portcullis/hub/internal/linkdoc"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// publishLinkLocked writes link.json v1 (contract §17.2) from state:
// every server that isn't revoked is a peer (P23: enrolling while
// enrolling, else ready — offline is the Hub's own notion, so an offline
// worker can come back), and every placed instance of a ready peer that
// has a relay token is a relay. Without HUB_LINK_DOC_DIR nothing is
// written. Caller holds mu.
func (h *Hub) publishLinkLocked() error {
	if h.cfg.LinkDocDir == "" {
		return nil
	}
	d := &linkdoc.Doc{Version: 1, WrittenAt: h.now().UTC(), Subnet: servers.LinkSubnet}
	ready := map[string]bool{}
	for id, s := range h.st.Servers {
		if s.State == ServerRevoked || s.Revoke != nil {
			continue
		}
		ip, err := netip.ParseAddr(s.TunnelIP)
		if err != nil {
			continue
		}
		st := linkdoc.StateReady
		if s.State == ServerEnrolling {
			st = linkdoc.StateEnrolling
		} else {
			ready[id] = true
		}
		d.Peers = append(d.Peers, linkdoc.Peer{ID: id, PublicKey: s.WGPublicKey, IP: ip, State: st})
	}
	for id, in := range h.st.Instances {
		if !ready[in.Server] || in.State == state.InstanceOrphaned {
			continue
		}
		if sum := h.relayTokenSHA(id); sum != "" {
			d.Relays = append(d.Relays, linkdoc.Relay{TokenSHA256: sum, Instance: id, Server: in.Server})
		}
	}
	sort.Slice(d.Peers, func(i, j int) bool { return d.Peers[i].ID < d.Peers[j].ID })
	sort.Slice(d.Relays, func(i, j int) bool { return d.Relays[i].Instance < d.Relays[j].Instance })
	return linkdoc.Write(h.cfg.LinkDocDir, h.cfg.LinkDocGID, d)
}
