package hub

import (
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
	"github.com/portcullis/hub/internal/version"
)

// The servers' doctor inputs (plan Task 13, contract §14.5): the raw
// facts doctor/servers_kinds.go judges. Caller holds mu (read); srvMu is
// taken for the poll facts. No network call, no lock of another order:
// only the backups directory is read (names, never an archive).

// serverKindsInLocked fills in's Task 13 fields.
func (h *Hub) serverKindsInLocked(in *doctor.ServersIn, backups map[string]time.Time) {
	in.Now = h.now()
	in.HubVersion = version.Version
	in.LinkSubnet = servers.LinkSubnet
	in.Orphaned = map[string]string{}
	byServer := map[string][]string{}
	for _, id := range slices.Sorted(maps.Keys(h.st.Instances)) {
		e := h.st.Instances[id]
		if e.Server == "" && e.MovedFrom == nil && e.MoveTargetLeftover == nil {
			continue
		}
		if e.Server != "" {
			byServer[e.Server] = append(byServer[e.Server], id)
			srv, ok := h.st.Servers[e.Server]
			if e.State == state.InstanceOrphaned || !ok || srv.State == ServerRevoked {
				in.Orphaned[id] = e.Server
			} else {
				in.Placed = append(in.Placed, doctor.PlacedIn{ID: id, Server: e.Server, Enabled: h.st.IsEnabled(id), LastBackup: backups[id]})
			}
		}
		if e.State != state.InstanceMoving {
			// A running move's records aren't leftovers yet.
			if mf := e.MovedFrom; mf != nil && len(mf.Volumes) > 0 && mf.Server != e.Server {
				in.Leftovers = append(in.Leftovers, doctor.LeftoverIn{Instance: id, Server: mf.Server, At: mf.At, Volumes: slices.Clone(mf.Volumes)})
			}
			if tl := e.MoveTargetLeftover; tl != nil && len(tl.Volumes) > 0 && tl.Server != e.Server {
				in.Leftovers = append(in.Leftovers, doctor.LeftoverIn{Instance: id, Server: tl.Server, At: tl.At, Volumes: slices.Clone(tl.Volumes), Target: true})
			}
		}
	}
	h.srvMu.Lock()
	for _, id := range slices.Sorted(maps.Keys(h.st.Servers)) {
		s := h.st.Servers[id]
		sv := doctor.ServerIn{ID: id, Name: s.Name, State: s.State, CertNotAfter: s.CertNotAfter, AgentVersion: s.AgentVersion, Instances: byServer[id]}
		if ps := h.polls[id]; ps != nil {
			sv.Reason = untrusted(ps.reason, 300)
			if inf := ps.info; inf != nil {
				sv.Info = true
				sv.AgentVersion = untrusted(inf.AgentVersion, 40)
				sv.DiskTotal, sv.DiskFree, sv.DataTotal, sv.DataFree = inf.DiskTotal, inf.DiskFree, inf.DataTotal, inf.DataFree
			}
		}
		in.Servers = append(in.Servers, sv)
	}
	h.srvMu.Unlock()
	in.Ranges = h.linkOverlapRangesLocked()
}

// linkOverlapRangesLocked are the ranges the link subnet must not
// overlap (link_subnet_overlap): the built-in VPN subnet, every wired
// provider's ranges, and each server's Local networks the admin set. The
// default Local networks list (RFC 1918 and friends, covering 10/8) and
// broad catch-alls shorter than /16 in a set list say "my LANs are
// somewhere in here", not that a LAN uses the link subnet: left out.
func (h *Hub) linkOverlapRangesLocked() []doctor.RangeIn {
	var out []doctor.RangeIn
	for _, r := range h.vpnAllowRangesLocked([]string{state.ReachAny}) {
		if p, err := netip.ParsePrefix(r); err == nil {
			out = append(out, doctor.RangeIn{Name: "the VPN range", Prefix: p.Masked()})
		}
	}
	add := func(owner string, list *[]string) {
		if list == nil {
			return
		}
		for _, c := range *list {
			if p, err := netip.ParsePrefix(c); err == nil && p.Bits() >= 16 {
				out = append(out, doctor.RangeIn{Name: owner + "'s Local network", Prefix: p.Masked()})
			}
		}
	}
	add("the primary", h.st.LocalNetworks)
	for _, id := range slices.Sorted(maps.Keys(h.st.Servers)) {
		add("server "+id, h.st.Servers[id].LocalNetworks)
	}
	return out
}

// newestBackups is every instance's newest archive time, from the file
// names (no archive read). No lock: call it before taking mu (I1).
func (h *Hub) newestBackups() map[string]time.Time {
	out := map[string]time.Time{}
	dirs, err := os.ReadDir(h.backupsDir())
	if err != nil {
		return out
	}
	for _, d := range dirs {
		if !d.IsDir() || !templates.ValidID(d.Name()) {
			continue
		}
		id := d.Name()
		files, err := os.ReadDir(filepath.Join(h.backupsDir(), id))
		if err != nil {
			continue
		}
		for _, f := range files {
			if !f.Type().IsRegular() || !archiveRe.MatchString(id+"/"+f.Name()) {
				continue
			}
			t, err := time.Parse(backupTimeFmt, strings.TrimSuffix(f.Name(), ".tar"))
			if err == nil && t.After(out[id]) {
				out[id] = t
			}
		}
	}
	return out
}

// serverLocalNetworksLocked are each worker's Local networks (its set
// list, else the defaults) for lan_only_exposed. Caller holds mu.
func (h *Hub) serverLocalNetworksLocked() map[string][]netip.Prefix {
	out := map[string][]netip.Prefix{}
	for id, s := range h.st.Servers {
		out[id] = h.localNetworksOfLocked(id, s)
	}
	return out
}

// localNetworksOfLocked is server id's Local networks (s its entry).
func (h *Hub) localNetworksOfLocked(id string, s state.Server) []netip.Prefix {
	if id == "" {
		return h.localNetworksLocked()
	}
	cidrs := DefaultLocalNetworks
	if s.LocalNetworks != nil {
		cidrs = *s.LocalNetworks
	}
	nets, err := state.ParseLocalNetworks(cidrs)
	if err != nil {
		return nil // fail closed: loopback only
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i].String() < nets[j].String() })
	return nets
}

// serverBindRootsLocked are each worker's folder roots as last polled.
// Caller holds mu; takes srvMu.
func (h *Hub) serverBindRootsLocked() map[string][]string {
	out := map[string][]string{}
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	for id, ps := range h.polls {
		if ps != nil && ps.info != nil {
			out[id] = slices.Clone(ps.info.BindRoots)
		}
	}
	return out
}

// tunnelRangesLocked are the ranges that are never a LAN (L3): the link
// subnet and the built-in VPN subnet. Caller holds mu.
func (h *Hub) tunnelRangesLocked() []doctor.RangeIn {
	out := []doctor.RangeIn{{Name: "the link subnet", Prefix: servers.LinkSubnet}}
	h.vpnrt.mu.Lock()
	pp := h.vpnrt.people
	h.vpnrt.mu.Unlock()
	if pp != nil {
		if sub, err := netip.ParsePrefix(pp.Subnet); err == nil {
			out = append(out, doctor.RangeIn{Name: "the VPN subnet", Prefix: sub.Masked()})
		}
	}
	return out
}
