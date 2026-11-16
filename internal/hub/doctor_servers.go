package hub

import (
	"context"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/version"
)

// The servers' doctor inputs (plan Task 13, contract §14.5): the raw
// facts doctor/servers_kinds.go judges. Caller holds mu (read); srvMu is
// taken for the poll facts. No network call, no lock of another order:
// only the backups directory is read (names, never an archive).

// serverKindsInLocked fills in's Task 13 fields.
func (h *Hub) serverKindsInLocked(in *doctor.ServersIn) {
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
				in.Placed = append(in.Placed, doctor.PlacedIn{ID: id, Server: e.Server, Enabled: h.st.IsEnabled(id), LastBackup: h.newestBackupAt(id)})
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
			sv.Reason = ps.reason
			if inf := ps.info; inf != nil {
				sv.Info = true
				sv.AgentVersion = inf.AgentVersion
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

// newestBackupAt is instance id's newest archive time, from its file
// names (zero: none). No lock.
func (h *Hub) newestBackupAt(id string) time.Time {
	files, err := os.ReadDir(filepath.Join(h.backupsDir(), id))
	if err != nil {
		return time.Time{}
	}
	var newest time.Time
	for _, f := range files {
		if !f.Type().IsRegular() || !archiveRe.MatchString(id+"/"+f.Name()) {
			continue
		}
		t, err := time.Parse(backupTimeFmt, strings.TrimSuffix(f.Name(), ".tar"))
		if err == nil && t.After(newest) {
			newest = t
		}
	}
	return newest
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

// OpMoveLeftover is remove_move_leftover's operation.
const OpMoveLeftover = "move_leftover"

func init() { RegisterFixer(removeMoveLeftoverFixer{}) }

// removeMoveLeftoverFixer is server_move_leftover's one-click fix
// (contract §14.6): preview one line per kept volume, "remove <volume>
// on <server>"; apply (param confirm: the instance id typed) runs what
// DELETE /api/instances/{id}/move-leftover runs.
type removeMoveLeftoverFixer struct{}

func (removeMoveLeftoverFixer) Kind() string { return doctor.FixRemoveMoveLeftover }

// TouchesData (G45): it removes volumes.
func (removeMoveLeftoverFixer) TouchesData() bool { return true }

func (removeMoveLeftoverFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	if len(f.Instances) == 1 {
		return f.Instances[0]
	}
	return ""
}

// leftoverPlan is the fix's lines and hash for finding f, as the state is
// now (409 when nothing is left to remove).
func (h *Hub) leftoverPlan(f doctor.Finding, params map[string]string) (string, []string, string, error) {
	if err := checkFixParams(params, "confirm"); err != nil {
		return "", nil, "", err
	}
	if len(f.Instances) != 1 {
		return "", nil, "", statusErr(409, "this finding names no instance")
	}
	id := f.Instances[0]
	h.mu.RLock()
	e := h.st.Instances[id]
	h.mu.RUnlock()
	var lines []string
	for _, l := range []*state.MovedFrom{e.MovedFrom, e.MoveTargetLeftover} {
		if l == nil || l.Server == e.Server {
			continue
		}
		for _, v := range l.Volumes {
			lines = append(lines, "remove "+v+" on "+serverLabel(l.Server))
		}
	}
	if len(lines) == 0 {
		return "", nil, "", statusErr(409, "%s has no move leftover any more", id)
	}
	return id, lines, fixHash(struct {
		Instance string
		Lines    []string
	}{id, lines}), nil
}

func (removeMoveLeftoverFixer) Preview(_ context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	_, lines, hash, err := h.leftoverPlan(f, params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: lines, Hash: hash, Warnings: []string{"Undo move isn't possible afterwards."}}, nil
}

func (removeMoveLeftoverFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash string, actor directory.Actor) (*AsyncOp, error) {
	id, _, hash, err := h.leftoverPlan(f, params)
	if err != nil {
		return nil, err
	}
	if params["confirm"] != id {
		return nil, statusErr(400, "type the instance id (%s) to confirm (param confirm)", id)
	}
	if planHash == "" || planHash != hash {
		return nil, statusErr(409, "the leftover changed since the preview: preview it again")
	}
	return h.startAsync(id, OpMoveLeftover, actor, nil, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		if _, _, now, err := h.leftoverPlan(f, params); err != nil || now != hash {
			return nil, nil, statusErr(409, "the leftover changed since the preview: preview it again")
		}
		return nil, nil, h.RemoveMoveLeftover(ctx, id, id, actor)
	})
}
