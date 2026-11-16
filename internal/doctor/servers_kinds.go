package doctor

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/servers"
)

// The servers' doctor kinds (contract §14.5, plan Task 13): each reads
// ServersIn's raw facts and judges them here (thresholds included).
const (
	KindServerOffline           = "server_offline"
	KindServerCertExpiring      = "server_cert_expiring"
	KindServerAgentIncompatible = "server_agent_incompatible"
	KindServerAgentOutdated     = "server_agent_outdated"
	KindServerDiskLow           = "server_disk_low"
	KindServerNoRecentBackup    = "server_no_recent_backup"
	KindServerMoveLeftover      = "server_move_leftover"
	KindLinkSubnetOverlap       = "link_subnet_overlap"
	KindInstanceOrphaned        = "instance_orphaned"

	// FixRemoveMoveLeftover removes a move's leftover volumes (param
	// confirm: the instance id typed).
	FixRemoveMoveLeftover = "remove_move_leftover"
)

// The thresholds (contract §14.5).
const (
	CertExpiringWithin = 7 * 24 * time.Hour
	DiskLowPercent     = 10.0
	NoBackupWithin     = 14 * 24 * time.Hour
	LeftoverAfter      = 7 * 24 * time.Hour
)

// ServerIn is one worker server as the doctor reads it (never a key, a
// secret or a serial). Info false: no /v1/info yet (the agent facts are
// unknown and judged by nothing).
type ServerIn struct {
	ID, Name, State string
	// Reason: why it is offline (an identity mismatch included).
	Reason       string
	CertNotAfter time.Time
	AgentVersion string
	Info         bool
	DiskTotal    int64
	DiskFree     int64
	DataTotal    int64
	DataFree     int64
	Instances    []string
}

// PlacedIn is an instance on a worker: its server and its newest backup
// (zero = none). Enabled: only running instances need backups.
type PlacedIn struct {
	ID, Server string
	Enabled    bool
	LastBackup time.Time
}

// LeftoverIn is a copy a move left: a kept source (Target false, judged
// after LeftoverAfter) or a failed move's half-restored target (at once).
type LeftoverIn struct {
	Instance, Server string
	At               time.Time
	Volumes          []string
	Target           bool
}

// RangeIn is a named address range the link subnet must not overlap.
type RangeIn struct {
	Name   string
	Prefix netip.Prefix
}

func init() {
	for _, k := range []string{KindServerOffline, KindServerCertExpiring, KindServerAgentIncompatible, KindServerAgentOutdated,
		KindServerDiskLow, KindServerNoRecentBackup, KindServerMoveLeftover, KindLinkSubnetOverlap, KindInstanceOrphaned} {
		Register(serverKindCheck{kind: k})
	}
}

type serverKindCheck struct{ kind string }

func (c serverKindCheck) Kind() string { return c.kind }

func serverLabel(s ServerIn) string {
	if s.Name != "" && s.Name != s.ID {
		return s.Name + " (" + s.ID + ")"
	}
	return s.ID
}

// Outdated: the agent is one minor behind the Hub (compatible, not the
// same minor).
func agentOutdated(hub, agent string) bool {
	return servers.Compatible(hub, agent) && !servers.Compatible(agent, hub)
}

// lowPercent is free/total as a percentage, and whether it is below the
// threshold (total 0: unknown, never low).
func lowPercent(free, total int64) (float64, bool) {
	if total <= 0 {
		return 0, false
	}
	p := float64(free) * 100 / float64(total)
	return p, p < DiskLowPercent
}

func (c serverKindCheck) Run(in *Inputs) []Finding {
	s := in.Servers
	if s == nil {
		return nil
	}
	now := s.Now
	if now.IsZero() {
		now = time.Now()
	}
	var out []Finding
	add := func(f Finding, subjects ...string) {
		f.Kind = c.kind
		f.FP = Fingerprint(c.kind, subjects...)
		if f.Class == "" {
			f.Class = FixExplain
		}
		out = append(out, f)
	}
	switch c.kind {
	case KindServerOffline:
		for _, sv := range s.Servers {
			if sv.State != "offline" {
				continue
			}
			why := "It missed three polls in a row, or its tunnel has had no handshake for 3 minutes."
			if sv.Reason != "" {
				why = "The Hub can't reach it: " + sv.Reason + "."
			}
			add(Finding{Severity: Problem, Title: "The server " + serverLabel(sv) + " is offline.", Why: why + " Its instances can't be reached until it is back.",
				Instances: append([]string(nil), sv.Instances...), Inputs: Digest([]any{sv.ID, sv.Reason, sv.Instances}),
				Steps: []string{"Check that the server is on, its Portcullis worker is up (./portcullis worker status) and it reaches the primary on the link port.",
					"If its identity changed (server_identity_mismatch), it isn't the server that enrolled: revoke it and enrol it again."}}, sv.ID)
		}
	case KindServerCertExpiring:
		for _, sv := range s.Servers {
			if sv.CertNotAfter.IsZero() || sv.State == "revoked" || sv.State == "enrolling" || sv.CertNotAfter.Sub(now) > CertExpiringWithin {
				continue
			}
			add(Finding{Severity: Warning, Title: "The certificate of server " + serverLabel(sv) + " expires " + sv.CertNotAfter.UTC().Format("2006-01-02 15:04 UTC") + ".",
				Why: "Its renewal (due at a third of its lifetime) keeps failing; once it expires the Hub can't reach the server.", Inputs: Digest([]any{sv.ID, sv.CertNotAfter}),
				Steps: []string{"Check that enroll is up on the primary and the server is online: the Hub retries the renewal on every poll."}}, sv.ID)
		}
	case KindServerAgentIncompatible, KindServerAgentOutdated:
		for _, sv := range s.Servers {
			if !sv.Info || sv.State == "revoked" || sv.State == "enrolling" {
				continue
			}
			incompatible := !servers.Compatible(s.HubVersion, sv.AgentVersion)
			if c.kind == KindServerAgentIncompatible && incompatible {
				add(Finding{Severity: Problem, Title: "The agent on server " + serverLabel(sv) + " (" + clipText(sv.AgentVersion) + ") doesn't fit this Hub (" + clipText(s.HubVersion) + ").",
					Why:       "The Hub works with an agent of its own minor version or the one before. Every start, stop or change of its instances is refused until it is upgraded.",
					Instances: append([]string(nil), sv.Instances...), Inputs: Digest([]any{sv.ID, sv.AgentVersion, s.HubVersion}),
					Steps: []string{"On the server, run ./portcullis worker upgrade (or pull the agent image the primary's release pins)."}}, sv.ID)
			}
			if c.kind == KindServerAgentOutdated && !incompatible && agentOutdated(s.HubVersion, sv.AgentVersion) {
				add(Finding{Severity: Info, Title: "The agent on server " + serverLabel(sv) + " is one version behind the Hub.",
					Why: "It still works; the next Hub upgrade will refuse it.", Inputs: Digest([]any{sv.ID, sv.AgentVersion, s.HubVersion}),
					Steps: []string{"On the server, run ./portcullis worker upgrade."}}, sv.ID)
			}
		}
	case KindServerDiskLow:
		for _, sv := range s.Servers {
			if !sv.Info || sv.State == "revoked" {
				continue
			}
			var low []string
			if p, ok := lowPercent(sv.DiskFree, sv.DiskTotal); ok {
				low = append(low, fmt.Sprintf("the engine's data root has %.1f %% free", p))
			}
			if p, ok := lowPercent(sv.DataFree, sv.DataTotal); ok {
				low = append(low, fmt.Sprintf("the worker's data directory has %.1f %% free", p))
			}
			if len(low) == 0 {
				continue
			}
			add(Finding{Severity: Warning, Title: "Server " + serverLabel(sv) + " is low on disk space.", Why: strings.Join(low, "; ") + " (below 10 %): starts, restores and moves can fail.",
				Instances: append([]string(nil), sv.Instances...), Inputs: Digest([]any{sv.ID, low}),
				Steps: []string{"Free space on the server (old images: docker image prune), or move an instance to another server."}}, sv.ID)
		}
	case KindServerNoRecentBackup:
		for _, p := range s.Placed {
			if !p.Enabled || (!p.LastBackup.IsZero() && now.Sub(p.LastBackup) <= NoBackupWithin) {
				continue
			}
			when := "has never been backed up"
			if !p.LastBackup.IsZero() {
				when = "was last backed up " + p.LastBackup.UTC().Format("2006-01-02")
			}
			add(Finding{Severity: Warning, Title: p.ID + " on " + p.Server + " " + when + ".",
				Why: "An instance on a worker has no backup from the last 14 days: if the server fails, its data is lost.", Instances: []string{p.ID},
				Inputs: Digest([]any{p.ID, p.Server, p.LastBackup}),
				Steps:  []string{"Back it up now (its Backups tab), or turn on scheduled backups for its server (Settings → Servers)."}}, p.ID)
		}
	case KindServerMoveLeftover:
		for _, l := range s.Leftovers {
			if !l.Target && now.Sub(l.At) <= LeftoverAfter {
				continue
			}
			what := "the stopped copy a move kept on " + labelOrPrimary(l.Server) + " since " + l.At.UTC().Format("2006-01-02")
			if l.Target {
				what = "the half-restored volumes a failed move left on " + labelOrPrimary(l.Server)
			}
			add(Finding{Severity: Info, Title: l.Instance + ": " + what + " can be removed.",
				Why:       "Undo move is no longer possible (or the move never finished there); its volumes only take space: " + strings.Join(l.Volumes, ", ") + ".",
				Instances: []string{l.Instance}, Inputs: Digest([]any{l.Instance, l.Server, l.At, l.Volumes, l.Target}),
				Class: FixOneClick, FixKind: FixRemoveMoveLeftover}, l.Instance)
		}
	case KindLinkSubnetOverlap:
		if !s.LinkSubnet.IsValid() {
			return nil
		}
		ranges := append([]RangeIn(nil), s.Ranges...)
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].Name < ranges[j].Name })
		var hit []string
		for _, r := range ranges {
			if r.Prefix.IsValid() && r.Prefix.Overlaps(s.LinkSubnet) {
				hit = append(hit, r.Name+" "+r.Prefix.String())
			}
		}
		if len(hit) == 0 {
			return nil
		}
		add(Finding{Severity: Problem, Title: "The link subnet " + s.LinkSubnet.String() + " overlaps " + strings.Join(hit, ", ") + ".",
			Why:    "The primary routes " + s.LinkSubnet.String() + " to its worker servers: addresses in the overlapping range are routed to the wrong place.",
			Inputs: Digest(hit),
			Steps:  []string{"Change the overlapping range (the VPN subnet, the provider's range or the Local network) so it doesn't cover " + s.LinkSubnet.String() + "."}}, "link")
	case KindInstanceOrphaned:
		for _, id := range sortedKeys(s.Orphaned) {
			add(Finding{Severity: Problem, Title: "The instance " + id + " is orphaned: its server " + s.Orphaned[id] + " was revoked.",
				Why: "It runs nowhere Portcullis can reach. Its data is in its last backup.", Instances: []string{id}, Inputs: Digest([]any{id, s.Orphaned[id]}),
				Steps: []string{"Restore its last backup onto another server, or forget it (its page: Delete → Forget)."}}, id)
		}
	}
	return out
}

func labelOrPrimary(s string) string {
	if s == "" {
		return "the primary"
	}
	return s
}

func clipText(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	if s == "" {
		return "unknown"
	}
	return s
}
