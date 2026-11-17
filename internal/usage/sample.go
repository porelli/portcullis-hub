// Package usage is the pure part of the Hub's usage page (contract
// §11.11): one sample's figures from two engine samples, the per-container
// rings, totals and the CSV export's escaping. It never calls the engine;
// internal/hub holds the sampler, its scope and caches.
package usage

import (
	"strings"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// The sampler's pinned values (contract §11.11).
const (
	Interval      = 15 * time.Second
	RingSize      = 240 // 1 h at Interval
	MaxContainers = 256
	Parallel      = 4
	StatsTimeout  = 5 * time.Second
	SweepBudget   = 12 * time.Second
	InspectEvery  = 5 * time.Minute
	InfoEvery     = time.Hour
	// MinInterval: two samples closer than this (by the engine's read
	// time) give no rate.
	MinInterval = time.Second
)

// Sample is one container's (or a total's) figures. Every field is nil
// when not measured: never 0 for missing data.
type Sample struct {
	CPUCores      *float64 `json:"cpu_cores"`
	MemBytes      *int64   `json:"mem_bytes"`
	MemLimitBytes *int64   `json:"mem_limit_bytes"` // 0 = no limit
	CPULimitCores *float64 `json:"cpu_limit_cores"` // nil = no limit
	Pids          *int64   `json:"pids"`
	PidsLimit     *int64   `json:"pids_limit"` // 0 = no limit
	NetRxBps      *float64 `json:"net_rx_bps"`
	NetTxBps      *float64 `json:"net_tx_bps"`
	BlkReadBps    *float64 `json:"blk_read_bps"`
	BlkWriteBps   *float64 `json:"blk_write_bps"`
}

// Limits are a container's limits and start, from its inspect.
type Limits struct {
	MemBytes    int64    // 0 = none
	CPUCores    *float64 // nil = none
	Pids        int64    // 0 = none
	NetworkMode string
	StartedAt   time.Time
	OOMKilled   bool
	Restarts    int
}

// LimitsOf reads the limits from an inspect: NanoCPUs, else
// CPUQuota/CPUPeriod.
func LimitsOf(i runtime.UnitInfo) Limits {
	l := Limits{MemBytes: max(i.Memory, 0), Pids: max(i.PidsLimit, 0), NetworkMode: i.NetworkMode,
		StartedAt: i.StartedAt, OOMKilled: i.OOMKilled, Restarts: i.RestartCount}
	switch {
	case i.NanoCPUs > 0:
		c := float64(i.NanoCPUs) / 1e9
		l.CPUCores = &c
	case i.CPUQuota > 0 && i.CPUPeriod > 0:
		c := float64(i.CPUQuota) / float64(i.CPUPeriod)
		l.CPUCores = &c
	}
	return l
}

// OwnNetwork reports whether a container's network counters are its own:
// host, none and a shared namespace (container:, service:) aren't.
func OwnNetwork(mode string) bool {
	switch {
	case mode == "host", mode == "none",
		strings.HasPrefix(mode, "container:"), strings.HasPrefix(mode, "service:"):
		return false
	}
	return true
}

// WorkingSet is the docker CLI's working set: usage − inactive_file,
// never below 0; the runtime's own figure when it gives one.
func WorkingSet(s runtime.UnitStats) *int64 {
	if s.MemWorkingSet != nil {
		v := clampInt(*s.MemWorkingSet)
		return &v
	}
	if s.MemUsage == nil {
		return nil
	}
	u := *s.MemUsage
	if s.MemInactiveFile != nil {
		if *s.MemInactiveFile >= u {
			u = 0
		} else {
			u -= *s.MemInactiveFile
		}
	}
	v := clampInt(u)
	return &v
}

func clampInt(u uint64) int64 {
	if u > 1<<62 {
		return 1 << 62
	}
	return int64(u)
}

// rate is (cur − prev) / dt per second, nil when either is missing or the
// counter went down.
func rate(prev, cur *uint64, dt time.Duration) *float64 {
	if prev == nil || cur == nil || *cur < *prev {
		return nil
	}
	v := float64(*cur-*prev) / dt.Seconds()
	return &v
}

// Derive is cur's figures, with rates against prev (the same container's
// previous sample, taken at the start prevStart). Rates are nil on the
// first sample, after a restart (StartedAt changed or a counter went
// down) and when the engine's read times are less than MinInterval
// apart or out of order.
func Derive(prev *runtime.UnitStats, prevStart time.Time, cur runtime.UnitStats, l Limits) Sample {
	mem, pidsLimit := l.MemBytes, l.Pids
	s := Sample{
		MemBytes:      WorkingSet(cur),
		MemLimitBytes: &mem,
		CPULimitCores: l.CPUCores,
		PidsLimit:     &pidsLimit,
	}
	if cur.Pids != nil {
		v := clampInt(*cur.Pids)
		s.Pids = &v
	}
	if cur.CPUCores != nil {
		v := *cur.CPUCores
		s.CPUCores = &v
	}
	if prev == nil || !prevStart.Equal(l.StartedAt) {
		return s
	}
	dt := cur.Read.Sub(prev.Read)
	if dt < MinInterval {
		return s
	}
	if s.CPUCores == nil && prev.CPUUsageNS != nil && cur.CPUUsageNS != nil && *cur.CPUUsageNS >= *prev.CPUUsageNS {
		v := float64(*cur.CPUUsageNS-*prev.CPUUsageNS) / float64(dt.Nanoseconds())
		s.CPUCores = &v
	}
	if OwnNetwork(l.NetworkMode) {
		s.NetRxBps = rate(prev.NetRx, cur.NetRx, dt)
		s.NetTxBps = rate(prev.NetTx, cur.NetTx, dt)
	}
	s.BlkReadBps = rate(prev.BlkRead, cur.BlkRead, dt)
	s.BlkWriteBps = rate(prev.BlkWrite, cur.BlkWrite, dt)
	return s
}
