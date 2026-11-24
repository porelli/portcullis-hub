package usage

import (
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

func TestDeriveWhy(t *testing.T) {
	full := func(at time.Time, n uint64) runtime.UnitStats {
		return runtime.UnitStats{Read: at, CPUUsageNS: u(n * 1e9), MemUsage: u(100), Pids: u(1), NetRx: u(n), NetTx: u(n), BlkRead: u(n), BlkWrite: u(n)}
	}
	// The first sample: every rate not measured yet, the rest measured.
	s := Derive(nil, time.Time{}, full(t0, 1), Limits{})
	for _, f := range []Field{FieldCPU, FieldNetRx, FieldNetTx, FieldBlkRead, FieldBlkWrite} {
		if s.Why[f] != WhyStart {
			t.Errorf("first: field %d why %d", f, s.Why[f])
		}
	}
	if s.Why[FieldMem] != WhyGap || s.Why[FieldPids] != WhyGap {
		t.Errorf("first: mem/pids why %v", s.Why)
	}
	nm := s.NotMeasured()
	if len(nm) != 5 || nm["cpu_cores"] != "not measured yet: no earlier sample since the container started" {
		t.Errorf("not_measured = %v", nm)
	}
	// After a restart (another start) too.
	prev := full(t0, 1)
	if s := Derive(&prev, t0.Add(-time.Hour), full(t0.Add(Interval), 2), Limits{StartedAt: t0}); s.Why[FieldCPU] != WhyStart {
		t.Errorf("restart: %v", s.Why)
	}
	// A counter going down: a restart seen by the counter.
	if s := Derive(&prev, time.Time{}, full(t0.Add(Interval), 0), Limits{}); s.CPUCores != nil || s.Why[FieldCPU] != WhyStart || s.Why[FieldBlkRead] != WhyStart {
		t.Errorf("counter down: %v", s.Why)
	}
	// Measured: no reason, no map.
	if s := Derive(&prev, time.Time{}, full(t0.Add(Interval), 2), Limits{}); s.Why != ([numFields]Why{}) || s.NotMeasured() != nil {
		t.Errorf("measured: %v %v", s.Why, s.NotMeasured())
	}
	// Network by network_mode.
	for mode, want := range map[string]Why{"host": WhyNetHost, "none": WhyNetNone, "container:abc": WhyNetShared, "service:db": WhyNetShared} {
		s := Derive(&prev, time.Time{}, full(t0.Add(Interval), 2), Limits{NetworkMode: mode})
		if s.Why[FieldNetRx] != want || s.Why[FieldNetTx] != want || s.Why[FieldCPU] != WhyGap {
			t.Errorf("%s: %v", mode, s.Why)
		}
		// Even on the first sample, the network reason wins.
		if s := Derive(nil, time.Time{}, full(t0, 1), Limits{NetworkMode: mode}); s.Why[FieldNetRx] != want {
			t.Errorf("%s first: %v", mode, s.Why)
		}
	}
	if got := (Sample{Why: [numFields]Why{FieldNetRx: WhyNetHost}}).NotMeasured(); got["net_rx_bps"] != "not measured: the container uses the host's network" {
		t.Errorf("host text = %v", got)
	}
	// The engine leaves a counter out (rootless Podman without io).
	cur := full(t0.Add(Interval), 2)
	cur.BlkRead, cur.BlkWrite, cur.Pids = nil, nil, nil
	if s := Derive(&prev, time.Time{}, cur, Limits{}); s.Why[FieldBlkRead] != WhyEngine || s.Why[FieldPids] != WhyEngine || s.Why[FieldCPU] != WhyGap ||
		s.NotMeasured()["blk_write_bps"] != "not measured: the engine gives no figure" {
		t.Errorf("engine: %v", s.Why)
	}
	if s := Derive(nil, time.Time{}, runtime.UnitStats{Read: t0}, Limits{}); s.Why[FieldCPU] != WhyEngine || s.Why[FieldMem] != WhyEngine {
		t.Errorf("no counters: %v", s.Why)
	}
	// Two samples less than a second apart: a gap, no reason.
	if s := Derive(&prev, time.Time{}, full(t0.Add(time.Millisecond), 2), Limits{}); s.CPUCores != nil || s.Why[FieldCPU] != WhyGap || s.Why[FieldNetRx] != WhyGap {
		t.Errorf("too close: %v", s.Why)
	}
	// A failed stats call: limits only, every figure a gap.
	if s := LimitsSample(Limits{}); s.Why != ([numFields]Why{}) {
		t.Errorf("limits sample: %v", s.Why)
	}
}

func TestMeanExcused(t *testing.T) {
	start := Sample{MemBytes: pi(1), Why: [numFields]Why{FieldCPU: WhyStart, FieldNetRx: WhyNetHost}}
	two := Sample{CPUCores: pf(2), MemBytes: pi(1), Why: [numFields]Why{FieldNetRx: WhyNetHost}}
	four := Sample{CPUCores: pf(4), MemBytes: pi(1), Why: [numFields]Why{FieldNetRx: WhyNetHost}}
	m, partial := Mean(meanPts(start, two, four))
	if m.CPUCores == nil || *m.CPUCores != 3 || m.NetRxBps != nil || m.Why[FieldNetRx] != WhyNetHost || m.Why[FieldCPU] != WhyGap {
		t.Errorf("mean = %v why %v", m.CPUCores, m.Why)
	}
	// Pids, NetTx, Blk are nil with no reason: real gaps.
	if !partial {
		t.Error("unexcused nil fields were not partial")
	}
	full := func(s Sample) Sample {
		s.Pids, s.NetTxBps, s.BlkReadBps, s.BlkWriteBps = pi(1), pf(1), pf(1), pf(1)
		return s
	}
	if _, partial := Mean(meanPts(full(start), full(two), full(four))); partial {
		t.Error("a first sample and a host network made the mean partial")
	}
	// Only the first sample: CPU not measured yet, not partial.
	m, partial = Mean(meanPts(full(start)))
	if m.CPUCores != nil || m.Why[FieldCPU] != WhyStart || partial {
		t.Errorf("first only = %v %v %v", m.CPUCores, m.Why, partial)
	}
	// A real gap mid-window (a failed stats call): partial.
	if _, partial := Mean(meanPts(full(start), LimitsSample(Limits{}), full(four))); !partial {
		t.Error("a gap mid-window was not partial")
	}
}

func TestTotalExcused(t *testing.T) {
	a := Sample{CPUCores: pf(1), MemBytes: pi(1), Pids: pi(1), BlkReadBps: pf(1), BlkWriteBps: pf(1), NetRxBps: pf(1), NetTxBps: pf(1)}
	b := Sample{CPUCores: pf(1), MemBytes: pi(1), Pids: pi(1), BlkReadBps: pf(1), BlkWriteBps: pf(1),
		Why: [numFields]Why{FieldNetRx: WhyNetHost, FieldNetTx: WhyNetHost}}
	tot, partial := TotalExcused([]Sample{a, b})
	if partial || tot.NetRxBps == nil || *tot.NetRxBps != 1 || *tot.CPUCores != 2 {
		t.Errorf("excused = %+v %v", tot, partial)
	}
	// Total (window last) still counts it.
	if _, partial := Total([]Sample{a, b}); !partial {
		t.Error("Total changed")
	}
	// A gap still makes it partial.
	c := b
	c.CPUCores = nil
	if _, partial := TotalExcused([]Sample{a, c}); !partial {
		t.Error("a gap was not partial")
	}
}

// TestTotalSaturates (Task 10 review M1): untrusted figures never wrap a
// total negative.
func TestTotalSaturates(t *testing.T) {
	big := Sample{MemBytes: pi(1 << 62), MemLimitBytes: pi(1 << 62)}
	for _, f := range []func([]Sample) (Sample, bool){Total, TotalExcused} {
		tot, _ := f([]Sample{big, big, big})
		if *tot.MemBytes != 1<<62 || *tot.MemLimitBytes != 1<<62 {
			t.Errorf("saturated = %d %d", *tot.MemBytes, *tot.MemLimitBytes)
		}
	}
	if s := DeriveHost(&HostCounters{At: t0, CPUTotal: 100}, HostCounters{At: t0.Add(Interval), CPUTotal: 200}, 1<<30); s.CPUUsedCores == nil || *s.CPUUsedCores != MaxCPUCores {
		t.Errorf("host cpus bounded: %v", s.CPUUsedCores)
	}
}
