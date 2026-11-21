package usage

import (
	"testing"
	"time"
)

func pf(v float64) *float64 { return &v }
func pi(v int64) *int64     { return &v }

var meanT0 = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

func meanPts(ss ...Sample) []Point {
	ps := make([]Point, len(ss))
	for i, s := range ss {
		ps[i] = Point{T: meanT0.Add(time.Duration(i) * Interval), S: s}
	}
	return ps
}

func TestMeanSkipsNulls(t *testing.T) {
	m, partial := Mean(meanPts(Sample{CPUCores: pf(1), MemBytes: pi(10)}, Sample{MemBytes: pi(20)}, Sample{CPUCores: pf(3), MemBytes: pi(30)}))
	if m.CPUCores == nil || *m.CPUCores != 2 || m.MemBytes == nil || *m.MemBytes != 20 || !partial {
		t.Errorf("mean = %v %v partial %v", m.CPUCores, m.MemBytes, partial)
	}
	// Every point has the figure: not partial.
	m, partial = Mean(meanPts(Sample{CPUCores: pf(1), MemBytes: pi(1), Pids: pi(2), NetRxBps: pf(1), NetTxBps: pf(1), BlkReadBps: pf(1), BlkWriteBps: pf(1)},
		Sample{CPUCores: pf(2), MemBytes: pi(2), Pids: pi(4), NetRxBps: pf(3), NetTxBps: pf(3), BlkReadBps: pf(3), BlkWriteBps: pf(3)}))
	if partial || *m.CPUCores != 1.5 || *m.Pids != 3 || *m.NetRxBps != 2 || *m.BlkWriteBps != 2 {
		t.Errorf("full = %+v partial %v", m, partial)
	}
	// Integers round to the nearest.
	m, _ = Mean(meanPts(Sample{MemBytes: pi(1)}, Sample{MemBytes: pi(2)}))
	if *m.MemBytes != 2 {
		t.Errorf("rounded mem = %d", *m.MemBytes)
	}
	// All nil: nil, and partial (every point was skipped).
	m, partial = Mean(meanPts(Sample{}, Sample{}))
	if m.CPUCores != nil || m.MemBytes != nil || !partial {
		t.Errorf("all nil = %+v partial %v", m, partial)
	}
	// No point: nothing, not partial.
	m, partial = Mean(nil)
	if m != (Sample{}) || partial {
		t.Errorf("empty = %+v partial %v", m, partial)
	}
}

func TestMeanLimitsFromLast(t *testing.T) {
	m, _ := Mean(meanPts(
		Sample{CPUCores: pf(1), MemLimitBytes: pi(100), CPULimitCores: pf(1), PidsLimit: pi(10)},
		Sample{CPUCores: pf(1), MemLimitBytes: pi(300), CPULimitCores: pf(3), PidsLimit: pi(30)},
		Sample{CPUCores: pf(1), MemLimitBytes: pi(0), CPULimitCores: nil, PidsLimit: pi(50)},
	))
	if m.MemLimitBytes == nil || *m.MemLimitBytes != 0 || m.CPULimitCores != nil || m.PidsLimit == nil || *m.PidsLimit != 50 {
		t.Errorf("limits = %v %v %v", m.MemLimitBytes, m.CPULimitCores, m.PidsLimit)
	}
	// A copy: the mean never aliases the ring's point.
	ps := meanPts(Sample{PidsLimit: pi(7), CPULimitCores: pf(2)})
	m, _ = Mean(ps)
	*m.PidsLimit, *m.CPULimitCores = 1, 1
	if *ps[0].S.PidsLimit != 7 || *ps[0].S.CPULimitCores != 2 {
		t.Error("the mean aliases the point's limits")
	}
}

func TestMeanHost(t *testing.T) {
	ps := []HostPoint{
		{T: meanT0, S: HostSample{MemUsedBytes: pi(100)}},
		{T: meanT0.Add(Interval), S: HostSample{CPUUsedCores: pf(1), MemUsedBytes: pi(200), BlkReadBps: pf(10), BlkWriteBps: pf(0)}},
		{T: meanT0.Add(2 * Interval), S: HostSample{CPUUsedCores: pf(2), MemUsedBytes: pi(300), BlkReadBps: pf(20), BlkWriteBps: pf(4)}},
	}
	m, partial := MeanHost(ps)
	if m.CPUUsedCores == nil || *m.CPUUsedCores != 1.5 || *m.MemUsedBytes != 200 || *m.BlkReadBps != 15 || *m.BlkWriteBps != 2 || !partial {
		t.Errorf("mean host = %+v partial %v", m, partial)
	}
	if m, partial := MeanHost(nil); m != (HostSample{}) || partial {
		t.Errorf("empty = %+v %v", m, partial)
	}
	if m, partial := MeanHost(ps[1:]); partial || *m.MemUsedBytes != 250 {
		t.Errorf("full = %+v %v", m, partial)
	}
}
