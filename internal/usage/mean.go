package usage

import "math"

// Window 1h (contract §11.11): the means of the last hour's points.

// Mean is the mean of ps, each usage field over the points where it
// isn't nil (nil when none is). Only a real gap makes it partial: a nil
// point whose Why is WhyGap. A nil point with a known reason (a first
// sample, a network that can't be measured, a counter the engine leaves
// out) is skipped silently; a field nil on every point takes the newest
// point's reason. The limits (MemLimitBytes, CPULimitCores, PidsLimit)
// are the newest point's, never averaged. No point: an empty sample, not
// partial.
func Mean(ps []Point) (Sample, bool) {
	if len(ps) == 0 {
		return Sample{}, false
	}
	partial := false
	last := ps[len(ps)-1].S
	var m Sample
	// gap notes field fd's nil points without a reason, and the newest
	// point's reason when every point is nil.
	gap := func(fd Field, isNil func(Sample) bool) {
		all := true
		for _, p := range ps {
			if !isNil(p.S) {
				all = false
			} else if p.S.Why[fd] == WhyGap {
				partial = true
			}
		}
		if all {
			m.Why[fd] = last.Why[fd]
		}
	}
	f := func(fd Field, get func(Sample) *float64) *float64 {
		vs := make([]*float64, len(ps))
		for i, p := range ps {
			vs[i] = get(p.S)
		}
		v, _ := meanF(vs)
		gap(fd, func(s Sample) bool { return get(s) == nil })
		return v
	}
	n := func(fd Field, get func(Sample) *int64) *int64 {
		vs := make([]*int64, len(ps))
		for i, p := range ps {
			vs[i] = get(p.S)
		}
		v, _ := meanI(vs)
		gap(fd, func(s Sample) bool { return get(s) == nil })
		return v
	}
	m.CPUCores = f(FieldCPU, func(s Sample) *float64 { return s.CPUCores })
	m.MemBytes = n(FieldMem, func(s Sample) *int64 { return s.MemBytes })
	m.Pids = n(FieldPids, func(s Sample) *int64 { return s.Pids })
	m.NetRxBps = f(FieldNetRx, func(s Sample) *float64 { return s.NetRxBps })
	m.NetTxBps = f(FieldNetTx, func(s Sample) *float64 { return s.NetTxBps })
	m.BlkReadBps = f(FieldBlkRead, func(s Sample) *float64 { return s.BlkReadBps })
	m.BlkWriteBps = f(FieldBlkWrite, func(s Sample) *float64 { return s.BlkWriteBps })
	m.MemLimitBytes, m.CPULimitCores, m.PidsLimit = copyI(last.MemLimitBytes), copyF(last.CPULimitCores), copyI(last.PidsLimit)
	return m, partial
}

// MeanHost is the mean of the host's points, each figure over the points
// where it isn't nil; partial when a nil point was skipped.
func MeanHost(ps []HostPoint) (HostSample, bool) {
	if len(ps) == 0 {
		return HostSample{}, false
	}
	partial := false
	f := func(get func(HostSample) *float64) *float64 {
		vs := make([]*float64, len(ps))
		for i, p := range ps {
			vs[i] = get(p.S)
		}
		m, skipped := meanF(vs)
		partial = partial || skipped
		return m
	}
	mem := make([]*int64, len(ps))
	for i, p := range ps {
		mem[i] = p.S.MemUsedBytes
	}
	m := HostSample{
		CPUUsedCores: f(func(s HostSample) *float64 { return s.CPUUsedCores }),
		BlkReadBps:   f(func(s HostSample) *float64 { return s.BlkReadBps }),
		BlkWriteBps:  f(func(s HostSample) *float64 { return s.BlkWriteBps }),
	}
	var skipped bool
	m.MemUsedBytes, skipped = meanI(mem)
	return m, partial || skipped
}

// meanF is the mean of the non-nil values (nil when none is), and
// whether a nil was skipped.
func meanF(vs []*float64) (*float64, bool) {
	var sum float64
	k := 0
	for _, v := range vs {
		if v != nil {
			sum += *v
			k++
		}
	}
	if k == 0 {
		return nil, len(vs) > 0
	}
	m := sum / float64(k)
	return &m, k < len(vs)
}

// meanI is meanF for integers, rounded to the nearest (summed as float64:
// no overflow on large byte counts).
func meanI(vs []*int64) (*int64, bool) {
	var sum float64
	k := 0
	for _, v := range vs {
		if v != nil {
			sum += float64(*v)
			k++
		}
	}
	if k == 0 {
		return nil, len(vs) > 0
	}
	m := int64(math.Round(sum / float64(k)))
	return &m, k < len(vs)
}

func copyI(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyF(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
