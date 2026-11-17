package usage

// Total sums samples. A usage field summing any nil is a lower bound
// (partial true); all nil stays nil. A limit sums only when every member
// has one (non-zero); none with one is 0 (no limit); some is nil: "partly
// unlimited".
func Total(ss []Sample) (Sample, bool) {
	var t Sample
	partial := false
	sumI := func(get func(Sample) *int64) *int64 {
		var sum int64
		n := 0
		for _, s := range ss {
			if v := get(s); v != nil {
				sum += *v
				n++
			}
		}
		if n == 0 {
			return nil
		}
		if n < len(ss) {
			partial = true
		}
		return &sum
	}
	sumF := func(get func(Sample) *float64) *float64 {
		var sum float64
		n := 0
		for _, s := range ss {
			if v := get(s); v != nil {
				sum += *v
				n++
			}
		}
		if n == 0 {
			return nil
		}
		if n < len(ss) {
			partial = true
		}
		return &sum
	}
	limI := func(get func(Sample) *int64) *int64 {
		if len(ss) == 0 {
			return nil
		}
		var sum int64
		zeros := 0
		for _, s := range ss {
			v := get(s)
			switch {
			case v == nil:
				return nil
			case *v <= 0:
				zeros++
			default:
				sum += *v
			}
		}
		switch zeros {
		case 0:
			return &sum
		case len(ss):
			var none int64 // no member has a limit: no limit (0)
			return &none
		}
		return nil // partly unlimited
	}
	limF := func(get func(Sample) *float64) *float64 {
		if len(ss) == 0 {
			return nil
		}
		var sum float64
		for _, s := range ss {
			v := get(s)
			if v == nil || *v <= 0 {
				return nil
			}
			sum += *v
		}
		return &sum
	}
	t.CPUCores = sumF(func(s Sample) *float64 { return s.CPUCores })
	t.MemBytes = sumI(func(s Sample) *int64 { return s.MemBytes })
	t.Pids = sumI(func(s Sample) *int64 { return s.Pids })
	t.NetRxBps = sumF(func(s Sample) *float64 { return s.NetRxBps })
	t.NetTxBps = sumF(func(s Sample) *float64 { return s.NetTxBps })
	t.BlkReadBps = sumF(func(s Sample) *float64 { return s.BlkReadBps })
	t.BlkWriteBps = sumF(func(s Sample) *float64 { return s.BlkWriteBps })
	t.MemLimitBytes = limI(func(s Sample) *int64 { return s.MemLimitBytes })
	t.CPULimitCores = limF(func(s Sample) *float64 { return s.CPULimitCores })
	t.PidsLimit = limI(func(s Sample) *int64 { return s.PidsLimit })
	return t, partial
}
