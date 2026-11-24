package usage

// Total sums samples. A usage field summing any nil is a lower bound
// (partial true); all nil stays nil. A limit sums only when every member
// has one (non-zero); none with one is 0 (no limit); some is nil: "partly
// unlimited".
func Total(ss []Sample) (Sample, bool) { return total(ss, false) }

// TotalExcused is Total for window 1h (contract §11.11): a member's nil
// field with a known reason (its Why) doesn't make the total partial.
func TotalExcused(ss []Sample) (Sample, bool) { return total(ss, true) }

func total(ss []Sample, excuse bool) (Sample, bool) {
	var t Sample
	partial := false
	// gaps: whether a member's nil field fd counts as partial.
	gaps := func(fd Field, isNil func(Sample) bool) {
		for _, s := range ss {
			if isNil(s) && (!excuse || s.Why[fd] == WhyGap) {
				partial = true
			}
		}
	}
	sumI := func(fd Field, get func(Sample) *int64) *int64 {
		var sum int64
		n := 0
		for _, s := range ss {
			if v := get(s); v != nil {
				sum = satAdd(sum, *v)
				n++
			}
		}
		if n == 0 {
			return nil
		}
		gaps(fd, func(s Sample) bool { return get(s) == nil })
		return &sum
	}
	sumF := func(fd Field, get func(Sample) *float64) *float64 {
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
		gaps(fd, func(s Sample) bool { return get(s) == nil })
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
				sum = satAdd(sum, *v)
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
	t.CPUCores = sumF(FieldCPU, func(s Sample) *float64 { return s.CPUCores })
	t.MemBytes = sumI(FieldMem, func(s Sample) *int64 { return s.MemBytes })
	t.Pids = sumI(FieldPids, func(s Sample) *int64 { return s.Pids })
	t.NetRxBps = sumF(FieldNetRx, func(s Sample) *float64 { return s.NetRxBps })
	t.NetTxBps = sumF(FieldNetTx, func(s Sample) *float64 { return s.NetTxBps })
	t.BlkReadBps = sumF(FieldBlkRead, func(s Sample) *float64 { return s.BlkReadBps })
	t.BlkWriteBps = sumF(FieldBlkWrite, func(s Sample) *float64 { return s.BlkWriteBps })
	t.MemLimitBytes = limI(func(s Sample) *int64 { return s.MemLimitBytes })
	t.CPULimitCores = limF(func(s Sample) *float64 { return s.CPULimitCores })
	t.PidsLimit = limI(func(s Sample) *int64 { return s.PidsLimit })
	return t, partial
}

// satAdd is a + b, saturating at ±maxBytes (an untrusted worker's figures
// never wrap a total).
func satAdd(a, b int64) int64 {
	switch {
	case b > 0 && a > maxBytes-b:
		return maxBytes
	case b < 0 && a < -maxBytes-b:
		return -maxBytes
	}
	return a + b
}
