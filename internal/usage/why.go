package usage

import "strings"

// Field is one usage field of a Sample (its limits aren't fields here).
type Field uint8

const (
	FieldCPU Field = iota
	FieldMem
	FieldPids
	FieldNetRx
	FieldNetTx
	FieldBlkRead
	FieldBlkWrite
	numFields
)

// fieldNames are the fields' JSON names (Sample's tags).
var fieldNames = [numFields]string{"cpu_cores", "mem_bytes", "pids", "net_rx_bps", "net_tx_bps", "blk_read_bps", "blk_write_bps"}

// Why is the known reason a field is nil (contract §11.11
// Container.not_measured). WhyGap: none known, a real gap (a failed
// stats call, samples less than MinInterval apart).
type Why uint8

const (
	WhyGap Why = iota
	WhyStart
	WhyNetHost
	WhyNetNone
	WhyNetShared
	WhyEngine
)

// whyTexts are the fixed texts (contract §11.11).
var whyTexts = [...]string{
	WhyStart:     "not measured yet: no earlier sample since the container started",
	WhyNetHost:   "not measured: the container uses the host's network",
	WhyNetNone:   "not measured: the container has no network",
	WhyNetShared: "not measured: the container shares another container's network",
	WhyEngine:    "not measured: the engine gives no figure",
}

// Text is w's fixed text ("" for WhyGap).
func (w Why) Text() string {
	if int(w) < len(whyTexts) {
		return whyTexts[w]
	}
	return ""
}

// NotMeasured maps each nil field with a known reason to its text (nil
// when none).
func (s Sample) NotMeasured() map[string]string {
	var out map[string]string
	for f := range numFields {
		if s.Why[f] == WhyGap || s.field(f) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[fieldNames[f]] = s.Why[f].Text()
	}
	return out
}

// field reports whether f is measured (non-nil) in s.
func (s Sample) field(f Field) bool {
	switch f {
	case FieldCPU:
		return s.CPUCores != nil
	case FieldMem:
		return s.MemBytes != nil
	case FieldPids:
		return s.Pids != nil
	case FieldNetRx:
		return s.NetRxBps != nil
	case FieldNetTx:
		return s.NetTxBps != nil
	case FieldBlkRead:
		return s.BlkReadBps != nil
	case FieldBlkWrite:
		return s.BlkWriteBps != nil
	}
	return false
}

// netWhy is the reason a network_mode's counters can't be measured
// (WhyGap: its own network).
func netWhy(mode string) Why {
	switch {
	case mode == "host":
		return WhyNetHost
	case mode == "none":
		return WhyNetNone
	case strings.HasPrefix(mode, "container:"), strings.HasPrefix(mode, "service:"):
		return WhyNetShared
	}
	return WhyGap
}
