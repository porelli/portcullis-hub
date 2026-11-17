package usage

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

func u(v uint64) *uint64 { return &v }

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func near(p *float64, want float64) bool { return p != nil && *p > want-1e-9 && *p < want+1e-9 }

func TestDeriveCPU(t *testing.T) {
	prev := runtime.UnitStats{Read: t0, CPUUsageNS: u(10e9)}
	cur := runtime.UnitStats{Read: t0.Add(15 * time.Second), CPUUsageNS: u(13e9)}
	if s := Derive(&prev, time.Time{}, cur, Limits{}); !near(s.CPUCores, 0.2) {
		t.Errorf("cpu = %v", s.CPUCores)
	}
}

func TestDeriveCPURestart(t *testing.T) {
	prev := runtime.UnitStats{Read: t0, CPUUsageNS: u(10e9)}
	cur := runtime.UnitStats{Read: t0.Add(15 * time.Second), CPUUsageNS: u(1e9)}
	if s := Derive(&prev, time.Time{}, cur, Limits{}); s.CPUCores != nil {
		t.Errorf("counter down: %v", *s.CPUCores)
	}
	cur.CPUUsageNS = u(13e9)
	if s := Derive(&prev, t0.Add(-time.Hour), cur, Limits{StartedAt: t0}); s.CPUCores != nil {
		t.Error("restarted: a rate")
	}
	if s := Derive(nil, time.Time{}, cur, Limits{}); s.CPUCores != nil {
		t.Error("first sample: a rate")
	}
}

func TestDeriveCPUGauge(t *testing.T) {
	c := 0.25
	if s := Derive(nil, time.Time{}, runtime.UnitStats{CPUCores: &c}, Limits{}); !near(s.CPUCores, 0.25) {
		t.Errorf("gauge = %v", s.CPUCores)
	}
}

func TestRateNullOnTinyOrNegativeInterval(t *testing.T) {
	prev := runtime.UnitStats{Read: t0, CPUUsageNS: u(1e9), NetRx: u(100), NetTx: u(100), BlkRead: u(10), BlkWrite: u(10)}
	for _, dt := range []time.Duration{0, 200 * time.Millisecond, -5 * time.Second} {
		cur := runtime.UnitStats{Read: t0.Add(dt), CPUUsageNS: u(2e9), NetRx: u(200), NetTx: u(200), BlkRead: u(20), BlkWrite: u(20)}
		s := Derive(&prev, time.Time{}, cur, Limits{})
		if s.CPUCores != nil || s.NetRxBps != nil || s.NetTxBps != nil || s.BlkReadBps != nil || s.BlkWriteBps != nil {
			t.Errorf("dt %s: a rate: %+v", dt, s)
		}
	}
	cur := runtime.UnitStats{Read: t0.Add(15 * time.Second), CPUUsageNS: u(2e9), NetRx: u(250), NetTx: u(400), BlkRead: u(25), BlkWrite: u(40)}
	s := Derive(&prev, time.Time{}, cur, Limits{})
	if !near(s.CPUCores, 1.0/15) || !near(s.NetRxBps, 10) || !near(s.NetTxBps, 20) || !near(s.BlkReadBps, 1) || !near(s.BlkWriteBps, 2) {
		t.Errorf("15 s: %+v", s)
	}
}

func TestWorkingSet(t *testing.T) {
	if v := WorkingSet(runtime.UnitStats{MemUsage: u(100 << 20), MemInactiveFile: u(30 << 20)}); v == nil || *v != 70<<20 {
		t.Errorf("v2 = %v", v)
	}
	if v := WorkingSet(runtime.UnitStats{MemUsage: u(10), MemInactiveFile: u(30)}); v == nil || *v != 0 {
		t.Errorf("inactive > usage = %v", v)
	}
	if v := WorkingSet(runtime.UnitStats{MemInactiveFile: u(30)}); v != nil {
		t.Errorf("no usage = %v", *v)
	}
	if v := WorkingSet(runtime.UnitStats{MemUsage: u(10), MemWorkingSet: u(64 << 20)}); v == nil || *v != 64<<20 {
		t.Errorf("given = %v", v)
	}
}

func TestDeriveNetworkModes(t *testing.T) {
	prev := runtime.UnitStats{Read: t0, NetRx: u(1), NetTx: u(1)}
	cur := runtime.UnitStats{Read: t0.Add(15 * time.Second), NetRx: u(100), NetTx: u(100)}
	for _, m := range []string{"none", "host", "container:x", "service:y"} {
		if s := Derive(&prev, time.Time{}, cur, Limits{NetworkMode: m}); s.NetRxBps != nil || s.NetTxBps != nil {
			t.Errorf("%s: net rates", m)
		}
	}
	if s := Derive(&prev, time.Time{}, cur, Limits{NetworkMode: "portcullis-x_default"}); s.NetRxBps == nil {
		t.Error("own network: no rate")
	}
}

func TestLimitsOf(t *testing.T) {
	if l := LimitsOf(runtime.UnitInfo{NanoCPUs: 5e8}); !near(l.CPUCores, 0.5) {
		t.Errorf("nano = %v", l.CPUCores)
	}
	if l := LimitsOf(runtime.UnitInfo{CPUQuota: 50000, CPUPeriod: 100000}); !near(l.CPUCores, 0.5) {
		t.Errorf("quota = %v", l.CPUCores)
	}
	if l := LimitsOf(runtime.UnitInfo{}); l.CPUCores != nil || l.MemBytes != 0 {
		t.Errorf("none = %+v", l)
	}
	s := Derive(nil, time.Time{}, runtime.UnitStats{}, LimitsOf(runtime.UnitInfo{}))
	if s.MemLimitBytes == nil || *s.MemLimitBytes != 0 {
		t.Errorf("mem limit = %v", s.MemLimitBytes)
	}
}

func TestRingWraps(t *testing.T) {
	r := NewRing(RingSize)
	for i := range 300 {
		r.Add(Point{T: t0.Add(time.Duration(i) * time.Second)})
	}
	ps := r.Points()
	if len(ps) != 240 || !ps[0].T.Equal(t0.Add(60*time.Second)) || !ps[239].T.Equal(t0.Add(299*time.Second)) {
		t.Fatalf("points: %d, %v … %v", len(ps), ps[0].T, ps[len(ps)-1].T)
	}
	if got := r.Since(t0.Add(290 * time.Second)); len(got) != 10 {
		t.Errorf("since = %d", len(got))
	}
	if last, ok := r.Last(); !ok || !last.T.Equal(t0.Add(299*time.Second)) {
		t.Errorf("last = %v", last.T)
	}
	if r := NewRing(4); len(r.Points()) != 0 || r.Since(t0) != nil {
		t.Error("empty ring")
	}
}

func i64(v int64) *int64 { return &v }

func TestTotalPartial(t *testing.T) {
	tot, partial := Total([]Sample{{MemBytes: i64(1)}, {}})
	if tot.MemBytes == nil || *tot.MemBytes != 1 || !partial {
		t.Errorf("partial = %v %v", tot.MemBytes, partial)
	}
	tot, _ = Total([]Sample{{MemLimitBytes: i64(10)}, {MemLimitBytes: i64(20)}})
	if tot.MemLimitBytes == nil || *tot.MemLimitBytes != 30 {
		t.Errorf("limits = %v", tot.MemLimitBytes)
	}
	tot, _ = Total([]Sample{{MemLimitBytes: i64(10)}, {MemLimitBytes: i64(0)}})
	if tot.MemLimitBytes != nil {
		t.Errorf("partly unlimited = %v", *tot.MemLimitBytes)
	}
	tot, _ = Total([]Sample{{MemLimitBytes: i64(0)}, {MemLimitBytes: i64(0)}})
	if tot.MemLimitBytes == nil || *tot.MemLimitBytes != 0 {
		t.Errorf("no limits = %v", tot.MemLimitBytes)
	}
	tot, partial = Total([]Sample{{}, {}})
	if tot.MemBytes != nil || tot.CPUCores != nil || partial {
		t.Errorf("all nil = %+v %v", tot, partial)
	}
}

func TestCSVCellEscapes(t *testing.T) {
	for _, in := range []string{"=1+1", "+x", "-x", "@x", "\tx", "\rx"} {
		if got := CSVCell(in); got != "'"+in {
			t.Errorf("CSVCell(%q) = %q", in, got)
		}
	}
	if CSVCell("plain") != "plain" || CSVCell("") != "" {
		t.Error("plain cells changed")
	}
	var b bytes.Buffer
	if err := WriteCSV(&b, []string{"a", "b"}, [][]string{{`a,b"c`, "=HYPERLINK(x)"}}); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil || len(recs) != 2 || recs[1][0] != `a,b"c` || recs[1][1] != "'=HYPERLINK(x)" {
		t.Errorf("round trip = %q, %v", recs, err)
	}
	if Int(nil) != "" || Float(nil) != "" || Int(i64(5)) != "5" {
		t.Error("number cells")
	}
}
