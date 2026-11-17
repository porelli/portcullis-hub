package hub

import (
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// The doctor's window is the last 10 minutes; RestartsHourAgo is the
// oldest point's within the hour.
func TestUsageDoctorInFromSnapshot(t *testing.T) {
	e := newUsageEnv(t, "a")
	if e.h.usageDoctorIn() != nil {
		t.Fatal("inputs before the first sweep")
	}
	e.setUnits(uunit("a1", "portcullis-a", "web", 1, "running"))
	restarts := 0
	for i := range 240 { // an hour at 15 s
		e.rt.Lock()
		e.rt.Infos = map[string]runtime.UnitInfo{"a1": {ID: "a1", Memory: 1 << 30, RestartCount: restarts, OOMKilled: i == 200}}
		e.rt.Unlock()
		e.stats("a1", uint64(i)*1e9, 1<<20)
		e.sweep()
		e.clock.Add(15 * time.Second)
		if i%20 == 19 {
			restarts++
			e.h.usage.mu.Lock()
			e.h.usage.conts["a1"].Inspect = time.Time{} // inspect again next sweep
			e.h.usage.mu.Unlock()
		}
	}
	in := e.h.usageDoctorIn()
	if in == nil || len(in.Containers) != 1 {
		t.Fatalf("in = %+v", in)
	}
	c := in.Containers[0]
	if n := len(c.Points); n < 39 || n > 41 {
		t.Errorf("window = %d points", n)
	}
	for _, p := range c.Points {
		if p.At.Before(in.Now.Add(-10 * time.Minute)) {
			t.Errorf("point %v outside the window", p.At)
		}
	}
	if c.Restarts != 11 || c.RestartsHourAgo > 1 || c.MemLimit != 1<<30 {
		t.Errorf("restarts %d, an hour ago %d, limit %d", c.Restarts, c.RestartsHourAgo, c.MemLimit)
	}
	if !c.OOMSeenHour {
		t.Error("the OOM kill wasn't seen")
	}
}
