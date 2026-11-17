package hub

import (
	"testing"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
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

// The storage kinds' input: the cache's disks with their owners
// (folders prefixed) and the capped targets.
func TestStorageDoctorIn(t *testing.T) {
	e := newStorageEnv(t)
	e.rep = func(r fixerRun) (*folderfix.Report, error) {
		rep := &folderfix.Report{Version: 1, Mode: "usage", AllocBytes: 10, Dev: 7, FreeBytes: 1, TotalBytes: 100}
		if r.Volume.Name == "portcullis-a_data" {
			rep.Partial, rep.PartialReason = true, "entries"
		}
		return rep, nil
	}
	if _, _, err := e.measure(t, ""); err != nil {
		t.Fatal(err)
	}
	in := e.h.storageDoctorIn()
	var d7 *doctor.FilesystemIn
	for i := range in.Filesystems {
		if in.Filesystems[i].Dev == 7 {
			d7 = &in.Filesystems[i]
		}
	}
	if d7 == nil || d7.Total != 100 || len(d7.Owners) < 3 {
		t.Fatalf("filesystems = %+v", in.Filesystems)
	}
	if len(in.Partial) != 1 || in.Partial[0].Target != "portcullis-a_data" || in.Partial[0].Owner != "a" {
		t.Errorf("partial = %+v", in.Partial)
	}
	r := doctor.Run(&doctor.Inputs{Storage: in}, nil)
	kinds := map[string]bool{}
	for _, f := range r.Findings {
		kinds[f.Kind] = true
	}
	if !kinds[doctor.KindDiskNearlyFull] || !kinds[doctor.KindStorageMeasurePartial] {
		t.Errorf("kinds = %v", kinds)
	}
}
