//go:build harness

package httpapi

import (
	"context"
	"hash/fnv"
	"math"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/usage"
)

// seedUsage runs the usage sampler over the harness's running containers
// (synthetic, slowly varying figures).
func seedUsage(t *testing.T, e *instEnv) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.s.Hub.RunUsageSampler(ctx, usage.Interval)
}

var harnessStart = time.Now()

func harnessSeed(id string) float64 {
	h := fnv.New32a()
	h.Write([]byte(id))
	return float64(h.Sum32()%1000) / 1000
}

// ContainerStats: a counter-based sample per container, varying with
// time; the "photos" server has no CPU counter (rootless without cpu).
func (e *harnessEngine) ContainerStats(_ context.Context, id string) (runtime.UnitStats, error) {
	el := time.Since(harnessStart).Seconds()
	s := harnessSeed(id)
	cpu := uint64((0.05 + s*0.6) * el * 1e9)
	mem := uint64((40 + s*400 + 30*math.Sin(el/120+s*6)) * (1 << 20))
	pids := uint64(3 + s*40)
	rx, tx := uint64(el*(2000+s*90000)), uint64(el*(500+s*20000))
	br, bw := uint64(el*s*50000), uint64(el*s*120000)
	st := runtime.UnitStats{Read: time.Now(), MemUsage: &mem, Pids: &pids, NetRx: &rx, NetTx: &tx, BlkRead: &br, BlkWrite: &bw}
	if id != "portcullis-photos-server" {
		st.CPUUsageNS = &cpu
	}
	return st, nil
}

func (e *harnessEngine) HostResources(context.Context) (int, int64, error) { return 8, 16 << 30, nil }
