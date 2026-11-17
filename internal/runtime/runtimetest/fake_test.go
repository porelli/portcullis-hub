package runtimetest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// TestFakeStatsBlock: Stats waits on StatsBlock, answers StatsVal /
// StatsErr, and records each call.
func TestFakeStatsBlock(t *testing.T) {
	n := uint64(5)
	f := &Fake{StatsBlock: make(chan struct{}), StatsErr: map[string]error{"bad": errors.New("boom")}}
	f.SetStats("c1", runtime.UnitStats{MemUsage: &n})
	done := make(chan runtime.UnitStats, 1)
	go func() {
		s, _ := f.Stats(context.Background(), "c1")
		done <- s
	}()
	select {
	case <-done:
		t.Fatal("Stats didn't wait on StatsBlock")
	case <-time.After(50 * time.Millisecond):
	}
	close(f.StatsBlock)
	if s := <-done; s.MemUsage == nil || *s.MemUsage != 5 {
		t.Errorf("stats = %+v", s)
	}
	if _, err := f.Stats(context.Background(), "bad"); err == nil {
		t.Error("StatsErr ignored")
	}
	var nm *runtime.NotMeasuredError
	if _, err := f.LayerSize(context.Background(), "c1"); !errors.As(err, &nm) {
		t.Errorf("layer size: %v", err)
	}
	f.ImageSizes = map[string]int64{"img": 9}
	if v, err := f.ImageSize(context.Background(), "img"); err != nil || v != 9 {
		t.Errorf("image size = %d, %v", v, err)
	}
	if got := f.Calls(); !slices.Equal(got, []string{"stats c1", "stats bad", "layer-size c1", "image-size img"}) {
		t.Errorf("calls = %q", got)
	}
}
