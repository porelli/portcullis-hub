package hub

import (
	"context"

	"github.com/portcullis/hub/internal/runtime"
)

// The usage calls of the docker Engine (contract §6 "Resource usage"):
// the engine fakes measure nothing.

func (e *fakeEngine) ContainerStats(context.Context, string) (runtime.UnitStats, error) {
	return runtime.UnitStats{}, &runtime.NotMeasuredError{Why: "fake engine"}
}

func (e *fakeEngine) ContainerSizeRw(context.Context, string) (int64, error) {
	return 0, &runtime.NotMeasuredError{Why: "fake engine"}
}

func (e *fakeEngine) ImageSize(context.Context, string) (int64, error) {
	return 0, &runtime.NotMeasuredError{Why: "fake engine"}
}

func (e *fakeEngine) HostResources(context.Context) (int, int64, error) { return 0, 0, nil }
