package kube

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// errHelpers: volume copies and the fixer need helper pods (not yet).
var errHelpers = errors.New("kube: helper pods are not available yet")

func (b *Backend) VolumeOut(context.Context, string, string, string) (io.ReadCloser, error) {
	return nil, errHelpers
}
func (b *Backend) VolumeIn(context.Context, string, string, string, io.Reader) error {
	return errHelpers
}
func (b *Backend) RemoveHelper(context.Context, string) error { return errHelpers }
func (b *Backend) RunFixer(context.Context, runtime.FixerSpec, func(io.Reader) error) (*runtime.RunResult, error) {
	return nil, errHelpers
}

// helperReady bounds the waits for a helper pod and a PVC's deletion.
const helperReady = 2 * time.Minute
