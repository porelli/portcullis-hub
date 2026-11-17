package agentapi

import (
	"errors"
	"fmt"
	"io"

	"github.com/portcullis/hub/internal/jsonstrict"
)

// Size caps (contract §17). Both sides enforce them: the agent on what
// the Hub sends, the Hub on what an agent answers (untrusted input).
const (
	MaxInfo   = 64 << 10 // GET /v1/info
	MaxJSON   = 1 << 20  // any other JSON request or response body
	MaxLogs   = 4 << 20  // GET /v1/containers/{cid}/logs
	MaxLine   = 64 << 10 // one ndjson line (progress, events)
	MaxBundle = 64 << 20 // PUT /v1/projects/{id}/bundle, the whole tar stream
	// MaxError bounds the error shape's message (runes).
	MaxError = 200
	// MaxBundleEntries bounds a bundle's tar entries (directories
	// included); MaxBundleName a bundle path.
	MaxBundleEntries = 10000
	MaxBundleName    = 1024
)

// ErrTooLarge: a body over its cap.
var ErrTooLarge = errors.New("agent API: body over its size cap")

// ReadCapped reads all of r, refusing more than max bytes.
func ReadCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

// Decode reads one JSON body of at most max bytes from r into v, strictly
// (jsonstrict: no unknown, duplicate, missing or null key, no trailing
// data). Errors carry JSON paths, never values.
func Decode(r io.Reader, max int64, v any) error {
	b, err := ReadCapped(r, max)
	if err != nil {
		return err
	}
	if err := jsonstrict.Decode(b, v); err != nil {
		return fmt.Errorf("agent API: %v", err)
	}
	return nil
}
