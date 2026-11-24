package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/runtime"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

// maxStatsBody caps one stats answer (contract §6 "Resource usage"): a
// one-shot sample is a few KiB.
const maxStatsBody = 1 << 20

// StatsTimeout bounds one stats call (a hung engine never holds the
// caller: the Hub's sampler has 5 s, the worker agent's route 20 s).
const StatsTimeout = 20 * time.Second

// sizeTimeout bounds one size=true inspect (the daemon walks the
// writable layer).
var sizeTimeout = 10 * time.Second

// statsBody is the part of GET /containers/{id}/stats the Hub keeps, all
// pointers: an absent field stays nil (never read as 0). The SDK's
// container.StatsResponse can't tell absent from 0.
type statsBody struct {
	Read     *time.Time `json:"read"`
	CPUStats *struct {
		CPUUsage *struct {
			TotalUsage *uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
	} `json:"cpu_stats"`
	MemoryStats *struct {
		Usage *uint64 `json:"usage"`
		Stats *struct {
			InactiveFile      *uint64 `json:"inactive_file"`
			TotalInactiveFile *uint64 `json:"total_inactive_file"`
		} `json:"stats"`
	} `json:"memory_stats"`
	PidsStats *struct {
		Current *uint64 `json:"current"`
	} `json:"pids_stats"`
	Networks map[string]struct {
		RxBytes *uint64 `json:"rx_bytes"`
		TxBytes *uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlkioStats *struct {
		IOServiceBytesRecursive []struct {
			Op    string  `json:"op"`
			Value *uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
}

// engineErr is an engine failure as fixed text: never the daemon's body
// (an inspect or stats error may echo container data). The guard's own
// refusal and a context error pass through.
func engineErr(what, id string, err error) error {
	if errors.Is(err, ErrEngineRefused) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	code := http.StatusBadGateway
	switch {
	case cerrdefs.IsNotFound(err):
		return fmt.Errorf("%s %s: %w", what, shortID(id), errNotFound)
	case cerrdefs.IsInvalidArgument(err):
		code = http.StatusBadRequest
	case cerrdefs.IsPermissionDenied(err):
		code = http.StatusForbidden
	case cerrdefs.IsConflict(err):
		code = http.StatusConflict
	case cerrdefs.IsUnavailable(err):
		code = http.StatusServiceUnavailable
	case cerrdefs.IsInternal(err):
		code = http.StatusInternalServerError
	}
	return fmt.Errorf("%s %s: %s", what, shortID(id), http.StatusText(code))
}

// errNotFound keeps IsNotFound true for a missing container while the
// daemon's text is dropped.
var errNotFound = cerrdefs.ErrNotFound.WithMessage("Not Found")

// ContainerStats takes one stats sample (GET /containers/{id}/stats?
// stream=false&one-shot=true: no 1 s wait, no precpu_stats), decoded field
// by field.
func (c *Client) ContainerStats(ctx context.Context, id string) (runtime.UnitStats, error) {
	ctx, cancel := context.WithTimeout(ctx, StatsTimeout)
	defer cancel()
	res, err := c.api.ContainerStats(ctx, id, client.ContainerStatsOptions{Stream: false})
	if err != nil {
		return runtime.UnitStats{}, engineErr("stats", id, err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxStatsBody+1))
	if err != nil {
		return runtime.UnitStats{}, engineErr("stats", id, err)
	}
	if len(b) > maxStatsBody {
		return runtime.UnitStats{}, fmt.Errorf("stats %s: the answer is over %d bytes", shortID(id), maxStatsBody)
	}
	return decodeStats(id, b)
}

func decodeStats(id string, b []byte) (runtime.UnitStats, error) {
	var sb statsBody
	if err := json.Unmarshal(b, &sb); err != nil {
		return runtime.UnitStats{}, fmt.Errorf("stats %s: undecodable answer", shortID(id))
	}
	var s runtime.UnitStats
	if sb.Read != nil {
		s.Read = *sb.Read
	}
	if sb.CPUStats != nil && sb.CPUStats.CPUUsage != nil {
		s.CPUUsageNS = sb.CPUStats.CPUUsage.TotalUsage
	}
	if m := sb.MemoryStats; m != nil {
		s.MemUsage = m.Usage
		if m.Stats != nil {
			// cgroup v2 names it inactive_file, v1 total_inactive_file.
			if m.Stats.InactiveFile != nil {
				s.MemInactiveFile = m.Stats.InactiveFile
			} else {
				s.MemInactiveFile = m.Stats.TotalInactiveFile
			}
		}
	}
	if sb.PidsStats != nil {
		s.Pids = sb.PidsStats.Current
	}
	if sb.Networks != nil {
		var rx, tx uint64
		rxOK, txOK := true, true
		for _, n := range sb.Networks {
			if n.RxBytes == nil {
				rxOK = false
			} else {
				rx += *n.RxBytes
			}
			if n.TxBytes == nil {
				txOK = false
			} else {
				tx += *n.TxBytes
			}
		}
		if rxOK {
			s.NetRx = &rx
		}
		if txOK {
			s.NetTx = &tx
		}
	}
	if sb.BlkioStats != nil {
		var r, w uint64
		var rOK, wOK bool
		for _, e := range sb.BlkioStats.IOServiceBytesRecursive {
			if e.Value == nil {
				continue
			}
			switch strings.ToLower(e.Op) {
			case "read":
				r, rOK = r+*e.Value, true
			case "write":
				w, wOK = w+*e.Value, true
			}
		}
		if rOK {
			s.BlkRead = &r
		}
		if wOK {
			s.BlkWrite = &w
		}
	}
	return s, nil
}

// ContainerSizeRw is the container's writable layer size (inspect
// size=true, at most sizeTimeout).
func (c *Client) ContainerSizeRw(ctx context.Context, id string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, sizeTimeout)
	defer cancel()
	res, err := c.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{Size: true})
	if err != nil {
		return 0, engineErr("size", id, err)
	}
	if res.Container.SizeRw == nil {
		return 0, &runtime.NotMeasuredError{Why: "the engine didn't report a size"}
	}
	return *res.Container.SizeRw, nil
}

// ImageSize is an image's size (GET /images/{id}/json).
func (c *Client) ImageSize(ctx context.Context, ref string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ImageInspect(ctx, ref)
	if err != nil {
		return 0, engineErr("image", ref, err)
	}
	return res.Size, nil
}

// HostResources are the host's CPUs and memory (Info NCPU / MemTotal).
func (c *Client) HostResources(ctx context.Context) (int, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return 0, 0, err
	}
	return res.Info.NCPU, res.Info.MemTotal, nil
}
