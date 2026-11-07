package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/moby/moby/client"
)

// pullLayer is one layer of a pull stream: its byte counts; ended: its
// download is over (a layer that never reported a size counts as sized
// then).
type pullLayer struct {
	done, total int64
	ended       bool
}

// errPullUnfinished: the daemon's stream ended without its closing
// "Digest:" / "Status:" line.
var errPullUnfinished = errors.New("the pull stream ended before the pull finished")

// PullWithProgress pulls ref unless the daemon already has it (then it
// returns at once without calling onBytes: nothing to download), calling
// onBytes with the bytes downloaded and the bytes known so far, summed
// over the image's layers (a layer already present counts for nothing),
// and sized = every layer seen so far has reported its size, whenever
// they change; the last call of a successful pull has done == total and
// sized. done never goes back; total grows as layers report their size.
// A stream that ends without the daemon's closing "Digest:" / "Status:"
// line is an error (the pull didn't finish). Cancelling ctx stops the
// pull (the stream is closed) with ctx's error. No timeout of its own:
// the caller's ctx bounds it.
func (c *Client) PullWithProgress(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error {
	ictx, cancel := context.WithTimeout(ctx, requestTimeout)
	_, err := c.api.ImageInspect(ictx, ref)
	cancel()
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("pull %s: %w", ref, cerr)
	}
	if !IsNotFound(err) {
		return err
	}
	resp, err := c.api.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("pull %s: %w", ref, cerr)
		}
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer resp.Close()
	layers := map[string]*pullLayer{}
	var lastDone, lastTotal int64 = -1, -1
	lastSized := false
	finished := false
	report := func(final bool) {
		var done, total int64
		sized := true
		for _, l := range layers {
			done += l.done
			total += l.total
			if l.total == 0 && !l.ended {
				sized = false
			}
		}
		if final {
			done, sized = total, true
		}
		done = max(done, lastDone)
		if done != lastDone || total != lastTotal || sized != lastSized {
			lastDone, lastTotal, lastSized = done, total, sized
			if onBytes != nil {
				onBytes(done, total, sized)
			}
		}
	}
	for m, err := range resp.JSONMessages(ctx) {
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return fmt.Errorf("pull %s: %w", ref, cerr)
			}
			return fmt.Errorf("pull %s: %w", ref, err)
		}
		if m.Error != nil {
			return fmt.Errorf("pull %s: %s", ref, m.Error.Message)
		}
		if m.ID == "" {
			if strings.HasPrefix(m.Status, "Digest:") || strings.HasPrefix(m.Status, "Status:") {
				finished = true
			}
			continue
		}
		var cur, tot int64
		if m.Progress != nil {
			cur, tot = m.Progress.Current, m.Progress.Total
		}
		switch m.Status {
		case "Pulling fs layer", "Waiting":
			if layers[m.ID] == nil {
				layers[m.ID] = &pullLayer{}
			}
		case "Downloading":
			l := layers[m.ID]
			if l == nil {
				l = &pullLayer{}
				layers[m.ID] = l
			}
			if tot > 0 {
				l.total = tot
			}
			l.done = max(l.done, min(cur, l.total))
		case "Verifying Checksum", "Download complete", "Extracting", "Pull complete":
			l := layers[m.ID]
			if l == nil {
				l = &pullLayer{}
				layers[m.ID] = l
			}
			if l.total == 0 && tot > 0 {
				l.total = tot
			}
			l.done, l.ended = l.total, true
		case "Already exists":
			delete(layers, m.ID)
		default:
			// "Pulling from …" (the tag), digests, final status lines.
			continue
		}
		report(false)
	}
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("pull %s: %w", ref, cerr)
	}
	if !finished {
		return fmt.Errorf("pull %s: %w", ref, errPullUnfinished)
	}
	report(true)
	return nil
}
