package docker

import (
	"context"
	"fmt"

	"github.com/moby/moby/client"
)

// pullLayer is one layer of a pull stream: its byte counts.
type pullLayer struct{ done, total int64 }

// PullWithProgress pulls ref unless the daemon already has it (then it
// returns at once without calling onBytes: nothing to download), calling
// onBytes with the bytes downloaded and the bytes known so far, summed
// over the image's layers (a layer already present counts for nothing),
// whenever they change; the last call of a successful pull has done ==
// total. done never goes back; total grows as layers report their size.
// Cancelling ctx stops the pull (the stream is closed) with ctx's error.
// No timeout of its own: the caller's ctx bounds it.
func (c *Client) PullWithProgress(ctx context.Context, ref string, onBytes func(done, total int64)) error {
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
	report := func(final bool) {
		var done, total int64
		for _, l := range layers {
			done += l.done
			total += l.total
		}
		if final {
			done = total
		}
		done = max(done, lastDone)
		if done != lastDone || total != lastTotal {
			lastDone, lastTotal = done, total
			if onBytes != nil {
				onBytes(done, total)
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
			l.done = l.total
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
	report(true)
	return nil
}
