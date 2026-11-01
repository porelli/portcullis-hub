package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// maxExecOutput bounds captured exec output.
const maxExecOutput = 4 << 20

// ExecResult is the outcome of Exec.
type ExecResult struct {
	Output    []byte
	ExitCode  int // -1 if unknown (timeout / still running)
	TimedOut  bool
	Truncated bool
}

// Exec runs cmd in container id (no TTY, no stdin) and returns combined
// stdout+stderr. The call is bounded by timeout and ctx; on expiry the
// stream is closed, but — as with `docker exec` — the process inside the
// container is not killed. Creating and inspecting the exec are each also
// bounded by requestTimeout (a hung daemon call never waits for timeout).
func (c *Client) Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (*ExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cctx, ccancel := context.WithTimeout(ctx, requestTimeout)
	created, err := c.api.ExecCreate(cctx, id, client.ExecCreateOptions{AttachStdout: true, AttachStderr: true, Cmd: cmd})
	ccancel()
	if err != nil {
		return nil, fmt.Errorf("exec create: %w", err)
	}
	if created.ID == "" {
		return nil, fmt.Errorf("exec create: bad response: no exec id")
	}
	att, err := c.api.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return &ExecResult{ExitCode: -1, TimedOut: ctx.Err() == context.DeadlineExceeded}, nil
		}
		return nil, fmt.Errorf("exec start: %w", err)
	}
	// The hijacked connection ignores ctx once set up: close it on expiry.
	stop := context.AfterFunc(ctx, att.Close)
	out := &limitedBuffer{max: maxExecOutput}
	_, streamErr := stdcopy.StdCopy(out, out, att.Reader)
	stop()
	att.Close()

	res := &ExecResult{Output: out.buf, ExitCode: -1, Truncated: out.truncated}
	if ctx.Err() != nil {
		res.TimedOut = ctx.Err() == context.DeadlineExceeded
		return res, nil
	}
	if streamErr != nil {
		return res, fmt.Errorf("exec stream: %w", streamErr)
	}
	ictx, icancel := context.WithTimeout(ctx, requestTimeout)
	info, err := c.api.ExecInspect(ictx, created.ID, client.ExecInspectOptions{})
	icancel()
	if err != nil {
		return res, fmt.Errorf("exec inspect: %w", err)
	}
	if !info.Running {
		res.ExitCode = info.ExitCode
	}
	return res, nil
}
