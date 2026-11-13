package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	// ExecID names the exec instance (ExecRunning: a timed-out process
	// may still run — Docker can't kill it).
	ExecID string
}

// ExecInput is one ExecStdin run: argv (never through a shell), the user
// to run as ("" = the container's), the stdin bytes and the timeout.
type ExecInput struct {
	Cmd     []string
	User    string
	Stdin   []byte
	Timeout time.Duration
}

// Exec runs cmd in container id (no TTY, no stdin) and returns combined
// stdout+stderr. The call is bounded by timeout and ctx; on expiry the
// stream is closed, but — as with `docker exec` — the process inside the
// container is not killed. Creating and inspecting the exec are each also
// bounded by requestTimeout (a hung daemon call never waits for timeout).
func (c *Client) Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (*ExecResult, error) {
	return c.exec(ctx, id, client.ExecCreateOptions{AttachStdout: true, AttachStderr: true, Cmd: cmd}, nil, timeout)
}

// ExecStdin runs in.Cmd in container id as Exec does (no TTY, same output
// cap and timeout), with stdin attached: in.Stdin is written, then the
// write side is closed (the process reads EOF).
func (c *Client) ExecStdin(ctx context.Context, id string, in ExecInput) (*ExecResult, error) {
	opts := client.ExecCreateOptions{AttachStdin: true, AttachStdout: true, AttachStderr: true, Cmd: in.Cmd, User: in.User}
	stdin := in.Stdin
	if stdin == nil {
		stdin = []byte{}
	}
	return c.exec(ctx, id, opts, stdin, in.Timeout)
}

// ExecSplitResult is the outcome of ExecStdinSplit: stdout and stderr
// apart, each capped (MaxRunStdout / MaxRunStderr, the first bytes kept).
type ExecSplitResult struct {
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int // -1 if unknown (timeout / still running)
	TimedOut        bool
	ExecID          string
}

// ExecStdinSplit is ExecStdin with stdout and stderr demultiplexed into
// two capped buffers (an AI hook, contract §6 / §15.5: stdout may carry a
// credential and goes back to the caller only; stderr is what a failure
// may show, redacted).
func (c *Client) ExecStdinSplit(ctx context.Context, id string, in ExecInput) (*ExecSplitResult, error) {
	opts := client.ExecCreateOptions{AttachStdin: true, AttachStdout: true, AttachStderr: true, Cmd: in.Cmd, User: in.User}
	stdin := in.Stdin
	if stdin == nil {
		stdin = []byte{}
	}
	stdout := &limitedBuffer{max: MaxRunStdout}
	stderr := &limitedBuffer{max: MaxRunStderr}
	run, err := c.execTo(ctx, id, opts, stdin, in.Timeout, stdout, stderr)
	if run == nil {
		clear(stdout.buf)
		return nil, err
	}
	return &ExecSplitResult{
		Stdout: stdout.buf, Stderr: stderr.buf, StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated,
		ExitCode: run.ExitCode, TimedOut: run.TimedOut, ExecID: run.ExecID,
	}, err
}

// ExecRunning reports whether exec instance execID still runs.
func (c *Client) ExecRunning(ctx context.Context, execID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	info, err := c.api.ExecInspect(ctx, execID, client.ExecInspectOptions{})
	if err != nil {
		return false, fmt.Errorf("exec inspect: %w", err)
	}
	return info.Running, nil
}

// exec is Exec / ExecStdin; stdin nil = not attached. Both streams go to
// one capped buffer.
func (c *Client) exec(ctx context.Context, id string, opts client.ExecCreateOptions, stdin []byte, timeout time.Duration) (*ExecResult, error) {
	out := &limitedBuffer{max: maxExecOutput}
	res, err := c.execTo(ctx, id, opts, stdin, timeout, out, out)
	if res != nil {
		res.Output, res.Truncated = out.buf, out.truncated
	}
	return res, err
}

// execTo runs the exec with stdout and stderr demultiplexed into the two
// writers (they may be the same one); the result's Output is unset.
func (c *Client) execTo(ctx context.Context, id string, opts client.ExecCreateOptions, stdin []byte, timeout time.Duration, stdout, stderr io.Writer) (*ExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cctx, ccancel := context.WithTimeout(ctx, requestTimeout)
	created, err := c.api.ExecCreate(cctx, id, opts)
	ccancel()
	if err != nil {
		return nil, fmt.Errorf("exec create: %w", err)
	}
	if created.ID == "" {
		return nil, fmt.Errorf("exec create: bad response: no exec id")
	}
	// The attach (a hijacked connection) runs the request hooks too (moby
	// hijack.go); the guard is asked here as well, a second check.
	if err := c.guard.Err(); err != nil {
		return nil, fmt.Errorf("exec start: %w", err)
	}
	att, err := c.api.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return &ExecResult{ExitCode: -1, TimedOut: ctx.Err() == context.DeadlineExceeded, ExecID: created.ID}, nil
		}
		return nil, fmt.Errorf("exec start: %w", err)
	}
	// The hijacked connection ignores ctx once set up: close it on expiry.
	stop := context.AfterFunc(ctx, att.Close)
	var stdinErr chan error
	if stdin != nil {
		cw, ok := att.Conn.(client.CloseWriter)
		if !ok {
			stop()
			att.Close()
			return &ExecResult{ExitCode: -1, ExecID: created.ID}, errors.New("exec stdin: the connection can't be half-closed")
		}
		// Written while the output is read: a process that writes before
		// it has read everything never blocks the other side.
		stdinErr = make(chan error, 1)
		go func() {
			_, werr := att.Conn.Write(stdin)
			if cerr := cw.CloseWrite(); werr == nil {
				werr = cerr
			}
			stdinErr <- werr
		}()
	}
	_, streamErr := stdcopy.StdCopy(stdout, stderr, att.Reader)
	stop()
	att.Close()
	if stdinErr != nil {
		// A write error is not the run's error: a process may exit
		// without reading its stdin; its exit code decides.
		<-stdinErr
	}

	res := &ExecResult{ExitCode: -1, ExecID: created.ID}
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
