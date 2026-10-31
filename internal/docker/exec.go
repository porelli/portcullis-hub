package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
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
// container is not killed.
func (c *Client) Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (*ExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var created struct {
		ID string `json:"Id"`
	}
	resp, err := c.do(ctx, c.http, http.MethodPost, "/containers/"+url.PathEscape(id)+"/exec", nil, map[string]interface{}{
		"AttachStdin":  false,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          false,
		"Cmd":          cmd,
	})
	if err != nil {
		return nil, fmt.Errorf("exec create: %w", err)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&created)
	resp.Body.Close()
	if err != nil || created.ID == "" {
		return nil, fmt.Errorf("exec create: bad response: %v", err)
	}

	// Without an Upgrade header the daemon answers 200 and streams the
	// multiplexed output until the process exits, then closes.
	resp, err = c.do(ctx, c.stream, http.MethodPost, "/exec/"+url.PathEscape(created.ID)+"/start", nil, map[string]interface{}{
		"Detach": false,
		"Tty":    false,
	})
	if err != nil {
		return nil, fmt.Errorf("exec start: %w", err)
	}
	out := &limitedBuffer{max: maxExecOutput}
	streamErr := Demux(resp.Body, out, out)
	resp.Body.Close()

	res := &ExecResult{Output: out.buf, ExitCode: -1, Truncated: out.truncated}
	if ctx.Err() != nil {
		res.TimedOut = ctx.Err() == context.DeadlineExceeded
		return res, nil
	}
	if streamErr != nil {
		return res, fmt.Errorf("exec stream: %w", streamErr)
	}
	var info struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	}
	if err := c.getJSON(ctx, "/exec/"+url.PathEscape(created.ID)+"/json", nil, &info); err != nil {
		return res, fmt.Errorf("exec inspect: %w", err)
	}
	if !info.Running {
		res.ExitCode = info.ExitCode
	}
	return res, nil
}
