// Package compose wraps the `docker compose` CLI. Compose has no Engine API
// equivalent, so the Hub shells out for up/down only; everything read-only
// (status, logs, exec, events) goes through internal/docker.
package compose

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// OutputTail is how much of a failed invocation's combined stdout/stderr
// an Error keeps (the end: compose prints the cause last).
const OutputTail = 8 << 10

// Error is a failed compose invocation. Output is the tail of what compose
// printed — the actual cause ("failed to bind host port …: address already
// in use"); the exit status alone says nothing.
type Error struct {
	Command string // "up", "down"
	Err     error  // exit status, timeout, …
	Output  string
}

func (e *Error) Error() string {
	msg := "docker compose " + e.Command + ": " + e.Err.Error()
	if l := LastLine(e.Output); l != "" {
		msg += ": " + l
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// LastLine returns the line of s that most likely names the cause (clipped):
// the last one mentioning an error, else the last non-empty one.
func LastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	pick := ""
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if pick == "" {
			pick = l
		}
		if strings.Contains(strings.ToLower(l), "error") {
			pick = l
			break
		}
	}
	if len(pick) > 300 {
		pick = pick[:300] + "…"
	}
	return pick
}

// tail keeps the last max bytes written to it (stdout and stderr are
// copied by separate goroutines: locked).
type tail struct {
	mu  sync.Mutex
	max int
	buf []byte
	cut bool
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
		t.cut = true
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := string(t.buf)
	if t.cut {
		// Drop the partial first line.
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		s = "[…]\n" + s
	}
	return s
}

// Project identifies one compose project invocation.
type Project struct {
	Name       string   // -p
	Files      []string // -f (in order)
	ProjectDir string   // --project-directory (HOST path: the daemon resolves bind mounts there)
	EnvFile    string   // --env-file
}

// Runner brings compose projects up and down. It is an interface so the
// Hub's lifecycle/locking logic can be tested without Docker.
type Runner interface {
	Up(ctx context.Context, p Project) error
	Down(ctx context.Context, p Project) error
	// DownByName stops a project using only its name — works even when the
	// template's compose file is gone or broken.
	DownByName(ctx context.Context, name string) error
}

// CLI runs the docker compose plugin.
type CLI struct {
	Binary      string // default "docker"
	DockerHost  string // exported as DOCKER_HOST (tcp://… or unix://…)
	UpTimeout   time.Duration
	DownTimeout time.Duration
	Stdout      io.Writer
	Stderr      io.Writer
}

// NewCLI returns a CLI with the Hub's default timeouts.
func NewCLI(dockerHost string) *CLI {
	return &CLI{
		Binary:      "docker",
		DockerHost:  dockerHost,
		UpTimeout:   15 * time.Minute, // includes image pulls
		DownTimeout: 5 * time.Minute,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	}
}

// Args returns the CLI arguments for running sub (e.g. "up", "-d") on p.
func Args(p Project, sub ...string) []string {
	args := []string{"compose", "-p", p.Name}
	for _, f := range p.Files {
		args = append(args, "-f", f)
	}
	if p.ProjectDir != "" {
		args = append(args, "--project-directory", p.ProjectDir)
	}
	if p.EnvFile != "" {
		args = append(args, "--env-file", p.EnvFile)
	}
	return append(args, sub...)
}

func (c *CLI) run(ctx context.Context, timeout time.Duration, sub string, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	bin := c.Binary
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	// WaitDelay makes Wait return even if a killed child left pipes open.
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	if c.DockerHost != "" {
		cmd.Env = append(cmd.Env, "DOCKER_HOST="+c.DockerHost)
	}
	// The Hub's own log keeps the full output; the tail goes into the error.
	out := &tail{max: OutputTail}
	cmd.Stdout = io.MultiWriter(orDiscard(c.Stdout), out)
	cmd.Stderr = io.MultiWriter(orDiscard(c.Stderr), out)
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("timed out after %s", timeout)
		}
		return &Error{Command: sub, Err: err, Output: out.String()}
	}
	return nil
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// Up runs `up -d --no-deps`.
func (c *CLI) Up(ctx context.Context, p Project) error {
	return c.run(ctx, c.UpTimeout, "up", Args(p, "up", "-d", "--no-deps"))
}

// Down runs `down --remove-orphans` (volumes are kept): containers of
// services no longer in the files (e.g. a dropped custom override) go too.
func (c *CLI) Down(ctx context.Context, p Project) error {
	return c.run(ctx, c.DownTimeout, "down", Args(p, "down", "--remove-orphans"))
}

// DownByName runs `compose -p <name> down --remove-orphans`.
func (c *CLI) DownByName(ctx context.Context, name string) error {
	return c.run(ctx, c.DownTimeout, "down", []string{"compose", "-p", name, "down", "--remove-orphans"})
}
