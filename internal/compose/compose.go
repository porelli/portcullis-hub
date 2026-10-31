// Package compose wraps the `docker compose` CLI. Compose has no Engine API
// equivalent, so the Hub shells out for up/down only; everything read-only
// (status, logs, exec, events) goes through internal/docker.
package compose

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

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

func (c *CLI) run(ctx context.Context, timeout time.Duration, args []string) error {
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
	cmd.Stdout, cmd.Stderr = c.Stdout, c.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("docker %s: timed out after %s", args[len(args)-1], timeout)
		}
		return err
	}
	return nil
}

// Up runs `up -d --no-deps`.
func (c *CLI) Up(ctx context.Context, p Project) error {
	return c.run(ctx, c.UpTimeout, Args(p, "up", "-d", "--no-deps"))
}

// Down runs `down`.
func (c *CLI) Down(ctx context.Context, p Project) error {
	return c.run(ctx, c.DownTimeout, Args(p, "down"))
}

// DownByName runs `compose -p <name> down`.
func (c *CLI) DownByName(ctx context.Context, name string) error {
	return c.run(ctx, c.DownTimeout, []string{"compose", "-p", name, "down"})
}
