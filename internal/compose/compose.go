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

	"golang.org/x/mod/semver"

	"github.com/portcullis/hub/internal/docker"
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

// LastLine returns the line of s that most likely names the cause: the
// last one mentioning an error, else the last non-empty one. Not clipped:
// callers redact secrets first and clip afterwards (hub.finishOp), since
// clipping first could cut a secret so its prefix escapes redaction.
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
	// Create runs `up --no-start`: containers are created (labels set),
	// none is started — the Hub inspects them before Up.
	Create(ctx context.Context, p Project) error
	Up(ctx context.Context, p Project) error
	Down(ctx context.Context, p Project) error
	// DownByName stops a project using only its name — works even when the
	// template's compose file is gone or broken.
	DownByName(ctx context.Context, name string) error
	// Env is the whole environment compose runs with (Environ): the Hub
	// interpolates the project from exactly it plus the env file, so its
	// checks read what compose will run.
	Env() []string
}

// PassedEnv are the only variables of the Hub's own environment compose
// gets. The docker CLI reads HOME (its config dir ~/.docker: config.json,
// contexts, cli-plugins, buildx state) and PATH (credential helpers
// docker-credential-*, which compose runs for image pulls); neither
// needs anything else of it to reach the daemon. Everything else of
// the Hub's environment holds Hub configuration and secrets
// (KEYCLOAK_ADMIN_PASSWORD, HUB_PROXY_SECRET, …): a template's ${NAME}
// must never read them, and a name set there would beat the instance's
// --env-file. Deliberately not passed: DOCKER_CONTEXT, DOCKER_CONFIG,
// DOCKER_CERT_PATH, DOCKER_TLS_VERIFY, DOCKER_API_VERSION, HTTP(S)_PROXY —
// compose reaches the same daemon the Hub's Engine client does, with
// DOCKER_HOST only (tcp:// or unix://, no TLS, no proxy: docker.New); the
// Hub's image sets none of them. TMPDIR isn't set in the image either
// (/tmp is a tmpfs, the default).
var PassedEnv = []string{"HOME", "PATH"}

// Environ is the environment of every compose invocation: PassedEnv's
// entries of the Hub's environment, COMPOSE_IGNORE_ORPHANS=true and
// DOCKER_HOST=dockerHost (when set). Every instance variable — profiles
// (COMPOSE_PROFILES, contract §13.18) included — comes only from the
// instance's --env-file.
func Environ(dockerHost string) []string {
	var env []string
	for _, name := range PassedEnv {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	env = append(env, "COMPOSE_IGNORE_ORPHANS=true")
	if dockerHost != "" {
		env = append(env, "DOCKER_HOST="+dockerHost)
	}
	return env
}

// CLI runs the docker compose plugin.
type CLI struct {
	Binary      string // default "docker"
	DockerHost  string // exported as DOCKER_HOST (tcp://… or unix://…)
	UpTimeout   time.Duration
	DownTimeout time.Duration
	Stdout      io.Writer
	Stderr      io.Writer
	// Guard is the engine runtime guard (contract §6): every command but
	// Version (the plugin's own version, which never reaches the engine)
	// returns its refusal first.
	Guard *docker.Guard
}

// NewCLI returns a CLI with the Hub's default timeouts, held by g. A nil g
// panics: there is no unguarded compose.
func NewCLI(dockerHost string, g *docker.Guard) *CLI {
	if g == nil {
		panic("compose.NewCLI: no runtime guard")
	}
	return &CLI{
		Guard:       g,
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
	if c.Guard == nil {
		return fmt.Errorf("docker compose %s: no runtime guard", sub)
	}
	if err := c.Guard.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	bin := c.Binary
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	// WaitDelay makes Wait return even if a killed child left pipes open.
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = c.Env()
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

// Env is Environ(c.DockerHost).
func (c *CLI) Env() []string { return Environ(c.DockerHost) }

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// Create runs `up --no-start --no-deps` (still the up verb: the Hub's
// compose CLI use stays up / down only).
func (c *CLI) Create(ctx context.Context, p Project) error {
	return c.run(ctx, c.UpTimeout, "up", Args(p, "up", "--no-start", "--no-deps"))
}

// Up runs `up -d --no-deps --pull never`: Create already pulled the
// images it inspected, so Up starts exactly those (a re-pull between the
// two could swap in an image whose labels the Hub never saw).
func (c *CLI) Up(ctx context.Context, p Project) error {
	return c.run(ctx, c.UpTimeout, "up", Args(p, "up", "-d", "--no-deps", "--pull", "never"))
}

// Down runs `--profile '*' down --remove-orphans` (volumes are kept):
// containers of services no longer in the files (e.g. a dropped custom
// override) go too, and so do those of every compose profile — compose
// never counts a service of an unselected profile as an orphan, so a
// setup choice's old profile would otherwise keep running (contract
// §13.18). Only take-downs select every profile; Create and Up follow the
// env file's COMPOSE_PROFILES.
func (c *CLI) Down(ctx context.Context, p Project) error {
	return c.run(ctx, c.DownTimeout, "down", Args(p, "--profile", "*", "down", "--remove-orphans"))
}

// DownByName runs `compose -p <name> down --remove-orphans`: with no
// compose files compose takes the project's containers by its label, so
// every profile's go (no --profile needed).
func (c *CLI) DownByName(ctx context.Context, name string) error {
	return c.run(ctx, c.DownTimeout, "down", []string{"compose", "-p", name, "down", "--remove-orphans"})
}

// MinVersion is the oldest docker compose the Hub works with: the Hub's
// override replaces non-default instances' labels with the !override tag
// (contract §3.1, compose 2.24.4) and mounts the per-person secrets as a
// volume subpath (`volume.subpath`, contract §6), which compose passes to
// the Engine since 2.26.0 (docker/compose 39504607, "Add support for
// volume Subpath option"), and reads COMPOSE_PROFILES from the env file
// (the setup choices' profiles, contract §13.18) since 2.27.2
// (docker/compose#11861, "Fix COMPOSE_PROFILES can be set by .env
// file"). Down's `--profile '*'` (every profile) is older: compose-go's
// "*" (e0ed5cd7) ships since compose 2.0.0.
const MinVersion = "2.27.2"

// Version returns `docker compose version --short` (e.g. "2.29.1").
func (c *CLI) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	bin := c.Binary
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(ctx, bin, "compose", "version", "--short")
	cmd.Env = c.Env()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker compose version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// CheckVersion refuses a docker compose older than MinVersion (or a
// version it can't read).
func CheckVersion(v string) error {
	// Builds like 2.24.4-desktop.1 are that release: compare the core only.
	core, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(v), "v"), "-")
	core, _, _ = strings.Cut(core, "+")
	sv := "v" + core
	if !semver.IsValid(sv) {
		return fmt.Errorf("cannot read the docker compose version %q (need %s or newer)", v, MinVersion)
	}
	if semver.Compare(sv, "v"+MinVersion) < 0 {
		return fmt.Errorf("docker compose %s is too old: the Hub needs %s or newer (its overrides use the !override tag and volume subpath mounts, and instances' compose profiles come from their env files)", v, MinVersion)
	}
	return nil
}
