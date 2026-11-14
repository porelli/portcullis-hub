package compose

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"

	"github.com/portcullis/hub/internal/docker"
)

func TestArgs(t *testing.T) {
	p := Project{Name: "portcullis-app", Files: []string{"/t/compose.yml", "/d/o.yml"}, ProjectDir: "/host/core", EnvFile: "/d/app.env"}
	got := strings.Join(Args(p, "up", "-d"), " ")
	want := "compose -p portcullis-app -f /t/compose.yml -f /d/o.yml --project-directory /host/core --env-file /d/app.env up -d"
	if got != want {
		t.Errorf("Args = %q", got)
	}
}

type fakeEngine []docker.Component

func (f fakeEngine) Components(context.Context) ([]docker.Component, error) { return f, nil }

// verifiedGuard is a docker guard verified against a fake engine.
func verifiedGuard(t *testing.T) *docker.Guard {
	t.Helper()
	g := docker.NewGuard(runtime.KindDocker)
	if err := g.Verify(context.Background(), fakeEngine{{Name: "Engine", Version: "29.0.0"}}); err != nil {
		t.Fatal(err)
	}
	return g
}

// P4: compose commands wait for the guard; the plugin's own version
// (checked before the Hub starts) never reaches the engine and passes.
func TestComposeRefusesUnverified(t *testing.T) {
	c, log := stub(t, "echo 2.30.0\nexit 0\n")
	c.Guard = docker.NewGuard(runtime.KindPodman)
	p := Project{Name: "portcullis-app", Files: []string{"/c.yml"}}
	for name, f := range map[string]func() error{
		"Create":     func() error { return c.Create(context.Background(), p) },
		"Up":         func() error { return c.Up(context.Background(), p) },
		"Down":       func() error { return c.Down(context.Background(), p) },
		"DownByName": func() error { return c.DownByName(context.Background(), "portcullis-app") },
	} {
		if err := f(); !errors.Is(err, docker.ErrEngineRefused) {
			t.Errorf("%s = %v, want the guard's refusal", name, err)
		}
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Errorf("a refused command ran docker:\n%s", b)
	}
	if _, err := c.Version(context.Background()); err != nil {
		t.Errorf("Version refused: %v", err)
	}
	if b, _ := os.ReadFile(log); !strings.Contains(string(b), "compose version --short") {
		t.Errorf("Version didn't run: %q", b)
	}
	defer func() {
		if recover() == nil {
			t.Error("NewCLI with a nil guard didn't panic")
		}
	}()
	NewCLI("tcp://x:2375", nil)
}

// stub writes a fake `docker` that records its args and env.
func stub(t *testing.T, script string) (*CLI, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	bin := filepath.Join(dir, "docker")
	body := "#!/bin/sh\necho \"$@\" >> " + log + "\necho \"DOCKER_HOST=$DOCKER_HOST ORPHANS=$COMPOSE_IGNORE_ORPHANS\" >> " + log + "\n" + script
	if err := os.WriteFile(bin, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	c := NewCLI("tcp://socket-proxy-hub:2375", verifiedGuard(t))
	c.Binary = bin
	c.Stdout, c.Stderr = io.Discard, io.Discard
	return c, log
}

func TestCLI(t *testing.T) {
	c, log := stub(t, "exit 0\n")
	p := Project{Name: "portcullis-app", Files: []string{"/c.yml"}}
	if err := c.Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := c.Up(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := c.Down(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := c.DownByName(context.Background(), "portcullis-app"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	out := string(b)
	for _, want := range []string{
		"compose -p portcullis-app -f /c.yml up --no-start --no-deps",
		"compose -p portcullis-app -f /c.yml up -d --no-deps --pull never",
		// Every profile is taken down (an unselected one's containers
		// are never orphans to compose).
		"compose -p portcullis-app -f /c.yml --profile * down --remove-orphans",
		"compose -p portcullis-app down --remove-orphans",
		"DOCKER_HOST=tcp://socket-proxy-hub:2375 ORPHANS=true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}

// Final fix C1: compose gets PassedEnv of the Hub's environment, the
// Hub's two variables and nothing else — no Hub secret, no profile.
func TestCLIEnvAllowlist(t *testing.T) {
	t.Setenv("HUB_SECRET_TEST", "leaked")
	t.Setenv("KEYCLOAK_ADMIN_PASSWORD", "leaked")
	t.Setenv("COMPOSE_PROFILES", "evil")
	t.Setenv("DOCKER_CONTEXT", "other")
	t.Setenv("HOME", "/home/hub")
	dump := filepath.Join(t.TempDir(), "env")
	c, log := stub(t, "env > "+dump+"\nexit 0\n")
	if err := c.Up(context.Background(), Project{Name: "x", EnvFile: "/d/x.env"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dump)
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		got[k] = v
	}
	// /bin/sh adds its own (PWD, SHLVL, _, OLDPWD).
	shell := map[string]bool{"PWD": true, "SHLVL": true, "_": true, "OLDPWD": true}
	for k := range got {
		if !shell[k] && k != "HOME" && k != "PATH" && k != "COMPOSE_IGNORE_ORPHANS" && k != "DOCKER_HOST" {
			t.Errorf("compose's environment has %s", k)
		}
	}
	if got["HOME"] != "/home/hub" || got["PATH"] != os.Getenv("PATH") || got["DOCKER_HOST"] != "tcp://socket-proxy-hub:2375" || got["COMPOSE_IGNORE_ORPHANS"] != "true" {
		t.Errorf("environment = %v", got)
	}
	// The argv carries no environment either: only the env file's path.
	if a, _ := os.ReadFile(log); strings.Contains(string(a), "leaked") || strings.Contains(string(a), "evil") || !strings.Contains(string(a), "--env-file /d/x.env") {
		t.Errorf("argv = %s", a)
	}
	if env := c.Env(); len(env) != 4 {
		t.Errorf("Env() = %v", env)
	}
}

func TestCLIErrorsAndTimeout(t *testing.T) {
	c, _ := stub(t, "exit 3\n")
	if err := c.Up(context.Background(), Project{Name: "x"}); err == nil {
		t.Error("exit status ignored")
	}
	c, _ = stub(t, "exec sleep 30\n")
	c.UpTimeout = 200 * time.Millisecond
	start := time.Now()
	err := c.Up(context.Background(), Project{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("timeout not enforced")
	}
}

func TestCLIErrorCarriesOutput(t *testing.T) {
	c, _ := stub(t, "echo ' Container x  Creating'\necho 'Error response from daemon: failed to bind host port 0.0.0.0:53/tcp: address already in use' >&2\nexit 1\n")
	err := c.Up(context.Background(), Project{Name: "x"})
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T %v", err, err)
	}
	if ce.Command != "up" || !strings.Contains(ce.Output, "Creating") || !strings.Contains(ce.Output, "address already in use") {
		t.Errorf("error = %+v", ce)
	}
	if !strings.Contains(err.Error(), "exit status 1: Error response from daemon: failed to bind") {
		t.Errorf("message = %q", err.Error())
	}
	// Bounded: only the tail is kept. One stream, as docker compose writes
	// its progress and errors to stderr (stdout/stderr are separate pipes,
	// so their relative order isn't deterministic).
	c, _ = stub(t, "exec >&2; i=0; while [ $i -lt 3000 ]; do echo \"line $i of noise\"; i=$((i+1)); done; echo 'the cause'; exit 2\n")
	err = c.Down(context.Background(), Project{Name: "x"})
	if !errors.As(err, &ce) || len(ce.Output) > OutputTail+8 || !strings.HasSuffix(ce.Output, "the cause\n") || !strings.HasPrefix(ce.Output, "[…]\nline ") {
		t.Errorf("tail = %d bytes, %q…", len(ce.Output), ce.Output[:40])
	}
}

func TestCheckVersion(t *testing.T) {
	for v, ok := range map[string]bool{
		// volume subpath (per-person secrets, contract §6) since 2.26.0,
		// COMPOSE_PROFILES from the env file (§13.18) since 2.27.2.
		"2.27.2": true, "v2.29.1": true, "5.6.1": true, "2.27.2-desktop.1": true,
		"2.27.1": false, "2.26.0": false, "2.25.0": false, "2.24.4": false, "2.24.3": false, "2.20.0": false, "1.29.2": false, "": false, "garbage": false,
	} {
		if err := CheckVersion(v); (err == nil) != ok {
			t.Errorf("CheckVersion(%q) = %v", v, err)
		}
	}
}
