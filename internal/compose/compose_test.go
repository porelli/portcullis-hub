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
)

func TestArgs(t *testing.T) {
	p := Project{Name: "portcullis-app", Files: []string{"/t/compose.yml", "/d/o.yml"}, ProjectDir: "/host/core", EnvFile: "/d/app.env"}
	got := strings.Join(Args(p, "up", "-d"), " ")
	want := "compose -p portcullis-app -f /t/compose.yml -f /d/o.yml --project-directory /host/core --env-file /d/app.env up -d"
	if got != want {
		t.Errorf("Args = %q", got)
	}
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
	c := NewCLI("tcp://socket-proxy-hub:2375")
	c.Binary = bin
	c.Stdout, c.Stderr = io.Discard, io.Discard
	return c, log
}

func TestCLI(t *testing.T) {
	c, log := stub(t, "exit 0\n")
	p := Project{Name: "portcullis-app", Files: []string{"/c.yml"}}
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
		"compose -p portcullis-app -f /c.yml up -d --no-deps",
		"compose -p portcullis-app -f /c.yml down --remove-orphans",
		"compose -p portcullis-app down --remove-orphans",
		"DOCKER_HOST=tcp://socket-proxy-hub:2375 ORPHANS=true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
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
