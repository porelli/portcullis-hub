package compose

import (
	"context"
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
		"compose -p portcullis-app -f /c.yml down",
		"compose -p portcullis-app down",
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
