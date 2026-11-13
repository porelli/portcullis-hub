//go:build docker

package hub

// docker compose against a real daemon (build tag docker, CI step with
// PORTCULLIS_DOCKER_TEST=require): the setup choices' COMPOSE_PROFILES in
// the env file select what `up` starts, and Down (`--profile '*'`) takes
// every profile's containers down — an unselected profile's leftover
// included (contract §13.18).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
)

func TestDockerComposeProfiles(t *testing.T) {
	_, guard := dockerGuardOrSkip(t)
	if out, err := exec.Command("docker", "compose", "version", "--short").Output(); err != nil {
		if os.Getenv("PORTCULLIS_DOCKER_TEST") == "require" {
			t.Fatalf("no docker compose: %v", err)
		}
		t.Skipf("no docker compose: %v", err)
	} else if err := compose.CheckVersion(strings.TrimSpace(string(out))); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	svc := func(name, profile string) string {
		s := "  " + name + ":\n    image: " + HelperImage + "\n    command: [\"sleep\", \"300\"]\n    network_mode: none\n"
		if profile != "" {
			s += "    profiles: [" + profile + "]\n"
		}
		return s
	}
	file := filepath.Join(dir, "compose.yml")
	if err := os.WriteFile(file, []byte("services:\n"+svc("app", "")+svc("db-a", "db-a")+svc("db-b", "db-b")), 0644); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "app.env")
	b := make([]byte, 4)
	rand.Read(b)
	p := compose.Project{Name: "portcullis-ptest" + hex.EncodeToString(b), Files: []string{file}, ProjectDir: dir, EnvFile: env}
	cli := compose.NewCLI(os.Getenv("DOCKER_HOST"), guard)
	t.Cleanup(func() { cli.DownByName(context.Background(), p.Name) })
	running := func() []string {
		t.Helper()
		out := dockerCLI(t, "ps", "--filter", "label=com.docker.compose.project="+p.Name, "--format", `{{.Label "com.docker.compose.service"}}`)
		var svcs []string
		for _, l := range strings.Fields(out) {
			svcs = append(svcs, l)
		}
		slices.Sort(svcs)
		return svcs
	}
	start := func(profiles string) {
		t.Helper()
		if err := os.WriteFile(env, []byte("COMPOSE_PROFILES='"+profiles+"'\n"), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := cli.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		if err := cli.Up(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	start("db-a")
	if got := running(); !slices.Equal(got, []string{"app", "db-a"}) {
		t.Fatalf("COMPOSE_PROFILES=db-a runs %v", got)
	}
	// The choice switched: up starts db-b and leaves db-a (compose never
	// counts an unselected profile's service as an orphan) …
	start("db-b")
	if got := running(); !slices.Equal(got, []string{"app", "db-a", "db-b"}) {
		t.Fatalf("after switching to db-b: %v", got)
	}
	// … and Down takes every profile down.
	if err := cli.Down(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := running(); len(got) != 0 {
		t.Fatalf("after Down: %v still run", got)
	}
}
