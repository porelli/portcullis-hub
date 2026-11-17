//go:build docker

package hub

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// TestDockerUsageHelper: the usage helper on a named volume (the real
// Hub-shaped image): the report decodes with alloc_bytes > 0; inside the
// same spec a write to /vol fails and the only effective capability is
// DAC_READ_SEARCH; nothing is left behind.
func TestDockerUsageHelper(t *testing.T) {
	c := dockerOrSkip(t)
	h := dockerHub(t, c)
	name := fmt.Sprintf("pcusagetest-%d", time.Now().UnixNano())
	dockerCLI(t, "volume", "create", name)
	t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", name).Run() })
	dockerCLI(t, "run", "--rm", "--network", "none", "-v", name+":/v", HelperImage, "sh", "-c",
		"mkdir -p /v/d && head -c 1048576 /dev/zero > /v/d/f && ln /v/d/f /v/d/g && chown -R 1000:1000 /v/d && chmod 0700 /v/d")
	ctx := context.Background()
	r := fixerRun{Mode: "usage", Volume: runtime.VolumeMount{Name: name}, Opts: usageCaps}
	rep, err := h.runUsageFixer(ctx, r)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if rep.Mode != "usage" || rep.AllocBytes < 1<<20 || rep.HardLinks.N != 2 || rep.Failed.N != 0 || rep.IOIdle == nil || rep.TotalBytes == 0 {
		t.Errorf("report = alloc %d hard links %d failed %d io_idle %v total %d", rep.AllocBytes, rep.HardLinks.N, rep.Failed.N, rep.IOIdle, rep.TotalBytes)
	}
	// The same spec, another command: the mount is read-only and the
	// capabilities are exactly DAC_READ_SEARCH (bit 2).
	s := r.Spec(h.fixerImage, fixerBinary)
	s.Cmd = []string{"/bin/sh", "-c", "touch /vol/x 2>/dev/null; echo rc=$?; grep CapEff /proc/self/status"}
	res, err := c.RunHelper(ctx, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout)
	if !strings.Contains(out, "rc=1") || !strings.Contains(out, "CapEff:\t0000000000000004") {
		t.Errorf("inside the helper: %q", out)
	}
	left := dockerCLI(t, "ps", "-a", "-q", "--filter", "label=io.portcullis.hub.helper=usage:"+name)
	if left != "" {
		t.Errorf("helpers left: %s", left)
	}
}
