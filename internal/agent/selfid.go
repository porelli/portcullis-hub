package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/portcullis/hub/internal/runtime"
)

// The agent's own container (fix round 5, R4-L1): never by a hostname
// lookup (a bundle's container_name could take the hostname). Its id
// comes from AGENT_CONTAINER_ID (core sets it), else from the kernel's
// view of the container (/proc/self/mountinfo, /proc/self/cgroup), and
// the container found must be exactly that id and carry the agent's
// compose service label and the agent image's own label (plus the image
// id, when AGENT_SELF_IMAGE_ID names it; not AGENT_IMAGE, which is core's
// image ref).

var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// containerIDFrom finds the one 64-hex container id the files name
// (mountinfo's /containers/<id>/ paths, cgroup's docker-<id> or
// libpod-<id> scopes). Several different ids: ambiguous, an error.
func containerIDFrom(files ...io.Reader) (string, error) {
	found := map[string]bool{}
	for _, f := range files {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.Contains(line, "containers/") && !strings.Contains(line, "docker") && !strings.Contains(line, "libpod") {
				continue
			}
			for _, id := range containerIDRe.FindAllString(line, -1) {
				found[id] = true
			}
		}
	}
	switch len(found) {
	case 0:
		return "", errors.New("no container id in /proc/self/mountinfo or /proc/self/cgroup")
	case 1:
		for id := range found {
			return id, nil
		}
	}
	return "", errors.New("more than one container id in /proc/self/mountinfo and /proc/self/cgroup: ambiguous")
}

// SelfContainerID is the agent's own container id: AGENT_CONTAINER_ID,
// else the kernel's view (proc names the files to read).
func SelfContainerID(getenv func(string) string, proc string) (string, error) {
	if id := strings.TrimSpace(getenv("AGENT_CONTAINER_ID")); id != "" {
		if !regexp.MustCompile(`^[0-9a-f]{12,64}$`).MatchString(id) {
			return "", errors.New("AGENT_CONTAINER_ID must be a container id (hex)")
		}
		return id, nil
	}
	var rs []io.Reader
	for _, n := range []string{"mountinfo", "cgroup"} {
		if f, err := os.Open(proc + "/self/" + n); err == nil {
			defer f.Close()
			rs = append(rs, f)
		}
	}
	return containerIDFrom(rs...)
}

// VerifySelf inspects id and checks it is the agent's container: the
// same id (a prefix of the full one at most), the agent's compose
// service (AGENT_SERVICE, default "agent") and, when given, its image.
// SelfImageLabel is the agent image's own label (Dockerfile.agent); its
// containers inherit it.
const SelfImageLabel = "io.portcullis.agent"

func VerifySelf(ctx context.Context, rt runtime.Instances, id, service, image string) (runtime.UnitInfo, error) {
	ui, err := rt.Inspect(ctx, id)
	if err != nil {
		return ui, fmt.Errorf("the agent can't inspect its own container %s: %v", id, err)
	}
	if !strings.HasPrefix(ui.ID, id) {
		return ui, fmt.Errorf("the container found for %s is %s: refusing to guess the agent's own container", id, ui.ID)
	}
	if got := ui.Labels["com.docker.compose.service"]; got != service {
		return ui, fmt.Errorf("the agent's container has the compose service %q, not %q: refusing to start", got, service)
	}
	if ui.Labels[SelfImageLabel] != "1" {
		return ui, fmt.Errorf("the container %s doesn't run the agent's image (no %s label): refusing to start", id, SelfImageLabel)
	}
	if image != "" && ui.Image != image {
		return ui, fmt.Errorf("the agent's container runs image %s, not AGENT_SELF_IMAGE_ID %s: refusing to start", ui.Image, image)
	}
	return ui, nil
}
