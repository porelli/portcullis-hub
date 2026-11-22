package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// The nodeagent's own upgrade (Task 30 fix round 1): nodeadm (only its
// client certificate, CN nodeadm.control) names the sha256 of the binary
// it serves for each architecture; a joined node whose installed binary
// differs downloads <endpoint>/nodeagent-<arch> from nodeadm's public path
// (the join's, cfg.HTTP), installs it only when its sha256 is the named
// one (a temp file in the binary's directory, 0755, renamed over it) and
// restarts its unit after the answer. The trust anchor is the same as the
// join's: nodeadm's digest-pinned image carries the binaries and their
// sums. The first node (adopted) is the CLI's: refused (409).

// maxAgentBinary bounds the download.
const maxAgentBinary = 256 << 20

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// UpgradeAgent is POST /v1/agent/upgrade: "current" or "upgraded".
func (a *Agent) UpgradeAgent(ctx context.Context, q na.AgentUpgrade) (string, error) {
	if !sha256Re.MatchString(q.AMD64) || !sha256Re.MatchString(q.ARM64) {
		return "", errStatus(http.StatusBadRequest, "amd64 and arm64 must be sha256 hex digests")
	}
	st := a.state()
	if st.ID == "" {
		return "", errStatus(http.StatusConflict, "this node has no state")
	}
	if st.Adopted {
		return "", errStatus(http.StatusConflict, "the first node's nodeagent is upgraded by ./portcullis up on its host")
	}
	want := map[string]string{"amd64": q.AMD64, "arm64": q.ARM64}[runtime.GOARCH]
	if want == "" {
		return "", errStatus(http.StatusConflict, "no nodeagent for %s", runtime.GOARCH)
	}
	if have, err := fileSHA256(a.fs.p(AgentBinary)); err == nil && have == want {
		return "current", nil
	}
	if !strings.HasPrefix(st.Endpoint, "https://") {
		return "", errStatus(http.StatusConflict, "this node has no nodeadm endpoint")
	}
	bin := a.fs.p(AgentBinary)
	tmp := filepath.Join(filepath.Dir(bin), ".nodeagent-upgrade")
	_ = os.Remove(tmp)
	if err := fetch(ctx, a.httpClient(), strings.TrimSuffix(st.Endpoint, "/")+"/nodeagent-"+runtime.GOARCH, want, tmp, maxAgentBinary); err != nil {
		_ = os.Remove(tmp)
		return "", errStatus(http.StatusBadGateway, "%v", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, bin); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	a.log.Info("nodeagent upgraded", "sha256", want)
	return "upgraded", nil
}

// restartSelf restarts the unit (the new binary runs from its start).
func (a *Agent) restartSelf(ctx context.Context) {
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"restart", "--no-block", UnitName}}); err != nil {
		a.log.Warn("the upgraded nodeagent isn't restarted (it runs at the next start)", "err", err.Error())
	}
}

func (a *Agent) httpClient() *http.Client {
	if a.cfg.HTTP != nil {
		return a.cfg.HTTP
	}
	return http.DefaultClient
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
