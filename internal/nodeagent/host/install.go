package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The k3s pins (plan Amendment 1; core's scripts/lib/kube_install.sh, the
// same values). get.k3s.io is unversioned: the script is taken from the
// release tag, and the binary is checked on its own.
const (
	K3sVersion       = "v1.37.2+k3s1"
	maxK3sBinary     = 512 << 20
	maxInstallScript = 1 << 20
)

// k3sPins are the download pins (a var only so tests can serve their own).
var k3sPins = struct {
	scriptURL, scriptSHA256, releaseBase string
	sha256                               map[string]string
}{
	scriptURL:    "https://raw.githubusercontent.com/k3s-io/k3s/v1.37.2%2Bk3s1/install.sh",
	scriptSHA256: "ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b",
	releaseBase:  "https://github.com/k3s-io/k3s/releases/download/v1.37.2%2Bk3s1/",
	sha256: map[string]string{
		"amd64": "265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda",
		"arm64": "a779ccf1e5e2e33a62f5a29c2f1c0bbf99431e100579d4c10f0aa0742a6aa84b",
	},
}

// FlannelNetConf is flannel's net-conf for the cluster network cidr (the
// join answer's cluster_cidr), used verbatim by k3s (core's
// kube_flannel_conf, fixture tests/fixtures/k3s-flannel-net-conf.json).
func FlannelNetConf(cidr string) string {
	return fmt.Sprintf(`{"Network":"%s","EnableIPv4":true,"EnableIPv6":false,"Backend":{"Type":"wireguard","ListenPort":%d,"PersistentKeepaliveInterval":25,"Mode":"separate"}}`+"\n",
		cidr, 51840)
}

func k3sAsset() (name, sum string, err error) {
	switch runtime.GOARCH {
	case "amd64":
		return "k3s", k3sPins.sha256["amd64"], nil
	case "arm64":
		return "k3s-arm64", k3sPins.sha256["arm64"], nil
	}
	return "", "", fmt.Errorf("no pinned k3s for %s", runtime.GOARCH)
}

// fetch downloads u into path (0600), refused unless its sha256 is sum.
func fetch(ctx context.Context, c *http.Client, u, sum, path string, max int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("could not download %s", redactURL(u))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not download %s (%d)", redactURL(u), resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("could not download %s", redactURL(u))
	}
	if n > max || hex.EncodeToString(h.Sum(nil)) != sum {
		return fmt.Errorf("%s doesn't match its pinned sha256: nothing was installed", redactURL(u))
	}
	return nil
}

// installK3s: the pinned script and binary (sha256-checked before
// anything runs), the token in its 0600 --token-file, flannel's net-conf,
// the unit ordering after the nodeagent (which brings pcmesh up), then
// `sh install.sh <server|agent> <flags…>` (the token never on argv).
func (a *Agent) installK3s(ctx context.Context, c *http.Client, out io.Writer, j K3sJoin) error {
	asset, sum, err := k3sAsset()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.fs.p(StateDir), 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(a.fs.p(StateDir), ".k3s-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	script, bin := filepath.Join(tmp, "install.sh"), filepath.Join(tmp, "k3s")
	if err := fetch(ctx, c, k3sPins.scriptURL, k3sPins.scriptSHA256, script, maxInstallScript); err != nil {
		return err
	}
	if err := fetch(ctx, c, k3sPins.releaseBase+asset, sum, bin, maxK3sBinary); err != nil {
		return err
	}
	if err := a.fs.write(K3sTokenFile, []byte(string(j.Token)+"\n"), 0o600, 0o700); err != nil {
		return err
	}
	if j.AgentToken != "" {
		if err := a.fs.write(K3sAgentToken, []byte(string(j.AgentToken)+"\n"), 0o600, 0o700); err != nil {
			return err
		}
	}
	if err := a.fs.write(FlannelConf, []byte(FlannelNetConf(j.ClusterCIDR)), 0o644, 0o700); err != nil {
		return err
	}
	unit := k3sUnit(j.Role)
	dropIn := "[Unit]\nAfter=" + UnitName + "\nWants=" + UnitName + "\n"
	if err := a.fs.write("/etc/systemd/system/"+unit+".service.d/10-pcmesh.conf", []byte(dropIn), 0o644, 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		return err
	}
	if err := a.fs.write(K3sBinary, b, 0o755, 0o755); err != nil {
		return err
	}
	// No unpinned k3s-selinux RPM from install.sh (RHEL family).
	env := []string{"INSTALL_K3S_SKIP_DOWNLOAD=true", "INSTALL_K3S_SKIP_SELINUX_RPM=true", "INSTALL_K3S_VERSION=" + K3sVersion, "K3S_TOKEN_FILE=" + K3sTokenFile}
	if j.Role != "server" {
		env = append(env, "K3S_URL="+j.ServerURL)
	}
	args := append([]string{script, j.Role}, j.Flags...)
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "sh", Args: args, Env: env, Out: out}); err != nil {
		return fmt.Errorf("the k3s install script failed (%v): see journalctl -u %s", err, unit)
	}
	return nil
}

// UnitText is the nodeagent's systemd unit: pcmesh up before the service
// counts as started (k3s is ordered after it), restarted on failure.
func UnitText() string {
	return strings.Join([]string{
		"[Unit]",
		"Description=Portcullis nodeagent (the cluster node's host service)",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"ExecStartPre=" + AgentBinary + " mesh-up",
		"ExecStart=" + AgentBinary + " serve",
		"Restart=on-failure",
		"RestartSec=5",
		// It writes /etc, /var/lib and /usr/local (k3s, pcmesh, its state).
		"NoNewPrivileges=yes",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
}

func (a *Agent) installUnit(ctx context.Context, role string) error {
	_ = role
	if err := a.fs.write(unitFile, []byte(UnitText()), 0o644, 0o755); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", UnitName}} {
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: args}); err != nil {
			return fmt.Errorf("starting %s: %v", UnitName, err)
		}
	}
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", UnitName}}); err != nil {
		return errors.New(UnitName + " didn't start: see journalctl -u " + UnitName)
	}
	return nil
}

func osMode(m uint32) os.FileMode { return os.FileMode(m) }
