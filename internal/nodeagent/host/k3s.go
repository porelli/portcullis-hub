package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// k3s on the node: its state, the token steps (contract §20.4; the
// supervisor call in-process, the tokens only in 0600 files), the etcd
// member removal (this server's own etcd client credentials, which never
// leave the node) and the uninstall.

// K10Re is k3s's CA-pinned token form K10<sha256 hex of the CA>::<creds>.
var K10Re = regexp.MustCompile(`^K10([0-9a-f]{64})::(.+)$`)

// secret is a token or a key: it never prints.
type secret string

func (secret) String() string   { return "<redacted>" }
func (secret) GoString() string { return "<redacted>" }

// k3sUnit is the node's k3s service (server or agent).
func k3sUnit(role string) string {
	if role == "server" {
		return "k3s"
	}
	return "k3s-agent"
}

// k3sState: absent (no binary), running or stopped.
func (a *Agent) k3sState(ctx context.Context) string {
	if !a.fs.exists(K3sBinary) {
		return "absent"
	}
	for _, u := range []string{"k3s", "k3s-agent"} {
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", u}}); err == nil {
			return "running"
		}
	}
	return "stopped"
}

// passphrase is the basic-auth password of a token for user: the part
// after K10<hash>::<user>: in the CA-pinned form, else the raw token
// (init's token file).
func passphrase(tok, user string) string {
	if m := K10Re.FindStringSubmatch(tok); m != nil {
		if p, ok := strings.CutPrefix(m[2], user+":"); ok {
			return p
		}
		return m[2]
	}
	return tok
}

// Supervisor is the k3s supervisor's token rotation.
type Supervisor interface {
	// RotateServerToken: PUT https://<ip>:6443/v1-k3s/token {"newToken"}
	// with basic auth server:<old passphrase>, the server's CA pinned by
	// the new token's hash.
	RotateServerToken(ctx context.Context, ip string, oldPass, newToken secret) error
}

type httpSupervisor struct{}

func (httpSupervisor) RotateServerToken(ctx context.Context, ip string, oldPass, newToken secret) error {
	m := K10Re.FindStringSubmatch(string(newToken))
	if m == nil {
		return errors.New("the new token isn't in k3s's CA-pinned form")
	}
	base := "https://" + net.JoinHostPort(ip, "6443")
	// #nosec G402: only /cacerts, checked against the token's CA hash below.
	insecure := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/cacerts", nil)
	resp, err := insecure.Do(req)
	if err != nil {
		return errors.New("the k3s supervisor is unreachable")
	}
	ca, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	sum := sha256.Sum256(ca)
	if hex.EncodeToString(sum[:]) != m[1] {
		return errors.New("the k3s server's CA doesn't match the token's hash")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	body, _ := json.Marshal(map[string]string{"newToken": string(newToken)})
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: ip, MinVersion: tls.VersionTLS12}}}
	req, _ = http.NewRequestWithContext(ctx, http.MethodPut, base+"/v1-k3s/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("server", string(oldPass))
	resp, err = c.Do(req)
	if err != nil {
		return errors.New("the k3s supervisor is unreachable")
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the k3s supervisor answered %d to the token rotation", resp.StatusCode)
	}
	return nil
}

// tokenFile reads a 0600 token file (refused otherwise).
func (a *Agent) tokenFile(path string) (secret, error) {
	fi, err := os.Lstat(a.fs.p(path))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is missing or not a 0600 file", path)
	}
	b, err := a.fs.read(path)
	if err != nil {
		return "", fmt.Errorf("%s is unreadable", path)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return secret(t), nil
}

// stageToken writes the request's new token to a 0600 file in a fresh
// 0700 directory and reads it back from there; the directory goes after.
func (a *Agent) stageToken(tok string) (secret, func(), error) {
	dir, err := os.MkdirTemp(a.fs.p(StateDir), ".rotate-*")
	if err != nil {
		return "", func() {}, errors.New("a staging directory for the token")
	}
	done := func() { os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil {
		done()
		return "", func() {}, errors.New("a staging directory for the token")
	}
	f := filepath.Join(dir, "new-token")
	if err := os.WriteFile(f, []byte(tok+"\n"), 0o600); err != nil {
		done()
		return "", func() {}, errors.New("staging the new token")
	}
	b, err := os.ReadFile(f)
	if err != nil {
		done()
		return "", func() {}, errors.New("staging the new token")
	}
	return secret(strings.TrimSpace(string(b))), done, nil
}

// tokenUser is the token's credential user: server, node, or "" (a
// bootstrap token id.secret).
func tokenUser(tok string) string {
	m := K10Re.FindStringSubmatch(tok)
	if m == nil {
		return ""
	}
	if u, _, ok := strings.Cut(m[2], ":"); ok {
		return u
	}
	return ""
}

// TokenStep is POST /v1/k3s/token-rotate (nodeadm.control).
//   - rotate (a server): the supervisor call with the old server token
//     (this node's token file), then the new one in the token file and
//     k3s restarted (the running server keeps the old token until it
//     restarts, and a server whose token file differs from the rotated
//     bootstrap can't start: spike-cluster.md);
//   - rotate-agent (a server): the agent token takes effect from
//     --agent-token-file when a server restarts (k3s's /v1-k3s/token
//     rotates only the server token), so: the file, then a restart;
//   - apply: the server token into a server's token file, the agent token
//     into an agent's, then a restart;
//   - apply-agent (a server): the agent token file, then a restart.
//
// Servers get the server token, agents the agent token (409 otherwise).
func (a *Agent) TokenStep(ctx context.Context, req na.TokenRotate) error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	st := a.state()
	if !K10Re.MatchString(req.NewToken) {
		return errStatus(400, "new_token isn't in k3s's CA-pinned form K10<hash>::<credentials>")
	}
	user := tokenUser(req.NewToken)
	server := st.Role == "server"
	switch req.Step {
	case "rotate", "rotate-agent", "apply-agent":
		if !server {
			return errStatus(409, "%s runs on a server: this node is an agent", req.Step)
		}
	case "apply":
	default:
		return errStatus(400, "step must be rotate, apply, rotate-agent or apply-agent")
	}
	wantUser := "node"
	if req.Step == "rotate" || (req.Step == "apply" && server) {
		wantUser = "server"
	}
	if user != wantUser {
		if wantUser == "node" && user == "server" {
			return errStatus(409, "%s takes the agent token, never the server token", req.Step)
		}
		return errStatus(409, "%s takes the %s token", req.Step, map[string]string{"server": "server", "node": "agent"}[wantUser])
	}
	if a.k3sState(ctx) == "absent" {
		return errStatus(409, "k3s isn't installed on this node")
	}
	newTok, cleanup, err := a.stageToken(req.NewToken)
	defer cleanup()
	if err != nil {
		return err
	}
	file := K3sTokenFile
	if wantUser == "node" && server {
		file = K3sAgentToken
	}
	if req.Step == "rotate" {
		old, err := a.tokenFile(K3sTokenFile)
		if err != nil {
			return err
		}
		if old != newTok {
			if err := a.cfg.Supervisor.RotateServerToken(ctx, st.MeshIP, secret(passphrase(string(old), "server")), newTok); err != nil {
				return err
			}
			a.log.Info("k3s server token rotated through the supervisor")
		}
	}
	cur, _ := a.tokenFile(file)
	if cur == newTok {
		a.log.Info("k3s token already in place", "step", req.Step)
		return nil
	}
	if err := a.fs.write(file, []byte(string(newTok)+"\n"), 0o600, 0o700); err != nil {
		return err
	}
	unit := k3sUnit(st.Role)
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"restart", "--no-block", unit}}); err != nil {
		return fmt.Errorf("restarting %s: %v", unit, err)
	}
	a.log.Info("k3s token written, k3s restarting", "step", req.Step, "unit", unit)
	return nil
}

// ── etcd ──

// Member is one etcd member.
type Member struct {
	ID       uint64
	Name     string
	PeerURLs []string
}

// Etcd is this server's etcd, through its own client credentials.
type Etcd interface {
	Members(ctx context.Context) ([]Member, error)
	Remove(ctx context.Context, id uint64) error
}

// etcdGateway is etcd's v3 JSON gateway on https://127.0.0.1:2379 with
// k3s's etcd client certificate.
type etcdGateway struct{ fs fsys }

const etcdTLS = "/var/lib/rancher/k3s/server/tls/etcd"

func (e *etcdGateway) client() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(e.fs.p(etcdTLS+"/client.crt"), e.fs.p(etcdTLS+"/client.key"))
	if err != nil {
		return nil, errors.New("this server's etcd client certificate is unreadable")
	}
	caPEM, err := e.fs.read(etcdTLS + "/server-ca.crt")
	if err != nil {
		return nil, errors.New("this server's etcd CA is unreadable")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil,
		TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}}}, nil
}

func (e *etcdGateway) post(ctx context.Context, path string, body, out any) error {
	c, err := e.client()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://127.0.0.1:2379"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("this server's etcd is unreachable")
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("etcd answered %d to %s", resp.StatusCode, path)
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

func (e *etcdGateway) Members(ctx context.Context) ([]Member, error) {
	var out struct {
		Members []struct {
			ID       string   `json:"ID"`
			Name     string   `json:"name"`
			PeerURLs []string `json:"peerURLs"`
		} `json:"members"`
	}
	if err := e.post(ctx, "/v3/cluster/member/list", map[string]any{}, &out); err != nil {
		return nil, err
	}
	ms := make([]Member, 0, len(out.Members))
	for _, m := range out.Members {
		id, err := strconv.ParseUint(m.ID, 10, 64)
		if err != nil {
			return nil, errors.New("etcd's member list is unreadable")
		}
		ms = append(ms, Member{ID: id, Name: m.Name, PeerURLs: m.PeerURLs})
	}
	return ms, nil
}

func (e *etcdGateway) Remove(ctx context.Context, id uint64) error {
	return e.post(ctx, "/v3/cluster/member/remove", map[string]string{"ID": strconv.FormatUint(id, 10)}, nil)
}

// peerHost is a peer URL's host.
func peerHost(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Hostname()
}

// RemoveMember is POST /v1/etcd/remove-member (nodeadm.control): on a
// server only, only a member whose peer URL host is mesh_ip and whose node
// portcullis-cluster-addresses lists as removed with that mesh address;
// never this node's own member. 204 once it is gone or already absent.
func (a *Agent) RemoveMember(ctx context.Context, req na.EtcdRemove) error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	st := a.state()
	if st.Role != "server" {
		return errStatus(409, "etcd members are removed on a server: this node is an agent")
	}
	if !meshAddrOK(req.MeshIP) || !idRe.MatchString(req.Node) {
		return errStatus(400, "mesh_ip or node is malformed")
	}
	if req.MeshIP == st.MeshIP || req.Node == st.ID {
		return errStatus(409, "a server never removes its own etcd member")
	}
	doc, err := a.cfg.Addresses(ctx)
	if err != nil {
		return errStatus(409, "portcullis-cluster-addresses can't be read through this node's k3s: %v", err)
	}
	n, ok := doc[req.Node]
	if !ok || n.State != "removed" || n.Mesh != req.MeshIP {
		return errStatus(409, "node %s isn't listed removed with mesh address %s in portcullis-cluster-addresses", req.Node, req.MeshIP)
	}
	ms, err := a.cfg.Etcd.Members(ctx)
	if err != nil {
		return err
	}
	removed := 0
	for _, m := range ms {
		hit, own := false, false
		for _, u := range m.PeerURLs {
			switch peerHost(u) {
			case req.MeshIP:
				hit = true
			case st.MeshIP:
				own = true
			}
		}
		if !hit || own {
			continue
		}
		if err := a.cfg.Etcd.Remove(ctx, m.ID); err != nil {
			return err
		}
		removed++
		a.log.Info("etcd member removed", "node", req.Node, "mesh_ip", req.MeshIP, "member", m.Name)
	}
	if removed == 0 {
		a.log.Info("etcd member already absent", "node", req.Node, "mesh_ip", req.MeshIP)
	}
	return nil
}

// k3sAddresses reads portcullis-cluster-addresses with the node's k3s
// admin kubeconfig (servers only), at this server's mesh address.
func (a *Agent) k3sAddresses(ctx context.Context) (map[string]DocNode, error) {
	rc, err := clientcmd.BuildConfigFromFlags("", a.fs.p(K3sKubeconfig))
	if err != nil {
		return nil, errors.New("no k3s kubeconfig on this node")
	}
	rc.Timeout = 10 * time.Second
	// The API server binds the mesh address only (--bind-address), which
	// its certificate names; k3s.yaml says 127.0.0.1.
	if ip := a.state().MeshIP; meshAddrOK(ip) {
		rc.Host = "https://" + net.JoinHostPort(ip, "6443")
	}
	c, err := corev1.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	cm, err := c.ConfigMaps(a.cfg.CoreNS).Get(ctx, "portcullis-cluster-addresses", metav1.GetOptions{})
	if err != nil {
		return nil, errors.New("the ConfigMap portcullis-cluster-addresses isn't readable")
	}
	var doc struct {
		Nodes map[string]DocNode `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(cm.Data["addresses.json"]), &doc); err != nil || doc.Nodes == nil {
		return nil, errors.New("portcullis-cluster-addresses holds no readable document")
	}
	return doc.Nodes, nil
}

// ── the uninstall ──

// Uninstall runs after POST /v1/k3s/uninstall answered: the pinned
// k3s uninstall script, pcmesh and its rules, the nodeagent's state and
// unit; then the process stops.
func (a *Agent) Uninstall(ctx context.Context) {
	a.uninst.Do(func() {
		a.opMu.Lock()
		defer a.opMu.Unlock()
		for _, s := range []string{"/usr/local/bin/k3s-uninstall.sh", "/usr/local/bin/k3s-agent-uninstall.sh"} {
			if a.fs.exists(s) {
				if _, err := a.cfg.Run.Run(ctx, Cmd{Name: s}); err != nil {
					a.log.Warn("the k3s uninstall script failed", "script", s, "err", err.Error())
				} else {
					a.log.Info("k3s uninstalled", "script", s)
				}
			}
		}
		a.probe.stop()
		a.removeMesh(ctx)
		for _, p := range []string{MeshKeyFile, "/etc/wireguard/pcmesh.conf", "/etc/systemd/system/k3s.service.d/10-pcmesh.conf",
			"/etc/systemd/system/k3s-agent.service.d/10-pcmesh.conf"} {
			if err := a.fs.remove(p); err != nil {
				a.log.Warn("uninstall", "err", err.Error())
			}
		}
		if err := a.fs.removeAll(StateDir); err != nil {
			a.log.Warn("uninstall", "err", err.Error())
		}
		a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"disable", UnitName}})
		a.fs.remove(unitFile)
		a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"daemon-reload"}})
		a.log.Info("the node left the cluster: the nodeagent stops")
		a.cfg.Exit()
	})
}

func defaultExit() { os.Exit(0) }
