package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/portcullis/hub/internal/jsonstrict"
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

// tokenStepTimeout bounds a token step (it runs on its own context, not
// the request's).
const tokenStepTimeout = 50 * time.Second

// tokenIntent is the 0600 intent file of a token step in progress: the
// step and the new token's sha256 (never the token).
type tokenIntent struct {
	Step      string `json:"step"`
	NewSHA256 string `json:"new_sha256"`
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// bootstrapKey is k3s's etcd key of the bootstrap data under a server
// token's passphrase: /bootstrap/<first 12 hex of its sha256> (k3s
// pkg/cluster/storage.go storageKey, util.ShortHash).
func bootstrapKey(pass string) string { return "/bootstrap/" + sha256Hex(pass)[:12] }

// usesAgentTokenFile: this server's k3s reads --agent-token-file (the
// unit install.sh wrote, or k3s's config.yaml): refused by TokenStep.
func (a *Agent) usesAgentTokenFile() bool {
	unit := string(must0(a.fs.read("/etc/systemd/system/k3s.service")))
	if strings.Contains(unit, "--agent-token-file="+K3sAgentToken) || strings.Contains(unit, "'--agent-token-file' '"+K3sAgentToken+"'") {
		return true
	}
	for _, l := range strings.Split(string(must0(a.fs.read("/etc/rancher/k3s/config.yaml"))), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.TrimSpace(k) == "agent-token-file" && strings.Trim(strings.TrimSpace(v), `"'`) == K3sAgentToken {
			return true
		}
	}
	return false
}

func must0(b []byte, _ error) []byte { return b }

// k3sCAHash is sha256 of this node's k3s server CA bundle (what /cacerts
// serves and a K10 token pins), "" when unreadable.
func (a *Agent) k3sCAHash(role string) string {
	f := "/var/lib/rancher/k3s/agent/server-ca.crt"
	if role == "server" {
		f = "/var/lib/rancher/k3s/server/tls/server-ca.crt"
	}
	b, err := a.fs.read(f)
	if err != nil || len(b) == 0 {
		return ""
	}
	return sha256Hex(string(b))
}

// TokenStep is POST /v1/k3s/token-rotate (nodeadm.control), on its own
// context, one at a time, resumable:
//   - rotate (a server): an intent file (the step and the new token's
//     sha256), then the supervisor call with the old server token (this
//     node's token file) unless etcd already holds the bootstrap under the
//     new token (a call whose answer was lost); a failed call counts as
//     done when etcd then holds it. Then the new token into the token file
//     and k3s restarted (the running server keeps the old token until it
//     restarts, and a server whose token file differs from the rotated
//     bootstrap can't start: spike-cluster.md); the intent goes last, so
//     a step cut short between the write and the restart restarts again;
//   - apply (a server): the server token into its token file, then a
//     restart; k3s takes the new cred/passwd from the datastore at that
//     start.
//
// Servers only, the server token only, pinning this node's k3s CA (409
// otherwise). No agent token steps (core agent-token fix): k3s v1.37.2
// can't rotate a separate --agent-token-file safely (genUsers rewrites
// passwd's node line at start, after the bootstrap reconcile, and nothing
// re-saves the datastore's copy: the next start of every server is fatal,
// "cred/passwd newer than datastore"), so no server runs with one (a
// server that does is refused: 409 agent_token_file_present) and the node
// credential k3s derives from the server token rotates with it. An agent
// holds no shared token (it restarts on its node identity): every step on
// an agent is refused.
func (a *Agent) TokenStep(ctx context.Context, req na.TokenRotate) error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	st := a.state()
	m := K10Re.FindStringSubmatch(req.NewToken)
	if m == nil {
		return errStatus(400, "new_token isn't in k3s's CA-pinned form K10<hash>::<credentials>")
	}
	switch req.Step {
	case "rotate", "apply":
		if st.Role != "server" {
			return errStatus(409, "%s runs on a server: an agent holds no shared k3s token", req.Step)
		}
	default:
		return errStatus(400, "step must be rotate or apply")
	}
	if tokenUser(req.NewToken) != "server" {
		return errStatus(409, "%s takes the server token", req.Step)
	}
	if a.k3sState(ctx) == "absent" {
		return errStatus(409, "k3s isn't installed on this node")
	}
	if a.usesAgentTokenFile() {
		return errKind(409, "agent_token_file_present", "this server's k3s uses --agent-token-file: k3s can't rotate that token without a fatal restart")
	}
	if h := a.k3sCAHash(st.Role); h == "" || h != m[1] {
		return errStatus(409, "the token doesn't pin this node's k3s CA (another cluster's token, or the CA is unreadable)")
	}
	newTok, cleanup, err := a.stageToken(req.NewToken)
	defer cleanup()
	if err != nil {
		return err
	}
	file := K3sTokenFile
	want := tokenIntent{Step: req.Step, NewSHA256: sha256Hex(string(newTok))}
	var have tokenIntent
	pending := json.Unmarshal(must0(a.fs.read(intentFile)), &have) == nil && have == want
	cur, _ := a.tokenFile(file)
	if cur == newTok && !pending {
		a.log.Info("k3s token already in place", "step", req.Step)
		return nil
	}
	ib, _ := json.Marshal(want)
	if err := a.fs.write(intentFile, ib, 0o600, 0o700); err != nil {
		return err
	}
	if req.Step == "rotate" && cur != newTok {
		newPass := passphrase(string(newTok), "server")
		done, herr := a.cfg.Etcd.HasKey(ctx, bootstrapKey(newPass))
		if herr != nil || !done {
			old, err := a.tokenFile(K3sTokenFile)
			if err != nil {
				return err
			}
			perr := a.cfg.Supervisor.RotateServerToken(ctx, st.MeshIP, secret(passphrase(string(old), "server")), newTok)
			if perr != nil {
				// The answer may have been lost after the re-key.
				if ok, _ := a.cfg.Etcd.HasKey(ctx, bootstrapKey(newPass)); !ok {
					return perr
				}
				a.log.Info("k3s server token rotation found in effect after a failed call")
			} else {
				a.log.Info("k3s server token rotated through the supervisor")
			}
		} else {
			a.log.Info("k3s server token rotation already in effect (resumed)")
		}
	}
	if cur != newTok {
		if err := a.fs.write(file, []byte(string(newTok)+"\n"), 0o600, 0o700); err != nil {
			return err
		}
	}
	unit := k3sUnit(st.Role)
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"restart", "--no-block", unit}}); err != nil {
		return fmt.Errorf("restarting %s: %v", unit, err)
	}
	if err := a.fs.remove(intentFile); err != nil {
		a.log.Warn("the token intent file stays", "err", err.Error())
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
	// HasKey: the key exists (a count only: no value is read).
	HasKey(ctx context.Context, key string) (bool, error)
}

// etcdGateway is etcd's v3 JSON gateway with k3s's etcd client
// certificate, on k3s's own HTTP listener https://127.0.0.1:2382 (k3s
// v1.37.2 sets etcd's listen-client-http-urls to it, pkg/etcd/etcd.go
// listenClientHTTPURLs; 2379 then serves gRPC only: a JSON call there gets
// 415 over HTTP/2 and an empty reply over HTTP/1.1 — found live, every
// server revoke stopped at etcd_removed).
type etcdGateway struct{ fs fsys }

const etcdTLS = "/var/lib/rancher/k3s/server/tls/etcd"

// etcdGatewayPort is k3s's loopback etcd HTTP port (listen-client-http-urls).
const etcdGatewayPort = "2382"

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
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://127.0.0.1:"+etcdGatewayPort+path, bytes.NewReader(b))
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

func (e *etcdGateway) HasKey(ctx context.Context, key string) (bool, error) {
	var out struct {
		Count string `json:"count"`
	}
	if err := e.post(ctx, "/v3/kv/range", map[string]any{"key": base64.StdEncoding.EncodeToString([]byte(key)), "count_only": true}, &out); err != nil {
		return false, err
	}
	n, _ := strconv.ParseInt(out.Count, 10, 64)
	return n > 0, nil
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
	// Independent of the document's writer: the Node object is gone (its
	// deletion comes before the member's removal).
	if exists, err := a.cfg.NodeExists(ctx, req.Node); err != nil || exists {
		if err != nil {
			return errStatus(409, "the Node %s can't be looked up through this node's k3s", req.Node)
		}
		return errStatus(409, "the Node %s still exists: its etcd member stays", req.Node)
	}
	ms, err := a.cfg.Etcd.Members(ctx)
	if err != nil {
		return err
	}
	removed := 0
	for _, m := range ms {
		hit, own := false, false
		if !strings.HasPrefix(m.Name, req.Node+"-") {
			// k3s names a member <node name>-<suffix>: another node's
			// member (or a foreign one) at that address is never removed.
			for _, u := range m.PeerURLs {
				if peerHost(u) == req.MeshIP {
					return errStatus(409, "the etcd member at %s isn't node %s's", req.MeshIP, req.Node)
				}
			}
			continue
		}
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
	// The API server binds the mesh address only (--bind-address), which
	// its certificate names; k3s.yaml says 127.0.0.1 (k3sClient).
	c, err := a.k3sClient()
	if err != nil {
		return nil, err
	}
	cm, err := c.ConfigMaps(a.cfg.CoreNS).Get(ctx, "portcullis-cluster-addresses", metav1.GetOptions{})
	if err != nil {
		return nil, errors.New("the ConfigMap portcullis-cluster-addresses isn't readable")
	}
	var doc addressesDoc
	if err := jsonstrict.Decode([]byte(cm.Data["addresses.json"]), &doc); err != nil || doc.V != 1 {
		return nil, errors.New("portcullis-cluster-addresses holds no readable document")
	}
	return doc.Nodes, nil
}

// addressesDoc is portcullis-cluster-addresses' addresses.json (§20.9),
// decoded strictly.
type addressesDoc struct {
	V           int                `json:"v"`
	MeshCIDR    string             `json:"mesh_cidr"`
	ClusterCIDR string             `json:"cluster_cidr"`
	ServiceCIDR string             `json:"service_cidr"`
	API         []string           `json:"api"`
	Nodes       map[string]DocNode `json:"nodes"`
	// RemovedNames: every node name nodeadm removed (the admission params'
	// removedNodes: a removed node's kubelet identity can't register its
	// Node again; Task 30 fix round 1).
	RemovedNames []string `json:"removed_names"`
}

func (a *Agent) k3sClient() (*corev1.CoreV1Client, error) {
	rc, err := clientcmd.BuildConfigFromFlags("", a.fs.p(K3sKubeconfig))
	if err != nil {
		return nil, errors.New("no k3s kubeconfig on this node")
	}
	rc.Timeout = 10 * time.Second
	if ip := a.state().MeshIP; meshAddrOK(ip) {
		rc.Host = "https://" + net.JoinHostPort(ip, "6443")
	}
	return corev1.NewForConfig(rc)
}

// k3sNodeExists: a Node of that name, through the node's k3s.
func (a *Agent) k3sNodeExists(ctx context.Context, name string) (bool, error) {
	c, err := a.k3sClient()
	if err != nil {
		return false, err
	}
	_, err = c.Nodes().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("the Node can't be read")
	}
	return true, nil
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
