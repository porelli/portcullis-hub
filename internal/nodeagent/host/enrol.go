package host

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/portcullis/hub/internal/jsonstrict"
	na "github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/pkinode"
	"github.com/portcullis/hub/internal/servers"
)

// The join (contract §20.3, §20.4 "join"): the code on stdin, the host
// checks, /node/v1/nonce and /node/v1/enrol (the CSR and the pcmesh key
// generated here), the CA checked against ca_sha256, pcmesh up with the
// bootstrap plan, the nodeagent service started, the RTT to the servers,
// the signed /node/v1/join (retried on mesh_pending / waiting_admission),
// then k3s from the pinned script and binary with the token in a 0600
// --token-file.

const (
	clusterDomain = "cluster.portcullis.internal"
	proofLabel    = "portcullis-node-enrol-v1"
)

// ErrCodeRefused is any 403 of /node/v1/enrol.
var ErrCodeRefused = errors.New("the join code was refused")

// ErrCAMismatch: the enrol answer's CA isn't the code's ca_sha256.
var ErrCAMismatch = errors.New("the cluster's CA doesn't match the join code")

// JoinDeps are the join's outside world (tests replace them).
type JoinDeps struct {
	// HTTP reaches the code's endpoint (https://<d>/node).
	HTTP *http.Client
	// Install installs k3s (default: the pinned script and binary).
	Install func(ctx context.Context, j K3sJoin) error
	// RTT measures the mesh RTT to addrs (default: the UDP echo).
	RTT func(ctx context.Context, addrs []string) map[string]int
	// Retry is the wait between join retries (5 s), MeshPendingFor and
	// AdmissionFor the limits (10 and 30 min), ServersFor how long the
	// servers' echo is awaited (5 min).
	Retry, MeshPendingFor, AdmissionFor, ServersFor time.Duration
}

// K3sJoin is what the k3s install gets: the tokens are secrets.
type K3sJoin struct {
	Role        string
	ServerURL   string
	Token       secret
	Flags       []string
	ClusterCIDR string
}

// joinAnswer is /node/v1/join's 200 (§20.2), decoded strictly: no
// agent_token (core agent-token fix: no node gets a separate agent token;
// an answer carrying one is refused as an unknown field).
type joinAnswer struct {
	Role        string   `json:"role"`
	ServerURL   string   `json:"server_url"`
	Token       string   `json:"token"`
	Flags       []string `json:"flags"`
	ClusterCIDR string   `json:"cluster_cidr"`
}

// checkNodeLeaf: a node-cluster certificate from ca for cn (its only SAN,
// a DNS name), for server and client auth, of the key spki.
func checkNodeLeaf(leaf, ca *x509.Certificate, cn string, spki []byte, now time.Time) error {
	for _, u := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(ca), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{u}}); err != nil {
			return err
		}
	}
	if leaf.Subject.CommonName != cn || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != cn ||
		len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses) != 0 || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) {
		return errors.New("another certificate")
	}
	return nil
}

// ProofFor is the §20.2 enrol proof: HMAC-SHA256(key = sha256(secret),
// "portcullis-node-enrol-v1" ‖ nonce ‖ server_id ‖ sha256(SPKI)).
func ProofFor(secretBytes, nonce []byte, serverID string, spki []byte) []byte {
	sp := sha256.Sum256(spki)
	return proofFromSPKISum(secretBytes, nonce, serverID, sp[:])
}

func proofFromSPKISum(secretBytes, nonce []byte, serverID string, spkiSum []byte) []byte {
	key := sha256.Sum256(secretBytes)
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(proofLabel))
	m.Write(nonce)
	m.Write([]byte(serverID))
	m.Write(spkiSum)
	return m.Sum(nil)
}

type signedCanon struct {
	ServerID   string `json:"server_id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Time       string `json:"time"`
	Nonce      string `json:"nonce"`
	BodySHA256 string `json:"body_sha256"`
}

// CanonicalBytes is the signed join request's canonical JSON (§20.2).
func CanonicalBytes(serverID, method, path, tm, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(signedCanon{serverID, method, path, tm, nonce, hex.EncodeToString(sum[:])})
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

type apiAnswer struct {
	status int
	body   []byte
	kind   string
	text   string
}

func (a *Agent) call(ctx context.Context, d JoinDeps, method, u string, body []byte, hdr http.Header) (*apiAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s is unreachable", redactURL(u))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, na.MaxBody))
	ans := &apiAnswer{status: resp.StatusCode, body: b}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
			Kind  string `json:"kind"`
		}
		json.Unmarshal(b, &e)
		ans.kind, ans.text = e.Kind, clip(e.Error, 200)
	}
	return ans, nil
}

func redactURL(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "the cluster's endpoint"
	}
	return p.Scheme + "://" + p.Host + p.Path
}

// readCode reads the code from r (≤ 4 KiB, trimmed).
func readCode(r io.Reader) (servers.JoinCodeV2, error) {
	b, err := io.ReadAll(io.LimitReader(r, servers.MaxJoinCodeV2+2))
	if err != nil {
		return servers.JoinCodeV2{}, errors.New("the join code couldn't be read from stdin")
	}
	return servers.DecodeJoinCodeV2(strings.TrimSpace(string(b)))
}

// Join joins this machine to the cluster with the code read from stdin.
// Progress goes to out; nothing secret goes to out, the log or an error.
func (a *Agent) Join(ctx context.Context, stdin io.Reader, out io.Writer, d JoinDeps) error {
	if d.Retry == 0 {
		d.Retry = 5 * time.Second
	}
	if d.MeshPendingFor == 0 {
		d.MeshPendingFor = 10 * time.Minute
	}
	if d.AdmissionFor == 0 {
		d.AdmissionFor = 30 * time.Minute
	}
	if d.ServersFor == 0 {
		d.ServersFor = 5 * time.Minute
	}
	if d.RTT == nil {
		d.RTT = a.measure
	}
	if d.Install == nil {
		d.Install = func(ctx context.Context, j K3sJoin) error { return a.installK3s(ctx, d.HTTP, out, j) }
	}
	code, err := readCode(stdin)
	if err != nil {
		return err
	}
	say := func(f string, args ...any) { fmt.Fprintf(out, f+"\n", args...) }
	if a.fs.exists(stateFile) {
		if a.k3sState(ctx) != "absent" {
			return errors.New("this machine is already a cluster node (k3s is installed): remove it from the cluster first")
		}
		say("An earlier join didn't finish: its nodeagent state goes first.")
		a.cfg.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"disable", "--now", UnitName}})
		a.removeMesh(ctx)
		a.fs.removeAll(StateDir)
	}

	// 1. The host checks.
	say("Checking this machine...")
	checks := a.HostChecks(ctx)
	var blockers []string
	for _, c := range checks.Checks {
		switch {
		case c.OK:
		case joinBlockers[c.ID]:
			blockers = append(blockers, c.ID+": "+c.Detail)
			say("  FAIL %s: %s", c.ID, c.Detail)
		default:
			say("  warn %s: %s", c.ID, c.Detail)
		}
	}
	if len(blockers) > 0 {
		return fmt.Errorf("this machine can't join: %s", strings.Join(blockers, "; "))
	}

	// 2. Keys, generated here: the node-cluster key and the pcmesh key.
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cn := code.ServerID + "." + clusterDomain
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, nodeKey)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csr, _ := x509.ParseCertificateRequest(csrDER)
	meshKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	lan, public := a.reportAddrs()

	// 3. The nonce and the enrolment.
	ep := strings.TrimSuffix(code.Endpoint, "/")
	nb, _ := json.Marshal(map[string]string{"server_id": code.ServerID})
	ans, err := a.call(ctx, d, http.MethodPost, ep+"/v1/nonce", nb, nil)
	if err != nil {
		return err
	}
	if ans.status != http.StatusOK {
		return fmt.Errorf("the cluster answered %d to the nonce: %s", ans.status, ans.text)
	}
	var nr struct {
		Nonce string `json:"nonce"`
	}
	if err := jsonstrict.Decode(ans.body, &nr); err != nil {
		return errors.New("the cluster's nonce answer is unreadable")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nr.Nonce)
	if err != nil || len(nonce) != 32 {
		return errors.New("the cluster's nonce is malformed")
	}
	proof := ProofFor(code.SecretBytes(), nonce, code.ServerID, csr.RawSubjectPublicKeyInfo)
	type report struct {
		Pub    string  `json:"pub"`
		LAN    *string `json:"lan"`
		Public *string `json:"public"`
	}
	eb, _ := json.Marshal(struct {
		ServerID string `json:"server_id"`
		Nonce    string `json:"nonce"`
		Proof    string `json:"proof"`
		CSR      string `json:"csr"`
		Mesh     report `json:"mesh"`
	}{code.ServerID, nr.Nonce, base64.RawURLEncoding.EncodeToString(proof), string(csrPEM),
		report{meshKey.PublicKey().String(), lan, public}})
	say("Enrolling %s...", code.ServerID)
	ans, err = a.call(ctx, d, http.MethodPost, ep+"/v1/enrol", eb, nil)
	if err != nil {
		return err
	}
	if ans.status == http.StatusForbidden {
		return ErrCodeRefused
	}
	if ans.status != http.StatusOK {
		return fmt.Errorf("the enrolment failed (%d): %s", ans.status, ans.text)
	}
	var er struct {
		Certificate string      `json:"certificate"`
		CA          string      `json:"ca"`
		NotAfter    string      `json:"not_after"`
		Mesh        na.MeshPlan `json:"mesh"`
	}
	if err := jsonstrict.Decode(ans.body, &er); err != nil {
		return errors.New("the enrolment answer is unreadable")
	}
	ca, err := parseCertPEM([]byte(er.CA))
	if err != nil || pkinode.DERSHA256(ca.Raw) != code.CASHA256 {
		return ErrCAMismatch
	}
	leaf, err := parseCertPEM([]byte(er.Certificate))
	if err != nil {
		return errors.New("the enrolment answer's certificate is unreadable")
	}
	if err := checkNodeLeafSkew(leaf, ca, cn, csr.RawSubjectPublicKeyInfo, a.cfg.Now()); err != nil {
		return errors.New("the enrolment answer's certificate isn't this node's, from the cluster's CA")
	}
	if err := validatePlan(er.Mesh, meshKey.PublicKey().String()); err != nil {
		return fmt.Errorf("the bootstrap mesh plan is refused: %v", err)
	}

	// 4. The state (keys 0600 in 0700 directories).
	st := State{V: 1, ID: code.ServerID, MeshIP: code.MeshIP, Role: code.Role, Site: code.Site, Class: code.Class,
		Endpoint: ep, Servers: code.Servers}
	sb, _ := json.Marshal(st)
	for _, f := range []struct {
		path string
		data []byte
		mode uint32
	}{
		{nodePEMFile, nodeBundle(nodeKey, []byte(er.Certificate)), 0o600},
		{caFile, []byte(er.CA), 0o600},
		{MeshKeyFile, []byte(meshKey.String() + "\n"), 0o600},
		{stateFile, sb, 0o600},
	} {
		if err := a.fs.write(f.path, f.data, osMode(f.mode), 0o700); err != nil {
			return err
		}
	}
	if err := a.Load(); err != nil {
		return err
	}
	say("Enrolled: certificate for %s until %s.", cn, er.NotAfter)

	// 5. pcmesh with the bootstrap plan, and the nodeagent service.
	if err := a.ensureLink(ctx, st.MeshIP); err != nil {
		return err
	}
	if err := a.ApplyMesh(ctx, er.Mesh); err != nil {
		return fmt.Errorf("the bootstrap mesh plan: %v", err)
	}
	say("Node mesh %s up: %s/24.", na.MeshIface, st.MeshIP)
	if err := a.installUnit(ctx, st.Role); err != nil {
		return err
	}
	say("The nodeagent service runs (%s).", UnitName)
	// From here a failed join stops the service and takes pcmesh down (the
	// next join removes the rest).
	installed := false
	defer func() {
		if !installed {
			cctx := context.WithoutCancel(ctx)
			a.cfg.Run.Run(cctx, Cmd{Name: "systemctl", Args: []string{"disable", "--now", UnitName}})
			a.removeMesh(cctx)
		}
	}()

	// 6. The RTT to every server, then the signed join, retried.
	signer := joinSigner{key: nodeKey, cert: leaf.Raw, id: st.ID, now: a.cfg.Now}
	var answer joinAnswer
	rtt, err := a.serverRTT(ctx, d, st.Servers, say)
	if err != nil {
		return err
	}
	start := a.cfg.Now()
	for {
		body, _ := json.Marshal(struct {
			ServerID string         `json:"server_id"`
			RTTms    map[string]int `json:"rtt_ms"`
		}{st.ID, rtt})
		hdr, err := signer.headers(http.MethodPost, ep+"/v1/join", body)
		if err != nil {
			return err
		}
		ans, err = a.call(ctx, d, http.MethodPost, ep+"/v1/join", body, hdr)
		if err == nil && ans.status == http.StatusOK {
			if err := jsonstrict.Decode(ans.body, &answer); err != nil {
				if strings.Contains(err.Error(), `"cluster_cidr"`) {
					return errors.New("the join answer has no cluster_cidr: nothing was installed")
				}
				return errors.New("the join answer is unreadable: nothing was installed")
			}
			break
		}
		waited := a.cfg.Now().Sub(start)
		switch {
		case err != nil || ans.status == http.StatusTooManyRequests || ans.status >= 500:
			if waited > d.AdmissionFor {
				if err != nil {
					return err
				}
				return fmt.Errorf("the join failed (%d): %s", ans.status, ans.text)
			}
		case ans.status == http.StatusConflict && ans.kind == "mesh_pending":
			if waited > d.MeshPendingFor {
				return fmt.Errorf("the join failed: %s", ans.text)
			}
		case ans.status == http.StatusConflict && ans.kind == "waiting_admission":
			if waited > d.AdmissionFor {
				return fmt.Errorf("the join failed: %s", ans.text)
			}
		case ans.status == http.StatusForbidden:
			return errors.New("the join was refused: the cluster doesn't accept this node's signature")
		default:
			return fmt.Errorf("the join failed: %s", ans.text)
		}
		if ans != nil && ans.text != "" {
			say("Waiting: %s", ans.text)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d.Retry):
		}
		if ans != nil && ans.kind == "mesh_pending" {
			if r, err := a.serverRTT(ctx, d, st.Servers, func(string, ...any) {}); err == nil {
				rtt = r
			}
		}
	}
	tok := secret(answer.Token)
	answer.Token = ""
	if !K10Re.MatchString(string(tok)) {
		return errors.New("the join answer's token isn't in k3s's CA-pinned form (K10…): nothing was installed")
	}
	cidr, err := netip.ParsePrefix(answer.ClusterCIDR)
	if err != nil || !cidr.Addr().Is4() || cidr.Masked() != cidr || cidr.String() != answer.ClusterCIDR || cidr.Bits() < 8 || cidr.Bits() > 24 || cidr.Overlaps(meshPrefix) {
		return errors.New("the join answer's cluster_cidr isn't an IPv4 network: nothing was installed")
	}
	if answer.Role != st.Role {
		return errors.New("the join answer's role isn't the join code's: nothing was installed")
	}
	if err := checkServerURL(answer.ServerURL, st.Servers); err != nil {
		return err
	}
	if err := checkFlags(answer.Flags, answer.ServerURL, st, answer.ClusterCIDR); err != nil {
		return err
	}

	// 7. k3s.
	say("Installing k3s %s as a%s %s...", K3sVersion, map[bool]string{true: "", false: "n"}[st.Role == "server"], st.Role)
	if err := d.Install(ctx, K3sJoin{Role: st.Role, ServerURL: answer.ServerURL, Token: tok,
		Flags: answer.Flags, ClusterCIDR: answer.ClusterCIDR}); err != nil {
		return err
	}
	installed = true
	say("k3s is installed: the Hub shows the node's progress.")
	a.log.Info("joined", "id", st.ID, "role", st.Role)
	return nil
}

func poolOf(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

// serverRTT waits until every server's echo answers (up to ServersFor)
// without a lost round in its figure, and returns the RTT map keyed by
// server id. A figure of the round timeout is lost rounds, not distance:
// right after the bootstrap plan a server may not hold this node's peer
// yet (the Hub pushes it), and its first echoes go unanswered (found
// live, Task 30: "too far for one cluster: 1000 ms" over a 1 ms link, a
// revoke). It is measured again; after ServersFor it is sent as it is.
func (a *Agent) serverRTT(ctx context.Context, d JoinDeps, srv []string, say func(string, ...any)) (map[string]int, error) {
	start := a.cfg.Now()
	for {
		rtt := d.RTT(ctx, srv)
		clean := true
		for _, v := range rtt {
			if v >= int(rttTimeout/time.Millisecond) {
				clean = false
			}
		}
		if len(rtt) >= len(srv) && clean {
			say("Mesh RTT to the servers: %v ms.", rtt)
			return rtt, nil
		}
		if a.cfg.Now().Sub(start) > d.ServersFor {
			// nodeadm names the missing server or the figure; send them.
			if len(rtt) >= len(srv) {
				say("The mesh round trips still lose echoes: %v ms.", rtt)
			} else {
				say("Not every server answers over the mesh yet: %d of %d.", len(rtt), len(srv))
			}
			return rtt, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(d.Retry):
		}
	}
}

type joinSigner struct {
	key  *ecdsa.PrivateKey
	cert []byte
	id   string
	now  func() time.Time
}

func (s joinSigner) headers(method, u string, body []byte) (http.Header, error) {
	p, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(n)
	tm := s.now().UTC().Format(time.RFC3339)
	digest := sha256.Sum256(CanonicalBytes(s.id, method, p.RequestURI(), tm, nonce, body))
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set("Portcullis-Node-Cert", base64.StdEncoding.EncodeToString(s.cert))
	h.Set("Portcullis-Node-Time", tm)
	h.Set("Portcullis-Node-Nonce", nonce)
	h.Set("Portcullis-Node-Signature", base64.RawURLEncoding.EncodeToString(sig))
	return h, nil
}

func checkServerURL(u string, srv []string) error {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Port() != "6443" || p.Path != "" || !meshAddrOK(p.Hostname()) {
		return errors.New("the join answer's server_url isn't https://<a server's mesh address>:6443: nothing was installed")
	}
	_ = srv // a server added since the code was made is fine: any mesh address
	return nil
}

// The join flags core added (nodeadm/flags.go, core 49b5697): exactly
// these values.
const (
	UnlabelledTaintFlag = "--node-taint=nodeadm.portcullis/unlabelled=true:NoSchedule"
	NoForceDetachFlag   = "--kube-controller-manager-arg=disable-force-detach-on-timeout=true"
)

// checkFlags is an allowlist (core's join flags, nodeadm/flags.go and the
// shared fixture k3s-server-flags.txt): each flag's name and value shape,
// never a token on argv, the node's own identity and mesh address, the
// answer's server. A refusal names the flag, never its value.
func checkFlags(flags []string, serverURL string, st State, clusterCIDR string) error {
	allowed := allowedFlags(serverURL, st, clusterCIDR)
	if len(flags) == 0 || len(flags) > 64 {
		return errors.New("the join answer has no k3s flags: nothing was installed")
	}
	seen := map[string]bool{}
	for _, f := range flags {
		name, _, _ := strings.Cut(f, "=")
		if !allowed[f] || seen[f] {
			return fmt.Errorf("the join answer's k3s flag %s is refused: nothing was installed", clip(name, 40))
		}
		seen[f] = true
	}
	// --bind-address too (core Task 28 fix round 2): without it k3s binds the
	// kubelet to 0.0.0.0, every interface, the public one included.
	for _, need := range []string{"--server=" + serverURL, "--token-file=" + K3sTokenFile, "--node-ip=" + st.MeshIP, "--node-name=" + st.ID, UnlabelledTaintFlag, "--bind-address=" + st.MeshIP} {
		if !seen[need] {
			name, _, _ := strings.Cut(need, "=")
			return fmt.Errorf("the join answer's k3s flags lack %s: nothing was installed", name)
		}
	}
	return nil
}

// allowedFlags is the allowlist for a node of st's role: every flag
// value it may take (core's join_flags_vectors.json holds nodeadm's list
// equal to it, TestJoinFlagsVectorsExact).
func allowedFlags(serverURL string, st State, clusterCIDR string) map[string]bool {
	ip := st.MeshIP
	exact := map[string]bool{
		"--server=" + serverURL: true, "--token-file=" + K3sTokenFile: true, "--node-name=" + st.ID: true,
		// The kubelet on the mesh address through k3s's --bind-address,
		// the address its agent tunnel dials (core Task 28 fix round 1);
		// --kubelet-arg=address= stays a server's (init's flags).
		"--node-ip=" + ip: true, "--bind-address=" + ip: true, "--kubelet-arg=pod-max-pids=1024": true,
		"--kubelet-arg=sync-frequency=10s": true, "--flannel-conf=" + FlannelConf: true, "--flannel-iface=pcmesh": true,
		// The registration taint (core ruling R-NODELABELS): no placement
		// label and no portcullis.io/ taint on the join's flags; nodeadm
		// labels the registered Node and lifts this taint.
		UnlabelledTaintFlag: true,
	}
	serverOnly := map[string]bool{
		"--secrets-encryption": true, "--disable=traefik": true, "--write-kubeconfig-mode=0600": true,
		"--flannel-backend=wireguard-native": true, "--advertise-address=" + ip: true, "--kubelet-arg=address=" + ip: true,
		"--etcd-arg=listen-client-urls=https://" + ip + ":2379,https://127.0.0.1:2379": true,
		"--etcd-arg=heartbeat-interval=200":                                            true, "--etcd-arg=election-timeout=2000": true,
		// Fencing unconfirmed → no stateful failover (core plan Task 24): no
		// volume leaves an unready node by timeout.
		NoForceDetachFlag: true,
		// The answer's cluster_cidr, the same one flannel's net-conf gets.
		"--cluster-cidr=" + clusterCIDR: clusterCIDR != "",
	}
	out := map[string]bool{}
	for f, ok := range exact {
		if ok {
			out[f] = true
		}
	}
	if st.Role == "server" {
		for f, ok := range serverOnly {
			if ok {
				out[f] = true
			}
		}
	}
	return out
}
