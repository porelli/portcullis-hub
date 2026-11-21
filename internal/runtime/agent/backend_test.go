package agent_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"github.com/portcullis/hub/internal/servers"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	wagent "github.com/portcullis/hub/internal/agent"
	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fixerspec"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/workertest"
)

// newWorker is the shared real-agent harness (internal/workertest) for
// these backend tests.
func newWorker(t *testing.T) *workertest.Worker {
	return workertest.NewWorker(t, workertest.Opts{BindRoots: []string{"/srv"}})
}

// dialTo dials addr whatever the address asked.
func dialTo(addr string) *workertest.Dialer { return workertest.DialerTo(addr) }

const compose = `services:
  web:
    image: ghcr.io/example/app:1
    volumes: ["data:/data"]
    labels:
      traefik.http.services.app.loadbalancer.server.port: "8080"
volumes:
  data: {}
`

func pushBundle(t *testing.T, b *agentrt.Backend) {
	files := fstest.MapFS{"compose.yml": {Data: []byte(compose), Mode: 0o644}, "env": {Data: []byte("A=1\n"), Mode: 0o600}}
	m := agentapi.BundleManifest{Instance: "app", Template: "app", Volumes: map[string]string{"data": "portcullis-app_data"}, Files: map[string]agentapi.FileEntry{}}
	for n, f := range files {
		s := sha256.Sum256(f.Data)
		m.Files[n] = agentapi.FileEntry{SHA256: hex.EncodeToString(s[:]), Mode: uint32(f.Mode), Size: int64(len(f.Data))}
	}
	if err := b.PushBundle(context.Background(), "app", files, m); err != nil {
		t.Fatalf("PushBundle: %v", err)
	}
}

func volTar(t *testing.T) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "data/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	tw.Write([]byte("hi"))
	tw.Close()
	return buf.Bytes()
}

// TestAgentBackendAgainstFakeAgent: every runtime.Instances method of the
// backend reaches the worker's engine through its route, end to end
// (pinned mTLS, the agent's scope checks, the wire types).
func TestAgentBackendAgainstFakeAgent(t *testing.T) {
	w := newWorker(t)
	// A route-coverage walk: the down keeps c1 for the calls after it.
	w.Engine.DownRemovesUnits = false
	b, d := w.Backend(nil)
	ctx := context.Background()
	pushBundle(t, b)
	if d.Asked() != "10.214.0.10:7443" {
		t.Errorf("dialed %q", d.Asked())
	}
	mine := map[string]string{docker.LabelProject: "portcullis-app", docker.LabelService: "web"}
	w.Engine.Units = []runtime.Unit{{ID: "c1", Project: "portcullis-app", Instance: "app", Service: "web", State: "running", Labels: mine}}
	w.Engine.Infos["c1"] = runtime.UnitInfo{ID: "c1", Labels: mine, Image: "sha256:x"}
	w.Engine.LogsVal["c1"] = []byte("log line\n")
	w.Engine.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	w.Engine.Contents["portcullis-app_data"] = volTar(t)
	p := runtime.Project{Name: "portcullis-app", Instance: "app"}
	check := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	info, err := b.Info(ctx)
	check("Info", err)
	if info.Kind != runtime.KindDocker || !info.SELinux || len(info.ForbiddenRoots) != 1 || info.ForbiddenRoots[0] != "/var/lib/docker" || info.APIVersion != "1.45" {
		t.Errorf("info %+v", info)
	}
	check("Create", b.Create(ctx, p))
	var pulled int
	check("Up", b.Up(ctx, p, func(string, int64, int64, bool) { pulled++ }))
	check("Down", b.Down(ctx, p))
	check("DownByName", b.DownByName(ctx, "portcullis-app"))
	check("Pull", b.Pull(ctx, "ghcr.io/example/app:1", nil))
	check("EnsureImage", b.EnsureImage(ctx, "ghcr.io/example/app:1"))
	us, err := b.List(ctx, runtime.Filter{Instance: "app"})
	check("List", err)
	if len(us) != 1 || us[0].ID != "c1" {
		t.Errorf("units %+v", us)
	}
	ui, err := b.Inspect(ctx, "c1")
	check("Inspect", err)
	if ui.Image != "sha256:x" {
		t.Errorf("inspect %+v", ui)
	}
	logs, err := b.Logs(ctx, "c1", 10, true)
	check("Logs", err)
	if string(logs) != "log line\n" {
		t.Errorf("logs %q", logs)
	}
	_, err = b.Exec(ctx, "c1", runtime.ExecInput{Cmd: []string{"id"}, Timeout: time.Second})
	check("Exec", err)
	_, err = b.ExecSplit(ctx, "c1", runtime.ExecInput{Cmd: []string{"id"}, Timeout: time.Second})
	check("ExecSplit", err)
	if _, err := b.ExecRunning(ctx, "never-started"); err == nil {
		t.Error("ExecRunning of a foreign exec answered")
	}
	check("Signal", b.Signal(ctx, "c1", "HUP"))
	_, err = b.State(ctx, "c1")
	check("State", err)
	ectx, cancel := context.WithTimeout(ctx, 2*time.Second)
	b.Events(ectx, runtime.Filter{}, func(runtime.Event) {})
	cancel()
	vs, err := b.ListVolumes(ctx, runtime.Filter{})
	check("ListVolumes", err)
	if len(vs) != 1 {
		t.Errorf("volumes %+v", vs)
	}
	_, err = b.InspectVolume(ctx, "portcullis-app_data")
	check("InspectVolume", err)
	rc, err := b.VolumeOut(ctx, "app", "portcullis-app_data", "/data")
	check("VolumeOut", err)
	if rc != nil {
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, volTar(t)) {
			t.Errorf("VolumeOut %d bytes", len(got))
		}
	}
	check("VolumeIn", b.VolumeIn(ctx, "app", "portcullis-app_data", "/data", bytes.NewReader(volTar(t))))
	check("CreateVolume", b.CreateVolume(ctx, runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}))
	check("RemoveVolume", b.RemoveVolume(ctx, "portcullis-app_data"))
	spec := fixerspec.Run{Mode: "scan", Source: "/srv/photos"}.Spec("sha256:hub", wagent.AgentBinary)
	_, err = b.RunFixer(ctx, spec, nil)
	check("RunFixer", err)
	if err := b.RemoveHelper(ctx, "nope"); err == nil || !docker.IsNotFound(err) {
		t.Errorf("RemoveHelper of nothing: %v (want a not-found)", err)
	}
	check("DeliverFile", b.DeliverFile(ctx, "app", runtime.FileDelivery{Name: "settings", Data: []byte("{}")}))
	// A settings secrets file is primary-only (contract §17.4): the agent's 400.
	if err := b.DeliverFile(ctx, "app", runtime.FileDelivery{Name: "settings", Data: []byte("{}"), Secrets: []byte("{}")}); err == nil || !strings.Contains(err.Error(), "primary-only") {
		t.Errorf("a secrets file delivered: %v", err)
	}
	calls := strings.Join(w.Engine.Calls(), "\n")
	for _, want := range []string{"create portcullis-app", "up portcullis-app", "down portcullis-app", "down-by-name portcullis-app", "pull ghcr.io/example/app:1",
		"ensure-image ghcr.io/example/app:1", "exec c1", "exec-split c1", "signal c1 HUP", "fixer [" + wagent.AgentBinary + " folderfix scan"} {
		if !strings.Contains(calls, want) {
			t.Errorf("the engine never got %q:\n%s", want, calls)
		}
	}
	if _, err := os.Stat(filepath.Join(w.DataDir, "appfiles", "app", "settings", "settings.json")); err != nil {
		t.Errorf("delivered file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.DataDir, "appfiles", "app", "settings", "settings.secrets.json")); err == nil {
		t.Error("a secrets file reached the worker")
	}
	// Refusals come back with the agent's status.
	err = b.Create(ctx, runtime.Project{Name: "portcullis-other", Instance: "other"})
	var ae *agentrt.Error
	if !errors.As(err, &ae) || ae.Status != http.StatusNotFound {
		t.Errorf("an unbundled project: %v", err)
	}
	if err := b.DownByName(ctx, "portcullis"); err == nil {
		t.Error("core's project name accepted")
	}
}

// TestIdentityMismatch: a worker presenting another certificate than the
// pinned one (another server's, a renewed serial not in state, another
// CA) is refused before any request, and OnMismatch fires.
func TestIdentityMismatch(t *testing.T) {
	w := newWorker(t)
	other := newWorker(t)
	for name, mut := range map[string]func(*agentrt.Config){
		"another serial":     func(c *agentrt.Config) { c.Serial = "01" },
		"another SPKI":       func(c *agentrt.Config) { c.SPKI = make([]byte, 32) },
		"another server id":  func(c *agentrt.Config) { c.ServerID = "nas2" },
		"another server's":   func(c *agentrt.Config) { c.Dial = dialTo(other.Server.Listener.Addr().String()) },
		"another CA trusted": func(c *agentrt.Config) { c.CACert = other.CA.Cert },
	} {
		mismatch := false
		b, _ := w.Backend(func(c *agentrt.Config) { mut(c); c.OnMismatch = func() { mismatch = true } })
		_, err := b.AgentInfo(context.Background())
		var ae *agentrt.Error
		if err == nil || !errors.As(err, &ae) || ae.Status != http.StatusBadGateway {
			t.Errorf("%s: %v", name, err)
		}
		if (name == "another serial" || name == "another SPKI") && (!mismatch || !errors.Is(err, agentrt.ErrIdentityMismatch)) {
			t.Errorf("%s: mismatch %v err %v", name, mismatch, err)
		}
	}
	b, _ := w.Backend(nil)
	if _, err := b.AgentInfo(context.Background()); err != nil {
		t.Errorf("the pinned identity: %v", err)
	}
}

// TestOversizedInfoCut: an /v1/info over 64 KiB is an error, never a
// partial decode; a JSON answer with an unknown key is refused too.
func TestOversizedInfoCut(t *testing.T) {
	w := newWorker(t)
	for name, body := range map[string]string{
		"oversized":   `{"agent_version":"` + strings.Repeat("x", agentapi.MaxInfo) + `"}`,
		"unknown key": `{"agent_version":"1.0.0","api":"v1","runtime":"docker","arch":"amd64","engine_version":"x","cpus":1,"mem_bytes":1,"docker_root_dir":"/","disk_total":0,"disk_free":0,"data_dir":"/d","data_total":0,"data_free":0,"unprivileged_port_start":1024,"clock":"2026-11-15T00:00:00Z","evil":1}`,
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { io.WriteString(rw, body) }),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{serverCert(t, w)}, ClientAuth: tls.RequireAnyClientCert}}
		go srv.ServeTLS(ln, "", "")
		b, _ := w.Backend(func(c *agentrt.Config) { c.Dial = dialTo(ln.Addr().String()) })
		if _, err := b.AgentInfo(context.Background()); err == nil {
			t.Errorf("%s: decoded", name)
		}
		srv.Close()
	}
}

func serverCert(t *testing.T, w *workertest.Worker) tls.Certificate {
	key, _ := os.ReadFile(filepath.Join(w.DataDir, "identity", "tls.key"))
	crt, _ := os.ReadFile(filepath.Join(w.DataDir, "identity", "tls.crt"))
	c, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAgentVersionGate: an agent outside {the Hub's minor, the one
// before} gets no call but /v1/info: 409 server_agent_incompatible.
func TestAgentVersionGate(t *testing.T) {
	w := newWorker(t)
	ctx := context.Background()
	for hub, ok := range map[string]bool{wagent.Version: true, "0.2.0": true, "0.3.0": false, "1.1.0": false, "edge": false} {
		b, _ := w.Backend(func(c *agentrt.Config) { c.HubVersion = hub })
		_, err := b.List(ctx, runtime.Filter{})
		var ae *agentrt.Error
		if ok && err != nil {
			t.Errorf("hub %s: %v", hub, err)
		}
		if !ok && (!errors.As(err, &ae) || ae.Status != http.StatusConflict || !errors.Is(err, agentrt.ErrIncompatible) || !strings.Contains(err.Error(), "server_agent_incompatible")) {
			t.Errorf("hub %s (agent %s): %v", hub, wagent.Version, err)
		}
		if _, err := b.AgentInfo(ctx); err != nil {
			t.Errorf("hub %s: /v1/info refused: %v", hub, err)
		}
	}
}

// TestAgentStatusPolicy (commit review): a worker's status passes only
// when it is 400/404/409/422/503 (message sanitized, capped); anything
// else is 502 "the server <id> answered unexpectedly".
func TestAgentStatusPolicy(t *testing.T) {
	w := newWorker(t)
	for _, c := range []struct {
		status int
		body   string
		want   int
		msg    string
	}{
		{401, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{302, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{999, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{500, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{403, `{"error":"x"}`, 502, "the server nas answered unexpectedly"},
		{409, `{"error":"in use\u001b[31m now"}`, 409, "in use [31m now"},
		{503, `not json`, 503, "the server nas refused the call"},
		{404, `{"error":"` + strings.Repeat("y", 500) + `"}`, 404, ""},
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		info := `{"agent_version":"` + wagent.Version + `","api":"v1","runtime":"docker","arch":"amd64","engine_version":"x","cpus":1,"mem_bytes":1,"docker_root_dir":"/","disk_total":0,"disk_free":0,"data_dir":"/d","data_total":0,"data_free":0,"unprivileged_port_start":1024,"clock":"2026-11-15T00:00:00Z"}`
		srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/info" {
				io.WriteString(rw, info)
				return
			}
			rw.WriteHeader(c.status)
			io.WriteString(rw, c.body)
		}), TLSConfig: &tls.Config{Certificates: []tls.Certificate{serverCert(t, w)}, ClientAuth: tls.RequireAnyClientCert}}
		go srv.ServeTLS(ln, "", "")
		b, _ := w.Backend(func(cfg *agentrt.Config) { cfg.Dial = dialTo(ln.Addr().String()) })
		err := b.Down(context.Background(), runtime.Project{Instance: "app"})
		var ae *agentrt.Error
		if !errors.As(err, &ae) || ae.Status != c.want || (c.msg != "" && ae.Msg != c.msg) || len([]rune(ae.Msg)) > 200 {
			t.Errorf("%d: %v (%+v)", c.status, err, ae)
		}
		srv.Close()
	}
}

// TestHelperCleanupBounded (review B-L6): a worker that never answers a
// helper's removal can't hold the Hub: deleteHelper ends at its timeout.
func TestHelperCleanupBounded(t *testing.T) {
	w := newWorker(t)
	block := make(chan struct{})
	defer close(block)
	orig := w.Server.Config.Handler
	w.Server.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/helpers/") {
			select {
			case <-block:
			case <-r.Context().Done():
			}
			return
		}
		orig.ServeHTTP(rw, r)
	})
	old := agentrt.HelperCleanupTimeout
	agentrt.HelperCleanupTimeout = 200 * time.Millisecond
	defer func() { agentrt.HelperCleanupTimeout = old }()
	b, _ := w.Backend(nil)
	start := time.Now()
	b.DeleteHelperForTest("h1")
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("deleteHelper took %s", d)
	}
}

// TestEnrollingPeerSPKIIsTheDER: in enrolling mode PeerSPKI is the DER
// SubjectPublicKeyInfo of the worker's certificate, the value the agent
// binds into the proof (internal/agent/enrol.go): a proof the Hub makes
// with it verifies the agent's way (CI e2e-servers: a hash here made every
// enrolment fail "the worker refused the enrolment proof").
func TestEnrollingPeerSPKIIsTheDER(t *testing.T) {
	w := newWorker(t)
	b, _ := w.Backend(func(c *agentrt.Config) { c.Enrolling = true })
	b.AgentInfo(context.Background())
	got := b.PeerSPKI()
	if !bytes.Equal(got, w.Node.RawSubjectPublicKeyInfo) {
		t.Fatalf("PeerSPKI is %d bytes, not the certificate's DER SPKI (%d bytes)", len(got), len(w.Node.RawSubjectPublicKeyInfo))
	}
	secret, nonce := bytes.Repeat([]byte{7}, servers.SecretLen), bytes.Repeat([]byte{9}, servers.NonceLen)
	if !servers.VerifyProof(secret, nonce, "nas", w.Node.RawSubjectPublicKeyInfo, servers.Proof(secret, nonce, "nas", got)) {
		t.Fatal("the Hub's proof doesn't verify the agent's way")
	}
}

// TestPreflightPullOverTheWire: the placement pre-pull against the real
// agent API with no bundle: a pinned ref pulls, an unpinned one is the
// agent's 400, and a plain Pull of the same ref is refused (imageOK).
func TestPreflightPullOverTheWire(t *testing.T) {
	w := newWorker(t)
	b, _ := w.Backend(nil)
	ref := "docker.io/library/busybox:1@sha256:" + strings.Repeat("e", 64)
	if err := b.Pull(context.Background(), ref, nil); err == nil {
		t.Fatal("a plain pull without a bundle was accepted")
	}
	if err := b.PreflightPull(context.Background(), ref); err != nil {
		t.Fatalf("PreflightPull: %v", err)
	}
	if !slices.Contains(w.Engine.Calls(), "pull "+ref) {
		t.Errorf("the engine never pulled %s: %v", ref, w.Engine.Calls())
	}
	if err := b.PreflightPull(context.Background(), "docker.io/library/busybox:1"); err == nil || !strings.Contains(err.Error(), "pinned by digest") {
		t.Errorf("an unpinned preflight: %v", err)
	}
}

// TestDownOfUnbundledProject (security reviews): over the wire, a down of
// a project the agent once held (bundle removed: a tombstone) is done only
// on the agent's 204; a leftover container that stays is its 409, an error
// the Hub never reads as "down"; an id it never held is a 404 error.
func TestDownOfUnbundledProject(t *testing.T) {
	w := newWorker(t)
	b, _ := w.Backend(nil)
	pushBundle(t, b)
	if err := b.RemoveProject(context.Background(), "app"); err != nil {
		t.Fatal(err)
	}
	p := runtime.Project{Name: "portcullis-app", Instance: "app"}
	if err := b.Down(context.Background(), p); err != nil {
		t.Fatalf("down with nothing there: %v", err)
	}
	w.Engine.Lock()
	w.Engine.DownRemovesUnits = false // a container the engine's down can't remove
	w.Engine.Units = append(w.Engine.Units, runtime.Unit{ID: "c9", Project: "portcullis-app", Instance: "app", State: "running"})
	w.Engine.Unlock()
	var ae *agentrt.Error
	if err := b.Down(context.Background(), p); !errors.As(err, &ae) || ae.Status != http.StatusConflict || !strings.Contains(ae.Msg, "still running") {
		t.Errorf("down with a leftover that stays: %v", err)
	}
	if err := b.Down(context.Background(), runtime.Project{Name: "portcullis-stranger", Instance: "stranger"}); !errors.As(err, &ae) || ae.Status != http.StatusNotFound {
		t.Errorf("down of an id the agent never held: %v", err)
	}
}

// TestCreateVolumeRefusalIs409 (seen live: a move back onto a worker that
// still held the previous copy failed as "answered unexpectedly"): the
// agent's 403 for a volume in no bundle's manifest is a clear 409 naming
// the server and the volume.
func TestCreateVolumeRefusalIs409(t *testing.T) {
	w := newWorker(t)
	b, _ := w.Backend(nil)
	err := b.CreateVolume(context.Background(), runtime.Volume{Name: "portcullis_se1-marker", Labels: map[string]string{docker.LabelProject: "portcullis-se1"}})
	var ae *agentrt.Error
	if !errors.As(err, &ae) || ae.Status != http.StatusConflict ||
		ae.Msg != "the server nas refused to create volume portcullis_se1-marker: a previous copy may still be there" {
		t.Fatalf("%v", err)
	}
}

// TestBackendUsageRoutes: Stats, LayerSize, ImageSize and HostUsage reach
// the worker through their routes (contract §17.4, ux3), end to end.
func TestBackendUsageRoutes(t *testing.T) {
	w := workertest.NewWorker(t, workertest.Opts{BindRoots: []string{"/srv"}, ProcDir: "../../usage/testdata/proc", SysDir: "../../usage/testdata/sys"})
	b, _ := w.Backend(nil)
	pushBundle(t, b)
	lbl := map[string]string{docker.LabelProject: "portcullis-app", docker.LabelService: "web"}
	w.Engine.Infos["c1"] = runtime.UnitInfo{ID: "c1", Labels: lbl}
	cpu := uint64(7e9)
	read := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	w.Engine.SetStats("c1", runtime.UnitStats{Read: read, CPUUsageNS: &cpu})
	w.Engine.LayerSizes = map[string]int64{"c1": 4096}
	w.Engine.ImageSizes = map[string]int64{"ghcr.io/example/app:1": 1 << 20}
	ctx := context.Background()
	st, err := b.Stats(ctx, "c1")
	if err != nil || st.CPUUsageNS == nil || *st.CPUUsageNS != 7e9 || st.MemUsage != nil || !st.Read.Equal(read) {
		t.Errorf("Stats = %+v %v", st, err)
	}
	if n, err := b.LayerSize(ctx, "c1"); err != nil || n != 4096 {
		t.Errorf("LayerSize = %d %v", n, err)
	}
	if n, err := b.ImageSize(ctx, "ghcr.io/example/app:1"); err != nil || n != 1<<20 {
		t.Errorf("ImageSize = %d %v", n, err)
	}
	if _, err := b.ImageSize(ctx, "docker.io/library/busybox:latest"); err == nil || errors.Is(err, agentrt.ErrOlderAgent) {
		t.Errorf("ImageSize of an image in no bundle: %v", err)
	}
	// The worker's CPUs and memory (its /v1/info: the usage page's host).
	if i, err := b.Info(ctx); err != nil || i.CPUs != 4 || i.MemoryBytes != 8<<30 {
		t.Errorf("Info = %d CPUs %d bytes, %v", i.CPUs, i.MemoryBytes, err)
	}
	hc, err := b.HostUsage(ctx)
	if err != nil || hc.CPUTotal != 6485 || hc.MemTotal != 16384000*1024 || hc.DiskRead != 3017*512 {
		t.Errorf("HostUsage = %+v %v", hc, err)
	}
	// A container that is gone is not an older agent.
	if _, err := b.Stats(ctx, "c-gone"); err == nil || errors.Is(err, agentrt.ErrOlderAgent) {
		t.Errorf("Stats of a gone container: %v", err)
	}
}

// TestBackendStatsOldAgent: an agent without the usage routes answers its
// catch-all 404: the worker's agent is older than the Hub (never a guess).
func TestBackendStatsOldAgent(t *testing.T) {
	w := newWorker(t)
	b, _ := w.Backend(nil)
	w.Fail(`/stats$|/size$|/images/size$|/host/usage$`, -1, http.StatusNotFound, "not found")
	ctx := context.Background()
	check := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, agentrt.ErrOlderAgent) || err.Error() != "the worker's agent is older than the Hub" {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := b.Stats(ctx, "c1")
	check("Stats", err)
	_, err = b.LayerSize(ctx, "c1")
	check("LayerSize", err)
	_, err = b.ImageSize(ctx, "ghcr.io/example/app:1")
	check("ImageSize", err)
	_, err = b.HostUsage(ctx)
	check("HostUsage", err)
}

// TestAgentUsageStrictDecode: a worker's usage answers are untrusted: an
// unknown field, a null, a negative size or a body over MaxJSON is an
// error, never a partial figure.
func TestAgentUsageStrictDecode(t *testing.T) {
	w := newWorker(t)
	b, _ := w.Backend(nil)
	ctx := context.Background()
	for name, c := range map[string]struct {
		pattern string
		body    []byte
		call    func() error
	}{
		"stats unknown field": {`/stats$`, []byte(`{"read":"2026-11-21T10:00:00Z","cpu_usage_ns":1,"evil":1}`), func() error { _, err := b.Stats(ctx, "c1"); return err }},
		"stats null":          {`/stats$`, []byte(`{"read":"2026-11-21T10:00:00Z","cpu_usage_ns":null}`), func() error { _, err := b.Stats(ctx, "c1"); return err }},
		"stats no read":       {`/stats$`, []byte(`{"cpu_usage_ns":1}`), func() error { _, err := b.Stats(ctx, "c1"); return err }},
		"stats huge cpu rate": {`/stats$`, []byte(`{"read":"2026-11-21T10:00:00Z","cpu_cores":1e300}`), func() error { _, err := b.Stats(ctx, "c1"); return err }},
		"size unknown field":  {`/size$`, []byte(`{"bytes":1,"x":2}`), func() error { _, err := b.LayerSize(ctx, "c1"); return err }},
		"size negative":       {`/size$`, []byte(`{"bytes":-1}`), func() error { _, err := b.LayerSize(ctx, "c1"); return err }},
		"image size string":   {`/images/size$`, []byte(`{"bytes":"1"}`), func() error { _, err := b.ImageSize(ctx, "x"); return err }},
		"host unknown field": {`/host/usage$`, []byte(`{"at":"2026-11-21T10:00:00Z","cpu_total":1,"cpu_idle":0,"mem_total":1,"mem_available":0,"disk_read":0,"disk_write":0,"net":1}`),
			func() error { _, err := b.HostUsage(ctx); return err }},
		"host idle over total": {`/host/usage$`, []byte(`{"at":"2026-11-21T10:00:00Z","cpu_total":1,"cpu_idle":2,"mem_total":1,"mem_available":0,"disk_read":0,"disk_write":0}`),
			func() error { _, err := b.HostUsage(ctx); return err }},
		"host over the cap": {`/host/usage$`, append([]byte(`{"at":"2026-11-21T10:00:00Z","cpu_total":1,"cpu_idle":0,"mem_total":1,"mem_available":0,"disk_read":0,"disk_write":0}`), bytes.Repeat([]byte(" "), agentapi.MaxJSON)...),
			func() error { _, err := b.HostUsage(ctx); return err }},
	} {
		w.ClearFaults()
		w.Respond(c.pattern, 1, http.StatusOK, c.body)
		if err := c.call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
