package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fixerspec"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
)

// fakeNet is the engine's network side in memory.
type fakeNet struct {
	mu      sync.Mutex
	addrs   map[string]netip.Addr // container id → address on portcullis-proxy
	labels  map[string]map[string]string
	created []string
	joined  []string
	binds   []docker.PortBind
}

func (n *fakeNet) EnsureNetwork(_ context.Context, name string, subnet, ipRange netip.Prefix, internal bool, _ map[string]string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.created = append(n.created, name+" "+subnet.String()+" "+ipRange.String())
	return nil
}

func (n *fakeNet) ConnectNetwork(_ context.Context, net, c string, ip netip.Addr) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.joined = append(n.joined, net+" "+c+" "+ip.String())
	return nil
}

func (n *fakeNet) ContainerAddr(_ context.Context, id, _ string) (netip.Addr, map[string]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, ok := n.addrs[id]
	if !ok {
		return netip.Addr{}, nil, io.EOF
	}
	return a, n.labels[id], nil
}

func (n *fakeNet) PortBinds(context.Context) ([]docker.PortBind, error) { return n.binds, nil }

// eventsFake answers Events with canned events (runtimetest.Fake's don't
// reach the callback).
type eventsFake struct {
	*runtimetest.Fake
	evs []runtime.Event
}

func (e *eventsFake) Events(ctx context.Context, f runtime.Filter, fn func(runtime.Event)) error {
	for _, ev := range e.evs {
		fn(ev)
	}
	return nil
}

const testCompose = `services:
  web:
    image: ghcr.io/example/app:1
    networks: [portcullis-proxy, default]
    volumes:
      - data:/data
      - ./templates/app/app.conf:/etc/app.conf:ro
    labels:
      traefik.http.routers.app.rule: Host(` + "`app.example.org`" + `)
      traefik.http.services.app.loadbalancer.server.port: "8080"
networks:
  portcullis-proxy:
    external: true
volumes:
  data: {}
`

type bundleFile struct {
	name, data string
	mode       int64
	typ        byte
	link       string
}

// bundleTar is MANIFEST.json (for instance, with its volume names) then
// files; the manifest lists every regular file.
func bundleTar(t *testing.T, instance string, vols map[string]string, files []bundleFile) []byte {
	t.Helper()
	m := agentapi.BundleManifest{Instance: instance, Template: instance, Volumes: vols, Files: map[string]agentapi.FileEntry{}}
	for _, f := range files {
		if f.typ == 0 || f.typ == tar.TypeReg {
			sum := sha256.Sum256([]byte(f.data))
			mode := f.mode
			if mode == 0 {
				mode = 0o644
			}
			m.Files[f.name] = agentapi.FileEntry{SHA256: hex.EncodeToString(sum[:]), Mode: uint32(mode), Size: int64(len(f.data))}
		}
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := agentapi.WriteManifest(tw, m); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: f.name, Typeflag: typ, Mode: mode, Linkname: f.link, Format: tar.FormatPAX}
		if typ == tar.TypeReg {
			h.Size = int64(len(f.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(f.data))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func appBundle(t *testing.T, instance string, extra ...bundleFile) []byte {
	files := append([]bundleFile{{name: BundleCompose, data: testCompose}, {name: BundleEnv, data: "A=1\n", mode: 0o600},
		{name: "templates/app/app.conf", data: "x=1\n"}}, extra...)
	return bundleTar(t, instance, map[string]string{"data": "portcullis-" + instance + "_data"}, files)
}

type apiFixture struct {
	api  *API
	rt   *eventsFake
	net  *fakeNet
	data string
	srv  *httptest.Server
}

func newAPI(t *testing.T) *apiFixture {
	t.Helper()
	data := t.TempDir()
	rt := &eventsFake{Fake: &runtimetest.Fake{Infos: map[string]runtime.UnitInfo{}, Volumes: map[string]runtime.Volume{}, LogsVal: map[string][]byte{}, States: map[string]runtime.State{}}}
	n := &fakeNet{addrs: map[string]netip.Addr{}, labels: map[string]map[string]string{}}
	api := NewAPI(APIConfig{DataDir: data, BindRoots: []string{"/srv"}, Runtime: rt, Net: n, SelfImage: "sha256:agent", HelperImage: "docker.io/library/alpine:3@sha256:" + strings.Repeat("a", 64)})
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return &apiFixture{api: api, rt: rt, net: n, data: data, srv: srv}
}

func (f *apiFixture) req(t *testing.T, method, path string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	r, _ := http.NewRequest(method, f.srv.URL+path, body)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func (f *apiFixture) code(t *testing.T, method, path string, body any) int {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	resp, out := f.req(t, method, path, rd)
	if resp.StatusCode >= 300 {
		t.Logf("%s %s: %d %s", method, path, resp.StatusCode, out)
	}
	return resp.StatusCode
}

func (f *apiFixture) bundle(t *testing.T, id string) {
	t.Helper()
	if c := f.code(t, "PUT", "/v1/projects/"+id+"/bundle", appBundle(t, id)); c != 204 {
		t.Fatalf("bundle %s: %d", id, c)
	}
}

// TestScopeTable: one case per row of the scope column (contract §17.4),
// each refused, with its in-scope twin allowed.
func TestScopeTable(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	mine := map[string]string{docker.LabelProject: "portcullis-app", docker.LabelService: "web"}
	theirs := map[string]string{docker.LabelProject: "portcullis-other"}
	f.rt.Units = []runtime.Unit{{ID: "c-mine", Labels: mine, Project: "portcullis-app", Instance: "app", Service: "web", State: "running"}, {ID: "c-theirs", Labels: theirs, Project: "portcullis-other"}, {ID: "c-core", Labels: map[string]string{docker.LabelProject: "portcullis"}, Project: "portcullis"}}
	f.rt.Infos["c-mine"] = runtime.UnitInfo{ID: "c-mine", Labels: mine}
	f.rt.Infos["c-theirs"] = runtime.UnitInfo{ID: "c-theirs", Labels: theirs}
	f.rt.Infos["c-core"] = runtime.UnitInfo{ID: "c-core", Labels: map[string]string{docker.LabelProject: "portcullis"}}
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	f.rt.Volumes["portcullis-other_data"] = runtime.Volume{Name: "portcullis-other_data", Labels: map[string]string{docker.LabelProject: "portcullis-other"}}
	f.rt.Volumes["portcullis_vault_data"] = runtime.Volume{Name: "portcullis_vault_data"}
	fix := fixerspec.Run{Mode: "scan", Source: "/srv/photos"}
	fixOK := agentapi.FixerSpecOf(fix.Spec("", AgentBinary))
	fixOut := agentapi.FixerSpecOf(fixerspec.Run{Mode: "scan", Source: "/etc"}.Spec("", AgentBinary))
	fixBad := fixOK
	fixBad.CapAdd = append([]string{"SYS_ADMIN"}, fixBad.CapAdd...)
	img := "ghcr.io/example/app:1"
	for _, c := range []struct {
		name         string
		method, path string
		body         any
		want         int
	}{
		{"foreign project up", "POST", "/v1/projects/other/up", nil, 404},
		{"own project create", "POST", "/v1/projects/app/create", nil, 204},
		{"invalid project id", "POST", "/v1/projects/App/down", nil, 404},
		{"foreign container", "GET", "/v1/containers/c-theirs", nil, 403},
		{"core container", "POST", "/v1/containers/c-core/exec", agentapi.ExecRequest{Cmd: []string{"id"}}, 403},
		{"own container", "GET", "/v1/containers/c-mine", nil, 200},
		{"own container state", "GET", "/v1/containers/c-mine/state", nil, 200},
		{"own exec", "POST", "/v1/containers/c-mine/exec", agentapi.ExecRequest{Cmd: []string{"id"}}, 200},
		{"bad signal", "POST", "/v1/containers/c-mine/kill", agentapi.SignalRequest{Signal: "KILL"}, 400},
		{"own signal", "POST", "/v1/containers/c-mine/kill", agentapi.SignalRequest{Signal: "HUP"}, 204},
		{"unknown exec id", "GET", "/v1/execs/abc", nil, 403},
		{"foreign volume", "GET", "/v1/volumes/portcullis-other_data", nil, 403},
		{"core volume", "DELETE", "/v1/volumes/portcullis_vault_data", nil, 403},
		{"own volume", "GET", "/v1/volumes/portcullis-app_data", nil, 200},
		{"unlisted image", "POST", "/v1/images/pull", agentapi.RefRequest{Ref: "docker.io/library/busybox:latest"}, 403},
		{"listed image", "POST", "/v1/images/ensure", agentapi.RefRequest{Ref: img}, 204},
		{"helper image", "POST", "/v1/images/ensure", agentapi.RefRequest{Ref: f.api.cfg.HelperImage}, 204},
		{"non-fixed helper", "POST", "/v1/helpers", agentapi.HelperSpec{Kind: agentapi.HelperFolderFix, Spec: &fixBad}, 403},
		{"fixer outside roots", "POST", "/v1/helpers", agentapi.HelperSpec{Kind: agentapi.HelperFolderFix, Spec: &fixOut}, 403},
		{"fixed helper", "POST", "/v1/helpers", agentapi.HelperSpec{Kind: agentapi.HelperFolderFix, Spec: &fixOK}, 200},
		{"volume helper on a foreign volume", "POST", "/v1/helpers", agentapi.HelperSpec{Kind: agentapi.HelperVolumeIO, Instance: "app", Volume: "portcullis-other_data", Path: "/data"}, 403},
		{"volume helper of an unbundled instance", "POST", "/v1/helpers", agentapi.HelperSpec{Kind: agentapi.HelperVolumeIO, Instance: "other", Volume: "portcullis-other_data", Path: "/data"}, 403},
		{"own volume helper", "POST", "/v1/helpers", agentapi.HelperSpec{Kind: agentapi.HelperVolumeIO, Instance: "app", Volume: "portcullis-app_data", Path: "/data"}, 200},
		{"create a volume in no manifest", "POST", "/v1/volumes", agentapi.Volume{Name: "portcullis-other_data", Labels: map[string]string{docker.LabelProject: "portcullis-other"}}, 403},
		{"create a manifest volume without labels", "POST", "/v1/volumes", agentapi.Volume{Name: "portcullis-app_data"}, 403},
		{"create a manifest volume", "POST", "/v1/volumes", agentapi.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}, 204},
		{"remove a project with containers", "DELETE", "/v1/projects/app", nil, 409},
	} {
		if got := f.code(t, c.method, c.path, c.body); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	// List shows only the bundled project's units.
	resp, b := f.req(t, "GET", "/v1/containers?all=1", nil)
	var units []agentapi.Unit
	json.Unmarshal(b, &units)
	if resp.StatusCode != 200 || len(units) != 1 || units[0].ID != "c-mine" {
		t.Errorf("list: %d %s", resp.StatusCode, b)
	}
	resp, b = f.req(t, "GET", "/v1/volumes", nil)
	if !strings.Contains(string(b), "portcullis-app_data") || strings.Contains(string(b), "other") || strings.Contains(string(b), "vault") {
		t.Errorf("volumes: %s", b)
	}
}

// TestVolumeWithoutLabelsNeverAdopted: an existing volume with a
// manifest's name but without the instance's compose labels stops create
// and up (controller ruling: refused, never adopted).
func TestVolumeWithoutLabelsNeverAdopted(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{"made-by": "hand"}}
	if c := f.code(t, "POST", "/v1/projects/app/create", nil); c != 409 {
		t.Errorf("create: %d", c)
	}
	_, b := f.req(t, "POST", "/v1/projects/app/up", nil)
	if !strings.Contains(string(b), "never adopted") {
		t.Errorf("up: %s", b)
	}
	for _, call := range f.rt.Calls() {
		if strings.HasPrefix(call, "create ") || strings.HasPrefix(call, "up ") {
			t.Errorf("the engine was asked to %s", call)
		}
	}
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	if c := f.code(t, "POST", "/v1/projects/app/create", nil); c != 204 {
		t.Errorf("labelled: %d", c)
	}
}

// listFiles is every path under dir (relative, sorted).
func listFiles(t *testing.T, dir string) []string {
	var out []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && p != dir {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// TestBundleRefusesLinksAndEscapes (Review Focus 5): a hostile bundle is
// refused whole and nothing is written outside <data>/projects/<id>.new
// (which is removed again); the previous bundle stays in place.
func TestBundleRefusesLinksAndEscapes(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	before := listFiles(t, f.data)
	for name, extra := range map[string]bundleFile{
		"symlink":          {name: "templates/app/link", typ: tar.TypeSymlink, link: "/etc/passwd", mode: 0o777},
		"hardlink":         {name: "templates/app/hard", typ: tar.TypeLink, link: "env"},
		"dot-dot":          {name: "../../escape", data: "x"},
		"absolute":         {name: "/tmp/escape", data: "x"},
		"duplicate":        {name: BundleEnv, data: "B=2\n", mode: 0o600},
		"device":           {name: "dev", typ: tar.TypeChar, mode: 0o600},
		"fifo":             {name: "pipe", typ: tar.TypeFifo, mode: 0o600},
		"setuid":           {name: "tool", data: "x", mode: 0o4755},
		"privileged model": {name: BundleOverride, data: "services:\n  web:\n    privileged: true\n"},
		"escaping bind":    {name: BundleOverride, data: "services:\n  web:\n    volumes: [\"/etc:/etc\"]\n"},
		"post_start hook":  {name: BundleOverride, data: "services:\n  web:\n    post_start:\n      - command: [id]\n        privileged: true\n"},
	} {
		if c := f.code(t, "PUT", "/v1/projects/app/bundle", appBundle(t, "app", extra)); c != 400 {
			t.Errorf("%s: %d", name, c)
		}
		if after := listFiles(t, f.data); strings.Join(after, "\n") != strings.Join(before, "\n") {
			t.Errorf("%s: the data dir changed:\n%v\n%v", name, before, after)
		}
	}
	for _, p := range []string{"/tmp/escape", filepath.Join(filepath.Dir(f.data), "escape")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was written", p)
		}
	}
	// A bundle for another id than the path's is refused too.
	if c := f.code(t, "PUT", "/v1/projects/app/bundle", appBundle(t, "other")); c != 400 {
		t.Errorf("another instance's manifest: %d", c)
	}
}

// TestBundleSwapKeepsAppfiles: a new bundle replaces the project dir, the
// appfiles dir survives, and data files are delivered atomically there.
func TestBundleSwapKeepsAppfiles(t *testing.T) {
	f := newAPI(t)
	if c := f.code(t, "PUT", "/v1/projects/app/bundle", appBundle(t, "app", bundleFile{name: "appfiles/settings/settings.json", data: "{}", mode: 0o640})); c != 204 {
		t.Fatalf("bundle: %d", c)
	}
	af := filepath.Join(f.data, "appfiles", "app", "settings", "settings.json")
	if b, err := os.ReadFile(af); err != nil || string(b) != "{}" {
		t.Fatalf("appfile from the bundle: %v %q", err, b)
	}
	// Deliver a data file.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range map[string]string{"settings.json": `{"a":1}`, "settings.secrets.json": `{"s":1}`} {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))})
		tw.Write([]byte(data))
	}
	tw.Close()
	if c := f.code(t, "PUT", "/v1/projects/app/appfiles/settings", buf.Bytes()); c != 204 {
		t.Fatalf("appfile: %d", c)
	}
	if fi, err := os.Stat(filepath.Join(f.data, "appfiles", "app", "settings", "settings.secrets.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("secrets file: %v %v", err, fi)
	}
	// A tar naming anything else is refused.
	var bad bytes.Buffer
	tw = tar.NewWriter(&bad)
	tw.WriteHeader(&tar.Header{Name: "../x.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	if c := f.code(t, "PUT", "/v1/projects/app/appfiles/settings", bad.Bytes()); c != 400 {
		t.Errorf("hostile appfile: %d", c)
	}
	// A new bundle (no appfiles): the project dir is new, appfiles stay.
	marker := filepath.Join(f.data, "projects", "app", "templates", "app", "app.conf")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
	f.bundle(t, "app")
	if b, err := os.ReadFile(af); err != nil || string(b) != `{"a":1}` {
		t.Errorf("appfiles after the swap: %v %q", err, b)
	}
	for _, d := range []string{"app.new", "app.old"} {
		if _, err := os.Stat(filepath.Join(f.data, "projects", d)); err == nil {
			t.Errorf("%s left behind", d)
		}
	}
	// The bundle survives a restart (re-validated from disk).
	api2 := NewAPI(APIConfig{DataDir: f.data, BindRoots: []string{"/srv"}, Runtime: f.rt, Net: f.net})
	if api2.project("app") == nil {
		t.Error("the bundle wasn't reloaded")
	}
}

// TestDataPreambleChecks: only a routed service's port of a bundled
// project is spliced; the rest closes.
func TestDataPreambleChecks(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	// The container behind it: a real listener on loopback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("app says hi"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	// Route the test's port: rewrite the model's label to it.
	p := f.api.project("app")
	p.routes = map[string]map[int]bool{"web": {port: true}}
	labels := map[string]string{docker.LabelProject: "portcullis-app", docker.LabelService: "web"}
	f.rt.Units = []runtime.Unit{{ID: "c1", Labels: labels, Instance: "app", Service: "web", State: "running"}}
	f.net.addrs["c1"] = netip.MustParseAddr("127.0.0.1")
	f.net.labels["c1"] = labels
	try := func(pre string, slow bool) string {
		a, b := net.Pipe()
		go f.api.HandleData(b)
		a.SetDeadline(time.Now().Add(8 * time.Second))
		if slow {
			time.Sleep(PreambleTimeout + 500*time.Millisecond)
		}
		go a.Write([]byte(pre))
		out, _ := io.ReadAll(a)
		a.Close()
		return string(out)
	}
	ok := agentapi.DataPreamble{Instance: "app", Service: "web", Port: port}
	if got := try(string(ok.Encode()), false); got != "app says hi" {
		t.Fatalf("routed: %q", got)
	}
	for name, pre := range map[string]string{
		"unplaced instance": string(agentapi.DataPreamble{Instance: "other", Service: "web", Port: port}.Encode()),
		"unrouted port":     string(agentapi.DataPreamble{Instance: "app", Service: "web", Port: 22}.Encode()),
		"unrouted service":  string(agentapi.DataPreamble{Instance: "app", Service: "db", Port: port}.Encode()),
		"oversized line":    `{"instance":"` + strings.Repeat("a", 2000) + "\"}\n",
		"extra key":         `{"instance":"app","service":"web","port":1,"x":1}` + "\n",
	} {
		if got := try(pre, false); got != "" {
			t.Errorf("%s: spliced %q", name, got)
		}
	}
	if testing.Short() {
		return
	}
	if got := try(string(ok.Encode()), true); got != "" {
		t.Errorf("slow preamble: spliced %q", got)
	}
}

// TestResponsesCapped: logs over 4 MiB keep the last bytes and say so;
// an events line over 64 KiB is dropped.
func TestResponsesCapped(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app")
	mine := map[string]string{docker.LabelProject: "portcullis-app"}
	f.rt.Infos["c1"] = runtime.UnitInfo{ID: "c1", Labels: mine}
	big := bytes.Repeat([]byte("x"), agentapi.MaxLogs+10)
	big[len(big)-1] = 'E'
	f.rt.LogsVal["c1"] = big
	resp, b := f.req(t, "GET", "/v1/containers/c1/logs?tail=100", nil)
	if resp.StatusCode != 200 || len(b) != agentapi.MaxLogs || b[len(b)-1] != 'E' || resp.Header.Get(TruncatedHeader) != "1" {
		t.Errorf("logs: %d len %d trunc %q", resp.StatusCode, len(b), resp.Header.Get(TruncatedHeader))
	}
	var small, huge, foreign runtime.Event
	small.Type, small.Action, small.Actor.Attributes = "container", "start", mine
	huge.Type, huge.Action, huge.Actor.Attributes = "container", "die", map[string]string{docker.LabelProject: "portcullis-app", "x": strings.Repeat("y", agentapi.MaxLine)}
	foreign.Type, foreign.Action, foreign.Actor.Attributes = "container", "start", map[string]string{docker.LabelProject: "portcullis-other"}
	f.rt.evs = []runtime.Event{small, huge, foreign}
	_, b = f.req(t, "GET", "/v1/events", nil)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"start"`) {
		t.Errorf("events: %d lines %.200s", len(lines), b)
	}
}

// TestNoRawPassthrough: nothing but the API's routes answers.
func TestNoRawPassthrough(t *testing.T) {
	f := newAPI(t)
	for _, p := range []string{"/v1/engine/containers/json", "/libpod/info", "/build", "/v1.45/containers/json", "/containers/create", "/v1/system/df", "/v1/images/prune"} {
		for _, m := range []string{"GET", "POST"} {
			if c := f.code(t, m, p, nil); c != 404 && c != 405 {
				t.Errorf("%s %s: %d", m, p, c)
			}
		}
	}
}

// TestSetupNetwork (pre-flight P35): the worker's portcullis-proxy with
// the primary's subnet and range, the agent attached at the Traefik IP.
func TestSetupNetwork(t *testing.T) {
	f := newAPI(t)
	n := agentapi.NetworkParams{ProxySubnet: netip.MustParsePrefix("172.31.254.0/26"), ProxyIPRange: netip.MustParsePrefix("172.31.254.32/27"), TraefikIP: netip.MustParseAddr("172.31.254.2")}
	if err := f.api.SetupNetwork(context.Background(), n, "agent-ctr"); err != nil {
		t.Fatal(err)
	}
	if len(f.net.created) != 1 || f.net.created[0] != "portcullis-proxy 172.31.254.0/26 172.31.254.32/27" || f.net.joined[0] != "portcullis-proxy agent-ctr 172.31.254.2" {
		t.Errorf("%v %v", f.net.created, f.net.joined)
	}
	n.TraefikIP = netip.MustParseAddr("172.31.254.40") // inside the dynamic range
	if err := f.api.SetupNetwork(context.Background(), n, "agent-ctr"); err == nil {
		t.Error("a Traefik IP in the dynamic range accepted")
	}
}

// TestFixerRunsOnOwnImage: a fixed folder_fix runs on the agent's image
// with its own binary.
func TestFixerRunsOnOwnImage(t *testing.T) {
	f := newAPI(t)
	spec := agentapi.FixerSpecOf(fixerspec.Run{Mode: "scan", Source: "/srv/photos", Opts: folderfix.Options{}}.Spec("", AgentBinary))
	resp, b := f.req(t, "POST", "/v1/helpers", bytes.NewReader(mustJSON(agentapi.HelperSpec{Kind: agentapi.HelperFolderFix, Spec: &spec})))
	var hc agentapi.HelperCreated
	json.Unmarshal(b, &hc)
	if resp.StatusCode != 200 || hc.ID == "" {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	if c := f.code(t, "POST", "/v1/helpers/"+hc.ID+"/run", nil); c != 200 {
		t.Errorf("run: %d", c)
	}
	if c := f.code(t, "POST", "/v1/helpers/"+hc.ID+"/run", nil); c != 409 {
		t.Errorf("second run: %d", c)
	}
	found := false
	for _, call := range f.rt.Calls() {
		if strings.HasPrefix(call, "fixer ["+AgentBinary+" folderfix scan") {
			found = true
		}
	}
	if !found {
		t.Errorf("calls %v", f.rt.Calls())
	}
	if c := f.code(t, "DELETE", "/v1/helpers/"+hc.ID, nil); c != 204 {
		t.Errorf("delete: %d", c)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
