package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fixerspec"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
)

// usageFixture: project app bundled, c-mine its container, c-theirs
// another project's; the fixture procfs of internal/usage.
func usageFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := newAPI(t)
	f.api.cfg.ProcDir, f.api.cfg.SysDir = "../usage/testdata/proc", "../usage/testdata/sys"
	f.bundle(t, "app")
	mine := map[string]string{docker.LabelProject: "portcullis-app", docker.LabelService: "web"}
	theirs := map[string]string{docker.LabelProject: "portcullis-other"}
	f.rt.Infos["c-mine"] = runtime.UnitInfo{ID: "c-mine", Labels: mine}
	f.rt.Infos["c-theirs"] = runtime.UnitInfo{ID: "c-theirs", Labels: theirs}
	f.rt.Infos["c-core"] = runtime.UnitInfo{ID: "c-core", Labels: map[string]string{docker.LabelProject: "portcullis"}}
	cpu, mem := uint64(5e9), uint64(64<<20)
	f.rt.SetStats("c-mine", runtime.UnitStats{Read: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), CPUUsageNS: &cpu, MemUsage: &mem})
	f.rt.SetStats("c-theirs", runtime.UnitStats{CPUUsageNS: &cpu})
	f.rt.LayerSizes = map[string]int64{"c-mine": 4096, "c-theirs": 1}
	f.rt.ImageSizes = map[string]int64{"ghcr.io/example/app:1": 1 << 20, "docker.io/library/busybox:latest": 1}
	return f
}

func TestAgentStatsScope(t *testing.T) {
	f := usageFixture(t)
	resp, b := f.req(t, "GET", "/v1/containers/c-mine/stats", nil)
	var s agentapi.UnitStats
	if resp.StatusCode != 200 || agentapi.Decode(bytes.NewReader(b), agentapi.MaxJSON, &s) != nil {
		t.Fatalf("own stats: %d %s", resp.StatusCode, b)
	}
	rs := s.Runtime()
	if rs.CPUUsageNS == nil || *rs.CPUUsageNS != 5e9 || rs.MemUsage == nil || *rs.MemUsage != 64<<20 || rs.NetRx != nil || !rs.Read.Equal(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("stats = %+v", rs)
	}
	for _, cid := range []string{"c-theirs", "c-core"} {
		if c := f.code(t, "GET", "/v1/containers/"+cid+"/stats", nil); c != 403 {
			t.Errorf("%s stats: %d", cid, c)
		}
		if c := f.code(t, "GET", "/v1/containers/"+cid+"/size", nil); c != 403 {
			t.Errorf("%s size: %d", cid, c)
		}
	}
	if c := f.code(t, "GET", "/v1/containers/c-gone/stats", nil); c != 404 {
		t.Errorf("unknown container: %d", c)
	}
	for _, call := range f.rt.Calls() {
		if strings.Contains(call, "c-theirs") && !strings.HasPrefix(call, "inspect") {
			t.Errorf("another project's container reached: %s", call)
		}
	}

	// Through the agent's guard: link.control may not read a usage route.
	ca := newCA(t, "example.org Node CA")
	ag := &Agent{cfg: Config{Routes: f.api, Now: time.Now}, state: StateReady, ca: ca.cert}
	h := ag.Handler()
	for cn, want := range map[string]int{CNControl: 200, CNLink: 403} {
		leaf, _ := ca.issue(t, cn, nil, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
		for _, p := range []string{"/v1/containers/c-mine/stats", "/v1/containers/c-mine/size", "/v1/host/usage", "/v1/images/size?ref=ghcr.io%2Fexample%2Fapp%3A1"} {
			r := httptest.NewRequest("GET", p, nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca.cert}}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != want {
				t.Errorf("%s on %s: %d %s", cn, p, rec.Code, rec.Body)
			}
		}
	}
	r := httptest.NewRequest("GET", "/v1/host/usage", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Errorf("no client certificate: %d", rec.Code)
	}
}

func TestAgentLayerAndImageSize(t *testing.T) {
	f := usageFixture(t)
	resp, b := f.req(t, "GET", "/v1/containers/c-mine/size", nil)
	var sz agentapi.SizeBody
	if resp.StatusCode != 200 || agentapi.Decode(bytes.NewReader(b), agentapi.MaxJSON, &sz) != nil || sz.Bytes != 4096 {
		t.Errorf("layer size: %d %s", resp.StatusCode, b)
	}
	resp, b = f.req(t, "GET", "/v1/images/size?ref=ghcr.io%2Fexample%2Fapp%3A1", nil)
	if resp.StatusCode != 200 || agentapi.Decode(bytes.NewReader(b), agentapi.MaxJSON, &sz) != nil || sz.Bytes != 1<<20 {
		t.Errorf("image size: %d %s", resp.StatusCode, b)
	}
	if c := f.code(t, "GET", "/v1/images/size?ref=docker.io%2Flibrary%2Fbusybox%3Alatest", nil); c != 403 {
		t.Errorf("an image in no bundle: %d", c)
	}
	for _, q := range []string{"", "?ref=", "?ref=a&ref=b"} {
		if c := f.code(t, "GET", "/v1/images/size"+q, nil); c != 400 && c != 403 {
			t.Errorf("image size%s: %d", q, c)
		}
	}
	for _, call := range f.rt.Calls() {
		if strings.Contains(call, "busybox") {
			t.Errorf("an image outside the bundles reached the engine: %s", call)
		}
	}
}

func TestAgentHostUsage(t *testing.T) {
	f := usageFixture(t)
	resp, b := f.req(t, "GET", "/v1/host/usage", nil)
	var hc agentapi.HostCounters
	if resp.StatusCode != 200 || agentapi.Decode(bytes.NewReader(b), agentapi.MaxJSON, &hc) != nil {
		t.Fatalf("host usage: %d %s", resp.StatusCode, b)
	}
	c := hc.Usage()
	if c.CPUTotal != 6485 || c.CPUIdle != 5100 || c.MemTotal != 16384000*1024 || c.MemAvailable != 8192000*1024 || c.DiskRead != 3017*512 || c.DiskWrite != 2003*512 || c.At.IsZero() {
		t.Errorf("counters = %+v", c)
	}
	// A procfs that can't be read: an error, no partial counters.
	f.api.cfg.ProcDir = t.TempDir()
	resp, b = f.req(t, "GET", "/v1/host/usage", nil)
	if resp.StatusCode < 500 || !strings.Contains(string(b), "host") {
		t.Errorf("no procfs: %d %s", resp.StatusCode, b)
	}
}

// TestAgentUsageFixer: the usage helper on a worker, through POST
// /v1/helpers: a bundled project's volume (its owner's) or a bind under
// the roots runs on the agent's own image; another project's volume, a
// volume named for another instance, and a bind outside the roots are
// refused before any run.
func TestAgentUsageFixer(t *testing.T) {
	f := usageFixture(t)
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	f.rt.Volumes["portcullis-other_data"] = runtime.Volume{Name: "portcullis-other_data", Labels: map[string]string{docker.LabelProject: "portcullis-other"}}
	caps := folderfix.Options{MaxEntries: 2_000_000, MaxTime: 2 * time.Minute}
	spec := func(r fixerspec.Run) *agentapi.FixerSpec {
		s := agentapi.FixerSpecOf(r.Spec("", AgentBinary))
		return &s
	}
	create := func(s *agentapi.FixerSpec) (int, string) {
		resp, b := f.req(t, "POST", "/v1/helpers", bytes.NewReader(mustJSON(agentapi.HelperSpec{Kind: agentapi.HelperFolderFix, Spec: s})))
		var hc agentapi.HelperCreated
		json.Unmarshal(b, &hc)
		if resp.StatusCode != 200 {
			return resp.StatusCode, string(b)
		}
		return resp.StatusCode, hc.ID
	}
	code, id := create(spec(fixerspec.Run{Mode: "usage", Volume: runtime.VolumeMount{Name: "portcullis-app_data", Instance: "app"}, Opts: caps}))
	if code != 200 {
		t.Fatalf("own volume: %d %s", code, id)
	}
	if c := f.code(t, "POST", "/v1/helpers/"+id+"/run", nil); c != 200 {
		t.Errorf("run: %d", c)
	}
	ran := false
	for _, call := range f.rt.Calls() {
		if strings.HasPrefix(call, "fixer ["+AgentBinary+" folderfix usage") {
			ran = true
		}
	}
	if !ran {
		t.Errorf("calls %v", f.rt.Calls())
	}
	if code, id := create(spec(fixerspec.Run{Mode: "usage", Source: f.root + "/photos", Opts: caps})); code != 200 {
		t.Errorf("a bind under the roots: %d %s", code, id)
	} else if c := f.code(t, "POST", "/v1/helpers/"+id+"/run", nil); c != 200 {
		t.Errorf("bind run: %d", c)
	}
	for name, s := range map[string]*agentapi.FixerSpec{
		"another project's volume":       spec(fixerspec.Run{Mode: "usage", Volume: runtime.VolumeMount{Name: "portcullis-other_data", Instance: "other"}, Opts: caps}),
		"own volume named for another":   spec(fixerspec.Run{Mode: "usage", Volume: runtime.VolumeMount{Name: "portcullis-app_data", Instance: "other"}, Opts: caps}),
		"an unknown volume":              spec(fixerspec.Run{Mode: "usage", Volume: runtime.VolumeMount{Name: "nope", Instance: "app"}, Opts: caps}),
		"a bind outside the roots":       spec(fixerspec.Run{Mode: "usage", Source: "/etc", Opts: caps}),
		"the agent's data dir as a bind": spec(fixerspec.Run{Mode: "usage", Source: f.data, Opts: caps}),
	} {
		if code, msg := create(s); code != 403 || !strings.Contains(msg, "not a fixed helper") {
			t.Errorf("%s: %d %s", name, code, msg)
		}
	}
}

// TestAgentUsageFixRound1 (Task 9 review): the stats deadline (M2), a
// volume the engine recreated during the run (M1), a volume name checked
// before the engine sees it (M3), the run-time re-check, the helper
// image's size and a core volume (nit 5).
func TestAgentUsageFixRound1(t *testing.T) {
	f := usageFixture(t)
	lbl := map[string]string{docker.LabelProject: "portcullis-app"}
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: lbl}
	f.rt.Volumes["portcullis_postgres_data"] = runtime.Volume{Name: "portcullis_postgres_data", Labels: map[string]string{docker.LabelProject: "portcullis"}}
	caps := folderfix.Options{MaxEntries: 2_000_000, MaxTime: 2 * time.Minute}
	volSpec := func(name, inst string) []byte {
		s := agentapi.FixerSpecOf(fixerspec.Run{Mode: "usage", Volume: runtime.VolumeMount{Name: name, Instance: inst}, Opts: caps}.Spec("", AgentBinary))
		return mustJSON(agentapi.HelperSpec{Kind: agentapi.HelperFolderFix, Spec: &s})
	}
	create := func(body []byte) string {
		t.Helper()
		resp, b := f.req(t, "POST", "/v1/helpers", bytes.NewReader(body))
		var hc agentapi.HelperCreated
		json.Unmarshal(b, &hc)
		if resp.StatusCode != 200 {
			t.Fatalf("create: %d %s", resp.StatusCode, b)
		}
		return hc.ID
	}

	// M2: a stats call the engine never answers ends at the deadline.
	old := statsTimeout
	statsTimeout = 50 * time.Millisecond
	t.Cleanup(func() { statsTimeout = old })
	block := make(chan struct{})
	f.rt.Lock()
	f.rt.StatsBlock = block
	f.rt.Unlock()
	start := time.Now()
	if c := f.code(t, "GET", "/v1/containers/c-mine/stats", nil); c < 400 {
		t.Errorf("a hung stats call: %d", c)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the stats call took %v", d)
	}
	close(block)
	f.rt.Lock()
	f.rt.StatsBlock = nil
	f.rt.Unlock()

	// M1: the volume is removed during the run and the engine recreates
	// it empty, unlabelled: removed again, the run fails.
	id := create(volSpec("portcullis-app_data", "app"))
	f.rt.Lock()
	f.rt.FixerFn = func(runtime.FixerSpec) (*runtime.RunResult, error) {
		f.rt.Lock()
		f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data"}
		f.rt.Unlock()
		return &runtime.RunResult{}, nil
	}
	f.rt.Unlock()
	resp, b := f.req(t, "POST", "/v1/helpers/"+id+"/run", nil)
	if resp.StatusCode != 409 || !strings.Contains(string(b), "the volume is gone") {
		t.Errorf("recreated volume: %d %s", resp.StatusCode, b)
	}
	f.rt.Lock()
	_, still := f.rt.Volumes["portcullis-app_data"]
	f.rt.FixerFn = nil
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: lbl}
	f.rt.Unlock()
	if still {
		t.Error("the recreated volume stayed")
	}
	// A volume gone for good after the run: failed too, nothing removed.
	id = create(volSpec("portcullis-app_data", "app"))
	f.rt.Lock()
	f.rt.FixerFn = func(runtime.FixerSpec) (*runtime.RunResult, error) {
		f.rt.Lock()
		delete(f.rt.Volumes, "portcullis-app_data")
		f.rt.Unlock()
		return &runtime.RunResult{}, nil
	}
	f.rt.Unlock()
	if resp, b := f.req(t, "POST", "/v1/helpers/"+id+"/run", nil); resp.StatusCode != 409 || !strings.Contains(string(b), "the volume is gone") {
		t.Errorf("deleted volume: %d %s", resp.StatusCode, b)
	}
	f.rt.Lock()
	f.rt.FixerFn = nil
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: lbl}
	f.rt.Unlock()
	// A labelled volume after the run: measured.
	id = create(volSpec("portcullis-app_data", "app"))
	if c := f.code(t, "POST", "/v1/helpers/"+id+"/run", nil); c != 200 {
		t.Errorf("a live volume's run: %d", c)
	}

	// The run-time re-check: the volume changed hands between create and run.
	id = create(volSpec("portcullis-app_data", "app"))
	f.rt.Lock()
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-other"}}
	f.rt.Unlock()
	if resp, b := f.req(t, "POST", "/v1/helpers/"+id+"/run", nil); resp.StatusCode != 409 || !strings.Contains(string(b), "no longer a bundled project's") {
		t.Errorf("re-check: %d %s", resp.StatusCode, b)
	}
	f.rt.Lock()
	f.rt.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: lbl}
	f.rt.Unlock()

	// M3: a bad name never reaches the engine; another volume's answer
	// is not this volume.
	n := usageCalls(f.rt.Calls(), "inspect-volume")
	for _, bad := range []string{"a/b", "a\x01b"} {
		if resp, b := f.req(t, "POST", "/v1/helpers", bytes.NewReader(volSpec(bad, "app"))); resp.StatusCode != 403 {
			t.Errorf("volume %q: %d %s", bad, resp.StatusCode, b)
		}
	}
	if c := f.code(t, "GET", "/v1/volumes/a%01b", nil); c != 400 {
		t.Errorf("a control character in a volume path: %d", c)
	}
	if got := usageCalls(f.rt.Calls(), "inspect-volume"); got != n {
		t.Errorf("the engine saw %d bad names", got-n)
	}
	f.rt.Lock()
	f.rt.Volumes["alias"] = runtime.Volume{Name: "portcullis-app_data", Labels: lbl}
	f.rt.Unlock()
	if c := f.code(t, "GET", "/v1/volumes/alias", nil); c != 404 {
		t.Errorf("another volume's answer: %d", c)
	}
	if resp, _ := f.req(t, "POST", "/v1/helpers", bytes.NewReader(volSpec("alias", "app"))); resp.StatusCode != 403 {
		t.Errorf("usage on another volume's answer: %d", resp.StatusCode)
	}

	// nit 5: core's volume is no target; the helper image is sized.
	if resp, b := f.req(t, "POST", "/v1/helpers", bytes.NewReader(volSpec("portcullis_postgres_data", ""))); resp.StatusCode != 403 {
		t.Errorf("core volume: %d %s", resp.StatusCode, b)
	}
	f.rt.Lock()
	f.rt.ImageSizes[f.api.cfg.HelperImage] = 7
	f.rt.Unlock()
	resp, b = f.req(t, "GET", "/v1/images/size?ref="+url.QueryEscape(f.api.cfg.HelperImage), nil)
	var sz agentapi.SizeBody
	if resp.StatusCode != 200 || json.Unmarshal(b, &sz) != nil || sz.Bytes != 7 {
		t.Errorf("helper image size: %d %s", resp.StatusCode, b)
	}
}

func usageCalls(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}
