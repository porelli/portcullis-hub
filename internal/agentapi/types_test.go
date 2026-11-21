package agentapi

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

func roundTrip[T any](t *testing.T, v T) T {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := Decode(bytes.NewReader(b), MaxJSON, &out); err != nil {
		t.Fatalf("%T: %v\n%s", v, err, b)
	}
	return out
}

// TestWireRoundTrip: whatever Marshal writes Decode reads, zero values
// included (no null in the encoding), and the runtime conversions keep
// every field.
func TestWireRoundTrip(t *testing.T) {
	roundTrip(t, Info{})
	in := Info{AgentVersion: "1.4.0", API: Version, Runtime: "podman", Arch: "arm64", EngineVersion: "5.4", EngineAPI: "1.45",
		Verified: true, Rootless: true, UIDMap: "0 1000 1\n", CPUs: 4, MemBytes: 8 << 30, DockerRootDir: "/home/u/.local/share/containers",
		DataDir: "/opt/portcullis/worker-data", SELinux: true, SecurityOptions: []string{"name=selinux"}, UnprivilegedPortStart: 1024,
		BindRoots: []string{"/srv"}, PortBinds: []PortBind{{Project: "portcullis-x", Service: "web", HostPort: 8080, Proto: "tcp"}},
		Networks: []Network{{Name: "portcullis-proxy", Subnets: []netip.Prefix{netip.MustParsePrefix("172.31.254.0/26")}}},
		Clock:    time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)}
	if got := roundTrip(t, in); !reflect.DeepEqual(got, in) {
		t.Errorf("info %+v", got)
	}
	ri, err := in.RuntimeInfo()
	if err != nil || ri.Kind != runtime.KindPodman || ri.ForbiddenRoots[0] != in.DockerRootDir || !ri.SELinux || ri.APIVersion != "1.45" || ri.Networks[0].Name != "portcullis-proxy" {
		t.Errorf("runtime info %+v %v", ri, err)
	}
	for _, rt := range []string{"kubernetes", "", "Docker"} {
		if _, err := (Info{Runtime: rt}).RuntimeInfo(); err == nil {
			t.Errorf("runtime %q accepted", rt)
		}
	}
	u := runtime.Unit{ID: "c1", Name: "n", Project: "portcullis-x", Instance: "x", Service: "web", Labels: map[string]string{"a": "b"}, Networks: map[string][]string{"n": {"web"}}}
	if got := roundTrip(t, UnitOf(u)).Runtime(); !reflect.DeepEqual(got, u) {
		t.Errorf("unit %+v", got)
	}
	// A created, never started container: a network without aliases
	// (nil) crosses as [] (seen live: the strict decoder refused null).
	created := runtime.Unit{ID: "c2", Name: "m", Networks: map[string][]string{"portcullis-proxy": nil, "d": {"web"}}}
	if got := roundTrip(t, UnitOf(created)).Runtime(); len(got.Networks["portcullis-proxy"]) != 0 || got.Networks["d"][0] != "web" {
		t.Errorf("created unit %+v", got)
	}
	ui := runtime.UnitInfo{ID: "c1", Image: "sha256:x", CapAdd: []string{"CHOWN"}, Memory: 5}
	if got := roundTrip(t, UnitInfoOf(ui)).Runtime(); !reflect.DeepEqual(got, ui) {
		t.Errorf("unit info %+v", got)
	}
	var ev runtime.Event
	ev.Type, ev.Action, ev.TimeNano, ev.Actor.ID, ev.Actor.Attributes = "container", "die", 7, "c1", map[string]string{"exitCode": "1"}
	if got := roundTrip(t, EventOf(ev)).Runtime(); !reflect.DeepEqual(got, ev) {
		t.Errorf("event %+v", got)
	}
	ei := runtime.ExecInput{Cmd: []string{"sh", "-c", "x"}, User: "1:1", Stdin: []byte("in"), Timeout: 3 * time.Second}
	if got := roundTrip(t, ExecRequestOf(ei)).Runtime(); !reflect.DeepEqual(got, ei) {
		t.Errorf("exec %+v", got)
	}
	st := runtime.State{Running: true, Health: "healthy", Status: "running"}
	if got := roundTrip(t, StateOf(st)).Runtime(); got != st {
		t.Errorf("state %+v", got)
	}
	vol := runtime.Volume{Name: "portcullis-x_data", Driver: "local", Labels: map[string]string{"k": "v"}}
	if got := roundTrip(t, VolumeOf(vol)).Runtime(); !reflect.DeepEqual(got, vol) {
		t.Errorf("volume %+v", got)
	}
	roundTrip(t, ProgressLine{End: true})
	roundTrip(t, ExecResult{})
	roundTrip(t, ExecSplitResult{ExitCode: -1})
	roundTrip(t, RunResult{})
	roundTrip(t, HelperSpec{Kind: HelperVolumeIO, Instance: "x", Volume: "v", Path: "/data", Write: true})
	roundTrip(t, HelperCreated{ID: "h1"})
	roundTrip(t, NetworkParams{ProxySubnet: netip.MustParsePrefix("172.31.254.0/26"), ProxyIPRange: netip.MustParsePrefix("172.31.254.32/27"), TraefikIP: netip.MustParseAddr("172.31.254.2")})
	roundTrip(t, IdentityWG{LinkPub: "k"})
	ep := roundTrip(t, EnrolProof{Proof: B64URL{0xfb, 0xff}, CSRCN: "nas.node.portcullis.internal"})
	if string(ep.Proof) != "\xfb\xff" {
		t.Errorf("proof %x", ep.Proof)
	}
	if b, _ := json.Marshal(EnrolNonce{Nonce: B64URL{0xfb, 0xff}}); string(b) != `{"nonce":"-_8"}` {
		t.Errorf("nonce encoding %s (base64url, no padding)", b)
	}
	for _, bad := range []string{`{"nonce":"-_8="}`, `{"nonce":"+/8"}`, `{"nonce":[1]}`} {
		var n EnrolNonce
		if err := Decode(strings.NewReader(bad), MaxJSON, &n); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestFixerSpecBytes: the wire spec drops the image and the reader, and
// a spec differing in any field isn't the same fixer.
func TestFixerSpecBytes(t *testing.T) {
	s := runtime.FixerSpec{Image: "sha256:hub", Cmd: []string{"/hub", "folderfix", "apply"}, User: "0:0", Env: []string{"A=1"},
		Binds: []runtime.BindMount{{Source: "/srv/photos", Target: "/target", ReadOnly: false}}, Scratch: []string{"/out"},
		CapAdd: []string{"CHOWN", "FOWNER"}, Label: "folder:photos", Pids: 64, Memory: 256 << 20, Timeout: time.Minute, OutPath: "/out"}
	w := FixerSpecOf(s)
	if strings.Contains(string(w.Canonical()), "sha256:hub") {
		t.Error("the image is on the wire")
	}
	back := roundTrip(t, w).Runtime("sha256:agent", nil)
	s.Image = "sha256:agent"
	if !reflect.DeepEqual(back, s) {
		t.Errorf("%+v\n%+v", back, s)
	}
	if !SameFixer(w, FixerSpecOf(s)) {
		t.Error("same spec differs")
	}
	other := FixerSpecOf(s)
	other.Binds[0].Source = "/etc"
	if SameFixer(w, other) {
		t.Error("another bind is the same fixer")
	}
}

func TestPreamble(t *testing.T) {
	p := DataPreamble{Instance: "immich", Service: "web", Port: 2283}
	r := bytes.NewReader(append(p.Encode(), "GET / HTTP/1.1\r\n"...))
	got, err := ReadPreamble(r)
	if err != nil || got != p {
		t.Fatalf("%+v %v", got, err)
	}
	if rest := r.Len(); rest != len("GET / HTTP/1.1\r\n") {
		t.Errorf("the preamble read past its line (%d left)", rest)
	}
	for name, in := range map[string]string{
		"no newline":  `{"instance":"a","service":"b","port":1}`,
		"extra key":   `{"instance":"a","service":"b","port":1,"token":"x"}` + "\n",
		"dup key":     `{"instance":"a","instance":"c","service":"b","port":1}` + "\n",
		"port 0":      `{"instance":"a","service":"b","port":0}` + "\n",
		"big port":    `{"instance":"a","service":"b","port":65536}` + "\n",
		"no service":  `{"instance":"a","service":"","port":1}` + "\n",
		"too long":    `{"instance":"` + strings.Repeat("a", MaxPreamble) + `","service":"b","port":1}` + "\n",
		"empty input": "",
	} {
		if _, err := ReadPreamble(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFilterQuery(t *testing.T) {
	for _, f := range []runtime.Filter{{}, {All: true}, {Helper: true}, {Instance: "x"}, {Instance: "x", Service: "web"}, {All: true, Names: true}} {
		q := url.Values{}
		for k, v := range FilterQuery(f) {
			q.Set(k, v)
		}
		got, err := ParseFilter(q)
		if err != nil || got != f {
			t.Errorf("%+v → %+v %v", f, got, err)
		}
	}
	for _, q := range []string{"all=true", "helper=0", "names=yes", "x=1", "instance=a&instance=b", "service=web"} {
		v, _ := url.ParseQuery(q)
		if _, err := ParseFilter(v); err == nil {
			t.Errorf("%s accepted", q)
		}
	}
}

func TestErrorBody(t *testing.T) {
	var e Error
	if err := Decode(bytes.NewReader(ErrorBody(strings.Repeat("é", 500))), MaxJSON, &e); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(e.Error)); n != MaxError {
		t.Errorf("%d runes", n)
	}
	if _, err := ReadCapped(strings.NewReader(strings.Repeat("x", 11)), 10); err != ErrTooLarge {
		t.Errorf("cap: %v", err)
	}
}

// TestRuntimeInfoBounds (Task 10 review M1): an impossible CPU count or
// memory from a worker is no figure.
func TestRuntimeInfoBounds(t *testing.T) {
	for _, i := range []Info{{Runtime: "docker", CPUs: MaxCPUCores + 1, MemBytes: 1}, {Runtime: "docker", CPUs: 4, MemBytes: -1}} {
		ri, err := i.RuntimeInfo()
		if err != nil || ri.CPUs != 0 || ri.MemoryBytes != 0 {
			t.Errorf("%+v → %d %d %v", i, ri.CPUs, ri.MemoryBytes, err)
		}
	}
	if ri, _ := (Info{Runtime: "docker", CPUs: 8, MemBytes: 1 << 30}).RuntimeInfo(); ri.CPUs != 8 || ri.MemoryBytes != 1<<30 {
		t.Errorf("good info = %+v", ri)
	}
}
