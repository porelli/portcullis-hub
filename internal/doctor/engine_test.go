package doctor

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/idmap"
)

func podmanEngine() *EngineIn { return &EngineIn{Runtime: "podman"} }

func engineFindings(in *Inputs, kind string) []Finding {
	return engineCheck{kind: kind}.Run(in)
}

// engineInputs fires every kind under podman.
func engineInputs(t *testing.T, e *EngineIn) *Inputs {
	t.Helper()
	um, _ := idmap.Parse("0 1001 1\n1 100000 65536")
	return &Inputs{
		Engine:  e,
		Runtime: []RuntimeIn{{Instance: "app", Service: "web", WantMemory: true, WantPids: true}},
		Scans: map[string]ScanIn{"/srv/media": {Folder: "media", Report: &folderfix.Report{IDMap: &folderfix.IDMaps{UID: um, GID: um},
			Unmapped: folderfix.Count{N: 2, Sample: []string{"a", "b c"}}, SELinux: "unconfined_u:object_r:user_home_t:s0"}}},
		Ports: []PortIn{{Instance: "dns", Key: "DNS_UDP", Port: 53, Protocol: "udp"}},
	}
}

func TestEngineKindsDockerSilent(t *testing.T) {
	for _, e := range []*EngineIn{nil, {Runtime: "docker", Mismatch: "HUB_CONTAINER_RUNTIME=docker but the engine is Podman Engine", SELinux: true}} {
		in := engineInputs(t, e)
		for _, k := range EngineKinds {
			if f := engineFindings(in, k); len(f) != 0 {
				t.Errorf("%v: %s fired: %+v", e, k, f)
			}
		}
	}
	// The registry knows all five.
	kinds := strings.Join(Kinds(), ",")
	for _, k := range EngineKinds {
		if !strings.Contains(kinds, k) {
			t.Errorf("%s not registered", k)
		}
	}
}

func TestRuntimeMismatchProblem(t *testing.T) {
	in := engineInputs(t, &EngineIn{Runtime: "podman", Mismatch: "HUB_CONTAINER_RUNTIME=podman but the engine is Docker Engine"})
	f := engineFindings(in, KindRuntimeMismatch)
	if len(f) != 1 || f[0].Severity != Problem || f[0].Class != FixExplain || !strings.Contains(f[0].Why, "but the engine is Docker Engine") {
		t.Fatalf("%+v", f)
	}
	if f := engineFindings(engineInputs(t, podmanEngine()), KindRuntimeMismatch); len(f) != 0 {
		t.Errorf("no mismatch: %+v", f)
	}
}

func TestLimitsNotEnforced(t *testing.T) {
	in := engineInputs(t, podmanEngine())
	in.Runtime = []RuntimeIn{
		{Instance: "app", Service: "web", WantMemory: true, Memory: 0, WantPids: true, PidsLimit: 256},
		{Instance: "app", Service: "db", WantMemory: true, Memory: 512 << 20, WantPids: true, PidsLimit: 100},
		{Instance: "old", Service: "x"}, // a cached entry from before: not checked
		{Instance: "bad", Service: "y", WantMemory: true, Err: "inspecting failed"},
	}
	f := engineFindings(in, KindLimitsNotEnforced)
	if len(f) != 1 || f[0].Severity != Warning || f[0].Class != FixExplain || len(f[0].Instances) != 1 || f[0].Instances[0] != "app" ||
		!strings.Contains(f[0].Title, "service web") || !strings.Contains(f[0].Title, "memory limit") || strings.Contains(f[0].Title, "pids") {
		t.Fatalf("%+v", f)
	}
}

func TestUnmappedOwnerWarning(t *testing.T) {
	f := engineFindings(engineInputs(t, podmanEngine()), KindUnmappedOwner)
	if len(f) != 1 || f[0].Severity != Warning || f[0].Class != FixExplain || !strings.Contains(f[0].Why, "a, b c") ||
		len(f[0].Folders) != 1 || f[0].Folders[0] != "media" {
		t.Fatalf("%+v", f)
	}
	steps := strings.Join(f[0].Steps, "\n")
	for _, want := range []string{"sudo chown -R 1001 '/srv/media/a'", "sudo chown -R 1001 '/srv/media/b c'"} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
	// A name that can't be quoted gets no command.
	in := engineInputs(t, podmanEngine())
	s := in.Scans["/srv/media"]
	s.Report.Unmapped = folderfix.Count{N: 1, Sample: []string{"x\nrm -rf ~"}}
	in.Scans["/srv/media"] = s
	f = engineFindings(in, KindUnmappedOwner)
	if len(f) != 1 || strings.Contains(strings.Join(f[0].Steps, "\n"), "rm -rf") {
		t.Errorf("unquotable name: %+v", f)
	}
}

func TestSELinuxLabelMissing(t *testing.T) {
	in := engineInputs(t, &EngineIn{Runtime: "podman", SELinux: true})
	f := engineFindings(in, KindSELinuxLabelMissing)
	if len(f) != 1 || f[0].Severity != Warning || f[0].Class != FixExplain {
		t.Fatalf("%+v", f)
	}
	steps := strings.Join(f[0].Steps, "\n")
	for _, want := range []string{"semanage fcontext -a -t container_file_t '/srv/media(/.*)?'", "restorecon -R '/srv/media'"} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
	// A scan that failed with permission denied.
	s := in.Scans["/srv/media"]
	s.Report, s.Err = nil, "open /folder: permission denied"
	in.Scans["/srv/media"] = s
	if f := engineFindings(in, KindSELinuxLabelMissing); len(f) != 1 {
		t.Errorf("permission denied: %+v", f)
	}
	// container_file_t: fine; SELinux off: nothing.
	s.Err, s.Report = "", &folderfix.Report{SELinux: "system_u:object_r:container_file_t:s0"}
	in.Scans["/srv/media"] = s
	if f := engineFindings(in, KindSELinuxLabelMissing); len(f) != 0 {
		t.Errorf("container_file_t: %+v", f)
	}
	in = engineInputs(t, podmanEngine())
	if f := engineFindings(in, KindSELinuxLabelMissing); len(f) != 0 {
		t.Errorf("SELinux off: %+v", f)
	}
}

func TestUDPSourceRewritten(t *testing.T) {
	f := engineFindings(engineInputs(t, podmanEngine()), KindUDPSourceRewritten)
	if len(f) != 1 || f[0].Severity != Info || f[0].Instances[0] != "dns" || !strings.Contains(f[0].Why, "53/udp") {
		t.Fatalf("%+v", f)
	}
}
