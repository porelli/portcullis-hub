package hub

import (
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

// TestSubpathByEngineVersion (Rulings R-POD, R-POD2): under Podman
// subpath mounts are refused whatever its version (its compat API
// ignores them), the version only named; Docker by the Engine API.
func TestSubpathByEngineVersion(t *testing.T) {
	for _, c := range []struct {
		name string
		kind runtime.Kind
		info runtime.Info
		ok   bool
	}{
		{"podman 5.4", runtime.KindPodman, runtime.Info{APIVersion: "1.41", EngineVersion: "5.4.0"}, false},
		{"podman 5.6", runtime.KindPodman, runtime.Info{APIVersion: "1.41", EngineVersion: "5.6.1"}, false},
		{"podman 4.9", runtime.KindPodman, runtime.Info{APIVersion: "1.41", EngineVersion: "4.9.3"}, false},
		{"podman unknown", runtime.KindPodman, runtime.Info{APIVersion: "1.45"}, false},
		{"docker 1.44", runtime.KindDocker, runtime.Info{APIVersion: "1.44", EngineVersion: "25.0.5"}, false},
		{"docker 1.45", runtime.KindDocker, runtime.Info{APIVersion: "1.45", EngineVersion: "26.0.0"}, true},
	} {
		why := subpathRefusal(c.kind, c.info)
		if (why == "") != c.ok {
			t.Errorf("%s: %q", c.name, why)
		}
	}
	if why := subpathRefusal(runtime.KindPodman, runtime.Info{EngineVersion: "5.6.1"}); why == "" || !containsSub(why, "per-person passwords need Docker for now") || !containsSub(why, "Podman 5.6.1") {
		t.Fatalf("%q", why)
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
