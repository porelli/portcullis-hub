package hub

import (
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

// TestSubpathByEngineVersion (Ruling R-POD): Podman is judged by its own
// version (/version's "Podman Engine"), never the compat API (1.41);
// Docker by the Engine API version.
func TestSubpathByEngineVersion(t *testing.T) {
	for _, c := range []struct {
		name string
		kind runtime.Kind
		info runtime.Info
		ok   bool
	}{
		{"podman 5.4", runtime.KindPodman, runtime.Info{APIVersion: "1.41", EngineVersion: "5.4.0"}, true},
		{"podman 5.6", runtime.KindPodman, runtime.Info{APIVersion: "1.41", EngineVersion: "5.6.1"}, true},
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
	if why := subpathRefusal(runtime.KindPodman, runtime.Info{EngineVersion: "4.9.3"}); why == "" || !containsSub(why, "Podman 4.9.3") {
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
