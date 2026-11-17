package hub

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
)

var usageCaps = folderfix.Options{MaxEntries: 2_000_000, MaxTime: 2 * time.Minute}

// TestFixerUsageSpec: one read-only mount at /vol (a volume, or a bind),
// DAC_READ_SEARCH only, the usage label and max-time + 30 s.
func TestFixerUsageSpec(t *testing.T) {
	img := "sha256:" + strings.Repeat("a", 64)
	v := fixerRun{Mode: "usage", Volume: runtime.VolumeMount{Name: "portcullis-a_data", Instance: "a"}, Opts: usageCaps}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	s := v.Spec(img, fixerBinary)
	if len(s.Binds) != 0 || !slices.Equal(s.Volumes, []runtime.VolumeMount{{Name: "portcullis-a_data", Target: "/vol", Instance: "a"}}) {
		t.Errorf("mounts = %+v %+v", s.Binds, s.Volumes)
	}
	if !slices.Equal(s.CapAdd, []string{"DAC_READ_SEARCH"}) || s.Label != "usage:portcullis-a_data" || s.Timeout != 150*time.Second ||
		s.User != "0:0" || s.Pids != 16 || s.Memory != 256<<20 || len(s.Scratch) != 0 || s.OutPath != "" {
		t.Errorf("spec = %+v", s)
	}
	if want := []string{"/usr/local/bin/hub", "folderfix", "usage", "--root=/vol", "--max-entries=2000000", "--max-time=2m0s"}; !slices.Equal(s.Cmd, want) {
		t.Errorf("argv = %q", s.Cmd)
	}
	b := fixerRun{Mode: "usage", Source: "/srv/media/app", Opts: usageCaps}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	s = b.Spec(img, fixerBinary)
	if len(s.Volumes) != 0 || !slices.Equal(s.Binds, []runtime.BindMount{{Source: "/srv/media/app", Target: "/vol", ReadOnly: true}}) || s.Label != "usage:/srv/media/app" {
		t.Errorf("bind spec = %+v", s)
	}
	long := fixerRun{Mode: "usage", Source: "/" + strings.Repeat("x", 300), Opts: usageCaps}
	if l := long.Spec(img, fixerBinary).Label; len([]rune(l)) != len("usage:")+200 {
		t.Errorf("label length %d", len([]rune(l)))
	}
	for name, r := range map[string]fixerRun{
		"both":      {Mode: "usage", Source: "/srv/x", Volume: runtime.VolumeMount{Name: "v"}, Opts: usageCaps},
		"neither":   {Mode: "usage", Opts: usageCaps},
		"no caps":   {Mode: "usage", Source: "/srv/x"},
		"a folder":  {Mode: "usage", Folder: "media", Source: "/srv/x", Opts: usageCaps},
		"a target":  {Mode: "usage", Source: "/srv/x", Opts: folderfix.Options{MaxEntries: 1, MaxTime: time.Second, Target: folderfix.Target{GID: 60001, Files: "r"}}},
		"bad vol":   {Mode: "usage", Volume: runtime.VolumeMount{Name: "../x"}, Opts: usageCaps},
		"root bind": {Mode: "usage", Source: "/", Opts: usageCaps},
		"scan vol":  {Mode: "scan", Source: "/srv/x", Volume: runtime.VolumeMount{Name: "v"}},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
