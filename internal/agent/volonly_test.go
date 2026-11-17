package agent

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

// TestVolumesOnlyBundle (a kept copy's removal on a worker): the copy's
// volume, labelled with its project but named in no bundle, is outside the
// agent's scope (invisible, not removable); a bundle with no services,
// only the top-level volumes the Hub pinned at move time, is accepted and
// brings exactly them into scope, so they can be removed.
func TestVolumesOnlyBundle(t *testing.T) {
	f := newAPI(t)
	const vol = "portcullis_app-data"
	f.rt.Volumes[vol] = runtime.Volume{Name: vol, Labels: map[string]string{docker.LabelProject: "portcullis-app"}}
	_, list := f.req(t, "GET", "/v1/volumes", nil)
	if strings.Contains(string(list), vol) {
		t.Fatalf("an unbundled copy is listed: %s", list)
	}
	if c := f.code(t, "DELETE", "/v1/volumes/"+vol, nil); c < 400 {
		t.Fatalf("an unbundled copy was removable: %d", c)
	}
	b := bundleTar(t, "app", map[string]string{"k0": vol}, []bundleFile{
		{name: BundleCompose, data: "services: {}\nvolumes:\n  k0:\n    name: " + vol + "\n"},
	})
	if c := f.code(t, "PUT", "/v1/projects/app/bundle", b); c != 204 {
		t.Fatalf("a volumes-only bundle: %d", c)
	}
	_, list = f.req(t, "GET", "/v1/volumes", nil)
	if !strings.Contains(string(list), vol) {
		t.Fatalf("the copy isn't in scope after the volumes-only bundle: %s", list)
	}
	if c := f.code(t, "DELETE", "/v1/volumes/"+vol, nil); c != 204 {
		t.Fatalf("removing the copy: %d", c)
	}
}
