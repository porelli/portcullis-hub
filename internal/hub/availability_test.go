package hub

import (
	"testing"

	"github.com/portcullis/hub/internal/nodeadm"
)

// TestInstancePodPrefix: an instance's pods are its "<id>--" objects in
// the apps namespace, never another instance's whose id extends it.
func TestInstancePodPrefix(t *testing.T) {
	ids := []string{"web", "web--x", "webapp"}
	for name, want := range map[string]bool{
		"web--app-7c9d-x1":  true,
		"web--x--app-7c9d":  false, // web--x's
		"webapp--app-1":     false,
		"web-app-1":         false,
		"other--web--app-1": false,
	} {
		p := nodeadm.Pod{Name: name, Namespace: "portcullis-apps"}
		if got := instancePod(&p, "portcullis-apps", "web", ids); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	p := nodeadm.Pod{Name: "web--app-1", Namespace: "portcullis"}
	if instancePod(&p, "portcullis-apps", "web", ids) {
		t.Error("a core-namespace pod counted")
	}
}
