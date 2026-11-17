package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
)

// fakeImages is the engine's image store for the preflight records.
type fakeImages struct {
	mu       sync.Mutex
	present  map[string]bool
	removed  []string
	inUse    map[string]bool
	inspectN int
}

func (f *fakeImages) ImagePresent(_ context.Context, ref string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspectN++
	return f.present[ref], nil
}

func (f *fakeImages) RemoveImage(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inUse[ref] {
		return errors.New("conflict: image is being used by a container")
	}
	f.removed = append(f.removed, ref)
	delete(f.present, ref)
	return nil
}

const pinnedRef = "docker.io/library/busybox:1.38.0-musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6"

func (f *apiFixture) pulled(ref string) bool {
	return slices.Contains(f.rt.Calls(), "pull "+ref)
}

func (f *apiFixture) preflightFile(t *testing.T) preflightFile {
	t.Helper()
	var pf preflightFile
	b, err := os.ReadFile(f.api.preflightPath())
	if err != nil {
		return preflightFile{Images: map[string]time.Time{}}
	}
	if err := json.Unmarshal(b, &pf); err != nil {
		t.Fatal(err)
	}
	return pf
}

// TestPreflightPullWithoutBundle: a preflight pull needs no bundle (the
// placement pre-pull runs before one exists); the same pull without
// preflight is refused (imageOK); a ref without a digest is 400.
func TestPreflightPullWithoutBundle(t *testing.T) {
	f := newAPI(t)
	imgs := &fakeImages{present: map[string]bool{}}
	f.api.cfg.Images = imgs
	if c := f.code(t, "POST", "/v1/images/pull", agentapi.RefRequest{Ref: pinnedRef}); c != 403 {
		t.Errorf("a plain pull of an unbundled image: %d, want 403", c)
	}
	if f.pulled(pinnedRef) {
		t.Fatal("the refused pull reached the engine")
	}
	for _, bad := range []string{"docker.io/library/busybox:1.38.0", "busybox", "sha256:" + strings.Repeat("a", 64), pinnedRef + " x"} {
		if c := f.code(t, "POST", "/v1/images/pull", agentapi.RefRequest{Ref: bad, Preflight: true}); c != 400 {
			t.Errorf("preflight %q: %d, want 400", bad, c)
		}
	}
	resp, body := f.req(t, "POST", "/v1/images/pull", strings.NewReader(`{"ref":"`+pinnedRef+`","preflight":true}`))
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"end":true`) || strings.Contains(string(body), `"error"`) {
		t.Fatalf("preflight: %d %s", resp.StatusCode, body)
	}
	if !f.pulled(pinnedRef) {
		t.Fatal("the preflight never pulled")
	}
	if _, ok := f.preflightFile(t).Images[pinnedRef]; !ok {
		t.Error("an image the preflight brought in isn't recorded")
	}
	// Already present: pulled (a no-op on the engine) but never recorded,
	// so the sweep can't remove an image someone else had.
	other := "docker.io/library/alpine:3.23@sha256:" + strings.Repeat("b", 64)
	imgs.present[other] = true
	if c := f.code(t, "POST", "/v1/images/pull", agentapi.RefRequest{Ref: other, Preflight: true}); c != 200 {
		t.Fatalf("preflight of a present image: %d", c)
	}
	if _, ok := f.preflightFile(t).Images[other]; ok {
		t.Error("an image that was already there is recorded")
	}
}

// TestPreflightLimits: at most PreflightConcurrency at once, and the
// per-minute limit (429 beyond either).
func TestPreflightLimits(t *testing.T) {
	f := newAPI(t)
	for i := 0; i < PreflightConcurrency; i++ {
		f.api.preflight.slots <- struct{}{}
	}
	if c := f.code(t, "POST", "/v1/images/pull", agentapi.RefRequest{Ref: pinnedRef, Preflight: true}); c != 429 {
		t.Errorf("a ninth concurrent preflight: %d, want 429", c)
	}
	for i := 0; i < PreflightConcurrency; i++ {
		<-f.api.preflight.slots
	}
	f2 := newAPI(t)
	n429 := 0
	for i := 0; i < PreflightConcurrency+3; i++ {
		if f2.code(t, "POST", "/v1/images/pull", agentapi.RefRequest{Ref: pinnedRef, Preflight: true}) == 429 {
			n429++
		}
	}
	if n429 == 0 {
		t.Error("no preflight was rate limited past the burst")
	}
}

// TestPreflightSweep: a recorded image no bundle names is removed once
// PreflightKeep passed (not before); one a bundle names is kept and its
// record dropped; one in use stays recorded for the next sweep.
func TestPreflightSweep(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app") // names ghcr.io/example/app:1
	imgs := &fakeImages{present: map[string]bool{}, inUse: map[string]bool{}}
	f.api.cfg.Images = imgs
	old := time.Now().Add(-25 * time.Hour).UTC()
	busy := "docker.io/library/nginx:1@sha256:" + strings.Repeat("c", 64)
	young := "docker.io/library/redis:8@sha256:" + strings.Repeat("d", 64)
	imgs.inUse[busy] = true
	f.api.savePreflight(preflightFile{Version: 1, Images: map[string]time.Time{
		pinnedRef: old, "ghcr.io/example/app:1": old, busy: old, young: time.Now().UTC(),
	}})
	f.api.SweepPreflight(context.Background(), time.Now())
	if !slices.Equal(imgs.removed, []string{pinnedRef}) {
		t.Errorf("removed %v, want only %s", imgs.removed, pinnedRef)
	}
	got := f.preflightFile(t).Images
	if _, ok := got["ghcr.io/example/app:1"]; ok {
		t.Error("a bundle's image is still recorded")
	}
	if _, ok := got[busy]; !ok {
		t.Error("an image in use was dropped from the record")
	}
	if _, ok := got[young]; !ok {
		t.Error("an image younger than PreflightKeep was dropped")
	}
	if _, ok := got[pinnedRef]; ok {
		t.Error("the removed image is still recorded")
	}
}
