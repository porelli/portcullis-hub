package hub

import (
	"archive/tar"
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

// movedToPrimary: plainapp on the worker, moved to the primary — the
// worker keeps its copy (MovedFrom) and no bundle of it (agent scope).
func movedToPrimary(t *testing.T) (*placedFixture, string) {
	t.Helper()
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", "nas"); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable("filesapp"); err != nil {
		t.Fatal(err)
	}
	vol := p.h.volumeNamesFor(p.h.Template("filesapp"), "filesapp")["data"]
	p.w.Lock()
	p.w.Volumes[vol] = runtime.Volume{Name: vol, Labels: map[string]string{docker.LabelProject: "portcullis-filesapp", docker.LabelVolume: "data"}}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "data/marker", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	tw.Write([]byte("hi"))
	tw.Close()
	if p.w.Contents == nil {
		p.w.Contents = map[string][]byte{}
	}
	p.w.Contents[vol] = buf.Bytes()
	p.w.Unlock()
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "primary", admin); err != nil {
		t.Fatal(err)
	}
	in := p.instance("filesapp")
	if in.MovedFrom == nil || in.MovedFrom.Server != "nas" || !slices.Contains(in.MovedFrom.Volumes, vol) {
		t.Fatalf("the kept copy isn't recorded: %+v", in.MovedFrom)
	}
	return p, vol
}

// TestMoveBackOntoKeptCopyRefused (contract §17.6): a move back onto the
// server that still holds the previous copy is refused up front (409),
// nothing sent there; undo is the way back.
func TestMoveBackOntoKeptCopyRefused(t *testing.T) {
	p, _ := movedToPrimary(t)
	before := len(p.w.Calls())
	_, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin)
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "still holds a previous copy of filesapp: use Undo move, or remove the old copy first") {
		t.Fatalf("a move back onto the kept copy: %v", err)
	}
	for _, c := range p.w.Calls()[before:] {
		if !strings.HasPrefix(c, "volumes ") && !strings.HasPrefix(c, "list ") {
			t.Errorf("the worker was sent %s", c)
		}
	}
	if err := p.h.UndoMove(context.Background(), "filesapp", "filesapp", admin); err != nil {
		t.Fatalf("undo back onto the kept copy: %v", err)
	}
	if in := p.instance("filesapp"); in.Server != "nas" {
		t.Errorf("after the undo: %+v", in)
	}
}

// TestRemoveKeptCopyOnWorker: the kept copy on the worker (out of the
// agent's scope: no bundle) is removed through a volumes-only bundle —
// only the pinned volume, no services, env, files or secrets — then the
// bundle goes and the record is cleared.
func TestRemoveKeptCopyOnWorker(t *testing.T) {
	p, vol := movedToPrimary(t)
	if err := p.h.RemoveMoveLeftover(context.Background(), "filesapp", "filesapp", admin); err != nil {
		t.Fatal(err)
	}
	p.w.Lock()
	_, still := p.w.Volumes[vol]
	p.w.Unlock()
	if still {
		t.Error("the kept volume is still on the worker")
	}
	b := p.w.lastBundle()
	if len(b) != 1 || b["compose.yml"] == "" {
		t.Fatalf("the removal's bundle carries %v", slices.Sorted(maps2keys(b)))
	}
	if c := b["compose.yml"]; strings.Contains(c, "image") || strings.Contains(c, "environment") || strings.Contains(c, "env_file") || !strings.Contains(c, vol) {
		t.Errorf("the volumes-only bundle: %q", c)
	}
	p.w.mu.Lock()
	held := p.w.held["filesapp"]
	p.w.mu.Unlock()
	if held {
		t.Error("the volumes-only bundle stayed on the worker")
	}
	in := p.instance("filesapp")
	if in.MovedFrom != nil || len(in.OlderCopies) != 0 {
		t.Errorf("the record wasn't cleared: %+v %+v", in.MovedFrom, in.OlderCopies)
	}
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin); err != nil {
		t.Errorf("a move after the removal: %v", err)
	}
}

// TestRemoveKeptCopyInUse: a pinned volume the worker can't remove (in
// use) keeps the record — and the move guard — and the doctor shows
// server_copy_not_removed.
func TestRemoveKeptCopyInUse(t *testing.T) {
	p, vol := movedToPrimary(t)
	p.w.mu.Lock()
	p.w.inUse = map[string]bool{vol: true}
	p.w.mu.Unlock()
	if err := p.h.RemoveMoveLeftover(context.Background(), "filesapp", "filesapp", admin); err == nil {
		t.Fatal("removed")
	}
	if in := p.instance("filesapp"); in.MovedFrom == nil || in.MovedFrom.Server != "nas" {
		t.Fatalf("the record went: %+v", in.MovedFrom)
	}
	if _, err := p.h.MoveInstance(context.Background(), "filesapp", "nas", admin); errStatus(err) != 409 {
		t.Errorf("the guard went: %v", err)
	}
	in := p.h.serversDoctorIn()
	if in == nil || !strings.Contains(in.OwedCopies["filesapp"], "nas") {
		t.Errorf("no server_copy_not_removed input: %+v", in)
	}
}
