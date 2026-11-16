package hub

import (
	"context"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
)

// TestFolderOnWorker (Task 12, the T10 open item): a folder can be
// defined on a worker. The probe and the check run on its agent, its
// folder roots apply (not the primary's), paths on different hosts never
// overlap, and an unknown server is 404.
func TestFolderOnWorker(t *testing.T) {
	p := newPlacedFixture(t)
	d := &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}
	d.add("/mnt/media", "ext4")
	p.w.mu.Lock()
	p.w.disk = d
	p.w.info.BindRoots = []string{"/mnt"}
	p.w.mu.Unlock()
	p.w.Lock()
	p.w.InfoVal = runtime.Info{ForbiddenRoots: []string{"/var/lib/docker"}}
	p.w.Unlock()
	if _, err := p.h.refreshServerFacts(context.Background(), "nas"); err != nil {
		t.Fatal(err)
	}
	admin := directory.Human("admin")
	if _, _, err := p.h.CreateFolder(context.Background(), FolderInput{ID: "media", Name: "Media", Path: "/srv/media", Server: "nas"}, admin); statusOf(err) != 400 {
		t.Errorf("outside the worker's folder roots: %v", err)
	}
	if _, _, err := p.h.CreateFolder(context.Background(), FolderInput{ID: "media", Name: "Media", Path: "/mnt/media", Server: "ghost"}, admin); statusOf(err) != 404 {
		t.Errorf("unknown server: %v", err)
	}
	before := len(p.runner.Calls())
	v, _, err := p.h.CreateFolder(context.Background(), FolderInput{ID: "media", Name: "Media", Path: "/mnt/media", Server: "nas"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if v.Server != "nas" {
		t.Errorf("view %+v", v)
	}
	if fo, _ := storedFolder(p.fixture, "media"); fo.Server != "nas" || fo.Dev == 0 {
		t.Errorf("stored %+v", fo)
	}
	if !workerHas(p.w, "signal fixer probe") || !workerHas(p.w, "signal fixer scan") {
		t.Errorf("not checked on the worker: %v", p.w.Calls())
	}
	for _, c := range p.runner.Calls()[before:] {
		if len(c) >= 5 && c[:5] == "fixer" {
			t.Errorf("a fixer ran on the primary: %v", c)
		}
	}
	// The same path checked on the worker again: an overlap (same host).
	pc, err := p.h.CheckFolderPath(context.Background(), "nas", "/mnt/media", false)
	if err != nil || len(pc.Problems) == 0 {
		t.Errorf("same host: %+v %v", pc, err)
	}
}
