package state

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func goodFolder(gid int) Folder {
	return Folder{Name: "Family photos", Path: "/srv/photos", GID: gid, CreatedAt: time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC),
		Dev: 2049, Ino: 12, MountRoot: "/srv/photos"}
}

// Folders and folder_gids round-trip; folder_gids keeps its order (P24).
func TestFoldersRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.yaml")
	s := New()
	s.FolderGIDs = []int{60000, 60001, 60005}
	ad := goodFolder(1000)
	ad.Adopted, ad.Path, ad.MountRoot = true, "/srv/music", "/srv/music"
	owner := 1000
	f := goodFolder(60001)
	f.WriteConfirmed = map[string]bool{"samba/share": true}
	f.LastApply = &FolderApply{At: f.CreatedAt, Files: "rw", OwnerUID: &owner, Snapshot: "photos/20261103T000000Z.ndjson.gz"}
	s.Folders = map[string]Folder{"photos": f, "music": ad}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.FolderGIDs, s.FolderGIDs) || !reflect.DeepEqual(got.Folders, s.Folders) {
		t.Errorf("round trip:\n%+v\n%+v", got.Folders, got.FolderGIDs)
	}
}

// A corrupt folders / folder_gids entry stops the Hub at start (P24).
func TestLoadRefusesCorruptFolders(t *testing.T) {
	for name, mut := range map[string]func(s *AppState){
		"gid out of range":  func(s *AppState) { s.FolderGIDs = append(s.FolderGIDs, 61000) },
		"gids unsorted":     func(s *AppState) { s.FolderGIDs = []int{60001, 60000} },
		"gids duplicate":    func(s *AppState) { s.FolderGIDs = []int{60000, 60000} },
		"gid not allocated": func(s *AppState) { s.FolderGIDs = []int{60001} },
		"bad id":            func(s *AppState) { s.Folders["Photos"] = s.Folders["photos"]; delete(s.Folders, "photos") },
		"same gid twice":    func(s *AppState) { g := goodFolder(60000); g.Path = "/srv/b"; s.Folders["b"] = g },
		"adopted hub gid":   func(s *AppState) { g := goodFolder(10001); g.Adopted, g.Path = true, "/srv/b"; s.Folders["b"] = g },
		"adopted in range":  func(s *AppState) { g := goodFolder(60000); g.Adopted = true; s.Folders["photos"] = g },
		"unclean path":      func(s *AppState) { g := goodFolder(60000); g.Path = "/srv/photos/"; s.Folders["photos"] = g },
		"relative path":     func(s *AppState) { g := goodFolder(60000); g.Path = "srv"; s.Folders["photos"] = g },
		"colon in path":     func(s *AppState) { g := goodFolder(60000); g.Path = "/srv/a:b"; s.Folders["photos"] = g },
		"no inode":          func(s *AppState) { g := goodFolder(60000); g.Ino = 0; s.Folders["photos"] = g },
		"no mount root":     func(s *AppState) { g := goodFolder(60000); g.MountRoot = ""; s.Folders["photos"] = g },
		"empty name":        func(s *AppState) { g := goodFolder(60000); g.Name = ""; s.Folders["photos"] = g },
		"control in name":   func(s *AppState) { g := goodFolder(60000); g.Name = "a\nb"; s.Folders["photos"] = g },
		"long description": func(s *AppState) {
			g := goodFolder(60000)
			g.Description = strings.Repeat("x", 501)
			s.Folders["photos"] = g
		},
		"bad last_apply mode": func(s *AppState) {
			g := goodFolder(60000)
			g.LastApply = &FolderApply{Files: "x"}
			s.Folders["photos"] = g
		},
	} {
		p := filepath.Join(t.TempDir(), "state.yaml")
		s := New()
		s.FolderGIDs = []int{60000}
		s.Folders = map[string]Folder{"photos": goodFolder(60000)}
		mut(s)
		if err := s.Save(p); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("%s: Load = %v, want a refusal", name, err)
		}
	}
	// The good one loads.
	p := filepath.Join(t.TempDir(), "state.yaml")
	os.WriteFile(p, []byte("folder_gids: [60000]\nfolders:\n  photos: {name: P, path: /srv/photos, gid: 60000, dev: 1, ino: 2, mount_root: /}\n"), 0o600)
	if _, err := Load(p); err != nil {
		t.Errorf("good folder: %v", err)
	}
}

func TestValidAdoptedGID(t *testing.T) {
	for gid, ok := range map[int]bool{999: false, 1000: true, 65534: false, 60000: false, 60500: false, 60999: false, 61000: true, 10001: false, 10002: false, 10003: true, 1 << 31: false} {
		if (ValidAdoptedGID(gid) == "") != ok {
			t.Errorf("%d: %q", gid, ValidAdoptedGID(gid))
		}
	}
}
