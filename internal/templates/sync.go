package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/portcullis/hub/internal/fsutil"
)

// SyncFiles publishes a template's support files (config templates,
// entrypoint scripts) to <root>/<id>/ so that relative bind mounts like
// ./templates/<id>/setup.sh resolve on the HOST: compose runs with
// --project-directory = the core checkout on the host, while the template
// itself lives in the Hub's data volume, which the host daemon can't address
// by path. Core mounts ./templates read-write at <root> for this.
//
// The copy is staged next to the target and swapped in by rename, so a
// running container never sees a half-written directory. Symlinks and
// special files are skipped (never follow out of the template); .git is
// skipped.
//
// All instances of a template share this copy (contract §3): it lives
// under the template id.
func SyncFiles(t *Template, root string) error {
	id := t.TemplateID
	if id == "" {
		id = t.ID
	}
	if !ValidID(id) {
		return os.ErrInvalid
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	dest := filepath.Join(root, id)
	// Sibling instances share dest and may be running from it: leave it
	// alone when it already holds exactly the template's files.
	if src, err := treeHash(t.Path); err == nil {
		if cur, err := treeHash(dest); err == nil && cur == src {
			return nil
		}
	}
	stage, err := os.MkdirTemp(root, "."+id+".stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	err = filepath.WalkDir(t.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(t.Path, path)
		if rel == "." {
			return nil
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(stage, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0755)
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			if err := fsutil.CopyFile(path, target); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode().Perm())
		default:
			return nil
		}
	})
	if err != nil {
		return err
	}
	old := dest + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			return err
		}
	}
	if err := os.Rename(stage, dest); err != nil {
		os.Rename(old, dest) // best-effort rollback
		return err
	}
	return os.RemoveAll(old)
}

// treeHash hashes what SyncFiles copies of dir: every directory and
// regular file (relative path; files also permission bits and content) in walk order,
// .git, symlinks and special files skipped.
func treeHash(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if rel == "." {
			return nil
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			// Copies are always 0755: only the name counts.
			fmt.Fprintf(h, "d %q\n", filepath.ToSlash(rel))
		case d.Type().IsRegular():
			fmt.Fprintf(h, "f %q %o %d\n", filepath.ToSlash(rel), info.Mode().Perm(), info.Size())
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(h, f); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
