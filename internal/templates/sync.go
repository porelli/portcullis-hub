package templates

import (
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
func SyncFiles(t *Template, root string) error {
	if !ValidID(t.ID) {
		return os.ErrInvalid
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	dest := filepath.Join(root, t.ID)
	stage, err := os.MkdirTemp(root, "."+t.ID+".stage-*")
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
