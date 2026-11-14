package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
// special files are skipped (never followed); a symlink that resolves
// outside the template refuses the copy; .git is skipped.
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
	stage, err := os.MkdirTemp(root, "."+id+".stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	base := realPath(t.Path)
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
		case d.Type()&os.ModeSymlink != 0:
			// Never copied or followed; one that resolves outside the
			// template (a chain or a dangling target included) refuses the
			// copy, so nothing outside can ever be published as its file.
			if r := realPath(path); r != base && !strings.HasPrefix(r, base+string(filepath.Separator)) {
				return fmt.Errorf("template %s: %s is a symlink that points outside the template", id, filepath.ToSlash(rel))
			}
			return nil
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

// SyncFilesIfChanged is SyncFiles for a dest sibling instances may be
// running from: it leaves dest alone only if the template's tree hash
// equals published (the hash the caller recorded, outside dest, when it
// last published this template) and dest still holds exactly that: a
// real directory (not a symlink) with no symlinks, special files or .git
// entries, and the same tree hash. dest is writable by others, so nothing
// in it is trusted on its own. Returns the hash to record.
func SyncFilesIfChanged(t *Template, root, published string) (string, error) {
	src, err := treeHash(t.Path)
	if err != nil {
		return "", err
	}
	id := t.TemplateID
	if id == "" {
		id = t.ID
	}
	if published != "" && src == published && ValidID(id) {
		dest := filepath.Join(root, id)
		if plainTree(dest) {
			if cur, err := treeHash(dest); err == nil && cur == src {
				return src, nil
			}
		}
	}
	if err := SyncFiles(t, root); err != nil {
		return "", err
	}
	return src, nil
}

// plainTree reports whether dir is a real directory holding only
// directories and regular files, none named .git.
func plainTree(dir string) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	ok := true
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir && d.Name() == ".git" {
			ok = false
			return filepath.SkipAll
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			ok = false
			return filepath.SkipAll
		}
		return nil
	})
	return ok && err == nil
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

// SourceHash is the hash of t's source tree (treeHash of t.Path): the
// Hub's shared-folder plan hash binds it, so a source sync between a
// preview and its apply is a "setup changed" refusal (T8 M1).
func SourceHash(t *Template) (string, error) { return treeHash(t.Path) }
