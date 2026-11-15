package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/portcullis/hub/internal/fsutil"
)

// Writes into directories tenant containers can see (the instance's
// appfiles, bind-mounted read-only into its services) go through os.Root
// rooted at the instance's own directory: nothing resolves outside it,
// and every existing component is checked with Lstat first — a symlink
// or anything but a directory (a file at the end) refuses the write.

// ErrNotPlain: a path component the agent would write through is a
// symlink or of the wrong type.
var ErrNotPlain = errors.New("a symlink or a non-directory is in the way: refused")

// openPlainDir opens dir (absolute) as a Root after checking it with
// Lstat: a directory, never a symlink. create makes it (0750) when absent,
// below an existing plain parent.
func openPlainDir(dir string, create bool) (*os.Root, error) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) && create {
		parent, perr := openPlainDir(filepath.Dir(dir), true)
		if perr != nil {
			return nil, perr
		}
		merr := parent.Mkdir(filepath.Base(dir), 0o750)
		parent.Close()
		if merr != nil && !errors.Is(merr, fs.ErrExist) {
			return nil, merr
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s: %w", dir, ErrNotPlain)
	}
	return os.OpenRoot(dir)
}

// checkRooted checks rel's existing components in r: directories all the
// way, and the last one absent or a regular file.
func checkRooted(r *os.Root, rel string) error {
	rel = path.Clean(rel)
	if rel == "." || strings.HasPrefix(rel, "../") || rel == ".." || path.IsAbs(rel) {
		return fmt.Errorf("%s: not a relative path", rel)
	}
	parts := strings.Split(rel, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		fi, err := r.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		last := i == len(parts)-1
		if fi.Mode()&fs.ModeSymlink != 0 || (!last && !fi.IsDir()) || (last && !fi.Mode().IsRegular()) {
			return fmt.Errorf("%s: %w", p, ErrNotPlain)
		}
	}
	return nil
}

// writeRooted writes rel in r atomically (a temp file in the same
// directory, then a rename), making missing directories 0750; every
// existing component is checked first (checkRooted).
func writeRooted(r *os.Root, rel string, data io.Reader, mode fs.FileMode) error {
	if err := checkRooted(r, rel); err != nil {
		return err
	}
	rel = path.Clean(rel)
	dir := path.Dir(rel)
	if dir != "." {
		parts := strings.Split(dir, "/")
		for i := range parts {
			p := strings.Join(parts[:i+1], "/")
			if err := r.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			if fi, err := r.Lstat(p); err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
				return fmt.Errorf("%s: %w", p, ErrNotPlain)
			}
		}
	}
	tmp := path.Join(dir, ".tmp-"+randomID())
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// The target is checked again just before the rename.
		if err = checkRooted(r, rel); err == nil {
			err = r.Rename(tmp, rel)
		}
	}
	if err != nil {
		r.Remove(tmp)
	}
	return err
}

// appfilesRoot opens <data>/appfiles/<id> as a Root, walking from the
// data dir with Lstat on each component (review L4): appfiles and
// appfiles/<id> must be real directories (made 0750 when absent).
func (a *API) appfilesRoot(id string) (*os.Root, error) {
	data, err := os.OpenRoot(a.cfg.DataDir)
	if err != nil {
		return nil, err
	}
	defer data.Close()
	for _, p := range []string{"appfiles", "appfiles/" + id} {
		fi, err := data.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			if err := data.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, err
			}
			fi, err = data.Lstat(p)
		}
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s: %w", p, ErrNotPlain)
		}
	}
	return data.OpenRoot("appfiles/" + id)
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// writeFileAtomic writes an agent-only file (0600).
func writeFileAtomic(p string, b []byte) error { return fsutil.WriteFileAtomic(p, b, 0o600) }
