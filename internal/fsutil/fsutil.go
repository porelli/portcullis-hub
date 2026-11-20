// Package fsutil holds small filesystem helpers shared by the Hub packages.
package fsutil

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomic writes via temp file + fsync + rename so readers never
// observe a partially written file and a crash can't truncate the original.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeAtomic(path, data, perm, -1)
}

// WriteFileAtomicGroup is WriteFileAtomic with the file's group set to
// gid before the rename, so a reader in that group never sees the new
// file without access (a reader that refuses an unreadable file must not
// flap between writes).
func WriteFileAtomicGroup(path string, data []byte, perm os.FileMode, gid int) error {
	return writeAtomic(path, data, perm, gid)
}

func writeAtomic(path string, data []byte, perm os.FileMode, gid int) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if gid >= 0 {
		if err := tmp.Chown(-1, gid); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Asked again before the rename, the one step readers see: a write
	// whose fsync outlived the lead never lands.
	if err := CheckWrite(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Within reports whether path p is inside (or equal to) base.
func Within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// CopyFile copies the contents of src to dest (created or truncated),
// behind the gate (every chunk asks it).
func CopyFile(src, dest string) error {
	if err := CheckWrite(); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
