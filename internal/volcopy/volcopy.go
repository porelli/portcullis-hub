// Package volcopy is the helper side of the Kubernetes helper pods and
// init containers (contract §6 "On Kubernetes", §3.4, §13.7): a volume
// as a tar out and in, the K4 seed copy and the mounted .rev.
package volcopy

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/portcullis/hub/internal/runtime/archive"
)

// Rev is <dir>/.rev (trimmed); an error when it is missing.
func Rev(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, ".rev"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Out writes dir as a tar on w in the "./" form (root "./",
// children "./x"; archive.Normalize reads it): owners, modes and
// symlinks kept, a link never followed; anything but files, directories
// and symlinks refuses the copy.
func Out(dir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	root := filepath.Clean(dir)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		link := ""
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		case info.Mode().IsRegular(), info.IsDir():
		default:
			return fmt.Errorf("%s: not a file, directory or symlink", p)
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		hdr.Name = "./"
		if rel != "." {
			hdr.Name += filepath.ToSlash(rel)
			if info.IsDir() {
				hdr.Name += "/"
			}
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			hdr.Uid, hdr.Gid = int(st.Uid), int(st.Gid)
		}
		hdr.Uname, hdr.Gname = "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// In extracts a tar from r into dir: any of the archive forms
// (archive.Names: "<base>/…", "/…", "./…" or bare names, the base taken
// from the first entry). Fail closed: every entry is resolved beneath
// dir through an os.Root and no symlink is ever followed — a path
// component that is a symlink (from the archive or already on the
// volume) refuses the copy, an entry whose path is an earlier entry's
// (or a link's) refuses it, ".." refuses it, hard links point inside
// only; modes are set by fchmod on a descriptor opened O_NOFOLLOW,
// owners by lchown.
func In(dir string, r io.Reader) error {
	root, err := os.OpenRoot(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(r)
	var an *archive.Names
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if an == nil {
			base := filepath.Clean(dir)
			if first, rest, _ := strings.Cut(strings.TrimPrefix(hdr.Name, "./"), "/"); first != "" && first != "." && rest == "" && hdr.Typeflag == tar.TypeDir {
				base = "/" + first
			}
			an = archive.NewNames(base)
		}
		rel, err := an.Rel(hdr)
		if err != nil {
			return err
		}
		rel = path.Clean(rel)
		if rel == ".." || strings.HasPrefix(rel, "../") || path.IsAbs(rel) {
			return fmt.Errorf("entry %q escapes the volume", hdr.Name)
		}
		if seen[rel] {
			return fmt.Errorf("entry %q appears twice", hdr.Name)
		}
		seen[rel] = true
		if err := noSymlinkParents(root, rel); err != nil {
			return fmt.Errorf("entry %q: %w", hdr.Name, err)
		}
		if err := extract(root, rel, hdr, tr, an); err != nil {
			return fmt.Errorf("entry %q: %w", hdr.Name, err)
		}
	}
}

// noSymlinkParents: no component above rel is a symlink (Lstat each).
func noSymlinkParents(root *os.Root, rel string) error {
	if rel == "." {
		return nil
	}
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		fi, err := root.Lstat(strings.Join(parts[:i], "/"))
		if errors.Is(err, fs.ErrNotExist) {
			return nil // created below in order: a missing parent fails the create
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return errors.New("a parent is a symlink")
		}
		if !fi.IsDir() {
			return errors.New("a parent is not a directory")
		}
	}
	return nil
}

func extract(root *os.Root, rel string, hdr *tar.Header, tr io.Reader, an *archive.Names) error {
	cur, lerr := root.Lstat(rel)
	exists := lerr == nil
	if exists && cur.Mode()&fs.ModeSymlink != 0 {
		return errors.New("its path is a symlink")
	}
	mode := fs.FileMode(hdr.Mode).Perm() | setBits(hdr.Mode)
	switch hdr.Typeflag {
	case tar.TypeDir:
		if exists && !cur.IsDir() {
			return errors.New("its path is not a directory")
		}
		if !exists {
			if err := root.Mkdir(rel, 0o700); err != nil {
				return err
			}
		}
		return setOwnerMode(root, rel, hdr, mode, syscall.O_DIRECTORY)
	case tar.TypeReg:
		if exists && !cur.Mode().IsRegular() {
			return errors.New("its path is not a regular file")
		}
		f, err := root.OpenFile(rel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return setOwnerMode(root, rel, hdr, mode, 0)
	case tar.TypeSymlink:
		if exists {
			return errors.New("its path exists")
		}
		if err := root.Symlink(hdr.Linkname, rel); err != nil {
			return err
		}
		if err := root.Lchown(rel, hdr.Uid, hdr.Gid); err != nil && !errors.Is(err, fs.ErrPermission) {
			return err
		}
		return nil
	case tar.TypeLink:
		if exists {
			return errors.New("its path exists")
		}
		target, err := an.Link(hdr.Linkname)
		if err != nil {
			return err
		}
		if err := noSymlinkParents(root, target); err != nil {
			return fmt.Errorf("link target: %w", err)
		}
		if fi, err := root.Lstat(target); err != nil || !fi.Mode().IsRegular() {
			return errors.New("a hard link to something other than a file of the volume")
		}
		return root.Link(target, rel)
	}
	return fmt.Errorf("type %c refused", hdr.Typeflag)
}

// setOwnerMode chowns rel (no follow) and sets its mode by fchmod on an
// O_NOFOLLOW descriptor.
func setOwnerMode(root *os.Root, rel string, hdr *tar.Header, mode fs.FileMode, flag int) error {
	if err := root.Lchown(rel, hdr.Uid, hdr.Gid); err != nil && !errors.Is(err, fs.ErrPermission) {
		return err
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|flag, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(mode)
}

// setBits are a tar mode's setuid / setgid / sticky bits.
func setBits(m int64) fs.FileMode {
	var out fs.FileMode
	if m&0o4000 != 0 {
		out |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		out |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		out |= fs.ModeSticky
	}
	return out
}

// Seed copies src/. into dst when dst has no entries but lost+found
// (modes and symlinks kept), writing .portcullis-seeded last; a dst
// that already has it is left alone.
func Seed(src, dst string) error {
	marker := filepath.Join(dst, ".portcullis-seeded")
	if _, err := os.Lstat(marker); err == nil {
		return nil
	}
	ents, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.Name() != "lost+found" {
			return nil // not empty: never overwritten
		}
	}
	if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
		return os.WriteFile(marker, nil, 0o644)
	}
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		t := filepath.Join(dst, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(l, t)
		case info.IsDir():
			if err := os.Mkdir(t, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(t, info.Mode().Perm())
		case info.Mode().IsRegular():
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(t, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
			return os.Chmod(t, info.Mode().Perm())
		}
		return nil // devices, sockets, fifos: not seeded
	})
	if err != nil {
		return err
	}
	return os.WriteFile(marker, nil, 0o644)
}
