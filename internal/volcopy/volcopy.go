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
// from the first entry), confined to dir (no "..", nothing below a
// symlink entry, hard links only inside), owners and modes as in the
// archive.
func In(dir string, r io.Reader) error {
	root := filepath.Clean(dir)
	tr := tar.NewReader(r)
	var an *archive.Names
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if an == nil {
			base := root
			if first, rest, _ := strings.Cut(strings.TrimPrefix(hdr.Name, "./"), "/"); first != "" && first != "." && rest == "" && hdr.Typeflag == tar.TypeDir {
				base = "/" + first
			}
			an = archive.NewNames(base)
		}
		rel, err := an.Rel(hdr)
		if err != nil {
			return err
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		if !strings.HasPrefix(p+"/", root+"/") {
			return fmt.Errorf("entry %q escapes the volume", hdr.Name)
		}
		mode := fs.FileMode(hdr.Mode).Perm()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if fi, err := os.Lstat(p); err == nil && !fi.Mode().IsRegular() {
				if err := os.Remove(p); err != nil {
					return err
				}
			}
			f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
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
		case tar.TypeSymlink:
			os.Remove(p)
			if err := os.Symlink(hdr.Linkname, p); err != nil {
				return err
			}
			if err := os.Lchown(p, hdr.Uid, hdr.Gid); err != nil && !errors.Is(err, fs.ErrPermission) {
				return err
			}
			continue
		case tar.TypeLink:
			target, err := an.Link(hdr.Linkname)
			if err != nil {
				return err
			}
			os.Remove(p)
			if err := os.Link(filepath.Join(root, filepath.FromSlash(target)), p); err != nil {
				return err
			}
			continue
		default:
			return fmt.Errorf("entry %q: type %c refused", hdr.Name, hdr.Typeflag)
		}
		if err := os.Lchown(p, hdr.Uid, hdr.Gid); err != nil && !errors.Is(err, fs.ErrPermission) {
			return err
		}
		if err := os.Chmod(p, mode|setBits(hdr.Mode)); err != nil {
			return err
		}
	}
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
