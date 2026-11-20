// Package volcopy is the helper side of the Kubernetes helper pods and
// init containers (contract §6 "On Kubernetes", §3.4, §13.7): a volume
// as a tar out and in, the K4 seed copy and the mounted .rev.
package volcopy

import (
	"archive/tar"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

// docName is a published document's name (contract §4: a key without
// ".json").
var docName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// RevOf is <dir>/.rev-<doc> (trimmed): a published document's revision
// in a projected directory several documents share (contract §4). An
// error when it is missing or doc isn't a plain name.
func RevOf(dir, doc string) (string, error) {
	if !docName.MatchString(doc) {
		return "", fmt.Errorf("%q is not a document name", doc)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".rev-"+doc))
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
// SeedSelf copies the running binary, and nothing else, to <dst>/hub
// (the portcullis-bin init containers, contract §3.4 / §4): through a
// temp file in dst, mode 0555, renamed into place, so a reader never
// sees a partial binary.
func SeedSelf(dst string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	return seedFile(self, dst)
}

// A retried init container (a killed attempt) leaves the emptyDir as it
// was: stale temp files are removed first, an identical hub (size and
// sha256) is kept as it is, and a different one is removed before the
// new copy is written (never two binaries' worth of space).
func seedFile(src, dst string) error {
	stale, err := filepath.Glob(filepath.Join(dst, ".hub.tmp-*"))
	if err != nil {
		return err
	}
	for _, p := range stale {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	target := filepath.Join(dst, "hub")
	same, err := sameFile(src, target)
	if err != nil {
		return err
	}
	if same {
		return nil
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(dst, ".hub.tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o555); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}

// sameFile: b is a regular file with a's size and sha256 (missing: no).
func sameFile(a, b string) (bool, error) {
	bi, err := os.Lstat(b)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	if !bi.Mode().IsRegular() || bi.Size() != ai.Size() {
		return false, nil
	}
	ha, err := fileSum(a)
	if err != nil {
		return false, err
	}
	hb, err := fileSum(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func fileSum(p string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	f, err := os.Open(p)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

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
