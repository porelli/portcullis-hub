package agentapi

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/templates"
)

// A bundle (PUT /v1/projects/{id}/bundle) is everything a worker needs to
// run an instance's compose project from its own disk: the compose files,
// env, overrides, the template's files, the instance's appfiles and the
// CA bundle, as a tar whose regular files the manifest lists with their
// sha256, mode and size.

// ValidBundlePath: a bundle path is relative, canonical (path.Clean of
// itself, no "." or ".." segment, no empty segment, no trailing "/"), at
// most MaxBundleName bytes, with no backslash, control character or
// invalid UTF-8.
func ValidBundlePath(p string) bool {
	if p == "" || len(p) > MaxBundleName || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	if !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if templates.IsControlRune(r) {
			return false
		}
	}
	return true
}

// ValidateManifest checks m before any byte of the tar is read: the
// instance id, each path, each entry (64 lower-case hex digits, mode only
// permission bits, size ≥ 0), no file below another file, and the sizes'
// total within maxBytes.
func ValidateManifest(m BundleManifest, maxBytes int64) error {
	if err := ValidInstance(m.Instance); err != nil {
		return fmt.Errorf("bundle manifest: %w", err)
	}
	if len(m.Files) == 0 {
		return errors.New("bundle manifest: no files")
	}
	if len(m.Files) > MaxBundleEntries {
		return fmt.Errorf("bundle manifest: more than %d files", MaxBundleEntries)
	}
	var total int64
	for _, p := range sortedFiles(m.Files) {
		e := m.Files[p]
		switch {
		case !ValidBundlePath(p):
			return fmt.Errorf("bundle manifest: path %q is not a clean relative path", clip(p))
		case !servers.ValidSHA256Hex(e.SHA256):
			return fmt.Errorf("bundle manifest: %s: sha256 must be 64 lower-case hex digits", clip(p))
		case e.Mode&^0o777 != 0:
			return fmt.Errorf("bundle manifest: %s: mode %#o has more than permission bits", clip(p), e.Mode)
		case e.Size < 0:
			return fmt.Errorf("bundle manifest: %s: negative size", clip(p))
		}
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			if _, file := m.Files[dir]; file {
				return fmt.Errorf("bundle manifest: %s is below the file %s", clip(p), clip(dir))
			}
		}
		total += e.Size
		if total > maxBytes {
			return fmt.Errorf("bundle manifest: files over the %d-byte cap", maxBytes)
		}
	}
	return nil
}

func sortedFiles(m map[string]FileEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func clip(s string) string {
	r := []rune(strings.ToValidUTF8(s, "?"))
	if len(r) > 80 {
		return string(r[:79]) + "…"
	}
	return string(r)
}

// countingReader fails once more than max bytes were read.
type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

// Read delivers at most max bytes in all, then only the error (sticky:
// io.ReadFull would drop an error that comes with a full buffer).
func (c *countingReader) Read(p []byte) (int, error) {
	over := fmt.Errorf("bundle: over the %d-byte cap", c.max)
	if c.n > c.max {
		return 0, over
	}
	if room := c.max - c.n + 1; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n - int(c.n-c.max), over
	}
	return n, err
}

// verifyingReader is one file's content: it fails instead of ending when
// the content's size or sha256 differ from the manifest's, so a writer
// that reads to EOF never commits a mismatched file.
type verifyingReader struct {
	name string
	r    io.Reader
	want FileEntry
	h    hashWriter
	n    int64
	done bool
	err  error
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	n, err := v.r.Read(p)
	v.n += int64(n)
	v.h.Write(p[:n])
	if v.n > v.want.Size {
		v.err = fmt.Errorf("bundle: %s is larger than the manifest says", clip(v.name))
		return n, v.err
	}
	if err == io.EOF {
		if v.n != v.want.Size {
			v.err = fmt.Errorf("bundle: %s is smaller than the manifest says", clip(v.name))
			return n, v.err
		}
		if hex.EncodeToString(v.h.Sum(nil)) != v.want.SHA256 {
			v.err = fmt.Errorf("bundle: %s: sha256 differs from the manifest", clip(v.name))
			return n, v.err
		}
		v.done = true
	}
	if err != nil && err != io.EOF {
		v.err = err
	}
	return n, err
}

// ReadBundle reads the tar r (at most maxBytes in all, headers included)
// against manifest m and calls write for each regular file, in tar
// order, with its manifest mode and a reader that fails (instead of
// ending) on a size or sha256 mismatch. Refused, before or while writing:
//   - an invalid manifest (ValidateManifest);
//   - any entry type but a regular file or a directory (symlinks, hard
//     links, devices, FIFOs, PAX global headers, sparse files…);
//   - a name that isn't a clean relative path (absolute, "..", "./x",
//     backslashes, control characters), a duplicate, or a path below a
//     file;
//   - a regular file the manifest doesn't list, or whose header mode or
//     size differ from it; a directory the manifest lists as a file;
//   - a manifest file missing from the tar;
//   - more than MaxBundleEntries entries, or more than maxBytes read.
//
// Directories are checked for their names only and never passed to
// write (a writer creates parents itself). Any error refuses the whole
// bundle: write must stage into a fresh directory and the caller commits
// it only when ReadBundle returns nil. An error from write is returned
// as is.
func ReadBundle(r io.Reader, m BundleManifest, maxBytes int64, write func(name string, mode fs.FileMode, data io.Reader) error) error {
	if err := ValidateManifest(m, maxBytes); err != nil {
		return err
	}
	cr := &countingReader{r: r, max: maxBytes}
	tr := tar.NewReader(cr)
	seen := map[string]bool{}
	files := map[string]bool{}
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("bundle: %v", err)
		}
		entries++
		if entries > MaxBundleEntries {
			return fmt.Errorf("bundle: more than %d entries", MaxBundleEntries)
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		default:
			return fmt.Errorf("bundle: entry %q has type %q: only regular files and directories", clip(hdr.Name), hdr.Typeflag)
		}
		name := hdr.Name
		if hdr.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if !ValidBundlePath(name) {
			return fmt.Errorf("bundle: entry %q is not a clean relative path", clip(hdr.Name))
		}
		if seen[name] {
			return fmt.Errorf("bundle: duplicate entry %q", clip(name))
		}
		seen[name] = true
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if files[dir] {
				return fmt.Errorf("bundle: entry %q is below the file %s", clip(name), clip(dir))
			}
		}
		want, listed := m.Files[name]
		if hdr.Typeflag == tar.TypeDir {
			if listed {
				return fmt.Errorf("bundle: %s is a directory, the manifest lists a file", clip(name))
			}
			continue
		}
		if !listed {
			return fmt.Errorf("bundle: %s is not in the manifest", clip(name))
		}
		if hdr.Mode&^0o777 != 0 || uint32(hdr.Mode) != want.Mode {
			return fmt.Errorf("bundle: %s: mode %#o differs from the manifest's %#o", clip(name), hdr.Mode, want.Mode)
		}
		if hdr.Size != want.Size {
			return fmt.Errorf("bundle: %s: size differs from the manifest", clip(name))
		}
		files[name] = true
		vr := &verifyingReader{name: name, r: tr, want: want, h: sha256.New()}
		if err := write(name, fs.FileMode(want.Mode), vr); err != nil {
			return err
		}
		// Whatever write left unread is still verified.
		if _, err := io.Copy(io.Discard, vr); err != nil {
			return err
		}
		if !vr.done {
			return fmt.Errorf("bundle: %s: content not verified", clip(name))
		}
	}
	if cr.n > cr.max {
		return fmt.Errorf("bundle: over the %d-byte cap", cr.max)
	}
	for _, p := range sortedFiles(m.Files) {
		if !files[p] {
			return fmt.Errorf("bundle: %s is in the manifest but not in the tar", clip(p))
		}
	}
	return nil
}
