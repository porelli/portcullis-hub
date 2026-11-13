package hub

import (
	"archive/tar"
	"fmt"
	"io"
	"path"
	"strings"
)

// Engine archives (GET /containers/{id}/archive?path=<dir>, the docker cp
// format) name entries differently per engine:
//
//   - Docker: the directory's base name, then its children under it
//     ("data/", "data/x", "data/sub/y"); "./" prefixes are tolerated.
//   - Podman (buildah's copier, rootless, a volume or bind mount):
//     the root directory as "/" — the copy runs chrooted at the volume's
//     mount point, so the kept directory name is filepath.Base("/") — and
//     its children joined to it ("/x", "/sub/y"). Hard link names follow
//     the same form.
//   - "./" or "." as the root, children "./x" or "x" (a tar the Hub or
//     the fixer wrote itself).
//
// archiveNames maps every entry to its path relative to the archived
// directory ("." = the directory itself), the same for every engine. The
// first entry fixes the archive's form; anything else is refused (fail
// closed): another form, an absolute path outside the form, "..", a
// root entry that isn't a directory, a second root, a hard link whose
// target isn't inside the directory. Symlinks are kept as entries
// (their targets are never followed by the Hub).
type archiveNames struct {
	base string // the archived directory's base name ("data", "out")
	form int    // 0 = not yet known
	root bool   // the root entry was seen
}

const (
	formBase  = iota + 1 // Docker: "<base>/…"
	formSlash            // Podman: "/" then "/…"
	formDot              // "./…" or bare relative names
)

func newArchiveNames(dir string) *archiveNames {
	return &archiveNames{base: path.Base(path.Clean("/" + dir))}
}

// rel is the entry hdr's path relative to the archived directory.
func (a *archiveNames) rel(hdr *tar.Header) (string, error) {
	r, err := a.relName(hdr.Name, hdr.Typeflag == tar.TypeDir)
	if err != nil {
		return "", err
	}
	if r == "." {
		if a.root {
			return "", fmt.Errorf("archive entry %q is a second root", clipRunes(hdr.Name, 80))
		}
		a.root = true
	}
	return r, nil
}

// link is hard link target name's path relative to the directory (it
// must be an entry inside it, never the root).
func (a *archiveNames) link(name string) (string, error) {
	r, err := a.relName(name, false)
	if err != nil || r == "." {
		return "", fmt.Errorf("archive link target %q is outside the directory", clipRunes(name, 80))
	}
	return r, nil
}

func (a *archiveNames) relName(name string, dir bool) (string, error) {
	bad := func() (string, error) {
		return "", fmt.Errorf("archive entry %q is outside the directory", clipRunes(name, 80))
	}
	if name == "" || strings.ContainsRune(name, 0) {
		return bad()
	}
	for _, c := range strings.Split(strings.Trim(name, "/"), "/") {
		if c == ".." {
			return bad()
		}
	}
	trimmed := strings.TrimRight(name, "/")
	if a.form == 0 {
		// The first entry is the root: it fixes the form. Anything else
		// first (a child, an absolute file) is refused.
		dot := strings.TrimPrefix(trimmed, "./")
		switch {
		case trimmed == "" && name != "":
			a.form = formSlash
		case trimmed == ".":
			a.form = formDot
		case dot == a.base:
			a.form = formBase
		default:
			return bad()
		}
	}
	var rest string
	switch a.form {
	case formSlash:
		if !strings.HasPrefix(name, "/") {
			return bad()
		}
		rest = strings.TrimLeft(trimmed, "/")
	case formBase:
		t := strings.TrimPrefix(trimmed, "./")
		if t != a.base && !strings.HasPrefix(t, a.base+"/") {
			return bad()
		}
		rest = strings.TrimPrefix(strings.TrimPrefix(t, a.base), "/")
	case formDot:
		if strings.HasPrefix(name, "/") {
			return bad()
		}
		rest = strings.TrimPrefix(trimmed, "./")
		if rest == "." {
			rest = ""
		}
	}
	if rest == "" {
		if !dir {
			return "", fmt.Errorf("archive entry %q names the directory but isn't one", clipRunes(name, 80))
		}
		return ".", nil
	}
	if c := path.Clean(rest); c != rest || strings.HasPrefix(c, "/") || c == "." {
		return bad()
	}
	return rest, nil
}

// normalizeArchive copies the engine archive r of directory dir to w in
// the Hub's canonical form — "<base>/" and "<base>/<rel>", Docker's —
// checking every entry with check (nil: none; it sees the relative path).
// Hard link names are rewritten the same way.
func normalizeArchive(r io.Reader, w io.Writer, dir string, check func(hdr *tar.Header, rel string) error) error {
	an := newArchiveNames(dir)
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading the archive: %w", err)
		}
		rel, err := an.rel(hdr)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(hdr, rel); err != nil {
				return err
			}
		}
		out := *hdr
		out.Name = canonicalName(an.base, rel, hdr.Typeflag == tar.TypeDir)
		if hdr.Typeflag == tar.TypeLink {
			lr, err := an.link(hdr.Linkname)
			if err != nil {
				return err
			}
			out.Linkname = canonicalName(an.base, lr, false)
		}
		// The PAX path / linkpath records would override the new names.
		if len(hdr.PAXRecords) > 0 {
			out.PAXRecords = map[string]string{}
			for k, v := range hdr.PAXRecords {
				if k != "path" && k != "linkpath" {
					out.PAXRecords[k] = v
				}
			}
		}
		if err := tw.WriteHeader(&out); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}
	if !an.root {
		return fmt.Errorf("the archive has no root directory entry")
	}
	return tw.Close()
}

func canonicalName(base, rel string, dir bool) string {
	n := base
	if rel != "." {
		n = base + "/" + rel
	}
	if dir {
		n += "/"
	}
	return n
}

// relativeArchive copies canonical archive r ("<base>/…") to w with names
// relative to the directory ("./" for the root, "./<rel>"): what an
// extract at the directory itself takes (Podman resolves only a target
// inside a volume or bind mount to it: an extract at "/" would write
// into the helper's own root filesystem).
func relativeArchive(r io.Reader, w io.Writer, dir string) error {
	an := newArchiveNames(dir)
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading the archive: %w", err)
		}
		rel, err := an.rel(hdr)
		if err != nil {
			return err
		}
		out := *hdr
		if rel == "." {
			out.Name = "./"
		} else {
			out.Name = "./" + rel
			if hdr.Typeflag == tar.TypeDir {
				out.Name += "/"
			}
		}
		if hdr.Typeflag == tar.TypeLink {
			lr, err := an.link(hdr.Linkname)
			if err != nil {
				return err
			}
			out.Linkname = "./" + lr
		}
		if len(hdr.PAXRecords) > 0 {
			out.PAXRecords = map[string]string{}
			for k, v := range hdr.PAXRecords {
				if k != "path" && k != "linkpath" {
					out.PAXRecords[k] = v
				}
			}
		}
		if err := tw.WriteHeader(&out); err != nil {
			return err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return err
		}
	}
	if !an.root {
		return fmt.Errorf("the archive has no root directory entry")
	}
	return tw.Close()
}
