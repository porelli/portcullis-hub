package volcopy

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

type entry struct {
	name, link string
	typ        byte
	body       string
	mode       int64
}

func mkTar(t *testing.T, es ...entry) *bytes.Reader {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		m := e.mode
		if m == 0 {
			m = 0o755
		}
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: m, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return bytes.NewReader(b.Bytes())
}

// outside is a directory beside the volume whose mode and content must
// never change.
func setup(t *testing.T) (vol, outside string) {
	base := t.TempDir()
	vol, outside = filepath.Join(base, "vol"), filepath.Join(base, "outside")
	os.Mkdir(vol, 0o755)
	os.Mkdir(outside, 0o700)
	return vol, outside
}

func untouched(t *testing.T, name, outside string) {
	t.Helper()
	fi, err := os.Stat(outside)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: the outside directory changed: %v %v", name, fi.Mode(), err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("%s: wrote outside: %v", name, ents)
	}
}

// Every escape through a symlink is refused and writes nothing outside.
func TestInRefusesSymlinkEscapes(t *testing.T) {
	cases := map[string]func(vol, outside string) *bytes.Reader{
		"a dir entry over a symlink to outside (archive)": func(vol, outside string) *bytes.Reader {
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./l", link: outside, typ: tar.TypeSymlink}, entry{name: "./l/", typ: tar.TypeDir, mode: 0o777})
		},
		"a dir entry over a symlink already on the volume": func(vol, outside string) *bytes.Reader {
			os.Symlink(outside, filepath.Join(vol, "l"))
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./l/", typ: tar.TypeDir, mode: 0o777})
		},
		"a file under a symlinked parent (on the volume)": func(vol, outside string) *bytes.Reader {
			os.Symlink(outside, filepath.Join(vol, "l"))
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./l/x", typ: tar.TypeReg, body: "pwned"})
		},
		"a file under a symlinked parent (archive)": func(vol, outside string) *bytes.Reader {
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./l", link: outside, typ: tar.TypeSymlink}, entry{name: "./l/x", typ: tar.TypeReg, body: "pwned"})
		},
		"a symlink then a same-name dir": func(vol, outside string) *bytes.Reader {
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./d", link: outside, typ: tar.TypeSymlink}, entry{name: "./d/", typ: tar.TypeDir, mode: 0o777})
		},
		"a file over a symlink": func(vol, outside string) *bytes.Reader {
			os.Symlink(filepath.Join(outside, "f"), filepath.Join(vol, "f"))
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./f", typ: tar.TypeReg, body: "pwned"})
		},
		"..": func(vol, outside string) *bytes.Reader {
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./../outside/x", typ: tar.TypeReg, body: "pwned"})
		},
		"a nested ..": func(vol, outside string) *bytes.Reader {
			return mkTar(t, entry{name: "data/", typ: tar.TypeDir}, entry{name: "data/a/../../outside/x", typ: tar.TypeReg, body: "pwned"})
		},
		"a duplicate entry": func(vol, outside string) *bytes.Reader {
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./x", typ: tar.TypeReg, body: "a"}, entry{name: "./x", typ: tar.TypeReg, body: "b"})
		},
		"a hard link to outside": func(vol, outside string) *bytes.Reader {
			return mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./h", link: "../outside/x", typ: tar.TypeLink})
		},
	}
	for name, mk := range cases {
		vol, outside := setup(t)
		if err := In(vol, mk(vol, outside)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		untouched(t, name, outside)
	}
}

// The volume root's mode and the canonical form still extract.
func TestInCanonical(t *testing.T) {
	vol, _ := setup(t)
	err := In(vol, mkTar(t, entry{name: "data/", typ: tar.TypeDir, mode: 0o750}, entry{name: "data/sub/", typ: tar.TypeDir, mode: 0o700},
		entry{name: "data/sub/f", typ: tar.TypeReg, body: "x", mode: 0o640}, entry{name: "data/l", link: "sub/f", typ: tar.TypeSymlink}))
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(vol); fi.Mode().Perm() != 0o750 {
		t.Errorf("root mode %v", fi.Mode())
	}
	if b, _ := os.ReadFile(filepath.Join(vol, "sub", "f")); string(b) != "x" {
		t.Errorf("f = %q", b)
	}
	if l, _ := os.Readlink(filepath.Join(vol, "l")); l != "sub/f" {
		t.Errorf("l = %q", l)
	}
}

// TestSeedFileRetried: a retried seed-self (an attempt killed mid-copy)
// removes the stale temp files first, keeps an identical hub as it is,
// and replaces a different one (removed before the new copy), leaving
// only hub behind.
func TestSeedFileRetried(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	src := filepath.Join(srcDir, "hub")
	os.WriteFile(src, []byte("binary v2"), 0o755)
	entries := func() []string {
		es, _ := os.ReadDir(dst)
		var out []string
		for _, e := range es {
			out = append(out, e.Name())
		}
		return out
	}
	// A killed attempt's temp files and an old binary.
	os.WriteFile(filepath.Join(dst, ".hub.tmp-111"), []byte("partial"), 0o600)
	os.WriteFile(filepath.Join(dst, ".hub.tmp-222"), []byte("partial"), 0o600)
	os.WriteFile(filepath.Join(dst, "hub"), []byte("binary v1, longer"), 0o555)
	if err := seedFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if got := entries(); len(got) != 1 || got[0] != "hub" {
		t.Fatalf("entries %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "hub")); string(b) != "binary v2" {
		t.Fatalf("hub %q", b)
	}
	// Identical: kept as it is (the same file, not rewritten).
	before, _ := os.Stat(filepath.Join(dst, "hub"))
	os.WriteFile(filepath.Join(dst, ".hub.tmp-333"), nil, 0o600)
	if err := seedFile(src, dst); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(filepath.Join(dst, "hub"))
	if !os.SameFile(before, after) {
		t.Error("an identical hub was copied again")
	}
	if got := entries(); len(got) != 1 {
		t.Errorf("entries %v", got)
	}
	// Same size, other bytes: replaced.
	os.WriteFile(src, []byte("binary v3"), 0o755)
	if err := seedFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "hub")); string(b) != "binary v3" {
		t.Errorf("same size, other bytes: hub %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "hub")); fi.Mode().Perm() != 0o555 {
		t.Errorf("mode %o", fi.Mode().Perm())
	}
}
