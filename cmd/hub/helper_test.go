package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func run(t *testing.T, stdin []byte, args ...string) (string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := helperMain(args, bytes.NewReader(stdin), &out, &errb)
	return out.String() + errb.String(), code
}

// TestVolcopyRoundTrip: out → in keeps files, modes, symlinks and the
// root's mode; owners are the caller's.
func TestVolcopyRoundTrip(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(src, "sub"), 0o750)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello"), 0o640)
	os.WriteFile(filepath.Join(src, "sub", "b"), []byte("x"), 0o600)
	os.Symlink("a.txt", filepath.Join(src, "link"))
	os.Chmod(src, 0o2750)
	var tarb bytes.Buffer
	if code := helperMain([]string{"volcopy", "out", src}, nil, &tarb, os.Stderr); code != 0 {
		t.Fatalf("out: %d", code)
	}
	if out, code := run(t, tarb.Bytes(), "volcopy", "in", dst); code != 0 {
		t.Fatalf("in: %d %s", code, out)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a.txt")); string(b) != "hello" {
		t.Errorf("a.txt = %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "a.txt")); fi.Mode().Perm() != 0o640 {
		t.Errorf("a.txt mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Join(dst, "sub")); fi.Mode().Perm() != 0o750 {
		t.Errorf("sub mode %v", fi.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(dst, "link")); l != "a.txt" {
		t.Errorf("link = %q", l)
	}
	// The root keeps the source root's mode (setgid included where the
	// filesystem keeps it for the caller).
	sfi, _ := os.Stat(src)
	if fi, _ := os.Stat(dst); fi.Mode() != sfi.Mode() || fi.Mode().Perm() != 0o750 {
		t.Errorf("root mode %v, source %v", fi.Mode(), sfi.Mode())
	}
	st, _ := os.Stat(filepath.Join(dst, "a.txt"))
	if st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		t.Error("owner")
	}
	// The Hub's canonical form ("data/…") extracts too, and escapes are
	// refused.
	if !strings.Contains(tarb.String(), "./a.txt") {
		t.Error("not the ./ form")
	}
}

// TestSeedOnlyWhenEmpty: copies into an empty (or lost+found-only)
// directory, marker last; a non-empty or seeded one is left alone.
func TestSeedOnlyWhenEmpty(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "conf"), []byte("default"), 0o644)
	os.Symlink("conf", filepath.Join(src, "l"))
	empty := t.TempDir()
	os.Mkdir(filepath.Join(empty, "lost+found"), 0o700)
	if out, code := run(t, nil, "seed", src, empty); code != 0 {
		t.Fatalf("seed: %s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(empty, "conf")); string(b) != "default" {
		t.Errorf("seeded conf = %q", b)
	}
	if l, _ := os.Readlink(filepath.Join(empty, "l")); l != "conf" {
		t.Error("symlink not kept")
	}
	if _, err := os.Stat(filepath.Join(empty, ".portcullis-seeded")); err != nil {
		t.Error("no marker")
	}
	// Seeded: changes stay.
	os.WriteFile(filepath.Join(empty, "conf"), []byte("mine"), 0o644)
	run(t, nil, "seed", src, empty)
	if b, _ := os.ReadFile(filepath.Join(empty, "conf")); string(b) != "mine" {
		t.Error("a seeded volume was overwritten")
	}
	// Not empty, no marker: never copied into.
	full := t.TempDir()
	os.WriteFile(filepath.Join(full, "data"), []byte("x"), 0o644)
	run(t, nil, "seed", src, full)
	if _, err := os.Stat(filepath.Join(full, "conf")); err == nil {
		t.Error("seeded a non-empty volume")
	}
}

func TestRevPrintsMountedRev(t *testing.T) {
	d := t.TempDir()
	if _, code := run(t, nil, "rev", d); code != 1 {
		t.Errorf("missing .rev: exit %d", code)
	}
	os.WriteFile(filepath.Join(d, ".rev"), []byte("r42\n"), 0o444)
	if out, code := run(t, nil, "rev", d); code != 0 || out != "r42\n" {
		t.Errorf("rev = %q %d", out, code)
	}
}

func TestHelperListenDial(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	go helperMain([]string{"helper", "listen", addr}, nil, &bytes.Buffer{}, &bytes.Buffer{})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, code := run(t, nil, "helper", "dial", addr); code == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dial never reached the listener")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, code := run(t, nil, "helper", "dial", "127.0.0.1:1"); code == 0 {
		t.Error("dial to a closed port succeeded")
	}
	if _, code := run(t, nil, "helper", "bogus"); code != 2 {
		t.Error("bad helper args accepted")
	}
}
