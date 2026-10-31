package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "new" || fi.Mode().Perm() != 0600 {
		t.Errorf("got %q mode %v", b, fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file left behind (%d entries)", len(entries))
	}
	// Failure (missing dir) leaves nothing behind and reports an error.
	if err := WriteFileAtomic(filepath.Join(dir, "nope", "f"), []byte("x"), 0600); err == nil {
		t.Error("expected error")
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		base, p string
		want    bool
	}{
		{"/project", "/project", true},
		{"/project", "/project/templates/x", true},
		{"/project", "/project/../etc/passwd", false},
		{"/project", "/projectx", false},
		{"/project", "/", false},
		{"/project", "/project/..x", true},
	}
	for _, c := range cases {
		if got := Within(c.base, filepath.Clean(c.p)); got != c.want {
			t.Errorf("Within(%q, %q) = %v", c.base, c.p, got)
		}
	}
}

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.WriteFile(src, []byte("data"), 0644)
	if err := CopyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "data" {
		t.Errorf("got %q", b)
	}
	if err := CopyFile(filepath.Join(dir, "missing"), dst); err == nil {
		t.Error("expected error")
	}
}
