package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRemoveAllRefusesASwappedDirectory: the walk empties a directory
// only through a root that is the directory it stat'ed (a directory
// swapped for a symlink or another directory mid-walk is left alone).
func TestRemoveAllRefusesASwappedDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"a", "b"} {
		os.Mkdir(filepath.Join(dir, d), 0o700)
		os.WriteFile(filepath.Join(dir, d, "f"), []byte("x"), 0o600)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fiB, err := r.Lstat("b")
	if err != nil {
		t.Fatal(err)
	}
	if err := removeChildren(r, "a", fiB); err == nil {
		t.Fatal("emptied a directory other than the one stat'ed")
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "f")); err != nil {
		t.Errorf("a/f removed: %v", err)
	}
	// A symlink in the tree is removed, its target kept.
	os.Symlink(filepath.Join(dir, "b"), filepath.Join(dir, "a", "link"))
	if err := RemoveAll(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b", "f")); err != nil {
		t.Errorf("the link's target was emptied: %v", err)
	}
	for _, bad := range []string{dir + "/.", dir + "/.."} {
		if err := RemoveAll(bad); err == nil {
			t.Errorf("RemoveAll(%q) accepted", bad)
		}
	}
	root := &Root{r: r}
	if err := root.RemoveAll("."); err == nil {
		t.Error("Root.RemoveAll(\".\") accepted")
	}
}
