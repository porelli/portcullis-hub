package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoLargeFilesTracked: no tracked file is over 5 MB (a built binary
// committed by mistake, fix round 1 I1). Skips without git or outside a
// checkout.
func TestNoLargeFilesTracked(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skip("not a git checkout")
	}
	dir := strings.TrimSpace(string(root))
	out, err := exec.Command("git", "-C", dir, "ls-files", "-z").Output()
	if err != nil {
		t.Skip("git ls-files failed")
	}
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" {
			continue
		}
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil && fi.Size() > 5<<20 {
			t.Errorf("%s is tracked and %d bytes (over 5 MB): a build output? untrack it and .gitignore it", f, fi.Size())
		}
	}
}
