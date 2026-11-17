package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProtectedSymlinkIntoRootRefused (final review L9): a protected path
// (AGENT_ENGINE_SOCKET) that is a symlink — or sits behind one — into a
// folder root is compared resolved: refused, though neither its written
// path nor any ancestor is the root.
func TestProtectedSymlinkIntoRootRefused(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(base, "srv")
	out := filepath.Join(base, "home", "u")
	os.MkdirAll(filepath.Join(root, "podman"), 0o755)
	os.MkdirAll(out, 0o755)
	os.WriteFile(filepath.Join(root, "podman", "podman.sock"), nil, 0o600)
	if err := os.Symlink(filepath.Join(root, "podman", "podman.sock"), filepath.Join(out, "docker.sock")); err != nil {
		t.Fatal(err)
	}
	err := CheckProtectedOutsideRoots([]string{filepath.Join(out, "docker.sock")}, []string{root})
	if err == nil || !strings.Contains(err.Error(), "inside the folder root") {
		t.Errorf("a socket linked into a root: %v", err)
	}
	// Behind a linked directory, the socket itself not visible.
	os.Symlink(filepath.Join(root, "podman"), filepath.Join(out, "run"))
	err = CheckProtectedOutsideRoots([]string{filepath.Join(out, "run", "missing.sock")}, []string{root})
	if err == nil || !strings.Contains(err.Error(), "inside the folder root") {
		t.Errorf("a socket behind a linked directory: %v", err)
	}
	// A socket really outside: fine.
	os.WriteFile(filepath.Join(out, "real.sock"), nil, 0o600)
	if err := CheckProtectedOutsideRoots([]string{filepath.Join(out, "real.sock"), filepath.Join(base, "none", "x.sock")}, []string{root}); err != nil {
		t.Errorf("outside: %v", err)
	}
}
