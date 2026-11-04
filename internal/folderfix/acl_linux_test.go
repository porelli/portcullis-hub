//go:build linux

package folderfix

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSetfaclBytes cross-checks setfaclSample against the kernel: where
// setfacl is installed and the temp filesystem supports ACLs, the xattr
// it leaves on a 0644 file is exactly the sample. With CI set a missing
// setfacl or a temp filesystem without ACLs fails the test.
func TestSetfaclBytes(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		setfaclUnavailable(t, "setfacl not installed")
	}
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o644); err != nil { // umask
		t.Fatal(err)
	}
	if out, err := exec.Command(setfacl, "-m", "u:1000:rw,g:60001:rwx,m::rwx", f).CombinedOutput(); err != nil {
		setfaclUnavailable(t, "setfacl: %v: %s", err, out)
	}
	buf := make([]byte, 256)
	n, err := unix.Getxattr(f, XattrAccess, buf)
	if err != nil {
		t.Fatalf("getxattr: %v", err)
	}
	if !bytes.Equal(buf[:n], setfaclSample) {
		t.Fatalf("kernel bytes % x\nsample       % x", buf[:n], setfaclSample)
	}
}
