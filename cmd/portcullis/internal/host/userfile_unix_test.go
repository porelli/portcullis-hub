//go:build !windows

package host

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadUserFileRefusesFIFOAndSymlink (M3): a person's FIFO can't hang
// the root agent, a symlink (to /dev/zero, another user's file) isn't
// followed, and a regular file is capped.
func TestReadUserFileRefusesFIFOAndSymlink(t *testing.T) {
	d := t.TempDir()
	fifo := filepath.Join(d, "authorized_keys2")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := readUserFile(fifo, maxAuthorizedKeys); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was read")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	link := filepath.Join(d, "authorized_keys")
	os.Symlink("/dev/zero", link)
	if _, err := readUserFile(link, maxAuthorizedKeys); err == nil {
		t.Error("a symlink was followed")
	}
	big := filepath.Join(d, "big")
	os.WriteFile(big, make([]byte, 3<<20), 0o600)
	if b, err := readUserFile(big, maxAuthorizedKeys); err != nil || len(b) != maxAuthorizedKeys {
		t.Errorf("big file: %d %v", len(b), err)
	}
}
