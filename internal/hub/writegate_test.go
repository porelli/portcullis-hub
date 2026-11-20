package hub

import (
	"errors"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
)

// TestRunGitAsksTheGate: clone, pull and reset write a checkout and are
// refused while standing by (contract §20.5); rev-parse only reads.
func TestRunGitAsksTheGate(t *testing.T) {
	standBy := errors.New("this Hub is standing by: another Hub is the active writer")
	fsutil.SetWriteGate(func() error { return standBy })
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	dir := t.TempDir()
	for _, args := range [][]string{
		{"clone", "--depth=1", "--", "https://example.invalid/x.git", dir + "/x"},
		{"-C", dir, "pull", "--ff-only"},
		{"-C", dir, "reset", "--keep", "HEAD"},
	} {
		if _, err := runGit(time.Second, args...); !errors.Is(err, standBy) {
			t.Errorf("git %v = %v, want the gate's error", args, err)
		}
	}
	if _, err := runGit(5*time.Second, "-C", dir, "rev-parse", "HEAD"); errors.Is(err, standBy) {
		t.Error("rev-parse was refused")
	}
}
