package folderfix

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func writeN(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), n), 0o644); err != nil {
		t.Fatal(err)
	}
}

// duSums are Σ st_blocks×512 and Σ st_size of root's tree (lstat, an
// inode once), what the usage report must equal.
func duSums(t *testing.T, root string) (alloc, apparent uint64) {
	t.Helper()
	seen := map[uint64]bool{}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		st := fi.Sys().(*syscall.Stat_t)
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if seen[uint64(st.Ino)] {
			return nil
		}
		seen[uint64(st.Ino)] = true
		alloc += uint64(st.Blocks) * 512
		apparent += uint64(st.Size)
		return nil
	})
	return
}

func usageOf(t *testing.T, root string) *Report {
	t.Helper()
	r, err := Usage(Options{Root: root})
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	return r
}

func TestUsageAllocMatchesBlocks(t *testing.T) {
	root := t.TempDir()
	writeN(t, filepath.Join(root, "a"), 1)
	writeN(t, filepath.Join(root, "b"), 4096)
	os.Mkdir(filepath.Join(root, "d"), 0o755)
	writeN(t, filepath.Join(root, "d", "c"), 1<<20)
	r := usageOf(t, root)
	alloc, apparent := duSums(t, root)
	if r.AllocBytes != alloc || r.ApparentBytes != apparent || r.Files != 3 || r.Dirs != 2 {
		t.Errorf("alloc %d (want %d), apparent %d (want %d), files %d dirs %d", r.AllocBytes, alloc, r.ApparentBytes, apparent, r.Files, r.Dirs)
	}
	if r.Mode != "usage" || r.Partial {
		t.Errorf("report = %+v", r)
	}
}

func TestUsageHardLinksOnce(t *testing.T) {
	root := t.TempDir()
	writeN(t, filepath.Join(root, "f"), 1<<20)
	os.Link(filepath.Join(root, "f"), filepath.Join(root, "g"))
	os.Link(filepath.Join(root, "f"), filepath.Join(root, "h"))
	r := usageOf(t, root)
	alloc, _ := duSums(t, root)
	if r.AllocBytes != alloc || r.HardLinks.N != 3 || r.ApparentBytes < 1<<20 || r.ApparentBytes >= 2<<20 {
		t.Errorf("alloc %d (want %d), apparent %d, hard links %d", r.AllocBytes, alloc, r.ApparentBytes, r.HardLinks.N)
	}
}

func TestUsageSparse(t *testing.T) {
	root := t.TempDir()
	f, err := os.Create(filepath.Join(root, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	f.Write(bytes.Repeat([]byte("y"), 4096))
	f.Truncate(1 << 30)
	f.Close()
	r := usageOf(t, root)
	if r.ApparentBytes < 1<<30 || r.AllocBytes > 64<<20 {
		t.Errorf("sparse: alloc %d, apparent %d", r.AllocBytes, r.ApparentBytes)
	}
}

func TestUsageSymlinkLoopNotFollowed(t *testing.T) {
	root := t.TempDir()
	os.Symlink(".", filepath.Join(root, "a"))
	os.Symlink("a", filepath.Join(root, "b"))
	r := usageOf(t, root)
	if r.Symlinks.N != 2 || r.Dirs != 1 {
		t.Errorf("symlinks %d dirs %d", r.Symlinks.N, r.Dirs)
	}
}

func TestUsageMaxTimePartial(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"a", "b", "c"} {
		writeN(t, filepath.Join(root, n), 10)
	}
	r, err := Usage(Options{Root: root, MaxTime: time.Nanosecond})
	if err != nil || !r.Partial || r.PartialReason != "time" {
		t.Errorf("partial = %v %q, %v", r.Partial, r.PartialReason, err)
	}
}

func TestUsageHardLinkCapPartial(t *testing.T) {
	old := maxHardLinkSet
	maxHardLinkSet = 2
	t.Cleanup(func() { maxHardLinkSet = old })
	root := t.TempDir()
	for _, n := range []string{"a", "b", "c"} {
		writeN(t, filepath.Join(root, n), 10)
		os.Link(filepath.Join(root, n), filepath.Join(root, n+"2"))
	}
	r := usageOf(t, root)
	if !r.Partial || r.PartialReason != "hard_links" {
		t.Errorf("partial = %v %q", r.Partial, r.PartialReason)
	}
}

func TestUsageFailedEntriesExitZero(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 directory")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	os.Mkdir(locked, 0o755)
	writeN(t, filepath.Join(locked, "x"), 10)
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	var out, errb bytes.Buffer
	code := Main([]string{"usage", "--root=" + root}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	var r Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Partial || r.PartialReason != "failed" || r.Failed.N != 1 {
		t.Errorf("report = partial %v %q failed %d", r.Partial, r.PartialReason, r.Failed.N)
	}
}

func TestScanGainsAlloc(t *testing.T) {
	root := t.TempDir()
	writeN(t, filepath.Join(root, "a"), 5000)
	os.Mkdir(filepath.Join(root, "d"), 0o755)
	writeN(t, filepath.Join(root, "d", "b"), 70000)
	os.Link(filepath.Join(root, "a"), filepath.Join(root, "d", "a2"))
	s, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	u := usageOf(t, root)
	if s.AllocBytes == 0 || s.AllocBytes != u.AllocBytes || s.ApparentBytes != u.ApparentBytes {
		t.Errorf("scan %d/%d, usage %d/%d", s.AllocBytes, s.ApparentBytes, u.AllocBytes, u.ApparentBytes)
	}
	if s.IOIdle != nil {
		t.Error("scan reports io_idle")
	}
}

func TestUsageArgsRoundTrip(t *testing.T) {
	o := Options{Root: "/vol", MaxEntries: 2_000_000, MaxTime: 2 * time.Minute}
	args := Args("usage", o, ArgsExtra{})
	if want := []string{"usage", "--root=/vol", "--max-entries=2000000", "--max-time=2m0s"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %q", args)
	}
	mode, got, _, err := parseArgs(args)
	if err != nil || mode != "usage" || got.Root != "/vol" || got.MaxEntries != 2_000_000 || got.MaxTime != 2*time.Minute {
		t.Errorf("parsed = %s %+v %v", mode, got, err)
	}
}

func TestUsageRejectsScanFlags(t *testing.T) {
	for _, extra := range []string{"--gid=60001", "--principal=a:1:rw", "--children", "--expect-dev=1"} {
		if _, _, _, err := parseArgs([]string{"usage", "--root=/vol", extra}); err == nil {
			t.Errorf("usage %s accepted", extra)
		}
	}
}

func TestUsageIOIdle(t *testing.T) {
	r := usageOf(t, t.TempDir())
	if r.IOIdle == nil {
		t.Fatal("no io_idle")
	}
	if runtime.GOOS != "linux" && *r.IOIdle {
		t.Error("io_idle true off Linux")
	}
}
