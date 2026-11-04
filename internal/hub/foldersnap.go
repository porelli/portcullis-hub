package hub

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/settings"
)

// Permissions snapshots (contract §14.4, ruling 31): the gzip NDJSON the
// fixer writes to /out, stored as it came (never decompressed on the
// way) under <data>/folder-snapshots/<folder>/<YYYYMMDDTHHMMSSZ>.ndjson.gz
// with <same>.sha256 beside it — the checksum computed by the Hub while
// streaming, written after the data, each atomically. Files 0600,
// directories 0700, the last snapshotsKept per folder kept (never the
// folder's last_apply snapshot). The checksum catches corruption only:
// write access to <data> is Hub compromise.

// snapshotsKept is how many snapshots a folder keeps.
const snapshotsKept = 3

// snapshotTSFormat names a snapshot (UTC).
const snapshotTSFormat = "20060102T150405Z"

var snapshotNameRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z\.ndjson\.gz$`)

func (h *Hub) snapshotsDir() string { return filepath.Join(h.cfg.DataDir, "folder-snapshots") }

// snapshotTS is a snapshot's timestamp ("<folder>/<ts>.ndjson.gz" → ts).
func snapshotTS(rel string) string {
	return strings.TrimSuffix(path.Base(rel), ".ndjson.gz")
}

// snapshotRel checks rel is "<folder id>/<ts>.ndjson.gz".
func snapshotRel(rel string) error {
	dir, name, ok := strings.Cut(rel, "/")
	if !ok || !settings.FolderIDRe.MatchString(dir) || !snapshotNameRe.MatchString(name) {
		return fmt.Errorf("snapshot name %q", clipRunes(rel, 80))
	}
	return nil
}

// saveSnapshot stores the snapshot r yields for folder and returns its
// name relative to the snapshots directory ("<folder>/<ts>.ndjson.gz").
// It is at most maxSnapshotBytes and within the free space left after
// freeMargin (507 beyond it); the sha256 is computed while streaming.
// Then the oldest snapshots beyond snapshotsKept go (never keep's).
func (h *Hub) saveSnapshot(folder string, r io.Reader) (rel string, err error) {
	if !settings.FolderIDRe.MatchString(folder) {
		return "", fmt.Errorf("folder id %q", folder)
	}
	dir := filepath.Join(h.snapshotsDir(), folder)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	os.Chmod(h.snapshotsDir(), 0o700)
	os.Chmod(dir, 0o700)
	avail, err := freeSpace(dir)
	if err != nil {
		return "", statusErr(http.StatusInternalServerError, "checking free space for the permissions snapshot: %v", err)
	}
	limit := maxSnapshotBytes
	if room := int64(avail) - freeMargin; room < limit {
		limit = room
	}
	if limit <= 0 {
		return "", statusErr(http.StatusInsufficientStorage, "not enough free space on the Hub's data volume for the permissions snapshot of %s (a %d MiB margin is kept)", folder, freeMargin>>20)
	}
	// A unique name that sorts after every existing one (retention keeps
	// the newest by name): a second after the newest when needed.
	ts := time.Now().UTC().Truncate(time.Second)
	if have := h.listSnapshots(folder); len(have) > 0 {
		if last, err := time.Parse(snapshotTSFormat, snapshotTS(have[len(have)-1])); err == nil && !ts.After(last) {
			ts = last.Add(time.Second)
		}
	}
	name := ts.Format(snapshotTSFormat) + ".ndjson.gz"
	tmp, err := os.CreateTemp(dir, ".partial-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if tmp != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", err
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(r, limit+1))
	if err != nil {
		return "", fmt.Errorf("writing the permissions snapshot: %w", err)
	}
	if n > limit {
		return "", statusErr(http.StatusInsufficientStorage, "the permissions snapshot of %s is larger than the space left for it (%d MiB): nothing was changed", folder, limit>>20)
	}
	if n == 0 {
		return "", errors.New("the permissions snapshot is empty")
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	final := filepath.Join(dir, name)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return "", err
	}
	tmp = nil
	digest := hex.EncodeToString(sum.Sum(nil))
	if err := fsutil.WriteFileAtomic(final+".sha256", []byte(digest+"  "+name+"\n"), 0o600); err != nil {
		os.Remove(final)
		return "", err
	}
	rel = folder + "/" + name
	h.pruneSnapshots(folder)
	return rel, nil
}

// pruneSnapshots removes folder's snapshots beyond the newest
// snapshotsKept, never the one its last_apply names (an undo needs it),
// and leftover partial files.
func (h *Hub) pruneSnapshots(folder string) {
	dir := filepath.Join(h.snapshotsDir(), folder)
	h.mu.RLock()
	keep := ""
	if f, ok := h.st.Folders[folder]; ok && f.LastApply != nil {
		keep = f.LastApply.Snapshot
	}
	h.mu.RUnlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		switch n := e.Name(); {
		case snapshotNameRe.MatchString(n) && e.Type().IsRegular():
			names = append(names, n)
		case strings.HasSuffix(n, ".sha256") && snapshotNameRe.MatchString(strings.TrimSuffix(n, ".sha256")):
			if _, err := os.Lstat(filepath.Join(dir, strings.TrimSuffix(n, ".sha256"))); errors.Is(err, os.ErrNotExist) {
				os.Remove(filepath.Join(dir, n)) // a checksum without its data
			}
		}
	}
	slices.Sort(names)
	for i := 0; i < len(names)-snapshotsKept; i++ {
		if folder+"/"+names[i] == keep {
			continue
		}
		if err := os.Remove(filepath.Join(dir, names[i])); err != nil {
			log.Printf("shared folders: removing old snapshot %s/%s: %v", folder, names[i], err)
			continue
		}
		os.Remove(filepath.Join(dir, names[i]+".sha256"))
	}
}

// listSnapshots is folder's stored snapshots, oldest first (tests, the
// doctor).
func (h *Hub) listSnapshots(folder string) []string {
	entries, _ := os.ReadDir(filepath.Join(h.snapshotsDir(), folder))
	var out []string
	for _, e := range entries {
		if snapshotNameRe.MatchString(e.Name()) {
			out = append(out, folder+"/"+e.Name())
		}
	}
	slices.Sort(out)
	return out
}

// openSnapshot opens snapshot rel and checks it against its .sha256,
// streaming (M4: never the whole file in memory): a missing one is 404, a
// damaged one (no checksum, another digest) 409. The file is returned at
// offset 0 with its size; the caller closes it.
func (h *Hub) openSnapshot(rel string) (*os.File, int64, error) {
	if err := snapshotRel(rel); err != nil {
		return nil, 0, statusErr(http.StatusNotFound, "%v", err)
	}
	p := filepath.Join(h.snapshotsDir(), filepath.FromSlash(rel))
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, statusErr(http.StatusNotFound, "permissions snapshot %s not found", rel)
	}
	fail := func(err error) (*os.File, int64, error) {
		f.Close()
		return nil, 0, err
	}
	sumLine, err := os.ReadFile(p + ".sha256")
	if err != nil {
		return fail(statusErr(http.StatusConflict, "permissions snapshot %s has no checksum: it can't be used", rel))
	}
	want, _, _ := strings.Cut(strings.TrimSpace(string(sumLine)), " ")
	sum := sha256.New()
	n, err := io.Copy(sum, f)
	if err != nil {
		return fail(statusErr(http.StatusInternalServerError, "reading permissions snapshot %s: %v", rel, err))
	}
	if want != hex.EncodeToString(sum.Sum(nil)) {
		return fail(statusErr(http.StatusConflict, "permissions snapshot %s is damaged (its checksum doesn't match): it can't be used", rel))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return f, n, nil
}

// snapshotHeaderOf opens snapshot rel (checksum checked) and reads its
// header.
func (h *Hub) snapshotHeaderOf(rel string) (*snapshotHeader, error) {
	f, _, err := h.openSnapshot(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hdr, err := readSnapshotHeader(f)
	if err != nil {
		return nil, statusErr(http.StatusConflict, "permissions snapshot %s can't be read: %v", rel, err)
	}
	return hdr, nil
}

// snapshotHeader is what the Hub reads of a snapshot's header line
// (contract §14.4; the fixer validates the whole snapshot).
type snapshotHeader struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	RootDev   uint64 `json:"root_dev"`
	RootIno   uint64 `json:"root_ino"`
	GID       int    `json:"gid"`
	Files     string `json:"files"`
	OwnerUID  *int   `json:"owner_uid"`
	CreatedAt string `json:"created_at"`
	Entries   int64  `json:"entries"`
}

// readSnapshotHeader decodes the first line of a snapshot.
func readSnapshotHeader(r io.Reader) (*snapshotHeader, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	defer gz.Close()
	line, err := bufio.NewReaderSize(io.LimitReader(gz, 64<<10), 64<<10).ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return nil, fmt.Errorf("snapshot header: %w", err)
	}
	var hdr snapshotHeader
	if err := json.Unmarshal(line, &hdr); err != nil {
		return nil, fmt.Errorf("snapshot header: %w", err)
	}
	if hdr.Version != 1 {
		return nil, fmt.Errorf("snapshot header: version %d", hdr.Version)
	}
	return &hdr, nil
}
