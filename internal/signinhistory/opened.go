package signinhistory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// OpenedDirName is the opened log's directory in group_gate_data.
const OpenedDirName = "opened"

// OpenedScan is how much of each day file is read at most: its newest
// 8 MiB (§8.2).
const OpenedScan = 8 << 20

// OpenedTotalScan bounds the bytes one read takes over all day files: past
// it the read stops at a day boundary with *Partial (the history goes on
// from that day on its next page).
const OpenedTotalScan = 64 << 20

// dayFileRe is a day file's name, <YYYY-MM-DD>.jsonl (UTC day).
var dayFileRe = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2})\.jsonl$`)

// OpenedLog is group-gate's opened log (§4 "Opened log"): Dir is the
// mount of group_gate_data (the log is <Dir>/opened); Now is the clock
// (nil: time.Now); MaxScan the bytes one read takes over all day files
// (0: OpenedTotalScan).
type OpenedLog struct {
	Dir     string
	Now     func() time.Time
	MaxScan int64
}

// openedLine is one line of a day file.
type openedLine struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user"`
	Session string    `json:"session"`
	Host    string    `json:"host"`
	App     string    `json:"app"`
	Methods []string  `json:"methods"`
	IP      string    `json:"ip"`
	UA      string    `json:"ua"`
	Act     string    `json:"act"`
}

func (l OpenedLog) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

func (l OpenedLog) maxScan() int64 {
	if l.MaxScan > 0 {
		return l.MaxScan
	}
	return OpenedTotalScan
}

func (l OpenedLog) dir() string { return filepath.Join(l.Dir, OpenedDirName) }

// usable: the mount must be there (a missing mount is an unknown source);
// a missing opened/ in it only means nothing was logged yet.
func (l OpenedLog) usable() (bool, error) {
	if l.Dir == "" {
		return false, errors.New("opened log: no group-gate data directory")
	}
	if st, err := os.Stat(l.Dir); err != nil {
		return false, fmt.Errorf("opened log: %w", err)
	} else if !st.IsDir() {
		return false, fmt.Errorf("opened log: %s is not a directory", l.Dir)
	}
	st, err := os.Lstat(l.dir())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("opened log: %w", err)
	}
	// Never followed: a symlink (or anything but a directory) is refused,
	// for reads and for Prune alike.
	if !st.IsDir() {
		return false, fmt.Errorf("opened log: %s is not a directory (%s)", OpenedDirName, st.Mode().Type())
	}
	return true, nil
}

// Entries are user's opened entries with since <= time < before, newest
// first, at most limit: the day files from before's day back to since's,
// each read (its newest OpenedScan bytes) and deduped on (session, host)
// keeping the day's first line. Torn and unparsable lines are skipped; a
// missing day file is an empty day. Past OpenedTotalScan bytes the read
// stops before the next day with *Partial{Through: the end of that day}.
func (l OpenedLog) Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error) {
	out := []Entry{}
	ok, err := l.usable()
	if err != nil || !ok {
		return out, err
	}
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" || limit < 1 || !since.Before(before) {
		return out, nil
	}
	first := since.UTC().Truncate(24 * time.Hour)
	var total int64
	for day := before.UTC().Truncate(24 * time.Hour); !day.Before(first) && len(out) < limit; day = day.AddDate(0, 0, -1) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if total >= l.maxScan() {
			// Every day after this one was read whole.
			return out, &Partial{Through: day.Add(24*time.Hour - time.Nanosecond), Why: "the opened log's read budget ran out"}
		}
		lines, n, err := l.readDay(day, user)
		total += n
		if err != nil {
			return nil, err
		}
		var es []Entry
		for _, ln := range dedupe(lines, user) {
			if ln.Time.Before(since) || !ln.Time.Before(before) {
				continue
			}
			es = append(es, openedEntry(ln))
		}
		slices.SortStableFunc(es, func(a, b Entry) int { return b.Time.Compare(a.Time) })
		out = append(out, es[:min(len(es), limit-len(out))]...)
	}
	return out, nil
}

// dedupe keeps user's lines (exactly: the log's names are lowercase), the first (earliest) per (session, host).
func dedupe(lines []openedLine, user string) []openedLine {
	slices.SortStableFunc(lines, func(a, b openedLine) int { return a.Time.Compare(b.Time) })
	seen := map[[2]string]bool{}
	var out []openedLine
	for _, ln := range lines {
		if ln.User != user || ln.Time.IsZero() {
			continue
		}
		k := [2]string{ln.Session, strings.ToLower(ln.Host)}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ln)
	}
	return out
}

func openedEntry(ln openedLine) Entry {
	app := Clean(ln.App, maxApp)
	if app == "" {
		app = Clean(ln.Host, maxApp)
	}
	ms := make([]string, len(ln.Methods))
	copy(ms, ln.Methods)
	return withScore(Entry{Time: ln.Time.UTC(), Kind: KindOpened, Methods: Methods(ms), App: app,
		IP: IP(ln.IP), Browser: Browser(ln.UA)})
}

// readDay reads day's file: its newest OpenedScan bytes (n, the bytes
// read), the first line dropped when the scan starts inside it, lines
// that don't hold user skipped before they are decoded, unparsable ones
// after. A missing file is no lines; a file that isn't a regular file (a
// symlink included: never followed) is an error.
func (l OpenedLog) readDay(day time.Time, user string) (lines []openedLine, n int64, err error) {
	p := filepath.Join(l.dir(), day.Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("opened log %s: %w", filepath.Base(p), err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("opened log %s: %w", filepath.Base(p), err)
	}
	if !st.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("opened log %s: not a regular file", filepath.Base(p))
	}
	off := max(st.Size()-OpenedScan, 0)
	buf := make([]byte, st.Size()-off)
	got, err := f.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return nil, int64(got), fmt.Errorf("opened log %s: %w", filepath.Base(p), err)
	}
	buf = buf[:got]
	if off > 0 {
		nl := bytes.IndexByte(buf, '\n')
		if nl < 0 {
			return nil, int64(got), nil
		}
		buf = buf[nl+1:]
	}
	needle := []byte(user)
	for _, raw := range bytes.Split(buf, []byte("\n")) {
		if !bytes.Contains(raw, needle) {
			continue
		}
		var ln openedLine
		if json.Unmarshal(raw, &ln) == nil {
			lines = append(lines, ln)
		}
	}
	return lines, int64(got), nil
}

// Prune deletes the day files older than days (their day before today −
// days, UTC); today's file (and any later one) is never deleted, whatever
// days is. Other names are left alone. A missing log prunes nothing.
func (l OpenedLog) Prune(days int) (removed int, err error) {
	ok, err := l.usable()
	if err != nil || !ok {
		return 0, err
	}
	ents, err := os.ReadDir(l.dir())
	if err != nil {
		return 0, fmt.Errorf("opened log: %w", err)
	}
	today := l.now().Truncate(24 * time.Hour)
	cutoff := today.AddDate(0, 0, -max(days, 0))
	var errs []error
	for _, de := range ents {
		m := dayFileRe.FindStringSubmatch(de.Name())
		if m == nil || de.IsDir() {
			continue
		}
		day, perr := time.Parse("2006-01-02", m[1])
		if perr != nil || !day.Before(cutoff) || !day.Before(today) {
			continue
		}
		if rerr := os.Remove(filepath.Join(l.dir(), de.Name())); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			errs = append(errs, rerr)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}
