package folderfix

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// Snapshot format (contract §14.4): gzip NDJSON, a header line, then one
// line per entry.
// planRules is the version of planEntry's rules a snapshot was made
// under: Restore recomputes what the apply produced, so it refuses another.
const planRules = 1

type snapHeader struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"` // "apply" | "undo"
	Rules     int    `json:"rules"`
	RootDev   uint64 `json:"root_dev"`
	RootIno   uint64 `json:"root_ino"`
	GID       int    `json:"gid"`
	Files     string `json:"files"`
	OwnerUID  *int   `json:"owner_uid"`
	CreatedAt string `json:"created_at"`
	Entries   int64  `json:"entries"`
}

type snapLine struct {
	P   string `json:"p"`
	T   string `json:"t"` // "d" | "f"
	Ino uint64 `json:"ino"`
	U   uint32 `json:"u"`
	G   uint32 `json:"g"`
	M   uint32 `json:"m"`
	A   string `json:"a"` // base64 access xattr, "" = none
	D   string `json:"d"` // base64 default xattr, "" = none
	// PB is the raw name (base64) when it isn't valid UTF-8 (R48): JSON
	// can't carry it, P then has U+FFFD in its place for reading only.
	PB string `json:"pb,omitempty"`
}

const maxSnapEntries = 100_000_000

// maxSnapLine is the longest snapshot line (a var for tests).
var maxSnapLine = 64 << 10

type snapWriter struct {
	gz     *gzip.Writer
	w      io.Writer
	n      int64
	digest hash.Hash
}

func newSnapWriter(out io.Writer, h snapHeader) (*snapWriter, error) {
	gz := gzip.NewWriter(out)
	enc := json.NewEncoder(gz)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(h); err != nil {
		return nil, err
	}
	return &snapWriter{gz: gz, w: gz, digest: sha256.New()}, nil
}

// snapshotLine is the node's snapshot line, checked as readSnapshot will
// check it (R49: a snapshot that was written always reads back).
func snapshotLine(n *node) ([]byte, error) {
	t := "f"
	if n.cur.Dir {
		t = "d"
	}
	l := snapLine{P: n.rel, T: t, Ino: n.st.Ino, U: n.st.UID, G: n.st.GID, M: n.st.Mode & modePerm,
		A: base64.StdEncoding.EncodeToString(n.raw.access), D: base64.StdEncoding.EncodeToString(n.raw.def)}
	if !utf8.ValidString(n.rel) {
		l.P = strings.ToValidUTF8(n.rel, "\uFFFD")
		l.PB = base64.StdEncoding.EncodeToString([]byte(n.rel))
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil {
		return nil, err
	}
	if b.Len() > maxSnapLine {
		return nil, fmt.Errorf("%s: snapshot line of %d bytes", clip(l.P, 80), b.Len())
	}
	if _, p, err := lineState(l); err != nil || p != n.rel {
		return nil, fmt.Errorf("%s: the snapshot line wouldn't read back: %v", clip(l.P, 80), err)
	}
	return b.Bytes(), nil
}

func (s *snapWriter) line(n *node) error {
	b, err := snapshotLine(n)
	if err != nil {
		return err
	}
	s.n++
	digestEntry(s.digest, n)
	_, err = s.w.Write(b)
	return err
}

func (s *snapWriter) close() error { return s.gz.Close() }

func (w *walker) header(kind string, entries int64, t Target) snapHeader {
	return snapHeader{Version: 1, Kind: kind, Rules: planRules, RootDev: w.root.Dev, RootIno: w.root.Ino, GID: t.GID, Files: t.Files,
		OwnerUID: t.OwnerUID, CreatedAt: time.Now().UTC().Format(time.RFC3339), Entries: entries}
}

// WriteSnapshot writes the permissions snapshot of every entry Apply would
// change (gzip NDJSON, header kind "apply"). It changes nothing. The tree
// is walked twice (the header carries the count); a different count the
// second time is an error.
func WriteSnapshot(o Options, out io.Writer) (*Report, error) {
	o.MaxEntries, o.MaxTime = 0, 0 // M4: a snapshot is whole or fails
	w, err := openWalker(o, "snapshot")
	if err != nil {
		return w.report(), err
	}
	defer w.close()
	if !w.hasT {
		return w.report(), errors.New("a snapshot needs the folder gid and files")
	}
	w.run(w.tally)
	if w.r.Partial || w.r.Failed.N > 0 {
		return w.finish(), fmt.Errorf("the folder couldn't be read completely (%d failed, partial %v)", w.r.Failed.N, w.r.Partial)
	}
	plan, exp := w.r.Plan, w.r.Expected
	plan.Digest = hex.EncodeToString(w.digest.Sum(nil))
	w.reset()
	sw, err := newSnapWriter(out, w.header("apply", plan.Changes, o.Target))
	if err != nil {
		return w.report(), err
	}
	var werr error
	w.run(func(n *node) {
		if o, ok := w.planNode(n); ok && o.change && werr == nil {
			werr = sw.line(n)
		}
	})
	if err := sw.close(); werr == nil {
		werr = err
	}
	r := w.finish()
	r.Plan, r.Expected = plan, exp
	switch {
	case werr != nil:
		return r, werr
	case r.Partial || r.Failed.N > 0:
		return r, errors.New("the folder couldn't be read completely")
	case sw.n != plan.Changes || hex.EncodeToString(sw.digest.Sum(nil)) != plan.Digest:
		return r, fmt.Errorf("the folder changed during the snapshot (%d entries, then %d)", plan.Changes, sw.n)
	}
	return r, nil
}

// readSnapshot decodes a snapshot strictly: the header, then exactly
// header.entries lines, each with a valid path and type. onHeader may
// refuse; onLine is called per line.
func readSnapshot(in io.Reader, onHeader func(snapHeader) error, onLine func(snapLine, state, string) error) error {
	gz, err := gzip.NewReader(in)
	if err != nil {
		return refuse("snapshot: %v", err)
	}
	defer gz.Close()
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 4096), maxSnapLine)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return refuse("snapshot: %v", err)
		}
		return refuse("snapshot: empty")
	}
	var h snapHeader
	if err := strictJSON(sc.Bytes(), &h); err != nil {
		return refuse("snapshot header: %v", err)
	}
	if h.Version != 1 || (h.Kind != "apply" && h.Kind != "undo") || h.Rules != planRules || h.GID <= 0 || h.GID >= 0xFFFFFFFF ||
		(h.Files != "rw" && h.Files != "r") || h.Entries < 0 || h.Entries > maxSnapEntries ||
		(h.OwnerUID != nil && (*h.OwnerUID < 0 || *h.OwnerUID >= 0xFFFFFFFF)) {
		return refuse("snapshot header: not a version 1 apply or undo snapshot of rules %d", planRules)
	}
	if err := onHeader(h); err != nil {
		return err
	}
	var n int64
	for sc.Scan() {
		n++
		if n > h.Entries {
			return refuse("snapshot: more lines than its %d entries", h.Entries)
		}
		var l snapLine
		if err := strictJSON(sc.Bytes(), &l); err != nil {
			return refuse("snapshot line %d: %v", n, err)
		}
		s, p, err := lineState(l)
		if err != nil {
			return refuse("snapshot line %d: %v", n, err)
		}
		if err := onLine(l, s, p); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return refuse("snapshot: %v", err)
	}
	if n != h.Entries {
		return refuse("snapshot: %d lines, its header says %d", n, h.Entries)
	}
	return nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// lineState validates a line and returns the state it records and its
// path (raw bytes from pb when the name isn't UTF-8).
func lineState(l snapLine) (state, string, error) {
	p := l.P
	if l.PB != "" {
		raw, err := base64.StdEncoding.Strict().DecodeString(l.PB)
		if err != nil {
			return state{}, "", fmt.Errorf("pb: %v", err)
		}
		p = string(raw)
		if utf8.ValidString(p) || strings.ToValidUTF8(p, "\uFFFD") != l.P {
			return state{}, "", errors.New("pb is only for a name that isn't UTF-8, with p its readable form")
		}
	}
	if err := validRel(p); err != nil {
		return state{}, "", err
	}
	if l.T != "d" && l.T != "f" {
		return state{}, "", fmt.Errorf("type %q", l.T)
	}
	if l.M&^modePerm != 0 {
		return state{}, "", fmt.Errorf("mode %o", l.M)
	}
	s := state{Dir: l.T == "d", UID: l.U, GID: l.G, Mode: l.M}
	var err error
	if s.Access, err = lineACL(l.A); err != nil {
		return state{}, "", fmt.Errorf("access ACL: %v", err)
	}
	if s.Default, err = lineACL(l.D); err != nil {
		return state{}, "", fmt.Errorf("default ACL: %v", err)
	}
	if !s.Dir && s.Default != nil {
		return state{}, "", errors.New("a default ACL on a file")
	}
	return s, p, nil
}

func lineACL(s string) (ACL, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	a, err := DecodeACL(b)
	if err != nil {
		return nil, err
	}
	if len(a) == 0 {
		return nil, nil
	}
	if err := a.Valid(); err != nil {
		return nil, err
	}
	return a, nil
}
