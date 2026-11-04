package folderfix

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Snapshot format (contract §14.4): gzip NDJSON, a header line, then one
// line per entry.
type snapHeader struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"` // "apply" | "undo"
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
}

const (
	maxSnapLine    = 64 << 10
	maxSnapEntries = 100_000_000
)

type snapWriter struct {
	gz  *gzip.Writer
	enc *json.Encoder
	n   int64
}

func newSnapWriter(out io.Writer, h snapHeader) (*snapWriter, error) {
	gz := gzip.NewWriter(out)
	enc := json.NewEncoder(gz)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(h); err != nil {
		return nil, err
	}
	return &snapWriter{gz: gz, enc: enc}, nil
}

func (s *snapWriter) line(n *node) error {
	t := "f"
	if n.cur.Dir {
		t = "d"
	}
	s.n++
	return s.enc.Encode(snapLine{P: n.rel, T: t, Ino: n.st.Ino, U: n.st.UID, G: n.st.GID, M: n.st.Mode & modePerm,
		A: base64.StdEncoding.EncodeToString(n.raw.access), D: base64.StdEncoding.EncodeToString(n.raw.def)})
}

func (s *snapWriter) close() error { return s.gz.Close() }

func (w *walker) header(kind string, entries int64, t Target) snapHeader {
	return snapHeader{Version: 1, Kind: kind, RootDev: w.root.Dev, RootIno: w.root.Ino, GID: t.GID, Files: t.Files,
		OwnerUID: t.OwnerUID, CreatedAt: time.Now().UTC().Format(time.RFC3339), Entries: entries}
}

// WriteSnapshot writes the permissions snapshot of every entry Apply would
// change (gzip NDJSON, header kind "apply"). It changes nothing. The tree
// is walked twice (the header carries the count); a different count the
// second time is an error.
func WriteSnapshot(o Options, out io.Writer) (*Report, error) {
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
	case sw.n != plan.Changes:
		return r, fmt.Errorf("the folder changed during the snapshot (%d entries, then %d)", plan.Changes, sw.n)
	}
	return r, nil
}

// readSnapshot decodes a snapshot strictly: the header, then exactly
// header.entries lines, each with a valid path and type. onHeader may
// refuse; onLine is called per line.
func readSnapshot(in io.Reader, onHeader func(snapHeader) error, onLine func(snapLine, state) error) error {
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
	if h.Version != 1 || (h.Kind != "apply" && h.Kind != "undo") || h.GID <= 0 || h.GID >= 0xFFFFFFFF ||
		(h.Files != "rw" && h.Files != "r") || h.Entries < 0 || h.Entries > maxSnapEntries ||
		(h.OwnerUID != nil && (*h.OwnerUID < 0 || *h.OwnerUID >= 0xFFFFFFFF)) {
		return refuse("snapshot header: not a version 1 apply or undo snapshot")
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
		s, err := lineState(l)
		if err != nil {
			return refuse("snapshot line %d: %v", n, err)
		}
		if err := onLine(l, s); err != nil {
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

// lineState validates a line and returns the state it records.
func lineState(l snapLine) (state, error) {
	if err := validRel(l.P); err != nil {
		return state{}, err
	}
	if l.T != "d" && l.T != "f" {
		return state{}, fmt.Errorf("type %q", l.T)
	}
	if l.M&^modePerm != 0 {
		return state{}, fmt.Errorf("mode %o", l.M)
	}
	s := state{Dir: l.T == "d", UID: l.U, GID: l.G, Mode: l.M}
	var err error
	if s.Access, err = lineACL(l.A); err != nil {
		return state{}, fmt.Errorf("access ACL: %v", err)
	}
	if s.Default, err = lineACL(l.D); err != nil {
		return state{}, fmt.Errorf("default ACL: %v", err)
	}
	if !s.Dir && s.Default != nil {
		return state{}, errors.New("a default ACL on a file")
	}
	return s, nil
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
