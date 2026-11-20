package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
)

func vectorRows(t *testing.T) []publishedDoc {
	t.Helper()
	b, err := os.ReadFile("testdata/published_docs.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []publishedDoc
	if err := jsonstrict.Decode(b, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestPublishedDocsVectorsMatchCode: every Doc const is one vector row,
// with the same object, kind, key, mount, readers, mode and rev path.
func TestPublishedDocsVectorsMatchCode(t *testing.T) {
	rows := vectorRows(t)
	if len(rows) != len(All) {
		t.Fatalf("%d rows, %d docs", len(rows), len(All))
	}
	for _, r := range rows {
		d := Doc(r.Doc)
		if !slices.Contains(All, d) {
			t.Errorf("row %s has no Doc", r.Doc)
			continue
		}
		s := Spec(d)
		fs := 0
		if r.FSGroup.Valid {
			fs = r.FSGroup.V
		}
		if s.Object != r.Object || string(s.Kind) != r.Kind || s.Key != r.Key || s.Mount != r.Mount ||
			strings.Join(s.Readers, " ") != strings.Join(r.Readers, " ") || s.Mode != r.Mode || s.FSGroup != fs || s.RevPath() != r.RevPath {
			t.Errorf("%s: code %+v, vector %+v", d, s, r)
		}
		if s.RevKey() != ".rev-"+r.Doc {
			t.Errorf("%s: rev key %q", d, s.RevKey())
		}
	}
	for _, c := range []struct {
		d    Doc
		want string
	}{{GroupGatePolicy, "group-gate-policy"}, {UserAttributes, "user-attributes"}, {PortalApps, "portal-apps"}, {SignInKeycloak, "signin-keycloak"},
		{Impersonation, "impersonation"}, {MCPGate, "mcp-gate"}, {MCPCredentials, "mcp-credentials"}, {VPN, "vpn"}} {
		if string(c.d) != c.want {
			t.Errorf("%q != %q", c.d, c.want)
		}
	}
}

// TestFileSinkByteCompatible: the FileSink writes each document exactly
// as today's writers did (the same bytes, 0644 for the four group-gate /
// Keycloak files, 0640 for the two mcp-gate files and vpn.json, vpn.json
// in its own group), atomically, and no .rev file beside it.
func TestFileSinkByteCompatible(t *testing.T) {
	dir, vdir := t.TempDir(), t.TempDir()
	gid := os.Getgid()
	s := FileSink{Dirs: map[Doc]string{}, GID: map[Doc]int{VPN: gid}}
	for _, d := range All {
		s.Dirs[d] = dir
	}
	s.Dirs[VPN] = vdir
	// Today's encoders: json.MarshalIndent(v, "", "  ") + "\n" for every
	// document (vpn.json, the gate files and the policy files alike).
	enc := func(v any) []byte {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return append(b, '\n')
	}
	today := map[Doc]struct {
		file string
		mode os.FileMode
	}{
		GroupGatePolicy: {"group-gate-policy.json", 0644},
		UserAttributes:  {"user-attributes.json", 0644},
		PortalApps:      {"portal-apps.json", 0644},
		SignInKeycloak:  {"signin-keycloak.json", 0644},
		Impersonation:   {"impersonation.json", 0644},
		MCPGate:         {"mcp-gate.json", 0640},
		MCPCredentials:  {"mcp-credentials.json", 0640},
		VPN:             {"vpn.json", 0640},
	}
	for _, d := range All {
		w := today[d]
		data := enc(map[string]any{"version": 1, "doc": string(d)})
		rev, err := s.Publish(context.Background(), d, data)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if rev != Rev(data) || len(rev) != 16 {
			t.Errorf("%s: rev %q", d, rev)
		}
		p := filepath.Join(s.Dirs[d], w.file)
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s: bytes %q (%v)", d, got, err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != w.mode {
			t.Errorf("%s: mode %o, want %o", d, fi.Mode().Perm(), w.mode)
		}
		if d == VPN {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Gid) != gid {
				t.Errorf("vpn.json gid %d, want %d", st.Gid, gid)
			}
		}
		if ok, err := s.Confirmed(context.Background(), d, rev); !ok || err != nil {
			t.Errorf("%s: a file is confirmed once renamed: %v %v", d, ok, err)
		}
	}
	for _, dd := range []string{dir, vdir} {
		es, _ := os.ReadDir(dd)
		for _, e := range es {
			if strings.HasPrefix(e.Name(), ".") {
				t.Errorf("stray file %s", e.Name())
			}
		}
	}
	// Remove: the file goes (missing is fine).
	if err := s.Remove(context.Background(), UserAttributes); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "user-attributes.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("not removed: %v", err)
	}
	if err := s.Remove(context.Background(), UserAttributes); err != nil {
		t.Errorf("remove twice: %v", err)
	}
	// Docker and Podman are unchanged: no size limit on the files.
	if _, err := s.Publish(context.Background(), PortalApps, bytes.Repeat([]byte("x"), MaxDoc+1)); err != nil {
		t.Errorf("a large file refused: %v", err)
	}
	if NewTracker(s).Max != 0 || NewTracker(newMem()).Max != MaxDoc {
		t.Error("the limit is Kubernetes'")
	}
	// A doc without a directory is an error, never a write elsewhere.
	if _, err := (FileSink{}).Publish(context.Background(), PortalApps, []byte("{}\n")); err == nil {
		t.Error("no directory accepted")
	}
}

// memSink is a Sink in memory (the object as a reader would see it).
type memSink struct {
	data    map[Doc][]byte
	rev     map[Doc]string
	behind  map[Doc][]string
	publish int
}

func (m *memSink) Publish(_ context.Context, d Doc, b []byte) (string, error) {
	if len(b) > MaxDoc {
		return "", ErrTooLarge
	}
	m.publish++
	m.data[d], m.rev[d] = append([]byte(nil), b...), Rev(b)
	return m.rev[d], nil
}

func (m *memSink) Confirmed(_ context.Context, d Doc, rev string) (bool, error) {
	return len(m.behind[d]) == 0, nil
}

func (m *memSink) Behind(_ context.Context, d Doc, rev string) ([]string, error) {
	return m.behind[d], nil
}

func newMem() *memSink {
	return &memSink{data: map[Doc][]byte{}, rev: map[Doc]string{}, behind: map[Doc][]string{}}
}

// TestTrackerTooLargeKeepsLast: a document of 1 000 001 bytes is never
// handed to the sink; the last good one and its rev stay; the problem
// names the document and its size, and clears with the next good one.
func TestTrackerTooLargeKeepsLast(t *testing.T) {
	m := newMem()
	tr := NewTracker(m)
	good := []byte(`{"version":7}` + "\n")
	if _, err := tr.Publish(context.Background(), GroupGatePolicy, good); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), MaxDoc+1)
	if _, err := tr.Publish(context.Background(), GroupGatePolicy, big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err %v", err)
	}
	if m.publish != 1 || !bytes.Equal(m.data[GroupGatePolicy], good) || m.rev[GroupGatePolicy] != Rev(good) {
		t.Errorf("the object changed: %d publishes, %q", m.publish, m.rev[GroupGatePolicy])
	}
	tl, _ := tr.Problems()
	if len(tl) != 1 || tl[0].Doc != GroupGatePolicy || tl[0].Size != MaxDoc+1 {
		t.Fatalf("too large %+v", tl)
	}
	// Exactly MaxDoc is fine.
	if _, err := tr.Publish(context.Background(), GroupGatePolicy, bytes.Repeat([]byte("y"), MaxDoc)); err != nil {
		t.Fatal(err)
	}
	if tl, _ := tr.Problems(); len(tl) != 0 {
		t.Errorf("not cleared: %+v", tl)
	}
	// Empty data is never published.
	if _, err := tr.Publish(context.Background(), PortalApps, nil); err == nil {
		t.Error("empty document published")
	}
}

// TestTrackerStale: a reader behind for more than 120 s is stale, named
// with its pod; it clears when the pod confirms (or is gone).
func TestTrackerStale(t *testing.T) {
	m := newMem()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	tr := NewTracker(m)
	tr.Now = func() time.Time { return now }
	m.behind[MCPGate] = []string{"mcp-gate-7d9c-abcde"}
	if _, err := tr.Publish(context.Background(), MCPGate, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now = now.Add(119 * time.Second)
	tr.Check(ctx)
	if _, st := tr.Problems(); len(st) != 0 {
		t.Fatalf("stale too early: %+v", st)
	}
	now = now.Add(2 * time.Second)
	tr.Check(ctx)
	_, st := tr.Problems()
	if len(st) != 1 || st[0].Doc != MCPGate || strings.Join(st[0].Pods, ",") != "mcp-gate-7d9c-abcde" {
		t.Fatalf("stale %+v", st)
	}
	if !tr.Pending() {
		t.Error("not pending")
	}
	m.behind[MCPGate] = nil
	tr.Check(ctx)
	if _, st := tr.Problems(); len(st) != 0 || tr.Pending() {
		t.Errorf("not cleared: %+v", st)
	}
}
