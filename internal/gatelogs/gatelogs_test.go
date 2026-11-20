package gatelogs_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/gatelogs"
	"github.com/portcullis/hub/internal/signinhistory"
)

var t0 = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

// fakeLog is a log port as contract §20.10 has it: lines in file order,
// an exclusive cursor (<gen>-<index>), from = the first line at or after
// it, at most page lines per answer (the server's own cut, so paging is
// exercised), 410 for another generation. The knobs break it on purpose.
type fakeLog struct {
	mu       sync.Mutex
	lines    []string
	gen      string
	page     int
	status   int    // non-zero: every request answers it
	body     []byte // non-nil: the 200's body as is
	clen     string // non-empty: the 200's Content-Length header as is
	requests []string
	expireAt int  // a cursor at this index answers 410 once (0: never)
	expire   bool // every cursor answers 410
	endless  bool // every answer is truncated, with one more new line
	stall    bool // a cursor answers no line, the same cursor, truncated
	bytes    int  // the bodies' bytes served
	// failBefore: a from-request (no cursor) earlier than it answers 503.
	failBefore time.Time
}

var fakeCursorRe = regexp.MustCompile(`^([a-z0-9]+)-([0-9]+)$`)

func (f *fakeLog) set(fn func(f *fakeLog)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeLog) reqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *fakeLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if f.status != 0 {
		text := map[int]string{503: "busy", 500: "the access log can't be read", 410: "cursor_expired"}[f.status]
		http.Error(w, text, f.status)
		return
	}
	if f.body != nil || f.clen != "" {
		w.Header().Set("X-Portcullis-Next", "x-0")
		w.Header().Set("X-Portcullis-Truncated", "false")
		if f.clen != "" {
			w.Header().Set("Content-Length", f.clen)
		}
		w.Write(f.body)
		return
	}
	q := r.URL.Query()
	if q.Has("cursor") && q.Has("from") {
		http.Error(w, "from and cursor together", 400)
		return
	}
	if l := q.Get("limit"); l != strconv.Itoa(gatelogs.PageLimit) {
		http.Error(w, "limit", 400)
		return
	}
	start := 0
	if c := q.Get("cursor"); c != "" {
		m := fakeCursorRe.FindStringSubmatch(c)
		if m == nil {
			http.Error(w, "malformed cursor", 400)
			return
		}
		start, _ = strconv.Atoi(m[2])
		if f.stall {
			w.Header().Set("X-Portcullis-Next", c)
			w.Header().Set("X-Portcullis-Truncated", "true")
			return
		}
		if f.expire || m[1] != f.gen || start > len(f.lines) || f.expireAt != 0 && start == f.expireAt {
			f.expireAt = 0
			http.Error(w, "cursor_expired", http.StatusGone)
			return
		}
	} else if fr := q.Get("from"); fr != "" {
		since, err := time.Parse(time.RFC3339, fr)
		if err != nil {
			http.Error(w, "from", 400)
			return
		}
		if since.Before(f.failBefore) {
			http.Error(w, "busy", 503)
			return
		}
		start = len(f.lines)
		for i, l := range f.lines {
			if !timeOf(l).Before(since) {
				start = i
				break
			}
		}
	}
	if f.endless {
		f.lines = append(f.lines, ln(time.Duration(len(f.lines))*time.Second, "alice", "endless"))
	}
	end := min(start+f.page, len(f.lines))
	var b bytes.Buffer
	for _, l := range f.lines[start:end] {
		b.WriteString(l + "\n")
	}
	f.bytes += b.Len()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Portcullis-Next", fmt.Sprintf("%s-%d", f.gen, end))
	w.Header().Set("X-Portcullis-Truncated", strconv.FormatBool(f.endless || end < len(f.lines)))
	w.Write(b.Bytes())
}

var timeRe = regexp.MustCompile(`"time":"([^"]+)"`)

func timeOf(l string) time.Time {
	m := timeRe.FindStringSubmatch(l)
	if m == nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, m[1])
	return t
}

func ln(at time.Duration, user, host string) string {
	return `{"time":"` + t0.Add(at).Format(time.RFC3339) + `","user":"` + user + `","session":"s1","host":"` + host +
		`","app":"","methods":["passkey_device"],"ip":"198.51.100.4","ua":"","act":""}`
}

// serve starts f on a listener: its host:port.
func serve(t *testing.T, f *fakeLog) string {
	t.Helper()
	if f.gen == "" {
		f.gen = "g1"
	}
	if f.page == 0 {
		f.page = 2
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u.Host
}

// replicas: the fakes as one gate's replicas gate-<i> at 10.0.0.<i+1>
// (a per-replica port map in the transport: one port for all).
func replicas(t *testing.T, fakes ...*fakeLog) gatelogs.Replicas {
	t.Helper()
	ports := map[string]string{}
	var reps []gatelogs.Replica
	for i, f := range fakes {
		addr := fmt.Sprintf("10.0.0.%d", i+1)
		ports[addr] = serve(t, f)
		reps = append(reps, gatelogs.Replica{Name: fmt.Sprintf("gate-%d", i), Addr: addr})
	}
	return gatelogs.Replicas{Service: "group-gate", Port: gatelogs.GroupGatePort, Client: dialMap(ports),
		Lister: func(context.Context) ([]gatelogs.Replica, error) { return reps, nil }}
}

func dialMap(ports map[string]string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(a)
		return (&net.Dialer{}).DialContext(ctx, network, ports[h])
	}}}
}

func lines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func q(from, to time.Time) gatelogs.Query { return gatelogs.Query{From: from, To: to} }

func TestMergeTwoReplicasOrdered(t *testing.T) {
	a := []string{ln(0, "alice", "a"), ln(2*time.Second, "alice", "c"), ln(4*time.Second, "alice", "e")}
	b := []string{ln(time.Second, "bob", "b"), ln(2*time.Second, "bob", "c2"), ln(3*time.Second, "bob", "d")}
	// Merge: by time, then replica, every line kept (a gate's own
	// identical lines too: the reads drop what a restart serves again).
	got := lines(gatelogs.Merge([][]byte{[]byte(strings.Join(append(a, a[1]), "\n") + "\n"), []byte(strings.Join(append(b, a[0]), "\n") + "\n")}))
	want := []string{a[0], a[0], b[0], a[1], a[1], b[1], b[2], a[2]}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Over the ports: paged (2 lines a page) until truncated is false,
	// from on the first page only, the cursor after.
	fa, fb := &fakeLog{lines: a}, &fakeLog{lines: b}
	r := replicas(t, fa, fb)
	out, err := r.Read(context.Background(), q(t0, time.Time{}))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{a[0], b[0], a[1], b[1], b[2], a[2]}; !reflect.DeepEqual(lines(out), want) {
		t.Errorf("Read = %q", lines(out))
	}
	if r := fa.reqs(); len(r) != 2 || !strings.Contains(r[0], "from=2026-11-18T10%3A00%3A00Z") ||
		strings.Contains(r[1], "from=") || !strings.Contains(r[1], "cursor=g1-2") {
		t.Errorf("requests = %q", r)
	}
	// Keep and the window.
	out, err = r.Read(context.Background(), gatelogs.Query{From: t0.Add(time.Second), To: t0.Add(3 * time.Second), Keep: func(l []byte) bool { return bytes.Contains(l, []byte("bob")) }})
	if err != nil || !reflect.DeepEqual(lines(out), b) {
		t.Errorf("bob's = %q %v", lines(out), err)
	}
}

func TestCursorExpiredRestartsFromLastTime(t *testing.T) {
	same := ln(time.Second, "alice", "same")
	ls := []string{ln(0, "alice", "a"), same, same, ln(2*time.Second, "alice", "d"), ln(3*time.Second, "alice", "e"), ln(30*time.Second, "alice", "f")}
	f := &fakeLog{lines: ls, expireAt: 2}
	out, err := replicas(t, f).Read(context.Background(), q(time.Time{}, time.Time{}))
	if err != nil {
		t.Fatal(err)
	}
	// Nothing twice, and the gate's own two identical lines both kept.
	if !reflect.DeepEqual(lines(out), ls) {
		t.Errorf("after a restart = %q", lines(out))
	}
	// The first page has neither from nor cursor (the start); the restart
	// is from = RestartBack before the last line's time, never before the
	// read's from (here the start: 10:00:01 − 10 s = 09:59:51).
	r := f.reqs()
	if len(r) != 5 || strings.Contains(r[0], "from=") || !strings.Contains(r[1], "cursor=g1-2") ||
		!strings.Contains(r[2], "from=2026-11-18T09%3A59%3A51Z") {
		t.Errorf("requests = %q", r)
	}
	// A cursor that always expires: at most 3 restarts, then unreadable.
	f2 := &fakeLog{lines: ls, expire: true}
	if _, err := replicas(t, f2).Read(context.Background(), q(time.Time{}, time.Time{})); !gatelogs.IsIncomplete(err) || len(f2.reqs()) > 8 {
		t.Errorf("always 410: %v after %d requests", err, len(f2.reqs()))
	}
}

func TestPagingBounds(t *testing.T) {
	// Truncated never ends: the page budget stops it.
	f := &fakeLog{endless: true, page: 1}
	r := replicas(t, f)
	r.MaxPages = 5
	if _, err := r.Read(context.Background(), q(time.Time{}, time.Time{})); !gatelogs.IsIncomplete(err) || len(f.reqs()) != 5 {
		t.Errorf("endless: %v after %d requests", err, len(f.reqs()))
	}
	// No progress (the same cursor, no line): stopped at once.
	s := &fakeLog{lines: []string{ln(0, "a", "1"), ln(time.Second, "a", "2"), ln(2*time.Second, "a", "3")}, stall: true}
	if _, err := replicas(t, s).Read(context.Background(), q(time.Time{}, time.Time{})); !gatelogs.IsIncomplete(err) || len(s.reqs()) != 2 {
		t.Errorf("stall: %v after %d requests", err, len(s.reqs()))
	}
	// Lines past To + Skew are dropped, and no page past them is asked.
	var ls []string
	for i := 0; i < 10; i++ {
		ls = append(ls, ln(time.Duration(i)*3*time.Minute, "a", strconv.Itoa(i)))
	}
	w := &fakeLog{lines: ls, page: 3}
	out, err := replicas(t, w).Read(context.Background(), q(t0, t0.Add(3*time.Minute)))
	// To + Skew = 10:08: lines at 0, 3, 6 min in; 9 min out; the second
	// page (9, 12, 15) ends the read.
	if err != nil || !reflect.DeepEqual(lines(out), ls[:3]) || len(w.reqs()) != 2 {
		t.Errorf("window: %q %v after %d requests", lines(out), err, len(w.reqs()))
	}
}

func TestReplicaDownMarksIncomplete(t *testing.T) {
	good := &fakeLog{lines: []string{ln(0, "alice", "a"), ln(time.Second, "alice", "b")}}
	for _, code := range []int{503, 500} {
		r := replicas(t, good, &fakeLog{status: code})
		out, err := r.Read(context.Background(), q(t0, time.Time{}))
		var inc *gatelogs.Incomplete
		if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Unread, []string{"gate-1"}) || inc.NoneRead() {
			t.Errorf("%d: err = %v", code, err)
		}
		if !reflect.DeepEqual(lines(out), good.lines) {
			t.Errorf("%d: lines = %q", code, lines(out))
		}
	}
	// Listed without an address (pending, terminating, an expected
	// ordinal without a pod), none at all, the list failing.
	r := replicas(t, good)
	r.Lister = func(context.Context) ([]gatelogs.Replica, error) {
		return []gatelogs.Replica{{Name: "gate-0", Addr: "10.0.0.1"}, {Name: "gate-1"}}, nil
	}
	if _, err := r.Read(context.Background(), q(t0, time.Time{})); !gatelogs.IsIncomplete(err) {
		t.Errorf("pending replica: %v", err)
	}
	var inc *gatelogs.Incomplete
	r.Lister = func(context.Context) ([]gatelogs.Replica, error) { return nil, nil }
	if _, err := r.Read(context.Background(), q(t0, time.Time{})); !errors.As(err, &inc) || !inc.NoneRead() {
		t.Errorf("no replica: %v", err)
	}
	r.Lister = func(context.Context) ([]gatelogs.Replica, error) { return nil, errors.New("forbidden") }
	if _, err := r.Read(context.Background(), q(t0, time.Time{})); !errors.As(err, &inc) || !inc.NoneRead() || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("lister error: %v", err)
	}
	// The opened log over it: the other's entries, *Incomplete (the
	// history names the source unknown; impersonation apps are marked
	// incomplete on any error: internal/hub TestImpersonationAppsHTTPIncomplete).
	ol := signinhistory.OpenedLog{Src: replicas(t, good, &fakeLog{status: 503})}
	es, err := ol.Entries(context.Background(), "alice", t0.Add(-time.Hour), t0.Add(time.Hour), 50)
	var sinc *signinhistory.Incomplete
	if !errors.As(err, &sinc) || len(es) != 2 {
		t.Errorf("opened entries = %+v, %v", es, err)
	}
}

func TestAnswerCappedAt4MiB(t *testing.T) {
	big := bytes.Repeat([]byte("x"), gatelogs.MaxAnswer)
	big = append(big, '\n') // 4 MiB + 1
	good := &fakeLog{lines: []string{ln(0, "alice", "a")}}
	r := replicas(t, good, &fakeLog{body: big})
	out, err := r.Read(context.Background(), q(t0, time.Time{}))
	var inc *gatelogs.Incomplete
	if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Unread, []string{"gate-1"}) || !strings.Contains(err.Error(), "4 MiB") {
		t.Errorf("err = %v", err)
	}
	if !reflect.DeepEqual(lines(out), good.lines) {
		t.Errorf("lines = %q", lines(out))
	}
	// Exactly 4 MiB is an answer.
	exact := append(bytes.Repeat([]byte("x"), gatelogs.MaxAnswer-1), '\n')
	if _, err := replicas(t, &fakeLog{body: exact}).Read(context.Background(), q(t0, time.Time{})); err != nil {
		t.Errorf("4 MiB exactly: %v", err)
	}
	// A declared length over the cap is refused before the body is read.
	_, err = replicas(t, &fakeLog{clen: strconv.Itoa(gatelogs.MaxAnswer + 1), body: []byte{}}).Read(context.Background(), q(t0, time.Time{}))
	if err == nil || !strings.Contains(err.Error(), "an answer of 4194305 bytes") {
		t.Errorf("Content-Length over the cap: %v", err)
	}
}

// TestBudgetAcrossReplicas: one byte budget over every replica's pages:
// past it the read stops (OverBudget, no replica unread) and fetches at
// most a page per replica more.
func TestBudgetAcrossReplicas(t *testing.T) {
	var ls []string
	for i := 0; i < 200; i++ {
		ls = append(ls, ln(time.Duration(i)*time.Second, "alice", "x"))
	}
	fa, fb := &fakeLog{lines: ls, page: 10}, &fakeLog{lines: ls, page: 10}
	r := replicas(t, fa, fb)
	max := 4 * 10 * len(ls[0])
	_, err := r.Read(context.Background(), gatelogs.Query{Budget: gatelogs.NewBudget(int64(max))})
	var inc *gatelogs.Incomplete
	if !errors.As(err, &inc) || !inc.OverBudget || len(inc.Unread) != 0 {
		t.Fatalf("err = %v", err)
	}
	fa.mu.Lock()
	fb.mu.Lock()
	total := fa.bytes + fb.bytes
	fb.mu.Unlock()
	fa.mu.Unlock()
	if page := 10 * (len(ls[0]) + 1); total > max+2*page {
		t.Errorf("fetched %d bytes for a budget of %d", total, max)
	}
	// Shared across reads: a spent budget fetches nothing more.
	b := gatelogs.NewBudget(1)
	r.Read(context.Background(), gatelogs.Query{Budget: b})
	n := len(fa.reqs())
	if _, err := r.Read(context.Background(), gatelogs.Query{Budget: b}); !gatelogs.IsIncomplete(err) || len(fa.reqs()) != n {
		t.Errorf("a spent budget fetched: %v", err)
	}
}

func TestBadHeadersUnreadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Portcullis-Next", "c-1")
		w.Header().Set("X-Portcullis-Truncated", "maybe")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := gatelogs.Replicas{Service: "mcp-gate", Port: 1, Client: dialMap(map[string]string{"10.0.0.1": u.Host}), Lister: func(context.Context) ([]gatelogs.Replica, error) {
		return []gatelogs.Replica{{Name: "mcp-gate-0", Addr: "10.0.0.1"}}, nil
	}}
	if _, err := r.Read(context.Background(), q(t0, time.Time{})); !gatelogs.IsIncomplete(err) {
		t.Errorf("a bad Truncated header: %v", err)
	}
}

// TestRequestsThroughFence: every request of this package goes through
// fsutil.Do (the write fence's transport, contract §20.5): no other Do,
// RoundTrip, Get or Post call in its code.
func TestRequestsThroughFence(t *testing.T) {
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	viaFsutil := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, _ := sel.X.(*ast.Ident)
			switch sel.Sel.Name {
			case "Do":
				if pkg != nil && pkg.Name == "fsutil" {
					viaFsutil++
					return true
				}
				if x, ok := sel.X.(*ast.SelectorExpr); ok && x.Sel.Name == "once" {
					return true // sync.Once
				}
				t.Errorf("%s: a Do outside fsutil.Do", fset.Position(call.Pos()))
			case "RoundTrip":
				t.Errorf("%s: a RoundTrip outside fsutil.Do", fset.Position(call.Pos()))
			case "Get", "Post", "Head", "PostForm":
				// A client's (http.Get, plainClient.Get, r.client().Get);
				// a header's or a query's Get is fine.
				_, onCall := sel.X.(*ast.CallExpr)
				if onCall || pkg != nil && (pkg.Name == "http" || pkg.Name == "plainClient") {
					t.Errorf("%s: %s outside fsutil.Do", fset.Position(call.Pos()), sel.Sel.Name)
				}
			}
			return true
		})
	}
	if viaFsutil != 1 {
		t.Errorf("fsutil.Do calls = %d, want the one in get", viaFsutil)
	}
}

func TestOpenedLogFileSourceUnchanged(t *testing.T) {
	day := t0.Truncate(24 * time.Hour)
	l1 := []string{ln(-26*time.Hour, "alice", "files.example.com")}
	l2 := []string{
		ln(-2*time.Hour, "alice", "files.example.com"),
		ln(-time.Hour, "alice", "files.example.com"), // same (session, host, day)
		ln(-30*time.Minute, "alice", "wiki.example.com"),
		ln(-20*time.Minute, "bob", "files.example.com"),
	}
	dir := t.TempDir()
	for d, ls := range map[time.Time][]string{day.AddDate(0, 0, -1): l1, day: l2} {
		p := filepath.Join(dir, signinhistory.OpenedDirName, d.Format("2006-01-02")+".jsonl")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Join(ls, "\n")+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	files := signinhistory.OpenedLog{Dir: dir}
	// The same lines on two replicas' ports (split between them).
	all := append(append([]string{}, l1...), l2...)
	viaHTTP := signinhistory.OpenedLog{Src: replicas(t, &fakeLog{lines: all[:3]}, &fakeLog{lines: all[3:]})}
	for _, c := range []struct {
		user          string
		since, before time.Time
		limit         int
	}{
		{"Alice", t0.AddDate(0, 0, -30), t0, 50},
		{"alice", t0.AddDate(0, 0, -30), t0, 1},
		{"alice", t0.AddDate(0, 0, -30), t0.Add(-time.Hour), 50},
		{"bob", t0.AddDate(0, 0, -30), t0, 50},
	} {
		want, err1 := files.Entries(context.Background(), c.user, c.since, c.before, c.limit)
		got, err2 := viaHTTP.Entries(context.Background(), c.user, c.since, c.before, c.limit)
		if err1 != nil || err2 != nil || !reflect.DeepEqual(got, want) || len(want) == 0 {
			t.Errorf("%+v: http %+v (%v), files %+v (%v)", c, got, err2, want, err1)
		}
	}
	// Prune leaves the replicas' logs to the gates.
	if n, err := viaHTTP.Prune(1); n != 0 || err != nil {
		t.Errorf("prune over http = %d %v", n, err)
	}
}

// TestOpenedNewestDayFirstPartial: from the replicas the history reads
// day by day, newest first (each day from its own start), stops at limit,
// and answers *Partial at a day boundary when the budget runs out.
func TestOpenedNewestDayFirstPartial(t *testing.T) {
	var ls []string
	for d := 30; d >= 0; d-- {
		for i := 0; i < 20; i++ {
			ls = append(ls, ln(-time.Duration(d)*24*time.Hour+time.Duration(i)*time.Minute, "alice", "h"+strconv.Itoa(i)))
		}
	}
	f := &fakeLog{lines: ls, page: 50}
	ol := signinhistory.OpenedLog{Src: replicas(t, f)}
	es, err := ol.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0.Add(time.Hour), 25)
	if err != nil || len(es) != 25 || !es[0].Time.Equal(t0.Add(19*time.Minute)) || !es[24].Time.Equal(t0.Add(-24*time.Hour+15*time.Minute)) {
		t.Fatalf("entries: %d %v (%v)", len(es), err, es)
	}
	// Two days asked, newest first, each from its own day's start.
	r := f.reqs()
	if len(r) != 2 || !strings.Contains(r[0], "from=2026-11-18T00%3A00%3A00Z") || !strings.Contains(r[1], "from=2026-11-17T00%3A00%3A00Z") {
		t.Errorf("requests = %q", r)
	}
	// A budget of about one day: the newest day, then *Partial at the end
	// of the next one (every newer day read whole).
	small := signinhistory.OpenedLog{Src: replicas(t, &fakeLog{lines: ls, page: 50}), MaxScan: int64(25 * (len(ls[0]) + 1))}
	es, err = small.Entries(context.Background(), "alice", t0.AddDate(0, 0, -30), t0.Add(time.Hour), 100)
	var p *signinhistory.Partial
	if !errors.As(err, &p) || len(es) != 20 || !p.Through.Equal(t0.Truncate(24*time.Hour).Add(-time.Nanosecond)) {
		t.Errorf("budget: %d entries, %v", len(es), err)
	}
}

// ── the tail ───────────────────────────────────────────────

func tailOf(t *testing.T, fakes ...*fakeLog) *gatelogs.Tail {
	return &gatelogs.Tail{R: replicas(t, fakes...), Now: func() time.Time { return t0.Add(time.Hour) }}
}

func TestTailFirstFillWidensBackward(t *testing.T) {
	// Lines every 10 min over 2 days before now (t0+1h).
	var ls []string
	for i := -48 * 6; i <= 6; i++ {
		ls = append(ls, ln(time.Duration(i)*10*time.Minute, "a", strconv.Itoa(i)))
	}
	f := &fakeLog{lines: ls, page: 100}
	tail := tailOf(t, f)
	tail.Max = 20 * (len(ls[0]) + 1) // 20 lines
	out, err := tail.Read(context.Background())
	if err != nil || !reflect.DeepEqual(lines(out), ls[len(ls)-20:]) {
		t.Fatalf("tail = %d lines %v", len(lines(out)), err)
	}
	// The first fill starts an hour back (7 lines, not the log's start),
	// then widens to 4 h back (18 more: past Max, done).
	r := f.reqs()
	if len(r) != 2 || !strings.Contains(r[0], "from=2026-11-18T10%3A00%3A00Z") || !strings.Contains(r[1], "from=2026-11-18T07%3A00%3A00Z") {
		t.Errorf("requests = %q", r)
	}
}

func TestTailCatchingUpIncomplete(t *testing.T) {
	// More lines in the last hour than one read's page budget fetches.
	var ls []string
	for i := 0; i < 30; i++ {
		ls = append(ls, ln(time.Duration(i)*time.Minute, "a", strconv.Itoa(i)))
	}
	f := &fakeLog{lines: ls, page: 4}
	tail := tailOf(t, f)
	tail.R.MaxPages = 3
	out, err := tail.Read(context.Background())
	var inc *gatelogs.Incomplete
	if !errors.As(err, &inc) || !strings.Contains(err.Error(), "catching up") || len(lines(out)) != 12 {
		t.Fatalf("first read: %d lines, %v", len(lines(out)), err)
	}
	// Read on from the cursor next time (no restart from the start).
	for i := 0; i < 2; i++ {
		out, err = tail.Read(context.Background())
	}
	// The third read reaches the end, then widens back (nothing older)
	// to the retention: complete.
	if !reflect.DeepEqual(lines(out), ls) || err != nil {
		t.Errorf("after catching up: %d lines, %v", len(lines(out)), err)
	}
	if r := f.reqs(); strings.Count(strings.Join(r, " "), "from=2026-11-18T10%3A00%3A00Z") != 1 {
		t.Errorf("the fill restarted: %q", r)
	}
}

func TestTailFollowsRestartAndMissingPod(t *testing.T) {
	same := ln(10*time.Second, "a", "same")
	f := &fakeLog{lines: []string{ln(0, "a", "1"), same, same}, page: 2}
	tail := tailOf(t, f)
	tail.Retention = time.Hour // the first fill reaches back the retention at once
	out, err := tail.Read(context.Background())
	if err != nil || len(lines(out)) != 3 {
		t.Fatalf("tail = %q %v", lines(out), err)
	}
	// Appended: one request from the cursor.
	n := len(f.reqs())
	f.set(func(f *fakeLog) { f.lines = append(f.lines, ln(20*time.Second, "a", "4")) })
	if out, err = tail.Read(context.Background()); err != nil || len(lines(out)) != 4 {
		t.Errorf("after an append = %q %v", lines(out), err)
	}
	if r := f.reqs()[n:]; len(r) != 1 || !strings.Contains(r[0], "cursor=g1-3") {
		t.Errorf("follow-up requests = %q", r)
	}
	// Rewritten (another generation): 410, then the restart fails once
	// (503): the next read restarts from the same point and still drops
	// the lines served again, keeping the gate's two identical ones.
	// A genuinely new line identical to two held ones is kept (counted).
	f.set(func(f *fakeLog) { f.gen = "g2"; f.lines = append(f.lines, ln(30*time.Second, "a", "5"), same) })
	srv := f
	calls := 0
	tail.R.Client.Transport = &failOnce{next: tail.R.Client.Transport, after: 1, calls: &calls}
	if _, err := tail.Read(context.Background()); !gatelogs.IsIncomplete(err) {
		t.Errorf("the restart's failure: %v", err)
	}
	out, err = tail.Read(context.Background())
	srv.mu.Lock()
	want := lines(gatelogs.Merge([][]byte{[]byte(strings.Join(srv.lines, "\n") + "\n")})) // time order
	srv.mu.Unlock()
	if err != nil || !reflect.DeepEqual(lines(out), want) {
		t.Errorf("after a rewrite = %q %v", lines(out), err)
	}
	// The pod missing from one list: its state is kept (no refill from
	// the start), its lines shown, the read incomplete.
	lister := tail.R.Lister
	tail.R.Lister = func(context.Context) ([]gatelogs.Replica, error) { return nil, nil }
	out, err = tail.Read(context.Background())
	if !gatelogs.IsIncomplete(err) || len(lines(out)) != len(want) {
		t.Errorf("pod missing: %d lines %v", len(lines(out)), err)
	}
	tail.R.Lister = lister
	n = len(f.reqs())
	if _, err := tail.Read(context.Background()); err != nil {
		t.Errorf("pod back: %v", err)
	}
	if r := f.reqs()[n:]; len(r) != 1 || !strings.Contains(r[0], "cursor=") {
		t.Errorf("pod back requests = %q (a refill?)", r)
	}
}

// failOnce answers 503 to the request number after (0-based) once.
type failOnce struct {
	next  http.RoundTripper
	after int
	calls *int
}

func (f *failOnce) RoundTrip(r *http.Request) (*http.Response, error) {
	n := *f.calls
	*f.calls++
	if n == f.after {
		return &http.Response{StatusCode: 503, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
	}
	return f.next.RoundTrip(r)
}

// TestTailWaiterGetsSnapshot: a read waiting for another that its
// context ends answers the last read's lines, incomplete.
func TestTailWaiterGetsSnapshot(t *testing.T) {
	f := &fakeLog{lines: []string{ln(0, "a", "1")}}
	tail := tailOf(t, f)
	tail.Retention = time.Hour
	if _, err := tail.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	release := make(chan struct{})
	lister := tail.R.Lister
	tail.R.Lister = func(ctx context.Context) ([]gatelogs.Replica, error) {
		close(block)
		<-release
		return lister(ctx)
	}
	done := make(chan struct{})
	go func() { tail.Read(context.Background()); close(done) }()
	<-block
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	out, err := tail.Read(ctx)
	if !gatelogs.IsIncomplete(err) || len(lines(out)) != 1 {
		t.Errorf("waiter: %q %v", lines(out), err)
	}
	close(release)
	<-done
}

func TestWGStatusFromReplicas(t *testing.T) {
	older := `{"version":1,"written":"2026-11-18T10:00:00Z"}`
	newer := `{"version":1,"written":"2026-11-18T10:00:05Z"}`
	hang := make(chan struct{})
	defer close(hang)
	mux := func(body string, wait bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/status" || r.URL.RawQuery != "" {
				http.Error(w, "no", 404)
				return
			}
			if wait {
				select {
				case <-hang:
				case <-r.Context().Done():
				}
				return
			}
			w.Write([]byte(body))
		}))
	}
	s0, s1, s2 := mux("", true), mux(older, false), mux(newer, false)
	defer s0.Close()
	defer s1.Close()
	defer s2.Close()
	ports := map[string]string{"10.0.0.9": s0.Listener.Addr().String(), "10.0.0.1": s1.Listener.Addr().String(), "10.0.0.2": s2.Listener.Addr().String()}
	reps := []gatelogs.Replica{{Name: "wg-0", Addr: "10.0.0.9"}, {Name: "wg-a", Addr: "10.0.0.1"}, {Name: "wg-b", Addr: "10.0.0.2"}, {Name: "wg-c"}}
	r := gatelogs.Replicas{Service: "wg", Port: gatelogs.WGStatusPort, Client: dialMap(ports),
		Lister: func(context.Context) ([]gatelogs.Replica, error) { return reps, nil }}
	// A hung replica doesn't starve the others (asked concurrently).
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := r.Status(ctx)
	if err != nil || string(b) != newer {
		t.Errorf("status = %s %v", b, err)
	}
	reps = []gatelogs.Replica{{Name: "wg-c"}}
	if _, err := r.Status(context.Background()); err == nil {
		t.Error("no running wg answered a status")
	}
}

// fromRequests are the requests' from= values, in order.
func fromRequests(r []string) []string {
	var out []string
	for _, x := range r {
		if i := strings.Index(x, "from="); i >= 0 {
			out = append(out, x[i:])
		}
	}
	return out
}

// TestTailBusyOldSegmentFinishes (fix round 2, the re-review's N1
// probe): one quiet line in the last hour, 200 lines 3 h back, a page
// of 10 and 5 pages a read: the backward segment can't be fetched in
// one read. Each read keeps what it got and goes on after it (never the
// same window twice in a row), and the fill ends complete within 10
// reads, with every line.
func TestTailBusyOldSegmentFinishes(t *testing.T) {
	var ls []string
	for i := 0; i < 200; i++ {
		ls = append(ls, ln(-2*time.Hour+time.Duration(i)*time.Second, "a", strconv.Itoa(i)))
	}
	ls = append(ls, ln(30*time.Minute, "a", "quiet"))
	f := &fakeLog{lines: ls, page: 10}
	tail := tailOf(t, f)
	tail.R.MaxPages = 5
	var err error
	var out []byte
	reads := 0
	for reads < 10 {
		reads++
		if out, err = tail.Read(context.Background()); err == nil {
			break
		}
		if !strings.Contains(err.Error(), "catching up") {
			t.Fatalf("read %d: %v", reads, err)
		}
	}
	if err != nil || !reflect.DeepEqual(lines(out), ls) || tail.OlderNotLoaded() {
		t.Fatalf("after %d reads: %d lines, %v (older not loaded %v)", reads, len(lines(out)), err, tail.OlderNotLoaded())
	}
	fr := fromRequests(f.reqs())
	for i := 1; i < len(fr); i++ {
		if fr[i] == fr[i-1] {
			t.Errorf("the same window twice in a row: %s (%q)", fr[i], fr)
		}
	}
}

// TestTailUnfetchableSegmentGivesUp: a backward segment that never
// answers is halved each read (never the same window twice), and once
// it is MinSegment or less and fails twice the fill is done, with
// OlderNotLoaded set (not incomplete for good); the recent lines are all
// there and the view complete.
func TestTailUnfetchableSegmentGivesUp(t *testing.T) {
	recent := []string{ln(20*time.Minute, "a", "1"), ln(40*time.Minute, "a", "2")}
	f := &fakeLog{lines: recent, failBefore: t0}
	tail := tailOf(t, f)
	var err error
	reads := 0
	for reads < 20 {
		reads++
		if _, err = tail.Read(context.Background()); err == nil {
			break
		}
	}
	out, err2 := tail.Read(context.Background())
	if err != nil || err2 != nil || !tail.OlderNotLoaded() || !reflect.DeepEqual(lines(out), recent) {
		t.Fatalf("after %d reads: %v %v, older not loaded %v, %q", reads, err, err2, tail.OlderNotLoaded(), lines(out))
	}
	fr := fromRequests(f.reqs())
	for i := 1; i < len(fr); i++ {
		if fr[i] == fr[i-1] {
			t.Errorf("the same window twice in a row: %s", fr[i])
		}
	}
}
