package gatelogs_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/gatelogs"
	"github.com/portcullis/hub/internal/signinhistory"
)

var t0 = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

// fakeLog is a log port as contract §20.10 has it: lines in file order,
// an exclusive cursor (<gen>-<index>), from = the first line at or after
// it, at most page lines per answer (the server's own cut, so paging is
// exercised), 410 for another generation.
type fakeLog struct {
	mu       sync.Mutex
	lines    []string
	gen      string
	page     int
	status   int    // non-zero: every request answers it
	body     []byte // non-nil: the 200's body as is
	requests []string
	expireAt int // a cursor at this index answers 410 once (0: never)
}

var fakeCursorRe = regexp.MustCompile(`^([a-z0-9]+)-([0-9]+)$`)

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
	if f.body != nil {
		w.Header().Set("X-Portcullis-Next", "x-0")
		w.Header().Set("X-Portcullis-Truncated", "false")
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
		if m[1] != f.gen || start > len(f.lines) || f.expireAt != 0 && start == f.expireAt {
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
		start = len(f.lines)
		for i, l := range f.lines {
			if !timeOf(l).Before(since) {
				start = i
				break
			}
		}
	}
	end := min(start+f.page, len(f.lines))
	var b bytes.Buffer
	for _, l := range f.lines[start:end] {
		b.WriteString(l + "\n")
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Portcullis-Next", fmt.Sprintf("%s-%d", f.gen, end))
	w.Header().Set("X-Portcullis-Truncated", strconv.FormatBool(end < len(f.lines)))
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

// serve starts f on a listener; the replica's address and port.
func serve(t *testing.T, f *fakeLog) (string, int) {
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
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	return host, p
}

// replicas: the fakes as one gate's replicas, all on one port (each on
// its own loopback address is not portable: a per-replica port map in
// the transport instead).
func replicas(t *testing.T, fakes ...*fakeLog) gatelogs.Replicas {
	t.Helper()
	ports := map[string]string{}
	var reps []gatelogs.Replica
	for i, f := range fakes {
		host, port := serve(t, f)
		addr := fmt.Sprintf("10.0.0.%d", i+1)
		ports[addr] = net.JoinHostPort(host, strconv.Itoa(port))
		reps = append(reps, gatelogs.Replica{Name: fmt.Sprintf("gate-%d", i), Addr: addr})
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(a)
		return (&net.Dialer{}).DialContext(ctx, network, ports[h])
	}}
	return gatelogs.Replicas{Service: "group-gate", Port: gatelogs.GroupGatePort, Client: &http.Client{Transport: tr},
		Lister: func(context.Context) ([]gatelogs.Replica, error) { return reps, nil }}
}

func lines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestMergeTwoReplicasOrdered(t *testing.T) {
	a := []string{ln(0, "alice", "a"), ln(2*time.Second, "alice", "c"), ln(4*time.Second, "alice", "e")}
	b := []string{ln(time.Second, "bob", "b"), ln(2*time.Second, "bob", "c2"), ln(3*time.Second, "bob", "d")}
	// Merge: by time, then replica; a line twice from one replica once,
	// the same line from two replicas twice.
	got := lines(gatelogs.Merge([][]byte{[]byte(strings.Join(append(a, a[1]), "\n") + "\n"), []byte(strings.Join(append(b, a[0]), "\n") + "\n")}))
	want := []string{a[0], a[0], b[0], a[1], b[1], b[2], a[2]}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Over the ports: paged (2 lines a page) until truncated is false,
	// from on the first page only, the cursor after.
	fa, fb := &fakeLog{lines: a}, &fakeLog{lines: b}
	r := replicas(t, fa, fb)
	out, err := r.Read(context.Background(), t0, time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{a[0], b[0], a[1], b[1], b[2], a[2]}; !reflect.DeepEqual(lines(out), want) {
		t.Errorf("Read = %q", lines(out))
	}
	if len(fa.requests) != 2 || !strings.Contains(fa.requests[0], "from=2026-11-18T10%3A00%3A00Z") ||
		strings.Contains(fa.requests[1], "from=") || !strings.Contains(fa.requests[1], "cursor=g1-2") {
		t.Errorf("requests = %q", fa.requests)
	}
	// keep and the window.
	out, err = r.Read(context.Background(), t0.Add(time.Second), t0.Add(3*time.Second), func(l []byte) bool { return bytes.Contains(l, []byte("bob")) })
	if err != nil || !reflect.DeepEqual(lines(out), b) {
		t.Errorf("bob's = %q %v", lines(out), err)
	}
}

func TestCursorExpiredRestartsFromLastTime(t *testing.T) {
	ls := []string{ln(0, "alice", "a"), ln(time.Second, "alice", "b"), ln(time.Second, "alice", "c"), ln(2*time.Second, "alice", "d"), ln(3*time.Second, "alice", "e")}
	f := &fakeLog{lines: ls, expireAt: 2}
	out, err := replicas(t, f).Read(context.Background(), time.Time{}, time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lines(out), ls) {
		t.Errorf("after a restart = %q", lines(out))
	}
	// The first page has neither from nor cursor (the start), the restart
	// from = the last line's time (b's, 10:00:01), and b again dropped.
	if len(f.requests) != 4 || strings.Contains(f.requests[0], "from=") || !strings.Contains(f.requests[1], "cursor=g1-2") ||
		!strings.Contains(f.requests[2], "from=2026-11-18T10%3A00%3A01Z") {
		t.Errorf("requests = %q", f.requests)
	}
}

func TestReplicaDownMarksIncomplete(t *testing.T) {
	good := &fakeLog{lines: []string{ln(0, "alice", "a"), ln(time.Second, "alice", "b")}}
	for _, code := range []int{503, 500} {
		r := replicas(t, good, &fakeLog{status: code})
		out, err := r.Read(context.Background(), t0, time.Time{}, nil)
		var inc *gatelogs.Incomplete
		if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Unread, []string{"gate-1"}) || inc.NoneRead() {
			t.Errorf("%d: err = %v", code, err)
		}
		if !reflect.DeepEqual(lines(out), good.lines) {
			t.Errorf("%d: lines = %q", code, lines(out))
		}
	}
	// Not running (no address), and no replica at all.
	r := replicas(t, good)
	r.Lister = func(context.Context) ([]gatelogs.Replica, error) {
		return []gatelogs.Replica{{Name: "gate-0", Addr: "10.0.0.1"}, {Name: "gate-1"}}, nil
	}
	if _, err := r.Read(context.Background(), t0, time.Time{}, nil); !gatelogs.IsIncomplete(err) {
		t.Errorf("pending replica: %v", err)
	}
	r.Lister = func(context.Context) ([]gatelogs.Replica, error) { return nil, nil }
	var inc *gatelogs.Incomplete
	if _, err := r.Read(context.Background(), t0, time.Time{}, nil); !errors.As(err, &inc) || !inc.NoneRead() {
		t.Errorf("no replica: %v", err)
	}
	// The opened log over it: the other's entries, *Incomplete (the
	// history names the source unknown; impersonation apps are marked
	// incomplete on any error, internal/hub TestImpersonationAppsHTTPIncomplete).
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
	out, err := r.Read(context.Background(), t0, time.Time{}, nil)
	var inc *gatelogs.Incomplete
	if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Unread, []string{"gate-1"}) || !strings.Contains(err.Error(), "4 MiB") {
		t.Errorf("err = %v", err)
	}
	if !reflect.DeepEqual(lines(out), good.lines) {
		t.Errorf("lines = %q", lines(out))
	}
	// Exactly 4 MiB is an answer.
	exact := append(bytes.Repeat([]byte("x"), gatelogs.MaxAnswer-1), '\n')
	if _, err := replicas(t, &fakeLog{body: exact}).Read(context.Background(), t0, time.Time{}, nil); err != nil {
		t.Errorf("4 MiB exactly: %v", err)
	}
}

func TestBadHeadersUnreadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Portcullis-Next", "c-1")
		w.Header().Set("X-Portcullis-Truncated", "maybe")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	r := gatelogs.Replicas{Service: "mcp-gate", Port: p, Lister: func(context.Context) ([]gatelogs.Replica, error) {
		return []gatelogs.Replica{{Name: "mcp-gate-0", Addr: host}}, nil
	}}
	if _, err := r.Read(context.Background(), t0, time.Time{}, nil); !gatelogs.IsIncomplete(err) {
		t.Errorf("a bad Truncated header: %v", err)
	}
}

// TestReadsPassStandingBy: the requests go through the write fence's
// transport (fsutil.Do), and a GET passes while the Hub stands by.
func TestReadsPassStandingBy(t *testing.T) {
	fsutil.SetWriteGate(func() error { return errors.New("standing by") })
	defer fsutil.SetWriteGate(nil)
	f := &fakeLog{lines: []string{ln(0, "alice", "a")}}
	out, err := replicas(t, f).Read(context.Background(), t0, time.Time{}, nil)
	if err != nil || len(lines(out)) != 1 {
		t.Errorf("standing by: %q %v", lines(out), err)
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

func TestTailFollowsAndKeepsNewest(t *testing.T) {
	f := &fakeLog{lines: []string{ln(0, "a", "1"), ln(time.Second, "a", "2"), ln(2*time.Second, "a", "3")}}
	r := replicas(t, f)
	tail := &gatelogs.Tail{R: r, Max: len(f.lines[0])*2 + 2}
	out, err := tail.Read(context.Background())
	if err != nil || !reflect.DeepEqual(lines(out), f.lines[1:]) {
		t.Fatalf("tail = %q %v", lines(out), err)
	}
	n := len(f.requests)
	f.mu.Lock()
	f.lines = append(f.lines, ln(3*time.Second, "a", "4"))
	f.mu.Unlock()
	out, err = tail.Read(context.Background())
	if err != nil || !reflect.DeepEqual(lines(out), f.lines[2:]) {
		t.Errorf("tail after an append = %q %v", lines(out), err)
	}
	if got := f.requests[n:]; len(got) != 1 || !strings.Contains(got[0], "cursor=g1-3") {
		t.Errorf("follow-up requests = %q", got)
	}
	// The log rewritten (another generation): 410, from the last time,
	// nothing kept twice.
	f.mu.Lock()
	f.gen = "g2"
	f.lines = append(f.lines, ln(4*time.Second, "a", "5"))
	f.mu.Unlock()
	out, err = tail.Read(context.Background())
	if err != nil || !reflect.DeepEqual(lines(out), f.lines[3:]) {
		t.Errorf("tail after a rewrite = %q %v", lines(out), err)
	}
	// The replica down: its kept lines, incomplete.
	f.mu.Lock()
	f.status = 503
	f.mu.Unlock()
	out, err = tail.Read(context.Background())
	var inc *gatelogs.Incomplete
	if !errors.As(err, &inc) || !inc.NoneRead() || len(lines(out)) != 2 {
		t.Errorf("tail down = %q %v", lines(out), err)
	}
}

func TestWGStatusFromReplicas(t *testing.T) {
	older := `{"version":1,"written":"2026-11-18T10:00:00Z"}`
	newer := `{"version":1,"written":"2026-11-18T10:00:05Z"}`
	mux := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/status" || r.URL.RawQuery != "" {
				http.Error(w, "no", 404)
				return
			}
			w.Write([]byte(body))
		}))
	}
	s1, s2 := mux(older), mux(newer)
	defer s1.Close()
	defer s2.Close()
	ports := map[string]string{"10.0.0.1": s1.Listener.Addr().String(), "10.0.0.2": s2.Listener.Addr().String()}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(a)
		return (&net.Dialer{}).DialContext(ctx, network, ports[h])
	}}
	reps := []gatelogs.Replica{{Name: "wg-a", Addr: "10.0.0.1"}, {Name: "wg-b", Addr: "10.0.0.2"}, {Name: "wg-c"}}
	r := gatelogs.Replicas{Service: "wg", Port: gatelogs.WGStatusPort, Client: &http.Client{Transport: tr},
		Lister: func(context.Context) ([]gatelogs.Replica, error) { return reps, nil }}
	b, err := r.Status(context.Background())
	if err != nil || string(b) != newer {
		t.Errorf("status = %s %v", b, err)
	}
	reps = []gatelogs.Replica{{Name: "wg-c"}}
	if _, err := r.Status(context.Background()); err == nil {
		t.Error("no running wg answered a status")
	}
}
