package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
)

// Stream ids of the multiplexed (non-TTY) format.
const (
	Stdout = byte(stdcopy.Stdout)
	Stderr = byte(stdcopy.Stderr)
)

// apiVersion matches the /v1.NN prefix the SDK puts on every path but
// /_ping (it negotiates the version over /_ping first; these fakes don't
// answer it, so the SDK falls back to its maximum version).
var apiVersion = regexp.MustCompile(`^/v[0-9]+\.[0-9]+/`)

func unversioned(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = apiVersion.ReplaceAllString(r.URL.Path, "/")
		h.ServeHTTP(w, r)
	})
}

// hijack answers an exec start the way the daemon does (101, then the
// raw multiplexed stream on the connection).
// It reads the request body first, like the daemon: closing a socket with
// unread input makes the kernel send RST, which can drop the output.
func hijack(t *testing.T, w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter) {
	io.Copy(io.Discard, r.Body)
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return nil, nil
	}
	rw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	rw.Flush()
	return conn, rw
}

func frame(stream byte, s string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return append(h, s...)
}

func newTestClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(unversioned(h))
	t.Cleanup(srv.Close)
	c, err := New("tcp://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNew(t *testing.T) {
	for _, h := range []string{"", "unix:///var/run/docker.sock", "tcp://socket-proxy-hub:2375", "http://1.2.3.4:2375"} {
		if _, err := New(h); err != nil {
			t.Errorf("New(%q): %v", h, err)
		}
	}
	for _, h := range []string{"unix://", "tcp://", "https://x:2376", "ssh://host", "::bad"} {
		if _, err := New(h); err == nil {
			t.Errorf("New(%q) accepted", h)
		}
	}
}

func TestListContainers(t *testing.T) {
	var gotFilters string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" || r.URL.Query().Get("all") != "1" {
			http.Error(w, `{"message":"bad path"}`, 404)
			return
		}
		gotFilters = r.URL.Query().Get("filters")
		fmt.Fprint(w, `[{"Id":"abc123","Names":["/portcullis-grafana-grafana-1"],"State":"running","Status":"Up 2 minutes",
			"Labels":{"com.docker.compose.project":"portcullis-grafana","com.docker.compose.service":"grafana"}}]`)
	}))
	cs, err := c.ListContainers(context.Background(), ProjectFilter("portcullis-grafana"))
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]map[string]bool
	if err := json.Unmarshal([]byte(gotFilters), &f); err != nil || len(f["label"]) != 1 || !f["label"]["com.docker.compose.project=portcullis-grafana"] {
		t.Errorf("filters = %q", gotFilters)
	}
	if len(cs) != 1 || cs[0].Name() != "portcullis-grafana-grafana-1" || cs[0].Project() != "portcullis-grafana" || cs[0].Service() != "grafana" || cs[0].State != "running" {
		t.Errorf("containers = %+v", cs)
	}
}

func TestAPIError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, `{"message":"No such container: x"}`)
	}))
	_, err := c.Logs(context.Background(), "x", 10, false)
	if !IsNotFound(err) || !strings.Contains(err.Error(), "No such container") {
		t.Errorf("err = %v", err)
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Error("ping should fail")
	}
}

func logsServer(t *testing.T, tty bool, contentType string, body []byte, gotQuery *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/c1/json":
			fmt.Fprintf(w, `{"Config":{"Tty":%v}}`, tty)
		case "/containers/c1/logs":
			*gotQuery = r.URL.RawQuery
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestLogsMultiplexed(t *testing.T) {
	var body bytes.Buffer
	body.Write(frame(Stdout, "2024-01-01T00:00:01.000000000Z hello\n"))
	body.Write(frame(Stderr, "2024-01-01T00:00:02.000000000Z oops\n"))
	var q string
	for _, ct := range []string{"", "application/vnd.docker.multiplexed-stream", "application/vnd.docker.raw-stream"} {
		c := newTestClient(t, logsServer(t, false, ct, body.Bytes(), &q))
		out, err := c.Logs(context.Background(), "c1", 50, true)
		if err != nil {
			t.Fatal(err)
		}
		want := "2024-01-01T00:00:01.000000000Z hello\n2024-01-01T00:00:02.000000000Z oops\n"
		if string(out) != want {
			t.Errorf("ct=%q: logs = %q", ct, out)
		}
	}
	for _, p := range []string{"stdout=1", "stderr=1", "tail=50", "timestamps=1"} {
		if !strings.Contains(q, p) {
			t.Errorf("query %q missing %s", q, p)
		}
	}
}

func TestLogsTTY(t *testing.T) {
	var q string
	raw := []byte("\x01not a frame header, raw tty output\n")
	c := newTestClient(t, logsServer(t, true, "application/vnd.docker.raw-stream", raw, &q))
	out, err := c.Logs(context.Background(), "c1", 10, false)
	if err != nil || !bytes.Equal(out, raw) {
		t.Errorf("tty logs = %q, %v", out, err)
	}
	if strings.Contains(q, "timestamps") {
		t.Errorf("timestamps requested: %q", q)
	}
}

func TestMergeLogs(t *testing.T) {
	got := string(MergeLogs(map[string][]byte{
		"web": []byte("2024-01-01T00:00:01Z w1\n2024-01-01T00:00:03Z w2\n"),
		"db":  []byte("2024-01-01T00:00:02Z d1\nno-timestamp line\n"),
	}, 3))
	// Lines without a timestamp sort first (zero time), so the merged order
	// is [no-ts, w1, d1, w2] and tail=3 keeps the last three.
	want := "web  | w1\ndb   | d1\nweb  | w2\n"
	if got != want {
		t.Errorf("merged =\n%q\nwant\n%q", got, want)
	}
	single := string(MergeLogs(map[string][]byte{"web": []byte("2024-01-01T00:00:01Z only\n")}, 10))
	if single != "only\n" {
		t.Errorf("single = %q", single)
	}
}

func TestExec(t *testing.T) {
	var gotCmd []string
	var started int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/containers/c1/exec":
			var body struct {
				Cmd          []string
				AttachStdout bool
				AttachStderr bool
				Tty          bool
			}
			json.NewDecoder(r.Body).Decode(&body)
			if !body.AttachStdout || !body.AttachStderr || body.Tty {
				http.Error(w, `{"message":"bad create"}`, 400)
				return
			}
			gotCmd = body.Cmd
			w.WriteHeader(201)
			fmt.Fprint(w, `{"Id":"e1"}`)
		case r.Method == "POST" && r.URL.Path == "/exec/e1/start":
			atomic.StoreInt32(&started, 1)
			conn, rw := hijack(t, w, r)
			if conn == nil {
				return
			}
			rw.Write(frame(Stdout, "hello\n"))
			rw.Write(frame(Stderr, "warn\n"))
			rw.Flush()
			conn.Close()
		case r.URL.Path == "/exec/e1/json":
			fmt.Fprint(w, `{"Running":false,"ExitCode":3}`)
		default:
			http.NotFound(w, r)
		}
	}))
	res, err := c.Exec(context.Background(), "c1", []string{"/bin/sh", "-c", "echo hello"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Output) != "hello\nwarn\n" || res.ExitCode != 3 || res.TimedOut {
		t.Errorf("res = %+v (%q)", res, res.Output)
	}
	if strings.Join(gotCmd, " ") != "/bin/sh -c echo hello" {
		t.Errorf("cmd = %v", gotCmd)
	}
}

func TestExecTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/c1/exec":
			fmt.Fprint(w, `{"Id":"e1"}`)
		case "/exec/e1/start":
			conn, rw := hijack(t, w, r)
			if conn == nil {
				return
			}
			defer conn.Close()
			rw.Write(frame(Stdout, "partial\n"))
			rw.Flush()
			closed := make(chan struct{})
			go func() { io.Copy(io.Discard, conn); close(closed) }() // returns when the client hangs up
			select {
			case <-release:
			case <-closed:
			}
		default:
			http.NotFound(w, r)
		}
	}))
	start := time.Now()
	res, err := c.Exec(context.Background(), "c1", []string{"sleep", "100"}, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != -1 || string(res.Output) != "partial\n" {
		t.Errorf("res = %+v (%q)", res, res.Output)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timeout not enforced")
	}
}

func TestEvents(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" || !strings.Contains(r.URL.Query().Get("filters"), "container") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, `{"Type":"container","Action":"start","Actor":{"ID":"c1","Attributes":{"com.docker.compose.project":"portcullis-a"}}}`)
		w.(http.Flusher).Flush()
		fmt.Fprintln(w, `{"Type":"container","Action":"die","Actor":{"ID":"c1","Attributes":{"com.docker.compose.project":"portcullis-a"}}}`)
	}))
	var got []string
	err := c.Events(context.Background(), Filters{"type": {"container"}}, func(e Event) {
		got = append(got, e.Action+":"+e.Actor.Attributes[LabelProject])
	})
	if err != io.EOF {
		t.Errorf("err = %v, want EOF at stream end", err)
	}
	if strings.Join(got, ",") != "start:portcullis-a,die:portcullis-a" {
		t.Errorf("events = %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	blocking := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" { // the SDK's HEAD /_ping must not block
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	done := make(chan error, 1)
	go func() { done <- blocking.Events(ctx, nil, func(Event) {}) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Events did not return on cancel")
	}
}

func TestUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			fmt.Fprint(w, "OK")
			return
		}
		http.NotFound(w, r)
	})}
	go srv.Serve(l)
	defer srv.Close()
	c, err := New("unix://" + sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("ping over unix socket: %v", err)
	}
}
