package relay

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLink is link's data listener: CONNECT <target>:<port> with the
// right bearer splices to backend; anything else is 403.
type fakeLink struct {
	ln      net.Listener
	token   string
	backend string
	mu      sync.Mutex
	targets []string
}

func newFakeLink(t *testing.T, token, backend string) *fakeLink {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &fakeLink{ln: ln, token: token, backend: backend}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go l.serve(c)
		}
	}()
	return l
}

func (l *fakeLink) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	l.mu.Lock()
	l.targets = append(l.targets, req.Host)
	l.mu.Unlock()
	if req.Method != http.MethodConnect || req.Header.Get("Proxy-Authorization") != "Bearer "+l.token {
		c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	up, err := net.Dial("tcp", l.backend)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer up.Close()
	c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	go io.Copy(up, br)
	io.Copy(c, up)
}

// backend is the app on the worker: plain HTTP (cookies set on several
// domains), and a WebSocket-style upgrade that echoes.
func backend(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			hj, _ := w.(http.Hijacker)
			c, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSet-Cookie: ws=1; Domain=.example.org\r\nSet-Cookie: _oauth2_proxy=evil\r\n\r\n")
			rw.Flush()
			buf := make([]byte, 4)
			for {
				if _, err := io.ReadFull(rw, buf); err != nil {
					return
				}
				c.Write(buf)
			}
		}
		w.Header().Add("Set-Cookie", "app=1; Domain=example.org")
		w.Header().Add("Set-Cookie", "_oauth2_proxy=evil; Domain=.example.org")
		w.Header().Set("X-Seen-Cookie", r.Header.Get("Cookie"))
		w.Header().Set("X-Seen-Host", r.Host)
		w.Header().Set("X-Seen-XFF", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Seen-Proto", r.Header.Get("X-Forwarded-Proto"))
		io.WriteString(w, "hello from the worker")
	}))
}

func relayFor(t *testing.T, link *fakeLink, token string, port int) *httptest.Server {
	cfg := Config{Ports: []int{port}, Target: "immich.web.relay", Link: link.ln.Addr().String(), Token: token, App: "Immich", Server: "nas"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(cfg.Handler(port))
	t.Cleanup(s.Close)
	return s
}

func TestRelayForwardsAndFilters(t *testing.T) {
	be := backend(t)
	defer be.Close()
	link := newFakeLink(t, "tok", strings.TrimPrefix(be.URL, "http://"))
	rs := relayFor(t, link, "tok", 2283)
	req, _ := http.NewRequest("GET", rs.URL+"/photos", nil)
	req.Host = "photos.example.org"
	req.Header.Set("Cookie", "_oauth2_proxy_0=s; app=1; __Host-portcullis_ext-2=e")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "hello from the worker" {
		t.Fatalf("body %q", b)
	}
	if got := resp.Header.Get("X-Seen-Cookie"); got != "app=1" {
		t.Errorf("the app saw cookies %q", got)
	}
	if resp.Header.Get("X-Seen-Host") != "photos.example.org" || resp.Header.Get("X-Seen-XFF") != "203.0.113.7" || resp.Header.Get("X-Seen-Proto") != "https" {
		t.Errorf("forwarded headers: host %q xff %q proto %q", resp.Header.Get("X-Seen-Host"), resp.Header.Get("X-Seen-XFF"), resp.Header.Get("X-Seen-Proto"))
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) != 1 || sc[0] != "app=1" {
		t.Errorf("set-cookie %q", sc)
	}
	link.mu.Lock()
	if len(link.targets) == 0 || link.targets[0] != "immich.web.relay:2283" {
		t.Errorf("CONNECT targets %v", link.targets)
	}
	link.mu.Unlock()
}

func TestWebSocketThroughRelay(t *testing.T) {
	be := backend(t)
	defer be.Close()
	link := newFakeLink(t, "tok", strings.TrimPrefix(be.URL, "http://"))
	rs := relayFor(t, link, "tok", 2283)
	c, err := net.Dial("tcp", strings.TrimPrefix(rs.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: photos.example.org\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\nCookie: _oauth2_proxy=s\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) != 1 || sc[0] != "ws=1" {
		t.Errorf("upgrade set-cookie %q", sc)
	}
	for i := 0; i < 3; i++ {
		io.WriteString(c, "ping")
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo %d: %q %v", i, buf, err)
		}
	}
}

func TestOfflinePage(t *testing.T) {
	// A link that refuses (wrong token) or is gone: the offline page.
	be := backend(t)
	defer be.Close()
	link := newFakeLink(t, "right", strings.TrimPrefix(be.URL, "http://"))
	cfg := Config{Ports: []int{80}, Target: "immich.web.relay", Link: link.ln.Addr().String(), Token: "wrong",
		App: "<script>alert(1)</script>Photos", Server: "nas\"><b>"}
	s := httptest.NewServer(cfg.Handler(80))
	defer s.Close()
	gone := cfg
	gone.Link = "127.0.0.1:1"
	s2 := httptest.NewServer(gone.Handler(80))
	defer s2.Close()
	for _, u := range []string{s.URL, s2.URL} {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(b)
		if resp.StatusCode != 503 || resp.Header.Get("Cache-Control") != "no-store" || len(resp.Header.Values("Set-Cookie")) != 0 {
			t.Errorf("%s: %d %v", u, resp.StatusCode, resp.Header)
		}
		if strings.Contains(body, "<script>") || strings.Contains(body, "<b>") ||
			!strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;Photos runs on nas&#34;&gt;&lt;b&gt;, which is offline") {
			t.Errorf("page %s", body)
		}
	}
	if !strings.Contains(string(mustGet(t, s2.URL)), "which is offline") {
		t.Error("copy")
	}
}

func mustGet(t *testing.T, u string) []byte {
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

// TestRelayHasNoOtherListener: the relay listens on exactly its ports.
func TestRelayHasNoOtherListener(t *testing.T) {
	ports, err := ParseListen(":0")
	if err == nil {
		t.Fatalf(":0 accepted: %v", ports)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := Config{Ports: []int{p}, Target: "immich.web.relay", Link: "127.0.0.1:3129", Token: "t"}
	lns, err := cfg.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, l := range lns {
			l.Close()
		}
	}()
	if len(lns) != 1 || lns[0].Addr().(*net.TCPAddr).Port != p {
		t.Errorf("listeners %v", lns)
	}
	for _, bad := range []string{"", "80", ":80,:80", ":70000", ":80,x", strings.Repeat(":1,", 17) + ":2"} {
		if _, err := ParseListen(bad); err == nil {
			t.Errorf("RELAY_LISTEN %q accepted", bad)
		}
	}
	if got, err := ParseListen(":8011,:10000"); err != nil || len(got) != 2 {
		t.Errorf("two ports: %v %v", got, err)
	}
	for _, bad := range []Config{
		{Ports: []int{1}, Target: "x.relay", Link: "a:1", Token: "t"},
		{Ports: []int{1}, Target: "immich.web.example.org", Link: "a:1", Token: "t"},
		{Ports: []int{1}, Target: "immich.web.relay", Link: "nohost", Token: "t"},
		{Ports: []int{1}, Target: "immich.web.relay", Link: "a:1", Token: ""},
		{Ports: nil, Target: "immich.web.relay", Link: "a:1", Token: "t"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	_ = strconv.Itoa
}
