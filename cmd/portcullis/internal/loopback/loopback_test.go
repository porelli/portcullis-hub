package loopback

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testPorts gives each test its own three free ports.
func testPorts(t *testing.T) {
	t.Helper()
	old := Ports
	var ps []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, ln.Addr().(*net.TCPAddr).Port)
		ln.Close()
	}
	Ports = ps
	t.Cleanup(func() { Ports = old })
}

func get(t *testing.T, l *Listener, path string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(l.Port()) + path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b), resp.Header
}

func TestLoopbackPortsTaken(t *testing.T) {
	testPorts(t)
	var held []net.Listener
	for _, p := range Ports {
		ln, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ln)
	}
	defer func() {
		for _, l := range held {
			l.Close()
		}
	}()
	if _, err := Listen(context.Background()); !errors.Is(err, ErrPortsTaken) {
		t.Fatalf("err = %v", err)
	}
	// The second port when the first is taken.
	held[1].Close()
	l, err := Listen(context.Background())
	if err != nil || l.Port() != Ports[1] {
		t.Fatalf("listen = %v %v", l, err)
	}
	l.Close()
}

func TestLoopbackWrongStateIs404(t *testing.T) {
	testPorts(t)
	l, _ := Listen(context.Background())
	got := make(chan string, 1)
	go func() { c, _ := l.Wait(context.Background(), "the-state"); got <- c }()
	time.Sleep(20 * time.Millisecond)
	for _, p := range []string{"/callback?state=other&code=c", "/callback?code=c", "/", "/callback/x?state=the-state&code=c", "/callback?state=the-state&state=x&code=c"} {
		if code, _, _ := get(t, l, p); code != 404 {
			t.Errorf("%s = %d", p, code)
		}
	}
	if code, _, _ := get(t, l, "/callback?state=the-state&code=the-code"); code != 200 {
		t.Fatalf("good callback = %d", code)
	}
	if c := <-got; c != "the-code" {
		t.Errorf("code %q", c)
	}
}

func TestLoopbackErrorParam(t *testing.T) {
	testPorts(t)
	l, _ := Listen(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := l.Wait(context.Background(), "s"); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	get(t, l, "/callback?state=s&error=access_denied&error_description=%3Cscript%3E")
	err := <-errc
	var se *SignInError
	if !errors.As(err, &se) || se.Code != "access_denied" || strings.Contains(err.Error(), "script") {
		t.Errorf("err = %v", err)
	}
}

func TestLoopbackSecondCallback404(t *testing.T) {
	testPorts(t)
	l, _ := Listen(context.Background())
	l.mu.Lock()
	l.want = "s"
	l.mu.Unlock()
	if code, _, _ := get(t, l, "/callback?state=s&code=one"); code != 200 {
		t.Fatal("first")
	}
	if code, _, _ := get(t, l, "/callback?state=s&code=two"); code != 404 {
		t.Errorf("second callback = %d", code)
	}
	if c, err := l.Wait(context.Background(), "s"); c != "one" || err != nil {
		t.Errorf("code %q %v", c, err)
	}
	// Closed afterwards.
	if _, err := http.Get("http://127.0.0.1:" + strconv.Itoa(l.Port()) + "/callback"); err == nil {
		t.Error("listener still open after Wait")
	}
}

func TestLoopbackTimeout(t *testing.T) {
	testPorts(t)
	l, _ := Listen(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Wait(ctx, "s"); err == nil {
		t.Error("no timeout")
	}
	if Timeout != 5*time.Minute {
		t.Errorf("timeout %s", Timeout)
	}
	if _, err := http.Get("http://127.0.0.1:" + strconv.Itoa(l.Port()) + "/callback"); err == nil {
		t.Error("listener open after the timeout")
	}
}

func TestLoopbackBindsLoopbackOnly(t *testing.T) {
	testPorts(t)
	l, _ := Listen(context.Background())
	defer l.Close()
	a := l.ln.Addr().(*net.TCPAddr)
	if !a.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("bound %s", a)
	}
	if l.RedirectURI() != "http://127.0.0.1:"+strconv.Itoa(l.Port())+"/callback" {
		t.Errorf("redirect %s", l.RedirectURI())
	}
}

func TestLoopbackPageNoStoreNoScript(t *testing.T) {
	testPorts(t)
	l, _ := Listen(context.Background())
	l.mu.Lock()
	l.want = "s"
	l.mu.Unlock()
	code, body, h := get(t, l, "/callback?state=s&code=c")
	if code != 200 || h.Get("Cache-Control") != "no-store" || strings.Contains(strings.ToLower(body), "<script") || !strings.Contains(body, "You can close this tab") {
		t.Errorf("%d %v %s", code, h, body)
	}
	l.Close()
}

func TestLoopbackRealPorts(t *testing.T) {
	if Ports[0] != 38917 || Ports[1] != 38918 || Ports[2] != 38919 {
		t.Errorf("ports %v", Ports)
	}
}
