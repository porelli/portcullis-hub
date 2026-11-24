package nodeadm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blackhole is a TCP proxy whose connections can be frozen: a frozen one
// stays open but carries nothing either way, as when nodeadm's node is
// cut off (packets dropped, no reset). New connections go through.
type blackhole struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  []*atomic.Bool
}

func newBlackhole(t *testing.T, target string) *blackhole {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{ln: ln, target: target}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			frozen := &atomic.Bool{}
			b.mu.Lock()
			b.conns = append(b.conns, frozen)
			b.mu.Unlock()
			pipe := func(dst, src net.Conn) {
				buf := make([]byte, 32<<10)
				for {
					n, err := src.Read(buf)
					if n > 0 && !frozen.Load() {
						dst.Write(buf[:n])
					}
					if err != nil {
						dst.Close()
						return
					}
				}
			}
			go pipe(s, c)
			go pipe(c, s)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return b
}

// freeze stops every connection open now.
func (b *blackhole) freeze() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, f := range b.conns {
		f.Store(true)
	}
	return len(b.conns)
}

// TestNodeadmClientDropsDeadConnection: once nodeadm's node is cut off,
// the HTTP/2 connection the Hub holds to it is dead but never reset. A
// call that times out on it leaves it in the pool, and without a health
// check every later call reused it and timed out too (seen in e2e-ha-k3d:
// the Hub blind to nodeadm for 13 min after nodeadm moved to another
// node). The client pings an idle connection and drops it when the ping
// isn't answered, so a later call dials again and reaches the new nodeadm.
func TestNodeadmClientDropsDeadConnection(t *testing.T) {
	defer func(a, b time.Duration) { h2SendPingTimeout, h2PingTimeout = a, b }(h2SendPingTimeout, h2PingTimeout)
	h2SendPingTimeout, h2PingTimeout = time.Second, time.Second
	var h2 atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h2.Store(r.ProtoMajor == 2)
		io.WriteString(w, `{"v":1,"taken_at":"t","nodes":[],"enrolling":[],"pods":[],"quorum":{"etcd":{"voters":1,"healthy":1},"vault":{"voters":1,"healthy":1},"sentinel":{"voters":1,"healthy":1}},"postgres":{"instances":1,"sync_standbys":0,"primary":null},"volumes":[],"errors":[]}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	bh := newBlackhole(t, srv.Listener.Addr().String())
	cl := &Client{BaseURL: "https://" + bh.ln.Addr().String(), TLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	if _, err := cl.Cluster(context.Background()); err != nil {
		t.Fatalf("the first snapshot: %v", err)
	}
	if !h2.Load() {
		t.Fatal("the client didn't speak HTTP/2 (the case under test)")
	}
	if n := bh.freeze(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
	deadline := time.Now().Add(8 * time.Second)
	for i := 0; ; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := cl.Cluster(ctx)
		cancel()
		if err == nil {
			if i == 0 {
				t.Fatal("a snapshot over the frozen connection succeeded: the blackhole doesn't hold")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still failing %d calls after the connection died: %v", i+1, err)
		}
	}
}
