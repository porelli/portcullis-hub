package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// probeServer is an HTTPS server whose certificate names cn and answers
// /healthz with status.
func probeServer(t *testing.T, ca *testCA, cn string, status int) string {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Host != "auth.example.org" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(status)
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{ca.tlsCert(t, cn)}}
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s.Listener.Addr().String()
}

// TestProbeClasses: ok, tls (another name), http_status, refused,
// timeout; a node with several addresses is ok when one is; the
// round's shape.
func TestProbeClasses(t *testing.T) {
	r := newRig(t, "server")
	ca := newCA(t)
	egressSrv := probeServer(t, ca, "api.dns.example", 200)
	route := map[string]string{
		"198.51.100.1:443": probeServer(t, ca, "auth.example.org", 200),
		"198.51.100.2:443": probeServer(t, ca, "other.example.net", 200),
		"198.51.100.3:443": probeServer(t, ca, "auth.example.org", 503),
		"198.51.100.6:443": probeServer(t, ca, "auth.example.org", 200),
	}
	r.a.cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch addr {
		case "198.51.100.4:443", "198.51.100.5:443":
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		case "198.51.100.7:443":
			<-ctx.Done()
			return nil, ctx.Err()
		case "api.dns.example:443":
			return net.Dial("tcp", egressSrv)
		}
		if to, ok := route[addr]; ok {
			return net.Dial("tcp", to)
		}
		return nil, errors.New("no route")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r.a.cfg.EgressRoots = pool
	old := probeTimeout
	probeTimeout = time.Second
	t.Cleanup(func() { probeTimeout = old })
	tg := na.ProbeTargets{Domain: "example.org", EgressHost: "api.dns.example", Targets: []na.ProbeTarget{
		{Node: "n1", Site: "main", Address: "198.51.100.1"},
		{Node: "n2", Site: "edge", Address: "198.51.100.2"},
		{Node: "n3", Site: "main", Address: "198.51.100.3"},
		{Node: "n4", Site: "main", Address: "198.51.100.4"},
		{Node: "n5", Site: "main", Address: "198.51.100.5"},
		{Node: "n5", Site: "main", Address: "198.51.100.6"},
		{Node: "n7", Site: "main", Address: "198.51.100.7"},
	}}
	if err := r.a.probe.SetTargets(tg); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r.a.probe.Round(context.Background())
	if time.Since(start) > 10*probeTimeout { // bounded by the timeout, not the slowest target
		t.Error("a round took longer than its timeout")
	}
	p := r.a.probe.Rounds()
	if len(p.Rounds) != 1 {
		t.Fatalf("rounds %v", p)
	}
	rd := p.Rounds[0]
	want := map[string]na.ProbeResult{
		"n1": {OK: true, Class: "ok"}, "n2": {OK: false, Class: "tls"}, "n3": {OK: false, Class: "http_status"}, "n4": {OK: false, Class: "refused"},
		"n5": {OK: true, Class: "ok"}, "n7": {OK: false, Class: "timeout"},
	}
	for k, v := range want {
		if rd.Results[k] != v {
			t.Errorf("%s: %+v, want %+v", k, rd.Results[k], v)
		}
	}
	if !rd.ReachedAny || rd.Prober != "n2" || rd.Site != "edge" || !rd.EgressOK {
		t.Errorf("round %+v", rd)
	}
	// Three rounds kept, newest first.
	for i := 0; i < 3; i++ {
		r.a.probe.Round(context.Background())
	}
	if n := len(r.a.probe.Rounds().Rounds); n != 3 {
		t.Errorf("%d rounds kept", n)
	}
}

// TestProbeHairpinFallback: from inside the node every public probe
// fails at the connect ("no route from inside": the provider doesn't
// hairpin) → each target refused and reached_any false, the blind bit the
// front door reads (R10); the targets survive a restart.
func TestProbeHairpinFallback(t *testing.T) {
	r := newRig(t, "agent")
	r.a.cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.EHOSTUNREACH}
	}
	tg := na.ProbeTargets{Domain: "example.org", EgressHost: "", Targets: []na.ProbeTarget{
		{Node: "n1", Site: "main", Address: "198.51.100.1"},
		{Node: "n2", Site: "main", Address: "198.51.100.2"},
		{Node: "e1", Site: "edge", Address: "203.0.113.5"},
	}}
	if err := r.a.probe.SetTargets(tg); err != nil {
		t.Fatal(err)
	}
	r.a.probe.Round(context.Background())
	rd := r.a.probe.Rounds().Rounds[0]
	if rd.ReachedAny || rd.EgressOK || len(rd.Results) != 3 {
		t.Fatalf("round %+v", rd)
	}
	for k, v := range rd.Results {
		if v.OK || v.Class != na.ClassRefused {
			t.Errorf("%s: %+v", k, v)
		}
	}
	// A restart keeps the targets.
	b := New(r.a.cfg)
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	if b.probe.tg == nil || len(b.probe.tg.Targets) != 3 {
		t.Error("the targets didn't survive a restart")
	}
	for _, bad := range []na.ProbeTargets{
		{Domain: "", Targets: []na.ProbeTarget{}},
		{Domain: "example.org", Targets: nil},
		{Domain: "example.org", Targets: []na.ProbeTarget{{Node: "N1", Site: "main", Address: "198.51.100.1"}}},
		{Domain: "example.org", Targets: []na.ProbeTarget{{Node: "n1", Site: "main", Address: "host.example"}}},
	} {
		if err := r.a.probe.SetTargets(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
