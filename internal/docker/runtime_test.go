package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// fakeVersion answers Components from a list of answers, then the last.
type fakeVersion struct {
	mu      sync.Mutex
	answers []func() ([]Component, error)
	calls   int
}

func (f *fakeVersion) Components(context.Context) ([]Component, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	if i >= len(f.answers) {
		i = len(f.answers) - 1
	}
	f.calls++
	return f.answers[i]()
}

func answer(cs ...Component) func() ([]Component, error) {
	return func() ([]Component, error) { return cs, nil }
}

func fail(msg string) func() ([]Component, error) {
	return func() ([]Component, error) { return nil, errors.New(msg) }
}

var (
	dockerEngine = Component{Name: "Engine", Version: "29.0.0"}
	podmanEngine = Component{Name: "Podman Engine", Version: "5.4.2"}
)

// verifiedGuard is a docker guard verified against a fake engine.
func verifiedGuard(t *testing.T) *Guard {
	t.Helper()
	g := NewGuard(runtime.KindDocker)
	if err := g.Verify(context.Background(), &fakeVersion{answers: []func() ([]Component, error){answer(dockerEngine)}}); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestParseRuntime(t *testing.T) {
	for _, ok := range []string{"docker", "podman"} {
		if rt, err := ParseRuntime(ok); err != nil || string(rt) != ok {
			t.Errorf("ParseRuntime(%q) = %q, %v", ok, rt, err)
		}
	}
	for _, bad := range []string{"", "rkt", "Docker", " docker", "podman "} {
		if _, err := ParseRuntime(bad); err == nil {
			t.Errorf("ParseRuntime(%q) accepted", bad)
		}
	}
}

func TestRuntimeOf(t *testing.T) {
	for _, tc := range []struct {
		cs   []Component
		want runtime.Kind
	}{
		{[]Component{{Name: "Podman Engine"}}, runtime.KindPodman},
		{[]Component{{Name: "Engine"}, {Name: "containerd"}}, runtime.KindDocker},
		{[]Component{{Name: "Engine"}, {Name: "Podman Engine"}}, runtime.KindPodman},
		{[]Component{}, ""},
		{nil, ""},
		{[]Component{{Name: "containerd"}}, ""},
	} {
		if got := RuntimeOf(tc.cs); got != tc.want {
			t.Errorf("RuntimeOf(%v) = %q, want %q", tc.cs, got, tc.want)
		}
	}
}

func TestGuardRetriesUntilVerified(t *testing.T) {
	g := NewGuard(runtime.KindDocker)
	if err := g.Err(); !errors.Is(err, ErrEngineRefused) {
		t.Fatalf("new guard Err = %v", err)
	}
	f := &fakeVersion{answers: []func() ([]Component, error){fail("connection refused"), fail("connection refused"), answer(dockerEngine)}}
	for i := 0; i < 2; i++ {
		err := g.Verify(context.Background(), f)
		if !errors.Is(err, ErrEngineRefused) || !errors.Is(g.Err(), ErrEngineRefused) {
			t.Fatalf("try %d: Verify = %v, Err = %v", i, err, g.Err())
		}
		if !strings.Contains(err.Error(), "the container engine is not verified: ") {
			t.Errorf("message = %q", err)
		}
		select {
		case <-g.Verified():
			t.Fatal("verified too early")
		default:
		}
		if g.Info().Verified {
			t.Fatal("Info verified too early")
		}
	}
	if err := g.Verify(context.Background(), f); err != nil {
		t.Fatalf("third try: %v", err)
	}
	if g.Err() != nil {
		t.Fatalf("Err after verification = %v", g.Err())
	}
	select {
	case <-g.Verified():
	default:
		t.Fatal("Verified not closed")
	}
	if i := g.Info(); !i.Verified || i.Engine != "Engine" || i.Version != "29.0.0" || i.Runtime != runtime.KindDocker || i.Mismatch != "" {
		t.Errorf("Info = %+v", i)
	}
}

func TestGuardRunStopsWhenVerified(t *testing.T) {
	g := NewGuard(runtime.KindPodman)
	f := &fakeVersion{answers: []func() ([]Component, error){fail("no proxy yet"), answer(podmanEngine)}}
	done := make(chan struct{})
	go func() { g.Run(context.Background(), f, time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't stop")
	}
	if g.Err() != nil {
		t.Fatal(g.Err())
	}
}

func TestGuardMismatchIsPermanent(t *testing.T) {
	g := NewGuard(runtime.KindDocker)
	f := &fakeVersion{answers: []func() ([]Component, error){answer(podmanEngine), answer(dockerEngine)}}
	err := g.Verify(context.Background(), f)
	if !errors.Is(err, ErrEngineRefused) || !strings.Contains(err.Error(), "HUB_CONTAINER_RUNTIME=docker but the engine is Podman Engine") {
		t.Fatalf("Verify = %v", err)
	}
	if err := g.Verify(context.Background(), f); err == nil || !strings.Contains(g.Err().Error(), "HUB_CONTAINER_RUNTIME=docker but the engine is Podman Engine") {
		t.Fatalf("a later docker answer cleared the mismatch: %v", err)
	}
	if f.calls != 1 {
		t.Errorf("a settled guard asked again (%d calls)", f.calls)
	}
	select {
	case <-g.Settled():
	default:
		t.Fatal("Settled not closed")
	}
	select {
	case <-g.Verified():
		t.Fatal("Verified closed on a mismatch")
	default:
	}
	if i := g.Info(); i.Verified || i.Mismatch == "" {
		t.Errorf("Info = %+v", i)
	}
	// Neither runtime is a mismatch too.
	g2 := NewGuard(runtime.KindPodman)
	if err := g2.Verify(context.Background(), &fakeVersion{answers: []func() ([]Component, error){answer(Component{Name: "containerd"})}}); err == nil || g2.Info().Mismatch == "" {
		t.Errorf("no engine component: %v", err)
	}
	g3 := NewGuard(runtime.KindPodman)
	if err := g3.Verify(context.Background(), &fakeVersion{answers: []func() ([]Component, error){answer(dockerEngine)}}); err == nil || !strings.Contains(err.Error(), "HUB_CONTAINER_RUNTIME=podman but the engine is Docker Engine") {
		t.Errorf("docker answer to podman = %v", err)
	}
}

func TestGuardedTransport(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Api-Version", "1.47")
		switch {
		case r.URL.Path == "/_ping":
			w.Write([]byte("OK"))
		case strings.HasSuffix(r.URL.Path, "/version"):
			fmt.Fprint(w, `{"ApiVersion":"1.47","Components":[{"Name":"Engine","Version":"29.0.0"},{"Name":"containerd","Version":"2.1"}]}`)
		default:
			w.Write([]byte("[]"))
		}
	}))
	defer srv.Close()
	g := NewGuard(runtime.KindDocker)
	c, err := New("tcp://"+srv.Listener.Addr().String(), g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListContainers(context.Background(), nil); !errors.Is(err, ErrEngineRefused) {
		t.Fatalf("ListContainers before verification = %v", err)
	}
	mu.Lock()
	for _, s := range seen {
		if strings.Contains(s, "/containers/") {
			t.Errorf("refused request reached the engine: %s", s)
		}
	}
	mu.Unlock()
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping before verification: %v", err)
	}
	if err := g.Verify(context.Background(), c); err != nil {
		t.Fatalf("Verify through the client: %v", err)
	}
	if _, err := c.ListContainers(context.Background(), nil); err != nil {
		t.Fatalf("ListContainers after verification: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(seen, "\n")
	for _, want := range []string{"/_ping", "/v1.47/version", "/v1.47/containers/json"} {
		if !strings.Contains(joined, want) {
			t.Errorf("engine never saw %s:\n%s", want, joined)
		}
	}
}

func TestUnguarded(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"HEAD", "/_ping", true},
		{"GET", "/_ping", true},
		{"POST", "/_ping", false},
		{"GET", "/version", true},
		{"GET", "/v1.47/version", true},
		{"POST", "/v1.47/version", false},
		{"GET", "/v1.47/containers/json", false},
		{"GET", "/v1.47/versions", false},
		{"GET", "/libpod/version", false},
		{"GET", "/v1.47/_ping/x", false},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if got := unguarded(r); got != tc.want {
			t.Errorf("%s %s: unguarded = %v", tc.method, tc.path, got)
		}
	}
}

func TestNewRefusesNilGuard(t *testing.T) {
	if _, err := New("tcp://x:2375", nil); err == nil {
		t.Fatal("New with a nil guard accepted")
	}
}

// I1: under a unix DOCKER_HOST whose socket is missing, the failed
// /version read ("dial unix …") never reaches a refusal's text: the SDK
// would replace such a transport error with its own unwrapped one. Every
// guarded request still wraps ErrEngineRefused, and Message is the
// guard's own refusal.
func TestGuardRefusalSurvivesMissingSocket(t *testing.T) {
	g := NewGuard(runtime.KindDocker)
	dir, err := os.MkdirTemp("/tmp", "pp-sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c, err := New("unix://"+filepath.Join(dir, "missing.sock"), g)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Verify(context.Background(), c); !errors.Is(err, ErrEngineRefused) {
		t.Fatalf("Verify = %v", err)
	}
	if le := g.LastError(); le == nil || !strings.Contains(le.Error(), "dial unix") {
		t.Fatalf("LastError = %v, want the dial error", le)
	}
	if strings.Contains(g.Err().Error(), "dial unix") || strings.Contains(g.Err().Error(), "connection refused") {
		t.Errorf("the refusal carries the engine error: %v", g.Err())
	}
	for name, f := range map[string]func() error{
		"ListContainers": func() error { _, err := c.ListContainers(context.Background(), nil); return err },
		"Logs":           func() error { _, err := c.Logs(context.Background(), "x", 10, false); return err },
		"SecurityOptions": func() error {
			_, err := c.SecurityOptions(context.Background())
			return err
		},
	} {
		err := f()
		if !errors.Is(err, ErrEngineRefused) {
			t.Errorf("%s = %v, want ErrEngineRefused", name, err)
			continue
		}
		var re *RefusedError
		if !errors.As(err, &re) || re.Message() != g.Err().Error() {
			t.Errorf("%s: message %q, want the guard's %q", name, re.Message(), g.Err())
		}
	}
}
