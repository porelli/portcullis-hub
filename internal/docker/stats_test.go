package docker

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

func statsClient(t *testing.T, fixture string) (*Client, *string) {
	t.Helper()
	body, err := os.ReadFile("testdata/stats/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	var query string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
		case "/containers/c1/stats":
			query = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		default:
			http.Error(w, `{"message":"no"}`, 404)
		}
	}))
	return c, &query
}

func u64(p *uint64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestStatsDecodeV2(t *testing.T) {
	c, _ := statsClient(t, "docker-v2.json")
	s, err := c.ContainerStats(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if u64(s.MemUsage) != uint64(104857600) || u64(s.MemInactiveFile) != uint64(31457280) || u64(s.Pids) != uint64(12) {
		t.Errorf("memory/pids = %v %v %v", u64(s.MemUsage), u64(s.MemInactiveFile), u64(s.Pids))
	}
	if u64(s.NetRx) != uint64(1500) || u64(s.NetTx) != uint64(2050) {
		t.Errorf("net = %v %v", u64(s.NetRx), u64(s.NetTx))
	}
	if u64(s.BlkRead) != uint64(5120) || u64(s.BlkWrite) != uint64(8192) {
		t.Errorf("blk = %v %v", u64(s.BlkRead), u64(s.BlkWrite))
	}
	if u64(s.CPUUsageNS) != uint64(123456789000) {
		t.Errorf("cpu = %v", u64(s.CPUUsageNS))
	}
	if want := time.Date(2026, 11, 15, 10, 0, 15, 123456789, time.UTC); !s.Read.Equal(want) {
		t.Errorf("read = %v", s.Read)
	}
}

func TestStatsDecodeV1(t *testing.T) {
	c, _ := statsClient(t, "docker-v1.json")
	s, err := c.ContainerStats(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if u64(s.MemInactiveFile) != uint64(500000) || u64(s.BlkRead) != uint64(700) || u64(s.BlkWrite) != uint64(300) {
		t.Errorf("v1 = %v %v %v", u64(s.MemInactiveFile), u64(s.BlkRead), u64(s.BlkWrite))
	}
}

func TestStatsPodman(t *testing.T) {
	c, _ := statsClient(t, "podman-v2.json")
	s, err := c.ContainerStats(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if s.BlkRead != nil || s.BlkWrite != nil || u64(s.NetRx) != uint64(0) || u64(s.CPUUsageNS) != uint64(42000000) {
		t.Errorf("podman = %+v", s)
	}
	if s.Read.IsZero() {
		t.Error("read not parsed")
	}
}

// Absent counters stay nil; a present 0 is a non-nil 0.
func TestStatsAbsentIsNil(t *testing.T) {
	c, _ := statsClient(t, "podman-nocpu.json")
	s, err := c.ContainerStats(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUUsageNS != nil || s.NetRx != nil || s.NetTx != nil || s.BlkRead != nil || s.MemInactiveFile != nil {
		t.Errorf("absent fields decoded: %+v", s)
	}
	if s.MemUsage == nil || *s.MemUsage != 0 || s.Pids == nil || *s.Pids != 0 {
		t.Errorf("present zeros lost: %v %v", u64(s.MemUsage), u64(s.Pids))
	}
}

func TestStatsRequestIsOneShot(t *testing.T) {
	c, q := statsClient(t, "docker-v2.json")
	if _, err := c.ContainerStats(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if *q != "one-shot=true&stream=false" {
		t.Errorf("query = %q", *q)
	}
}

func TestStatsBodyCapped(t *testing.T) {
	big := `{"read":"2026-11-15T10:00:15Z","name":"` + strings.Repeat("x", 2<<20) + `"}`
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/c1/stats" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(big))
		}
	}))
	if _, err := c.ContainerStats(context.Background(), "c1"); err == nil {
		t.Error("a 2 MiB answer was decoded")
	}
}

func TestStatsErrorNeverEchoesBody(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
		case "/containers/c1/stats", "/containers/c1/json", "/images/sha256:x/json":
			http.Error(w, `{"message":"SECRET=hunter2"}`, 500)
		case "/containers/gone/stats":
			http.Error(w, `{"message":"no such container: SECRET=hunter2"}`, 404)
		}
	}))
	ctx := context.Background()
	_, err := c.ContainerStats(ctx, "c1")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("stats err = %v", err)
	}
	if _, err := c.ContainerSizeRw(ctx, "c1"); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("size err = %v", err)
	}
	if _, err := c.ImageSize(ctx, "sha256:x"); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("image err = %v", err)
	}
	_, err = c.ContainerStats(ctx, "gone")
	if err == nil || strings.Contains(err.Error(), "hunter2") || !IsNotFound(err) {
		t.Errorf("missing err = %v (not found %v)", err, IsNotFound(err))
	}
}

func TestContainerSizeAndImage(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/_ping":
		case "/containers/c1/json":
			if r.URL.Query().Get("size") == "" {
				t.Errorf("inspect without size: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"Id":"c1","SizeRw":4096,"Config":{"Env":["A=b"]}}`))
		case "/containers/c2/json":
			w.Write([]byte(`{"Id":"c2"}`))
		case "/images/sha256:x/json":
			w.Write([]byte(`{"Id":"sha256:x","Size":123456}`))
		}
	}))
	ctx := context.Background()
	if n, err := c.ContainerSizeRw(ctx, "c1"); err != nil || n != 4096 {
		t.Errorf("size = %d, %v", n, err)
	}
	var nm *runtime.NotMeasuredError
	if _, err := c.ContainerSizeRw(ctx, "c2"); !errors.As(err, &nm) {
		t.Errorf("no SizeRw: %v", err)
	}
	if n, err := c.ImageSize(ctx, "sha256:x"); err != nil || n != 123456 {
		t.Errorf("image = %d, %v", n, err)
	}
}

func TestHostResources(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/info" {
			w.Write([]byte(`{"NCPU":8,"MemTotal":16777216000}`))
		}
	}))
	n, m, err := c.HostResources(context.Background())
	if err != nil || n != 8 || m != 16777216000 {
		t.Errorf("host = %d, %d, %v", n, m, err)
	}
}
