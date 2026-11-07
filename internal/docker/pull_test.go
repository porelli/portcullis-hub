package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// pullStream is a daemon pull stream: two layers downloading, one
// already present, the tag line and the final status lines.
const pullStream = `{"status":"Pulling from library/postgres","id":"17"}
{"status":"Pulling fs layer","progressDetail":{},"id":"aaa"}
{"status":"Pulling fs layer","progressDetail":{},"id":"bbb"}
{"status":"Already exists","progressDetail":{},"id":"ccc"}
{"status":"Downloading","progressDetail":{"current":100,"total":1000},"id":"aaa"}
{"status":"Downloading","progressDetail":{"current":500,"total":3000},"id":"bbb"}
{"status":"Downloading","progressDetail":{"current":1000,"total":1000},"id":"aaa"}
{"status":"Verifying Checksum","progressDetail":{},"id":"aaa"}
{"status":"Download complete","progressDetail":{},"id":"aaa"}
{"status":"Extracting","progressDetail":{"current":200,"total":1000},"id":"aaa"}
{"status":"Downloading","progressDetail":{"current":2500,"total":3000},"id":"bbb"}
{"status":"Pull complete","progressDetail":{},"id":"aaa"}
{"status":"Download complete","progressDetail":{},"id":"bbb"}
{"status":"Extracting","progressDetail":{"current":3000,"total":3000},"id":"bbb"}
{"status":"Pull complete","progressDetail":{},"id":"bbb"}
{"status":"Digest: sha256:abc"}
{"status":"Status: Downloaded newer image for postgres:17"}
`

// TestPullProgressSumsLayers: the pull stream's byte counts are summed
// over the layers (an already-present layer counts for nothing), never
// go back, and end at 100 %; an image already present is not pulled.
func TestPullProgressSumsLayers(t *testing.T) {
	var pulled []string
	present := false
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json"):
			if present {
				fmt.Fprint(w, `{"Id":"sha256:1"}`)
				return
			}
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"No such image"}`)
		case r.Method == "POST" && r.URL.Path == "/images/create":
			pulled = append(pulled, r.URL.Query().Get("fromImage")+":"+r.URL.Query().Get("tag"))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, pullStream)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	var pcts []int64
	var last [2]int64
	err := c.PullWithProgress(context.Background(), "postgres:17", func(done, total int64) {
		if done < last[0] {
			t.Errorf("done went back: %d after %d", done, last[0])
		}
		if done > total {
			t.Errorf("done %d > total %d", done, total)
		}
		last = [2]int64{done, total}
		if total > 0 {
			pcts = append(pcts, done*100/total)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pulled) != 1 || pulled[0] != "docker.io/library/postgres:17" {
		t.Fatalf("pulled = %v", pulled)
	}
	if last != [2]int64{4000, 4000} {
		t.Fatalf("last = %v, want 4000 of 4000", last)
	}
	if len(pcts) < 3 || pcts[len(pcts)-1] != 100 {
		t.Fatalf("percents = %v", pcts)
	}
	// Both layers' totals are known from the first downloads on: the
	// percent only grows.
	for i := 1; i < len(pcts); i++ {
		if pcts[i] < pcts[i-1] {
			t.Fatalf("percent went back: %v", pcts)
		}
	}

	// Already present: no pull, no byte counts.
	present, pulled = true, nil
	called := false
	if err := c.PullWithProgress(context.Background(), "postgres:17", func(int64, int64) { called = true }); err != nil || len(pulled) != 0 || called {
		t.Fatalf("present: err %v, pulled %v, called %v", err, pulled, called)
	}
}

// A pull error in the stream is returned.
func TestPullStreamError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
		case r.Method == "GET":
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"No such image"}`)
		default:
			fmt.Fprint(w, `{"status":"Pulling from x/y","id":"1"}`+"\n"+`{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}`+"\n")
		}
	}))
	err := c.PullWithProgress(context.Background(), "x/y:1", func(int64, int64) {})
	if err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("err = %v", err)
	}
}

// TestPullWithProgressCancelled: cancelling the context stops a pull in
// progress (the stream is closed) with the context's error.
func TestPullWithProgressCancelled(t *testing.T) {
	started := make(chan struct{})
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
		case r.Method == "GET":
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"No such image"}`)
		default:
			fmt.Fprint(w, `{"status":"Downloading","progressDetail":{"current":1,"total":10},"id":"aaa"}`+"\n")
			w.(http.Flusher).Flush()
			close(started)
			select { // a pull that never ends by itself
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	done := make(chan error, 1)
	go func() { done <- c.PullWithProgress(ctx, "x/y:1", func(int64, int64) {}) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pull did not stop")
	}
}
