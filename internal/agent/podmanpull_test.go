package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"
)

// podmanStream is Podman 6.1's compat pull stream as seen live
// (quay.io/podman/stable v6.1.3): layer lines only, no Docker "Digest:" /
// "Status:" closing lines.
const podmanStream = `{"status":"Pulling fs layer","progressDetail":{},"id":"2013d9003084"}
{"status":"Download complete","progressDetail":{},"id":"2013d9003084"}
{"status":"Pulling fs layer","progressDetail":{},"id":"cf45b89a82fa"}
{"status":"Download complete","progressDetail":{},"id":"cf45b89a82fa"}
{"status":"Download complete","progressDetail":{},"id":"cf45b89a82fa"}
`

var apiVersionRe = regexp.MustCompile(`^/v[0-9.]+/`)

// imageKey is how the fake finds an image: by digest when the reference
// has one (Podman matches name:tag@digest by its digest), else by name:tag.
func imageKey(ref string) string {
	if _, d, ok := strings.Cut(ref, "@"); ok {
		return d
	}
	return strings.TrimPrefix(ref, "docker.io/library/")
}

// fakePodman is an engine API answering as Podman: /version names the
// "Podman Engine", an image is absent until it is pulled, the pull
// answers podmanStream.
func fakePodman(t *testing.T) (*docker.Client, *[]string) {
	t.Helper()
	var mu sync.Mutex
	pulled := map[string]bool{}
	var creates []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := apiVersionRe.ReplaceAllString(r.URL.Path, "/")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case p == "/_ping":
			w.Header().Set("Api-Version", "1.41")
		case p == "/version":
			json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.41", "Version": "6.1.3",
				"Components": []map[string]any{{"Name": "Podman Engine", "Version": "6.1.3"}}})
		case r.Method == "GET" && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
			ref := strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/json")
			if !pulled[imageKey(ref)] {
				w.WriteHeader(404)
				fmt.Fprintf(w, `{"message":"failed to find image %s: No such image"}`, ref)
				return
			}
			fmt.Fprint(w, `{"Id":"sha256:cf45b89a82fa"}`)
		case r.Method == "POST" && p == "/images/create":
			q := r.URL.Query()
			ref := q.Get("fromImage")
			if tag := q.Get("tag"); strings.HasPrefix(tag, "sha256:") {
				ref += "@" + tag
			} else if tag != "" {
				ref += ":" + tag
			}
			creates = append(creates, ref)
			pulled[imageKey(ref)] = true // a later inspect by name[:tag][@digest] finds it, as Podman does
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, podmanStream)
		default:
			w.WriteHeader(404)
			fmt.Fprintf(w, `{"message":"unexpected %s %s"}`, r.Method, p)
		}
	}))
	t.Cleanup(srv.Close)
	g := docker.NewGuard(runtime.KindPodman)
	c, err := docker.New("tcp://"+srv.Listener.Addr().String(), g)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Verify(context.Background(), c); err != nil {
		t.Fatalf("the guard: %v", err)
	}
	return c, &creates
}

// TestAgentPullPodmanStream: the agent's pull route (an up's image step,
// after the bundle), over the real docker runtime backend and engine
// client, against a Podman-shaped engine: the stream without Docker's
// closing lines is a finished pull once the image is there — no error
// reaches the Hub (live, the up's pull was "answered unexpectedly").
func TestAgentPullPodmanStream(t *testing.T) {
	f := newAPI(t)
	f.bundle(t, "app") // names ghcr.io/example/app:1
	eng, creates := fakePodman(t)
	f.api.cfg.Runtime = dockerrt.New(nil, eng, dockerrt.Options{Kind: runtime.KindPodman})
	resp, body := f.req(t, "POST", "/v1/images/pull", strings.NewReader(`{"ref":"ghcr.io/example/app:1"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("pull: %d %s", resp.StatusCode, body)
	}
	var end agentapi.ProgressLine
	for _, ln := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		json.Unmarshal([]byte(ln), &end)
	}
	if !end.End || end.Error != "" {
		t.Fatalf("the pull didn't end cleanly: %s", body)
	}
	if len(*creates) != 1 {
		t.Errorf("the engine was asked %v", *creates)
	}
	// The preflight route over the same engine (a digest-pinned ref).
	ref := "docker.io/library/busybox:1.38.0-musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6"
	resp, body = f.req(t, "POST", "/v1/images/pull", strings.NewReader(`{"ref":"`+ref+`","preflight":true}`))
	end = agentapi.ProgressLine{}
	for _, ln := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		json.Unmarshal([]byte(ln), &end)
	}
	if resp.StatusCode != 200 || !end.End || end.Error != "" {
		t.Fatalf("preflight: %d %s", resp.StatusCode, body)
	}
}
