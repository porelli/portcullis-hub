package hub

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

// TestPlacedEnvOverrideImages (contract §11.7): an override of a worker
// instance's image (here the custom compose override; settings and env
// resolve the same way) is checked at every start — set to a tag after
// create, the next start is refused (409) with nothing sent to the worker
// and the value never echoed; set to a pinned ref, it is preflight-pulled
// before the start (once, until it changes).
func TestPlacedEnvOverrideImages(t *testing.T) {
	p := newPlacedFixture(t)
	writeFile(t, filepath.Join(p.src, "ovrapp", "manifest.yaml"), "name: Ovr\ncategory: misc\nai: {unsupported: t}\nauth: {method: forward-auth}\n")
	writeFile(t, filepath.Join(p.src, "ovrapp", "compose.yml"), "services:\n  web:\n    image: ovr:1@sha256:"+strings.Repeat("7", 64)+"\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.ovr.rule: Host(`${PORTCULLIS_HOST_OVR:-ovr.portcullis.local}`)\n      traefik.http.routers.ovr.middlewares: portcullis-auth@docker,portcullis-groups@docker\n      traefik.http.services.ovr.loadbalancer.server.port: \"8080\"\n")
	p.h.Discover()
	if err := p.create(t, "ovrapp", "nas"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.h.SaveUserOverride("ovrapp", "services:\n  web:\n    image: evil.example/ovr:latest\n"); err != nil {
		t.Fatal(err)
	}
	before := len(p.w.Calls())
	err := p.h.Enable("ovrapp")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "image of service web (an override) isn't pinned by digest: templates must pin images to run on a worker") {
		t.Fatalf("an unpinned override: %v", err)
	}
	if strings.Contains(err.Error(), "evil.example") {
		t.Error("the override's value is echoed")
	}
	if calls := p.w.Calls()[before:]; len(calls) != 0 {
		t.Errorf("the worker was sent %v", calls)
	}
	pinned := "other.example/ovr:2@sha256:" + strings.Repeat("8", 64)
	if _, _, err := p.h.SaveUserOverride("ovrapp", "services:\n  web:\n    image: "+pinned+"\n"); err != nil {
		t.Fatal(err)
	}
	before = len(p.w.Calls())
	if err := p.h.Enable("ovrapp"); err != nil {
		t.Fatalf("a pinned override: %v", err)
	}
	calls := p.w.Calls()[before:]
	pre := slices.Index(calls, "pull "+pinned)
	bundle := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "signal bundle") })
	if pre < 0 || bundle < 0 || pre > bundle {
		t.Errorf("the pinned override isn't preflighted before the bundle: %v", calls)
	}
	// The same override at the next start: not pulled again.
	before = len(p.w.Calls())
	if err := p.h.Disable("ovrapp"); err != nil {
		t.Fatal(err)
	}
	if err := p.h.Enable("ovrapp"); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.w.Calls()[before:], "pull "+pinned) {
		t.Error("an unchanged override was preflighted again")
	}
}

// TestPlacedOverridePullFailureLog (security review of b15bd02): a failed
// pre-pull of an overridden image logs the instance, server, service and
// a category only — never the ref or the agent's message (either may
// carry a setting's value).
func TestPlacedOverridePullFailureLog(t *testing.T) {
	p := newPlacedFixture(t)
	writeFile(t, filepath.Join(p.src, "ovrapp", "manifest.yaml"), "name: Ovr\ncategory: misc\nai: {unsupported: t}\nauth: {method: forward-auth}\n")
	writeFile(t, filepath.Join(p.src, "ovrapp", "compose.yml"), "services:\n  web:\n    image: ovr:1@sha256:"+strings.Repeat("7", 64)+"\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.ovr.rule: Host(`${PORTCULLIS_HOST_OVR:-ovr.portcullis.local}`)\n      traefik.http.routers.ovr.middlewares: portcullis-auth@docker,portcullis-groups@docker\n      traefik.http.services.ovr.loadbalancer.server.port: \"8080\"\n")
	p.h.Discover()
	if err := p.create(t, "ovrapp", "nas"); err != nil {
		t.Fatal(err)
	}
	secretish := "registry.example/tok-9f8e7d6c5b4a/ovr:2@sha256:" + strings.Repeat("9", 64)
	if _, _, err := p.h.SaveUserOverride("ovrapp", "services:\n  web:\n    image: "+secretish+"\n"); err != nil {
		t.Fatal(err)
	}
	// Each failure as the real agent gives it: an engine error (its end
	// line: 502, error_kind no_platform for an architecture), the agent's
	// own 429 (rate limit) or 400.
	engineFails := func(e error) func() {
		return func() {
			p.w.mu.Lock()
			p.w.pullErr = e
			p.w.mu.Unlock()
		}
	}
	agentAnswers := func(status int, msg string) func() {
		return func() { p.w.wt.Fail(`^POST /v1/images/pull$`, 1, status, msg) }
	}
	for _, c := range []struct {
		inject func()
		cat    string
		want   string
	}{
		{engineFails(errors.New("pull " + secretish + ": no matching manifest for linux/arm64")), pullArchMismatch, "has no amd64 image"},
		{agentAnswers(429, "too many preflight pulls"), pullRateLimited, "pulling an overridden image of ovrapp on NAS failed"},
		{agentAnswers(400, "pull "+secretish+" refused"), pullRefused, "pulling an overridden image of ovrapp on NAS failed"},
		{engineFails(errors.New("pull " + secretish + ": tok-9f8e7d6c5b4a: connection reset")), pullFailed, "pulling an overridden image of ovrapp on NAS failed"},
	} {
		p.h.overridePreflight.Delete("ovrapp")
		p.w.mu.Lock()
		p.w.pullErr = nil
		p.w.mu.Unlock()
		c.inject()
		logs := captureLog(t)
		err := p.h.Enable("ovrapp")
		if errStatus(err) != 409 || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", c.cat, err, c.want)
		}
		// The in-process agent logs on the same logger: its own lines (the
		// worker's log, which knows the ref anyway) are not the Hub's.
		var hubLines []string
		for _, l := range strings.Split(logs.String(), "\n") {
			if !strings.Contains(l, " preflight pull ") {
				hubLines = append(hubLines, l)
			}
		}
		out := strings.Join(hubLines, "\n")
		if strings.Contains(out, "tok-9f8e7d6c5b4a") || strings.Contains(out, "registry.example") || strings.Contains(err.Error(), "tok-9f8e7d6c5b4a") {
			t.Errorf("%s: the override value leaked: log %q, error %v", c.cat, out, err)
		}
		if !strings.Contains(out, "service web's overridden image of ovrapp on nas: "+c.cat) {
			t.Errorf("%s: log %q", c.cat, out)
		}
	}
}

// TestPlacedUpPullsAfterBundle (seen live on both runtimes: "downloading
// … failed, compose will pull it: the server w1 answered unexpectedly"):
// a worker instance's first up pushes its bundle before the image step,
// so the agent (which pulls only images a bundle names; the fake refuses
// as it does) pulls them and nothing falls back to compose.
func TestPlacedUpPullsAfterBundle(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", "nas"); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	before := len(p.w.Calls())
	_, ctx := acceptedProgress(p.fixture, "filesapp") // an up that plans its image step
	if err := p.h.composeUp(ctx, p.h.Template("filesapp")); err != nil {
		t.Fatal(err)
	}
	if out := logs.String(); strings.Contains(out, "compose will pull it") {
		t.Errorf("a pull fell back to compose: %s", out)
	}
	calls := p.w.Calls()[before:]
	ref := "pull files:1@sha256:" + strings.Repeat("f", 64)
	bundle := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "signal bundle") })
	pull := slices.Index(calls, ref)
	if bundle < 0 || pull < 0 || pull < bundle {
		t.Errorf("want the bundle, then the pull: %v", calls)
	}
}

// TestRelaysHealthyBeforeUpIsDone (seen live: the enable was done while
// Traefik still had no router for the host — 404, then 421 on the kept
// connection): relaysUp waits for its relays' health checks, and a relay
// that never turns healthy fails the up.
func TestRelaysHealthyBeforeUpIsDone(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	// The relay container on the primary (the fake engine lists what it holds).
	p.engine.mu.Lock()
	p.engine.containers = append(p.engine.containers, docker.Container{ID: "relay-1", State: "running",
		Labels: map[string]string{docker.LabelProject: "portcullis-plainapp", docker.LabelService: "web"}})
	p.engine.mu.Unlock()
	units, err := p.h.rt.List(context.Background(), runtime.Filter{Instance: "plainapp"})
	if err != nil || len(units) == 0 {
		t.Fatalf("no relay listed on the primary: %v %v", units, err)
	}
	var mu sync.Mutex
	asks := 0
	p.engine.mu.Lock()
	p.engine.stateHook = func(id string, st docker.State) docker.State {
		mu.Lock()
		defer mu.Unlock()
		asks++
		st.Running = true
		st.Health = "starting"
		if asks > 3 {
			st.Health = "healthy"
		}
		return st
	}
	p.engine.mu.Unlock()
	if err := p.h.relaysUp(context.Background(), "plainapp"); err != nil {
		t.Fatalf("relaysUp: %v", err)
	}
	mu.Lock()
	n := asks
	mu.Unlock()
	if n < 4 {
		t.Errorf("relaysUp returned before the relays were healthy (%d state reads)", n)
	}
	old := RelayHealthyWait
	RelayHealthyWait = 1500 * time.Millisecond
	t.Cleanup(func() { RelayHealthyWait = old })
	p.engine.mu.Lock()
	p.engine.stateHook = func(id string, st docker.State) docker.State {
		st.Running, st.Health = true, "unhealthy"
		return st
	}
	p.engine.mu.Unlock()
	err = p.h.relaysUp(context.Background(), "plainapp")
	if errStatus(err) != 504 || !strings.Contains(err.Error(), "aren't healthy") {
		t.Errorf("an unhealthy relay: %v", err)
	}
}
