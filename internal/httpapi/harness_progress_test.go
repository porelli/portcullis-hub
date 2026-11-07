//go:build harness

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// The progress panel's fixtures (operation progress Task 8, contract
// §11.7), served by TestHarness:
//
//   - gitea (the default instance, not enabled; groups users_gitea and
//     admin_gitea don't exist, so its enable creates them): its two
//     images download slowly — gitea/gitea:1.25 (690 MB, about 25 s) and
//     postgres:17 (150 MB, about 6 s) — so an enable stays in "images"
//     with a moving percent. Bytes already downloaded are kept (a pull
//     after a Stop goes on from there; a finished image is present).
//     Deleting a group takes 2 s, so a Stop's undo can be watched.
//     POST /harness/op/break-undo makes deleting a group fail (a Stop's
//     undo then fails: "Stop again"), POST /harness/op/fix-undo heals it.
//   - gitea-warn (created): once up, its containers never get healthy;
//     the healthy step gives up after 8 s with a warning (an enable that
//     ends ok with a warning).
//   - grafana-scratch (created, with a volume): removing its volume
//     takes 30 s, so a delete stays past its point of no return.
//   - nativeapp: an enable interrupted by a Hub stop (seeded running
//     before the Hub loaded it): stoppable, Stop undoes it.
//   - POST /harness/op/delay-lastop?id=<id>&ms=<n>: the next GET
//     /api/templates/lastop/<id> is answered n ms after the Hub read the
//     record (a late, stale answer: the panel's ordering check).

// harnessProgress is the engine side of the fixtures.
type harnessProgress struct {
	unhealthy map[string]bool     // instance id → its containers stay "starting"
	services  map[string][]string // instance id → the services Up starts
	slowPull  map[string]int64    // image ref → its size
	pulled    map[string]int64    // image ref → bytes downloaded (runMu)
	slowVol   string              // volume name prefix whose removal is slow
}

// harnessPullRate is the slow pulls' speed in bytes per second.
const harnessPullRate = 28_000_000

func newHarnessProgress() harnessProgress {
	return harnessProgress{
		unhealthy: map[string]bool{"gitea-warn": true},
		services:  map[string][]string{"gitea-warn": {"db", "web"}},
		slowPull:  map[string]int64{"gitea/gitea:1.25": 690_000_000, "postgres:17": 150_000_000},
		pulled:    map[string]int64{},
		slowVol:   "portcullis_grafana-scratch-",
	}
}

// PullWithProgress: the slow images download at harnessPullRate (from
// where an earlier pull stopped), reporting every 200 ms; the others
// are present.
func (e *harnessEngine) PullWithProgress(ctx context.Context, ref string, fn func(int64, int64, bool)) error {
	total, slow := e.prog.slowPull[ref]
	if !slow {
		return nil
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		e.runMu.Lock()
		done := e.prog.pulled[ref]
		e.runMu.Unlock()
		if done >= total {
			return nil
		}
		fn(done, total, true)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		e.runMu.Lock()
		e.prog.pulled[ref] = min(total, e.prog.pulled[ref]+harnessPullRate/5)
		e.runMu.Unlock()
	}
}

// RemoveVolume: grafana-scratch's volumes take 30 s.
func (e *harnessEngine) RemoveVolume(ctx context.Context, name string) error {
	if strings.HasPrefix(name, e.prog.slowVol) {
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
	return e.fakeEngine.RemoveVolume(ctx, name)
}

// harnessRunner is the no-op compose runner, except that Up starts the
// harnessProgress services of an instance (as running containers of
// the harness engine) and Down removes them.
type harnessRunner struct {
	nopRunner
	eng *harnessEngine
}

func (r *harnessRunner) Up(ctx context.Context, p compose.Project) error {
	id := strings.TrimPrefix(p.Name, hub.ProjectPrefix)
	if r.eng != nil && r.eng.prog.services[id] != nil {
		r.eng.runMu.Lock()
		r.eng.running[id] = r.eng.prog.services[id]
		r.eng.runMu.Unlock()
	}
	return nil
}

func (r *harnessRunner) Down(ctx context.Context, p compose.Project) error {
	return r.DownByName(ctx, p.Name)
}

func (r *harnessRunner) DownByName(ctx context.Context, name string) error {
	id := strings.TrimPrefix(name, hub.ProjectPrefix)
	if r.eng != nil && r.eng.prog.services[id] != nil {
		r.eng.runMu.Lock()
		delete(r.eng.running, id)
		r.eng.runMu.Unlock()
	}
	return nil
}

// harnessGroups is Users & Groups whose group deletes take 2 s, and fail
// while broken (POST /harness/op/break-undo).
type harnessGroups struct {
	*directory.Service
	broken *atomic.Bool
}

func (g harnessGroups) DeleteInstanceGroup(ctx context.Context, actor directory.Actor, name string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(2 * time.Second):
	}
	if g.broken.Load() {
		return nil, errors.New("LLDAP didn't answer: read tcp 10.0.0.4:41920->10.0.0.2:17170: connection reset by peer")
	}
	return g.Service.DeleteInstanceGroup(ctx, actor, name)
}

const harnessGiteaManifest = `name: Gitea
category: development
icon: "🍵"
description: "Git hosting (the progress panel fixture, slow image downloads)"
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: header-auth
  group_access: true
  access_group: users_gitea
  admin_group: admin_gitea
urls:
  - label: Web
    url: "https://{{HOST_GITEA}}"
`

const harnessGiteaCompose = "services:\n" +
	"  web:\n    image: gitea/gitea:1.25\n    volumes:\n      - gitea-data:/data\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.gitea.rule: Host(`${PORTCULLIS_HOST_GITEA:-gitea.portcullis.local}`)\n" +
	"      traefik.http.services.gitea.loadbalancer.server.port: \"3000\"\n" +
	"  db:\n    image: postgres:17\n    volumes:\n      - gitea-db:/var/lib/postgresql/data\n" +
	"volumes:\n  gitea-data: {}\n  gitea-db: {}\n"

// seedInterruptedOp writes nativeapp's op record as a Hub stop left it:
// an enable running on its images step (loadOps marks it interrupted).
func seedInterruptedOp(t *testing.T, data string) {
	t.Helper()
	at := time.Now().UTC().Add(-50 * time.Minute).Truncate(time.Second)
	ts := func(d time.Duration) string { return at.Add(d).Format(time.RFC3339) }
	rec := map[string]any{
		"op": "enable", "op_id": "a1b2c3d4e5f60718", "at": ts(0), "running": true, "actor": "root", "ok": false,
		"steps": []map[string]any{
			{"key": "groups", "label": "Groups", "state": "done", "detail": "users_nativeapp already exists", "started_at": ts(0), "ended_at": ts(time.Second)},
			{"key": "keycloak", "label": "Sign-in client in Keycloak", "state": "done", "started_at": ts(time.Second), "ended_at": ts(2 * time.Second)},
			{"key": "images", "label": "Downloading images", "state": "running", "percent": 62, "detail": "nativeapp — 210 of 340 MB", "started_at": ts(2 * time.Second)},
			{"key": "create", "label": "Creating containers", "state": "waiting"},
			{"key": "start", "label": "Starting services", "state": "waiting"},
			{"key": "healthy", "label": "Waiting until healthy", "state": "waiting"},
			{"key": "settings", "label": "Applying settings", "state": "waiting"},
		},
		"created":   map[string]any{"volumes": []string{}, "keycloak_clients": []string{}, "groups": []string{}},
		"stoppable": true,
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(data, "ops")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nativeapp.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// seedProgress creates the fixtures' instances and wires the slow,
// breakable group deletes; it registers the /harness/op/ endpoints.
func seedProgress(t *testing.T, e *instEnv, mux *http.ServeMux) {
	t.Helper()
	h := e.s.Hub
	hub.SetAIReadyWaitForTest(8 * time.Second)
	broken := &atomic.Bool{}
	h.SetGroups(harnessGroups{Service: e.s.Directory, broken: broken})
	for _, c := range []struct{ tmpl, id string }{{"gitea", "gitea-warn"}, {"grafana", "grafana-scratch"}} {
		if _, err := h.CreateInstanceAs(c.tmpl, c.id, nil, directory.Human("root")); err != nil {
			t.Fatal(err)
		}
	}
	e.engine.addVolume("portcullis_grafana-scratch-grafana-data", "portcullis-grafana-scratch", "grafana-data", map[string]string{"grafana.db": "scratch rows"})
	mux.HandleFunc("POST /harness/op/break-undo", func(w http.ResponseWriter, r *http.Request) {
		broken.Store(true)
		fmt.Fprintln(w, "deleting a group now fails (a Stop's undo of an enable fails)")
	})
	mux.HandleFunc("POST /harness/op/delay-lastop", func(w http.ResponseWriter, r *http.Request) {
		ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
		id := r.URL.Query().Get("id")
		if err != nil || ms <= 0 || ms > 60000 || id == "" {
			http.Error(w, "want ?id=<instance>&ms=<1..60000>", http.StatusBadRequest)
			return
		}
		harnessLastopDelay.Lock()
		harnessLastopDelay.path, harnessLastopDelay.d = "/api/templates/lastop/"+id, time.Duration(ms)*time.Millisecond
		harnessLastopDelay.Unlock()
		fmt.Fprintf(w, "the next lastop answer of %s comes %d ms late\n", id, ms)
	})
	mux.HandleFunc("POST /harness/op/fix-undo", func(w http.ResponseWriter, r *http.Request) {
		broken.Store(false)
		fmt.Fprintln(w, "deleting a group works again")
	})
}

// harnessLastopDelay is the one-shot late lastop answer
// (POST /harness/op/delay-lastop).
var harnessLastopDelay struct {
	sync.Mutex
	path string
	d    time.Duration
}

// harnessDelayed answers the armed lastop request d after the Hub
// handled it (the record read before the wait).
func harnessDelayed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		harnessLastopDelay.Lock()
		d := time.Duration(0)
		if r.Method == http.MethodGet && harnessLastopDelay.path != "" && r.URL.Path == harnessLastopDelay.path {
			d = harnessLastopDelay.d
			harnessLastopDelay.path = ""
		}
		harnessLastopDelay.Unlock()
		if d == 0 {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		time.Sleep(d)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
	})
}
