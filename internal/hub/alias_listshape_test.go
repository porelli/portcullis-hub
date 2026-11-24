package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"
)

// daemonContainer is one container of daemonShape: what the list
// summary says (no aliases, as Docker sends it) and what the inspect
// says (aliases; inspectErr: a 500 instead).
type daemonContainer struct {
	id, name, project, service string
	labels                     map[string]string
	aliases                    []string
	inspectErr                 bool
}

// listShapeEngine is the fixture's fake engine with its container list
// and inspect from a real *docker.Client talking to a fake daemon that
// answers in the Engine API's shape: the alias checks go through the
// same code as on a real host.
type listShapeEngine struct {
	*fakeEngine
	cli *docker.Client
}

func (e *listShapeEngine) ListContainers(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	return e.cli.ListContainers(ctx, f)
}

func (e *listShapeEngine) ListContainersNames(ctx context.Context, f docker.Filters) ([]docker.Container, error) {
	return e.cli.ListContainersNames(ctx, f)
}

type engineComponents struct{}

func (engineComponents) Components(context.Context) ([]docker.Component, error) {
	return []docker.Component{{Name: "Engine", Version: "29.0.0"}}, nil
}

// useDaemonShape points a's Hub at a fake daemon listing cs.
func useDaemonShape(t *testing.T, a *instAIFixture, cs []daemonContainer) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if i := strings.Index(path[1:], "/"); strings.HasPrefix(path, "/v1.") && i > 0 {
			path = path[i+1:]
		}
		switch {
		case path == "/_ping":
			w.Header().Set("API-Version", "1.47")
			fmt.Fprint(w, "OK")
		case path == "/containers/json":
			var out []map[string]any
			for i, c := range cs {
				out = append(out, map[string]any{"Id": c.id, "Names": []string{"/" + c.name}, "State": "running", "Status": "Up 1 minute",
					"Labels":          c.labels,
					"NetworkSettings": map[string]any{"Networks": map[string]any{"portcullis-proxy": map[string]any{"EndpointID": fmt.Sprint("ep", i), "Aliases": nil, "DNSNames": nil}}}})
			}
			json.NewEncoder(w).Encode(out)
		default:
			for i, c := range cs {
				if path == "/containers/"+c.id+"/json" {
					if c.inspectErr {
						http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"Id": c.id, "State": map[string]any{"Running": true, "Status": "running"},
						"NetworkSettings": map[string]any{"Networks": map[string]any{"portcullis-proxy": map[string]any{"EndpointID": fmt.Sprint("ep", i),
							"Aliases": c.aliases, "DNSNames": append([]string{c.name}, c.aliases...)}}}})
					return
				}
			}
			http.Error(w, `{"message":"no such container"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	g := docker.NewGuard(runtime.KindDocker)
	if err := g.Verify(context.Background(), engineComponents{}); err != nil {
		t.Fatal(err)
	}
	cli, err := docker.New("tcp://"+srv.Listener.Addr().String(), g)
	if err != nil {
		t.Fatal(err)
	}
	a.h.rt = dockerrt.New(a.runner, &listShapeEngine{fakeEngine: a.engine, cli: cli}, dockerrt.Options{HelperImage: HelperImage})
}

// The alias check through a daemon that answers like Docker (the list
// summary has no aliases; only the inspect does), both directions: the
// companion's rendered alias is seen (no "missing" drift: the old list
// read never saw it), and a rogue portcullis-mcp- alias — on the app's
// own service, on a container outside any compose project, or on a
// disabled instance's — is drift (the old read never saw one). A
// container whose names can't be read is drift, never clean.
func TestMCPAliasDaemonListShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []daemonContainer
		rogue []string // app's aliases beyond its name
		// unread: the companion's own inspect fails.
		unread bool
		// other: oauthapp is enabled too, and the drift looked at is its.
		other bool
		want  string // "" = no drift
	}{
		{name: "match"},
		{name: "unexpected on the app", rogue: []string{"portcullis-mcp-aiapp--evil"}, want: "app: unexpected network alias portcullis-mcp-aiapp--evil"},
		{name: "non-compose container", extra: []daemonContainer{{id: "c9", name: "intruder", aliases: []string{"portcullis-mcp-aiapp--tok"}}},
			want: "container intruder (not one of the instance's) answers network alias portcullis-mcp-aiapp--tok"},
		{name: "disabled instance's container", extra: []daemonContainer{{id: "c8", name: "portcullis-oauthapp-web-1", project: "portcullis-oauthapp", service: "web",
			aliases: []string{"portcullis-mcp-aiapp--tok"}}}, want: "container portcullis-oauthapp-web-1 (not one of the instance's) answers network alias portcullis-mcp-aiapp--tok"},
		{name: "names unread", extra: []daemonContainer{{id: "c7", name: "mystery", inspectErr: true}},
			want: "can't read the network names of container mystery on portcullis-proxy"},
		{name: "companion's names unread", unread: true, want: "tok-mcp: can't read network names"},
		// Instance A's own container carrying instance B's alias: drift of B
		// (A's own comparison is never what accepts or hides it).
		{name: "A carries B's alias", other: true, rogue: []string{"portcullis-mcp-oauthapp--x"},
			want: "container portcullis-aiapp-app-1 (not one of the instance's) answers network alias portcullis-mcp-oauthapp--x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newInstAIFixture(t, nil)
			a.enable(t, "aiapp")
			driftID := "aiapp"
			if tc.other {
				a.enable(t, "oauthapp")
				driftID = "oauthapp"
			}
			if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
				t.Fatal(err)
			}
			a.h.mu.RLock()
			want, _ := a.h.desiredRouteLabelsLocked(a.h.findLocked("aiapp"))
			a.h.mu.RUnlock()
			labels := map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: "app", docker.LabelNumber: "1"}
			for k, v := range want["app"] {
				labels[k] = v
			}
			cs := []daemonContainer{
				{id: "c1", name: "portcullis-aiapp-app-1", labels: labels, aliases: append([]string{"app"}, tc.rogue...)},
				{id: "c2", name: "portcullis-aiapp-tok-mcp-1", aliases: []string{"tok-mcp", "portcullis-mcp-aiapp--tok"}, inspectErr: tc.unread,
					labels: map[string]string{docker.LabelProject: "portcullis-aiapp", docker.LabelService: "tok-mcp", docker.LabelNumber: "1"}},
			}
			if tc.other {
				a.h.mu.RLock()
				ow, _ := a.h.desiredRouteLabelsLocked(a.h.findLocked("oauthapp"))
				a.h.mu.RUnlock()
				ol := map[string]string{docker.LabelProject: "portcullis-oauthapp", docker.LabelService: "web", docker.LabelNumber: "1"}
				for k, v := range ow["web"] {
					ol[k] = v
				}
				cs = append(cs, daemonContainer{id: "c5", name: "portcullis-oauthapp-web-1", labels: ol, aliases: []string{"web"}})
			}
			for _, x := range tc.extra {
				x.labels = map[string]string{}
				if x.project != "" {
					x.labels = map[string]string{docker.LabelProject: x.project, docker.LabelService: x.service, docker.LabelNumber: "1"}
				}
				cs = append(cs, x)
			}
			useDaemonShape(t, a, cs)
			var msg string
			for _, d := range a.h.Reconcile(context.Background()).Items {
				if d.ID == driftID && d.Kind == DriftPublicAccess {
					msg = d.Message
				}
			}
			if tc.want == "" && msg != "" || tc.want != "" && !strings.Contains(msg, tc.want) {
				t.Errorf("drift = %q, want %q", msg, tc.want)
			}
		})
	}
}

// Switching a companion on reads every container's names from the
// inspect: one answering the alias only there is seen (409), one whose
// names can't be read refuses (503), never "free".
func TestCheckAliasFreeDaemonListShape(t *testing.T) {
	for _, tc := range []struct {
		c    daemonContainer
		code int
	}{
		{daemonContainer{id: "c9", name: "intruder", aliases: []string{"portcullis-mcp-aiapp--tok"}}, 409},
		{daemonContainer{id: "c9", name: "mystery", inspectErr: true}, 503},
	} {
		a := newInstAIFixture(t, nil)
		a.enable(t, "aiapp")
		tc.c.labels = map[string]string{}
		useDaemonShape(t, a, []daemonContainer{tc.c})
		if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); errStatus(err) != tc.code {
			t.Errorf("%s: %v", tc.c.name, err)
		}
	}
}
