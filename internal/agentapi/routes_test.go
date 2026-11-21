package agentapi

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

// TestRoutesCoverInstances: one route per runtime.Instances method but
// Kind, Env and RestartService (the backend answers them: core never
// runs on a worker; the usage verbs Stats, LayerSize and ImageSize have
// routes since ux3), no route for anything else, every pattern unique and
// valid for http.ServeMux (with the extra routes).
func TestRoutesCoverInstances(t *testing.T) {
	it := reflect.TypeFor[runtime.Instances]()
	methods := map[string]bool{}
	for i := 0; i < it.NumMethod(); i++ {
		methods[it.Method(i).Name] = true
	}
	if len(methods) != 30 {
		t.Fatalf("runtime.Instances has %d methods: update Routes", len(methods))
	}
	for m := range methods {
		_, ok := Routes[m]
		if m == "Kind" || m == "Env" || m == "RestartService" {
			if ok {
				t.Errorf("%s has a route (the backend answers it)", m)
			}
			continue
		}
		if !ok {
			t.Errorf("runtime.Instances.%s has no route", m)
		}
	}
	for m := range Routes {
		if !methods[m] {
			t.Errorf("route %s names no runtime.Instances method", m)
		}
	}
	if len(Routes) != 27 {
		t.Errorf("%d methods with routes, want 27", len(Routes))
	}
	// The usage routes (contract §17.4, ux3).
	for m, want := range map[string]string{"Stats": "GET /v1/containers/{cid}/stats", "LayerSize": "GET /v1/containers/{cid}/size", "ImageSize": "GET /v1/images/size"} {
		if rs := Routes[m]; len(rs) != 1 || rs[0].Pattern() != want || rs[0].Response != BodyJSON {
			t.Errorf("%s routes = %+v", m, rs)
		}
	}
	if r := ExtraRoutes["HostUsage"]; r.Pattern() != "GET /v1/host/usage" || r.Response != BodyJSON {
		t.Errorf("HostUsage = %+v", r)
	}
	mux := http.NewServeMux()
	seen := map[string]string{}
	all := map[string][]Route{}
	for m, rs := range Routes {
		if len(rs) == 0 {
			t.Errorf("%s: no route", m)
		}
		all[m] = rs
	}
	for n, r := range ExtraRoutes {
		all["extra "+n] = []Route{r}
	}
	for name, rs := range all {
		for _, r := range rs {
			if !strings.HasPrefix(r.Path, "/v1/") {
				t.Errorf("%s: %s outside /v1", name, r.Path)
			}
			if _, dup := seen[r.Pattern()]; dup {
				continue // a shared helper route
			}
			seen[r.Pattern()] = name
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s: %v", name, p)
					}
				}()
				mux.HandleFunc(r.Pattern(), func(http.ResponseWriter, *http.Request) {})
			}()
			for _, b := range []Body{r.Request, r.Response} {
				switch b {
				case BodyNone, BodyJSON, BodyNDJSON, BodyText, BodyTar:
				default:
					t.Errorf("%s: body %q", name, b)
				}
			}
		}
	}
	if _, ok := ExtraRoutes["Metrics"]; !ok {
		t.Error("no metrics route")
	}
	// Only the helper routes are shared, and an extra route is never an
	// Instances route.
	for p, n := range seen {
		if strings.HasPrefix(n, "extra ") {
			for m, rs := range Routes {
				for _, r := range rs {
					if r.Pattern() == p {
						t.Errorf("%s is both %s and %s", p, n, m)
					}
				}
			}
		}
	}
}
