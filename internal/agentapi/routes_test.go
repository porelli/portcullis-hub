package agentapi

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

// TestRoutesCoverInstances: one route per runtime.Instances method but
// Kind and Env, no route for anything else, every pattern unique and
// valid for http.ServeMux (with the extra routes).
func TestRoutesCoverInstances(t *testing.T) {
	it := reflect.TypeFor[runtime.Instances]()
	methods := map[string]bool{}
	for i := 0; i < it.NumMethod(); i++ {
		methods[it.Method(i).Name] = true
	}
	if len(methods) != 26 {
		t.Fatalf("runtime.Instances has %d methods: update Routes", len(methods))
	}
	for m := range methods {
		_, ok := Routes[m]
		if m == "Kind" || m == "Env" {
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
	if len(Routes) != 24 {
		t.Errorf("%d routes, want 24", len(Routes))
	}
	mux := http.NewServeMux()
	seen := map[string]string{}
	for _, table := range []map[string]Route{Routes, ExtraRoutes} {
		for name, r := range table {
			if !strings.HasPrefix(r.Path, "/v1/") {
				t.Errorf("%s: %s outside /v1", name, r.Path)
			}
			if other, dup := seen[r.Pattern()]; dup {
				t.Errorf("%s and %s share %s", name, other, r.Pattern())
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
				case BodyNone, BodyJSON, BodyNDJSON, BodyText, BodyTar, BodyHeaderTar:
				default:
					t.Errorf("%s: body %q", name, b)
				}
			}
		}
	}
	if _, ok := ExtraRoutes["Metrics"]; !ok {
		t.Error("no metrics route")
	}
}
