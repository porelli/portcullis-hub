package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

var errStandingBy = errors.New("this Hub is standing by: another Hub is the active writer")

// fakeLeader leads until standBy is set.
type fakeLeader struct{ standBy atomic.Bool }

func (f *fakeLeader) Check() error {
	if f.standBy.Load() {
		return errStandingBy
	}
	return nil
}

// TestStandbyAnswers503: while the fence stands by, every request but
// GET and HEAD answers 503 with the fence's text and reaches no route;
// reads still answer; /healthz reports leading. Leading again, writes
// pass the gate.
func TestStandbyAnswers503(t *testing.T) {
	l := &fakeLeader{}
	srv := newServerWith(t, func(s *Server) { s.Leader = l })
	l.standBy.Store(true)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/templates/enable", `{"id":"demo"}`},
		{"POST", "/api/sources/sync", ""},
		{"PUT", "/api/settings", `{}`},
		{"DELETE", "/api/instances/demo", ""},
		{"PATCH", "/api/templates", `{}`},
	} {
		r, b := do(t, srv, c.method, c.path, c.body, true)
		if r.StatusCode != 503 || b != `{"error":"this Hub is standing by: another Hub is the active writer"}`+"\n" {
			t.Errorf("%s %s while standing by = %d %q", c.method, c.path, r.StatusCode, b)
		}
	}
	if r, b := do(t, srv, "GET", "/api/templates", "", true); r.StatusCode != 200 {
		t.Errorf("GET /api/templates while standing by = %d %s", r.StatusCode, b)
	}
	if r, _ := do(t, srv, "HEAD", "/healthz", "", false); r.StatusCode != 200 {
		t.Errorf("HEAD /healthz = %d", r.StatusCode)
	}
	if r, b := do(t, srv, "GET", "/healthz", "", false); r.StatusCode != 200 || b != `{"leading":false}`+"\n" {
		t.Errorf("healthz while standing by = %d %q", r.StatusCode, b)
	}
	// The proxy secret still comes first: no secret, 401 not 503.
	if r, _ := do(t, srv, "POST", "/api/templates/enable", `{"id":"demo"}`, false); r.StatusCode != 401 {
		t.Errorf("POST without secret while standing by = %d", r.StatusCode)
	}
	l.standBy.Store(false)
	if r, b := do(t, srv, "GET", "/healthz", "", false); b != `{"leading":true}`+"\n" {
		t.Errorf("healthz while leading = %d %q", r.StatusCode, b)
	}
	if r, b := do(t, srv, "POST", "/api/sources/sync", "", true); r.StatusCode == 503 {
		t.Errorf("POST while leading = %d %s", r.StatusCode, b)
	}
}

// TestLeaderGateNil: no fence (Docker, Podman) is the handler unchanged.
func TestLeaderGateNil(t *testing.T) {
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++ })
	h := LeaderGate(nil, next)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/x", nil))
	if called != 1 {
		t.Errorf("called %d", called)
	}
	l := &fakeLeader{}
	l.standBy.Store(true)
	w := httptest.NewRecorder()
	LeaderGate(l, next).ServeHTTP(w, httptest.NewRequest("POST", "/x", nil))
	if w.Code != 503 || called != 1 {
		t.Errorf("standing by: %d, called %d", w.Code, called)
	}
}
