//go:build harness

package httpapi

import (
	"net/http"
	"os"
	"testing"
	"time"
)

// TestHarness serves the Hub UI against the in-memory fakes (LLDAP,
// Keycloak, Docker engine, compose runner, domains) for a browser check:
//
//	go test -tags harness -run TestHarness -timeout 0 ./internal/httpapi
//
// It listens on HUB_HARNESS_ADDR (default 127.0.0.1:18888), signs every
// request in as "root" (an LLDAP admin) with the proxy secret, and runs
// until HUB_HARNESS_FOR (a duration, default 30m) has passed.
func TestHarness(t *testing.T) {
	e := newInstEnv(t)
	h := e.s.Hub
	// Seed: two extra instances, one enabled, with data; backups, one of
	// a deleted instance.
	for _, c := range []struct{ tmpl, id string }{{"grafana", "grafana-team-a"}, {"home", "home-b"}, {"grafana", "grafana-old"}} {
		if _, err := h.CreateInstanceAs(c.tmpl, c.id, nil, "root"); err != nil {
			t.Fatal(err)
		}
	}
	e.engine.addVolume("portcullis_grafana-team-a-grafana-data", "portcullis-grafana-team-a", "grafana-data", map[string]string{"grafana.db": "rows"})
	e.engine.addVolume("portcullis_grafana-old-grafana-data", "portcullis-grafana-old", "grafana-data", map[string]string{"grafana.db": "old rows"})
	if err := h.Enable("grafana-team-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.BackupInstance("grafana-team-a", "root"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := h.DeleteInstance("grafana-old", "grafana-old", "root"); err != nil {
		t.Fatal(err)
	}

	addr := os.Getenv("HUB_HARNESS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18888"
	}
	d, err := time.ParseDuration(os.Getenv("HUB_HARNESS_FOR"))
	if err != nil {
		d = 30 * time.Minute
	}
	handler := e.hub.Config.Handler
	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(ProxySecretHeader, testSecret)
		r.Header.Set("X-Forwarded-User", "root")
		handler.ServeHTTP(w, r)
	})}
	go func() {
		time.Sleep(d)
		srv.Close()
	}()
	t.Logf("harness on http://%s for %s", addr, d)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		t.Fatal(err)
	}
}
