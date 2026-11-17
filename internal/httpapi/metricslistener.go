package httpapi

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler is the Hub's metrics listener (contract §16.2,
// HUB_METRICS_ADDR on the internal network portcullis-metrics-hub): GET
// /metrics from a registry holding only c (no Go runtime or process
// collectors), GET /healthz, anything else 404 (another method 405). No
// proxy secret, no CSRF: the network is the protection. onScrape is
// called once per /metrics request.
func MetricsHandler(c prometheus.Collector, onScrape func()) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	prom := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if onScrape != nil {
			onScrape()
		}
		prom.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	return mux
}
