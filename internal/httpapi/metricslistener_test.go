package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

type oneGauge struct{}

var oneDesc = prometheus.NewDesc("portcullis_test_gauge", "test", nil, nil)

func (oneGauge) Describe(ch chan<- *prometheus.Desc) { ch <- oneDesc }
func (oneGauge) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(oneDesc, prometheus.GaugeValue, 1)
}

func TestMetricsHandlerOnly(t *testing.T) {
	scrapes := 0
	srv := httptest.NewServer(MetricsHandler(oneGauge{}, func() { scrapes++ }))
	t.Cleanup(srv.Close)
	get := func(method, path string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := new(strings.Builder)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, b.String()
	}
	code, body := get("GET", "/metrics")
	if code != 200 || !strings.Contains(body, "portcullis_test_gauge 1") || strings.Contains(body, "go_goroutines") || strings.Contains(body, "process_") {
		t.Errorf("/metrics = %d %s", code, body)
	}
	if code, _ := get("GET", "/healthz"); code != 200 {
		t.Errorf("/healthz = %d", code)
	}
	if code, _ := get("GET", "/api/usage"); code != 404 {
		t.Errorf("/api/usage = %d", code)
	}
	if code, _ := get("POST", "/metrics"); code != 405 {
		t.Errorf("POST /metrics = %d", code)
	}
	if scrapes != 1 {
		t.Errorf("scrapes = %d", scrapes)
	}
}
