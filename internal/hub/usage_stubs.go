package hub

// MetricsScrapedRecently: the metrics listener was scraped in the last
// 5 min (the Grafana link).
func (h *Hub) MetricsScrapedRecently() bool { return false }
