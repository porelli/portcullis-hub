package hub

// usageStorageGroup is an instance's storage from the storage cache (nil:
// never measured).
func (h *Hub) usageStorageGroup(string) *StorageGroup { return nil }

// MetricsScrapedRecently: the metrics listener was scraped in the last
// 5 min (the Grafana link).
func (h *Hub) MetricsScrapedRecently() bool { return false }
