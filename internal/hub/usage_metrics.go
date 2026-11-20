package hub

// The usage metrics (contract §16.2): a prometheus.Collector over the
// sampler's cache and the storage cache, read on scrape (never the
// engine). The app label is the instance id or "core" — never
// "instance", which Prometheus keeps for the scrape target (FR-H1). Null
// figures are left out, never exported as 0; storage
// targets are volume names, folder ids, services or images, never a host
// path (binds are bind:<n>, numbered per instance in path order).

import (
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/portcullis/hub/internal/usage"
)

// metricsScrapedWithin: the Grafana link shows while Prometheus scraped
// the listener this recently (U25).
const metricsScrapedWithin = 5 * time.Minute

var (
	containerLabels = []string{"app", "service", "number"}
	descCPU         = prometheus.NewDesc("portcullis_container_cpu_seconds_total", "CPU time the container used (seconds).", containerLabels, nil)
	descMem         = prometheus.NewDesc("portcullis_container_memory_working_set_bytes", "The container's working set (usage minus inactive file pages).", containerLabels, nil)
	descMemLimit    = prometheus.NewDesc("portcullis_container_memory_limit_bytes", "The container's memory limit (left out when it has none).", containerLabels, nil)
	descPids        = prometheus.NewDesc("portcullis_container_pids", "Processes and threads in the container.", containerLabels, nil)
	descNetRx       = prometheus.NewDesc("portcullis_container_network_receive_bytes_total", "Bytes the container received.", containerLabels, nil)
	descNetTx       = prometheus.NewDesc("portcullis_container_network_transmit_bytes_total", "Bytes the container sent.", containerLabels, nil)
	descBlkR        = prometheus.NewDesc("portcullis_container_blkio_read_bytes_total", "Bytes the container read from block devices.", containerLabels, nil)
	descBlkW        = prometheus.NewDesc("portcullis_container_blkio_write_bytes_total", "Bytes the container wrote to block devices.", containerLabels, nil)
	descOOM         = prometheus.NewDesc("portcullis_container_oom_killed", "1 when the container's current start was killed for running out of memory.", containerLabels, nil)
	storageLabels   = []string{"app", "kind", "target"}
	descAlloc       = prometheus.NewDesc("portcullis_storage_alloc_bytes", "Allocated bytes of a measured volume, bind, folder, layer or image.", storageLabels, nil)
	descMeasured    = prometheus.NewDesc("portcullis_storage_measured_timestamp_seconds", "When the target was last measured (Unix seconds).", storageLabels, nil)
	descFree        = prometheus.NewDesc("portcullis_filesystem_free_bytes", "Free bytes of a filesystem with Portcullis data.", []string{"dev"}, nil)
	descTotal       = prometheus.NewDesc("portcullis_filesystem_total_bytes", "Size of a filesystem with Portcullis data.", []string{"dev"}, nil)
	descLastOK      = prometheus.NewDesc("portcullis_usage_sampler_last_success_timestamp_seconds", "The usage sampler's last successful sweep (Unix seconds).", nil, nil)
	// The node mesh (§20.11, pre-flight P47): the nodeagents' round trips
	// as the Hub last read them (none older than 5 min).
	descMeshRTT = prometheus.NewDesc("portcullis_mesh_rtt_ms", "Round trip over pcmesh from node from to node to (the nodeagent's p95 of 20 rounds, ms).", []string{"from", "to"}, nil)
)

type usageCollector struct{ h *Hub }

// UsageCollector is the usage metrics' collector (the metrics listener
// registers it in its own registry).
func (h *Hub) UsageCollector() prometheus.Collector { return usageCollector{h} }

func (usageCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descCPU, descMem, descMemLimit, descPids, descNetRx, descNetTx, descBlkR, descBlkW, descOOM,
		descAlloc, descMeasured, descFree, descTotal, descLastOK, descMeshRTT} {
		ch <- d
	}
}

func (c usageCollector) Collect(out chan<- prometheus.Metric) {
	h := c.h
	// send drops a series it can't build (an invalid label value) and a
	// label set already sent for the metric (two running containers with
	// one service and number, L6): the first wins, the scrape never fails.
	seen := map[string]bool{}
	send := func(d *prometheus.Desc, t prometheus.ValueType, v float64, lv ...string) {
		k := d.String() + "\x00" + strings.Join(lv, "\x00")
		if seen[k] {
			return
		}
		m, err := prometheus.NewConstMetric(d, t, v, lv...)
		if err != nil {
			return
		}
		seen[k] = true
		out <- m
	}
	rtt := h.MeshRTT()
	for _, from := range slices.Sorted(maps.Keys(rtt)) {
		for _, to := range slices.Sorted(maps.Keys(rtt[from])) {
			send(descMeshRTT, prometheus.GaugeValue, float64(rtt[from][to]), from, to)
		}
	}
	snap := h.usageSnapshot()
	if !snap.LastSuccess.IsZero() {
		send(descLastOK, prometheus.GaugeValue, float64(snap.LastSuccess.Unix()))
	}
	for _, sc := range snap.Containers {
		if !sc.Running {
			continue
		}
		inst := sc.Instance
		if inst == "" {
			inst = usageCoreOwner
		}
		lv := []string{inst, sc.Service, strconv.Itoa(sc.Number)}
		emit := func(d *prometheus.Desc, t prometheus.ValueType, v float64) {
			send(d, t, v, lv...)
		}
		if r := sc.Raw; r != nil {
			// Kubernetes gives CPU as a gauge only: no counter there (U9).
			if r.CPUUsageNS != nil {
				emit(descCPU, prometheus.CounterValue, float64(*r.CPUUsageNS)/1e9)
			}
			if usage.OwnNetwork(sc.Limits.NetworkMode) {
				if r.NetRx != nil {
					emit(descNetRx, prometheus.CounterValue, float64(*r.NetRx))
				}
				if r.NetTx != nil {
					emit(descNetTx, prometheus.CounterValue, float64(*r.NetTx))
				}
			}
			if r.BlkRead != nil {
				emit(descBlkR, prometheus.CounterValue, float64(*r.BlkRead))
			}
			if r.BlkWrite != nil {
				emit(descBlkW, prometheus.CounterValue, float64(*r.BlkWrite))
			}
		}
		if sc.Sample.MemBytes != nil {
			emit(descMem, prometheus.GaugeValue, float64(*sc.Sample.MemBytes))
		}
		if sc.Limits.MemBytes > 0 {
			emit(descMemLimit, prometheus.GaugeValue, float64(sc.Limits.MemBytes))
		}
		if sc.Sample.Pids != nil {
			emit(descPids, prometheus.GaugeValue, float64(*sc.Sample.Pids))
		}
		oom := 0.0
		if sc.Limits.OOMKilled {
			oom = 1
		}
		emit(descOOM, prometheus.GaugeValue, oom)
	}
	// Storage: per owner; binds numbered per instance in path order.
	sf := h.storageSnapshot()
	bindN := map[string]map[string]int{}
	keys := slices.Sorted(maps.Keys(sf.Entries))
	for _, k := range keys {
		e := sf.Entries[k]
		if e.Kind != "bind" {
			continue
		}
		for _, o := range e.Owners {
			if bindN[o] == nil {
				bindN[o] = map[string]int{}
			}
			bindN[o][e.Target] = 0
		}
	}
	for _, m := range bindN {
		paths := slices.Sorted(maps.Keys(m))
		for i, p := range paths {
			m[p] = i + 1
		}
	}
	for _, k := range keys {
		e := sf.Entries[k]
		for _, o := range e.Owners {
			target := e.Target
			if e.Kind == "bind" {
				target = "bind:" + strconv.Itoa(bindN[o][e.Target])
			}
			if e.AllocBytes != nil {
				send(descAlloc, prometheus.GaugeValue, float64(*e.AllocBytes), o, e.Kind, target)
			}
			if !e.MeasuredAt.IsZero() {
				send(descMeasured, prometheus.GaugeValue, float64(e.MeasuredAt.Unix()), o, e.Kind, target)
			}
		}
	}
	v := h.storageModel()
	for _, f := range v.Folders {
		// A shared folder belongs to no one app: app "" (absent).
		if f.AllocBytes != nil {
			send(descAlloc, prometheus.GaugeValue, float64(*f.AllocBytes), "", "folder", f.ID)
		}
		if f.MeasuredAt != nil {
			send(descMeasured, prometheus.GaugeValue, float64(f.MeasuredAt.Unix()), "", "folder", f.ID)
		}
	}
	sort.Slice(v.Disks, func(i, j int) bool { return v.Disks[i].Dev < v.Disks[j].Dev })
	for _, d := range v.Disks {
		dev := strconv.FormatUint(d.Dev, 10)
		send(descFree, prometheus.GaugeValue, float64(d.FreeBytes), dev)
		send(descTotal, prometheus.GaugeValue, float64(d.TotalBytes), dev)
	}
}

// NoteMetricsScrape records a scrape of the metrics listener.
func (h *Hub) NoteMetricsScrape() { h.usage.scrapedAt.Store(h.usage.now().UnixNano()) }

// MetricsScrapedRecently: the listener was scraped in the last 5 min.
func (h *Hub) MetricsScrapedRecently() bool {
	at := h.usage.scrapedAt.Load()
	return at != 0 && h.usage.now().Sub(time.Unix(0, at)) < metricsScrapedWithin
}
