package httpapi

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/usage"
)

// The usage page's routes (contract §11.11): Hub listener only, admins,
// no-store, answered from the Hub's caches (never the engine).
func (s *Server) registerUsage(mux routeMux) {
	mux.HandleFunc("GET /api/usage", s.handleUsage)
	mux.HandleFunc("GET /api/usage/instances/{id}", s.handleUsageInstance)
	mux.HandleFunc("GET /api/usage/export.csv", s.handleUsageCSV)
}

// usageOverview / usageInstance: the route's and the tool's work.
func (s *Server) usageOverview() hub.UsageView { return s.Hub.UsageOverview() }

func (s *Server) usageInstance(id string) (*hub.UsageGroup, error) { return s.Hub.UsageInstance(id) }

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.usageOverview())
}

func (s *Server) handleUsageInstance(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	noStore(w)
	g, err := s.usageInstance(r.PathValue("id"))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, g)
}

// The CSV headers (contract §11.11, U22).
var (
	usageCSVApps = []string{"instance", "template", "name", "status", "cpu_cores", "mem_bytes", "mem_limit_bytes", "cpu_limit_cores",
		"pids", "pids_limit", "net_rx_bps", "net_tx_bps", "blk_read_bps", "blk_write_bps", "partial", "measured_at"}
	usageCSVContainers = []string{"instance", "service", "number", "id12", "state", "cpu_cores", "mem_bytes", "mem_limit_bytes", "cpu_limit_cores",
		"pids", "pids_limit", "net_rx_bps", "net_tx_bps", "blk_read_bps", "blk_write_bps", "oom_killed", "restarts", "measured_at"}
)

// usageCSVTime is the filename's timestamp form (UTC).
const usageCSVTime = "20060102T150405Z"

func csvTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func sampleCells(sm usage.Sample) []string {
	return []string{usage.Float(sm.CPUCores), usage.Int(sm.MemBytes), usage.Int(sm.MemLimitBytes), usage.Float(sm.CPULimitCores),
		usage.Int(sm.Pids), usage.Int(sm.PidsLimit), usage.Float(sm.NetRxBps), usage.Float(sm.NetTxBps),
		usage.Float(sm.BlkReadBps), usage.Float(sm.BlkWriteBps)}
}

// usageCSV is one view's header and rows.
func (s *Server) usageCSV(view string) ([]string, [][]string, bool) {
	switch view {
	case "apps", "containers":
		v := s.usageOverview()
		at := csvTime(v.SampledAt)
		groups := append(append(append([]hub.UsageGroup{}, v.Apps...), v.Core), v.UnknownProjects...)
		var rows [][]string
		for _, g := range groups {
			inst := g.Instance
			if inst == "" {
				inst = g.Name // an unknown project: its project name
			}
			if view == "apps" {
				row := append([]string{inst, g.Template, g.Name, g.Status}, sampleCells(g.Totals)...)
				rows = append(rows, append(row, strconv.FormatBool(g.Partial), at))
				continue
			}
			for _, c := range g.Containers {
				row := append([]string{inst, c.Service, strconv.Itoa(c.Number), c.ID12, c.State}, sampleCells(c.Sample)...)
				rows = append(rows, append(row, strconv.FormatBool(c.OOMKilled), strconv.Itoa(c.Restarts), at))
			}
		}
		if view == "apps" {
			return usageCSVApps, rows, true
		}
		return usageCSVContainers, rows, true
	}
	return nil, nil, false
}

func (s *Server) handleUsageCSV(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	view := r.URL.Query().Get("view")
	header, rows, ok := s.usageCSV(view)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "view must be apps or containers")
		return
	}
	var b bytes.Buffer
	if err := usage.WriteCSV(&b, header, rows); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the CSV export failed")
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="portcullis-usage-%s-%s.csv"`, view, time.Now().UTC().Format(usageCSVTime)))
	w.Write(b.Bytes())
}
