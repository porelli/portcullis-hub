package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/usage"
)

// The usage page's routes (contract §11.11): Hub listener only, admins,
// no-store, answered from the Hub's caches (never the engine).
func (s *Server) registerUsage(mux routeMux) {
	mux.HandleFunc("GET /api/usage", s.handleUsage)
	mux.HandleFunc("GET /api/usage/instances/{id}", s.handleUsageInstance)
	mux.HandleFunc("GET /api/usage/export.csv", s.handleUsageCSV)
	mux.HandleFunc("GET /api/usage/storage", s.handleUsageStorage)
	mux.HandleFunc("POST /api/usage/storage/measure", s.handleUsageMeasure)
	mux.HandleFunc("GET /api/usage/storage/op", s.handleUsageStorageOp)
	mux.HandleFunc("POST /api/usage/storage/op/stop", s.handleUsageStorageStop)
}

// usageBodyMax caps the storage routes' bodies (contract §11.11).
const usageBodyMax = 1 << 10

// usageBody decodes a strict body of at most 1 KiB: 413 above it, 400
// on anything else wrong (a fixed message, never the decoder's).
func usageBody(w http.ResponseWriter, r *http.Request, v any, usage string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, usageBodyMax))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		writeJSONError(w, http.StatusRequestEntityTooLarge, "the body is over 1 KiB")
		return false
	case err != nil:
		writeJSONError(w, http.StatusBadRequest, "body must be "+usage)
		return false
	}
	return true
}

// usageMeasure: the route's and the tool's work.
func (s *Server) usageMeasure(a directory.Actor, instance string) (*hub.AsyncOp, error) {
	s.rec("StartUsageMeasure", a.User, instance)
	return s.Hub.StartUsageMeasure(a, instance)
}

func (s *Server) handleUsageStorage(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.UsageStorage())
}

func (s *Server) handleUsageMeasure(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var b struct {
		Instance string `json:"instance"`
	}
	if !usageBody(w, r, &b, `{} or {"instance": "<id>"}`) {
		return
	}
	op, err := s.usageMeasure(requestActor(r), b.Instance)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeOpAccepted(w, op)
}

func (s *Server) handleUsageStorageOp(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	s.writeOpRecord(w, "_usage", "the storage measurement")
}

func (s *Server) handleUsageStorageStop(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var b struct {
		OpID string `json:"op_id"`
	}
	const usage = `{} or {"op_id": "<16 hex>"}`
	if !usageBody(w, r, &b, usage) {
		return
	}
	if b.OpID != "" && !stopOpIDRe.MatchString(b.OpID) {
		writeJSONError(w, http.StatusBadRequest, "body must be "+usage)
		return
	}
	rec, err := s.Hub.StopUsageMeasure(requestActor(r), b.OpID)
	noStore(w)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, rec)
}

// usageOverview / usageInstance: the route's and the tool's work.
func (s *Server) usageOverview(window string) hub.UsageView { return s.Hub.UsageOverview(window) }

// usageWindow is GET /api/usage's window: absent = last; given once, last
// or 1h; anything else, or given twice, is refused (false).
func usageWindow(r *http.Request) (string, bool) {
	vs, ok := r.URL.Query()["window"]
	switch {
	case !ok:
		return hub.UsageWindowLast, true
	case len(vs) == 1 && (vs[0] == hub.UsageWindowLast || vs[0] == hub.UsageWindow1h):
		return vs[0], true
	}
	return "", false
}

func (s *Server) usageInstance(id string) (*hub.UsageGroup, error) { return s.Hub.UsageInstance(id) }

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	noStore(w)
	window, ok := usageWindow(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "window must be last or 1h")
		return
	}
	writeJSON(w, s.usageOverview(window))
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
	usageCSVStorage    = []string{"owner", "kind", "target", "alloc_bytes", "apparent_bytes", "partial", "in_total", "shared_with", "measured_at"}
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
		v := s.usageOverview(hub.UsageWindowLast)
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
	case "storage":
		return usageCSVStorage, s.usageStorageRows(), true
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
		writeJSONError(w, http.StatusBadRequest, "view must be apps, containers or storage")
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

// usageStorageRows are the storage view's CSV rows (the storage cache).
func (s *Server) usageStorageRows() [][]string {
	v := s.Hub.UsageStorage()
	var rows [][]string
	add := func(it hub.StorageItem) {
		rows = append(rows, []string{it.Owner, it.Kind, it.Target, usage.Int(it.AllocBytes), usage.Int(it.ApparentBytes),
			strconv.FormatBool(it.Partial), strconv.FormatBool(it.InTotal), strings.Join(it.Shared, ";"), csvTime(it.MeasuredAt)})
	}
	for _, g := range v.Apps {
		for _, it := range g.Items {
			add(it)
		}
	}
	for _, f := range v.Folders {
		rows = append(rows, []string{f.ID, "folder", f.ID, usage.Int(f.AllocBytes), "", strconv.FormatBool(f.Partial), "false",
			strings.Join(f.UsedBy, ";"), csvTime(f.MeasuredAt)})
	}
	for _, it := range v.Core {
		add(it)
	}
	return rows
}
