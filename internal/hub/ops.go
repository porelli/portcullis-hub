package hub

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/templates"
)

// Lifecycle operations recorded per app.
const (
	OpEnable  = "enable"
	OpDisable = "disable"
	OpRestart = "restart"
	OpStart   = "start" // drift: compose up an enabled app
	OpApply   = "apply" // drift: regenerate the override and compose up
	OpStop    = "stop"  // drift: compose down a project that is not enabled
)

// OpRecord is an app's last lifecycle operation, kept in
// <data>/ops/<id>.json so a failure stays explainable after a reload —
// also for an app that is not enabled (a failed enable).
type OpRecord struct {
	Op     string    `json:"op"`
	At     time.Time `json:"at"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	Output string    `json:"output,omitempty"` // tail of compose's output (secrets redacted)
	Hint   string    `json:"hint,omitempty"`
	// RolledBack: a failed enable was undone (compose down: containers
	// and network removed, volumes kept).
	RolledBack bool `json:"rolled_back,omitempty"`
}

// OpError is a failed lifecycle operation as the API returns it: the
// message plus compose's output and a hint. It unwraps to the cause (for
// the HTTP status).
type OpError struct {
	Record OpRecord
	Err    error
}

func (e *OpError) Error() string { return e.Record.Error }
func (e *OpError) Unwrap() error { return e.Err }

func (h *Hub) opsDir() string          { return filepath.Join(h.cfg.DataDir, "ops") }
func (h *Hub) opPath(id string) string { return filepath.Join(h.opsDir(), id+".json") }

// loadOps reads the stored records (unreadable ones are skipped).
func (h *Hub) loadOps() {
	h.ops = map[string]OpRecord{}
	entries, _ := os.ReadDir(h.opsDir())
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !templates.ValidID(id) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.opsDir(), e.Name()))
		if err != nil {
			continue
		}
		var r OpRecord
		if json.Unmarshal(data, &r) == nil {
			h.ops[id] = r
		}
	}
}

// LastOp returns an app's last recorded operation (nil: none).
func (h *Hub) LastOp(id string) *OpRecord {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	if r, ok := h.ops[id]; ok {
		return &r
	}
	return nil
}

// FailedOps maps app ID → operation, for apps whose last operation failed.
func (h *Hub) FailedOps() map[string]string {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	out := map[string]string{}
	for id, r := range h.ops {
		if !r.OK {
			out[id] = r.Op
		}
	}
	return out
}

// finishOp records the outcome of op on id and returns err as an
// *OpError carrying compose's (redacted) output and a hint, or nil.
// Unknown apps and busy refusals are not recorded.
func (h *Hub) finishOp(id, op string, err error, rolledBack bool) error {
	var busy ErrBusy
	if errors.As(err, &busy) || errors.Is(err, ErrNotFound) || !templates.ValidID(id) {
		return err
	}
	if h.Template(id) == nil && !h.IsEnabled(id) {
		return err // e.g. "template not found": nothing to show it on
	}
	r := OpRecord{Op: op, At: time.Now().UTC(), OK: err == nil, RolledBack: rolledBack}
	if err != nil {
		redact := h.secretRedactor(id)
		r.Error = redact(err.Error())
		var ce *compose.Error
		if errors.As(err, &ce) {
			r.Output = redact(ce.Output)
		}
		r.Hint = opHint(r.Error + "\n" + r.Output)
	}
	h.opsMu.Lock()
	h.ops[id] = r
	h.opsMu.Unlock()
	if data, merr := json.MarshalIndent(r, "", "  "); merr == nil {
		if werr := fsutil.WriteFileAtomic(h.opPath(id), data, 0600); werr != nil {
			log.Printf("ops: cannot record %s %s: %v", op, id, werr)
		}
	}
	if err == nil {
		return nil
	}
	log.Printf("%s %s failed: %s", op, id, r.Error)
	return &OpError{Record: r, Err: err}
}

var bindInUseRe = regexp.MustCompile(`(?i)(?:bind(?: host port)?(?: for)? |listen \w+ )((?:\[[0-9a-fA-F:.]*\]|[0-9.]*):\d+(?:/(?:tcp|udp))?)`)

// opHint turns well-known compose failures into an actionable hint.
func opHint(out string) string {
	low := strings.ToLower(out)
	if strings.Contains(low, "address already in use") || strings.Contains(low, "port is already allocated") {
		port := "A host port"
		if m := bindInUseRe.FindStringSubmatch(out); m != nil {
			port = "Host port " + m[1]
		}
		return port + " this app publishes is already in use on the server, by a service outside Portcullis " +
			"(e.g. systemd-resolved holds port 53) or another container. Open the app's Settings → Host Ports to " +
			"change the host port, bind it to a specific address, or leave it empty to disable the binding — then try again."
	}
	return ""
}

var secretKeyRe = regexp.MustCompile(`(?i)secret|passw|token|key|salt|credential|private|auth|cookie`)

// secretRedactor returns a function that blanks the values of the app's and
// core's secret-looking env variables (and generated ones) in s. Compose
// doesn't print env values on up/down, but its error output is shown to the
// browser and stored: never let one through.
func (h *Hub) secretRedactor(id string) func(string) string {
	generated := map[string]bool{}
	if t := h.Template(id); t != nil {
		for _, e := range t.Manifest.Env {
			if e.Generate != "" && e.Generate != "none" {
				generated[e.Key] = true
			}
		}
	}
	var vals []string
	for _, p := range []string{h.envPath(id), filepath.Join(h.cfg.ProjectDir, ".env")} {
		for k, v := range readEnvFile(p) {
			if len(v) >= 6 && (generated[k] || secretKeyRe.MatchString(k)) {
				vals = append(vals, v)
			}
		}
	}
	// Longest first, so a secret containing another is blanked whole.
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	return func(s string) string {
		for _, v := range vals {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
		return s
	}
}
