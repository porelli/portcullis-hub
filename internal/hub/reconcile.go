package hub

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// DriftKind classifies a mismatch between state.yaml and Docker.
type DriftKind string

const (
	// DriftNotRunning: enabled, but no container of the project is running.
	DriftNotRunning DriftKind = "enabled_not_running"
	// DriftNotEnabled: containers of the project are running, but the app
	// is not enabled.
	DriftNotEnabled DriftKind = "running_not_enabled"
	// DriftLeftovers: stopped containers of a disabled/unknown app remain.
	DriftLeftovers DriftKind = "stopped_not_enabled"
	// DriftTemplateMissing: enabled, but no (valid) template provides it.
	DriftTemplateMissing DriftKind = "template_missing"
)

// Drift actions accepted by ResolveDrift.
const (
	ActionStart   = "start"   // compose up an enabled app
	ActionDisable = "disable" // mark disabled and compose down
	ActionStop    = "stop"    // compose down a project that is not enabled
	ActionAdopt   = "adopt"   // enable an app whose containers already run
)

// Drift is one mismatch.
type Drift struct {
	ID             string    `json:"id"`
	Kind           DriftKind `json:"kind"`
	Message        string    `json:"message"`
	Running        int       `json:"running"`
	Total          int       `json:"total"`
	TemplateExists bool      `json:"template_exists"`
	Actions        []string  `json:"actions"`
}

// DriftReport is the latest reconcile result.
type DriftReport struct {
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error,omitempty"`
	Items     []Drift   `json:"items"`
}

type projectCount struct{ running, total int }

// computeDrift compares enabled apps with project container counts. busy
// apps (mid-operation) are skipped.
func computeDrift(enabled map[string]bool, known map[string]bool, counts map[string]projectCount, busy func(string) bool) []Drift {
	var out []Drift
	ids := map[string]bool{}
	for id := range enabled {
		ids[id] = true
	}
	for id := range counts {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		if busy(id) {
			continue
		}
		c := counts[id]
		d := Drift{ID: id, Running: c.running, Total: c.total, TemplateExists: known[id]}
		switch {
		case enabled[id] && !known[id]:
			d.Kind = DriftTemplateMissing
			d.Message = "enabled, but no valid template provides it any more"
			d.Actions = []string{ActionDisable}
		case enabled[id] && c.running == 0:
			d.Kind = DriftNotRunning
			d.Message = "enabled but not running"
			if c.total > 0 {
				d.Message += " (containers stopped)"
			} else {
				d.Message += " (no containers)"
			}
			d.Actions = []string{ActionStart, ActionDisable}
		case !enabled[id] && c.running > 0:
			d.Kind = DriftNotEnabled
			d.Message = "running but not enabled"
			d.Actions = []string{ActionStop}
			if known[id] {
				d.Actions = append(d.Actions, ActionAdopt)
			}
		case !enabled[id] && c.total > 0:
			d.Kind = DriftLeftovers
			d.Message = "stopped containers left behind by an app that is not enabled"
			d.Actions = []string{ActionStop}
		default:
			continue
		}
		out = append(out, d)
	}
	return out
}

// Reconcile checks state against Docker once, stores and returns the report.
// It never changes anything; drift is logged when it appears or clears.
func (h *Hub) Reconcile(ctx context.Context) DriftReport {
	rep := DriftReport{CheckedAt: time.Now().UTC(), Items: []Drift{}}
	if h.engine == nil {
		rep.Error = "docker engine not configured"
		return h.storeDrift(rep)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cs, err := h.engine.ListContainers(ctx, docker.Filters{"label": {docker.LabelProject}})
	if err != nil {
		rep.Error = err.Error()
		return h.storeDrift(rep)
	}
	counts := map[string]projectCount{}
	for _, c := range cs {
		p := c.Project()
		if !strings.HasPrefix(p, ProjectPrefix) || c.Labels[docker.LabelOneoff] == "True" {
			continue
		}
		id := strings.TrimPrefix(p, ProjectPrefix)
		if !templates.ValidID(id) {
			continue
		}
		pc := counts[id]
		pc.total++
		if c.State == "running" || c.State == "restarting" {
			pc.running++
		}
		counts[id] = pc
	}
	h.mu.RLock()
	enabled := map[string]bool{}
	for _, id := range h.st.Enabled {
		enabled[id] = true
	}
	known := map[string]bool{}
	for _, t := range h.templates {
		known[t.ID] = true
	}
	h.mu.RUnlock()
	rep.Items = computeDrift(enabled, known, counts, h.appBusy)
	return h.storeDrift(rep)
}

func (h *Hub) storeDrift(rep DriftReport) DriftReport {
	h.driftMu.Lock()
	defer h.driftMu.Unlock()
	if rep.Error != "" {
		if h.drift.Error != rep.Error {
			log.Printf("reconcile: cannot query docker: %s", rep.Error)
		}
		// Keep the last known items: an unreachable daemon is not drift.
		rep.Items = h.drift.Items
		if rep.Items == nil {
			rep.Items = []Drift{}
		}
	} else {
		now := map[string]string{}
		for _, d := range rep.Items {
			now[d.ID] = string(d.Kind)
			if h.driftKey[d.ID] != string(d.Kind) {
				log.Printf("drift: %s: %s (running %d/%d; actions: %s)", d.ID, d.Message, d.Running, d.Total, strings.Join(d.Actions, ", "))
			}
		}
		for id := range h.driftKey {
			if _, still := now[id]; !still {
				log.Printf("drift: %s: resolved", id)
			}
		}
		h.driftKey = now
	}
	h.drift = rep
	return rep
}

// Drift returns the latest report.
func (h *Hub) Drift() DriftReport {
	h.driftMu.Lock()
	defer h.driftMu.Unlock()
	r := h.drift
	r.Items = append([]Drift{}, r.Items...)
	return r
}

// TriggerReconcile requests a reconcile soon (coalesced).
func (h *Hub) TriggerReconcile() {
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

// RunReconciler reconciles periodically, on Docker container events of app
// projects and on TriggerReconcile, until ctx is done.
func (h *Hub) RunReconciler(ctx context.Context) {
	if h.engine != nil {
		go h.watchEvents(ctx)
	}
	h.Reconcile(ctx)
	tick := time.NewTicker(h.cfg.ReconcileInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-h.kick:
			// Debounce bursts (compose up emits many events).
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			select {
			case <-h.kick:
			default:
			}
		}
		h.Reconcile(ctx)
	}
}

func (h *Hub) watchEvents(ctx context.Context) {
	backoff := time.Second
	f := docker.Filters{"type": {"container"}, "label": {docker.LabelProject}}
	for ctx.Err() == nil {
		start := time.Now()
		err := h.engine.Events(ctx, f, func(ev docker.Event) {
			if strings.HasPrefix(ev.Actor.Attributes[docker.LabelProject], ProjectPrefix) {
				switch ev.Action {
				case "start", "die", "stop", "kill", "destroy", "create", "pause", "unpause", "restart", "oom":
					h.TriggerReconcile()
				}
			}
		})
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		log.Printf("reconcile: docker event stream ended (%v); retrying in %s", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
		h.TriggerReconcile() // events may have been missed
	}
}

// ResolveDrift performs an explicit, user-chosen action for a drifted app.
func (h *Hub) ResolveDrift(id, action string) error {
	if !templates.ValidID(id) {
		return statusErr(400, "invalid app id")
	}
	defer h.TriggerReconcile()
	switch action {
	case ActionDisable:
		return h.Disable(id)
	case ActionAdopt:
		if h.Template(id) == nil {
			return statusErr(400, "no template for %s — it can only be stopped", id)
		}
		return h.Enable(id)
	case ActionStart:
		unlock, err := h.lockApp(id)
		if err != nil {
			return err
		}
		defer unlock()
		t := h.Template(id)
		if t == nil || !t.Enabled {
			return statusErr(400, "%s is not an enabled app with a template", id)
		}
		if err := h.composeUp(t); err != nil {
			return statusErr(500, "compose up failed: %v", err)
		}
		return nil
	case ActionStop:
		unlock, err := h.lockApp(id)
		if err != nil {
			return err
		}
		defer unlock()
		if h.IsEnabled(id) {
			return statusErr(400, "%s is enabled — use disable instead", id)
		}
		if err := h.compose.DownByName(context.Background(), projectName(id)); err != nil {
			return statusErr(500, "compose down failed: %v", err)
		}
		return nil
	default:
		return statusErr(400, "unknown action %q", action)
	}
}
