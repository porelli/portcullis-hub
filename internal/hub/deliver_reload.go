package hub

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// The reload action, signal form (contract §13.8, spec call 25): the
// signal goes to the reload service's running containers through the
// Engine API (ContainerKill). It counts as applied when every call
// returned 2xx and the containers still run — and are not unhealthy —
// after reloadGrace. The panel says "reload signal sent, app still
// running", never that the app accepted the change. A failure is the
// instance's op record (op reload), unless another operation's running
// record is there (P20). Not running: nothing is sent (the next start
// reads the files). The hook form runs the declared hook with the same
// stdin and exit-code rules (deliver_hooks.go).

// reloadApplied is a successful signal reload's status text.
const reloadApplied = "reload signal sent, app still running"

// reloadUnit runs t's reload action. The hook form: the hook already ran
// in this run's hook step (forced there, folded with the hook
// deliveries); ran has its result.
func (h *Hub) reloadUnit(ctx context.Context, t *templates.Template, ran map[string]UnitResult) UnitResult {
	u := UnitResult{Unit: unitReload, At: time.Now().UTC()}
	r := t.Manifest.Reload
	switch {
	case r == nil:
		u.Skipped = SkipUnsupported
		return u
	case r.Hook != "":
		hu, ok := ran[r.Hook]
		switch {
		case !ok:
			u.Skipped = SkipUnchanged // not run: nothing to reload
		case hu.OK:
			u.OK, u.Message = true, "applied by hook "+r.Hook
		default:
			// Its failure is the hook's op record already.
			u.Skipped, u.Error = hu.Skipped, hu.Error
		}
		return u
	case h.noEngine():
		u.Skipped = SkipNotRunning
		return u
	}
	fail := func(err error) UnitResult {
		u.Error = h.redactUnitError(t.ID, err)
		h.finishDeliveryOp(t.ID, OpReload, err)
		return u
	}
	cs, err := h.rt.List(ctx, runtime.Filter{Instance: t.ID, Service: r.Service})
	if err != nil {
		return fail(fmt.Errorf("reload: listing the %s containers: %w", r.Service, err))
	}
	var ids []string
	for _, c := range cs {
		if c.State == "running" && c.Labels[docker.LabelOneoff] != "True" {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		u.Skipped = SkipNotRunning
		return u
	}
	degraded := false
	for _, id := range ids {
		err := h.rt.Signal(ctx, id, r.Signal)
		if errors.Is(err, kube.ErrReloadDegraded) {
			// Kubernetes, no kill in the image: the pod was restarted
			// through its Deployment (doctor reload_degraded).
			degraded = true
			continue
		}
		if err != nil {
			return fail(fmt.Errorf("reload: sending %s to %s failed: %w", r.Signal, r.Service, err))
		}
	}
	if degraded {
		h.reloadDegraded.Store(t.ID, true)
		u.OK, u.Message = true, reloadDegradedMsg
		return u
	}
	h.reloadDegraded.Delete(t.ID)
	if err := h.sleep(ctx, reloadGrace); err != nil {
		return fail(fmt.Errorf("reload: %w", err))
	}
	for _, id := range ids {
		st, err := h.rt.State(ctx, id)
		switch {
		case err != nil:
			return fail(fmt.Errorf("reload: checking %s after the %s signal: %w", r.Service, r.Signal, err))
		case !st.Running:
			return fail(errors.New("reload: " + r.Service + " stopped after the " + r.Signal + " signal"))
		case st.Health == "unhealthy":
			return fail(errors.New("reload: " + r.Service + " is unhealthy after the " + r.Signal + " signal"))
		}
	}
	u.OK, u.Message = true, reloadApplied
	if last := h.LastOp(t.ID); last != nil && last.Op == OpReload && !last.OK {
		// The failure it recorded is over.
		h.finishDeliveryOp(t.ID, OpReload, nil)
	}
	return u
}

// reloadDegradedMsg is a reload unit's message when the pod had to be
// restarted instead (Kubernetes, no kill in the image).
const reloadDegradedMsg = "reload_degraded: the image has no kill, the pod was restarted"
