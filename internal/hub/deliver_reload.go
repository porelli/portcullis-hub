package hub

import (
	"context"
	"errors"
	"fmt"
	"time"

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
// reads the files).

// reloadApplied is a successful signal reload's status text.
const reloadApplied = "reload signal sent, app still running"

// reloadUnit runs t's reload action.
func (h *Hub) reloadUnit(ctx context.Context, t *templates.Template) UnitResult {
	u := UnitResult{Unit: unitReload, At: time.Now().UTC()}
	r := t.Manifest.Reload
	switch {
	case r == nil:
		u.Skipped = SkipUnsupported
		return u
	case r.Hook != "":
		// The hook form arrives with hooks (Task 10).
		u.Skipped = SkipUnsupported
		return u
	case h.engine == nil:
		u.Skipped = SkipNotRunning
		return u
	}
	fail := func(err error) UnitResult {
		u.Error = h.redactUnitError(t.ID, err)
		h.finishDeliveryOp(t.ID, OpReload, err)
		return u
	}
	cs, err := h.engine.ListContainers(ctx, docker.Filters{"label": {
		docker.LabelProject + "=" + projectName(t.ID), docker.LabelService + "=" + r.Service}})
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
	for _, id := range ids {
		if err := h.engine.ContainerKill(ctx, id, r.Signal); err != nil {
			return fail(fmt.Errorf("reload: sending %s to %s failed: %w", r.Signal, r.Service, err))
		}
	}
	if err := h.sleep(ctx, reloadGrace); err != nil {
		return fail(fmt.Errorf("reload: %w", err))
	}
	for _, id := range ids {
		st, err := h.engine.ContainerState(ctx, id)
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
