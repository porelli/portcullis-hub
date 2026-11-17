package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/templates"
)

// usageIDArgs names one instance (the instance routes' {id} rule: an
// unknown or malformed id is 404).
type usageIDArgs struct {
	ID string `json:"id" jsonschema:"the instance id"`
}

// registerUsageTools: the usage page's tools (contract §15.10, §11.11).
// Each Run calls the same Server method as its route; answers come from
// the Hub's caches, never the engine.
func (s *Server) registerUsageTools() {
	for _, t := range []Tool{
		admin("usage_overview", "Every app's CPU, memory, network, disk IO and PIDs, aggregated per app with its containers, plus the core group. Live, from the Hub's last sample: each figure is a number or null (not measured, never 0), totals with a null member are lower bounds (partial).",
			ClassRead, "GET /api/usage", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.usageOverview(), nil
			}),
		admin("usage_instance", "One instance's containers, last hour and storage.",
			ClassRead, "GET /api/usage/instances/{id}", "", func(_ context.Context, _ directory.Actor, in usageIDArgs) (any, error) {
				return s.usageInstance(in.ID)
			}),
		admin("usage_storage", "Disk use per app volume, bind, shared folder and core volume, and each filesystem's free space, as last measured (with dates): null figures are not measured, partial ones lower bounds.",
			ClassRead, "GET /api/usage/storage", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.Hub.UsageStorage(), nil
			}),
		admin("usage_storage_measure", "Measure storage now (all, or instance) in the background: answers {op_id, op, instance, poll}; see usage_storage_op. Read-only on disk and bounded (2 min per target, 1 h per run).",
			ClassWrite, "POST /api/usage/storage/measure", "usage.measure", func(_ context.Context, a directory.Actor, in usageMeasureArgs) (any, error) {
				if in.Instance != "" && !templates.InstanceIDRe.MatchString(in.Instance) && !templates.ValidID(in.Instance) {
					return nil, &hub.StatusError{Status: http.StatusNotFound, Err: fmt.Errorf("app instance not found: %s", in.Instance)}
				}
				op, err := s.usageMeasure(a, in.Instance)
				if err != nil {
					return nil, err
				}
				return opAcceptedBody(op), nil
			}),
		admin("usage_storage_op", "The last storage measurement's op record: its step, ok / error, the result {targets, measured, failed, skipped} and warnings.",
			ClassRead, "GET /api/usage/storage/op", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				rec := s.Hub.LastOp("_usage")
				if rec == nil {
					return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no operation recorded for the storage measurement")}
				}
				return rec, nil
			}),
	} {
		s.registerTool(t)
	}
}

// usageMeasureArgs: one instance (optional; "" = everything).
type usageMeasureArgs struct {
	Instance string `json:"instance,omitempty" jsonschema:"the instance id whose storage to measure (default: everything)"`
}
