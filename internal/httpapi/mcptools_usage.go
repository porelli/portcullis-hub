package httpapi

import (
	"context"

	"github.com/portcullis/hub/internal/directory"
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
	} {
		s.registerTool(t)
	}
}
