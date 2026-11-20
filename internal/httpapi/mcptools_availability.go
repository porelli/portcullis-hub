package httpapi

import (
	"context"

	"github.com/portcullis/hub/internal/directory"
)

// The availability tool (contract §20.6): instance_availability_get (R)
// reads an instance's priority, Runs on, the cluster's nodes and the
// N−1 result. Changing it has no tool (availabilityNoToolRoutes).

func (s *Server) registerAvailabilityTools() {
	s.registerTool(admin("instance_availability_get", "An instance's availability on Kubernetes: its priority (critical, high, normal or low), where it runs (anywhere, prefer or only, with the class, site or nodes), the cluster's nodes (name, class, site, small) and the N−1 check per node (green, yellow, red or unknown: what wouldn't have room if that node failed). Refused off Kubernetes.",
		ClassRead, "GET /api/instances/{id}/availability", "", func(ctx context.Context, _ directory.Actor, in idArgs) (any, error) {
			if err := instanceIDOK(in.ID); err != nil {
				return nil, err
			}
			return s.Hub.InstanceAvailability(ctx, in.ID)
		}))
}
