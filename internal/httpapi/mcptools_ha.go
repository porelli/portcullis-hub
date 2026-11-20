package httpapi

import (
	"context"

	"github.com/portcullis/hub/internal/directory"
)

// ha_status (R, contract §20.1): the HA page's answer. There is no tool
// that turns HA on: that is `./portcullis ha enable` on the host (D5).

func (s *Server) registerHATools() {
	s.registerTool(admin("ha_status", "High availability on Kubernetes (experimental): the checklist `./portcullis ha enable` needs all green (nodes, servers, storage, ingress, backup destination, N−1, watchdogs; with several sites the mesh gateways and round trips), the Postgres guarantee, each node's role, class, site, readiness, fencing and N−1 level, the etcd, Vault and Sentinel quorums, the sites, the front door's state and each name's worst-case failover time, the replicated volumes, warnings and known gaps. Read-only: turning HA on is the host command `./portcullis ha enable`. Refused off Kubernetes.",
		ClassRead, "GET /api/ha", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
			return s.Hub.HA(ctx)
		}))
}
