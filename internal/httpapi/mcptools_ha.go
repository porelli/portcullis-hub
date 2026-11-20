package httpapi

import (
	"context"

	"github.com/portcullis/hub/internal/directory"
)

// The HA read tools (class R only): ha_status (contract §20.1), the HA
// page's answer, and ha_findings (§14.5), the doctor's HA findings — the
// same Hub.Doctor as doctor_findings, kept to the HA kinds. Neither
// answers a secret, a token, a join code or a credential: the page holds
// none (the front door's and the backup destination's credentials never
// reach the Hub) and findings name nodes, sites, pods and instances only.
// There is no tool that turns HA on: that is `./portcullis ha enable` on
// the host (D5).

func (s *Server) registerHATools() {
	s.registerTool(admin("ha_status", "High availability on Kubernetes (experimental): the checklist `./portcullis ha enable` needs all green (nodes, servers, storage, ingress, backup destination, N−1, watchdogs; with several sites the mesh gateways and round trips), the Postgres guarantee, each node's role, class, site, readiness, fencing and N−1 level, the etcd, Vault and Sentinel quorums, the sites, the front door's state and each name's worst-case failover time, the replicated volumes, warnings and known gaps. Read-only: turning HA on is the host command `./portcullis ha enable`. Refused off Kubernetes.",
		ClassRead, "GET /api/ha", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
			return s.Hub.HA(ctx)
		}))
	s.registerTool(admin("ha_findings", "The doctor's high-availability findings on Kubernetes (experimental): nodes down, quorums at risk, degraded volumes, Postgres without a synchronous standby, nodes that can't be fenced, the N−1 check, a stale core backup, instances on the default memory limit, the front door probing from inside only, published documents, a lost Lease, the node mesh, node certificates and API ports on public addresses — each with severity, why and the steps (all explain-only), with the counts. Read-only (doctor_findings has the whole report). Refused off Kubernetes.",
		ClassRead, "GET /api/doctor", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
			return s.Hub.DoctorHA(ctx)
		}))
}
