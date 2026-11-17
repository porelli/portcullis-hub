package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// The server tools (contract §15.10, Task 12): list_servers and
// get_server (R; never a join code, a key, a secret or a serial),
// move_instance (D, typed on the instance id) and set_backup_schedule
// (W). Adding, revoking and removing a server have no tool (a join code
// must never land in a transcript; revocation stays a human action).

type (
	serverIDArgs struct {
		ID string `json:"id"`
	}
	moveArgs struct {
		ID     string `json:"id"`
		Server string `json:"server"`
	}
	scheduleArgs struct {
		Server  string `json:"server"`
		Mode    string `json:"mode"`
		Hour    int    `json:"hour"`
		Weekday int    `json:"weekday,omitempty"`
	}
)

func serverIDOK(id string, primaryOK bool) error {
	if primaryOK && id == servers.PrimaryID {
		return nil
	}
	if servers.ValidID(id) != nil {
		return badArg("invalid server id")
	}
	return nil
}

// humanSize is n bytes as "1.4 GB".
func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// moveConsequences name the downtime and the size of what moves (the
// newest backup's, the best estimate before the move's own).
func (s *Server) moveConsequences(_ context.Context, args json.RawMessage) []string {
	a, err := decode[moveArgs](args)
	if err != nil {
		return []string{"Moves an instance (invalid arguments)."}
	}
	to := a.Server
	if to == "" || to == servers.PrimaryID {
		to = "the primary"
	}
	size := "its size isn't known yet (no backup)"
	// Scoped to a valid id (I6): ListBackups("") lists every instance.
	if instanceIDOK(a.ID) != nil {
		return []string{"Moves instance " + q(a.ID) + " (invalid id: refused)."}
	}
	if list, err := s.Hub.ListBackups(a.ID); err == nil && len(list) > 0 {
		newest := list[0]
		for _, b := range list[1:] {
			if b.CreatedAt.After(newest.CreatedAt) {
				newest = b
			}
		}
		size = "about " + humanSize(newest.Size) + " (its newest backup)"
	}
	return []string{
		"Moves instance " + q(a.ID) + " to " + q(to) + ": it is stopped, backed up and restored there, so it is down for the whole move; " + size + " is copied.",
		"The source copy is kept, stopped, for 7 days (Undo move in the Hub).",
	}
}

func (s *Server) registerServerTools() {
	sched := admin("set_backup_schedule", "Set a server's scheduled backups (server \"primary\" for the primary): mode off, daily or weekly, at hour 0–23 of the Hub's time zone, weekday 0–6 (0 = Sunday) for weekly. Only the schedule changes.",
		ClassWrite, "PUT /api/servers/{id}/settings", "server.settings", func(ctx context.Context, a directory.Actor, in scheduleArgs) (any, error) {
			if err := serverIDOK(in.Server, true); err != nil {
				return nil, err
			}
			sch := state.BackupSchedule{Mode: in.Mode, Hour: in.Hour, Weekday: in.Weekday}
			if err := s.setServerSettings(ctx, a, in.Server, hub.ServerSettings{BackupSchedule: &sch}); err != nil {
				return nil, err
			}
			return s.serverDetail(ctx, in.Server)
		})
	sched.AlsoTwins = []string{"PUT /api/servers/primary/settings"}
	for _, t := range []Tool{
		admin("list_servers", "Every server, the primary first: name, state, runtime, architecture, CPUs, memory, disk and data free space, its instances, last contact, agent version and certificate expiry. No join code, key, secret or serial.",
			ClassRead, "GET /api/servers", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return s.listServers(ctx), nil
			}),
		admin("get_server", "One server (\"primary\" for the primary): the list's fields plus its instances, Local networks, folder roots and backup schedule. No join code, key, secret or serial.",
			ClassRead, "GET /api/servers/{id}", "", func(ctx context.Context, _ directory.Actor, in serverIDArgs) (any, error) {
				if err := serverIDOK(in.ID, true); err != nil {
					return nil, err
				}
				return s.serverDetail(ctx, in.ID)
			}),
		{Name: "move_instance", Description: "Move an instance to another server (server \"\" or \"primary\" = the primary; needs your confirmation in the browser, typing the instance id): it is stopped, backed up, restored and started there; the source copy is kept stopped for 7 days. Runs in the background: answers {op_id, op, instance, poll}; see wait_for_op.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/instances/{id}/move", Audit: "instance.move", In: moveArgs{},
			Typed: idOf, Consequences: s.moveConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, err := decode[moveArgs](args)
				if err != nil {
					return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: fmt.Errorf("invalid arguments")}
				}
				if err := instanceIDOK(in.ID); err != nil {
					return nil, err
				}
				to := in.Server
				if to == servers.PrimaryID {
					to = ""
				}
				op, err := s.startMove(toolActor(ctx, c), in.ID, to)
				if err != nil {
					return nil, err
				}
				return acceptedBody(op), nil
			}},
		sched,
	} {
		s.registerTool(t)
	}
}
