package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// The availability tools (contract §20.6): instance_availability_get (R)
// reads an instance's priority, Runs on, the cluster's nodes and the N−1
// result; set_instance_availability (W) changes them. With
// confirm_n_minus_1 it is D (the person confirms in the browser), and
// even then an AI overrides only a yellow N−1 result: a red or unknown
// one always answers the 409 {error, n_minus_1} (the Hub's rule, by the
// actor's Via).

type availabilityArgs struct {
	ID             string        `json:"id"`
	Priority       string        `json:"priority" jsonschema:"critical, high, normal or low"`
	RunsOn         *state.RunsOn `json:"runs_on" jsonschema:"where it runs: {mode: anywhere|prefer|only, class?: home|cloud, site?, nodes?: [...]}"`
	ConfirmNMinus1 bool          `json:"confirm_n_minus_1,omitempty" jsonschema:"go ahead past a yellow N−1 result (asks the person in the browser); never past red or unknown"`
}

func (s *Server) registerAvailabilityTools() {
	s.registerTool(admin("instance_availability_get", "An instance's availability on Kubernetes: its priority (critical, high, normal or low), where it runs (anywhere, prefer or only, with the class, site or nodes), the cluster's nodes (name, class, site, small) and the N−1 check per node (green, yellow, red or unknown: what wouldn't have room if that node failed). Refused off Kubernetes.",
		ClassRead, "GET /api/instances/{id}/availability", "", func(ctx context.Context, _ directory.Actor, in idArgs) (any, error) {
			if err := instanceIDOK(in.ID); err != nil {
				return nil, err
			}
			return s.Hub.InstanceAvailability(ctx, in.ID)
		}))
	s.registerTool(Tool{Name: "set_instance_availability",
		Description: "Set an instance's priority and where it runs (Kubernetes). Raising it to critical or high, or moving a critical or high instance, first runs the N−1 check: a yellow, red or unknown result answers 409 {error, n_minus_1} and nothing changes. confirm_n_minus_1 goes ahead past a yellow result only (needs your confirmation in the browser); a red or unknown one is changed in the Hub only. An enabled instance restarts.",
		Class:       ClassDestructive, Scope: ScopeAdmin, Twin: "PUT /api/instances/{id}/availability", Audit: "instance.availability", In: availabilityArgs{},
		ClassFor: func(_ context.Context, args json.RawMessage) ToolClass {
			if a, err := decode[availabilityArgs](args); err == nil && !a.ConfirmNMinus1 {
				return ClassWrite
			}
			return ClassDestructive
		},
		Typed: idOf,
		Consequences: func(_ context.Context, args json.RawMessage) []string {
			a, _ := decode[availabilityArgs](args)
			return []string{"Sets " + a.ID + " to priority " + q(a.Priority) + " although the N−1 check warns that a node's failure would leave some apps degraded; it restarts if enabled."}
		},
		Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
			in, err := decode[availabilityArgs](args)
			if err != nil {
				return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("invalid arguments")}
			}
			if err := instanceIDOK(in.ID); err != nil {
				return nil, err
			}
			a := state.Availability{Priority: strings.TrimSpace(in.Priority)}
			if in.RunsOn != nil {
				a.RunsOn = *in.RunsOn
			}
			return s.setAvailability(ctx, toolActor(ctx, c), in.ID, a, in.ConfirmNMinus1)
		}})
}
