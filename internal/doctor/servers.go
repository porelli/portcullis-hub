package doctor

import (
	"sort"
	"strings"
)

// Servers (contract §17, §14.5). More kinds follow with the servers'
// doctor (plan Task 13).
const (
	KindServerSecretsNotRotated = "server_secrets_not_rotated"
	KindInstanceQuarantined     = "server_instance_quarantined"
	KindPlacementInvalid        = "server_placement_invalid"
	KindMoveStuck               = "server_move_stuck"
)

// ServersIn is the servers' state the doctor reads:
//   - NotRotated: revoked server → why its revocation couldn't rotate
//     what the worker held;
//   - Quarantined: instance → "<server>: <why>", its agent's start
//     backstop quarantined it;
//   - PlacementInvalid: placed instance → why its template can't run on
//     a worker any more;
//   - Stuck: instance → the server a failed move couldn't take it down
//     on (routed nowhere).
type ServersIn struct {
	NotRotated       map[string]string
	Quarantined      map[string]string
	PlacementInvalid map[string]string
	Stuck            map[string]string
}

func init() {
	for _, k := range []string{KindServerSecretsNotRotated, KindInstanceQuarantined, KindPlacementInvalid, KindMoveStuck} {
		Register(serversCheck{kind: k})
	}
}

type serversCheck struct{ kind string }

func (c serversCheck) Kind() string { return c.kind }

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c serversCheck) Run(in *Inputs) []Finding {
	if in.Servers == nil {
		return nil
	}
	var src map[string]string
	switch c.kind {
	case KindServerSecretsNotRotated:
		src = in.Servers.NotRotated
	case KindInstanceQuarantined:
		src = in.Servers.Quarantined
	case KindPlacementInvalid:
		src = in.Servers.PlacementInvalid
	case KindMoveStuck:
		src = in.Servers.Stuck
	}
	var out []Finding
	for _, id := range sortedKeys(src) {
		why := strings.TrimSpace(src[id])
		f := Finding{FP: Fingerprint(c.kind, id), Kind: c.kind, Severity: Problem, Class: FixExplain, Inputs: Digest(id + " " + why)}
		switch c.kind {
		case KindServerSecretsNotRotated:
			f.Title = "The revoked server " + id + " still holds working client secrets."
			f.Why = "Its revocation couldn't rotate the Keycloak client secrets or relay tokens of its instances (" + why + "). The Hub retries every 30 seconds."
			f.Steps = []string{"Check that Keycloak is reachable.", "If an instance's template is gone, forget the instance or restore it elsewhere."}
		case KindInstanceQuarantined:
			f.Title = "The instance " + id + " is quarantined on its worker."
			f.Why = "A container of it started with a bind source that failed the agent's check (" + why + "): the agent stopped it, and refuses to start it again until an admin lifts the quarantine."
			f.Steps = []string{"Find what replaced a bind source's directory (a symlink planted by another container?) and fix it on the worker.", "Then lift the quarantine on the instance's page (fresh sign-in): the agent checks the bind sources again first."}
		case KindPlacementInvalid:
			f.Title = "The instance " + id + " can't run on its worker any more."
			f.Why = "Its template changed and is now primary-only (" + why + "): it was stopped on the worker and nothing more is sent there."
			f.Steps = []string{"Move it to the primary (its data comes along), or pin the template to a version that can run on a worker."}
		case KindMoveStuck:
			f.Title = "The move of " + id + " is stuck: it runs nowhere."
			f.Why = "A failed move couldn't take the copy on " + why + " down, so the source wasn't started again (two routed copies never exist). The Hub retries every 30 seconds."
			f.Steps = []string{"Bring " + why + " back (or take " + id + "'s containers down there by hand); the next retry starts it on its source."}
		}
		out = append(out, f)
	}
	return out
}
