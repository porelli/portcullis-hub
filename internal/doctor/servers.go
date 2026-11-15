package doctor

import (
	"sort"
	"strings"
)

// Servers (contract §17, §14.5). More kinds follow with the servers'
// doctor (plan Task 13).
const (
	KindServerSecretsNotRotated = "server_secrets_not_rotated"
)

// ServersIn is the servers' state the doctor reads: per revoked server,
// why its revocation couldn't rotate what the worker held.
type ServersIn struct {
	NotRotated map[string]string
}

func init() { Register(serverSecretsCheck{}) }

type serverSecretsCheck struct{}

func (serverSecretsCheck) Kind() string { return KindServerSecretsNotRotated }

func (serverSecretsCheck) Run(in *Inputs) []Finding {
	if in.Servers == nil {
		return nil
	}
	ids := make([]string, 0, len(in.Servers.NotRotated))
	for id := range in.Servers.NotRotated {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Finding
	for _, id := range ids {
		why := in.Servers.NotRotated[id]
		out = append(out, Finding{FP: Fingerprint(KindServerSecretsNotRotated, id), Kind: KindServerSecretsNotRotated, Severity: Problem,
			Title:  "The revoked server " + id + " still holds working client secrets.",
			Why:    "Its revocation couldn't rotate the Keycloak client secrets or relay tokens of its instances (" + strings.TrimSpace(why) + "). The Hub retries every 30 seconds.",
			Class:  FixExplain,
			Steps:  []string{"Check that Keycloak is reachable.", "If an instance's template is gone, forget the instance or restore it elsewhere."},
			Inputs: Digest(id + " " + why)})
	}
	return out
}
