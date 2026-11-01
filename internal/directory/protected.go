package directory

import (
	"os"
	"strings"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/policy"
)

// ProtectedGroups returns the groups whose members core refuses to invite
// (contract §9.4) — the same set core's enroll computes: lldap_admin,
// lldap_password_manager, extra (INVITE_PROTECTED_GROUPS, space or comma
// separated) and the group of every core subdomain in group-gate-map.conf
// (the consoles: auth, traefik, hub, directory, enroll, metrics; people
// is "*", any signed-in user, and adds no group). A missing
// map file leaves the built-in groups and extra.
func ProtectedGroups(extra, mapFile string) map[string]bool {
	set := map[string]bool{lldap.AdminGroup: true, "lldap_password_manager": true}
	for _, g := range strings.FieldsFunc(extra, func(r rune) bool { return r == ',' || r == ' ' }) {
		set[g] = true
	}
	b, err := os.ReadFile(mapFile)
	if err != nil {
		return set
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		// "*" (people: any signed-in user, contract §5.1) is no group.
		if v = strings.TrimSpace(v); ok && policy.CoreSubdomains[strings.ToLower(strings.TrimSpace(k))] && v != "" && v != "*" {
			set[v] = true
		}
	}
	return set
}
