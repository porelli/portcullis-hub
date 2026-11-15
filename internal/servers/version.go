package servers

import (
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// Compatible reports whether an agent of version agent may serve a Hub
// of version hub (contract §17): the same major, and the agent's minor
// is the Hub's or the one before. Versions are semver with at least
// major.minor ("1.4", "v1.4.2", "1.4.0-rc.1"); anything else (empty,
// "edge", "dev", a bare major) is never compatible.
func Compatible(hub, agent string) bool {
	hm, hn, ok1 := majorMinor(hub)
	am, an, ok2 := majorMinor(agent)
	if !ok1 || !ok2 || hm != am {
		return false
	}
	return an == hn || an+1 == hn
}

func majorMinor(v string) (int, int, bool) {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return 0, 0, false
	}
	mm := strings.TrimPrefix(semver.MajorMinor(v), "v")
	// semver accepts "v1" as v1.0.0: a bare major is refused.
	core, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	core, _, _ = strings.Cut(core, "+")
	if !strings.Contains(core, ".") {
		return 0, 0, false
	}
	maj, min, _ := strings.Cut(mm, ".")
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	return a, b, err1 == nil && err2 == nil
}
