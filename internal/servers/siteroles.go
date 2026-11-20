package servers

import (
	"fmt"
	"sort"
)

// The role of a new cluster node (contract §20.1, §20.11; vectors
// site_roles_vectors.json, byte-copied to core nodeadm/testdata/).
// Rulings: at most 5 servers (beyond that new nodes are agents); one site:
// a server while fewer than 3 healthy servers exist; two sites: servers
// only at the primary site main (and the tie-breaker warning); three or
// more: a server goes where no site holds a majority of the servers
// afterwards — while main holds a majority, only at the site with the
// fewest servers (ties by name). An even server count warns.

// PrimarySite is the site sign-in and the data stay at.
const PrimarySite = "main"

// MaxServers is the most servers ever suggested.
const MaxServers = 5

// The texts of the role suggestion (site_roles_vectors.json).
const (
	WarnEvenServers = "an even number of servers doesn't add failure tolerance"
	WarnTieBreaker  = "Only main can survive on its own: add a tie-breaker at a third location (a small cloud VM or a Pi elsewhere)."
	WarnNoSite      = "no site can take another server without holding a majority of them: this node joins as an agent."
)

// ClusterNode is one node the suggestion counts.
type ClusterNode struct {
	ID, Site, Role string
	Healthy        bool
}

// NewNode is the joining node: its site, its mesh round trips to the
// servers (nil: not measured yet, no RTT check) and the admin's role
// override ("" = the suggestion).
type NewNode struct {
	Site     string
	RTTms    map[string]int
	Override string
}

// SuggestRole is the new node's role and the warnings to show; err is a
// refusal (the RTT limits) when RTTms is given.
func SuggestRole(cluster []ClusterNode, n NewNode) (role string, warnings []string, err error) {
	warnings = []string{}
	site := n.Site
	if site == "" {
		site = PrimarySite
	}
	perSite := map[string]int{}
	sites := map[string]bool{site: true}
	total, healthy := 0, 0
	for _, c := range cluster {
		sites[c.Site] = true
		if c.Role == "server" {
			total++
			perSite[c.Site]++
			if c.Healthy {
				healthy++
			}
		}
	}
	names := make([]string, 0, len(sites))
	for s := range sites {
		names = append(names, s)
	}
	sort.Strings(names)
	majority := func(count, of int) bool { return 2*count > of }

	role = "agent"
	switch {
	case len(sites) == 1:
		if total < MaxServers && healthy < 3 {
			role = "server"
		}
	case len(sites) == 2:
		warnings = append(warnings, WarnTieBreaker)
		if total < MaxServers && site == PrimarySite && healthy < 3 {
			role = "server"
		}
	default:
		if total >= MaxServers {
			break
		}
		// takes: a server at s leaves no site with a majority.
		takes := func(s string) bool {
			for _, o := range names {
				c := perSite[o]
				if o == s {
					c++
				}
				if majority(c, total+1) {
					return false
				}
			}
			return true
		}
		if majority(perSite[PrimarySite], total) {
			fewest := ""
			for _, s := range names {
				if s != PrimarySite && (fewest == "" || perSite[s] < perSite[fewest]) {
					fewest = s
				}
			}
			if site == fewest {
				role = "server"
			} else if fewest != "" {
				warnings = append(warnings, fmt.Sprintf("main holds a majority of the servers: add the next server at %s.", fewest))
			}
			break
		}
		if takes(site) {
			role = "server"
			break
		}
		any := false
		for _, s := range names {
			any = any || takes(s)
		}
		if !any {
			warnings = append(warnings, WarnNoSite)
		}
	}
	if n.Override != "" {
		role = n.Override
	}
	if role == "server" && total+1 >= 4 && (total+1)%2 == 0 { // 2 servers are the way to 3
		warnings = append(warnings, WarnEvenServers)
	}
	if n.RTTms != nil {
		var hs []string
		for _, c := range cluster {
			if c.Role == "server" && c.Healthy {
				hs = append(hs, c.ID)
			}
		}
		w, err := CheckRTT(role, hs, n.RTTms)
		if err != nil {
			return "", nil, err
		}
		warnings = append(warnings, w...)
	}
	return role, warnings, nil
}

// CheckRTT: every healthy server answered, a server within 100 ms of
// each, an agent within 250 ms; 80 % of the limit or more warns.
func CheckRTT(role string, servers []string, rtt map[string]int) (warnings []string, err error) {
	limit := 250
	what := "agents"
	if role == "server" {
		limit, what = 100, "servers"
	}
	sort.Strings(servers)
	worst := -1
	for _, s := range servers {
		v, ok := rtt[s]
		if !ok {
			return nil, fmt.Errorf("no mesh answer from %s: the node can't join", s)
		}
		worst = max(worst, v)
	}
	if worst > limit {
		return nil, fmt.Errorf("too far for one cluster: %d ms (%s need %d ms or less)", worst, what, limit)
	}
	for _, s := range servers {
		if v := rtt[s]; v*5 >= limit*4 {
			warnings = append(warnings, fmt.Sprintf("mesh round trip to %s is %d ms: near the %d ms limit", s, v, limit))
		}
	}
	return warnings, nil
}
