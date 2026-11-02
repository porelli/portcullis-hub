package settings

import (
	"sort"

	"github.com/portcullis/hub/internal/templates"
)

// Row is one per-group value for a person option: the group name, its LLDAP
// id and the value.
type Row struct {
	Group   string
	GroupID int
	Value   Value
}

// PersonConfig is the admin's configuration for resolving one person option:
// the default (fallback for people in no row group), the resolve rule (""
// means o.Resolve), and zero or more per-group rows in the admin's order.
type PersonConfig struct {
	Default Value
	Rule    string // "" = o.Resolve
	Rows    []Row
}

// Candidate is one group-value pair (a row that matched or lost).
type Candidate struct {
	Group string `json:"group"`
	Value Value  `json:"value"`
}

// Reason sources.
const (
	ReasonGroup    = "group"
	ReasonDefault  = "default"
	ReasonCombined = "combined"
)

// Reason explains how the value was resolved: which group won, which rule
// was used, and which other groups lost (for the admin preview only).
type Reason struct {
	Source string      `json:"source"` // ReasonGroup | ReasonDefault | ReasonCombined
	Group  string      `json:"group,omitempty"`
	Groups []string    `json:"groups,omitempty"` // union/intersection/any/all
	Rule   string      `json:"rule"`
	Others []Candidate `json:"others,omitempty"` // losing rows (admin preview only)
}

// Resolved is the resolved value and the reason explaining how it was picked.
type Resolved struct {
	Value  Value
	Reason Reason
}

// Resolve resolves one person option for person p using config c. The
// default is a fallback: it applies only to people in none of the row groups.
// A row whose group id mismatches p.Groups[row.Group] is skipped (call 29).
func (r *Registry) Resolve(o *templates.Option, c PersonConfig, p Person) Resolved {
	rule := c.Rule
	if rule == "" {
		rule = o.Resolve
	}

	// Find matching rows (rows whose group the person is in, and whose id
	// matches).
	var matches []Candidate
	for _, row := range c.Rows {
		if gid, ok := p.Groups[row.Group]; ok && gid == row.GroupID {
			matches = append(matches, Candidate{Group: row.Group, Value: row.Value})
		}
	}

	// No matches → default
	if len(matches) == 0 {
		return Resolved{
			Value: c.Default,
			Reason: Reason{
				Source: ReasonDefault,
				Rule:   rule,
			},
		}
	}

	// Resolve
	switch rule {
	case templates.ResolveMax, templates.ResolveMin:
		return r.resolveMaxMin(o, rule, matches, c.Default)
	case templates.ResolvePriority:
		return resolvePriority(matches, rule)
	case templates.ResolveUnion:
		return resolveUnion(matches, rule)
	case templates.ResolveIntersection:
		return resolveIntersection(matches, rule)
	case templates.ResolveAny:
		return resolveAny(matches, rule)
	case templates.ResolveAll:
		return resolveAll(matches, rule)
	default:
		// Shouldn't happen (validator checks this)
		return Resolved{
			Value: c.Default,
			Reason: Reason{
				Source: ReasonDefault,
				Rule:   rule,
			},
		}
	}
}

// resolveMaxMin resolves max or min by comparing values.
func (r *Registry) resolveMaxMin(o *templates.Option, rule string, matches []Candidate, def Value) Resolved {
	if len(matches) == 0 {
		return Resolved{
			Value: def,
			Reason: Reason{
				Source: ReasonDefault,
				Rule:   rule,
			},
		}
	}

	k, err := r.Kind(o.Type)
	if err != nil {
		// Shouldn't happen
		return Resolved{Value: def, Reason: Reason{Source: ReasonDefault, Rule: rule}}
	}

	best := matches[0]
	var others []Candidate

	for i := 1; i < len(matches); i++ {
		cand := matches[i]
		cmp, ok := k.Compare(o, best.Value, cand.Value)
		if !ok {
			// Type not comparable (shouldn't happen)
			continue
		}

		// For unlimited under max: unlimited beats any number
		// For unlimited under min: any number beats unlimited
		_, bestUnlimited := best.Value.(Unlimited)
		_, candUnlimited := cand.Value.(Unlimited)

		if rule == templates.ResolveMax {
			// Max: higher wins, ties to earlier
			// unlimited beats any number
			if candUnlimited && !bestUnlimited {
				others = append(others, best)
				best = cand
			} else if !candUnlimited && bestUnlimited {
				others = append(others, cand)
			} else if cmp < 0 {
				// cand > best
				others = append(others, best)
				best = cand
			} else {
				others = append(others, cand)
			}
		} else {
			// Min: lower wins, ties to earlier
			// any number beats unlimited
			if candUnlimited && !bestUnlimited {
				others = append(others, cand)
			} else if !candUnlimited && bestUnlimited {
				others = append(others, best)
				best = cand
			} else if cmp > 0 {
				// cand < best
				others = append(others, best)
				best = cand
			} else {
				others = append(others, cand)
			}
		}
	}

	return Resolved{
		Value: best.Value,
		Reason: Reason{
			Source: ReasonGroup,
			Group:  best.Group,
			Rule:   rule,
			Others: others,
		},
	}
}

// resolvePriority picks the first match (admin's row order).
func resolvePriority(matches []Candidate, rule string) Resolved {
	if len(matches) == 0 {
		// Shouldn't happen
		return Resolved{}
	}

	best := matches[0]
	var others []Candidate
	if len(matches) > 1 {
		others = matches[1:]
	}

	return Resolved{
		Value: best.Value,
		Reason: Reason{
			Source: ReasonGroup,
			Group:  best.Group,
			Rule:   rule,
			Others: others,
		},
	}
}

// resolveUnion computes the union of all matching sets.
func resolveUnion(matches []Candidate, rule string) Resolved {
	seen := map[any]bool{}
	var result []any

	for _, m := range matches {
		list, ok := m.Value.([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			if !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
	}

	groups := make([]string, len(matches))
	for i, m := range matches {
		groups[i] = m.Group
	}
	sort.Strings(groups)

	return Resolved{
		Value: result,
		Reason: Reason{
			Source: ReasonCombined,
			Groups: groups,
			Rule:   rule,
		},
	}
}

// resolveIntersection computes the intersection of all matching sets.
func resolveIntersection(matches []Candidate, rule string) Resolved {
	if len(matches) == 0 {
		return Resolved{Value: []any{}}
	}

	// Start with the first set
	first, ok := matches[0].Value.([]any)
	if !ok {
		return Resolved{Value: []any{}}
	}

	counts := map[any]int{}
	for _, item := range first {
		counts[item]++
	}

	// Count occurrences in other sets
	for i := 1; i < len(matches); i++ {
		list, ok := matches[i].Value.([]any)
		if !ok {
			continue
		}
		seen := map[any]bool{}
		for _, item := range list {
			if _, exists := counts[item]; exists && !seen[item] {
				counts[item]++
				seen[item] = true
			}
		}
	}

	// Keep only items present in all sets
	var result []any
	for _, item := range first {
		if counts[item] == len(matches) {
			result = append(result, item)
			// Mark as added to avoid duplicates
			counts[item] = -1
		}
	}

	groups := make([]string, len(matches))
	for i, m := range matches {
		groups[i] = m.Group
	}
	sort.Strings(groups)

	return Resolved{
		Value: result,
		Reason: Reason{
			Source: ReasonCombined,
			Groups: groups,
			Rule:   rule,
		},
	}
}

// resolveAny returns true if any match is true.
func resolveAny(matches []Candidate, rule string) Resolved {
	result := false
	for _, m := range matches {
		if b, ok := m.Value.(bool); ok && b {
			result = true
			break
		}
	}

	groups := make([]string, len(matches))
	for i, m := range matches {
		groups[i] = m.Group
	}
	sort.Strings(groups)

	return Resolved{
		Value: result,
		Reason: Reason{
			Source: ReasonCombined,
			Groups: groups,
			Rule:   rule,
		},
	}
}

// resolveAll returns true only if all matches are true.
func resolveAll(matches []Candidate, rule string) Resolved {
	result := true
	for _, m := range matches {
		b, ok := m.Value.(bool)
		if !ok || !b {
			result = false
			break
		}
	}

	groups := make([]string, len(matches))
	for i, m := range matches {
		groups[i] = m.Group
	}
	sort.Strings(groups)

	return Resolved{
		Value: result,
		Reason: Reason{
			Source: ReasonCombined,
			Groups: groups,
			Rule:   rule,
		},
	}
}

// ResolveAll resolves o for every person in people, returning a map of
// lowercase username → Resolved.
func (r *Registry) ResolveAll(o *templates.Option, c PersonConfig, people []Person) map[string]Resolved {
	out := make(map[string]Resolved, len(people))
	for _, p := range people {
		out[p.User] = r.Resolve(o, c, p)
	}
	return out
}
