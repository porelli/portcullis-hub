package settings

import (
	"sort"
	"strings"

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
	ReasonGroup      = "group"
	ReasonDefault    = "default"
	ReasonCombined   = "combined"
	ReasonFailClosed = "fail-closed" // Stale rows under min, or duplicate group names
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

// canonicalizeSet canonicalizes a set result (multi_enum, list, groups, users):
// validates items with item-level parsers (NO count checks), drops stale items,
// applies the kind's canonical order. min_items/max_items are NOT applied
// (they're enforced when admins save rows, not at resolution).
func (r *Registry) canonicalizeSet(o *templates.Option, items []any) []any {
	if len(items) == 0 {
		return []any{}
	}

	var valid []any

	switch o.Type {
	case templates.TypeMultiEnum:
		// Validate against Choices (no Parse call, no countItems)
		choiceSet := make(map[string]bool, len(o.Choices))
		for _, c := range o.Choices {
			choiceSet[c.Value] = true
		}
		// Option order: iterate Choices and collect matching items
		for _, c := range o.Choices {
			for _, item := range items {
				if s, ok := item.(string); ok && s == c.Value {
					valid = append(valid, s)
					break // Only add once per choice
				}
			}
		}

	case templates.TypeGroups, templates.TypeUsers:
		// Validate as names (lowercase, no @), then sort
		seen := map[string]bool{}
		for _, item := range items {
			s, ok := item.(string)
			if !ok || s == "" {
				continue
			}
			if o.Type == templates.TypeUsers {
				// Users: lowercase, no @
				if strings.ContainsRune(s, '@') {
					continue
				}
				s = strings.ToLower(s)
			}
			// Groups/users: valid name
			if !seen[s] {
				valid = append(valid, s)
				seen[s] = true
			}
		}
		// Sort for canonical order
		sort.Slice(valid, func(i, j int) bool {
			return valid[i].(string) < valid[j].(string)
		})

	case templates.TypeList:
		// Validate each item with the list's item kind (no countItems)
		if o.Items == nil {
			return []any{}
		}
		// Build a temporary option for the item type
		itemOpt := &templates.Option{Type: o.Items.Type}
		// Copy item-level constraints
		if o.Items.Pattern != "" {
			itemOpt.Pattern = o.Items.Pattern
		}
		if o.Items.Format != "" {
			itemOpt.Format = o.Items.Format
		}
		if o.Items.MinLen != nil {
			itemOpt.MinLen = o.Items.MinLen
		}
		if o.Items.MaxLen != nil {
			itemOpt.MaxLen = o.Items.MaxLen
		}
		if o.Items.Min != nil {
			itemOpt.Min = o.Items.Min
		}
		if o.Items.Max != nil {
			itemOpt.Max = o.Items.Max
		}
		if len(o.Items.Choices) > 0 {
			itemOpt.Choices = o.Items.Choices
		}

		itemKind, err := r.Kind(itemOpt.Type)
		if err != nil {
			return []any{}
		}

		// Parse each item individually
		seen := map[any]bool{}
		for _, item := range items {
			if parsed, err := itemKind.Parse(itemOpt, item); err == nil {
				// Dedupe
				if !seen[parsed] {
					valid = append(valid, parsed)
					seen[parsed] = true
				}
			}
		}
		// First-row order (already in order from iteration)

	default:
		return []any{}
	}

	return valid
}

// failClosedValue returns the fail-closed value for an option when stale rows
// exist under min or duplicate group names are found. For enum: first choice.
// For bool: false. For int/size/duration: lower bound (Min, else 0) - never
// Unlimited, never the default. For sets: empty []any{}.
func failClosedValue(o *templates.Option) Value {
	switch o.Type {
	case templates.TypeEnum:
		if len(o.Choices) > 0 {
			return o.Choices[0].Value
		}
		return ""
	case templates.TypeBool:
		return false
	case templates.TypeInt, templates.TypeSize, templates.TypeDuration:
		// Lower bound: option's Min if set, else 0
		if o.Min != nil {
			// Parse Min (can be "10GiB" for size, "30d" for duration, or int)
			r := NewRegistry()
			if k, err := r.Kind(o.Type); err == nil {
				if minVal, err := k.Parse(o, o.Min); err == nil {
					return minVal
				}
			}
		}
		return int64(0)
	case templates.TypeMultiEnum, templates.TypeList, templates.TypeGroups, templates.TypeUsers:
		return []any{}
	default:
		return nil
	}
}

// Resolve resolves one person option for person p using config c. The
// default is a fallback: it applies only to people in none of the row groups.
// A row whose group id mismatches p.Groups[row.Group] is skipped (call 29).
// Duplicate group names in config → fail-closed (invalid configuration).
func (r *Registry) Resolve(o *templates.Option, c PersonConfig, p Person) Resolved {
	rule := c.Rule
	if rule == "" {
		rule = o.Resolve
	}

	// Detect duplicate group names (invalid configuration)
	seen := map[string]bool{}
	var duplicates []string
	for _, row := range c.Rows {
		if seen[row.Group] {
			duplicates = append(duplicates, row.Group)
		}
		seen[row.Group] = true
	}

	// Duplicate group names → fail-closed
	if len(duplicates) > 0 {
		return Resolved{
			Value: failClosedValue(o),
			Reason: Reason{
				Source: ReasonFailClosed,
				Rule:   rule,
				// Note: duplicates in a comment would be helpful but Reason has no comment field
			},
		}
	}

	// Find matching rows (rows whose group the person is in, and whose id matches)
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
		return r.resolveUnion(o, matches, rule)
	case templates.ResolveIntersection:
		return r.resolveIntersection(o, matches, rule)
	case templates.ResolveAny:
		return resolveAny(matches, rule)
	case templates.ResolveAll:
		return resolveAll(matches, rule)
	}

	// Unreachable (validator ensures rule is valid)
	return Resolved{Value: c.Default, Reason: Reason{Source: ReasonDefault, Rule: rule}}
}

// resolveMaxMin resolves max or min by comparing values. Under min with stale rows:
// enum/bool fail closed to lowest-ranked choice; int/size/duration drop stale and
// take min of comparable (or lower bound if none comparable). Under max: stale rows
// are dropped.
func (r *Registry) resolveMaxMin(o *templates.Option, rule string, matches []Candidate, def Value) Resolved {
	k, err := r.Kind(o.Type)
	if err != nil {
		// Shouldn't happen
		return Resolved{Value: def, Reason: Reason{Source: ReasonDefault, Rule: rule}}
	}

	// Separate comparable and incomparable (stale) rows
	var comparable, stale []Candidate
	for _, m := range matches {
		if _, ok := k.Compare(o, m.Value, m.Value); ok {
			comparable = append(comparable, m)
		} else {
			stale = append(stale, m)
		}
	}

	// Under min with stale rows: fail closed behavior depends on type
	if rule == templates.ResolveMin && len(stale) > 0 {
		// For enum/bool: fail closed to lowest-ranked choice
		if o.Type == templates.TypeEnum || o.Type == templates.TypeBool {
			allRows := append([]Candidate{}, comparable...)
			allRows = append(allRows, stale...)
			return Resolved{
				Value: failClosedValue(o),
				Reason: Reason{
					Source: ReasonFailClosed,
					Rule:   rule,
					Others: allRows,
				},
			}
		}
		// For int/size/duration: drop stale, continue with comparable, but keep stale in Others
		// (if none comparable, fall through to handle below)
	}

	// Track stale for Others
	staleForOthers := stale

	// No comparable matches → fail closed for int/size/duration under min, default otherwise
	if len(comparable) == 0 {
		if rule == templates.ResolveMin && (o.Type == templates.TypeInt || o.Type == templates.TypeSize || o.Type == templates.TypeDuration) {
			// Lower bound, not default
			return Resolved{
				Value: failClosedValue(o),
				Reason: Reason{
					Source: ReasonFailClosed,
					Rule:   rule,
					Others: stale,
				},
			}
		}
		return Resolved{
			Value: def,
			Reason: Reason{
				Source: ReasonDefault,
				Rule:   rule,
				Others: stale,
			},
		}
	}

	best := comparable[0]
	var others []Candidate

	for i := 1; i < len(comparable); i++ {
		cand := comparable[i]
		cmp, ok := k.Compare(o, best.Value, cand.Value)
		if !ok {
			// Type not comparable (shouldn't happen after filtering)
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

	// Under max: stale rows are dropped but shown in Others
	// Under min with numeric types: stale rows also shown in Others
	if rule == templates.ResolveMax || (rule == templates.ResolveMin && len(staleForOthers) > 0) {
		others = append(others, staleForOthers...)
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

// resolveUnion computes the union of all matching sets. Canonicalizes item by
// item (drops stale choices) and applies the kind's canonical order.
func (r *Registry) resolveUnion(o *templates.Option, matches []Candidate, rule string) Resolved {
	seen := map[any]bool{}
	var result []any

	for _, m := range matches {
		list, ok := m.Value.([]any)
		if !ok {
			// Treat non-list as empty set
			continue
		}
		for _, item := range list {
			if !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
	}

	// Canonicalize: parse item by item, apply canonical order
	result = r.canonicalizeSet(o, result)

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
// Builds intersection by iterating first row's list (first-row order, deterministic).
// Canonicalizes item by item (drops stale choices).
func (r *Registry) resolveIntersection(o *templates.Option, matches []Candidate, rule string) Resolved {
	// Get first row's list (for deterministic order)
	var firstList []any
	if len(matches) > 0 {
		if list, ok := matches[0].Value.([]any); ok {
			firstList = list
		}
	}

	// Empty first list or non-list → empty intersection
	if len(firstList) == 0 {
		groups := make([]string, len(matches))
		for i, m := range matches {
			groups[i] = m.Group
		}
		sort.Strings(groups)
		return Resolved{
			Value: []any{},
			Reason: Reason{
				Source: ReasonCombined,
				Groups: groups,
				Rule:   rule,
			},
		}
	}

	// Build sets for all other rows (for efficient lookup)
	otherSets := make([]map[any]bool, len(matches))
	for i, m := range matches {
		otherSets[i] = map[any]bool{}
		list, ok := m.Value.([]any)
		if !ok {
			// Non-list treated as empty set
			continue
		}
		for _, item := range list {
			otherSets[i][item] = true
		}
	}

	// Iterate first row's list (first-row order, deterministic)
	var result []any
	for _, item := range firstList {
		inAll := true
		for i := 0; i < len(matches); i++ {
			if !otherSets[i][item] {
				inAll = false
				break
			}
		}
		if inAll {
			result = append(result, item)
		}
	}

	// Canonicalize: validate items, NO count checks (list keeps first-row order)
	result = r.canonicalizeSet(o, result)

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
