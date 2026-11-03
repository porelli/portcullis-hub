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
	// ReasonFailClosed: the rows couldn't be resolved safely (stale or
	// invalid rows under min or priority, duplicate group names). The value
	// is the option's most restrictive one; when there is none (string,
	// path, secret, table, single group/user, or a number with no safe
	// lower bound) Value is nil, which means "no value": consumers must
	// omit the setting for this person, never substitute the default.
	ReasonFailClosed = "fail-closed"
)

// Reason explains how the value was resolved: which group won, which rule
// was used, and which other groups lost (for the admin preview only).
type Reason struct {
	Source string      `json:"source"` // ReasonGroup | ReasonDefault | ReasonCombined | ReasonFailClosed
	Group  string      `json:"group,omitempty"`
	Groups []string    `json:"groups,omitempty"` // union/intersection/any/all
	Rule   string      `json:"rule"`
	Others []Candidate `json:"others,omitempty"` // losing rows (admin preview only)
}

// Resolved is the resolved value and the reason explaining how it was picked.
// Value nil with Reason.Source ReasonFailClosed is UNRESOLVED: there is no
// value for this person and consumers (deliveries) must omit it.
type Resolved struct {
	Value  Value
	Reason Reason
}

// unresolved is the UNRESOLVED result (see Resolved).
func unresolved(rule string, others []Candidate) Resolved {
	return Resolved{Value: nil, Reason: Reason{Source: ReasonFailClosed, Rule: rule, Others: others}}
}

// setItemParser is Task 4's item parser for a set-like option (multi_enum,
// list, groups, users): one item in, its canonical value out. nil = not a
// set-like type.
func (r *Registry) setItemParser(o *templates.Option) func(any) (Value, error) {
	switch o.Type {
	case templates.TypeMultiEnum:
		return func(it any) (Value, error) { return parseChoice(o.Choices, it) }
	case templates.TypeGroups, templates.TypeUsers:
		k := nameKind{user: o.Type == templates.TypeUsers, set: true}
		return func(it any) (Value, error) { return k.one(it) }
	case templates.TypeList:
		io := itemOption(o)
		k := listItemTypes[io.Type]
		if k == nil {
			return nil
		}
		return func(it any) (Value, error) { return k.Parse(io, it) }
	}
	return nil
}

// canonicalItems canonicalises one set row: each item goes through the
// item parser, items that fail (stale choices, invalid names, nested or
// wrongly typed values) are dropped, duplicates (by canonical key)
// collapse. The row's order is kept; no count bounds are applied
// (min_items/max_items are enforced when admins save rows). A row that
// isn't a list contributes no items.
func canonicalItems(parse func(any) (Value, error), raw Value) ([]Value, []string) {
	l, err := toList(raw)
	if err != nil || parse == nil {
		return nil, nil
	}
	var out []Value
	var keys []string
	seen := map[string]bool{}
	for _, it := range l {
		v, err := parse(it)
		if err != nil {
			continue
		}
		key := itemKey(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
		keys = append(keys, key)
	}
	return out, keys
}

// canonicalOrder applies the kind's canonical order to canonical items:
// option order (multi_enum), sorted (groups, users), as given (list:
// first-row order).
func canonicalOrder(o *templates.Option, items []Value) []Value {
	switch o.Type {
	case templates.TypeMultiEnum:
		in := map[string]bool{}
		for _, it := range items {
			in[it.(string)] = true
		}
		out := []Value{}
		for _, c := range o.Choices {
			if in[c.Value] {
				out = append(out, c.Value)
				in[c.Value] = false
			}
		}
		return out
	case templates.TypeGroups, templates.TypeUsers:
		out := append([]Value{}, items...)
		sort.Slice(out, func(i, j int) bool { return out[i].(string) < out[j].(string) })
		return out
	}
	if items == nil {
		return []Value{}
	}
	return items
}

// failClosedValue is the most restrictive value of o, used when rows can't
// be resolved safely. ok = false means UNRESOLVED (no safe value). enum:
// the lowest-ranked choice; bool: false; sets: empty; int/size/duration:
// the option's Min if set, else the default def — either only if it is a
// safeNumber; everything else: UNRESOLVED.
func (r *Registry) failClosedValue(o *templates.Option, def Value) (Value, bool) {
	switch o.Type {
	case templates.TypeEnum:
		if len(o.Choices) > 0 {
			return o.Choices[0].Value, true
		}
	case templates.TypeBool:
		return false, true
	case templates.TypeMultiEnum, templates.TypeList, templates.TypeGroups, templates.TypeUsers:
		return []Value{}, true
	case templates.TypeInt, templates.TypeSize, templates.TypeDuration:
		k, err := r.Kind(o.Type)
		if err != nil {
			return nil, false
		}
		bound := def
		if o.Min != nil {
			bound = o.Min
		}
		if bound == nil {
			return nil, false
		}
		return r.safeNumber(o, k, bound)
	}
	return nil, false
}

// safeNumber parses raw (a Min or a default) through k and accepts it only
// if it isn't Unlimited and every delivery with a render.unlimited renders
// it as something else (an app may read 0 or -1 as unlimited).
func (r *Registry) safeNumber(o *templates.Option, k Kind, raw any) (Value, bool) {
	v, err := k.Parse(o, raw)
	if err != nil || v == (Unlimited{}) {
		return nil, false
	}
	for i := range o.Delivery {
		d := &o.Delivery[i]
		rd := RenderOf(d)
		if rd == nil || rd.Unlimited == nil {
			continue
		}
		out, err := RenderDelivery(o, v, d)
		if err != nil || out.Text == *rd.Unlimited {
			return nil, false
		}
	}
	return v, true
}

// failClosed is the fail-closed result: failClosedValue, or UNRESOLVED.
func (r *Registry) failClosed(o *templates.Option, rule string, def Value, others []Candidate) Resolved {
	v, ok := r.failClosedValue(o, def)
	if !ok {
		return unresolved(rule, others)
	}
	return Resolved{Value: v, Reason: Reason{Source: ReasonFailClosed, Rule: rule, Others: others}}
}

// Resolve resolves one person option for person p using config c. The
// default is a fallback: it applies only to people in none of the row groups.
// A row whose group id mismatches p.Groups[row.Group] is skipped (call 29).
// Duplicate group names in c → fail-closed (invalid configuration).
// Matching row values are canonicalised through the option's kind before
// they are compared or combined; a nil Value is UNRESOLVED (see Resolved).
func (r *Registry) Resolve(o *templates.Option, c PersonConfig, p Person) Resolved {
	rule := c.Rule
	if rule == "" {
		rule = o.Resolve
	}

	// Duplicate group names: invalid configuration, fail closed (a stale-id
	// row must never shadow or add to the current one).
	seen := map[string]bool{}
	for _, row := range c.Rows {
		if seen[row.Group] {
			return r.failClosed(o, rule, c.Default, nil)
		}
		seen[row.Group] = true
	}

	var matches []Candidate
	for _, row := range c.Rows {
		if gid, ok := p.Groups[row.Group]; ok && gid == row.GroupID {
			matches = append(matches, Candidate{Group: row.Group, Value: row.Value})
		}
	}
	if len(matches) == 0 {
		return Resolved{Value: c.Default, Reason: Reason{Source: ReasonDefault, Rule: rule}}
	}

	switch rule {
	case templates.ResolveMax, templates.ResolveMin:
		return r.resolveMaxMin(o, rule, matches, c.Default)
	case templates.ResolvePriority:
		return r.resolvePriority(o, rule, matches, c.Default)
	case templates.ResolveUnion:
		return r.resolveUnion(o, rule, matches)
	case templates.ResolveIntersection:
		return r.resolveIntersection(o, rule, matches)
	case templates.ResolveAny, templates.ResolveAll:
		return r.resolveAnyAll(o, rule, matches)
	}
	// Unknown rule (the validator refuses it): fail closed.
	return r.failClosed(o, rule, c.Default, matches)
}

// canonical parses v through o's kind; ok = false for a stale or invalid
// value. Set kinds are canonicalised item by item with no count bounds,
// as under union/intersection (a non-list is invalid).
func (r *Registry) canonical(o *templates.Option, v Value) (Value, bool) {
	if parse := r.setItemParser(o); parse != nil {
		if _, err := toList(v); err != nil {
			return nil, false
		}
		items, _ := canonicalItems(parse, v)
		return canonicalOrder(o, items), true
	}
	k, err := r.Kind(o.Type)
	if err != nil {
		return nil, false
	}
	cv, err := k.Parse(o, v)
	if err != nil {
		return nil, false
	}
	return cv, true
}

// resolveMaxMin resolves max or min on canonical values; ties go to the
// earlier row. Rows that don't parse or aren't ordered are stale: under max
// they're dropped; under min enum/bool fail closed, int/size/duration drop
// them and take the min of the rest (fail closed if none is left). Stale
// rows are listed in Others.
func (r *Registry) resolveMaxMin(o *templates.Option, rule string, matches []Candidate, def Value) Resolved {
	k, err := r.Kind(o.Type)
	if err != nil {
		return r.failClosed(o, rule, def, matches)
	}

	var good, stale []Candidate
	for _, m := range matches {
		if cv, ok := r.canonical(o, m.Value); ok {
			if _, ok := k.Compare(o, cv, cv); ok {
				good = append(good, Candidate{Group: m.Group, Value: cv})
				continue
			}
		}
		stale = append(stale, m)
	}

	if rule == templates.ResolveMin && len(stale) > 0 &&
		(o.Type == templates.TypeEnum || o.Type == templates.TypeBool) {
		return r.failClosed(o, rule, def, append(append([]Candidate{}, good...), stale...))
	}
	if len(good) == 0 {
		if rule == templates.ResolveMin {
			return r.failClosed(o, rule, def, stale)
		}
		return Resolved{Value: def, Reason: Reason{Source: ReasonDefault, Rule: rule, Others: stale}}
	}

	best := good[0]
	var others []Candidate
	for _, cand := range good[1:] {
		cmp, _ := k.Compare(o, best.Value, cand.Value)
		if (rule == templates.ResolveMax && cmp < 0) || (rule == templates.ResolveMin && cmp > 0) {
			others = append(others, best)
			best = cand
		} else {
			others = append(others, cand)
		}
	}
	others = append(others, stale...)

	return Resolved{
		Value:  best.Value,
		Reason: Reason{Source: ReasonGroup, Group: best.Group, Rule: rule, Others: others},
	}
}

// resolvePriority picks the first match (admin's row order). A first match
// that doesn't parse fails closed: falling through to a later row could
// hand out a less restrictive value.
func (r *Registry) resolvePriority(o *templates.Option, rule string, matches []Candidate, def Value) Resolved {
	var others []Candidate
	if len(matches) > 1 {
		others = matches[1:]
	}
	cv, ok := r.canonical(o, matches[0].Value)
	if !ok {
		return r.failClosed(o, rule, def, matches)
	}
	return Resolved{
		Value:  cv,
		Reason: Reason{Source: ReasonGroup, Group: matches[0].Group, Rule: rule, Others: others},
	}
}

// contributing is the sorted names of the matching rows.
func contributing(matches []Candidate) []string {
	groups := make([]string, len(matches))
	for i, m := range matches {
		groups[i] = m.Group
	}
	sort.Strings(groups)
	return groups
}

// resolveUnion is the union of the matching rows' canonical items, in the
// kind's canonical order.
func (r *Registry) resolveUnion(o *templates.Option, rule string, matches []Candidate) Resolved {
	parse := r.setItemParser(o)
	seen := map[string]bool{}
	var result []Value
	for _, m := range matches {
		items, keys := canonicalItems(parse, m.Value)
		for i, it := range items {
			if !seen[keys[i]] {
				seen[keys[i]] = true
				result = append(result, it)
			}
		}
	}
	return Resolved{
		Value:  canonicalOrder(o, result),
		Reason: Reason{Source: ReasonCombined, Groups: contributing(matches), Rule: rule},
	}
}

// resolveIntersection is the intersection of the matching rows' canonical
// items: the first row's items (first-row order) present in every row, then
// the kind's canonical order.
func (r *Registry) resolveIntersection(o *templates.Option, rule string, matches []Candidate) Resolved {
	parse := r.setItemParser(o)
	first, firstKeys := canonicalItems(parse, matches[0].Value)
	sets := make([]map[string]bool, len(matches)-1)
	for i, m := range matches[1:] {
		_, keys := canonicalItems(parse, m.Value)
		sets[i] = make(map[string]bool, len(keys))
		for _, k := range keys {
			sets[i][k] = true
		}
	}
	var result []Value
	for i, it := range first {
		inAll := true
		for _, s := range sets {
			if !s[firstKeys[i]] {
				inAll = false
				break
			}
		}
		if inAll {
			result = append(result, it)
		}
	}
	return Resolved{
		Value:  canonicalOrder(o, result),
		Reason: Reason{Source: ReasonCombined, Groups: contributing(matches), Rule: rule},
	}
}

// resolveAnyAll: any = true if some row is true; all = true only if every
// row is true. A row that doesn't parse as a bool counts as false.
func (r *Registry) resolveAnyAll(o *templates.Option, rule string, matches []Candidate) Resolved {
	result := rule == templates.ResolveAll
	for _, m := range matches {
		cv, ok := r.canonical(o, m.Value)
		b := ok && cv == true
		if rule == templates.ResolveAny && b {
			result = true
			break
		}
		if rule == templates.ResolveAll && !b {
			result = false
			break
		}
	}
	return Resolved{
		Value:  result,
		Reason: Reason{Source: ReasonCombined, Groups: contributing(matches), Rule: rule},
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
