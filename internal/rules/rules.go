package rules

import (
	"sort"
	"strings"
)

// Op represents an operation in a rule expression
type Op string

const (
	OpAll       Op = "all"
	OpAny       Op = "any"
	OpIs        Op = "is"
	OpIsNot     Op = "is_not"
	OpIn        Op = "in"
	OpEmpty     Op = "empty"
	OpReportsTo Op = "reports_to"
)

// Expr is a rule expression node
type Expr struct {
	Op     Op       `json:"op"`
	Field  string   `json:"field,omitempty"`
	Values []string `json:"values,omitempty"` // is/is_not: 1; in: >=1; reports_to: 1 username
	Not    bool     `json:"not,omitempty"`    // negates the node
	Items  []*Expr  `json:"items,omitempty"`  // all/any
}

// Person represents a person in the directory
type Person struct {
	User  string              // username
	Attrs map[string][]string // attributes with lowercase keys
}

// Directory represents the directory of people
type Directory struct {
	People       map[string]Person // keyed by username
	ManagerField string            // field name for manager; "" = no reports_to
}

// Format returns the canonical text representation of an expression
func Format(e *Expr) string {
	return formatExpr(e, false)
}

func formatExpr(e *Expr, inAnd bool) string {
	var result string

	switch e.Op {
	case OpAll: // and
		var parts []string
		for _, item := range e.Items {
			parts = append(parts, formatExpr(item, true))
		}
		result = joinWithSep(parts, " and ")

	case OpAny: // or
		var parts []string
		for _, item := range e.Items {
			parts = append(parts, formatExpr(item, false))
		}
		result = joinWithSep(parts, " or ")
		// Put parens around or inside and
		if inAnd {
			result = "(" + result + ")"
		}

	case OpIs:
		result = e.Field + " = " + quoteString(e.Values[0])

	case OpIsNot:
		result = e.Field + " != " + quoteString(e.Values[0])

	case OpIn:
		var quoted []string
		for _, v := range e.Values {
			quoted = append(quoted, quoteString(v))
		}
		result = e.Field + " in (" + joinWithSep(quoted, ", ") + ")"

	case OpEmpty:
		result = e.Field + " is empty"

	case OpReportsTo:
		result = e.Field + " reports-to " + quoteString(e.Values[0])
	}

	if e.Not {
		// Wrap compound expressions in parens when negating
		if e.Op == OpAll || e.Op == OpAny {
			result = "not (" + result + ")"
		} else {
			result = "not " + result
		}
	}

	return result
}

func quoteString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, ch := range s {
		if ch == '"' {
			sb.WriteString(`\"`)
		} else if ch == '\\' {
			sb.WriteString(`\\`)
		} else {
			sb.WriteRune(ch)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func joinWithSep(parts []string, sep string) string {
	var sb strings.Builder
	for i, part := range parts {
		if i > 0 {
			sb.WriteString(sep)
		}
		sb.WriteString(part)
	}
	return sb.String()
}

// Eval evaluates an expression against a user in the directory
func Eval(e *Expr, user string, d *Directory) bool {
	result := evalExpr(e, user, d)
	if e.Not {
		return !result
	}
	return result
}

func evalExpr(e *Expr, user string, d *Directory) bool {
	person, exists := d.People[user]
	if !exists {
		return false
	}

	switch e.Op {
	case OpAll:
		for _, item := range e.Items {
			if !Eval(item, user, d) {
				return false
			}
		}
		return true

	case OpAny:
		for _, item := range e.Items {
			if Eval(item, user, d) {
				return true
			}
		}
		return false

	case OpIs:
		values := person.Attrs[e.Field]
		for _, v := range values {
			if strings.EqualFold(v, e.Values[0]) {
				return true
			}
		}
		return false

	case OpIsNot:
		values := person.Attrs[e.Field]
		for _, v := range values {
			if strings.EqualFold(v, e.Values[0]) {
				return false
			}
		}
		return true

	case OpIn:
		values := person.Attrs[e.Field]
		for _, v := range values {
			for _, target := range e.Values {
				if strings.EqualFold(v, target) {
					return true
				}
			}
		}
		return false

	case OpEmpty:
		values := person.Attrs[e.Field]
		return len(values) == 0

	case OpReportsTo:
		if d.ManagerField == "" {
			return false
		}
		target := e.Values[0]
		// Start from user's manager
		managers := person.Attrs[d.ManagerField]
		if len(managers) == 0 {
			return false
		}
		current := managers[0]
		visited := make(map[string]bool)
		steps := 0
		maxSteps := len(d.People)

		// Walk up the manager chain (starting from manager's manager)
		// Direct manager doesn't count as reports-to
		for steps < maxSteps {
			if visited[current] {
				// Cycle detected, stop
				break
			}
			visited[current] = true

			// Move to next manager first (skip direct manager)
			if p, ok := d.People[current]; ok {
				nextManagers := p.Attrs[d.ManagerField]
				if len(nextManagers) == 0 {
					break
				}
				current = nextManagers[0]
			} else {
				break
			}

			// Now check if we reached the target (indirect manager)
			if strings.EqualFold(current, target) {
				return true
			}

			steps++
		}
		return false

	default:
		return false
	}
}

// Fields returns all field names referenced in the expression, sorted and unique
func Fields(e *Expr) []string {
	seen := make(map[string]bool)
	collectFields(e, seen)
	var result []string
	for field := range seen {
		result = append(result, field)
	}
	sort.Strings(result)
	return result
}

func collectFields(e *Expr, seen map[string]bool) {
	if e.Field != "" {
		seen[e.Field] = true
	}
	for _, item := range e.Items {
		collectFields(item, seen)
	}
}

// Cycles detects manager cycles in the directory
func Cycles(d *Directory) [][]string {
	if d.ManagerField == "" {
		return nil
	}

	var cycles [][]string
	visited := make(map[string]bool)

	for user := range d.People {
		if visited[user] {
			continue
		}

		// Walk from this user
		path := make(map[string]int)
		current := user
		index := 0

		for {
			if visited[current] {
				break
			}

			if pos, inPath := path[current]; inPath {
				// Found a cycle
				cycle := []string{}
				for u, p := range path {
					if p >= pos {
						cycle = append(cycle, u)
					}
				}
				sort.Strings(cycle)
				cycles = append(cycles, cycle)

				// Mark all in cycle as visited
				for u, p := range path {
					if p >= pos {
						visited[u] = true
					}
				}
				break
			}

			path[current] = index
			index++

			// Get manager
			person, exists := d.People[current]
			if !exists {
				break
			}
			managers := person.Attrs[d.ManagerField]
			if len(managers) == 0 {
				// No manager, mark path as visited
				for u := range path {
					visited[u] = true
				}
				break
			}

			current = managers[0]
		}
	}

	return cycles
}
