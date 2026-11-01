package rules

import (
	"fmt"
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

// Format returns the canonical text representation of an expression.
// Returns empty string for invalid expressions (callers should Validate first).
// Does not panic on invalid expressions.
func Format(e *Expr) string {
	if e == nil {
		return ""
	}
	return formatExpr(e, false)
}

func formatExpr(e *Expr, inAnd bool) string {
	var result string

	switch e.Op {
	case OpAll: // and
		var parts []string
		for _, item := range e.Items {
			if item == nil {
				return "" // Invalid, fail safely
			}
			parts = append(parts, formatExpr(item, true))
		}
		result = joinWithSep(parts, " and ")

	case OpAny: // or
		var parts []string
		for _, item := range e.Items {
			if item == nil {
				return "" // Invalid, fail safely
			}
			parts = append(parts, formatExpr(item, false))
		}
		result = joinWithSep(parts, " or ")
		// Put parens around or inside and
		if inAnd {
			result = "(" + result + ")"
		}

	case OpIs:
		if len(e.Values) == 0 {
			return ""
		}
		result = e.Field + " = " + quoteString(e.Values[0])

	case OpIsNot:
		if len(e.Values) == 0 {
			return ""
		}
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
		if len(e.Values) == 0 {
			return ""
		}
		result = e.Field + " reports-to " + quoteString(e.Values[0])
	default:
		return ""
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

// Eval evaluates an expression against a user in the directory.
// All value comparisons are case-insensitive.
// Returns false for users not in the directory, regardless of Not flags (fail closed).
// Does not panic on invalid expressions (returns false; callers should Validate first).
// Validates the entire expression tree before evaluation to prevent Not from inverting invalid expressions.
func Eval(e *Expr, user string, d *Directory) bool {
	// Fail closed: validate entire tree first to prevent Not from inverting invalid expressions
	if err := Validate(e); err != nil {
		return false
	}
	// Fail closed: unknown users don't match anything
	if _, exists := d.People[user]; !exists {
		return false
	}
	result := evalExpr(e, user, d)
	if e.Not {
		return !result
	}
	return result
}

func evalExpr(e *Expr, user string, d *Directory) bool {
	person := d.People[user]

	switch e.Op {
	case OpAll:
		// Fail closed on invalid
		if len(e.Items) == 0 {
			return false
		}
		for _, item := range e.Items {
			if item == nil || !Eval(item, user, d) {
				return false
			}
		}
		return true

	case OpAny:
		// Fail closed on invalid
		if len(e.Items) == 0 {
			return false
		}
		for _, item := range e.Items {
			if item != nil && Eval(item, user, d) {
				return true
			}
		}
		return false

	case OpIs:
		// Fail closed: need exactly 1 value
		if len(e.Values) != 1 {
			return false
		}
		values := person.Attrs[e.Field]
		for _, v := range values {
			if strings.EqualFold(v, e.Values[0]) {
				return true
			}
		}
		return false

	case OpIsNot:
		// Fail closed: need exactly 1 value
		if len(e.Values) != 1 {
			return false
		}
		values := person.Attrs[e.Field]
		for _, v := range values {
			if strings.EqualFold(v, e.Values[0]) {
				return false
			}
		}
		return true

	case OpIn:
		// Fail closed: need at least 1 value
		if len(e.Values) == 0 {
			return false
		}
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
		// Fail closed: need exactly 1 value
		if d.ManagerField == "" || len(e.Values) != 1 {
			return false
		}
		target := e.Values[0]
		// User never reports to themselves
		if strings.EqualFold(user, target) {
			return false
		}
		// Start from user's manager (direct or indirect)
		managers := person.Attrs[d.ManagerField]
		if len(managers) == 0 {
			return false
		}
		current := managers[0]
		visited := make(map[string]bool)
		// Prevent cycles reaching back to the evaluated user
		visited[strings.ToLower(user)] = true
		steps := 0
		maxSteps := len(d.People)

		// Walk up the manager chain (direct and indirect managers)
		for steps < maxSteps {
			// Check if we reached the target (direct or indirect manager)
			if strings.EqualFold(current, target) {
				return true
			}

			currentLower := strings.ToLower(current)
			if visited[currentLower] {
				// Cycle detected (or reached back to user), stop
				break
			}
			visited[currentLower] = true

			// Move to next manager
			if p, ok := d.People[current]; ok {
				nextManagers := p.Attrs[d.ManagerField]
				if len(nextManagers) == 0 {
					break
				}
				current = nextManagers[0]
			} else {
				break
			}
			steps++
		}
		return false

	default:
		// Unknown operation, fail closed
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

// Validate checks if an expression is valid.
// Returns an error if the expression violates any constraints:
// - Unknown operation
// - Invalid field names (must match ^[a-z][a-z0-9_]{0,30}$)
// - Wrong value counts per operation
// - Items on non-compound operations
// - Nesting depth exceeds 16
// - Total nodes exceed 256
// - Values longer than 256 bytes or containing control characters
func Validate(e *Expr) error {
	if e == nil {
		return fmt.Errorf("expression is nil")
	}
	nodeCount := 0
	return validateExpr(e, 0, &nodeCount)
}

func validateExpr(e *Expr, depth int, nodeCount *int) error {
	if depth > 16 {
		return fmt.Errorf("nesting depth exceeds 16")
	}
	*nodeCount++
	if *nodeCount > 256 {
		return fmt.Errorf("total nodes exceed 256")
	}

	// Check operation is known
	switch e.Op {
	case OpAll, OpAny, OpIs, OpIsNot, OpIn, OpEmpty, OpReportsTo:
		// valid
	default:
		return fmt.Errorf("unknown operation: %q", e.Op)
	}

	// Compound operations (all/any)
	if e.Op == OpAll || e.Op == OpAny {
		if len(e.Items) == 0 {
			return fmt.Errorf("operation %q requires non-empty Items", e.Op)
		}
		if e.Field != "" {
			return fmt.Errorf("operation %q must not have Field", e.Op)
		}
		if len(e.Values) > 0 {
			return fmt.Errorf("operation %q must not have Values", e.Op)
		}
		for _, item := range e.Items {
			if item == nil {
				return fmt.Errorf("operation %q has nil item", e.Op)
			}
			if err := validateExpr(item, depth+1, nodeCount); err != nil {
				return err
			}
		}
		return nil
	}

	// Condition operations
	if len(e.Items) > 0 {
		return fmt.Errorf("operation %q must not have Items", e.Op)
	}

	// Validate field name
	if !isValidFieldName(e.Field) {
		return fmt.Errorf("invalid field name: %q", e.Field)
	}

	// Check value counts and content per operation
	switch e.Op {
	case OpIs, OpIsNot:
		if len(e.Values) != 1 {
			return fmt.Errorf("operation %q requires exactly 1 value, got %d", e.Op, len(e.Values))
		}
	case OpIn:
		if len(e.Values) < 1 {
			return fmt.Errorf("operation %q requires at least 1 value, got %d", e.Op, len(e.Values))
		}
	case OpEmpty:
		if len(e.Values) != 0 {
			return fmt.Errorf("operation %q requires 0 values, got %d", e.Op, len(e.Values))
		}
	case OpReportsTo:
		if len(e.Values) != 1 {
			return fmt.Errorf("operation %q requires exactly 1 value, got %d", e.Op, len(e.Values))
		}
	}

	// Validate values
	for _, v := range e.Values {
		if len(v) > 256 {
			return fmt.Errorf("value exceeds 256 bytes")
		}
		for _, r := range v {
			if r < 32 && r != '\t' && r != '\n' && r != '\r' {
				return fmt.Errorf("value contains control character")
			}
		}
	}

	return nil
}

func isValidFieldName(name string) bool {
	if len(name) == 0 || len(name) > 31 {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if r < 'a' || r > 'z' {
				return false
			}
		} else {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
				return false
			}
		}
	}
	return true
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
