package rules

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseFormatRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		canonical string // expected canonical form after Format
	}{
		{
			name:      "simple equality",
			text:      `city = "Milan"`,
			canonical: `city = "Milan"`,
		},
		{
			name:      "and with or in parens",
			text:      `city = "Milan" and (department = "Sales" or department = "Support")`,
			canonical: `city = "Milan" and (department = "Sales" or department = "Support")`,
		},
		{
			name:      "not",
			text:      `not department = "HR"`,
			canonical: `not department = "HR"`,
		},
		{
			name:      "in operator",
			text:      `city in ("Milan","Turin")`,
			canonical: `city in ("Milan", "Turin")`,
		},
		{
			name:      "reports-to",
			text:      `manager reports-to "anna"`,
			canonical: `manager reports-to "anna"`,
		},
		{
			name:      "is empty",
			text:      `languages is empty`,
			canonical: `languages is empty`,
		},
		{
			name:      "escaped quote",
			text:      `name = "say \"hello\""`,
			canonical: `name = "say \"hello\""`,
		},
		{
			name:      "escaped backslash",
			text:      `path = "C:\\\\Users"`,
			canonical: `path = "C:\\\\Users"`,
		},
		{
			name:      "not equal",
			text:      `city != "Rome"`,
			canonical: `city != "Rome"`,
		},
		{
			name:      "complex nested",
			text:      `(city = "Milan" or city = "Turin") and not department = "HR"`,
			canonical: `(city = "Milan" or city = "Turin") and not department = "HR"`,
		},
		{
			name:      "case insensitive keywords",
			text:      `City = "Milan" AND Department = "Sales"`,
			canonical: `city = "Milan" and department = "Sales"`,
		},
		{
			name:      "OR keyword",
			text:      `city = "Milan" OR city = "Turin"`,
			canonical: `city = "Milan" or city = "Turin"`,
		},
		{
			name:      "NOT keyword",
			text:      `NOT city = "Rome"`,
			canonical: `not city = "Rome"`,
		},
		{
			name:      "IS EMPTY keywords",
			text:      `languages IS EMPTY`,
			canonical: `languages is empty`,
		},
		{
			name:      "IN keyword",
			text:      `city IN ("Milan", "Turin")`,
			canonical: `city in ("Milan", "Turin")`,
		},
		{
			name:      "REPORTS-TO keyword",
			text:      `manager REPORTS-TO "anna"`,
			canonical: `manager reports-to "anna"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.text)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.text, err)
			}
			formatted := Format(expr)
			if formatted != tt.canonical {
				t.Errorf("Format(Parse(%q)) = %q, want %q", tt.text, formatted, tt.canonical)
			}
			// Round-trip: parse the formatted string again
			expr2, err := Parse(formatted)
			if err != nil {
				t.Fatalf("Parse(Format(Parse(%q))) failed: %v", tt.text, err)
			}
			if !reflect.DeepEqual(expr, expr2) {
				t.Errorf("Parse(Format(Parse(%q))) not deep equal", tt.text)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		wantColumn int // 1-based
	}{
		{
			name:       "incomplete equality",
			text:       `city = `,
			wantColumn: 8,
		},
		{
			name:       "unclosed paren",
			text:       `(city = "a"`,
			wantColumn: 12, // at EOF
		},
		{
			name:       "unknown operator",
			text:       `city ~ "Milan"`,
			wantColumn: 6,
		},
		{
			name:       "missing string",
			text:       `city = Milan`,
			wantColumn: 8,
		},
		{
			name:       "empty input",
			text:       ``,
			wantColumn: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.text)
			if err == nil {
				t.Fatalf("Parse(%q) should have failed", tt.text)
			}
			// Check that error message contains column number
			errStr := err.Error()
			if !strings.Contains(errStr, "column") {
				t.Errorf("Parse(%q) error should contain 'column', got: %v", tt.text, err)
			}
		})
	}
}

func TestEval(t *testing.T) {
	// Create a directory with 5 people for testing
	dir := &Directory{
		People: map[string]Person{
			"alice": {
				User: "alice",
				Attrs: map[string][]string{
					"city":       {"Milan"},
					"department": {"Sales"},
				},
			},
			"bob": {
				User: "bob",
				Attrs: map[string][]string{
					"city":       {"Turin"},
					"department": {"Sales"},
				},
			},
			"charlie": {
				User: "charlie",
				Attrs: map[string][]string{
					"city":       {"Milan"},
					"department": {"Support"},
				},
			},
			"diana": {
				User: "diana",
				Attrs: map[string][]string{
					"city":       {"Rome"},
					"department": {"HR"},
				},
			},
			"eve": {
				User: "eve",
				Attrs: map[string][]string{
					"city": {"Milan"},
					// no department
				},
			},
		},
		ManagerField: "manager",
	}

	tests := []struct {
		name     string
		rule     string
		expected []string // users who should match
	}{
		{
			name:     "single equality",
			rule:     `city = "Milan"`,
			expected: []string{"alice", "charlie", "eve"},
		},
		{
			name:     "and condition",
			rule:     `city = "Milan" and department = "Sales"`,
			expected: []string{"alice"},
		},
		{
			name:     "or condition",
			rule:     `department = "Sales" or department = "Support"`,
			expected: []string{"alice", "bob", "charlie"},
		},
		{
			name:     "not condition",
			rule:     `not department = "HR"`,
			expected: []string{"alice", "bob", "charlie", "eve"},
		},
		{
			name:     "in condition",
			rule:     `city in ("Milan", "Turin")`,
			expected: []string{"alice", "bob", "charlie", "eve"},
		},
		{
			name:     "is empty",
			rule:     `department is empty`,
			expected: []string{"eve"},
		},
		{
			name:     "not equal",
			rule:     `city != "Rome"`,
			expected: []string{"alice", "bob", "charlie", "eve"},
		},
		{
			name:     "complex with parens",
			rule:     `city = "Milan" and (department = "Sales" or department = "Support")`,
			expected: []string{"alice", "charlie"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.rule)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.rule, err)
			}

			var matched []string
			for user := range dir.People {
				if Eval(expr, user, dir) {
					matched = append(matched, user)
				}
			}
			sort.Strings(matched)
			sort.Strings(tt.expected)

			if !reflect.DeepEqual(matched, tt.expected) {
				t.Errorf("Eval(%q) matched %v, want %v", tt.rule, matched, tt.expected)
			}
		})
	}
}

func TestReportsTo(t *testing.T) {
	// Chain: c→b→a
	dir := &Directory{
		People: map[string]Person{
			"a": {
				User:  "a",
				Attrs: map[string][]string{
					// no manager
				},
			},
			"b": {
				User: "b",
				Attrs: map[string][]string{
					"manager": {"a"},
				},
			},
			"c": {
				User: "c",
				Attrs: map[string][]string{
					"manager": {"b"},
				},
			},
		},
		ManagerField: "manager",
	}

	tests := []struct {
		user     string
		rule     string
		expected bool
	}{
		{"c", `manager reports-to "a"`, true},  // indirect manager
		{"c", `manager reports-to "b"`, true},  // direct manager (directly or indirectly)
		{"b", `manager reports-to "a"`, true},  // direct manager (directly or indirectly)
		{"a", `manager reports-to "a"`, false}, // user never their own report
		{"a", `manager reports-to "b"`, false}, // a has no manager
	}

	for _, tt := range tests {
		t.Run(tt.user+"_"+tt.rule, func(t *testing.T) {
			expr, err := Parse(tt.rule)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.rule, err)
			}
			result := Eval(expr, tt.user, dir)
			if result != tt.expected {
				t.Errorf("Eval(%q, %q) = %v, want %v", tt.rule, tt.user, result, tt.expected)
			}
		})
	}
}

func TestReportsToCycle(t *testing.T) {
	// Cycle: a→b→a
	dir := &Directory{
		People: map[string]Person{
			"a": {
				User: "a",
				Attrs: map[string][]string{
					"manager": {"b"},
				},
			},
			"b": {
				User: "b",
				Attrs: map[string][]string{
					"manager": {"a"},
				},
			},
		},
		ManagerField: "manager",
	}

	// Test that reports-to terminates with cycles
	// a reports-to b should be true (b is a's direct manager)
	exprB, err := Parse(`manager reports-to "b"`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !Eval(exprB, "a", dir) {
		t.Errorf("Eval(a, reports-to b) should be true (direct manager)")
	}

	// a reports-to a should be false (never report to self)
	exprA, err := Parse(`manager reports-to "a"`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if Eval(exprA, "a", dir) {
		t.Errorf("Eval(a, reports-to a) should be false (never self)")
	}

	// Test Cycles function
	cycles := Cycles(dir)
	if len(cycles) != 1 {
		t.Fatalf("Cycles() = %v, want 1 cycle", cycles)
	}

	cycle := cycles[0]
	sort.Strings(cycle)
	expected := []string{"a", "b"}
	if !reflect.DeepEqual(cycle, expected) {
		t.Errorf("Cycles() = %v, want %v", cycles, [][]string{expected})
	}
}

func TestFields(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		expected []string
	}{
		{
			name:     "single field",
			rule:     `city = "Milan"`,
			expected: []string{"city"},
		},
		{
			name:     "multiple fields",
			rule:     `city = "Milan" and department = "Sales"`,
			expected: []string{"city", "department"},
		},
		{
			name:     "duplicate fields",
			rule:     `city = "Milan" or city = "Turin"`,
			expected: []string{"city"},
		},
		{
			name:     "nested fields",
			rule:     `(city = "Milan" or department = "Sales") and not manager is empty`,
			expected: []string{"city", "department", "manager"},
		},
		{
			name:     "in operator",
			rule:     `city in ("Milan", "Turin")`,
			expected: []string{"city"},
		},
		{
			name:     "reports-to",
			rule:     `manager reports-to "anna"`,
			expected: []string{"manager"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.rule)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.rule, err)
			}
			fields := Fields(expr)
			if !reflect.DeepEqual(fields, tt.expected) {
				t.Errorf("Fields(%q) = %v, want %v", tt.rule, fields, tt.expected)
			}
		})
	}
}

func TestEvalUnknownUser(t *testing.T) {
	// Test that unknown users return false even with Not flags (fail closed)
	dir := &Directory{
		People: map[string]Person{
			"alice": {
				User: "alice",
				Attrs: map[string][]string{
					"department": {"HR"},
				},
			},
		},
		ManagerField: "manager",
	}

	tests := []struct {
		name string
		rule string
	}{
		{"positive condition", `department = "HR"`},
		{"negation", `not department = "HR"`},
		{"double negation", `not not department = "HR"`},
		{"is empty", `department is empty`},
		{"not is empty", `not department is empty`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.rule)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.rule, err)
			}
			// Unknown user must return false regardless of Not flags
			if Eval(expr, "unknown", dir) {
				t.Errorf("Eval(%q, unknown) should be false (fail closed)", tt.rule)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		expr    *Expr
		wantErr bool
	}{
		{
			name:    "nil expression",
			expr:    nil,
			wantErr: true,
		},
		{
			name: "unknown op",
			expr: &Expr{
				Op:    "unknown",
				Field: "city",
			},
			wantErr: true,
		},
		{
			name: "invalid field name - uppercase",
			expr: &Expr{
				Op:     OpIs,
				Field:  "City",
				Values: []string{"Milan"},
			},
			wantErr: true,
		},
		{
			name: "invalid field name - starts with digit",
			expr: &Expr{
				Op:     OpIs,
				Field:  "9city",
				Values: []string{"Milan"},
			},
			wantErr: true,
		},
		{
			name: "invalid field name - too long",
			expr: &Expr{
				Op:     OpIs,
				Field:  "this_field_name_is_way_too_long_for_validation",
				Values: []string{"Milan"},
			},
			wantErr: true,
		},
		{
			name: "is with wrong value count",
			expr: &Expr{
				Op:     OpIs,
				Field:  "city",
				Values: []string{"Milan", "Turin"},
			},
			wantErr: true,
		},
		{
			name: "is_not with no values",
			expr: &Expr{
				Op:     OpIsNot,
				Field:  "city",
				Values: []string{},
			},
			wantErr: true,
		},
		{
			name: "in with no values",
			expr: &Expr{
				Op:     OpIn,
				Field:  "city",
				Values: []string{},
			},
			wantErr: true,
		},
		{
			name: "empty with values",
			expr: &Expr{
				Op:     OpEmpty,
				Field:  "city",
				Values: []string{"Milan"},
			},
			wantErr: true,
		},
		{
			name: "reports_to with wrong value count",
			expr: &Expr{
				Op:     OpReportsTo,
				Field:  "manager",
				Values: []string{"alice", "bob"},
			},
			wantErr: true,
		},
		{
			name: "all with empty items",
			expr: &Expr{
				Op:    OpAll,
				Items: []*Expr{},
			},
			wantErr: true,
		},
		{
			name: "any with field",
			expr: &Expr{
				Op:    OpAny,
				Field: "city",
				Items: []*Expr{
					{Op: OpIs, Field: "city", Values: []string{"Milan"}},
				},
			},
			wantErr: true,
		},
		{
			name: "condition with items",
			expr: &Expr{
				Op:     OpIs,
				Field:  "city",
				Values: []string{"Milan"},
				Items: []*Expr{
					{Op: OpIs, Field: "dept", Values: []string{"Sales"}},
				},
			},
			wantErr: true,
		},
		{
			name: "value too long",
			expr: &Expr{
				Op:     OpIs,
				Field:  "city",
				Values: []string{strings.Repeat("a", 257)},
			},
			wantErr: true,
		},
		{
			name: "value with control character",
			expr: &Expr{
				Op:     OpIs,
				Field:  "city",
				Values: []string{"Milan\x00"},
			},
			wantErr: true,
		},
		{
			name: "valid simple",
			expr: &Expr{
				Op:     OpIs,
				Field:  "city",
				Values: []string{"Milan"},
			},
			wantErr: false,
		},
		{
			name: "valid compound",
			expr: &Expr{
				Op: OpAll,
				Items: []*Expr{
					{Op: OpIs, Field: "city", Values: []string{"Milan"}},
					{Op: OpIsNot, Field: "department", Values: []string{"HR"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid with underscore and digits",
			expr: &Expr{
				Op:     OpIs,
				Field:  "cost_center_2",
				Values: []string{"CC123"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDepthAndNodes(t *testing.T) {
	// Test depth limit
	deepExpr := &Expr{Op: OpIs, Field: "city", Values: []string{"Milan"}}
	for i := 0; i < 17; i++ {
		deepExpr = &Expr{Op: OpAll, Items: []*Expr{deepExpr}}
	}
	if err := Validate(deepExpr); err == nil {
		t.Error("Validate() should fail for depth > 16")
	}

	// Test node count limit
	manyItems := make([]*Expr, 257)
	for i := 0; i < 257; i++ {
		manyItems[i] = &Expr{Op: OpIs, Field: "city", Values: []string{"Milan"}}
	}
	largeExpr := &Expr{Op: OpAll, Items: manyItems}
	if err := Validate(largeExpr); err == nil {
		t.Error("Validate() should fail for > 256 total nodes")
	}
}

func TestParseFormatRoundTripAdditional(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		canonical string
	}{
		{
			name:      "negated compound",
			text:      `not (city = "Milan" and department = "Sales")`,
			canonical: `not (city = "Milan" and department = "Sales")`,
		},
		{
			name:      "double negation",
			text:      `not not city = "Milan"`,
			canonical: `city = "Milan"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.text)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.text, err)
			}
			formatted := Format(expr)
			if formatted != tt.canonical {
				t.Errorf("Format(Parse(%q)) = %q, want %q", tt.text, formatted, tt.canonical)
			}
		})
	}
}

func TestEvalFormatPanicSafety(t *testing.T) {
	// Test that Eval and Format don't panic on invalid expressions
	dir := &Directory{
		People: map[string]Person{
			"alice": {
				User: "alice",
				Attrs: map[string][]string{
					"city": {"Milan"},
				},
			},
		},
		ManagerField: "manager",
	}

	tests := []struct {
		name string
		expr *Expr
	}{
		{
			name: "nil expression",
			expr: nil,
		},
		{
			name: "is with no values",
			expr: &Expr{
				Op:    OpIs,
				Field: "city",
			},
		},
		{
			name: "is_not with no values",
			expr: &Expr{
				Op:    OpIsNot,
				Field: "city",
			},
		},
		{
			name: "reports_to with no values",
			expr: &Expr{
				Op:    OpReportsTo,
				Field: "manager",
			},
		},
		{
			name: "all with nil item",
			expr: &Expr{
				Op:    OpAll,
				Items: []*Expr{nil},
			},
		},
		{
			name: "any with nil item",
			expr: &Expr{
				Op:    OpAny,
				Items: []*Expr{nil},
			},
		},
		{
			name: "unknown operation",
			expr: &Expr{
				Op:    "unknown",
				Field: "city",
			},
		},
		{
			name: "in with no values",
			expr: &Expr{
				Op:    OpIn,
				Field: "city",
			},
		},
		{
			name: "all with empty items",
			expr: &Expr{
				Op:    OpAll,
				Items: []*Expr{},
			},
		},
		{
			name: "any with empty items",
			expr: &Expr{
				Op:    OpAny,
				Items: []*Expr{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that Format doesn't panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Format() panicked: %v", r)
				}
			}()
			result := Format(tt.expr)
			// Format should return empty string for invalid
			if tt.expr == nil || tt.expr.Op == "unknown" || len(tt.expr.Values) == 0 && (tt.expr.Op == OpIs || tt.expr.Op == OpIsNot || tt.expr.Op == OpReportsTo) {
				if result != "" {
					t.Errorf("Format() = %q, want empty string for invalid", result)
				}
			}

			// Test that Eval doesn't panic and returns false (fail closed)
			evalResult := Eval(tt.expr, "alice", dir)
			if evalResult {
				t.Errorf("Eval() = true, want false (fail closed) for invalid expression")
			}
		})
	}
}

func TestEvalNotOnInvalid(t *testing.T) {
	// Test that Not on invalid expressions still returns false (fail closed)
	dir := &Directory{
		People: map[string]Person{
			"alice": {
				User: "alice",
				Attrs: map[string][]string{
					"city": {"Milan"},
				},
			},
		},
		ManagerField: "manager",
	}

	tests := []struct {
		name string
		expr *Expr
	}{
		{
			name: "is with Not and no values",
			expr: &Expr{
				Op:    OpIs,
				Field: "city",
				Not:   true,
			},
		},
		{
			name: "reports_to with Not and no values",
			expr: &Expr{
				Op:    OpReportsTo,
				Field: "manager",
				Not:   true,
			},
		},
		{
			name: "all with Not and nil item",
			expr: &Expr{
				Op:    OpAll,
				Items: []*Expr{nil},
				Not:   true,
			},
		},
		{
			name: "any with Not and invalid nested op",
			expr: &Expr{
				Op: OpAny,
				Items: []*Expr{
					{Op: "bogus", Field: "city"},
				},
				Not: true,
			},
		},
		{
			name: "unknown op with Not",
			expr: &Expr{
				Op:    "unknown",
				Field: "city",
				Not:   true,
			},
		},
		{
			name: "is_not with Not and no values",
			expr: &Expr{
				Op:    OpIsNot,
				Field: "city",
				Not:   true,
			},
		},
		{
			name: "in with Not and no values",
			expr: &Expr{
				Op:    OpIn,
				Field: "city",
				Not:   true,
			},
		},
		{
			name: "all with Not and empty items",
			expr: &Expr{
				Op:    OpAll,
				Items: []*Expr{},
				Not:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Eval(tt.expr, "alice", dir)
			if result {
				t.Errorf("Eval() = true, want false (fail closed even with Not on invalid expression)")
			}
		})
	}
}
