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
		{"c", `manager reports-to "a"`, true},
		{"c", `manager reports-to "b"`, false}, // b is direct manager, not indirect
		{"b", `manager reports-to "a"`, false}, // a is direct manager, not indirect
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
	expr, err := Parse(`manager reports-to "b"`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// a reports-to b should be true (b is a's manager's manager in the cycle)
	if !Eval(expr, "a", dir) {
		t.Errorf("Eval(a, reports-to b) should be true")
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
