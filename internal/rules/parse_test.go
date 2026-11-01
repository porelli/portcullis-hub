package rules

import (
	"fmt"
	"strings"
	"testing"
)

// TestParseErrorColumns pins the 1-based error column and the cases the
// hand-written parser refused (keywords as field names, unknown escapes).
func TestParseErrorColumns(t *testing.T) {
	tests := []struct {
		text string
		col  int
	}{
		{`city = `, 8},
		{`(city = "a"`, 12},
		{`city ~ "Milan"`, 6},
		{`city = Milan`, 8},
		{``, 1},
		{`and = "x"`, 1},
		{`city = "x" and in = "y"`, 16},
		{`city = "a\nb"`, 10},
		{`city = "abc`, 8},
		{`city = "a" city`, 12},
		{`x is not`, 6},
	}
	for _, tt := range tests {
		_, err := Parse(tt.text)
		if err == nil {
			t.Errorf("Parse(%q) should have failed", tt.text)
			continue
		}
		if want := fmt.Sprintf("column %d:", tt.col); !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %s", tt.text, err, want)
		}
	}
}

// TestParseLimits: pathological nesting and size are refused before
// participle runs (its recursion would otherwise overflow the stack, fatally).
func TestParseLimits(t *testing.T) {
	cases := map[string]string{
		"1M parens":   strings.Repeat("(", 1<<20),
		"200k not":    strings.Repeat("not ", 200000) + `a = "x"`,
		"9 KiB text":  `a = "` + strings.Repeat("x", 9<<10) + `"`,
		"65 parens":   strings.Repeat("(", 65) + `a = "x"` + strings.Repeat(")", 65),
		"mixed chain": strings.Repeat("not (", 40) + `a = "x"` + strings.Repeat(")", 40),
	}
	for name, text := range cases {
		_, err := Parse(text)
		if err == nil || !strings.Contains(err.Error(), "column ") {
			t.Errorf("%s: err = %v", name, err)
		}
		if err != nil && len(err.Error()) > 120 {
			t.Errorf("%s: error too long (%d bytes)", name, len(err.Error()))
		}
	}
	// Siblings don't add up: 100 parenthesised conditions in a row are fine
	// for the scanner (Validate's node limit decides).
	sib := strings.TrimSuffix(strings.Repeat(`(not a = "x") or `, 10), " or ")
	if _, err := Parse(sib); err != nil {
		t.Errorf("siblings: %v", err)
	}
}

// TestParseErrorMessages: short, user-facing messages without participle
// internals, quoting at most ~20 bytes of input.
func TestParseErrorMessages(t *testing.T) {
	tests := []struct{ text, want string }{
		{`city = "abc`, "column 8: unterminated string"},
		{`city ~ "Milan"`, `column 6: unexpected character "~"`},
		{`and = "x"`, `column 1: expected field name, got keyword "and"`},
		{`city = "a\nb"`, "column 10: invalid escape sequence"},
		{`city = Milan`, `column 8: unexpected "Milan", expected string value`},
		{`city = "a" or`, "column 14: unexpected end of input, expected a condition"},
	}
	for _, tt := range tests {
		_, err := Parse(tt.text)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Parse(%q) = %v, want %q", tt.text, err, tt.want)
		}
		for _, bad := range []string{"failed to capture", "lexer:", "token", "Expr"} {
			if err != nil && strings.Contains(err.Error(), bad) {
				t.Errorf("Parse(%q) = %v leaks %q", tt.text, err, bad)
			}
		}
	}
	long := `city = "a" ` + strings.Repeat("y", 500)
	if _, err := Parse(long); err == nil || len(err.Error()) > 80 {
		t.Errorf("long input echoed: %v", err)
	}
}
