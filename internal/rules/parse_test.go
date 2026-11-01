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

// TestValidateFormatLength: Validate refuses an Expr whose Format exceeds
// the Parse cap, and anything it accepts round-trips through Parse.
func TestValidateFormatLength(t *testing.T) {
	block := func(n, valueLen int) *Expr {
		e := &Expr{Op: OpAll}
		for i := 0; i < n; i++ {
			e.Items = append(e.Items, &Expr{Op: OpIs, Field: fmt.Sprintf("field%05d", i), Values: []string{strings.Repeat("v", valueLen)}})
		}
		return e
	}
	big := block(255, 20) // 255 × len(`field00000 = "vvv…"`) + " and " ≈ 9.4 KiB
	err := Validate(big)
	if err == nil || !strings.Contains(err.Error(), "rule too long:") || !strings.Contains(err.Error(), "max 8192") {
		t.Fatalf("Validate(255 conditions) = %v, want rule too long", err)
	}
	// Largest n that still fits, then the value length that fills it up.
	var e *Expr
	for n := 255; n > 0; n-- {
		if e = block(n, 20); len(Format(e)) <= maxRuleLen {
			break
		}
	}
	last := e.Items[len(e.Items)-1]
	last.Values[0] += strings.Repeat("w", maxRuleLen-len(Format(e)))
	if got := len(Format(e)); got != maxRuleLen {
		t.Fatalf("setup: Format length %d, want %d", got, maxRuleLen)
	}
	if err := Validate(e); err != nil {
		t.Fatalf("Validate(at limit) = %v", err)
	}
	back, err := Parse(Format(e))
	if err != nil {
		t.Fatalf("Parse(Format(e)) = %v", err)
	}
	if Format(back) != Format(e) {
		t.Error("round trip changed the rule")
	}
	last.Values[0] += "w" // one byte over
	if err := Validate(e); err == nil || !strings.Contains(err.Error(), "rule too long: 8193 bytes, max 8192") {
		t.Errorf("Validate(limit+1) = %v", err)
	}
}
