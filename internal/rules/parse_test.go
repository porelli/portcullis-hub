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
		{`city = "a\nb"`, 8},
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
