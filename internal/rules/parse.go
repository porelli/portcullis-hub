package rules

import (
	"errors"
	"fmt"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

// parseError wraps an error with a column position
type parseError struct {
	col int
	msg string
}

func (e *parseError) Error() string {
	return fmt.Sprintf("parse error at column %d: %s", e.col, e.msg)
}

// Grammar types for participle

type grammar struct {
	Expr *orExpr `parser:"@@"`
}

type orExpr struct {
	Left  *andExpr   `parser:"@@"`
	Right []*andExpr `parser:"( 'or' @@ )*"`
	Pos   lexer.Position
}

type andExpr struct {
	Left  *unaryExpr   `parser:"@@"`
	Right []*unaryExpr `parser:"( 'and' @@ )*"`
	Pos   lexer.Position
}

type unaryExpr struct {
	Not   *unaryExpr `parser:"( 'not' @@"`
	Paren *orExpr    `parser:"  | '(' @@ ')'"`
	Cond  *condExpr  `parser:"  | @@ )"`
	Pos   lexer.Position
}

type condExpr struct {
	Field     fieldName `parser:"@Ident"`
	Equal     *string   `parser:"( '=' @String"`
	NotEqual  *string   `parser:"  | NotEqual @String"`
	In        []string  `parser:"  | 'in' '(' @String ( ',' @String )* ')'"`
	IsEmpty   bool      `parser:"  | 'is' @'empty'"`
	ReportsTo *string   `parser:"  | 'reports-to' @String )"`
	Pos       lexer.Position
}

// keywords may not be used as field names (as in the grammar of Task 3).
var keywords = map[string]bool{"and": true, "or": true, "not": true, "in": true, "is": true, "empty": true, "reports-to": true}

// fieldName captures a field identifier, lowercased; keywords are refused.
type fieldName string

func (f *fieldName) Capture(values []string) error {
	v := strings.ToLower(values[0])
	if keywords[v] {
		return fmt.Errorf("expected field name, got keyword %q", values[0])
	}
	*f = fieldName(v)
	return nil
}

var parser = participle.MustBuild[grammar](
	participle.Lexer(lexer.MustSimple([]lexer.SimpleRule{
		{Name: "String", Pattern: `"(?:[^"\\]|\\["\\])*"`}, // only \" and \\ escapes
		{Name: "NotEqual", Pattern: `!=`},
		{Name: "Ident", Pattern: `[a-zA-Z_][a-zA-Z0-9_-]*`},
		{Name: "Punct", Pattern: `[()=,]`},
		{Name: "whitespace", Pattern: `\s+`},
	})),
	participle.CaseInsensitive("Ident"),
	participle.Elide("whitespace"),
	participle.UseLookahead(2),
)

// Input limits, checked before participle runs: its recursive descent has no
// depth limit, so a deep enough nesting would overflow the stack (fatal, not
// recoverable). Validate's own limits (depth 16) apply afterwards.
const (
	maxRuleLen   = 8 << 10
	maxScanDepth = 64
)

// scanDepth returns the 0-based offset where the nesting of parens plus
// pending `not` prefixes first exceeds maxScanDepth, or -1. Strings are
// skipped (an unterminated one is left to the lexer).
func scanDepth(text string) int {
	var stack []int // pending nots at each open paren
	pending, parens, nots := 0, 0, 0
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '"':
			i++
			for i < len(text) && text[i] != '"' {
				if text[i] == '\\' {
					i++
				}
				i++
			}
			i++
			pending = 0
			continue
		case c == '(':
			stack = append(stack, pending)
			parens++
			nots += pending
			pending = 0
		case c == ')':
			if len(stack) > 0 {
				nots -= stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				parens--
			}
			pending = 0
		case isIdentStart(c):
			j := i
			for j < len(text) && isIdentPart(text[j]) {
				j++
			}
			if strings.EqualFold(text[i:j], "not") {
				pending++
			} else {
				pending = 0
			}
			if parens+nots+pending > maxScanDepth {
				return i
			}
			i = j
			continue
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			pending = 0
		}
		if parens+nots+pending > maxScanDepth {
			return i
		}
		i++
	}
	return -1
}

func isIdentStart(c byte) bool {
	return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || c == '-' || (c >= '0' && c <= '9') }

// excerpt quotes at most 20 bytes of input for an error message.
func excerpt(s string) string {
	if len(s) > 20 {
		s = s[:20] + "…"
	}
	return fmt.Sprintf("%q", s)
}

// friendlyExpect turns participle's expectation into words.
var friendlyExpect = strings.NewReplacer("<string>", "string value", "<ident>", "field name",
	"OrExpr", "a condition", "AndExpr", "a condition", "UnaryExpr", "a condition", "CondExpr", "a condition")

// parseErrorFor maps a participle error to a short message with a 1-based
// column (byte offset + 1 across the whole text, as the old parser).
func parseErrorFor(text string, err error) *parseError {
	var perr participle.Error
	if !errors.As(err, &perr) {
		return &parseError{1, "invalid rule"}
	}
	off := perr.Position().Offset
	if off < 0 || off > len(text) {
		off = 0
	}
	col := off + 1
	var cerr interface{ Unwrap() error }
	if errors.As(err, &cerr) && cerr.Unwrap() != nil && strings.HasPrefix(perr.Message(), "failed to capture") {
		return &parseError{col, cerr.Unwrap().Error()} // our own Capture message
	}
	var lerr *lexer.Error
	if errors.As(err, &lerr) {
		rest := text[off:]
		if strings.HasPrefix(rest, `"`) {
			for i := 1; i < len(rest); i++ {
				if rest[i] == '\\' {
					if i+1 < len(rest) && rest[i+1] != '"' && rest[i+1] != '\\' {
						return &parseError{off + i + 1, "invalid escape sequence (only \\\" and \\\\)"}
					}
					i++
					continue
				}
				if rest[i] == '"' {
					break
				}
			}
			return &parseError{col, "unterminated string"}
		}
		r := rest
		if r == "" {
			return &parseError{col, "unexpected end of input"}
		}
		return &parseError{col, "unexpected character " + excerpt(r[:1])}
	}
	var uerr *participle.UnexpectedTokenError
	if errors.As(err, &uerr) {
		msg := "unexpected " + excerpt(uerr.Unexpected.Value)
		if uerr.Unexpected.EOF() {
			msg = "unexpected end of input"
		}
		if m := perr.Message(); strings.HasSuffix(m, ")") {
			if i := strings.LastIndex(m, " (expected "); i >= 0 {
				exp := friendlyExpect.Replace(m[i+len(" (expected ") : len(m)-1])
				if len(exp) > 40 {
					exp = exp[:40] + "…"
				}
				msg += ", expected " + exp
			}
		}
		return &parseError{col, msg}
	}
	return &parseError{col, "invalid rule"}
}

// Parse parses a rule text into an expression tree.
// Returns only validated expressions.
func Parse(text string) (*Expr, error) {
	if strings.TrimSpace(text) == "" {
		return nil, &parseError{1, "empty input"}
	}
	if len(text) > maxRuleLen {
		return nil, &parseError{maxRuleLen + 1, fmt.Sprintf("rule longer than %d bytes", maxRuleLen)}
	}
	if off := scanDepth(text); off >= 0 {
		return nil, &parseError{off + 1, fmt.Sprintf("nesting deeper than %d", maxScanDepth)}
	}

	g, err := parser.ParseString("", text)
	if err != nil {
		return nil, parseErrorFor(text, err)
	}

	if g.Expr == nil {
		return nil, &parseError{1, "empty expression"}
	}

	expr := convertOrExpr(g.Expr)

	// Validate the parsed expression
	if err := Validate(expr); err != nil {
		return nil, &parseError{1, err.Error()}
	}

	return expr, nil
}

func convertOrExpr(o *orExpr) *Expr {
	if len(o.Right) == 0 {
		return convertAndExpr(o.Left)
	}

	items := []*Expr{convertAndExpr(o.Left)}
	for _, r := range o.Right {
		items = append(items, convertAndExpr(r))
	}
	return &Expr{Op: OpAny, Items: items}
}

func convertAndExpr(a *andExpr) *Expr {
	if len(a.Right) == 0 {
		return convertUnaryExpr(a.Left)
	}

	items := []*Expr{convertUnaryExpr(a.Left)}
	for _, r := range a.Right {
		items = append(items, convertUnaryExpr(r))
	}
	return &Expr{Op: OpAll, Items: items}
}

func convertUnaryExpr(u *unaryExpr) *Expr {
	var expr *Expr

	if u.Not != nil {
		// Recursively convert the negated expression
		expr = convertUnaryExpr(u.Not)
		// Toggle negation (double negation cancels out)
		expr.Not = !expr.Not
	} else if u.Paren != nil {
		expr = convertOrExpr(u.Paren)
	} else {
		expr = convertCondExpr(u.Cond)
	}

	return expr
}

func convertCondExpr(c *condExpr) *Expr {
	field := string(c.Field)

	if c.Equal != nil {
		return &Expr{Op: OpIs, Field: field, Values: []string{unescapeString(*c.Equal)}}
	}
	if c.NotEqual != nil {
		return &Expr{Op: OpIsNot, Field: field, Values: []string{unescapeString(*c.NotEqual)}}
	}
	if len(c.In) > 0 {
		values := make([]string, len(c.In))
		for i, v := range c.In {
			values[i] = unescapeString(v)
		}
		return &Expr{Op: OpIn, Field: field, Values: values}
	}
	if c.IsEmpty {
		return &Expr{Op: OpEmpty, Field: field}
	}
	if c.ReportsTo != nil {
		return &Expr{Op: OpReportsTo, Field: field, Values: []string{unescapeString(*c.ReportsTo)}}
	}

	// Should not reach here if grammar is correct
	return &Expr{Op: OpEmpty, Field: field}
}

// unescapeString removes the quotes and processes escape sequences
func unescapeString(s string) string {
	// Remove quotes
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	// Process escapes: \" and \\
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			if next == '"' || next == '\\' {
				result.WriteByte(next)
				i++ // skip next char
				continue
			}
		}
		result.WriteByte(s[i])
	}

	return result.String()
}
