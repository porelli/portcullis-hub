package rules

import (
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

// Parse parses a rule text into an expression tree.
// Returns only validated expressions.
func Parse(text string) (*Expr, error) {
	if strings.TrimSpace(text) == "" {
		return nil, &parseError{1, "empty input"}
	}

	g, err := parser.ParseString("", text)
	if err != nil {
		// Convert participle error to parseError with column
		if perr, ok := err.(participle.Error); ok {
			col := perr.Position().Column
			if col == 0 {
				col = 1
			}
			msg := perr.Message()
			msg = strings.Replace(msg, "unexpected token", "unexpected input", 1)
			return nil, &parseError{col, msg}
		}
		return nil, &parseError{1, err.Error()}
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
