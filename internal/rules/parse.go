package rules

import (
	"fmt"
	"strings"
	"unicode"
)

// parseError wraps an error with a column position
type parseError struct {
	col int
	msg string
}

func (e *parseError) Error() string {
	return fmt.Sprintf("parse error at column %d: %s", e.col, e.msg)
}

// lexer tokenizes the input
type lexer struct {
	input string
	pos   int // current position in input (0-based)
	col   int // current column (1-based)
}

type tokenType int

const (
	tokEOF tokenType = iota
	tokLParen
	tokRParen
	tokComma
	tokEqual
	tokNotEqual
	tokAnd
	tokOr
	tokNot
	tokIn
	tokIs
	tokEmpty
	tokReportsTo
	tokIdent
	tokString
)

type token struct {
	typ tokenType
	val string
	col int
}

func newLexer(input string) *lexer {
	return &lexer{input: input, pos: 0, col: 1}
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) && unicode.IsSpace(rune(l.input[l.pos])) {
		l.pos++
		l.col++
	}
}

func (l *lexer) peek() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

func (l *lexer) next() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	ch := l.input[l.pos]
	l.pos++
	l.col++
	return ch
}

func (l *lexer) readString() (string, error) {
	start := l.col
	l.next() // skip opening quote
	var sb strings.Builder
	for {
		ch := l.peek()
		if ch == 0 {
			return "", &parseError{start, "unterminated string"}
		}
		if ch == '"' {
			l.next()
			break
		}
		if ch == '\\' {
			l.next()
			escaped := l.peek()
			if escaped == 0 {
				return "", &parseError{l.col, "unterminated escape sequence"}
			}
			if escaped == '"' || escaped == '\\' {
				sb.WriteByte(escaped)
				l.next()
			} else {
				return "", &parseError{l.col, "invalid escape sequence"}
			}
		} else {
			sb.WriteByte(ch)
			l.next()
		}
	}
	return sb.String(), nil
}

func (l *lexer) readIdent() string {
	var sb strings.Builder
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch)) || ch == '_' || ch == '-' {
			sb.WriteByte(ch)
			l.pos++
			l.col++
		} else {
			break
		}
	}
	return sb.String()
}

func (l *lexer) nextToken() (token, error) {
	l.skipWhitespace()
	col := l.col

	if l.pos >= len(l.input) {
		return token{tokEOF, "", col}, nil
	}

	ch := l.peek()
	switch ch {
	case '(':
		l.next()
		return token{tokLParen, "(", col}, nil
	case ')':
		l.next()
		return token{tokRParen, ")", col}, nil
	case ',':
		l.next()
		return token{tokComma, ",", col}, nil
	case '=':
		l.next()
		return token{tokEqual, "=", col}, nil
	case '!':
		l.next()
		if l.peek() == '=' {
			l.next()
			return token{tokNotEqual, "!=", col}, nil
		}
		return token{}, &parseError{col, "unexpected '!'"}
	case '"':
		str, err := l.readString()
		if err != nil {
			return token{}, err
		}
		return token{tokString, str, col}, nil
	default:
		if unicode.IsLetter(rune(ch)) || ch == '_' {
			ident := l.readIdent()
			identLower := strings.ToLower(ident)
			switch identLower {
			case "and":
				return token{tokAnd, ident, col}, nil
			case "or":
				return token{tokOr, ident, col}, nil
			case "not":
				return token{tokNot, ident, col}, nil
			case "in":
				return token{tokIn, ident, col}, nil
			case "is":
				return token{tokIs, ident, col}, nil
			case "empty":
				return token{tokEmpty, ident, col}, nil
			case "reports-to":
				return token{tokReportsTo, ident, col}, nil
			default:
				return token{tokIdent, ident, col}, nil
			}
		}
		return token{}, &parseError{col, fmt.Sprintf("unexpected character '%c'", ch)}
	}
}

// parser parses tokens into an expression tree
type parser struct {
	lex *lexer
	tok token
}

func newParser(input string) (*parser, error) {
	p := &parser{lex: newLexer(input)}
	tok, err := p.lex.nextToken()
	if err != nil {
		return nil, err
	}
	p.tok = tok
	return p, nil
}

func (p *parser) advance() error {
	tok, err := p.lex.nextToken()
	if err != nil {
		return err
	}
	p.tok = tok
	return nil
}

func (p *parser) expect(typ tokenType) error {
	if p.tok.typ != typ {
		return &parseError{p.tok.col, fmt.Sprintf("expected %v, got %v", typ, p.tok.typ)}
	}
	return p.advance()
}

// Parse parses a rule text into an expression tree
func Parse(text string) (*Expr, error) {
	if strings.TrimSpace(text) == "" {
		return nil, &parseError{1, "empty input"}
	}
	p, err := newParser(text)
	if err != nil {
		return nil, err
	}
	expr, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.tok.typ != tokEOF {
		return nil, &parseError{p.tok.col, "unexpected input after expression"}
	}
	return expr, nil
}

func (p *parser) parseExpr() (*Expr, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (*Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	if p.tok.typ == tokOr {
		items := []*Expr{left}
		for p.tok.typ == tokOr {
			if err := p.advance(); err != nil {
				return nil, err
			}
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			items = append(items, right)
		}
		return &Expr{Op: OpAny, Items: items}, nil
	}

	return left, nil
}

func (p *parser) parseAnd() (*Expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	if p.tok.typ == tokAnd {
		items := []*Expr{left}
		for p.tok.typ == tokAnd {
			if err := p.advance(); err != nil {
				return nil, err
			}
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			items = append(items, right)
		}
		return &Expr{Op: OpAll, Items: items}, nil
	}

	return left, nil
}

func (p *parser) parseUnary() (*Expr, error) {
	if p.tok.typ == tokNot {
		if err := p.advance(); err != nil {
			return nil, err
		}
		expr, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		expr.Not = !expr.Not
		return expr, nil
	}

	if p.tok.typ == tokLParen {
		if err := p.advance(); err != nil {
			return nil, err
		}
		expr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(tokRParen); err != nil {
			return nil, err
		}
		return expr, nil
	}

	return p.parseCond()
}

func (p *parser) parseCond() (*Expr, error) {
	if p.tok.typ != tokIdent {
		return nil, &parseError{p.tok.col, "expected field name"}
	}
	field := strings.ToLower(p.tok.val)
	col := p.tok.col
	if err := p.advance(); err != nil {
		return nil, err
	}

	switch p.tok.typ {
	case tokEqual:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.typ != tokString {
			return nil, &parseError{p.tok.col, "expected string value"}
		}
		value := p.tok.val
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &Expr{Op: OpIs, Field: field, Values: []string{value}}, nil

	case tokNotEqual:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.typ != tokString {
			return nil, &parseError{p.tok.col, "expected string value"}
		}
		value := p.tok.val
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &Expr{Op: OpIsNot, Field: field, Values: []string{value}}, nil

	case tokIn:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if err := p.expect(tokLParen); err != nil {
			return nil, err
		}
		var values []string
		for {
			if p.tok.typ != tokString {
				return nil, &parseError{p.tok.col, "expected string value"}
			}
			values = append(values, p.tok.val)
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.tok.typ == tokRParen {
				break
			}
			if err := p.expect(tokComma); err != nil {
				return nil, err
			}
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &Expr{Op: OpIn, Field: field, Values: values}, nil

	case tokIs:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.typ != tokEmpty {
			return nil, &parseError{p.tok.col, "expected 'empty' after 'is'"}
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &Expr{Op: OpEmpty, Field: field}, nil

	case tokReportsTo:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.tok.typ != tokString {
			return nil, &parseError{p.tok.col, "expected username string"}
		}
		value := p.tok.val
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &Expr{Op: OpReportsTo, Field: field, Values: []string{value}}, nil

	default:
		return nil, &parseError{col, "expected operator (=, !=, in, is, reports-to)"}
	}
}
