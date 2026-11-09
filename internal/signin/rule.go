package signin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Group operators.
const (
	OpAll = "all"
	OpAny = "any"
)

// Rule limits (D2, contract §8.1 "Rules").
const (
	MaxDepth      = 3   // group levels; the top group is level 1
	MaxItems      = 8   // items per group
	MaxLeaves     = 16  // methods and families per rule
	MaxAlternates = 256 // alternatives Alternatives will return
)

// Node is a rule: a group (Op "all" or "any" with Items) or a leaf (Op ""
// with Leaf, a method id or a family). In JSON a leaf is a string and a
// group {"op": …, "items": […]}.
type Node struct {
	Op    string
	Items []Node
	Leaf  string
}

func (n Node) isLeaf() bool { return n.Op == "" }

// MarshalJSON writes a leaf as its string and a group as {"op","items"}.
func (n Node) MarshalJSON() ([]byte, error) {
	if n.isLeaf() {
		if n.Leaf == "" || n.Items != nil {
			return nil, errors.New("signin: malformed rule node")
		}
		return json.Marshal(n.Leaf)
	}
	items := n.Items
	if items == nil {
		items = []Node{}
	}
	return json.Marshal(struct {
		Op    string `json:"op"`
		Items []Node `json:"items"`
	}{n.Op, items})
}

// maxJSONNesting bounds the decoder's recursion; Validate applies the real
// limits.
const maxJSONNesting = 16

// UnmarshalJSON decodes strictly: a non-empty string, or an object with
// exactly the keys "op" ("all" or "any") and "items" (an array), each once.
// Anything else, trailing data included, is an error.
func (n *Node) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeNode(dec, 1)
	if err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("signin: trailing data after rule")
	}
	*n = v
	return nil
}

func decodeNode(dec *json.Decoder, depth int) (Node, error) {
	if depth > maxJSONNesting {
		return Node{}, errors.New("signin: rule nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return Node{}, fmt.Errorf("signin: rule: %w", err)
	}
	switch t := tok.(type) {
	case string:
		if t == "" {
			return Node{}, errors.New("signin: empty rule item")
		}
		return Node{Leaf: t}, nil
	case json.Delim:
		if t != '{' {
			return Node{}, fmt.Errorf("signin: rule item must be a string or a group, got %q", t)
		}
	default:
		return Node{}, fmt.Errorf("signin: rule item must be a string or a group, got %v", tok)
	}
	var out Node
	var sawOp, sawItems bool
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return Node{}, fmt.Errorf("signin: rule: %w", err)
		}
		key, _ := kt.(string)
		switch key {
		case "op":
			if sawOp {
				return Node{}, errors.New(`signin: duplicate "op"`)
			}
			sawOp = true
			vt, err := dec.Token()
			if err != nil {
				return Node{}, fmt.Errorf("signin: rule: %w", err)
			}
			op, _ := vt.(string)
			if op != OpAll && op != OpAny {
				return Node{}, fmt.Errorf(`signin: "op" must be "all" or "any"`)
			}
			out.Op = op
		case "items":
			if sawItems {
				return Node{}, errors.New(`signin: duplicate "items"`)
			}
			sawItems = true
			vt, err := dec.Token()
			if err != nil {
				return Node{}, fmt.Errorf("signin: rule: %w", err)
			}
			if d, ok := vt.(json.Delim); !ok || d != '[' {
				return Node{}, errors.New(`signin: "items" must be an array`)
			}
			out.Items = []Node{}
			for dec.More() {
				it, err := decodeNode(dec, depth+1)
				if err != nil {
					return Node{}, err
				}
				out.Items = append(out.Items, it)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return Node{}, fmt.Errorf("signin: rule: %w", err)
			}
		default:
			return Node{}, fmt.Errorf("signin: unknown rule key %q", key)
		}
	}
	if _, err := dec.Token(); err != nil { // '}'
		return Node{}, fmt.Errorf("signin: rule: %w", err)
	}
	if !sawOp || !sawItems {
		return Node{}, errors.New(`signin: a group needs "op" and "items"`)
	}
	return out, nil
}

// Validate checks a source rule (families allowed) against D2: the top is a
// group; groups are "all" / "any" with 1–8 items, nested at most 3 levels;
// at most 16 leaves, each a method id or a family.
func Validate(n Node) error {
	if n.isLeaf() {
		return errors.New("a rule must be an all-of or any-of group")
	}
	leaves := 0
	var walk func(n Node, depth int) error
	walk = func(n Node, depth int) error {
		if n.isLeaf() {
			if n.Items != nil {
				return errors.New("malformed rule item")
			}
			if _, ok := methodInfo[Method(n.Leaf)]; !ok {
				if _, ok := families[n.Leaf]; !ok {
					return fmt.Errorf("unknown sign-in method %q", n.Leaf)
				}
			}
			leaves++
			return nil
		}
		if n.Op != OpAll && n.Op != OpAny {
			return fmt.Errorf("unknown group kind %q", n.Op)
		}
		if n.Leaf != "" {
			return errors.New("malformed rule group")
		}
		if depth > MaxDepth {
			return fmt.Errorf("groups nest at most %d levels", MaxDepth)
		}
		if len(n.Items) < 1 || len(n.Items) > MaxItems {
			return fmt.Errorf("a group holds 1–%d items", MaxItems)
		}
		for _, it := range n.Items {
			if err := walk(it, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(n, 1); err != nil {
		return err
	}
	if leaves > MaxLeaves {
		return fmt.Errorf("a rule has at most %d methods", MaxLeaves)
	}
	return nil
}

// ErrUnmeetable is Compile's error for a rule naming a switched-off method,
// or a family with no switched-on member.
var ErrUnmeetable = errors.New("the rule names a sign-in method that is switched off")

// Compile validates n and turns each family into an "any" group of its
// switched-on members, in the family's order. A direct method that is off,
// or a family with no member on, fails with ErrUnmeetable (wrapped, naming
// it). The result has no families and only switched-on leaves.
func Compile(n Node, on map[Method]bool) (Node, error) {
	if err := Validate(n); err != nil {
		return Node{}, err
	}
	return compile(n, on)
}

func compile(n Node, on map[Method]bool) (Node, error) {
	if n.isLeaf() {
		if f, ok := families[n.Leaf]; ok {
			ms := f.onMembers(on)
			if len(ms) == 0 {
				return Node{}, fmt.Errorf("%w: %s has no method switched on", ErrUnmeetable, n.Leaf)
			}
			g := Node{Op: OpAny, Items: make([]Node, 0, len(ms))}
			for _, m := range ms {
				g.Items = append(g.Items, Node{Leaf: string(m)})
			}
			return g, nil
		}
		if !on[Method(n.Leaf)] {
			return Node{}, fmt.Errorf("%w: %s", ErrUnmeetable, n.Leaf)
		}
		return Node{Leaf: n.Leaf}, nil
	}
	out := Node{Op: n.Op, Items: make([]Node, 0, len(n.Items))}
	for _, it := range n.Items {
		c, err := compile(it, on)
		if err != nil {
			return Node{}, err
		}
		out.Items = append(out.Items, c)
	}
	return out, nil
}

// Satisfied reports whether the methods in have meet a compiled rule: a leaf
// when have holds it, "any" when some item is met, "all" when every item is.
// Anything that isn't a compiled rule (a family, an unknown leaf, an empty or
// unknown group) is never met.
func Satisfied(compiled Node, have map[Method]bool) bool {
	if compiled.isLeaf() {
		m := Method(compiled.Leaf)
		return rank(m) >= 0 && have[m]
	}
	if len(compiled.Items) == 0 {
		return false
	}
	switch compiled.Op {
	case OpAny:
		for _, it := range compiled.Items {
			if Satisfied(it, have) {
				return true
			}
		}
		return false
	case OpAll:
		for _, it := range compiled.Items {
			if !Satisfied(it, have) {
				return false
			}
		}
		return true
	}
	return false
}

// methodSet is a set of methods, bit i = Methods[i].
type methodSet uint8

// minimal drops duplicates and supersets of another set, keeping the order of
// first appearance.
func minimal(sets []methodSet) []methodSet {
	var out []methodSet
	for i, s := range sets {
		keep := true
		for j, o := range sets {
			if i == j {
				continue
			}
			if o&s == o && (o != s || j < i) { // o ⊆ s: s is redundant (first copy of equals kept)
				keep = false
				break
			}
		}
		if keep {
			out = append(out, s)
		}
	}
	return out
}

func alternatives(n Node) ([]methodSet, error) {
	if n.isLeaf() {
		r := rank(Method(n.Leaf))
		if r < 0 {
			return nil, fmt.Errorf("not a compiled rule: leaf %q", n.Leaf)
		}
		return []methodSet{1 << r}, nil
	}
	if len(n.Items) == 0 {
		return nil, errors.New("not a compiled rule: empty group")
	}
	switch n.Op {
	case OpAny:
		var out []methodSet
		for _, it := range n.Items {
			a, err := alternatives(it)
			if err != nil {
				return nil, err
			}
			out = minimal(append(out, a...))
		}
		return out, nil
	case OpAll:
		out := []methodSet{0}
		for _, it := range n.Items {
			a, err := alternatives(it)
			if err != nil {
				return nil, err
			}
			next := make([]methodSet, 0, len(out)*len(a))
			for _, x := range out {
				for _, y := range a {
					next = append(next, x|y)
				}
			}
			out = minimal(next)
		}
		return out, nil
	}
	return nil, fmt.Errorf("not a compiled rule: group kind %q", n.Op)
}

func (s methodSet) methods() []Method {
	var out []Method
	for i, m := range Methods {
		if s&(1<<i) != 0 {
			out = append(out, m)
		}
	}
	return out
}

// Alternatives returns a compiled rule's ways to be met: the minimal
// any-of-all-of form, in the rule's order, each alternative's methods in
// canonical order. A rule that isn't compiled is an error, and so are more
// than MaxAlternates alternatives.
func Alternatives(compiled Node) ([][]Method, error) {
	sets, err := alternatives(compiled)
	if err != nil {
		return nil, err
	}
	if len(sets) > MaxAlternates {
		return nil, fmt.Errorf("the rule has more than %d alternatives", MaxAlternates)
	}
	out := make([][]Method, 0, len(sets))
	for _, s := range sets {
		out = append(out, s.methods())
	}
	return out, nil
}

// Implies reports whether whoever meets compiled rule a meets compiled rule
// b: every alternative of a contains an alternative of b. An invalid rule
// implies nothing.
func Implies(a, b Node) bool {
	as, err := alternatives(a)
	if err != nil {
		return false
	}
	bs, err := alternatives(b)
	if err != nil {
		return false
	}
	for _, x := range as {
		if !slices.ContainsFunc(bs, func(y methodSet) bool { return x&y == y }) {
			return false
		}
	}
	return true
}

// NeedsCertificate reports whether every alternative of a compiled rule
// contains yubikey_cert or browser_cert, i.e. no way in without a client
// certificate. A rule that isn't compiled counts as needing one (the
// stricter answer for AI support and the TLS tier).
func NeedsCertificate(compiled Node) bool {
	sets, err := alternatives(compiled)
	if err != nil {
		return true
	}
	cert := methodSet(1<<rank(YubiKeyCert) | 1<<rank(BrowserCert))
	for _, s := range sets {
		if s&cert == 0 {
			return false
		}
	}
	return true
}

// Needs lists, in canonical order, the methods source rule n can't do
// without (D3): each direct method leaf, and the only switched-on member of
// a family it names.
func Needs(n Node, on map[Method]bool) []Method {
	need := map[Method]bool{}
	var walk func(n Node)
	walk = func(n Node) {
		if n.isLeaf() {
			if f, ok := families[n.Leaf]; ok {
				if ms := f.onMembers(on); len(ms) == 1 {
					need[ms[0]] = true
				}
				return
			}
			if rank(Method(n.Leaf)) >= 0 {
				need[Method(n.Leaf)] = true
			}
			return
		}
		for _, it := range n.Items {
			walk(it)
		}
	}
	walk(n)
	out := []Method{}
	for _, m := range Methods {
		if need[m] {
			out = append(out, m)
		}
	}
	return out
}
