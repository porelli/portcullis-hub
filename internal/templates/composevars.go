package templates

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// ComposeVarUse is where compose.yml references each variable (contract
// §11.9, apps Task 5 security fix): EnvOnly are referenced only inside
// services' environment: values, Outside anywhere else (keys included).
// Only a variable compose doesn't reference outside environment: may be
// env-overridden. Err: compose.yml doesn't parse or can't be walked
// (every override is refused).
type ComposeVarUse struct {
	EnvOnly map[string]bool
	Outside map[string]bool
	Err     string
}

// composeVarDepth bounds the walk's nesting (alias chains, deep
// documents); composeVarVisits bounds the nodes it visits (aliases
// can make a small file expand enormously). Either exceeded = Err.
const (
	composeVarDepth  = 256
	composeVarVisits = 100000
)

// ComposeVars walks the whole compose document: every scalar, in keys
// and values, aliases followed (in the context of the place that uses
// them), interpolation parsed (RefNames). A reference counts as inside
// environment only in the value part of services.<svc>.environment: a
// map value, or the part after the first "=" of a list item; a literal
// bare name (a list item "FOO", a map key "FOO" with no value) reads
// FOO from the environment, so FOO is environment too. Everything else
// is Outside: keys, a list item's name part, an item without "=" that
// holds a reference, labels, image, volumes, user, privileged, top-level
// sections, x- extensions, include, and the names compose reads from
// the environment by name outside a service's environment: (build args
// without a value, a secret's or config's environment: source). More
// than one YAML document, too deep or too large = Err. Never returns nil
// maps.
func ComposeVars(compose []byte) *ComposeVarUse {
	u := &ComposeVarUse{EnvOnly: map[string]bool{}, Outside: map[string]bool{}}
	dec := yaml.NewDecoder(bytes.NewReader(compose))
	var docs []*yaml.Node
	for {
		var d yaml.Node
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			u.Err = fmt.Sprintf("compose.yml: %v", err)
			return u
		}
		docs = append(docs, &d)
	}
	if len(docs) > 1 {
		u.Err = "compose.yml holds more than one YAML document"
		return u
	}
	w := &varWalk{outside: u.Outside, env: map[string]bool{}}
	for _, d := range docs {
		w.document(d)
	}
	if w.tooDeep {
		u.Err = "compose.yml is nested too deeply or too large to be checked"
		return u
	}
	for n := range w.env {
		if !u.Outside[n] {
			u.EnvOnly[n] = true
		}
	}
	return u
}

type varWalk struct {
	outside, env map[string]bool
	visits       int
	tooDeep      bool
}

// document walks the root: services' environment values in env
// context, everything else outside.
func (w *varWalk) document(doc *yaml.Node) {
	if doc.Kind == yaml.DocumentNode {
		for _, c := range doc.Content {
			w.document(c)
		}
		return
	}
	root := w.deref(doc, 0)
	if root == nil || root.Kind != yaml.MappingNode {
		w.node(doc, false, 0)
		return
	}
	// Names compose reads from the environment by name anywhere: a
	// secret's / config's environment: source (top-level or build).
	w.envSources(root, 0)
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		w.node(k, false, 1)
		if k.Value != "services" {
			w.node(v, false, 1)
			continue
		}
		svcs := w.deref(v, 1)
		if svcs == nil || svcs.Kind != yaml.MappingNode {
			w.node(v, false, 1)
			continue
		}
		for j := 0; j+1 < len(svcs.Content); j += 2 {
			w.node(svcs.Content[j], false, 2)
			s := w.deref(svcs.Content[j+1], 2)
			if s == nil || s.Kind != yaml.MappingNode {
				w.node(svcs.Content[j+1], false, 2)
				continue
			}
			for m := 0; m+1 < len(s.Content); m += 2 {
				sk, sv := s.Content[m], s.Content[m+1]
				w.node(sk, false, 3)
				switch sk.Value {
				case "environment":
					w.environment(sv, 3)
				case "build":
					w.buildArgs(sv, 3)
					w.node(sv, false, 3)
				default:
					w.node(sv, false, 3)
				}
			}
		}
	}
}

// environment walks a service's environment: map values and the value
// part of list items in env context, names outside — except a literal
// bare name, which reads that variable from the environment.
func (w *varWalk) environment(n *yaml.Node, depth int) {
	if w.spend(depth) {
		return
	}
	e := w.deref(n, depth)
	switch {
	case e == nil:
	case e.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(e.Content); i += 2 {
			k, v := e.Content[i], e.Content[i+1]
			if k.Value == "<<" {
				// A merge key: the merged map (or each of a list of them)
				// is an environment map too.
				if mv := w.deref(v, depth+1); mv != nil && mv.Kind == yaml.SequenceNode {
					for _, it := range mv.Content {
						w.environment(it, depth+1)
					}
				} else {
					w.environment(v, depth+1)
				}
				continue
			}
			w.node(k, false, depth+1)
			if dv := w.deref(v, depth+1); dv == nil || dv.Kind == yaml.ScalarNode && dv.Tag == "!!null" {
				// FOO: (no value): compose reads FOO from the environment.
				w.bareName(k.Value, true)
				continue
			}
			w.node(v, true, depth+1)
		}
	case e.Kind == yaml.SequenceNode:
		for _, it := range e.Content {
			w.envItem(it, depth+1)
		}
	default:
		w.node(e, false, depth+1)
	}
}

// envItem is one list-form environment item: NAME=VALUE (name part
// outside, value part environment), or NAME alone (a literal name reads
// it from the environment; any reference in it is outside).
func (w *varWalk) envItem(n *yaml.Node, depth int) {
	it := w.deref(n, depth)
	if it == nil || w.spend(depth) {
		return
	}
	if it.Kind != yaml.ScalarNode {
		w.node(it, false, depth)
		return
	}
	name, value, hasValue := strings.Cut(it.Value, "=")
	w.refs(name, false)
	if hasValue {
		w.refs(value, true)
		return
	}
	w.bareName(name, true)
}

// buildArgs: a build arg without a value (list "BASE", map "BASE:")
// reads BASE from the environment, and BASE may choose the image (FROM
// ${BASE}): outside.
func (w *varWalk) buildArgs(n *yaml.Node, depth int) {
	b := w.deref(n, depth)
	if b == nil || b.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(b.Content); i += 2 {
		if b.Content[i].Value != "args" {
			continue
		}
		args := w.deref(b.Content[i+1], depth+1)
		switch {
		case args == nil:
		case args.Kind == yaml.SequenceNode:
			for _, a := range args.Content {
				if a = w.deref(a, depth+2); a != nil && a.Kind == yaml.ScalarNode && !strings.Contains(a.Value, "=") {
					w.bareName(a.Value, false)
				}
			}
		case args.Kind == yaml.MappingNode:
			for j := 0; j+1 < len(args.Content); j += 2 {
				if v := w.deref(args.Content[j+1], depth+2); v == nil || v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
					w.bareName(args.Content[j].Value, false)
				}
			}
		}
	}
}

// envSources marks outside every name a mapping's environment: key
// names as a scalar, anywhere outside services.<svc>.environment: a
// top-level secret's or config's source, a build secret's.
func (w *varWalk) envSources(n *yaml.Node, depth int) {
	if w.spend(depth) {
		return
	}
	n = w.deref(n, depth)
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if dv := w.deref(v, depth+1); k.Value == "environment" && dv != nil && dv.Kind == yaml.ScalarNode {
				w.bareName(dv.Value, false)
				continue
			}
			w.envSources(v, depth+1)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			w.envSources(c, depth+1)
		}
	}
}

// bareName: s, a literal variable name compose reads from the
// environment, is env (true) or outside; anything else in s counts as
// outside references.
func (w *varWalk) bareName(s string, env bool) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "$") && EnvKeyRe.MatchString(s) {
		if env {
			w.env[s] = true
		} else {
			w.outside[s] = true
		}
		return
	}
	w.refs(s, false)
}

func (w *varWalk) refs(s string, env bool) {
	set := w.outside
	if env {
		set = w.env
	}
	for _, r := range RefNames(s) {
		set[r] = true
	}
}

// spend counts a visit; true = over budget or too deep (stop).
func (w *varWalk) spend(depth int) bool {
	w.visits++
	if w.visits > composeVarVisits || depth > composeVarDepth {
		w.tooDeep = true
	}
	return w.tooDeep
}

func (w *varWalk) deref(n *yaml.Node, depth int) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		if depth++; depth > composeVarDepth || w.spend(depth) {
			w.tooDeep = true
			return nil
		}
		n = n.Alias
	}
	return n
}

// node adds every reference under n (keys and values) to env or
// outside.
func (w *varWalk) node(n *yaml.Node, env bool, depth int) {
	if n == nil || w.spend(depth) {
		return
	}
	switch n.Kind {
	case yaml.ScalarNode:
		w.refs(n.Value, env)
	case yaml.AliasNode:
		w.node(n.Alias, env, depth+1)
	default:
		for _, c := range n.Content {
			w.node(c, env, depth+1)
		}
	}
}

// RefNames are the variables s references as compose interpolates it:
// $NAME, ${NAME} and ${NAME<op>…} (nested references in a default
// included); $$ is an escaped $.
func RefNames(s string) []string {
	var out []string
	isStart := func(c byte) bool { return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
	isName := func(c byte) bool { return isStart(c) || c >= '0' && c <= '9' }
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		switch c := s[i+1]; {
		case c == '$':
			i++
		case c == '{':
			j := i + 2
			for j < len(s) && isName(s[j]) {
				j++
			}
			if j > i+2 && isStart(s[i+2]) {
				out = append(out, s[i+2:j])
			}
			i = j - 1
		case isStart(c):
			j := i + 1
			for j < len(s) && isName(s[j]) {
				j++
			}
			out = append(out, s[i+1:j])
			i = j - 1
		}
	}
	return out
}
