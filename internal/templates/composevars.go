package templates

import (
	"fmt"

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

// composeVarDepth bounds the walk (alias chains, deep documents).
const composeVarDepth = 256

// ComposeVars walks the whole compose document: every scalar, in keys
// and values, aliases followed (in the context of the place that uses
// them), interpolation parsed (RefNames). A reference counts as inside
// environment only as a value of services.<svc>.environment (map form)
// or an item of it (list form); everything else — keys, labels, image,
// volumes, user, privileged, top-level sections, x- extensions, include
// — is Outside. Never returns nil maps.
func ComposeVars(compose []byte) *ComposeVarUse {
	u := &ComposeVarUse{EnvOnly: map[string]bool{}, Outside: map[string]bool{}}
	var doc yaml.Node
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		u.Err = fmt.Sprintf("compose.yml: %v", err)
		return u
	}
	w := &varWalk{outside: u.Outside, env: map[string]bool{}}
	w.document(&doc)
	if w.tooDeep {
		u.Err = "compose.yml is nested too deeply to be checked"
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
	tooDeep      bool
}

// document walks the root: services' environment values in env
// context, everything else outside.
func (w *varWalk) document(doc *yaml.Node) {
	root := doc
	if doc.Kind == yaml.DocumentNode {
		for _, c := range doc.Content {
			w.document(c)
		}
		return
	}
	root = w.deref(root, 0)
	if root == nil || root.Kind != yaml.MappingNode {
		w.node(doc, false, 0)
		return
	}
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
				if sk.Value != "environment" {
					w.node(sv, false, 3)
					continue
				}
				w.environment(sv, 3)
			}
		}
	}
}

// environment walks a service's environment: map values and list items
// in env context, map keys outside.
func (w *varWalk) environment(n *yaml.Node, depth int) {
	e := w.deref(n, depth)
	switch {
	case e == nil:
	case e.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(e.Content); i += 2 {
			k, v := e.Content[i], e.Content[i+1]
			if k.Value == "<<" {
				// A merge key: the merged map is an environment map too.
				w.environment(v, depth+1)
				continue
			}
			w.node(k, false, depth+1)
			w.node(v, true, depth+1)
		}
	case e.Kind == yaml.SequenceNode:
		for _, it := range e.Content {
			w.node(it, true, depth+1)
		}
	default:
		w.node(e, false, depth+1)
	}
}

func (w *varWalk) deref(n *yaml.Node, depth int) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		if depth++; depth > composeVarDepth {
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
	if n == nil || w.tooDeep {
		return
	}
	if depth > composeVarDepth {
		w.tooDeep = true
		return
	}
	switch n.Kind {
	case yaml.ScalarNode:
		set := w.outside
		if env {
			set = w.env
		}
		for _, r := range RefNames(n.Value) {
			set[r] = true
		}
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
