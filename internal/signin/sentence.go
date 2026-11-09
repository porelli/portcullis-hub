package signin

import "strings"

// Sentence writes source rule n in plain English: a method or family is its
// phrase; "all" joins its items with " and "; "any" with " or ", or with
// ", or " when one of its items is a group of several items; an "any" of
// several items inside an "all" is wrapped in parentheses. A group of one
// item reads as that item. For the rule as the switches leave it, pass
// Usable's result.
func Sentence(n Node) string {
	if n.isLeaf() {
		return phrase(n.Leaf)
	}
	if len(n.Items) == 1 {
		return Sentence(n.Items[0])
	}
	parts := make([]string, len(n.Items))
	multi := false
	for i, it := range n.Items {
		parts[i] = Sentence(it)
		if !it.isLeaf() && len(it.Items) > 1 {
			multi = true
			if n.Op == OpAll && it.Op == OpAny {
				parts[i] = "(" + parts[i] + ")"
			}
		}
	}
	if n.Op == OpAll {
		return strings.Join(parts, " and ")
	}
	if multi {
		return strings.Join(parts, ", or ")
	}
	return strings.Join(parts, " or ")
}

func phrase(leaf string) string {
	if f, ok := families[leaf]; ok {
		return f.phrase
	}
	if i, ok := methodInfo[Method(leaf)]; ok {
		return i.Phrase
	}
	return leaf
}
