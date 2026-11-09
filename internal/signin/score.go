package signin

import "fmt"

// Score is a rule's strength out of 5, in tenths, with a one-line reason.
type Score struct {
	Tenths int
	Reason string
}

// String formats the score as "2.9 / 5".
func (s Score) String() string {
	return fmt.Sprintf("%d.%d / 5", s.Tenths/10, s.Tenths%10)
}

// Score rules (D4).
const (
	maxTenths   = 50 // 5.0
	perExtraAll = 4  // + 0.4 per extra part of an "all" group
)

// ScoreOf scores source rule n against the switched-on methods (D4): a
// method scores its strength, a family its weakest switched-on member (0
// when none is on), an "any" group its weakest item, an "all" group its
// strongest item + 0.4 per extra item, capped at 5.
func ScoreOf(n Node, on map[Method]bool) Score {
	t := scoreTenths(n, on)
	if n.isLeaf() || len(n.Items) == 0 {
		return Score{Tenths: t}
	}
	scores := make([]int, len(n.Items))
	for i, it := range n.Items {
		scores[i] = scoreTenths(it, on)
	}
	if n.Op == OpAny {
		w := 0
		for i, s := range scores {
			if s < scores[w] {
				w = i
			}
		}
		return Score{Tenths: t, Reason: "its weakest way in: " + Sentence(n.Items[w])}
	}
	b := 0
	for i, s := range scores {
		if s > scores[b] {
			b = i
		}
	}
	reason := fmt.Sprintf("its strongest part (%s) + 0.4 for each of %d more", Sentence(n.Items[b]), len(n.Items)-1)
	if scores[b]+perExtraAll*(len(n.Items)-1) > maxTenths {
		reason += ", capped at 5"
	}
	return Score{Tenths: t, Reason: reason}
}

func scoreTenths(n Node, on map[Method]bool) int {
	if n.isLeaf() {
		if f, ok := families[n.Leaf]; ok {
			ms := f.onMembers(on)
			if len(ms) == 0 {
				return 0
			}
			low := methodInfo[ms[0]].Tenths
			for _, m := range ms[1:] {
				low = min(low, methodInfo[m].Tenths)
			}
			return low
		}
		return methodInfo[Method(n.Leaf)].Tenths
	}
	if len(n.Items) == 0 {
		return 0
	}
	switch n.Op {
	case OpAny:
		low := scoreTenths(n.Items[0], on)
		for _, it := range n.Items[1:] {
			low = min(low, scoreTenths(it, on))
		}
		return low
	case OpAll:
		high := 0
		for _, it := range n.Items {
			high = max(high, scoreTenths(it, on))
		}
		return min(maxTenths, high+perExtraAll*(len(n.Items)-1))
	}
	return 0
}
