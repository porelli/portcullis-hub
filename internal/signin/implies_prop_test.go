package signin

import (
	"math/rand/v2"
	"testing"
)

// randomRule is a random source rule: nested all/any groups (up to 3
// levels) over methods and families.
func randomRule(r *rand.Rand, depth int) Node {
	leaves := []string{"password", "passkey_synced", "browser_cert", "passkey_device", "security_key", "yubikey_cert", "family:passkey", "family:yubikey", "family:certificate"}
	op := OpAny
	if r.IntN(2) == 0 {
		op = OpAll
	}
	n := Node{Op: op}
	seen := map[string]bool{}
	for range 1 + r.IntN(3) {
		if depth < 3 && r.IntN(3) == 0 {
			n.Items = append(n.Items, randomRule(r, depth+1))
			continue
		}
		l := leaves[r.IntN(len(leaves))]
		if !seen[l] {
			seen[l] = true
			n.Items = append(n.Items, Node{Leaf: l})
		}
	}
	return n
}

// TestImpliesProperty: for random compiled rules a, b under random
// switches, whenever Implies(a, b), every one of the 64 method sets that
// meets a meets b (the lockout guard skips its read on Implies).
func TestImpliesProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 2026))
	var sets []map[Method]bool
	for mask := range 1 << len(Methods) {
		h := map[Method]bool{}
		for i, m := range Methods {
			if mask&(1<<i) != 0 {
				h[m] = true
			}
		}
		sets = append(sets, h)
	}
	implied, checked := 0, 0
	for range 400 {
		on := map[Method]bool{}
		for _, m := range Methods {
			on[m] = r.IntN(4) != 0
		}
		var rules []Node
		for tries := 0; len(rules) < 8 && tries < 200; tries++ {
			src := randomRule(r, 1)
			if Validate(src) != nil {
				continue
			}
			c, err := Compile(src, on)
			if err != nil {
				continue
			}
			rules = append(rules, c)
		}
		for _, a := range rules {
			for _, b := range rules {
				checked++
				if !Implies(a, b) {
					continue
				}
				implied++
				for _, h := range sets {
					if Satisfied(a, h) && !Satisfied(b, h) {
						t.Fatalf("Implies(%s, %s) but %v meets only the first", Sentence(a), Sentence(b), h)
					}
				}
			}
		}
	}
	if implied < checked/20 {
		t.Errorf("only %d of %d pairs implied: the generator explores too little", implied, checked)
	}
}
