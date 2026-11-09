package signin

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
)

// vectorFile is testdata/vectors.json, which group-gate, mcp-gate and the
// Keycloak extension copy byte for byte. Readers use "compiled" only; "have"
// holds amr values, mapped through the method table (inv and unknown values
// count as nothing); "alternatives" compare as a set of sets.
type vectorFile struct {
	Version int          `json:"version"`
	Cases   []vectorCase `json:"cases"`
}

type vectorCase struct {
	Name         string     `json:"name"`
	Rule         Node       `json:"rule"`
	On           []Method   `json:"on"`
	Compiled     *Node      `json:"compiled,omitempty"`
	Error        string     `json:"error,omitempty"`
	Have         *[]string  `json:"have,omitempty"`
	Satisfied    *bool      `json:"satisfied,omitempty"`
	Alternatives [][]Method `json:"alternatives,omitempty"`
}

func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f vectorFile
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 {
		t.Fatalf("version %d", f.Version)
	}
	if len(f.Cases) < 25 {
		t.Fatalf("%d cases, want at least 25", len(f.Cases))
	}
	names := map[string]bool{}
	sawInv := false
	for _, c := range f.Cases {
		if names[c.Name] {
			t.Errorf("duplicate case name %q", c.Name)
		}
		names[c.Name] = true
		if c.Have != nil && slices.Contains(*c.Have, "inv") {
			sawInv = true
		}
		if !slices.IsSortedFunc(c.On, func(a, b Method) int { return rank(a) - rank(b) }) {
			t.Errorf("%s: on not in canonical order", c.Name)
		}
		on := onSet(c.On...)
		got, err := Compile(c.Rule, on)
		if c.Error != "" {
			if c.Error != "unmeetable" || c.Compiled != nil || c.Have != nil || c.Satisfied != nil || c.Alternatives != nil {
				t.Errorf("%s: an error case carries only error \"unmeetable\"", c.Name)
			}
			if !errors.Is(err, ErrUnmeetable) {
				t.Errorf("%s: Compile = %s, %v; want unmeetable", c.Name, js(got), err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Compile: %v", c.Name, err)
			continue
		}
		if c.Compiled == nil || c.Have == nil || c.Satisfied == nil || c.Alternatives == nil {
			t.Errorf("%s: compiled, have, satisfied and alternatives are required", c.Name)
			continue
		}
		if js(got) != js(*c.Compiled) {
			t.Errorf("%s: compiled %s, file has %s", c.Name, js(got), js(*c.Compiled))
		}
		if err := checkCompiledShape(*c.Compiled); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		have := map[Method]bool{}
		for _, a := range *c.Have {
			if m, ok := MethodForAMR(a); ok {
				have[m] = true
			}
		}
		if s := Satisfied(*c.Compiled, have); s != *c.Satisfied {
			t.Errorf("%s: Satisfied(%v) = %v, want %v", c.Name, *c.Have, s, *c.Satisfied)
		}
		alts, err := Alternatives(*c.Compiled)
		if err != nil {
			t.Errorf("%s: Alternatives: %v", c.Name, err)
			continue
		}
		if !sameSetOfSets(alts, c.Alternatives) {
			t.Errorf("%s: alternatives %v, want %v", c.Name, alts, c.Alternatives)
		}
		// Satisfied agrees with the alternatives.
		met := false
		for _, a := range alts {
			if !slices.ContainsFunc(a, func(m Method) bool { return !have[m] }) {
				met = true
			}
		}
		if met != *c.Satisfied {
			t.Errorf("%s: alternatives say met=%v", c.Name, met)
		}
	}
	if !sawInv {
		t.Error(`no case with "have": ["inv"]`)
	}
}

// checkCompiledShape is the readers' check: no families, depth ≤ 4, ≤ 48 leaves.
func checkCompiledShape(n Node) error {
	leaves := 0
	var walk func(n Node, depth int) error
	walk = func(n Node, depth int) error {
		if n.Op == "" {
			if _, ok := InfoOf(Method(n.Leaf)); !ok {
				return errors.New("compiled leaf " + n.Leaf)
			}
			leaves++
			return nil
		}
		if depth > 4 {
			return errors.New("compiled depth over 4")
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
	if leaves > 48 {
		return errors.New("over 48 compiled leaves")
	}
	return nil
}

func sameSetOfSets(a, b [][]Method) bool {
	key := func(s []Method) string {
		c := slices.Clone(s)
		slices.Sort(c)
		c = slices.Compact(c)
		var buf bytes.Buffer
		for _, m := range c {
			buf.WriteString(string(m) + ",")
		}
		return buf.String()
	}
	set := func(x [][]Method) map[string]bool {
		m := map[string]bool{}
		for _, s := range x {
			m[key(s)] = true
		}
		return m
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}
