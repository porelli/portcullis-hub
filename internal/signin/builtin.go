package signin

// Template is a named rule (D12). Rule is the source rule (families allowed).
type Template struct {
	ID      string
	Name    string
	Rule    Node
	Enabled bool
	BuiltIn bool
}

// Builtins returns fresh copies of the four built-in templates (D12), in
// order: Basic and YubiKey + certificate start disabled, Standard (the
// default) and Strong enabled.
func Builtins() []Template {
	g := func(op string, leaves ...string) Node {
		n := Node{Op: op, Items: make([]Node, 0, len(leaves))}
		for _, l := range leaves {
			n.Items = append(n.Items, Node{Leaf: l})
		}
		return n
	}
	return []Template{
		{ID: "basic", Name: "Basic", Rule: g(OpAny, "family:passkey", "family:certificate", string(Password)), BuiltIn: true},
		{ID: "standard", Name: "Standard", Rule: g(OpAny, "family:passkey", "family:certificate"), Enabled: true, BuiltIn: true},
		{ID: "strong", Name: "Strong", Rule: g(OpAny, string(SecurityKey), string(YubiKeyCert)), Enabled: true, BuiltIn: true},
		{ID: "yubikey-and-certificate", Name: "YubiKey + certificate", Rule: g(OpAll, string(YubiKeyCert), string(SecurityKey)), BuiltIn: true},
	}
}
