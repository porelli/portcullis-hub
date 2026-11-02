package templates

// Hooks for the external test package (templates_test), which can import
// internal/settings without an import cycle.

// SetNilKinds makes a nil Kinds mean k for the rest of the test binary.
func SetNilKinds(k Kinds) { nilKinds = k }

// BuildForTest is build (one template from its manifest and compose).
var BuildForTest = build

// Fixture heads and composes of the internal tests.
const (
	HdrHead    = hdrHead
	HdrCompose = hdrCompose
)
