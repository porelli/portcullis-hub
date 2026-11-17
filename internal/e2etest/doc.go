// Package e2etest holds core's CI-only end-to-end test hooks (core T19).
// They exist only in binaries built with -tags e2etest (the images'
// GO_TAGS build argument; empty by default): a default build has no hook
// code, and a hook's environment variable set on it refuses the start.
//
//   - HUB_DEV_CLOCK_OFFSET_FILE names a file holding a Go duration
//     ("16m") that is added to the Hub's clock, re-read at most once a
//     second (missing or empty: 0; unparsable: logged once, 0);
//   - AGENT_TEST_OVERSIZE_INFO=1 pads the agent's /v1/info past 64 KiB.
package e2etest

// The hooks' environment variables.
const (
	EnvClockOffset  = "HUB_DEV_CLOCK_OFFSET_FILE"
	EnvOversizeInfo = "AGENT_TEST_OVERSIZE_INFO"
)
