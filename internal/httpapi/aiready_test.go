package httpapi

import "github.com/portcullis/hub/internal/hub"

// Hooks that run right after a compose up run once, as before the
// readiness wait (hub's ai_ready.go): these tests fail hooks on purpose
// and want that failure at once.
func init() { hub.SetAIReadyWaitForTest(0) }
