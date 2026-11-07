package mcpsdk

import (
	"context"
	"errors"
	"testing"
)

// Final review hub-mcp M2: when the caller can't be resolved, tools/call
// still reaches the tool (whose answer is a tool result); every other
// method gets the JSON-RPC error.
func TestAdminOnlyUnavailable(t *testing.T) {
	reached := ""
	next := func(_ context.Context, method string, _ Request) (Result, error) {
		reached = method
		return &CallToolResult{}, nil
	}
	h := AdminOnly(func(context.Context) (bool, error) { return false, errors.New("directory down") }, "unavailable")(next)
	if _, err := h(context.Background(), "tools/call", nil); err != nil || reached != "tools/call" {
		t.Errorf("tools/call = %v (reached %q)", err, reached)
	}
	reached = ""
	if _, err := h(context.Background(), MethodListTools, nil); err == nil || reached != "" {
		t.Errorf("tools/list = %v (reached %q), want the JSON-RPC error", err, reached)
	}
}
