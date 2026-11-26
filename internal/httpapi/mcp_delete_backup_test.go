package httpapi

import (
	"reflect"
	"strings"
	"testing"
)

// TestAIDeleteAlwaysBacksUp (user ruling 2026-11-26): the AI channel
// can't skip the delete's backup nor delete a backup. delete_instance
// takes no backup argument (any is refused before a confirmation or the
// Hub is reached), and no tool mirrors the backup-delete route.
func TestAIDeleteAlwaysBacksUp(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	var calls []string
	e.s.callHook = func(method string, args ...any) { calls = append(calls, method) }
	for _, args := range []map[string]any{
		{"id": "grafana", "backup": false},
		{"id": "grafana", "no_backup": true},
	} {
		txt, isErr := e.rawTool(t, "delete_instance", args)
		// Refused before anything (an undeclared argument is never
		// passed: the schema's refusal, or the secret guard's first).
		if !isErr || !(strings.Contains(txt, "invalid arguments") || strings.Contains(txt, "never passed through the AI")) || strings.Contains(txt, "confirm") {
			t.Errorf("delete_instance %v = %q %v, want a refusal", args, txt, isErr)
		}
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "StartDelete") || c == "DeleteBackup" {
			t.Errorf("a refused tool call reached the Hub: %v", calls)
		}
	}
	for _, scope := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range e.s.tools(scope) {
			for _, twin := range append([]string{tl.Twin}, tl.AlsoTwins...) {
				if strings.HasPrefix(twin, "DELETE /api/backups") {
					t.Errorf("tool %s mirrors %s: the AI channel must never delete a backup", tl.Name, twin)
				}
			}
			if tl.Name == "delete_instance" {
				in := reflect.TypeOf(tl.In)
				for i := 0; i < in.NumField(); i++ {
					if tag := in.Field(i).Tag.Get("json"); strings.Contains(tag, "backup") {
						t.Errorf("delete_instance's arguments offer %q", tag)
					}
				}
			}
		}
	}
}
