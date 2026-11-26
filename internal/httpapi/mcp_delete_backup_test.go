package httpapi

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/hub"
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

// TestAIRetryOfNoBackupDeleteRefused (review I1): an administrator's
// no-backup delete that stopped part-way can't be finished through the
// AI channel: delete_instance (after its confirmation) is refused with a
// message that an administrator must finish it in the Hub; nothing
// changes; the route with "backup": false finishes it.
func TestAIRetryOfNoBackupDeleteRefused(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	// The files step fails: a non-empty directory where a file is removed.
	block := filepath.Join(e.data, "ops", "secretapp.hosts.json")
	if err := os.MkdirAll(filepath.Join(block, "x"), 0700); err != nil {
		t.Fatal(err)
	}
	if code, b := e.do(t, "root", "DELETE", "/api/instances/secretapp", `{"confirm":"secretapp","backup":false}`); code != 202 {
		t.Fatalf("delete = %d %s", code, b)
	}
	waitIdle(t, e.s.Hub, "secretapp")
	if r := e.s.Hub.LastOp("secretapp"); r == nil || r.OK {
		t.Fatalf("the delete didn't fail part-way: %+v", r)
	}
	v, ok := e.s.Hub.InstanceView("secretapp")
	if !ok || v.State != hub.StateDeleting {
		t.Fatalf("instance = %+v %v", v, ok)
	}
	os.RemoveAll(block)
	txt, isErr, _ := e.tool(t, "delete_instance", map[string]any{"id": "secretapp"})
	if !isErr || !strings.Contains(txt, "409") || !strings.Contains(txt, "started without a backup by an administrator") {
		t.Fatalf("delete_instance = %q %v, want the 409 refusal", txt, isErr)
	}
	waitIdle(t, e.s.Hub, "secretapp")
	if v, ok := e.s.Hub.InstanceView("secretapp"); !ok || v.State != hub.StateDeleting {
		t.Errorf("the refused AI retry changed the instance: %+v %v", v, ok)
	}
	if list, _ := e.s.Hub.ListBackups(""); len(list) != 0 {
		t.Errorf("archives = %+v", list)
	}
	// An administrator finishes it, saying "no backup" again.
	if code, b := e.do(t, "root", "DELETE", "/api/instances/secretapp", `{"confirm":"secretapp","backup":false}`); code != 202 {
		t.Fatalf("admin retry = %d %s", code, b)
	}
	waitIdle(t, e.s.Hub, "secretapp")
	if r := e.s.Hub.LastOp("secretapp"); r == nil || !r.OK || r.Result["no_backup"] != "true" {
		t.Fatalf("admin retry = %+v", r)
	}
}
