package hub

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// G5: ai hooks (when: [ai]) are never run by the settings delivery
// engine — not on start, not on a save, not on the panel's Retry (which
// forces every other hook) — and their input is never built.
func TestRetryRunsNoAIHook(t *testing.T) {
	const id = "aiapp"
	dir := filepath.Join("..", "templates", "testdata", "ai", "companion")
	m := mustRead(t, filepath.Join(dir, "manifest.yaml"))
	c := mustRead(t, filepath.Join(dir, "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{id: {string(m), string(c)}})
	if f.h.Template(id) == nil {
		t.Fatalf("aiapp not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople()
	people.addGroup("users_companion", "alice")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_companion": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc = clk.afterFunc
	f.h.sleep = clk.sleep
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if _, err := f.h.SaveSettings(id, SettingsUpdate{Values: map[string]json.RawMessage{"motd": json.RawMessage(`"hi"`)}}, directory.Human("admin")); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	rep, err := f.h.RetryDeliveries(context.Background(), id, directory.Human("admin"))
	if err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	applied := 0
	for _, call := range f.engine.ExecCalls() {
		switch call.in.Cmd[0] {
		case "/mint", "/revoke":
			t.Errorf("the settings engine ran ai hook %v", call.in.Cmd)
		case "/apply":
			applied++
		}
	}
	if applied < 2 {
		t.Errorf("apply ran %d times, want start + retry at least (the engine ran)", applied)
	}
	for _, u := range rep.Units {
		if u.Unit == "hook:mcp-mint" || u.Unit == "hook:mcp-revoke" {
			t.Errorf("retry reported ai hook unit %s", u.Unit)
		}
	}
	for u := range f.h.DeliveryStatus(id).Units {
		if u == "hook:mcp-mint" || u == "hook:mcp-revoke" {
			t.Errorf("delivery status lists ai hook unit %s", u)
		}
	}
}
