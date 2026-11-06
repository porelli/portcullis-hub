package hub

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

var aiAdmin = directory.Human("root")

func ptr[T any](v T) *T { return &v }

// TestAISettingsDefaultsAndBounds (contract §15.11): a new install's
// values, the bounds (400, audited refused), a save audited settings.ai
// with the changed keys only, an unchanged save not audited, persisted.
func TestAISettingsDefaultsAndBounds(t *testing.T) {
	f := newInstanceFixture(t, nil)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)

	v := f.h.AISettings()
	want := AISettingsView{
		Clients: state.AIClients{
			Claude:     state.AIClient{Offered: true},
			ClaudeCode: state.AIClient{Offered: true},
			Generic:    state.AIClient{Offered: true},
		},
		PortcullisAdmin: true, PortcullisPeople: true, OfflineIdleDays: 7, OfflineMaxDays: 30,
		Limits: state.AILimits{ResourceRPM: 120, ResourceBurst: 30, PersonRPM: 600, ToolCallsRPM: 60,
			ConfirmationsPerHour: 10, MintsPerMinute: 10, Fanout: 4},
		AllowedOrigins: []string{},
	}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("defaults =\n%+v\nwant\n%+v", v, want)
	}

	// gate_present follows the recipient file.
	rec := filepath.Join(t.TempDir(), "age.pub")
	f.h.cfg.MCPGateRecipientFile = rec
	if f.h.AISettings().GatePresent {
		t.Error("gate_present without the recipient file")
	}
	os.WriteFile(rec, []byte("age1xyz\n"), 0640)
	if !f.h.AISettings().GatePresent {
		t.Error("gate_present false with the recipient file")
	}

	bad := map[string]AISettingsUpdate{
		"idle 0":           {OfflineIdleDays: ptr(0)},
		"idle 31":          {OfflineIdleDays: ptr(31)},
		"max 0":            {OfflineMaxDays: ptr(0)},
		"max 91":           {OfflineMaxDays: ptr(91)},
		"idle > max":       {OfflineIdleDays: ptr(20), OfflineMaxDays: ptr(10)},
		"fanout 5":         {Limits: &AILimitsUpdate{Fanout: ptr(5)}},
		"rpm 0":            {Limits: &AILimitsUpdate{ResourceRPM: ptr(0)}},
		"origin http":      {AllowedOrigins: &[]string{"http://claude.ai"}},
		"origin path":      {AllowedOrigins: &[]string{"https://claude.ai/"}},
		"origin user":      {AllowedOrigins: &[]string{"https://u@claude.ai"}},
		"origin query":     {AllowedOrigins: &[]string{"https://claude.ai?x"}},
		"origin port 0":    {AllowedOrigins: &[]string{"https://claude.ai:0"}},
		"origin bare":      {AllowedOrigins: &[]string{"claude.ai"}},
		"origin empty":     {AllowedOrigins: &[]string{"https://"}},
		"origin twice":     {AllowedOrigins: &[]string{"https://claude.ai", "https://CLAUDE.ai"}},
		"origin bad host":  {AllowedOrigins: &[]string{"https://exa mple.org"}},
		"origin fragment":  {AllowedOrigins: &[]string{"https://claude.ai#x"}},
		"origin empty prt": {AllowedOrigins: &[]string{"https://claude.ai:"}},
	}
	for name, u := range bad {
		if err := f.h.SaveAISettings(u, aiAdmin); statusOf(err) != 400 {
			t.Errorf("%s: err = %v, want 400", name, err)
		}
	}
	if n := len(audit.entries); n != len(bad) {
		t.Fatalf("%d audit entries for %d refusals", n, len(bad))
	}
	for _, e := range audit.entries {
		if e.Action != "settings.ai" || e.Result != "refused" || e.Actor != "root" {
			t.Errorf("refusal audit = %+v", e)
		}
	}
	if !reflect.DeepEqual(f.h.AISettings().Limits, want.Limits) || f.h.AISettings().OfflineIdleDays != 7 {
		t.Fatal("a refused save changed the settings")
	}
	if err := f.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(true)}, directory.Actor{}); statusOf(err) != 401 {
		t.Errorf("no actor = %v, want 401", err)
	}

	n := len(audit.entries)
	err := f.h.SaveAISettings(AISettingsUpdate{
		Enabled:         ptr(true),
		Clients:         &AIClientsUpdate{Claude: &AIClientUpdate{Admin: ptr(true)}, Generic: &AIClientUpdate{Offered: ptr(false)}},
		OfflineIdleDays: ptr(14),
		Limits:          &AILimitsUpdate{Fanout: ptr(2)},
		AllowedOrigins:  &[]string{"https://x.example.org:8443", "https://Claude.AI"},
		PortcullisAdmin: ptr(true), // unchanged: not a changed key
	}, aiAdmin)
	if err != nil {
		t.Fatal(err)
	}
	got := f.h.AISettings()
	if !got.Enabled || !got.Clients.Claude.Admin || !got.Clients.Claude.Offered || got.Clients.Generic.Offered ||
		got.Clients.ClaudeCode.Admin || got.OfflineIdleDays != 14 || got.OfflineMaxDays != 30 || got.Limits.Fanout != 2 ||
		got.Limits.ResourceRPM != 120 || strings.Join(got.AllowedOrigins, ",") != "https://claude.ai,https://x.example.org:8443" {
		t.Fatalf("saved = %+v", got)
	}
	if len(audit.entries) != n+1 {
		t.Fatalf("audit entries %d, want %d", len(audit.entries), n+1)
	}
	e := audit.last()
	if e.Action != "settings.ai" || e.Result != "ok" || e.Actor != "root" {
		t.Fatalf("audit = %+v", e)
	}
	for _, k := range []string{"enabled: false -> true", "clients.claude.admin: false -> true", "clients.generic.offered: true -> false",
		"offline_idle_days: 7 -> 14", "limits.fanout: 4 -> 2", "allowed_origins: [] -> [https://claude.ai https://x.example.org:8443]"} {
		if !strings.Contains(e.Detail, k) {
			t.Errorf("detail %q lacks %q", e.Detail, k)
		}
	}
	for _, k := range []string{"portcullis_admin", "offline_max_days", "claude_code", "resource_rpm"} {
		if strings.Contains(e.Detail, k) {
			t.Errorf("detail %q names the unchanged %s", e.Detail, k)
		}
	}
	// The same values again: nothing changed, nothing audited.
	if err := f.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(true), OfflineIdleDays: ptr(14)}, aiAdmin); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != n+1 {
		t.Errorf("an unchanged save was audited: %+v", audit.last())
	}
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.AI.Enabled || st.AI.OfflineIdleDays != 14 || !st.AI.Clients.Claude.Admin || len(st.AI.AllowedOrigins) != 2 {
		t.Errorf("persisted = %+v", st.AI)
	}
}
