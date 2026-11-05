package hub

import (
	"reflect"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/state"
)

// fullInstanceSettings has every InstanceSettings field set (checked by
// reflection: a new field fails the test until it is set here).
func fullInstanceSettings(t *testing.T) state.InstanceSettings {
	t.Helper()
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	s := state.InstanceSettings{
		Ports:    map[string]string{"GRAFANA_PORT": "3301"},
		Values:   map[string]any{"share1_writers": []any{"users_smb"}},
		Types:    map[string]string{"share1_writers": "groups"},
		Person:   map[string]state.PersonSetting{"quota": {Default: "1GiB", Rows: []state.GroupValue{{Group: "office", GroupID: 7, Value: "2GiB"}}}},
		Groups:   map[string][]state.GroupValue{"seats": {{Group: "office", GroupID: 7, Value: 3}}},
		Secrets:  map[string]state.SecretMeta{"api_key": {UpdatedAt: at, Generated: true}},
		Entered:  map[string]map[string]state.EnteredValue{"ext_id": {"alice": {Value: "a1", UUID: "u-1", UpdatedAt: at}}},
		GroupIDs: map[string]map[string]int{"share1_writers": {"users_smb": 12}},
	}
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Fatalf("fullInstanceSettings leaves InstanceSettings.%s unset", v.Type().Field(i).Name)
		}
	}
	return s
}

// e2e Hub bug 2: an instance archive whose settings set every
// InstanceSettings field (group_ids included) is staged, never refused as
// the old flat form.
func TestStageArchiveEveryInstanceSettingsField(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", "root")
	if err != nil {
		t.Fatal(err)
	}
	p := archivePath(f, entry.Archive)
	_, data, _ := readArchive(t, p)
	var cfg instanceConfig
	if err := yaml.Unmarshal(data["config/instance.yaml"], &cfg); err != nil {
		t.Fatal(err)
	}
	full := fullInstanceSettings(t)
	cfg.Settings = &full
	b, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rewriteMember(t, p, "config/instance.yaml", b)
	sb, err := f.h.stageArchive(entry.Archive)
	if err != nil {
		t.Fatalf("stageArchive(every field) = %v\n%s", err, b)
	}
	defer sb.cleanup()
	if sb.cfg.Settings == nil || !reflect.DeepEqual(*sb.cfg.Settings, full) {
		t.Errorf("staged settings = %+v, want %+v", sb.cfg.Settings, full)
	}
}

// The e2e path: a saved share group (group_ids stored) survives a backup
// and a same-instance restore, and state.yaml still loads.
func TestRestoreWithShareGroupBinding(t *testing.T) {
	c := credSvcFixture(t)
	shareSetup(t, c)
	f := c.f
	f.h.mu.RLock()
	ids := f.h.st.Settings[smbID].GroupIDs
	f.h.mu.RUnlock()
	if len(ids["share1_writers"]) == 0 {
		t.Fatalf("no group_ids stored: %+v", ids)
	}
	if _, err := state.Load(f.h.statePath()); err != nil {
		t.Fatalf("state.yaml with group_ids = %v", err)
	}
	entry, err := f.h.BackupInstance(smbID, "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstance(smbID, entry.Archive, "root"); err != nil {
		t.Fatalf("restore of its own archive = %v", err)
	}
	f.h.mu.RLock()
	got := f.h.st.Settings[smbID].GroupIDs
	f.h.mu.RUnlock()
	if !reflect.DeepEqual(got, ids) {
		t.Errorf("group_ids after restore = %v, want %v", got, ids)
	}
}
