package state

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// yamlKeys are the YAML keys of struct type t's exported fields.
func yamlKeys(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	var keys []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			t.Fatalf("InstanceSettings.%s has no yaml name", f.Name)
		}
		keys = append(keys, name)
	}
	return keys
}

// e2e Hub bug 2: every InstanceSettings field is a key IsLegacySettings
// accepts — a new field can't be mistaken for the old flat form.
func TestInstanceSettingsKeysCoverEveryField(t *testing.T) {
	keys := yamlKeys(t, reflect.TypeOf(InstanceSettings{}))
	for _, k := range keys {
		if !instanceSettingsKeys[k] {
			t.Errorf("instanceSettingsKeys lacks %q (an InstanceSettings yaml key)", k)
		}
	}
	if len(instanceSettingsKeys) != len(keys) {
		t.Errorf("instanceSettingsKeys = %v, InstanceSettings' keys = %v", instanceSettingsKeys, keys)
	}
}

// fullSettings has every InstanceSettings field set (checked by
// reflection: a new field fails the tests until it is set here).
func fullSettings(t *testing.T) InstanceSettings {
	t.Helper()
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	s := InstanceSettings{
		Ports:    map[string]string{"SMB": "445", "SMB_BIND": "192.168.1.2"},
		Values:   map[string]any{"share1_writers": []any{"users_smb"}},
		Types:    map[string]string{"share1_writers": "groups"},
		Person:   map[string]PersonSetting{"quota": {Default: "1GiB", Rows: []GroupValue{{Group: "office", GroupID: 7, Value: "2GiB"}}}},
		Groups:   map[string][]GroupValue{"seats": {{Group: "office", GroupID: 7, Value: 3}}},
		Secrets:  map[string]SecretMeta{"api_key": {UpdatedAt: at, Generated: true}},
		Entered:  map[string]map[string]EnteredValue{"ext_id": {"alice": {Value: "a1", UUID: "u-1", UpdatedAt: at}}},
		GroupIDs: map[string]map[string]int{"share1_writers": {"users_smb": 12}},
	}
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Fatalf("fullSettings leaves InstanceSettings.%s unset", v.Type().Field(i).Name)
		}
	}
	return s
}

// Every field set: IsZero is false with any one field alone, Clone
// copies it, and the
// whole value survives Save + Load (which would refuse it as the old
// flat form if a key were missing).
func TestInstanceSettingsRoundTripEveryField(t *testing.T) {
	full := fullSettings(t)
	v := reflect.ValueOf(full)
	for i := 0; i < v.NumField(); i++ {
		var one InstanceSettings
		reflect.ValueOf(&one).Elem().Field(i).Set(v.Field(i))
		if one.IsZero() {
			t.Errorf("IsZero with only %s set", v.Type().Field(i).Name)
		}
	}
	if c := full.Clone(); !reflect.DeepEqual(c, full) {
		t.Errorf("Clone drops a field:\n got %+v\nwant %+v", c, full)
	}
	p := filepath.Join(t.TempDir(), "state.yaml")
	s := New()
	s.Settings["smb"] = full
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("Load of every field = %v", err)
	}
	if !reflect.DeepEqual(got.Settings["smb"], full) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got.Settings["smb"], full)
	}
	// One instance's settings node alone, as archives read it.
	b, err := yaml.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil {
		t.Fatal(err)
	}
	if IsLegacySettings(n.Content[0]) {
		t.Errorf("IsLegacySettings(every field) = true:\n%s", b)
	}
}
