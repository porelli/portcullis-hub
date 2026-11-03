package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUserAttributesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user-attributes.json")

	// Test case: multiple fields, multiple users, multi-valued fields
	fields := []AttrField{
		{Name: "department", Multi: false},
		{Name: "cost_center", Multi: false},
		{Name: "office_location", Multi: true},
	}

	users := map[string]map[string][]string{
		"jsmith": {
			"department":      {"Engineering"},
			"cost_center":     {"CC-1234"},
			"office_location": {"Milan"},
		},
		"alee": {
			"department":      {"HR", "Operations"}, // multi-valued
			"office_location": {"Berlin"},
			// cost_center missing
		},
	}

	doc := BuildUserAttributes(fields, users, nil)

	if doc.Version != 2 {
		t.Errorf("version = %d, want 2", doc.Version)
	}

	// Check header name derivation
	wantFields := map[string]string{
		"department":      "Department",
		"cost_center":     "Cost-Center",
		"office_location": "Office-Location",
	}
	if !reflect.DeepEqual(doc.Fields, wantFields) {
		t.Errorf("fields = %+v, want %+v", doc.Fields, wantFields)
	}

	// Check user attributes
	if len(doc.Users) != 2 {
		t.Errorf("users count = %d, want 2", len(doc.Users))
	}

	jsmith := doc.Users["jsmith"]
	if !reflect.DeepEqual(jsmith["department"], []string{"Engineering"}) {
		t.Errorf("jsmith department = %+v", jsmith["department"])
	}
	if !reflect.DeepEqual(jsmith["cost_center"], []string{"CC-1234"}) {
		t.Errorf("jsmith cost_center = %+v", jsmith["cost_center"])
	}

	alee := doc.Users["alee"]
	if !reflect.DeepEqual(alee["department"], []string{"HR", "Operations"}) {
		t.Errorf("alee department = %+v", alee["department"])
	}
	if _, has := alee["cost_center"]; has {
		t.Error("alee should not have cost_center")
	}

	// Write and verify file
	if err := WriteUserAttributes(path, doc); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}

	// Verify JSON structure
	data, _ := os.ReadFile(path)
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed["version"] != float64(2) {
		t.Errorf("parsed version = %v", parsed["version"])
	}

	fields2 := parsed["fields"].(map[string]interface{})
	if fields2["cost_center"] != "Cost-Center" {
		t.Errorf("cost_center header = %v", fields2["cost_center"])
	}

	users2 := parsed["users"].(map[string]interface{})
	jsmith2 := users2["jsmith"].(map[string]interface{})
	dept := jsmith2["department"].([]interface{})
	if dept[0] != "Engineering" {
		t.Errorf("jsmith department[0] = %v", dept[0])
	}
}

func TestHeaderNameDerivation(t *testing.T) {
	cases := []struct {
		field string
		want  string
	}{
		{"department", "Department"},
		{"cost_center", "Cost-Center"},
		{"office_location", "Office-Location"},
		{"a", "A"},
		{"a_b_c", "A-B-C"},
	}

	for _, c := range cases {
		got := fieldToHeader(c.field)
		if got != c.want {
			t.Errorf("fieldToHeader(%q) = %q, want %q", c.field, got, c.want)
		}
	}
}

func TestUserAttributesEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user-attributes.json")

	// Empty fields and users
	doc := BuildUserAttributes([]AttrField{}, map[string]map[string][]string{}, nil)
	if err := WriteUserAttributes(path, doc); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"fields": {}`) {
		t.Errorf("empty fields not serialized as {}: %s", string(data))
	}
	if !strings.Contains(string(data), `"users": {}`) {
		t.Errorf("empty users not serialized as {}: %s", string(data))
	}
}

func TestControlCharsAndLargeValues(t *testing.T) {
	fields := []AttrField{{Name: "field1", Multi: false}}

	// Control chars should be stripped
	users := map[string]map[string][]string{
		"user1": {
			"field1": {"hello\nworld\x00test"},
		},
	}

	doc := BuildUserAttributes(fields, users, nil)
	cleaned := doc.Users["user1"]["field1"][0]
	if strings.Contains(cleaned, "\n") || strings.Contains(cleaned, "\x00") {
		t.Errorf("control chars not stripped: %q", cleaned)
	}
	if cleaned != "helloworldtest" {
		t.Errorf("cleaned value = %q, want %q", cleaned, "helloworldtest")
	}

	// Values > 1KB should be dropped
	largeValue := strings.Repeat("a", 1025)
	users = map[string]map[string][]string{
		"user1": {
			"field1": {largeValue},
		},
	}

	doc = BuildUserAttributes(fields, users, nil)
	if vals, ok := doc.Users["user1"]["field1"]; ok && len(vals) > 0 {
		t.Errorf("large value not dropped: len = %d", len(vals[0]))
	}
}

// TestUserAttributesV2: version 2 with a hosts section (contract §4.1):
// always an object; host keys lowercase; header keys are the suffix after
// X-Forwarded-Attr- (what group-gate prefixes); users lowercase; values
// control-stripped, over 1 KB dropped.
func TestUserAttributesV2(t *testing.T) {
	empty := BuildUserAttributes(nil, nil, nil)
	b, _ := json.Marshal(empty)
	if empty.Version != 2 || !strings.Contains(string(b), `"hosts":{}`) {
		t.Errorf("empty document = %s, want version 2 and hosts {}", b)
	}
	doc := BuildUserAttributes(nil, nil, map[string]map[string]map[string]string{
		"Grafana.Team-B.Example.org": {
			"Grafana-Role": {"Alice": "Ad\x00m\nin", "bob": "Editor", "carol": strings.Repeat("a", 1025), "dave": "\x01"},
			"Empty":        {},
		},
		"bare.example.org": {},
	})
	host, ok := doc.Hosts["grafana.team-b.example.org"]
	if !ok || len(doc.Hosts) != 1 {
		t.Fatalf("hosts = %+v, want only grafana.team-b.example.org", doc.Hosts)
	}
	want := map[string]string{"alice": "Admin", "bob": "Editor"}
	if !reflect.DeepEqual(host["Grafana-Role"], want) {
		t.Errorf("Grafana-Role = %+v, want %+v", host["Grafana-Role"], want)
	}
	// A declared header without values stays (on that host it replaces a
	// same-named field header for everybody).
	if v, ok := host["Empty"]; !ok || len(v) != 0 {
		t.Errorf("Empty = %+v %v, want declared and empty", v, ok)
	}
	// Header names group-gate would refuse, or that collide case-
	// insensitively (it would drop the whole file), are left out.
	doc = BuildUserAttributes(nil, nil, map[string]map[string]map[string]string{
		"a.example.org": {"Bad--Name": {"x": "1"}, "X-Forwarded-Attr-Full": {"x": "1"}, "Role": {"x": "1"}, "ROLE": {"x": "2"}},
	})
	if got := doc.Hosts["a.example.org"]; len(got) != 1 || got["ROLE"]["x"] != "2" {
		t.Errorf("headers = %+v, want only ROLE (sorted first of the collision)", got)
	}
	// Two spellings of one user: one value (group-gate refuses duplicates).
	doc = BuildUserAttributes(nil, nil, map[string]map[string]map[string]string{
		"a.example.org": {"Role": {"Alice": "1", "alice": "2"}},
	})
	if got := doc.Hosts["a.example.org"]["Role"]; len(got) != 1 {
		t.Errorf("Role = %+v, want one alice", got)
	}
	data, _ := json.Marshal(doc)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil || parsed["version"] != float64(2) {
		t.Errorf("parsed = %v (%v)", parsed, err)
	}
}
