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

	doc := BuildUserAttributes(fields, users)

	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
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

	if parsed["version"] != float64(1) {
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
	doc := BuildUserAttributes([]AttrField{}, map[string]map[string][]string{})
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

	doc := BuildUserAttributes(fields, users)
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

	doc = BuildUserAttributes(fields, users)
	if vals, ok := doc.Users["user1"]["field1"]; ok && len(vals) > 0 {
		t.Errorf("large value not dropped: len = %d", len(vals[0]))
	}
}
