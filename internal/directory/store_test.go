package directory

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/rules"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Path: filepath.Join(dir, "directory.yaml")}

	// Build a config with one field of each kind
	expiryTime := time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC)
	exceptionTime := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	// Parse a rule for the rule group
	ruleExpr, err := rules.Parse(`department = "Engineering"`)
	if err != nil {
		t.Fatalf("failed to parse rule: %v", err)
	}

	cfg := &Config{
		Version: 1,
		Fields: []Field{
			{
				Name:  "department",
				Label: "Department",
				Kind:  "text",
			},
			{
				Name:   "role_tags",
				Label:  "Role Tags",
				Kind:   "list",
				Values: []string{"developer", "manager", "designer"},
				Multi:  true,
			},
			{
				Name:  "manager",
				Label: "Manager",
				Kind:  "person",
			},
		},
		Groups: map[string]*GroupConfig{
			"engineering": {
				Rule: ruleExpr,
				Exceptions: []Exception{
					{
						User:    "alice",
						Reason:  "contractor ending",
						By:      "bob",
						Include: false,
						Until:   &expiryTime,
						At:      exceptionTime,
					},
				},
			},
			"manual_group": {
				Rule: nil,
				Expiry: map[string]time.Time{
					"charlie": expiryTime,
				},
			},
		},
		Permissions: map[string]string{
			"edit_details": "admins",
		},
		CreatedBy: map[string]string{
			"alice": "bob",
		},
	}

	// Save
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Deep equal check
	if !reflect.DeepEqual(cfg, loaded) {
		t.Errorf("loaded config does not match saved config.\nExpected: %+v\nGot: %+v", cfg, loaded)
	}
}

func TestStoreMissingIsEmpty(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Path: filepath.Join(dir, "nonexistent.yaml")}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load on missing file should not error, got: %v", err)
	}

	expected := &Config{
		Version:     1,
		Fields:      []Field{},
		Groups:      map[string]*GroupConfig{},
		Permissions: map[string]string{},
		CreatedBy:   map[string]string{},
	}

	if !reflect.DeepEqual(cfg, expected) {
		t.Errorf("missing file should return empty config.\nExpected: %+v\nGot: %+v", expected, cfg)
	}
}

func TestStoreCorruptRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.yaml")
	store := &Store{Path: path}

	// Write garbage YAML
	if err := os.WriteFile(path, []byte("this is: not: valid: yaml: {{{}"), 0600); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	_, err := store.Load()
	if err == nil {
		t.Fatal("Load should fail on corrupt YAML")
	}

	// Error should mention the path
	if err.Error() == "" || !contains(err.Error(), path) {
		t.Errorf("error should mention path %q, got: %v", path, err)
	}
}

func TestStoreUnknownVersionRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badversion.yaml")
	store := &Store{Path: path}

	// Write YAML with version 2
	if err := os.WriteFile(path, []byte("version: 2\n"), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := store.Load()
	if err == nil {
		t.Fatal("Load should fail on unknown version")
	}

	// Error should mention version
	if !contains(err.Error(), "version") {
		t.Errorf("error should mention version, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && anySubstring(s, substr))
}

func anySubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
