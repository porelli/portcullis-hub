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
		Deleted: map[string]time.Time{"carol": exceptionTime},
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
		Deleted:     map[string]time.Time{},
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

func TestStoreUnknownKeyRefuses(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string // substring that should appear in error
	}{
		{
			name: "unknown key under group",
			yaml: `version: 1
groups:
  sales:
    exceptionsss:
      - user: alice
`,
			want: "exceptionsss",
		},
		{
			name: "unknown key under exception",
			yaml: `version: 1
groups:
  sales:
    exceptions:
      - user: alice
        reasonnn: "typo"
        by: bob
        include: false
        at: 2026-11-01T12:00:00Z
`,
			want: "reasonnn",
		},
		{
			name: "unknown key under field",
			yaml: `version: 1
fields:
  - name: department
    label: Department
    kindd: text
`,
			want: "kindd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "test.yaml")
			store := &Store{Path: path}

			if err := os.WriteFile(path, []byte(tt.yaml), 0600); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}

			_, err := store.Load()
			if err == nil {
				t.Fatal("Load should fail on unknown key")
			}

			if !contains(err.Error(), tt.want) {
				t.Errorf("error should mention %q, got: %v", tt.want, err)
			}
		})
	}
}

func TestStoreTimesNormalizedToUTC(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Path: filepath.Join(dir, "directory.yaml")}

	// Create times in non-UTC zone
	cet := time.FixedZone("CET", 3600)
	expiryTime := time.Date(2027, 3, 31, 1, 0, 0, 0, cet)     // 01:00 CET = 00:00 UTC
	exceptionTime := time.Date(2026, 11, 1, 13, 0, 0, 0, cet) // 13:00 CET = 12:00 UTC

	ruleExpr, err := rules.Parse(`department = "Sales"`)
	if err != nil {
		t.Fatalf("failed to parse rule: %v", err)
	}

	cfg := &Config{
		Version: 1,
		Fields:  []Field{},
		Groups: map[string]*GroupConfig{
			"sales": {
				Rule: ruleExpr,
				Exceptions: []Exception{
					{
						User:    "alice",
						Reason:  "test",
						By:      "bob",
						Include: false,
						Until:   &expiryTime,
						At:      exceptionTime,
					},
				},
			},
			"manual": {
				Rule: nil,
				Expiry: map[string]time.Time{
					"charlie": expiryTime,
				},
			},
		},
		Permissions: map[string]string{},
		CreatedBy:   map[string]string{},
	}

	// Save
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Check that saved file contains Z timestamps
	data, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}

	content := string(data)
	if !contains(content, "Z") {
		t.Errorf("saved file should contain Z (UTC) timestamps, got:\n%s", content)
	}

	// Load and verify times are UTC
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Check exception times
	if len(loaded.Groups["sales"].Exceptions) != 1 {
		t.Fatal("expected 1 exception")
	}
	exc := loaded.Groups["sales"].Exceptions[0]
	if exc.At.Location() != time.UTC {
		t.Errorf("exception At should be UTC, got %v", exc.At.Location())
	}
	if exc.Until.Location() != time.UTC {
		t.Errorf("exception Until should be UTC, got %v", exc.Until.Location())
	}

	// Check expiry times
	expiry := loaded.Groups["manual"].Expiry["charlie"]
	if expiry.Location() != time.UTC {
		t.Errorf("expiry should be UTC, got %v", expiry.Location())
	}
}

func TestStoreRuleParseErrorIncludesGroupAndPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	store := &Store{Path: path}

	// Write YAML with invalid rule
	yaml := `version: 1
groups:
  sales:
    rule: "invalid rule syntax!!!"
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := store.Load()
	if err == nil {
		t.Fatal("Load should fail on invalid rule")
	}

	// Error should mention path, group name, and "rule"
	errStr := err.Error()
	if !contains(errStr, path) {
		t.Errorf("error should mention path %q, got: %v", path, err)
	}
	if !contains(errStr, "sales") {
		t.Errorf("error should mention group name %q, got: %v", "sales", err)
	}
	if !contains(errStr, "rule") {
		t.Errorf("error should mention %q, got: %v", "rule", err)
	}
}

func TestStoreSaveFailsWhenParentMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "directory.yaml")
	store := &Store{Path: path}

	cfg := &Config{
		Version:     1,
		Fields:      []Field{},
		Groups:      map[string]*GroupConfig{},
		Permissions: map[string]string{},
		CreatedBy:   map[string]string{},
	}

	err := store.Save(cfg)
	if err == nil {
		t.Fatal("Save should fail when parent directory doesn't exist")
	}
}

func TestStoreDeletedTombstones(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	cfg, _ := store.Load()
	cfg.Deleted = map[string]time.Time{"Bob": time.Date(2026, 11, 1, 13, 0, 0, 0, time.FixedZone("CET", 3600))}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if at, ok := got.Deleted["bob"]; !ok || at.Location() != time.UTC || !at.Equal(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)) || len(got.Deleted) != 1 {
		t.Errorf("deleted = %v", got.Deleted)
	}
	empty := &Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if c, _ := empty.Load(); c.Deleted == nil {
		t.Error("missing file: Deleted is nil")
	}
}
