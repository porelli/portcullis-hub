package directory_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/rules"
)

func TestCreateFieldCreatesLLDAPAttribute(t *testing.T) {
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store

	f := directory.Field{
		Name:          "department",
		Label:         "Department",
		Kind:          directory.FieldKindList,
		Values:        []string{"Engineering", "Sales"},
		Multi:         false,
		ShareWithApps: true,
		AdminOnly:     false,
	}

	if err := e.svc.CreateField(ctx, "root", f); err != nil {
		t.Fatalf("CreateField: %v", err)
	}

	// Check LLDAP attribute was created
	attrs, err := e.svc.LLDAP.UserAttributes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range attrs {
		if a.Name == "department" {
			found = true
			if a.IsList != false {
				t.Errorf("department isList = %v, want false", a.IsList)
			}
		}
	}
	if !found {
		t.Error("department attribute not created in LLDAP")
	}

	// Check directory.yaml was written
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Fields) != 1 {
		t.Fatalf("Fields = %d, want 1", len(cfg.Fields))
	}
	if cfg.Fields[0].Name != "department" || cfg.Fields[0].Label != "Department" {
		t.Errorf("Field = %+v", cfg.Fields[0])
	}

	// Check audit
	entries, _ := e.svc.Recent(10)
	if len(entries) == 0 || entries[0].Action != "field.create" || entries[0].Target != "department" {
		t.Errorf("audit = %+v", entries)
	}
}

func TestFieldNameRules(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	tests := []struct {
		name      string
		wantError string
	}{
		{"Mail", "invalid field name"},
		{"mail", "reserved"},
		{"uid", "reserved"},
		{"display_name", "reserved"},
		{"9x", "invalid field name"},
		{"a-b", "invalid field name"},
		{"", "invalid field name"},
		{"a_very_long_name_that_exceeds_the_31_char_limit", "invalid field name"},
		{"department", ""},  // valid
		{"cost_center", ""}, // valid
	}

	for _, tt := range tests {
		f := directory.Field{
			Name:  tt.name,
			Label: "Test Field",
			Kind:  directory.FieldKindText,
		}
		err := e.svc.CreateField(ctx, "root", f)
		if tt.wantError == "" {
			if err != nil {
				t.Errorf("CreateField(%q): unexpected error: %v", tt.name, err)
			}
		} else {
			if err == nil {
				t.Errorf("CreateField(%q): expected error containing %q, got nil", tt.name, tt.wantError)
			} else if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("CreateField(%q): expected error containing %q, got %v", tt.name, tt.wantError, err)
			}
		}
	}
}

func TestDeleteFieldInUseRefused(t *testing.T) {
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store

	// Create a field
	f := directory.Field{
		Name:   "location",
		Label:  "Location",
		Kind:   directory.FieldKindList,
		Values: []string{"Milan", "London"},
	}
	if err := e.svc.CreateField(ctx, "root", f); err != nil {
		t.Fatal(err)
	}

	// Create a group with a rule using the field
	cfg, _ := store.Load()
	cfg.Groups = map[string]*directory.GroupConfig{
		"milan_team": {
			Rule: &rules.Expr{
				Op:     rules.OpIs,
				Field:  "location",
				Values: []string{"Milan"},
			},
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Try to delete the field
	err := e.svc.DeleteField(ctx, "root", "location", "location")
	if err == nil {
		t.Fatal("DeleteField: expected error, got nil")
	}
	if status(err) != 409 {
		t.Errorf("status = %d, want 409", status(err))
	}
	if !strings.Contains(err.Error(), "milan_team") {
		t.Errorf("error should list the group using the field: %v", err)
	}
}

func TestAdminOnlyLockedWhileGuarding(t *testing.T) {
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store

	// Create an admin-only field
	f := directory.Field{
		Name:      "security_clearance",
		Label:     "Security Clearance",
		Kind:      directory.FieldKindText,
		AdminOnly: true,
	}
	if err := e.svc.CreateField(ctx, "root", f); err != nil {
		t.Fatal(err)
	}

	// Use it in a permission group rule
	cfg, _ := store.Load()
	cfg.Permissions = map[string]string{"edit_details": "hr_team"}
	cfg.Groups = map[string]*directory.GroupConfig{
		"hr_team": {
			Rule: &rules.Expr{
				Op:     rules.OpIs,
				Field:  "security_clearance",
				Values: []string{"high"},
			},
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Try to turn off AdminOnly
	f.AdminOnly = false
	err := e.svc.UpdateField(ctx, "root", f)
	if err == nil {
		t.Fatal("UpdateField: expected error, got nil")
	}
	if status(err) != 409 {
		t.Errorf("status = %d, want 409", status(err))
	}
	if !strings.Contains(err.Error(), "hr_team") {
		t.Errorf("error should mention the guarding group: %v", err)
	}
}

func TestRemoveListValueInUseRefused(t *testing.T) {
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store

	// Create a list field
	f := directory.Field{
		Name:   "office",
		Label:  "Office",
		Kind:   directory.FieldKindList,
		Values: []string{"NYC", "SF", "Austin"},
	}
	if err := e.svc.CreateField(ctx, "root", f); err != nil {
		t.Fatal(err)
	}

	// Use SF in a rule
	cfg, _ := store.Load()
	cfg.Groups = map[string]*directory.GroupConfig{
		"sf_team": {
			Rule: &rules.Expr{
				Op:     rules.OpIs,
				Field:  "office",
				Values: []string{"SF"},
			},
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Try to remove SF
	f.Values = []string{"NYC", "Austin"}
	err := e.svc.UpdateField(ctx, "root", f)
	if err == nil {
		t.Fatal("UpdateField: expected error, got nil")
	}
	if status(err) != 409 {
		t.Errorf("status = %d, want 409", status(err))
	}
	if !strings.Contains(err.Error(), "sf_team") {
		t.Errorf("error should list the group using the value: %v", err)
	}
}

func TestFieldMutationsAreAudited(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	// Create
	f := directory.Field{Name: "dept", Label: "Department", Kind: directory.FieldKindText}
	e.svc.CreateField(ctx, "root", f)

	// Update
	f.Label = "Department Name"
	e.svc.UpdateField(ctx, "root", f)

	// Delete
	e.svc.DeleteField(ctx, "root", "dept", "dept")

	entries, _ := e.svc.Recent(10)
	if len(entries) < 3 {
		t.Fatalf("entries = %d, want at least 3", len(entries))
	}
	actions := []string{entries[2].Action, entries[1].Action, entries[0].Action}
	expected := []string{"field.create", "field.update", "field.delete"}
	for i, want := range expected {
		if actions[i] != want {
			t.Errorf("action[%d] = %q, want %q", i, actions[i], want)
		}
	}
}

func TestKindAndMultiImmutable(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	f := directory.Field{Name: "dept", Label: "Department", Kind: directory.FieldKindText, Multi: false}
	if err := e.svc.CreateField(ctx, "root", f); err != nil {
		t.Fatal(err)
	}

	// Try to change Kind
	f.Kind = directory.FieldKindList
	if err := e.svc.UpdateField(ctx, "root", f); err == nil || status(err) != 400 {
		t.Errorf("changing Kind: want 400, got %v", err)
	}

	// Try to change Multi
	f.Kind = directory.FieldKindText
	f.Multi = true
	if err := e.svc.UpdateField(ctx, "root", f); err == nil || status(err) != 400 {
		t.Errorf("changing Multi: want 400, got %v", err)
	}
}

func TestMultiRefusedForPerson(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	f := directory.Field{
		Name:  "manager",
		Label: "Manager",
		Kind:  directory.FieldKindPerson,
		Multi: true,
	}
	err := e.svc.CreateField(ctx, "root", f)
	if err == nil {
		t.Fatal("CreateField with Multi person: expected error, got nil")
	}
	if status(err) != 400 {
		t.Errorf("status = %d, want 400", status(err))
	}
}

func TestListValueValidation(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	tests := []struct {
		name   string
		values []string
		want   string // error substring
	}{
		{"empty value", []string{"Sales", "", "Eng"}, "empty"},
		{"blank value", []string{"Sales", "  ", "Eng"}, "empty"},
		{"duplicate ignoring case", []string{"Sales", "sales"}, "duplicate"},
		{"duplicate different case", []string{"NYC", "nyc", "SF"}, "duplicate"},
		{"valid", []string{"Sales", "Engineering", "HR"}, ""},
	}

	for _, tt := range tests {
		f := directory.Field{
			Name:   "dept",
			Label:  "Department",
			Kind:   directory.FieldKindList,
			Values: tt.values,
		}
		err := e.svc.CreateField(ctx, "root", f)
		if tt.want == "" {
			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.name, err)
			}
			// Clean up for next test
			e.svc.DeleteField(ctx, "root", "dept", "dept")
		} else {
			if err == nil {
				t.Errorf("%s: expected error containing %q, got nil", tt.name, tt.want)
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("%s: expected error containing %q, got %v", tt.name, tt.want, err)
			}
		}
	}
}

func TestFieldLabelRequired(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	tests := []struct {
		label string
		valid bool
	}{
		{"", false},
		{"  ", false},
		{"Department", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
	}

	for _, tt := range tests {
		f := directory.Field{Name: "test", Label: tt.label, Kind: directory.FieldKindText}
		err := e.svc.CreateField(ctx, "root", f)
		if tt.valid && err != nil {
			t.Errorf("Label %q: unexpected error: %v", tt.label, err)
		} else if !tt.valid && err == nil {
			t.Errorf("Label %q: expected error, got nil", tt.label)
		}
		if err == nil {
			e.svc.DeleteField(ctx, "root", "test", "test")
		}
	}
}

func TestCreateFieldDuplicateRefused(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	f := directory.Field{Name: "dept", Label: "Department", Kind: directory.FieldKindText}
	if err := e.svc.CreateField(ctx, "root", f); err != nil {
		t.Fatal(err)
	}

	// Try to create again
	err := e.svc.CreateField(ctx, "root", f)
	if err == nil {
		t.Fatal("CreateField duplicate: expected error, got nil")
	}
	if status(err) != 409 {
		t.Errorf("status = %d, want 409", status(err))
	}
}

func TestDeleteFieldConfirmRequired(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}

	f := directory.Field{Name: "dept", Label: "Department", Kind: directory.FieldKindText}
	if err := e.svc.CreateField(ctx, "root", f); err != nil {
		t.Fatal(err)
	}

	// Wrong confirm
	err := e.svc.DeleteField(ctx, "root", "dept", "wrong")
	if err == nil || status(err) != 400 {
		t.Errorf("DeleteField with wrong confirm: want 400, got %v", err)
	}

	// Correct confirm
	if err := e.svc.DeleteField(ctx, "root", "dept", "dept"); err != nil {
		t.Errorf("DeleteField with correct confirm: %v", err)
	}
}

func TestNilStoreReturns503(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = nil

	f := directory.Field{Name: "dept", Label: "Department", Kind: directory.FieldKindText}
	err := e.svc.CreateField(ctx, "root", f)
	if status(err) != 503 {
		t.Errorf("CreateField with nil Store: status = %d, want 503", status(err))
	}
}
