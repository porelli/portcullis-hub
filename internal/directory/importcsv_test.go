package directory_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/rules"
)

func TestParseCSVExcelVariants(t *testing.T) {
	// All these variants should parse to the same rows
	expected := [][]string{
		{"alice", "Alice", "alice@example.org", "Rome"},
		{"bob", "Bob", "bob@example.org", "Milan"},
		{"carol", "Carol", "carol@example.org", "Naples"},
	}

	tests := []struct {
		name string
		csv  string
	}{
		{
			name: "comma",
			csv:  "username,display_name,email,city\nalice,Alice,alice@example.org,Rome\nbob,Bob,bob@example.org,Milan\ncarol,Carol,carol@example.org,Naples",
		},
		{
			name: "semicolon",
			csv:  "username;display_name;email;city\nalice;Alice;alice@example.org;Rome\nbob;Bob;bob@example.org;Milan\ncarol;Carol;carol@example.org;Naples",
		},
		{
			name: "CRLF",
			csv:  "username,display_name,email,city\r\nalice,Alice,alice@example.org,Rome\r\nbob,Bob,bob@example.org,Milan\r\ncarol,Carol,carol@example.org,Naples",
		},
		{
			name: "BOM",
			csv:  "\xef\xbb\xbfusername,display_name,email,city\nalice,Alice,alice@example.org,Rome\nbob,Bob,bob@example.org,Milan\ncarol,Carol,carol@example.org,Naples",
		},
		{
			name: "quoted_newline",
			csv:  "username,display_name,email,city\nalice,Alice,alice@example.org,Rome\nbob,\"Bob\",bob@example.org,Milan\ncarol,\"Carol\nSurname\",carol@example.org,Naples",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, rows, err := directory.ParseCSV(strings.NewReader(tt.csv))
			if err != nil {
				t.Fatalf("ParseCSV failed: %v", err)
			}

			// Check header
			wantHeader := []string{"username", "display_name", "email", "city"}
			if len(header) != len(wantHeader) {
				t.Fatalf("header length: got %d, want %d", len(header), len(wantHeader))
			}
			for i := range header {
				if header[i] != wantHeader[i] {
					t.Errorf("header[%d]: got %q, want %q", i, header[i], wantHeader[i])
				}
			}

			// For quoted newline test, adjust expected
			expectedRows := expected
			if tt.name == "quoted_newline" {
				expectedRows = [][]string{
					{"alice", "Alice", "alice@example.org", "Rome"},
					{"bob", "Bob", "bob@example.org", "Milan"},
					{"carol", "Carol\nSurname", "carol@example.org", "Naples"},
				}
			}

			// Check rows
			if len(rows) != len(expectedRows) {
				t.Fatalf("row count: got %d, want %d", len(rows), len(expectedRows))
			}
			for i, row := range rows {
				if len(row) != len(expectedRows[i]) {
					t.Errorf("row %d length: got %d, want %d", i, len(row), len(expectedRows[i]))
					continue
				}
				for j := range row {
					if row[j] != expectedRows[i][j] {
						t.Errorf("row %d col %d: got %q, want %q", i, j, row[j], expectedRows[i][j])
					}
				}
			}
		})
	}
}

func TestImportReviewStatuses(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice Old", "pass-123456")
	env.ll.AddUser("bob", "bob@example.org", "Bob", "pass-123456")
	env.ll.AddUser("missing", "missing@example.org", "Missing", "pass-123456")

	// Create a field to test changes
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.SetUserAttributes(ctx, "alice", map[string][]string{"city": {"Rome"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.SetUserAttributes(ctx, "bob", map[string][]string{"city": {"Milan"}}, nil); err != nil {
		t.Fatal(err)
	}

	// Set up config
	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindText, Multi: false},
		},
		Groups:      map[string]*directory.GroupConfig{},
		Permissions: map[string]string{},
		CreatedBy:   map[string]string{},
		Deleted:     map[string]time.Time{},
	}
	env.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	admin, _ := env.svc.CallerFor(ctx, "root")

	// CSV: alice (changed), bob (same), carol (new), Missing is in LLDAP but not in file
	csv := "username,display_name,email,city\nalice,Alice New,alice@example.org,Naples\nbob,Bob,bob@example.org,Milan\nCarol,Carol,carol@example.org,Rome"
	header, rows, err := directory.ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}

	review, err := env.svc.ImportReview(ctx, admin, header, rows)
	if err != nil {
		t.Fatalf("ImportReview: %v", err)
	}

	// Check statuses
	statuses := make(map[string]string)
	for _, r := range review.Rows {
		statuses[strings.ToLower(r.User)] = r.Status
	}

	if statuses["alice"] != "changed" {
		t.Errorf("alice status: got %q, want %q", statuses["alice"], "changed")
	}
	if statuses["bob"] != "same" {
		t.Errorf("bob status: got %q, want %q", statuses["bob"], "same")
	}
	if statuses["carol"] != "new" {
		t.Errorf("carol status: got %q, want %q", statuses["carol"], "new")
	}
	if statuses["missing"] != "missing" {
		t.Errorf("missing status: got %q, want %q", statuses["missing"], "missing")
	}
}

func TestImportReviewProblems(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")

	// Create fields: manager (person), city (list)
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "manager", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "manager", Kind: directory.FieldKindPerson, Multi: false},
			{Name: "city", Kind: directory.FieldKindList, Values: []string{"Rome", "Milan", "Naples"}, Multi: false},
		},
		Groups:      map[string]*directory.GroupConfig{},
		Permissions: map[string]string{},
		CreatedBy:   map[string]string{},
		Deleted:     map[string]time.Time{},
	}
	env.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	admin, _ := env.svc.CallerFor(ctx, "root")

	t.Run("unknown_manager", func(t *testing.T) {
		csv := "username,manager\nalice,unknown"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, admin, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		// Find alice's row
		var aliceRow *directory.ReviewRow
		for i := range review.Rows {
			if strings.EqualFold(review.Rows[i].User, "alice") {
				aliceRow = &review.Rows[i]
				break
			}
		}
		if aliceRow == nil {
			t.Fatalf("alice not found in review rows")
		}
		if len(aliceRow.Problems) == 0 {
			t.Fatalf("expected problems for unknown manager, got none")
		}
		found := false
		for _, p := range aliceRow.Problems {
			if strings.Contains(p, "manager") && strings.Contains(p, "unknown") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected problem mentioning unknown manager, got: %v", aliceRow.Problems)
		}
	})

	t.Run("invalid_list_value", func(t *testing.T) {
		csv := "username,city\nalice,Paris"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, admin, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		// Find alice's row
		var aliceRow *directory.ReviewRow
		for i := range review.Rows {
			if strings.EqualFold(review.Rows[i].User, "alice") {
				aliceRow = &review.Rows[i]
				break
			}
		}
		if aliceRow == nil {
			t.Fatalf("alice not found in review rows")
		}
		if len(aliceRow.Problems) == 0 {
			t.Fatalf("expected problems for invalid list value, got none")
		}
		found := false
		for _, p := range aliceRow.Problems {
			if strings.Contains(p, "city") && strings.Contains(strings.ToLower(p), "paris") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected problem mentioning invalid city, got: %v", aliceRow.Problems)
		}
	})

	t.Run("duplicate_username", func(t *testing.T) {
		csv := "username,email\nalice,alice1@example.org\nAlice,alice2@example.org"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, admin, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		// Both rows should have problems about duplicate username
		foundProblems := 0
		for _, row := range review.Rows {
			for _, p := range row.Problems {
				if strings.Contains(strings.ToLower(p), "duplicate") {
					foundProblems++
				}
			}
		}
		if foundProblems == 0 {
			t.Errorf("expected duplicate username problems, got none")
		}
	})
}

func TestImportReviewEffect(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.SetUserAttributes(ctx, "alice", map[string][]string{"city": {"Rome"}}, nil); err != nil {
		t.Fatal(err)
	}

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindList, Values: []string{"Rome", "Milan", "Naples"}, Multi: false},
		},
		Groups: map[string]*directory.GroupConfig{
			"sales-milan": {
				Rule: &rules.Expr{
					Op:     rules.OpIs,
					Field:  "city",
					Values: []string{"Milan"},
				},
			},
		},
		Permissions: map[string]string{},
		CreatedBy:   map[string]string{},
		Deleted:     map[string]time.Time{},
	}
	env.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	admin, _ := env.svc.CallerFor(ctx, "root")

	// Change Alice from Rome to Milan
	csv := "username,city\nalice,Milan"
	header, rows, err := directory.ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}

	review, err := env.svc.ImportReview(ctx, admin, header, rows)
	if err != nil {
		t.Fatalf("ImportReview: %v", err)
	}

	// Check that sales-milan shows +1
	effect, ok := review.Effect["sales-milan"]
	if !ok {
		t.Fatalf("sales-milan not in Effect")
	}
	if effect[0] != 1 {
		t.Errorf("sales-milan added: got %d, want 1", effect[0])
	}
	if effect[1] != 0 {
		t.Errorf("sales-milan removed: got %d, want 0", effect[1])
	}
}

func TestImportApplyRevalidates(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")
	env.ll.AddUser("bob", "bob@example.org", "Bob", "pass-123456")
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindList, Values: []string{"Rome", "Milan", "Naples"}, Multi: false},
		},
		Groups:      map[string]*directory.GroupConfig{},
		Permissions: map[string]string{},
		CreatedBy:   map[string]string{},
		Deleted:     map[string]time.Time{},
	}
	env.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	admin, _ := env.svc.CallerFor(ctx, "root")

	// Apply two rows: one valid, one with invalid list value
	req := directory.ApplyRequest{
		Rows: []directory.ApplyRow{
			{User: "alice", Attrs: map[string][]string{"city": {"Milan"}}},
			{User: "bob", Attrs: map[string][]string{"city": {"Paris"}}},
		},
	}

	result, err := env.svc.ImportApply(ctx, admin, req)
	if err != nil {
		t.Fatalf("ImportApply: %v", err)
	}

	if len(result.Rows) != 2 {
		t.Fatalf("result row count: got %d, want 2", len(result.Rows))
	}

	// First row (alice) should succeed
	if !result.Rows[0].OK {
		t.Errorf("alice row should succeed, but got error: %s", result.Rows[0].Error)
	}

	// Second row (bob) should fail
	if result.Rows[1].OK {
		t.Errorf("bob row should fail (invalid list value)")
	}
	if !strings.Contains(result.Rows[1].Error, "city") {
		t.Errorf("bob error should mention city, got: %s", result.Rows[1].Error)
	}
}
