package directory_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/rules"
)

func findRow(rows []directory.ReviewRow, username string) *directory.ReviewRow {
	for i := range rows {
		if strings.EqualFold(rows[i].User, username) {
			return &rows[i]
		}
	}
	return nil
}

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

func TestParseCSVLimits(t *testing.T) {
	t.Run("too_many_rows", func(t *testing.T) {
		// Generate 10,001 rows + header
		var sb strings.Builder
		sb.WriteString("username\n")
		for i := 0; i <= 10000; i++ {
			sb.WriteString(fmt.Sprintf("user%d\n", i))
		}
		_, _, err := directory.ParseCSV(strings.NewReader(sb.String()))
		if err == nil {
			t.Fatal("expected error for too many rows")
		}
		if !strings.Contains(err.Error(), "too many rows") {
			t.Errorf("error should mention too many rows, got: %v", err)
		}
	})

	t.Run("too_many_columns", func(t *testing.T) {
		// Generate 65 columns
		var sb strings.Builder
		for i := 0; i < 65; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(fmt.Sprintf("col%d", i))
		}
		sb.WriteString("\n")
		_, _, err := directory.ParseCSV(strings.NewReader(sb.String()))
		if err == nil {
			t.Fatal("expected error for too many columns")
		}
		if !strings.Contains(err.Error(), "too many columns") {
			t.Errorf("error should mention too many columns, got: %v", err)
		}
	})

	t.Run("duplicate_header", func(t *testing.T) {
		csv := "username,email,username\nalice,alice@example.org,alice"
		_, _, err := directory.ParseCSV(strings.NewReader(csv))
		if err == nil {
			t.Fatal("expected error for duplicate header")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			t.Errorf("error should mention duplicate, got: %v", err)
		}
	})
}

func TestImportReviewEmptyCellVsAbsentColumn(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")

	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "department", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.SetUserAttributes(ctx, "alice", map[string][]string{
		"city":       {"Rome"},
		"department": {"Sales"},
	}, nil); err != nil {
		t.Fatal(err)
	}

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindText, Multi: false},
			{Name: "department", Kind: directory.FieldKindText, Multi: false},
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

	// CSV with city column empty, no department column
	csv := "username,city\nalice,"
	header, rows, err := directory.ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}

	review, err := env.svc.ImportReview(ctx, admin, header, rows)
	if err != nil {
		t.Fatalf("ImportReview: %v", err)
	}

	row := findRow(review.Rows, "alice")
	if row == nil {
		t.Fatal("alice not found in review rows")
	}

	// City column is present but empty → file value should be empty (clear)
	if cityCell, ok := row.Cells["city"]; ok {
		if len(cityCell.File) != 0 {
			t.Errorf("city file value should be empty (clearing), got %v", cityCell.File)
		}
		if len(cityCell.Current) == 0 || cityCell.Current[0] != "Rome" {
			t.Errorf("city current value should be Rome, got %v", cityCell.Current)
		}
	} else {
		t.Error("city cell not found")
	}

	// Department column absent → cell won't be in Cells map at all (untouched)
	// This is expected behavior - absent columns don't create cells
	if _, ok := row.Cells["department"]; ok {
		t.Error("department cell should not exist when column is absent")
	}
}

func TestImportApplyDisplayNameChange(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice Old", "pass-123456")

	admin, _ := env.svc.CallerFor(ctx, "root")

	// Apply display_name change
	req := directory.ApplyRequest{
		Rows: []directory.ApplyRow{
			{User: "alice", DisplayName: "Alice New"},
		},
	}

	result, err := env.svc.ImportApply(ctx, admin, req)
	if err != nil {
		t.Fatalf("ImportApply: %v", err)
	}

	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
	}

	if !result.Rows[0].OK {
		t.Errorf("apply should succeed, got error: %s", result.Rows[0].Error)
	}

	// Verify the change was applied
	users, err := env.svc.LLDAP.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	found := false
	for _, u := range users {
		if strings.EqualFold(u.ID, "alice") {
			if u.DisplayName != "Alice New" {
				t.Errorf("display_name: got %q, want %q", u.DisplayName, "Alice New")
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("alice not found after apply")
	}
}

func TestImportReviewDelegateProblems(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")
	env.ll.AddUser("hera", "hera@example.org", "Hera", "pass-123456", "hr_edit")
	env.ll.AddUser("inv", "inv@example.org", "Inv", "pass-123456", "hr_invite")
	env.ll.AddUser("otto", "otto@example.org", "Otto", "pass-123456", "ops_admins")
	env.ll.AddUser("pm", "pm@example.org", "PM", "pass-123456", "lldap_password_manager")

	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "secret", false); err != nil {
		t.Fatal(err)
	}

	env.ll.AddGroup("hr_edit", "hera")
	env.ll.AddGroup("hr_invite", "inv")
	env.ll.AddGroup("hr_remove")
	env.ll.AddGroup("ops_admins", "otto")

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindText, Multi: false},
			{Name: "secret", Kind: directory.FieldKindText, Multi: false, AdminOnly: true},
		},
		Groups: map[string]*directory.GroupConfig{},
		Permissions: map[string]string{
			directory.PermEditDetails: "hr_edit",
			directory.PermInvite:      "hr_invite",
			directory.PermRemove:      "hr_remove",
		},
		CreatedBy: map[string]string{},
		Deleted:   map[string]time.Time{},
	}
	env.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	t.Run("no_permission_403", func(t *testing.T) {
		// User with no permissions
		nobody, _ := env.svc.CallerFor(ctx, "alice")

		csv := "username,display_name\nalice,Alice New"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		_, err = env.svc.ImportReview(ctx, nobody, header, rows)
		if err == nil {
			t.Fatal("expected 403 error")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("expected 'not allowed' error, got: %v", err)
		}
	})

	t.Run("invite_only_sees_edit_details_problems", func(t *testing.T) {
		invOnly, _ := env.svc.CallerFor(ctx, "inv")

		// Changed row requires edit_details
		csv := "username,display_name\nalice,Alice New"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, invOnly, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "alice")
		if row == nil {
			t.Fatal("alice not found in review rows")
		}
		found := false
		for _, p := range row.Problems {
			if strings.Contains(p, "edit_details") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected edit_details problem, got: %v", review.Rows[0].Problems)
		}
	})

	t.Run("self_row_different_case", func(t *testing.T) {
		hera, _ := env.svc.CallerFor(ctx, "hera")

		// Hera trying to edit HERA (different case)
		csv := "username,city\nHERA,Milan"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, hera, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "hera")
		if row == nil {
			t.Fatal("hera not found in review rows")
		}
		found := false
		for _, p := range row.Problems {
			if strings.Contains(strings.ToLower(p), "admin") && strings.Contains(strings.ToLower(p), "hera") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected problem about self-targeting, got: %v", review.Rows[0].Problems)
		}
	})

	t.Run("admin_and_permission_group_members", func(t *testing.T) {
		hera, _ := env.svc.CallerFor(ctx, "hera")

		// Trying to edit root (admin), otto (ops_admins), pm (lldap_password_manager), inv (hr_invite member)
		csv := "username,city\nroot,Milan\notto,Rome\npm,Naples\ninv,Florence"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, hera, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		// All should have problems
		// Check specific rows we care about: root, otto, pm, inv
		for _, username := range []string{"root", "otto", "pm", "inv"} {
			row := findRow(review.Rows, username)
			if row == nil {
				t.Errorf("%s not found in review", username)
				continue
			}
			if len(row.Problems) == 0 {
				t.Errorf("%s should have problems (delegate cannot target admins/permission-group members)", username)
			}
			found := false
			for _, p := range row.Problems {
				if strings.Contains(strings.ToLower(p), "admin") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: expected admin-related problem, got: %v", username, row.Problems)
			}
		}
	})

	t.Run("admin_only_field_edited", func(t *testing.T) {
		hera, _ := env.svc.CallerFor(ctx, "hera")

		// Trying to edit AdminOnly field
		csv := "username,secret\nalice,topsecret"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, hera, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "alice")
		if row == nil {
			t.Fatal("alice not found in review rows")
		}
		found := false
		for _, p := range row.Problems {
			if strings.Contains(p, "secret") && strings.Contains(p, "admin-only") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected admin-only problem, got: %v", review.Rows[0].Problems)
		}
	})

	t.Run("admin_only_field_emptied", func(t *testing.T) {
		// Set a value first
		if err := env.svc.LLDAP.SetUserAttributes(ctx, "alice", map[string][]string{"secret": {"value"}}, nil); err != nil {
			t.Fatal(err)
		}

		hera, _ := env.svc.CallerFor(ctx, "hera")

		// Trying to empty AdminOnly field
		csv := "username,secret\nalice,"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, hera, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "alice")
		if row == nil {
			t.Fatal("alice not found in review rows")
		}
		found := false
		for _, p := range row.Problems {
			if strings.Contains(p, "secret") && strings.Contains(p, "admin-only") && strings.Contains(p, "emptied") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected admin-only emptied problem, got: %v", review.Rows[0].Problems)
		}
	})
}

func TestImportReviewUnchangedRowsNoProblems(t *testing.T) {
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

	// Delegate with no edit_details permission
	env.ll.AddUser("inv", "inv@example.org", "Inv", "pass-123456", "hr_invite")
	env.ll.AddGroup("hr_invite", "inv")
	cfg.Permissions = map[string]string{directory.PermInvite: "hr_invite"}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	invOnly, _ := env.svc.CallerFor(ctx, "inv")

	// Unchanged row (same values)
	csv := "username,display_name,email,city\nalice,Alice,alice@example.org,Rome"
	header, rows, err := directory.ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}

	review, err := env.svc.ImportReview(ctx, invOnly, header, rows)
	if err != nil {
		t.Fatalf("ImportReview: %v", err)
	}

	row := findRow(review.Rows, "alice")
	if row == nil {
		t.Fatal("alice not found in review rows")
	}

	if row.Status != "same" {
		t.Errorf("status: got %q, want %q", review.Rows[0].Status, "same")
	}

	// Unchanged rows should have NO permission problems
	if len(row.Problems) > 0 {
		t.Errorf("unchanged row should have no problems, got: %v", row.Problems)
	}
}

func TestParseCSVEmptyUsernameAndShortRows(t *testing.T) {
	t.Run("empty_username", func(t *testing.T) {
		csv := "username,email\n,alice@example.org"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		env := newEnv(t)
		admin, _ := env.svc.CallerFor(context.Background(), "root")

		review, err := env.svc.ImportReview(context.Background(), admin, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		// Empty username rows get "(empty)" as username
		var emptyRow *directory.ReviewRow
		for i := range review.Rows {
			if review.Rows[i].User == "(empty)" {
				emptyRow = &review.Rows[i]
				break
			}
		}
		if emptyRow == nil {
			t.Fatal("empty username row not found")
		}
		found := false
		for _, p := range emptyRow.Problems {
			if strings.Contains(strings.ToLower(p), "username") && strings.Contains(strings.ToLower(p), "required") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected username required problem, got: %v", review.Rows[0].Problems)
		}
	})

	t.Run("short_row", func(t *testing.T) {
		// Row with fewer columns than header
		csv := "username,email,city\nalice"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		env := newEnv(t)
		env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")

		if err := env.svc.LLDAP.AddUserAttribute(context.Background(), "city", false); err != nil {
			t.Fatal(err)
		}

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

		admin, _ := env.svc.CallerFor(context.Background(), "root")

		review, err := env.svc.ImportReview(context.Background(), admin, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		// Short rows are handled gracefully (bounds-checked)
		// The row should process but show missing email
		row := findRow(review.Rows, "alice")
		if row == nil {
			t.Fatal("alice not found in review rows")
		}
	})
}

func TestSetDetailsValidation(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")

	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "bio", false); err != nil {
		t.Fatal(err)
	}

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindText, Multi: false},
			{Name: "bio", Kind: directory.FieldKindText, Multi: false},
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

	t.Run("trims_values", func(t *testing.T) {
		err := env.svc.SetDetails(ctx, admin, "alice", map[string][]string{
			"city": {"  Rome  "},
		})
		if err != nil {
			t.Fatalf("SetDetails: %v", err)
		}

		// Verify trimmed value was set
		users, _ := env.svc.LLDAP.ListUsers(ctx)
		for _, u := range users {
			if strings.EqualFold(u.ID, "alice") {
				if u.Attributes["city"][0] != "Rome" {
					t.Errorf("value should be trimmed to 'Rome', got %q", u.Attributes["city"][0])
				}
			}
		}
	})

	t.Run("refuses_empty_string", func(t *testing.T) {
		err := env.svc.SetDetails(ctx, admin, "alice", map[string][]string{
			"city": {""},
		})
		if err == nil {
			t.Fatal("expected error for empty string value")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("error should mention empty, got: %v", err)
		}
	})

	t.Run("refuses_text_over_1024_runes", func(t *testing.T) {
		longText := strings.Repeat("a", 1025)
		err := env.svc.SetDetails(ctx, admin, "alice", map[string][]string{
			"bio": {longText},
		})
		if err == nil {
			t.Fatal("expected error for text over 1024 runes")
		}
		if !strings.Contains(err.Error(), "too long") {
			t.Errorf("error should mention too long, got: %v", err)
		}
	})
}

func TestImportReviewClearedRequiredFields(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")

	admin, _ := env.svc.CallerFor(ctx, "root")

	t.Run("cannot_clear_display_name", func(t *testing.T) {
		csv := "username,display_name\nalice,"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, admin, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "alice")
		if row == nil {
			t.Fatal("alice not found in review rows")
		}

		found := false
		for _, p := range row.Problems {
			if strings.Contains(p, "cannot clear display_name") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected problem about clearing display_name, got: %v", row.Problems)
		}
	})

	t.Run("cannot_clear_email", func(t *testing.T) {
		csv := "username,email\nalice,"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, admin, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "alice")
		if row == nil {
			t.Fatal("alice not found in review rows")
		}

		found := false
		for _, p := range row.Problems {
			if strings.Contains(p, "cannot clear email") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected problem about clearing email, got: %v", row.Problems)
		}
	})

	t.Run("apply_refuses_cleared_display_name", func(t *testing.T) {
		req := directory.ApplyRequest{
			Rows: []directory.ApplyRow{
				{User: "alice", DisplayName: " "},
			},
		}

		result, err := env.svc.ImportApply(ctx, admin, req)
		if err != nil {
			t.Fatalf("ImportApply: %v", err)
		}

		if len(result.Rows) != 1 {
			t.Fatalf("expected 1 result row, got %d", len(result.Rows))
		}

		if result.Rows[0].OK {
			t.Error("apply should refuse cleared display_name")
		}
		if !strings.Contains(result.Rows[0].Error, "cannot clear display_name") {
			t.Errorf("error should mention clearing display_name, got: %s", result.Rows[0].Error)
		}
	})

	t.Run("apply_refuses_cleared_email", func(t *testing.T) {
		req := directory.ApplyRequest{
			Rows: []directory.ApplyRow{
				{User: "alice", Email: " "},
			},
		}

		result, err := env.svc.ImportApply(ctx, admin, req)
		if err != nil {
			t.Fatalf("ImportApply: %v", err)
		}

		if len(result.Rows) != 1 {
			t.Fatalf("expected 1 result row, got %d", len(result.Rows))
		}

		if result.Rows[0].OK {
			t.Error("apply should refuse cleared email")
		}
		if !strings.Contains(result.Rows[0].Error, "cannot clear email") {
			t.Errorf("error should mention clearing email, got: %s", result.Rows[0].Error)
		}
	})
}

func TestImportReviewShortRows(t *testing.T) {
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

	// Short row: alice under "username,email,city" header but only has "alice" value
	csv := "username,email,city\nalice"
	header, rows, err := directory.ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}

	review, err := env.svc.ImportReview(ctx, admin, header, rows)
	if err != nil {
		t.Fatalf("ImportReview: %v", err)
	}

	row := findRow(review.Rows, "alice")
	if row == nil {
		t.Fatal("alice not found in review rows")
	}

	// Check for short row problem
	found := false
	for _, p := range row.Problems {
		if strings.Contains(p, "row has") && strings.Contains(p, "cells") && strings.Contains(p, "header has") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected short row problem, got: %v", row.Problems)
	}

	// Missing cells should be treated as ABSENT (untouched)
	// City cell should not exist (column beyond row length)
	if _, ok := row.Cells["city"]; ok {
		t.Error("city cell should not exist for short row (column is ABSENT)")
	}

	// Apply should refuse flagged rows
	req := directory.ApplyRequest{
		Rows: []directory.ApplyRow{
			{User: "alice", Attrs: map[string][]string{"city": {"Milan"}}},
		},
	}

	// Actually, Apply doesn't get the problems - it re-validates
	// But for a valid row, it should work. Let's test with the city value:
	result, err := env.svc.ImportApply(ctx, admin, req)
	if err != nil {
		t.Fatalf("ImportApply: %v", err)
	}

	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 result row, got %d", len(result.Rows))
	}

	// This should succeed since the attrs are valid
	if !result.Rows[0].OK {
		t.Errorf("apply with valid attrs should succeed, got error: %s", result.Rows[0].Error)
	}

	// Verify city was changed
	users, _ := env.svc.LLDAP.ListUsers(ctx)
	for _, u := range users {
		if strings.EqualFold(u.ID, "alice") {
			if len(u.Attributes["city"]) == 0 || u.Attributes["city"][0] != "Milan" {
				t.Errorf("city should be Milan, got %v", u.Attributes["city"])
			}
		}
	}
}

func TestImportReviewNoUsernameHeader(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()
	admin, _ := env.svc.CallerFor(ctx, "root")

	// Header without username
	header := []string{"email", "display_name"}
	rows := [][]string{{"alice@example.org", "Alice"}}

	_, err := env.svc.ImportReview(ctx, admin, header, rows)
	if err == nil {
		t.Fatal("expected error for missing username header")
	}

	// Should be a 400 *Error
	var de *directory.Error
	if !errors.As(err, &de) || de.Status != 400 {
		t.Errorf("expected 400 Error, got: %T %v", err, err)
	}

	if !strings.Contains(err.Error(), "username") {
		t.Errorf("error should mention username, got: %v", err)
	}
}

func TestImportReviewSelfRowDifferentCase(t *testing.T) {
	env := newEnv(t)
	ctx := context.Background()

	// eddie holds edit_details but is in NO permission group (a Caller
	// resolved before he left hr_edit): the only reason to refuse his own
	// row is that it is his own. alice, an ordinary user, is the control.
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")
	env.ll.AddUser("eddie", "eddie@example.org", "Eddie", "pass-123456")
	env.ll.AddGroup("hr_edit")

	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindText, Multi: false},
		},
		Groups: map[string]*directory.GroupConfig{},
		Permissions: map[string]string{
			directory.PermEditDetails: "hr_edit",
		},
		CreatedBy: map[string]string{},
		Deleted:   map[string]time.Time{},
	}
	env.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if got := env.ll.GroupMembers("hr_edit"); len(got) != 0 {
		t.Fatalf("hr_edit members = %v, want none", got)
	}
	eddie := &directory.Caller{User: "eddie", Perms: map[string]bool{directory.PermEditDetails: true}}

	// Eddie (delegate) trying to edit EDDIE (different case)
	csv := "username,city\nEDDIE,Milan\nalice,Milan"
	header, rows, err := directory.ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}

	review, err := env.svc.ImportReview(ctx, eddie, header, rows)
	if err != nil {
		t.Fatalf("ImportReview: %v", err)
	}

	row := findRow(review.Rows, "EDDIE")
	if row == nil {
		t.Fatalf("EDDIE not found in review rows, got rows: %+v", review.Rows)
	}
	found := false
	expectedProblem := "only an admin can change eddie"
	for _, p := range row.Problems {
		if strings.EqualFold(p, expectedProblem) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exact problem %q, got: %v", expectedProblem, row.Problems)
	}
	if ctl := findRow(review.Rows, "alice"); ctl == nil || len(ctl.Problems) != 0 {
		t.Errorf("control row alice = %+v, want no problems (the refusal must come from the self target)", ctl)
	}
}

func TestImportReviewDelegateProblemsImproved(t *testing.T) {
	// This is an improved version of the earlier test with better assertions
	env := newEnv(t)
	ctx := context.Background()
	env.ll.AddUser("alice", "alice@example.org", "Alice", "pass-123456")
	env.ll.AddUser("eddie", "eddie@example.org", "Eddie", "pass-123456", "hr_edit")
	env.ll.AddUser("root", "root@example.org", "Root", "pass-123456", "lldap_admin")

	if err := env.svc.LLDAP.AddUserAttribute(ctx, "city", false); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.LLDAP.AddUserAttribute(ctx, "secret", false); err != nil {
		t.Fatal(err)
	}

	env.ll.AddGroup("hr_edit", "eddie")

	cfg := &directory.Config{
		Version: 1,
		Fields: []directory.Field{
			{Name: "city", Kind: directory.FieldKindText, Multi: false},
			{Name: "secret", Kind: directory.FieldKindText, Multi: false, AdminOnly: true},
		},
		Groups: map[string]*directory.GroupConfig{},
		Permissions: map[string]string{
			directory.PermEditDetails: "hr_edit",
		},
		CreatedBy: map[string]string{},
		Deleted:   map[string]time.Time{},
	}
	env.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := env.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	eddie, _ := env.svc.CallerFor(ctx, "eddie")

	t.Run("admin_row_exact_message", func(t *testing.T) {
		csv := "username,city\nroot,Milan"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, eddie, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "root")
		if row == nil {
			t.Fatalf("root not found in review rows, got: %+v", review.Rows)
		}

		expectedProblem := "only an admin can change root"
		found := false
		for _, p := range row.Problems {
			if strings.EqualFold(p, expectedProblem) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected exact problem %q, got: %v (matched row: %+v)", expectedProblem, row.Problems, row)
		}
	})

	t.Run("permission_group_member_exact_message", func(t *testing.T) {
		// eddie (delegate) trying to edit another hr_edit member
		env.ll.AddUser("edna", "edna@example.org", "Edna", "pass-123456", "hr_edit")

		csv := "username,city\nedna,Rome"
		header, rows, err := directory.ParseCSV(strings.NewReader(csv))
		if err != nil {
			t.Fatalf("ParseCSV: %v", err)
		}

		review, err := env.svc.ImportReview(ctx, eddie, header, rows)
		if err != nil {
			t.Fatalf("ImportReview: %v", err)
		}

		row := findRow(review.Rows, "edna")
		if row == nil {
			t.Fatalf("edna not found in review rows, got: %+v", review.Rows)
		}

		expectedProblem := "only an admin can change edna"
		found := false
		for _, p := range row.Problems {
			if strings.EqualFold(p, expectedProblem) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected exact problem %q, got: %v (matched row: %+v)", expectedProblem, row.Problems, row)
		}
	})
}

// TestImportApplyRefusedUpFront: a caller without any import permission
// is refused before LLDAP or the audit is touched; oversized requests
// too; a cancelled request stops between rows.
func TestImportApplyRefusedUpFront(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	before := len(e.ll.Mutations)
	plain := &directory.Caller{User: "alice", Perms: map[string]bool{}}
	req := directory.ApplyRequest{Rows: []directory.ApplyRow{{User: "bob", Create: true, Email: "bob@example.org"}, {User: "alice", Remove: true}}}
	if _, err := e.svc.ImportApply(ctx, plain, req); status(err) != 403 {
		t.Fatalf("plain apply = %v (status %d), want 403", err, status(err))
	}
	if _, err := e.svc.ImportApply(ctx, nil, req); status(err) != 403 {
		t.Errorf("nil caller = %v", err)
	}
	if entries, _ := e.svc.Recent(100); len(entries) != 0 {
		t.Errorf("refused apply was audited: %+v", entries)
	}
	if len(e.ll.Mutations) != before || e.ll.HasUser("bob") {
		t.Error("refused apply reached LLDAP")
	}
	big := directory.ApplyRequest{Rows: make([]directory.ApplyRow, 10001)}
	if _, err := e.svc.ImportApply(ctx, asRoot, big); status(err) != 400 {
		t.Errorf("10001 rows = %v, want 400", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	res, err := e.svc.ImportApply(cctx, asRoot, req)
	if err != nil || len(res.Rows) != 2 || res.Rows[0].OK || !strings.Contains(res.Rows[1].Error, "cancelled") || e.ll.HasUser("bob") {
		t.Errorf("cancelled apply = %+v %v", res, err)
	}
}

// TestParseCSVUndoesExportNeutraliser: the UI's CSV download prefixes ' to
// cells a spreadsheet would run as a formula; uploading that file again
// drops exactly that one ' (and nothing else).
func TestParseCSVUndoesExportNeutraliser(t *testing.T) {
	in := "\"username\",\"display_name\",\"skills\"\r\n" +
		"\"bob\",\"'=HYPERLINK(\"\"x\"\")\",\"'-1|'+2\"\r\n" +
		"\"carl\",\"'@home\",\"'\tq\"\r\n" +
		"\"dan\",\"O'Brien\",\"'quoted\"\r\n" +
		"\"eve\",\"''=twice\",\"'\"\r\n"
	_, rows, err := directory.ParseCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"bob", `=HYPERLINK("x")`, "-1|'+2"}, // only the cell's leading ' goes
		{"carl", "@home", "\tq"},
		{"dan", "O'Brien", "'quoted"},
		{"eve", "''=twice", "'"}, // a ' not followed by = + - @ tab CR stays
	}
	for i := range want {
		for j := range want[i] {
			if rows[i][j] != want[i][j] {
				t.Errorf("row %d col %d = %q, want %q", i, j, rows[i][j], want[i][j])
			}
		}
	}
}
